//! Isolated PDF rendering worker.
//!
//! The parent sends one PDF through stdin, then receives one page at a time. The worker waits
//! for an acknowledgement after every page, so at most the worker's outgoing frame and the
//! parent's current page are resident. No source path or plaintext temporary file is used.

use crate::{Error, Result};
use file_ingest::{
    self, OcrAsset, PdfPage, PdfPageOutput, MAX_FILE_BYTES, MAX_OCR_IMAGE_BYTES, MAX_TEXT_BYTES,
};
#[cfg(feature = "document-worker-fault-injection")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, OnceLock,
};
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;

pub const DOCUMENT_WORKER_MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;
pub const DOCUMENT_WORKER_RENDER_TIMEOUT: Duration = Duration::from_secs(90);
pub const DOCUMENT_WORKER_MAX_BUFFERED_PAGES: usize = 2;
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_TEST_RENDER_TIMEOUT: Duration = Duration::from_millis(750);
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_TEST_STALL_DURATION: Duration = Duration::from_secs(3);
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_FAULT_ENV: &str = "LAWYER_ASSISTANCE_DOCUMENT_WORKER_FAULT";
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES: usize =
    DOCUMENT_WORKER_MEMORY_LIMIT_BYTES + 8 * 1024 * 1024;
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_FAULT_MEMORY_CHUNK_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "document-worker-fault-injection")]
const DOCUMENT_WORKER_FAULT_PAGE_BYTES: usize = 4 * 1024;

const INPUT_PDF: u8 = 1;
const PAGE: u8 = 2;
const DONE: u8 = 3;
const FAILURE: u8 = 4;
const ACK: u8 = 5;
const REQUEST_ALL: u8 = 6;
const REQUEST_SELECTED: u8 = 7;
const REQUEST_METADATA: u8 = 8;
const METADATA: u8 = 9;
#[cfg(feature = "document-worker-fault-injection")]
const FAULT_REPORT: u8 = 10;
const PAGE_HEADER_BYTES: usize = 1 + 4 + 1 + 4 + 4 + 4 + 4;
const REQUEST_HEADER_BYTES: usize = 2;
const SELECTED_REQUEST_HEADER_BYTES: usize = REQUEST_HEADER_BYTES + 2;
const SELECTED_PAGE_RANGE_BYTES: usize = 8;
const MAX_SELECTED_PAGE_RANGES: usize = file_ingest::MAX_PDF_PAGES;
const MAX_REQUEST_FRAME_BYTES: usize = MAX_FILE_BYTES
    + SELECTED_REQUEST_HEADER_BYTES
    + SELECTED_PAGE_RANGE_BYTES * MAX_SELECTED_PAGE_RANGES;
const MAX_RESPONSE_FRAME_BYTES: usize = PAGE_HEADER_BYTES + MAX_TEXT_BYTES + MAX_OCR_IMAGE_BYTES;
const MAX_ERROR_CODE_BYTES: usize = 128;
const METADATA_RESPONSE_BYTES: usize = 1 + 4;
#[cfg(feature = "document-worker-fault-injection")]
const FAULT_REPORT_BYTES: usize = 1 + 1 + 1 + 8 + 8 + 8 + 8 + 4;
/// A preflight has no source-text tokenizer available. Reserve a documented, conservative page
/// envelope; actual text and visual work still charge the execution budget incrementally.
pub(crate) const PDF_METADATA_TOKENS_PER_PAGE: u32 = 1_024;
pub(crate) const PDF_METADATA_ESTIMATE_BASIS: &str = "conservative_per_page_metadata";

/// A single page received from the worker. Its image is dropped by the caller before it asks the
/// worker to render the following page.
pub(crate) struct WorkerPage {
    pub page: PdfPage,
    pub ocr_asset: Option<OcrAsset>,
}

/// Payload-free local structural facts returned by the isolated PDF worker. The estimate is a
/// conservative page envelope, never a claim that the PDF's body was extracted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PdfDocumentMetadata {
    pub page_count: u32,
    pub estimated_input_tokens: u32,
    pub estimate_basis: String,
}

enum WorkerRequestMode<'a> {
    All,
    Selected(&'a [(u32, u32)]),
    Metadata,
}

enum DecodedWorkerRequest<'a> {
    All(&'a [u8]),
    Selected {
        bytes: &'a [u8],
        ranges: Vec<(u32, u32)>,
    },
    Metadata(&'a [u8]),
}

#[cfg(feature = "document-worker-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DocumentWorkerFault {
    Memory,
    Stall,
}

#[cfg(feature = "document-worker-fault-injection")]
impl DocumentWorkerFault {
    fn from_env() -> Option<Self> {
        match std::env::var(DOCUMENT_WORKER_FAULT_ENV).ok()?.as_str() {
            "memory" => Some(Self::Memory),
            "stall" => Some(Self::Stall),
            _ => None,
        }
    }

    fn from_cli(value: &str) -> Result<Self> {
        match value {
            "memory" => Ok(Self::Memory),
            "stall" => Ok(Self::Stall),
            _ => Err(Error::new("document_worker_fault_invalid")),
        }
    }

    const fn as_cli(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Stall => "stall",
        }
    }

    const fn as_code(self) -> u8 {
        match self {
            Self::Memory => 1,
            Self::Stall => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Stall => "stall",
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Memory),
            2 => Ok(Self::Stall),
            _ => Err(Error::new("document_worker_protocol_error")),
        }
    }
}

#[cfg(feature = "document-worker-fault-injection")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DocumentWorkerFaultReport {
    fault: DocumentWorkerFault,
    outcome: u8,
    attempted_bytes: u64,
    touched_bytes: u64,
    target_bytes: u64,
    first_rejection_bytes: u64,
    win32_error: u32,
}

#[cfg(feature = "document-worker-fault-injection")]
impl DocumentWorkerFaultReport {
    const OUTCOME_MEMORY_LIMIT_REJECTED: u8 = 1;
    const OUTCOME_MEMORY_LIMIT_NOT_ENFORCED: u8 = 2;
    const OUTCOME_UNAVAILABLE: u8 = 3;

    fn public_view(&self) -> serde_json::Value {
        serde_json::json!({
            "fault": self.fault.as_str(),
            "outcome": match self.outcome {
                Self::OUTCOME_MEMORY_LIMIT_REJECTED => "memory_limit_rejected",
                Self::OUTCOME_MEMORY_LIMIT_NOT_ENFORCED => "memory_limit_not_enforced",
                Self::OUTCOME_UNAVAILABLE => "unavailable",
                _ => "unknown",
            },
            "attempted_bytes": self.attempted_bytes,
            "touched_bytes": self.touched_bytes,
            "target_bytes": self.target_bytes,
            "first_rejection_bytes": self.first_rejection_bytes,
            "win32_error": self.win32_error,
        })
    }
}

#[cfg(feature = "document-worker-fault-injection")]
static DOCUMENT_WORKER_FAULT_CONSUMED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "document-worker-fault-injection")]
static DOCUMENT_WORKER_LAST_FAULT_REPORT: OnceLock<Mutex<Option<DocumentWorkerFaultReport>>> =
    OnceLock::new();

#[cfg(feature = "document-worker-fault-injection")]
fn take_document_worker_fault_for_render() -> Option<DocumentWorkerFault> {
    let fault = DocumentWorkerFault::from_env()?;
    DOCUMENT_WORKER_FAULT_CONSUMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| fault)
}

#[cfg(feature = "document-worker-fault-injection")]
fn record_document_worker_fault_report(report: DocumentWorkerFaultReport) {
    if let Ok(mut slot) = DOCUMENT_WORKER_LAST_FAULT_REPORT
        .get_or_init(|| Mutex::new(None))
        .lock()
    {
        *slot = Some(report);
    }
}

pub(crate) struct PdfDocumentWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    renderer_elapsed: Duration,
    renderer_timeout: Duration,
    _job: WorkerJob,
}

impl PdfDocumentWorker {
    pub(crate) async fn start(bytes: &[u8], cancel: &CancellationToken) -> Result<Self> {
        Self::start_with_request(bytes, WorkerRequestMode::All, cancel).await
    }

    /// Start the existing streaming worker for only selected one-based, inclusive page ranges.
    /// An empty selection is never interpreted as all pages.
    pub(crate) async fn start_selected(
        bytes: &[u8],
        ranges: &[(u32, u32)],
        cancel: &CancellationToken,
    ) -> Result<Self> {
        // Reject malformed local input before a child process or Job is created. The child repeats
        // this check because its stdin is still an isolation boundary.
        let canonical = canonicalize_worker_ranges(ranges)?;
        Self::start_with_request(bytes, WorkerRequestMode::Selected(&canonical), cancel).await
    }

    /// Count the PDF page tree in the isolated executable without extracting text, inspecting
    /// image resources, rendering a page, or loading Pdfium.
    pub(crate) async fn metadata(
        bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<PdfDocumentMetadata> {
        let mut worker =
            Self::start_with_request(bytes, WorkerRequestMode::Metadata, cancel).await?;
        let result = worker.read_metadata(cancel).await;
        match result {
            Ok(metadata) => worker.finish().await.map(|()| metadata),
            Err(error) => {
                worker.abort().await;
                Err(error)
            }
        }
    }

    async fn start_with_request(
        bytes: &[u8],
        request: WorkerRequestMode<'_>,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::new("file_too_large"));
        }
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        // Encode before spawning so a malformed request cannot leave a short-lived unreaped
        // worker behind. All post-spawn failures use `abort`, which waits for the child.
        #[cfg(feature = "document-worker-fault-injection")]
        let render_request = request.is_render();
        let payload = encode_worker_request(bytes, request)?;
        #[cfg(feature = "document-worker-fault-injection")]
        let fault = render_request
            .then(take_document_worker_fault_for_render)
            .flatten();
        let executable =
            std::env::current_exe().map_err(|_| Error::new("document_worker_unavailable"))?;
        let mut command = Command::new(executable);
        #[cfg(feature = "document-worker-fault-injection")]
        if let Some(fault) = fault {
            command.arg("document-worker-fault").arg(fault.as_cli());
        } else {
            command.arg("document-worker");
        }
        #[cfg(not(feature = "document-worker-fault-injection"))]
        command.arg("document-worker");
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command
            .spawn()
            .map_err(|_| Error::new("document_worker_unavailable"))?;
        let job = match WorkerJob::assign(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::new("document_worker_unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::new("document_worker_unavailable"))?;
        let mut worker = Self {
            child,
            stdin,
            stdout,
            renderer_elapsed: Duration::ZERO,
            #[cfg(feature = "document-worker-fault-injection")]
            renderer_timeout: if matches!(fault, Some(DocumentWorkerFault::Stall)) {
                DOCUMENT_WORKER_TEST_RENDER_TIMEOUT
            } else {
                DOCUMENT_WORKER_RENDER_TIMEOUT
            },
            #[cfg(not(feature = "document-worker-fault-injection"))]
            renderer_timeout: DOCUMENT_WORKER_RENDER_TIMEOUT,
            _job: job,
        };
        if let Err(error) = worker.write_renderer_frame(&payload, cancel).await {
            worker.abort().await;
            return Err(error);
        }
        Ok(worker)
    }

    #[cfg(feature = "document-worker-fault-injection")]
    pub(crate) async fn next_page(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<WorkerPage>> {
        loop {
            let payload = self.read_renderer_response(cancel).await?;
            if payload.first() == Some(&FAULT_REPORT) {
                record_document_worker_fault_report(decode_fault_report(&payload)?);
                continue;
            }
            return parse_worker_response(&payload);
        }
    }

    #[cfg(not(feature = "document-worker-fault-injection"))]
    pub(crate) async fn next_page(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<WorkerPage>> {
        parse_worker_response(&self.read_renderer_response(cancel).await?)
    }

    async fn read_metadata(&mut self, cancel: &CancellationToken) -> Result<PdfDocumentMetadata> {
        let payload = self.read_renderer_response(cancel).await?;
        decode_metadata(&payload)
    }

    async fn read_renderer_response(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        let remaining = self.renderer_remaining()?;
        let started = std::time::Instant::now();
        let payload = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                self.charge_renderer_elapsed(started);
                return Err(Error::new("cancelled"));
            },
            result = tokio::time::timeout(remaining, read_frame_async(&mut self.stdout, MAX_RESPONSE_FRAME_BYTES)) => match result {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(Error::new("document_worker_timeout")),
            },
        };
        self.charge_renderer_elapsed(started);
        Ok(payload)
    }

    pub(crate) async fn acknowledge_page(&mut self, cancel: &CancellationToken) -> Result<()> {
        self.write_renderer_frame(&[ACK], cancel).await
    }

    /// Polls the child while a remote OCR request is pending. This deliberately does not impose a
    /// renderer deadline: the worker is waiting for an ACK during model work, and model latency
    /// must not consume the 90 second render budget.
    pub(crate) async fn wait_for_exit(&mut self) -> Result<()> {
        loop {
            match self
                .child
                .try_wait()
                .map_err(|_| Error::new("document_worker_exited"))?
            {
                Some(_) => return Err(Error::new("document_worker_exited")),
                None => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }

    pub(crate) async fn finish(mut self) -> Result<()> {
        match tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(_) => Err(Error::new("document_worker_exited")),
            Err(_) => {
                self.abort().await;
                Err(Error::new("document_worker_exited"))
            }
        }
    }

    pub(crate) async fn abort(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    async fn write_renderer_frame(
        &mut self,
        payload: &[u8],
        cancel: &CancellationToken,
    ) -> Result<()> {
        if payload.is_empty() || payload.len() > MAX_REQUEST_FRAME_BYTES {
            return Err(Error::new("document_worker_protocol_error"));
        }
        let remaining = self.renderer_remaining()?;
        let started = std::time::Instant::now();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new("cancelled")),
            value = tokio::time::timeout(remaining, write_frame_async(&mut self.stdin, payload)) => match value {
                Ok(value) => value,
                Err(_) => Err(Error::new("document_worker_timeout")),
            },
        };
        self.charge_renderer_elapsed(started);
        result
    }

    fn renderer_remaining(&self) -> Result<Duration> {
        renderer_budget_remaining_for(self.renderer_timeout, self.renderer_elapsed)
    }

    fn charge_renderer_elapsed(&mut self, started: std::time::Instant) {
        self.renderer_elapsed = self.renderer_elapsed.saturating_add(started.elapsed());
    }
}

#[cfg(test)]
fn renderer_budget_remaining(elapsed: Duration) -> Result<Duration> {
    renderer_budget_remaining_for(DOCUMENT_WORKER_RENDER_TIMEOUT, elapsed)
}

fn renderer_budget_remaining_for(timeout: Duration, elapsed: Duration) -> Result<Duration> {
    timeout
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| Error::new("document_worker_timeout"))
}

#[cfg(feature = "document-worker-fault-injection")]
impl WorkerRequestMode<'_> {
    const fn is_render(&self) -> bool {
        matches!(self, Self::All | Self::Selected(_))
    }
}

fn encode_worker_request(bytes: &[u8], request: WorkerRequestMode<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(bytes.len() + SELECTED_REQUEST_HEADER_BYTES);
    payload.push(INPUT_PDF);
    match request {
        WorkerRequestMode::All => payload.push(REQUEST_ALL),
        WorkerRequestMode::Metadata => payload.push(REQUEST_METADATA),
        WorkerRequestMode::Selected(ranges) => {
            let ranges = canonicalize_worker_ranges(ranges)?;
            if ranges.is_empty() {
                return Err(Error::new("invalid_pdf_page_range"));
            }
            let range_count =
                u16::try_from(ranges.len()).map_err(|_| Error::new("invalid_pdf_page_range"))?;
            payload.push(REQUEST_SELECTED);
            payload.extend_from_slice(&range_count.to_le_bytes());
            for (start, end) in ranges {
                payload.extend_from_slice(&start.to_le_bytes());
                payload.extend_from_slice(&end.to_le_bytes());
            }
        }
    }
    payload.extend_from_slice(bytes);
    if payload.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(Error::new("document_worker_protocol_error"));
    }
    Ok(payload)
}

fn decode_worker_request(payload: &[u8]) -> Result<DecodedWorkerRequest<'_>> {
    let Some((&INPUT_PDF, payload)) = payload.split_first() else {
        return Err(Error::new("document_worker_protocol_error"));
    };
    // Accept the pre-1.2.1 all-page request layout for an already running paired executable.
    // New parents always use an explicit mode, avoiding any interpretation of PDF bytes as a
    // page selection command.
    let Some((&mode, remaining)) = payload.split_first() else {
        return Err(Error::new("document_worker_protocol_error"));
    };
    match mode {
        REQUEST_ALL => validate_worker_pdf_bytes(remaining).map(DecodedWorkerRequest::All),
        REQUEST_METADATA => {
            validate_worker_pdf_bytes(remaining).map(DecodedWorkerRequest::Metadata)
        }
        REQUEST_SELECTED => {
            if remaining.len() < 2 {
                return Err(Error::new("document_worker_protocol_error"));
            }
            let count = usize::from(u16::from_le_bytes([remaining[0], remaining[1]]));
            if count == 0 || count > MAX_SELECTED_PAGE_RANGES {
                return Err(Error::new("invalid_pdf_page_range"));
            }
            let ranges_len = count
                .checked_mul(SELECTED_PAGE_RANGE_BYTES)
                .ok_or_else(|| Error::new("document_worker_protocol_error"))?;
            let bytes_start = 2usize
                .checked_add(ranges_len)
                .ok_or_else(|| Error::new("document_worker_protocol_error"))?;
            if bytes_start >= remaining.len() {
                return Err(Error::new("document_worker_protocol_error"));
            }
            let mut ranges = Vec::with_capacity(count);
            for range in remaining[2..bytes_start]
                .as_chunks::<SELECTED_PAGE_RANGE_BYTES>()
                .0
            {
                ranges.push((read_u32(&range[..4])?, read_u32(&range[4..])?));
            }
            let ranges = canonicalize_worker_ranges(&ranges)?;
            let bytes = validate_worker_pdf_bytes(&remaining[bytes_start..])?;
            Ok(DecodedWorkerRequest::Selected { bytes, ranges })
        }
        // The former request was `[INPUT_PDF, %PDF…]`; only an actual PDF signature earns
        // compatibility, so malformed inputs never turn into a hidden all-page request.
        b'%' if payload.starts_with(b"%PDF-") => {
            validate_worker_pdf_bytes(payload).map(DecodedWorkerRequest::All)
        }
        _ => Err(Error::new("document_worker_protocol_error")),
    }
}

fn validate_worker_pdf_bytes(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::new("file_too_large"));
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(Error::new("document_worker_protocol_error"));
    }
    Ok(bytes)
}

fn canonicalize_worker_ranges(ranges: &[(u32, u32)]) -> Result<Vec<(u32, u32)>> {
    if ranges.is_empty() || ranges.len() > MAX_SELECTED_PAGE_RANGES {
        return Err(Error::new("invalid_pdf_page_range"));
    }
    let mut result = ranges.to_vec();
    result.sort_unstable();
    let mut canonical: Vec<(u32, u32)> = Vec::with_capacity(result.len());
    for (start, end) in result {
        if start == 0 || end < start {
            return Err(Error::new("invalid_pdf_page_range"));
        }
        match canonical.last_mut() {
            Some((_, prior_end)) if start <= prior_end.saturating_add(1) => {
                *prior_end = (*prior_end).max(end);
            }
            _ => canonical.push((start, end)),
        }
    }
    Ok(canonical)
}

fn decode_metadata(payload: &[u8]) -> Result<PdfDocumentMetadata> {
    if payload.first() == Some(&FAILURE) {
        return Err(decode_worker_failure(payload));
    }
    if payload.len() != METADATA_RESPONSE_BYTES || payload.first() != Some(&METADATA) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let page_count = read_u32(&payload[1..])?;
    if page_count == 0 || usize::try_from(page_count).ok() > Some(file_ingest::MAX_PDF_PAGES) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    Ok(PdfDocumentMetadata {
        page_count,
        estimated_input_tokens: page_count.saturating_mul(PDF_METADATA_TOKENS_PER_PAGE),
        estimate_basis: PDF_METADATA_ESTIMATE_BASIS.to_owned(),
    })
}

impl Drop for PdfDocumentWorker {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Entrypoint for the hidden same-executable command. It does not construct a [`crate::Workspace`]
/// or open a store, database, socket, or source path.
pub fn run_internal_document_worker() -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let payload = read_frame_blocking(&mut input, MAX_REQUEST_FRAME_BYTES)?;
    let request = decode_worker_request(&payload)?;
    let metadata_request = matches!(&request, DecodedWorkerRequest::Metadata(_));
    let result: std::result::Result<(), file_ingest::IngestError> = match request {
        DecodedWorkerRequest::Metadata(bytes) => {
            file_ingest::inspect_pdf_metadata(bytes).and_then(|metadata| {
                write_metadata_blocking(&mut output, metadata.page_count)
                    .map_err(|_| file_ingest::IngestError::PdfRenderFailed)
            })
        }
        DecodedWorkerRequest::All(bytes) => stream_worker_pages(
            &mut input,
            &mut output,
            bytes,
            None,
            worker_pdfium_library().as_deref(),
        ),
        DecodedWorkerRequest::Selected { bytes, ranges } => stream_worker_pages(
            &mut input,
            &mut output,
            bytes,
            Some(&ranges),
            worker_pdfium_library().as_deref(),
        ),
    };
    match result {
        Ok(()) => {
            if metadata_request {
                Ok(())
            } else {
                write_frame_blocking(&mut output, &[DONE])
            }
        }
        Err(error) => {
            let _ = write_failure(&mut output, error.code());
            Err(Error::new(error.code()))
        }
    }
}

/// Test-only counterpart of [`run_internal_document_worker`]. The parent picks this hidden
/// command only for one actual render request after the default-off feature is enabled. It is
/// deliberately unavailable in ordinary builds, and a metadata request is rejected here rather
/// than consuming the one-shot parent fault setting.
#[cfg(feature = "document-worker-fault-injection")]
pub fn run_internal_document_worker_fault(mode: &str) -> Result<()> {
    let fault = DocumentWorkerFault::from_cli(mode)?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let payload = read_frame_blocking(&mut input, MAX_REQUEST_FRAME_BYTES)?;
    let request = decode_worker_request(&payload)?;
    if !matches!(
        request,
        DecodedWorkerRequest::All(_) | DecodedWorkerRequest::Selected { .. }
    ) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    match fault {
        DocumentWorkerFault::Memory => {
            let report = run_document_worker_memory_fault();
            write_fault_report(&mut output, &report)?;
            let code = if report.outcome == DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED
            {
                "document_worker_memory_limit_rejected"
            } else if report.outcome == DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_NOT_ENFORCED
            {
                "document_worker_memory_limit_not_enforced"
            } else {
                "document_worker_fault_unavailable"
            };
            let _ = write_failure(&mut output, code);
            Err(Error::new(code))
        }
        DocumentWorkerFault::Stall => {
            // This child has already received a render request. A feature-only short parent
            // deadline proves timeout/kill/reap without weakening the production 90 s deadline.
            std::thread::sleep(DOCUMENT_WORKER_TEST_STALL_DURATION);
            Err(Error::new("document_worker_fault_stalled"))
        }
    }
}

#[cfg(all(feature = "document-worker-fault-injection", windows))]
fn run_document_worker_memory_fault() -> DocumentWorkerFaultReport {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::GetLastError,
        System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        },
    };

    let mut allocations: Vec<*mut c_void> = Vec::new();
    let mut attempted_bytes = 0usize;
    let mut touched_bytes = 0usize;
    let mut rejected = false;
    let mut first_rejection_bytes = 0usize;
    let mut win32_error = 0u32;
    while attempted_bytes < DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES {
        let requested = DOCUMENT_WORKER_FAULT_MEMORY_CHUNK_BYTES
            .min(DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES.saturating_sub(attempted_bytes));
        attempted_bytes = attempted_bytes.saturating_add(requested);
        let allocation = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                requested,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if allocation.is_null() {
            // Keep issuing bounded requests through the declared target: Windows has rejected a
            // real allocation, but the report still records the intended over-limit attempt.
            rejected = true;
            if first_rejection_bytes == 0 {
                first_rejection_bytes = attempted_bytes;
                win32_error = unsafe { GetLastError() };
            }
            continue;
        }
        for offset in (0..requested).step_by(DOCUMENT_WORKER_FAULT_PAGE_BYTES) {
            unsafe {
                ptr::write_volatile((allocation as *mut u8).add(offset), 0xA5);
            }
            touched_bytes = touched_bytes.saturating_add(DOCUMENT_WORKER_FAULT_PAGE_BYTES);
        }
        allocations.push(allocation);
    }
    for allocation in allocations {
        unsafe {
            let _ = VirtualFree(allocation, 0, MEM_RELEASE);
        }
    }
    DocumentWorkerFaultReport {
        fault: DocumentWorkerFault::Memory,
        outcome: if rejected {
            DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED
        } else {
            DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_NOT_ENFORCED
        },
        attempted_bytes: attempted_bytes as u64,
        touched_bytes: touched_bytes as u64,
        target_bytes: DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES as u64,
        first_rejection_bytes: first_rejection_bytes as u64,
        win32_error,
    }
}

#[cfg(all(feature = "document-worker-fault-injection", not(windows)))]
fn run_document_worker_memory_fault() -> DocumentWorkerFaultReport {
    DocumentWorkerFaultReport {
        fault: DocumentWorkerFault::Memory,
        outcome: DocumentWorkerFaultReport::OUTCOME_UNAVAILABLE,
        attempted_bytes: 0,
        touched_bytes: 0,
        target_bytes: DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES as u64,
        first_rejection_bytes: 0,
        win32_error: 0,
    }
}

fn stream_worker_pages(
    input: &mut impl Read,
    output: &mut impl Write,
    bytes: &[u8],
    ranges: Option<&[(u32, u32)]>,
    pdfium_library: Option<&std::path::Path>,
) -> std::result::Result<(), file_ingest::IngestError> {
    file_ingest::stream_pdf_selected_pages(bytes, ranges, pdfium_library, |page| {
        write_page_blocking(output, &page)
            .map_err(|_| file_ingest::IngestError::PdfRenderFailed)?;
        // The renderer keeps no image after its page bytes have entered the bounded pipe. The
        // parent must ACK before this callback returns and Pdfium can render another page.
        drop(page);
        let acknowledgement =
            read_frame_blocking(input, 1).map_err(|_| file_ingest::IngestError::PdfRenderFailed)?;
        if acknowledgement.as_slice() != [ACK] {
            return Err(file_ingest::IngestError::PdfRenderFailed);
        }
        Ok(())
    })
}

pub(crate) fn health_status() -> serde_json::Value {
    let executable_available = std::env::current_exe().is_ok_and(|path| path.is_file());
    let renderer_available = worker_pdfium_library().is_some();
    let status = serde_json::json!({
        "enabled": executable_available && renderer_available,
        "executable_available": executable_available,
        "renderer_available": renderer_available,
        "memory_limit_bytes": DOCUMENT_WORKER_MEMORY_LIMIT_BYTES,
        "render_timeout_seconds": DOCUMENT_WORKER_RENDER_TIMEOUT.as_secs(),
        "max_buffered_pages": DOCUMENT_WORKER_MAX_BUFFERED_PAGES,
    });
    #[cfg(feature = "document-worker-fault-injection")]
    {
        let mut status = status;
        if let Some(object) = status.as_object_mut() {
            object.insert("fault_injection".to_owned(), fault_injection_status());
        }
        status
    }
    #[cfg(not(feature = "document-worker-fault-injection"))]
    {
        status
    }
}

#[cfg(feature = "document-worker-fault-injection")]
fn fault_injection_status() -> serde_json::Value {
    let configured = DocumentWorkerFault::from_env();
    let last_report = DOCUMENT_WORKER_LAST_FAULT_REPORT
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|report| report.clone()))
        .map(|report| report.public_view());
    serde_json::json!({
        "enabled": true,
        "configured_fault": configured.map(DocumentWorkerFault::as_str),
        "armed": configured.is_some() && !DOCUMENT_WORKER_FAULT_CONSUMED.load(Ordering::Acquire),
        "last_report": last_report,
        "test_render_timeout_millis": DOCUMENT_WORKER_TEST_RENDER_TIMEOUT.as_millis(),
    })
}

fn worker_pdfium_library() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("LAWYER_ASSISTANCE_PDFIUM") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(directory) = std::env::var_os("LAWYER_RUNTIME_TOOLS") {
        let directory = PathBuf::from(directory);
        candidates.push(directory.join("pdfium.dll"));
        candidates.push(directory);
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            candidates.push(parent.join("tools/pdfium.dll"));
            candidates.push(parent.join("runtime-tools/pdfium.dll"));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../output/runtime-tools/pdfium.dll"),
    );
    candidates
        .into_iter()
        .find(|path| path.is_absolute() && path.is_file())
}

fn parse_worker_response(payload: &[u8]) -> Result<Option<WorkerPage>> {
    match payload.first().copied() {
        Some(DONE) if payload.len() == 1 => Ok(None),
        Some(FAILURE) => Err(decode_worker_failure(payload)),
        Some(PAGE) => decode_page(payload).map(Some),
        _ => Err(Error::new("document_worker_protocol_error")),
    }
}

fn decode_worker_failure(payload: &[u8]) -> Error {
    let code = std::str::from_utf8(&payload[1..])
        .ok()
        .filter(|code| valid_error_code(code))
        .unwrap_or("document_worker_exited");
    Error::new(code)
}

#[cfg(feature = "document-worker-fault-injection")]
fn write_fault_report(output: &mut impl Write, report: &DocumentWorkerFaultReport) -> Result<()> {
    let mut frame = [0u8; FAULT_REPORT_BYTES];
    frame[0] = FAULT_REPORT;
    frame[1] = report.fault.as_code();
    frame[2] = report.outcome;
    frame[3..11].copy_from_slice(&report.attempted_bytes.to_le_bytes());
    frame[11..19].copy_from_slice(&report.touched_bytes.to_le_bytes());
    frame[19..27].copy_from_slice(&report.target_bytes.to_le_bytes());
    frame[27..35].copy_from_slice(&report.first_rejection_bytes.to_le_bytes());
    frame[35..39].copy_from_slice(&report.win32_error.to_le_bytes());
    write_frame_blocking(output, &frame)
}

#[cfg(feature = "document-worker-fault-injection")]
fn decode_fault_report(payload: &[u8]) -> Result<DocumentWorkerFaultReport> {
    if payload.len() != FAULT_REPORT_BYTES || payload.first() != Some(&FAULT_REPORT) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let fault = DocumentWorkerFault::from_code(payload[1])?;
    let outcome = payload[2];
    if !matches!(
        outcome,
        DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED
            | DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_NOT_ENFORCED
            | DocumentWorkerFaultReport::OUTCOME_UNAVAILABLE
    ) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let attempted_bytes = read_u64(&payload[3..11])?;
    let touched_bytes = read_u64(&payload[11..19])?;
    let target_bytes = read_u64(&payload[19..27])?;
    let first_rejection_bytes = read_u64(&payload[27..35])?;
    let win32_error = read_u32(&payload[35..39])?;
    if fault != DocumentWorkerFault::Memory
        || target_bytes != DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES as u64
        || attempted_bytes < touched_bytes
        || attempted_bytes < target_bytes
        || (outcome == DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED
            && (first_rejection_bytes == 0
                || first_rejection_bytes > attempted_bytes
                || win32_error == 0))
        || (outcome != DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED
            && (first_rejection_bytes != 0 || win32_error != 0))
    {
        return Err(Error::new("document_worker_protocol_error"));
    }
    Ok(DocumentWorkerFaultReport {
        fault,
        outcome,
        attempted_bytes,
        touched_bytes,
        target_bytes,
        first_rejection_bytes,
        win32_error,
    })
}

fn page_parts(output: &PdfPageOutput) -> Result<(u8, &[u8], u32, u32)> {
    let text = output.page.text.as_bytes();
    if text.len() > MAX_TEXT_BYTES || output.page.number == 0 {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let (flags, image, width, height) = match output.ocr_asset.as_ref() {
        Some(asset)
            if asset.locator == output.page.locator
                && asset.mime_type == "image/png"
                && asset.bytes.len() <= MAX_OCR_IMAGE_BYTES =>
        {
            (1u8, asset.bytes.as_slice(), asset.width, asset.height)
        }
        Some(_) => return Err(Error::new("document_worker_protocol_error")),
        None => (0, &[][..], 0, 0),
    };
    Ok((flags, image, width, height))
}

#[cfg(test)]
fn encode_page(output: &PdfPageOutput) -> Result<Vec<u8>> {
    let text = output.page.text.as_bytes();
    let (flags, image, width, height) = page_parts(output)?;
    let text_len =
        u32::try_from(text.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    let image_len =
        u32::try_from(image.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    let mut frame = Vec::with_capacity(PAGE_HEADER_BYTES + text.len() + image.len());
    frame.push(PAGE);
    frame.extend_from_slice(&output.page.number.to_le_bytes());
    frame.push(flags);
    frame.extend_from_slice(&text_len.to_le_bytes());
    frame.extend_from_slice(&image_len.to_le_bytes());
    frame.extend_from_slice(&width.to_le_bytes());
    frame.extend_from_slice(&height.to_le_bytes());
    frame.extend_from_slice(text);
    frame.extend_from_slice(image);
    Ok(frame)
}

fn write_page_blocking(output: &mut impl Write, page: &PdfPageOutput) -> Result<()> {
    let text = page.page.text.as_bytes();
    let (flags, image, width, height) = page_parts(page)?;
    let frame_length = PAGE_HEADER_BYTES
        .checked_add(text.len())
        .and_then(|length| length.checked_add(image.len()))
        .filter(|length| *length <= MAX_RESPONSE_FRAME_BYTES)
        .ok_or_else(|| Error::new("document_worker_protocol_error"))?;
    let frame_length =
        u32::try_from(frame_length).map_err(|_| Error::new("document_worker_protocol_error"))?;
    let text_len =
        u32::try_from(text.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    let image_len =
        u32::try_from(image.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    output
        .write_all(&frame_length.to_le_bytes())
        .and_then(|()| output.write_all(&[PAGE]))
        .and_then(|()| output.write_all(&page.page.number.to_le_bytes()))
        .and_then(|()| output.write_all(&[flags]))
        .and_then(|()| output.write_all(&text_len.to_le_bytes()))
        .and_then(|()| output.write_all(&image_len.to_le_bytes()))
        .and_then(|()| output.write_all(&width.to_le_bytes()))
        .and_then(|()| output.write_all(&height.to_le_bytes()))
        .and_then(|()| output.write_all(text))
        .and_then(|()| output.write_all(image))
        .and_then(|()| output.flush())
        .map_err(|_| Error::new("document_worker_protocol_error"))
}

fn write_metadata_blocking(output: &mut impl Write, page_count: u32) -> Result<()> {
    if page_count == 0 || usize::try_from(page_count).ok() > Some(file_ingest::MAX_PDF_PAGES) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let mut payload = [0u8; METADATA_RESPONSE_BYTES];
    payload[0] = METADATA;
    payload[1..].copy_from_slice(&page_count.to_le_bytes());
    write_frame_blocking(output, &payload)
}

fn decode_page(frame: &[u8]) -> Result<WorkerPage> {
    if frame.len() < PAGE_HEADER_BYTES || frame[0] != PAGE {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let number = read_u32(&frame[1..5])?;
    let flags = frame[5];
    let text_len = usize::try_from(read_u32(&frame[6..10])?)
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    let image_len = usize::try_from(read_u32(&frame[10..14])?)
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    let width = read_u32(&frame[14..18])?;
    let height = read_u32(&frame[18..22])?;
    if number == 0
        || text_len > MAX_TEXT_BYTES
        || image_len > MAX_OCR_IMAGE_BYTES
        || !matches!(flags, 0 | 1)
        || frame.len()
            != PAGE_HEADER_BYTES
                .saturating_add(text_len)
                .saturating_add(image_len)
        || (flags == 0 && (image_len != 0 || width != 0 || height != 0))
        || (flags == 1 && (image_len == 0 || width == 0 || height == 0))
    {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let text_range = PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + text_len;
    let text = std::str::from_utf8(&frame[text_range])
        .map_err(|_| Error::new("document_worker_protocol_error"))?
        .to_owned();
    if text.contains('\0') {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let locator = format!("page:{number}");
    let image = &frame[PAGE_HEADER_BYTES + text_len..];
    let ocr_asset = if flags == 1 {
        Some(OcrAsset {
            locator: locator.clone(),
            mime_type: "image/png".to_owned(),
            bytes: image.to_vec(),
            width,
            height,
        })
    } else {
        None
    };
    Ok(WorkerPage {
        page: PdfPage {
            number,
            locator,
            text,
            needs_ocr: flags == 1,
        },
        ocr_asset,
    })
}

fn read_u32(bytes: &[u8]) -> Result<u32> {
    let value: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(feature = "document-worker-fault-injection")]
fn read_u64(bytes: &[u8]) -> Result<u64> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    Ok(u64::from_le_bytes(value))
}

fn valid_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_ERROR_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn write_failure(output: &mut impl Write, code: &str) -> Result<()> {
    if !valid_error_code(code) {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let mut frame = Vec::with_capacity(code.len() + 1);
    frame.push(FAILURE);
    frame.extend_from_slice(code.as_bytes());
    write_frame_blocking(output, &frame)
}

fn read_frame_blocking(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    if length == 0 || length > maximum {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let mut payload = vec![0u8; length];
    input
        .read_exact(&mut payload)
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    Ok(payload)
}

fn write_frame_blocking(output: &mut impl Write, payload: &[u8]) -> Result<()> {
    let length =
        u32::try_from(payload.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    output
        .write_all(&length.to_le_bytes())
        .and_then(|()| output.write_all(payload))
        .and_then(|()| output.flush())
        .map_err(|_| Error::new("document_worker_protocol_error"))
}

async fn read_frame_async(input: &mut (impl AsyncRead + Unpin), maximum: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    input
        .read_exact(&mut length)
        .await
        .map_err(|_| Error::new("document_worker_exited"))?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| Error::new("document_worker_protocol_error"))?;
    if length == 0 || length > maximum {
        return Err(Error::new("document_worker_protocol_error"));
    }
    let mut payload = vec![0u8; length];
    input
        .read_exact(&mut payload)
        .await
        .map_err(|_| Error::new("document_worker_exited"))?;
    Ok(payload)
}

async fn write_frame_async(output: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> Result<()> {
    let length =
        u32::try_from(payload.len()).map_err(|_| Error::new("document_worker_protocol_error"))?;
    output
        .write_all(&length.to_le_bytes())
        .await
        .map_err(|_| Error::new("document_worker_exited"))?;
    output
        .write_all(payload)
        .await
        .map_err(|_| Error::new("document_worker_exited"))?;
    output
        .flush()
        .await
        .map_err(|_| Error::new("document_worker_exited"))
}

#[cfg(windows)]
struct WorkerJob(windows_sys::Win32::Foundation::HANDLE);

// A Windows job handle is process-owned and `CloseHandle` is thread-safe. The worker future
// owns it exclusively and never exposes the raw handle, so moving the supervisor task between
// Tokio threads cannot create concurrent job-handle access.
#[cfg(windows)]
unsafe impl Send for WorkerJob {}

#[cfg(windows)]
impl WorkerJob {
    fn assign(child: &Child) -> Result<Self> {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, HANDLE},
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            },
        };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(Error::new("document_worker_unavailable"));
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.ProcessMemoryLimit = DOCUMENT_WORKER_MEMORY_LIMIT_BYTES;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                u32::try_from(std::mem::size_of_val(&limits)).unwrap_or(u32::MAX),
            )
        };
        if configured == 0 {
            unsafe { CloseHandle(handle) };
            return Err(Error::new("document_worker_unavailable"));
        }
        let mut observed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let inspected = unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &mut observed as *mut _ as *mut _,
                u32::try_from(std::mem::size_of_val(&observed)).unwrap_or(u32::MAX),
                std::ptr::null_mut(),
            )
        };
        let required = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        if inspected == 0
            || observed.ProcessMemoryLimit != DOCUMENT_WORKER_MEMORY_LIMIT_BYTES
            || observed.BasicLimitInformation.ActiveProcessLimit != 1
            || observed.BasicLimitInformation.LimitFlags & required != required
        {
            unsafe { CloseHandle(handle) };
            return Err(Error::new("document_worker_unavailable"));
        }
        let process = child
            .raw_handle()
            .ok_or_else(|| Error::new("document_worker_unavailable"))?;
        let assigned = unsafe { AssignProcessToJobObject(handle, process as HANDLE) };
        if assigned == 0 {
            unsafe { CloseHandle(handle) };
            return Err(Error::new("document_worker_unavailable"));
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for WorkerJob {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(not(windows))]
struct WorkerJob;

#[cfg(not(windows))]
impl WorkerJob {
    fn assign(_child: &Child) -> Result<Self> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_rejects_declared_length_over_the_bound_before_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            read_frame_blocking(&mut bytes.as_slice(), 32)
                .unwrap_err()
                .code,
            "document_worker_protocol_error"
        );
    }

    #[test]
    fn page_frame_round_trips_only_one_bounded_page() {
        let output = PdfPageOutput {
            page: PdfPage {
                number: 2,
                locator: "page:2".to_owned(),
                text: "本地文字".to_owned(),
                needs_ocr: true,
            },
            ocr_asset: Some(OcrAsset {
                locator: "page:2".to_owned(),
                mime_type: "image/png".to_owned(),
                bytes: vec![1, 2, 3],
                width: 1,
                height: 1,
            }),
        };
        let decoded = decode_page(&encode_page(&output).expect("encode")).expect("decode");
        assert_eq!(decoded.page.locator, "page:2");
        assert_eq!(decoded.page.text, "本地文字");
        assert_eq!(decoded.ocr_asset.expect("asset").bytes, vec![1, 2, 3]);
    }

    #[test]
    fn malformed_page_frames_are_rejected() {
        let malformed = match parse_worker_response(&[PAGE, 0]) {
            Ok(_) => panic!("malformed frame was accepted"),
            Err(error) => error,
        };
        assert_eq!(malformed.code, "document_worker_protocol_error");
        let bad_failure = match parse_worker_response(&[FAILURE, b'B']) {
            Ok(_) => panic!("bad failure frame was accepted"),
            Err(error) => error,
        };
        assert_eq!(bad_failure.code, "document_worker_exited");
    }

    #[test]
    fn health_advertises_fixed_worker_limits() {
        let health = health_status();
        assert_eq!(
            health["memory_limit_bytes"],
            DOCUMENT_WORKER_MEMORY_LIMIT_BYTES
        );
        assert_eq!(health["render_timeout_seconds"], 90);
        assert_eq!(
            health["max_buffered_pages"],
            DOCUMENT_WORKER_MAX_BUFFERED_PAGES
        );
    }

    #[test]
    fn renderer_budget_is_per_document_not_per_page() {
        assert_eq!(
            renderer_budget_remaining(Duration::from_secs(89)).expect("remaining"),
            Duration::from_secs(1)
        );
        assert_eq!(
            renderer_budget_remaining(Duration::from_secs(90))
                .unwrap_err()
                .code,
            "document_worker_timeout"
        );
    }

    #[test]
    fn selected_request_canonicalizes_before_the_child_can_open_a_page() {
        let request = encode_worker_request(
            b"%PDF-1.5\nfixture",
            WorkerRequestMode::Selected(&[(4, 4), (2, 3), (3, 4)]),
        )
        .expect("selected request");
        match decode_worker_request(&request).expect("decode selected request") {
            DecodedWorkerRequest::Selected { bytes, ranges } => {
                assert_eq!(bytes, b"%PDF-1.5\nfixture");
                assert_eq!(ranges, vec![(2, 4)]);
            }
            _ => panic!("selected request lost its mode"),
        }
    }

    #[test]
    fn selected_request_rejects_empty_zero_and_reversed_ranges() {
        for ranges in [&[][..], &[(0, 1)][..], &[(2, 1)][..]] {
            assert_eq!(
                encode_worker_request(b"%PDF-1.5\nfixture", WorkerRequestMode::Selected(ranges))
                    .unwrap_err()
                    .code,
                "invalid_pdf_page_range"
            );
        }
    }

    #[test]
    fn metadata_response_is_bounded_and_uses_the_documented_conservative_estimate() {
        let mut frame = vec![METADATA];
        frame.extend_from_slice(&3u32.to_le_bytes());
        let metadata = decode_metadata(&frame).expect("metadata frame");
        assert_eq!(metadata.page_count, 3);
        assert_eq!(metadata.estimated_input_tokens, 3_072);
        assert_eq!(metadata.estimate_basis, PDF_METADATA_ESTIMATE_BASIS);
        assert_eq!(
            decode_metadata(&[METADATA, 0, 0, 0, 0]).unwrap_err().code,
            "document_worker_protocol_error"
        );
    }

    #[test]
    fn legacy_all_page_request_requires_an_actual_pdf_signature() {
        let mut legacy = vec![INPUT_PDF];
        legacy.extend_from_slice(b"%PDF-1.5\nfixture");
        assert!(matches!(
            decode_worker_request(&legacy),
            Ok(DecodedWorkerRequest::All(_))
        ));
        match decode_worker_request(&[INPUT_PDF, b'x']) {
            Err(error) => assert_eq!(error.code, "document_worker_protocol_error"),
            Ok(_) => panic!("invalid legacy request was accepted"),
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn worker_exit_is_observed_promptly_after_job_assignment() {
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit 9"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("exit fixture starts");
        let job = WorkerJob::assign(&child).expect("job configured and read back");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut worker = PdfDocumentWorker {
            child,
            stdin,
            stdout,
            renderer_elapsed: Duration::ZERO,
            renderer_timeout: DOCUMENT_WORKER_RENDER_TIMEOUT,
            _job: job,
        };
        let result = tokio::time::timeout(Duration::from_secs(1), worker.wait_for_exit())
            .await
            .expect("child exit is prompt");
        assert_eq!(result.unwrap_err().code, "document_worker_exited");
    }

    #[cfg(feature = "document-worker-fault-injection")]
    #[test]
    fn fault_report_round_trips_only_a_valid_over_limit_memory_attempt() {
        let report = DocumentWorkerFaultReport {
            fault: DocumentWorkerFault::Memory,
            outcome: DocumentWorkerFaultReport::OUTCOME_MEMORY_LIMIT_REJECTED,
            attempted_bytes: DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES as u64,
            touched_bytes: 8 * 1024 * 1024,
            target_bytes: DOCUMENT_WORKER_FAULT_MEMORY_TARGET_BYTES as u64,
            first_rejection_bytes: 512 * 1024 * 1024,
            win32_error: 8,
        };
        let mut bytes = Vec::new();
        write_fault_report(&mut bytes, &report).expect("report frame");
        let mut input = bytes.as_slice();
        let frame = read_frame_blocking(&mut input, FAULT_REPORT_BYTES).expect("frame");
        assert_eq!(decode_fault_report(&frame).expect("report"), report);

        let mut malformed = frame;
        malformed[2] = 99;
        assert_eq!(
            decode_fault_report(&malformed).unwrap_err().code,
            "document_worker_protocol_error"
        );
    }

    #[cfg(feature = "document-worker-fault-injection")]
    #[test]
    fn fault_stall_uses_only_the_feature_deadline() {
        assert_eq!(
            renderer_budget_remaining_for(
                DOCUMENT_WORKER_TEST_RENDER_TIMEOUT,
                Duration::from_millis(749),
            )
            .expect("one millisecond remains"),
            Duration::from_millis(1)
        );
        assert_eq!(
            renderer_budget_remaining_for(
                DOCUMENT_WORKER_TEST_RENDER_TIMEOUT,
                DOCUMENT_WORKER_TEST_RENDER_TIMEOUT,
            )
            .unwrap_err()
            .code,
            "document_worker_timeout"
        );
        assert_eq!(DOCUMENT_WORKER_RENDER_TIMEOUT, Duration::from_secs(90));
    }

    #[cfg(feature = "document-worker-fault-injection")]
    #[test]
    fn feature_health_is_explicit_and_production_limits_remain_visible() {
        let health = health_status();
        assert_eq!(health["render_timeout_seconds"], 90);
        assert_eq!(health["fault_injection"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            health["fault_injection"]["test_render_timeout_millis"].as_u64(),
            u64::try_from(DOCUMENT_WORKER_TEST_RENDER_TIMEOUT.as_millis()).ok()
        );
    }
}
