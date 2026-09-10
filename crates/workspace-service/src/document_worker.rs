//! Isolated PDF rendering worker.
//!
//! The parent sends one PDF through stdin, then receives one page at a time. The worker waits
//! for an acknowledgement after every page, so at most the worker's outgoing frame and the
//! parent's current page are resident. No source path or plaintext temporary file is used.

use crate::{Error, Result};
use file_ingest::{
    self, OcrAsset, PdfPage, PdfPageOutput, MAX_FILE_BYTES, MAX_OCR_IMAGE_BYTES, MAX_TEXT_BYTES,
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

const INPUT_PDF: u8 = 1;
const PAGE: u8 = 2;
const DONE: u8 = 3;
const FAILURE: u8 = 4;
const ACK: u8 = 5;
const PAGE_HEADER_BYTES: usize = 1 + 4 + 1 + 4 + 4 + 4 + 4;
const MAX_REQUEST_FRAME_BYTES: usize = MAX_FILE_BYTES + 1;
const MAX_RESPONSE_FRAME_BYTES: usize = PAGE_HEADER_BYTES + MAX_TEXT_BYTES + MAX_OCR_IMAGE_BYTES;
const MAX_ERROR_CODE_BYTES: usize = 128;

/// A single page received from the worker. Its image is dropped by the caller before it asks the
/// worker to render the following page.
pub(crate) struct WorkerPage {
    pub page: PdfPage,
    pub ocr_asset: Option<OcrAsset>,
}

pub(crate) struct PdfDocumentWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    renderer_elapsed: Duration,
    _job: WorkerJob,
}

impl PdfDocumentWorker {
    pub(crate) async fn start(bytes: &[u8], cancel: &CancellationToken) -> Result<Self> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::new("file_too_large"));
        }
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        let executable =
            std::env::current_exe().map_err(|_| Error::new("document_worker_unavailable"))?;
        let mut command = Command::new(executable);
        command
            .arg("document-worker")
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
            _job: job,
        };
        let mut payload = Vec::with_capacity(bytes.len() + 1);
        payload.push(INPUT_PDF);
        payload.extend_from_slice(bytes);
        if let Err(error) = worker.write_renderer_frame(&payload, cancel).await {
            worker.abort().await;
            return Err(error);
        }
        Ok(worker)
    }

    pub(crate) async fn next_page(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<WorkerPage>> {
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
        parse_worker_response(&payload)
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
        renderer_budget_remaining(self.renderer_elapsed)
    }

    fn charge_renderer_elapsed(&mut self, started: std::time::Instant) {
        self.renderer_elapsed = self.renderer_elapsed.saturating_add(started.elapsed());
    }
}

fn renderer_budget_remaining(elapsed: Duration) -> Result<Duration> {
    DOCUMENT_WORKER_RENDER_TIMEOUT
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| Error::new("document_worker_timeout"))
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
    let Some(bytes) = payload.strip_prefix(&[INPUT_PDF]) else {
        return Err(Error::new("document_worker_protocol_error"));
    };
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::new("file_too_large"));
    }
    let pdfium = worker_pdfium_library();
    let result = file_ingest::stream_pdf_pages(bytes, pdfium.as_deref(), |page| {
        write_page_blocking(&mut output, &page)
            .map_err(|_| file_ingest::IngestError::PdfRenderFailed)?;
        // The renderer keeps no image after its page bytes have entered the bounded pipe. The
        // parent must ACK before this callback returns and Pdfium can render another page.
        drop(page);
        let acknowledgement = read_frame_blocking(&mut input, 1)
            .map_err(|_| file_ingest::IngestError::PdfRenderFailed)?;
        if acknowledgement.as_slice() != [ACK] {
            return Err(file_ingest::IngestError::PdfRenderFailed);
        }
        Ok(())
    });
    match result {
        Ok(()) => write_frame_blocking(&mut output, &[DONE]),
        Err(error) => {
            let _ = write_failure(&mut output, error.code());
            Err(Error::new(error.code()))
        }
    }
}

pub(crate) fn health_status() -> serde_json::Value {
    let executable_available = std::env::current_exe().is_ok_and(|path| path.is_file());
    let renderer_available = worker_pdfium_library().is_some();
    serde_json::json!({
        "enabled": executable_available && renderer_available,
        "executable_available": executable_available,
        "renderer_available": renderer_available,
        "memory_limit_bytes": DOCUMENT_WORKER_MEMORY_LIMIT_BYTES,
        "render_timeout_seconds": DOCUMENT_WORKER_RENDER_TIMEOUT.as_secs(),
        "max_buffered_pages": DOCUMENT_WORKER_MAX_BUFFERED_PAGES,
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
        Some(FAILURE) => {
            let code = std::str::from_utf8(&payload[1..])
                .ok()
                .filter(|code| valid_error_code(code))
                .unwrap_or("document_worker_exited");
            Err(Error::new(code))
        }
        Some(PAGE) => decode_page(payload).map(Some),
        _ => Err(Error::new("document_worker_protocol_error")),
    }
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
            _job: job,
        };
        let result = tokio::time::timeout(Duration::from_secs(1), worker.wait_for_exit())
            .await
            .expect("child exit is prompt");
        assert_eq!(result.unwrap_err().code, "document_worker_exited");
    }
}
