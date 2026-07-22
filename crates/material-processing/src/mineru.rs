use crate::{
    mineru_config::{validate_config, validate_config_full_support, ValidatedLocalMineru},
    network_isolation::{verify_network_isolation, RuntimeNetworkIsolationMeasurement},
    types::{
        BackendTrace, DeviceSelection, ExtractionBackend, LocalMineruConfig,
        NetworkIsolationEvidence, ProcessedSpan, ProcessingError, ProcessingLimits,
        QualityReasonCode, SpanKind,
    },
    validate_ocr_document_v1,
    worker_protocol_client::run_worker_ocr_v1,
    OcrDocumentV1, OcrPageStatusV1, OcrProvenanceV1, OcrValidationExpectationV1, OcrWarningV1,
    WorkerDeviceV1, MINERU_WORKER_PROTOCOL_V1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const MAX_CONTENT_ENTRIES: usize = 1_000_000;
const MAX_PINNED_OUTPUT_FILES: usize = 20_000;

#[derive(Debug)]
pub(crate) struct MineruRun {
    pub spans_by_page: BTreeMap<u32, Vec<ProcessedSpan>>,
    pub page_quality_reasons: BTreeMap<u32, Vec<QualityReasonCode>>,
    pub trace: BackendTrace,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PageGeometry {
    width: f32,
    height: f32,
}

#[derive(Debug, Clone, PartialEq)]
struct MiddleTextCandidate {
    text: String,
    confidence: f32,
}

#[derive(Debug, Clone, PartialEq)]
struct MiddleBlockEvidence {
    content_bbox: [u32; 4],
    candidates: Vec<MiddleTextCandidate>,
}

#[derive(Debug, Clone, PartialEq)]
struct MiddleEvidence {
    page_sizes: Vec<PageGeometry>,
    blocks_by_page: Vec<Vec<MiddleBlockEvidence>>,
}

pub(crate) fn run_local_mineru(
    pdf_bytes: &[u8],
    page_count: u32,
    required_pages: &[u32],
    config: &LocalMineruConfig,
    limits: &ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
) -> Result<MineruRun, ProcessingError> {
    run_local_mineru_with_verifier(
        pdf_bytes,
        page_count,
        required_pages,
        config,
        limits,
        cancelled,
        verify_network_isolation,
    )
}

fn run_local_mineru_with_verifier<F>(
    pdf_bytes: &[u8],
    page_count: u32,
    required_pages: &[u32],
    config: &LocalMineruConfig,
    limits: &ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
    verifier: F,
) -> Result<MineruRun, ProcessingError>
where
    F: Fn(
        &[PathBuf],
        &NetworkIsolationEvidence,
    ) -> Result<RuntimeNetworkIsolationMeasurement, ProcessingError>,
{
    if pdf_bytes.is_empty() {
        return Err(ProcessingError::InvalidInput);
    }
    if pdf_bytes.len() > limits.max_input_bytes {
        return Err(ProcessingError::InputTooLarge);
    }
    if usize::try_from(page_count).map_or(true, |count| count > limits.max_pages) {
        return Err(ProcessingError::PageLimitExceeded);
    }
    if page_count == 0
        || required_pages.is_empty()
        || !(0.0..=1.0).contains(&limits.min_ocr_confidence)
        || limits.min_ocr_confidence == 0.0
        || !limits.max_page_dimension.is_finite()
        || limits.max_page_dimension <= 0.0
        || limits.max_output_files == 0
        || limits.max_output_files > MAX_PINNED_OUTPUT_FILES
        || limits.max_output_bytes == 0
    {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    let required = required_pages.iter().copied().collect::<BTreeSet<_>>();
    if required.len() != required_pages.len()
        || required_pages.windows(2).any(|pages| pages[0] >= pages[1])
        || required.iter().any(|page| *page == 0 || *page > page_count)
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }

    let validated = validate_config_full_support(config)?;
    let isolation = verifier(&validated.runtime_programs, &config.network_isolation)?;
    if is_cancelled(cancelled) {
        return Err(ProcessingError::Cancelled);
    }
    let job = tempfile::Builder::new()
        .prefix("la-ocr-")
        .tempdir_in(&config.temporary_root)
        .map_err(|_| ProcessingError::OcrFailed)?;
    let result = run_in_job(
        job.path(),
        pdf_bytes,
        page_count,
        &required,
        required_pages,
        config,
        limits,
        cancelled,
        &validated,
        &isolation,
        &verifier,
    );
    let post_run_verification = reverify_full_support(config, &validated, &isolation, &verifier);
    let result = match (result, post_run_verification) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    };
    match (result, job.close()) {
        (_, Err(_)) => Err(ProcessingError::OcrCleanupFailed),
        (result, Ok(())) => result,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_in_job<F>(
    job_root: &Path,
    pdf_bytes: &[u8],
    page_count: u32,
    required: &BTreeSet<u32>,
    required_pages: &[u32],
    config: &LocalMineruConfig,
    limits: &ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
    validated: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
    verifier: &F,
) -> Result<MineruRun, ProcessingError>
where
    F: Fn(
        &[PathBuf],
        &NetworkIsolationEvidence,
    ) -> Result<RuntimeNetworkIsolationMeasurement, ProcessingError>,
{
    let input_path = job_root.join("input.pdf");
    let output_path = job_root.join("output");
    let cache_path = job_root.join("cache");
    let hf_path = cache_path.join("huggingface");
    let paddle_path = cache_path.join("paddle");
    let matplotlib_path = cache_path.join("matplotlib");
    for directory in [&cache_path, &hf_path, &paddle_path, &matplotlib_path] {
        fs::create_dir(directory).map_err(|_| ProcessingError::OcrFailed)?;
    }
    let mut input = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&input_path)
        .map_err(|_| ProcessingError::OcrFailed)?;
    std::io::Write::write_all(&mut input, pdf_bytes).map_err(|_| ProcessingError::OcrFailed)?;
    input.sync_all().map_err(|_| ProcessingError::OcrFailed)?;
    drop(input);
    fs::create_dir(&output_path).map_err(|_| ProcessingError::OcrFailed)?;

    let source_sha256 = sha256_hex_bytes(pdf_bytes);
    let min_ocr_confidence_ppm = (limits.min_ocr_confidence * crate::MAX_PPM as f32).round() as u32;
    let processing_parameters = serde_json::to_vec(&serde_json::json!({
        "protocolVersion": MINERU_WORKER_PROTOCOL_V1,
        "backend": config.backend.cli_value(),
        "device": config.device.display_value(),
        "language": config.language,
        "pageCount": page_count,
        "requiredPages": required_pages,
        "minimumOcrConfidencePpm": min_ocr_confidence_ppm,
        "maximumOutputFiles": limits.max_output_files,
        "maximumOutputBytes": config.max_output_bytes.min(limits.max_output_bytes),
    }))
    .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    let processing_parameters_sha256 = sha256_hex_bytes(&processing_parameters);
    let protocol = run_worker_ocr_v1(
        job_root,
        config,
        validated,
        isolation,
        &source_sha256,
        &processing_parameters_sha256,
        page_count,
        cancelled,
        || reverify(config, validated, isolation, verifier),
    )?;
    reverify(config, validated, isolation, verifier)?;
    let output_limit = config.max_output_bytes.min(limits.max_output_bytes);
    let mut files = collect_output_files(&output_path, limits.max_output_files, output_limit)?;
    let output_sha256 = output_tree_sha256(&output_path, &mut files)?;
    let expectation = OcrValidationExpectationV1 {
        document_id: protocol.document_id.clone(),
        source_sha256: source_sha256.clone(),
        input_unmodified_sha256: source_sha256,
        page_count,
        output_sha256,
        worker_sha256: validated.executable_sha256.clone(),
        model_manifest_sha256: validated.model_manifest_sha256.clone(),
        config_sha256: validated.config_sha256.clone(),
        processing_parameters_sha256,
        isolation_evidence_id: protocol.isolation_evidence_id,
        isolation_evidence_sha256: isolation.bundle_sha256.clone(),
        qualification_report_id: config.qualification_report_id.clone(),
        output_tree_confined: true,
    };
    validate_ocr_document_v1(&protocol.document, &expectation)
        .map_err(|_| ProcessingError::OcrWorkerProtocolViolation)?;
    if !provenance_matches_identity(
        &protocol.document.provenance,
        &protocol.probe.identity,
        config,
    ) {
        return Err(ProcessingError::OcrWorkerIdentityMismatch);
    }
    let content_index = unique_suffix(&files, "_content_list.json")?;
    let middle_index = unique_suffix(&files, "_middle.json")?;
    let content = read_bounded(&mut files[content_index], output_limit)?;
    let middle = read_bounded(&mut files[middle_index], output_limit)?;
    let middle_evidence = parse_middle(&middle, page_count, limits.max_page_dimension)?;
    let all_spans = parse_content_list(
        &content,
        page_count,
        &middle_evidence,
        limits.min_ocr_confidence,
    )?;
    if !protocol_matches_production_parser(&protocol.document, &all_spans) {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    let spans_by_page = all_spans
        .into_iter()
        .filter(|(page, _)| required.contains(page))
        .collect::<BTreeMap<_, _>>();
    if required
        .iter()
        .any(|page| spans_by_page.get(page).is_none_or(Vec::is_empty))
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    reverify(config, validated, isolation, verifier)?;
    let page_quality_reasons = protocol
        .document
        .pages
        .iter()
        .filter_map(|page| {
            let reasons = page
                .warnings
                .iter()
                .filter_map(|warning| match warning {
                    OcrWarningV1::LowResolution => Some(QualityReasonCode::OcrLowResolution),
                    OcrWarningV1::LowConfidence => Some(QualityReasonCode::OcrLowConfidence),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!reasons.is_empty()).then_some((page.page_index.saturating_add(1), reasons))
        })
        .collect();

    Ok(MineruRun {
        spans_by_page,
        trace: trace(config, validated, required_pages),
        page_quality_reasons,
    })
}

fn provenance_matches_identity(
    provenance: &OcrProvenanceV1,
    identity: &crate::WorkerIdentityV1,
    config: &LocalMineruConfig,
) -> bool {
    provenance.worker_version == identity.worker_version
        && provenance.worker_sha256 == identity.worker_sha256
        && provenance.python_version == identity.python_version
        && provenance.mineru_version == identity.mineru_version
        && provenance.pytorch_version == identity.pytorch_version
        && provenance.cuda_runtime_version == identity.cuda_runtime_version
        && provenance.gpu_driver_version == identity.gpu_driver_version
        && provenance.actual_device == identity.actual_device
        && provenance.model_version == identity.model_version
        && provenance.model_manifest_sha256 == identity.model_manifest_sha256
        && provenance.config_sha256 == identity.config_sha256
        && requested_device_matches(config, &provenance.requested_device)
}

fn requested_device_matches(config: &LocalMineruConfig, actual: &WorkerDeviceV1) -> bool {
    match (&config.device, actual) {
        (DeviceSelection::Auto, _) => true,
        (DeviceSelection::Cpu, WorkerDeviceV1::Cpu { .. }) => true,
        (
            DeviceSelection::Cuda { indices },
            WorkerDeviceV1::Cuda {
                indices: actual, ..
            },
        ) => indices
            .iter()
            .copied()
            .map(u16::try_from)
            .collect::<Result<Vec<_>, _>>()
            .is_ok_and(|expected| expected == *actual),
        _ => false,
    }
}

fn protocol_matches_production_parser(
    document: &OcrDocumentV1,
    parsed: &BTreeMap<u32, Vec<ProcessedSpan>>,
) -> bool {
    document.pages.iter().all(|page| {
        let page_number = page.page_index.saturating_add(1);
        let protocol_text = page
            .blocks
            .iter()
            .map(|block| normalized_ocr_text(&block.normalized_text))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>();
        let parsed_text = parsed
            .get(&page_number)
            .into_iter()
            .flatten()
            .map(|span| normalized_ocr_text(&span.text))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>();
        match page.status {
            OcrPageStatusV1::Ok => !protocol_text.is_empty() && protocol_text == parsed_text,
            OcrPageStatusV1::VerifiedBlank => protocol_text.is_empty() && parsed_text.is_empty(),
            OcrPageStatusV1::Blocked => false,
        }
    })
}

fn normalized_ocr_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '\u{feff}')
        .collect()
}
fn reverify<F>(
    config: &LocalMineruConfig,
    expected: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
    verifier: &F,
) -> Result<(), ProcessingError>
where
    F: Fn(
        &[PathBuf],
        &NetworkIsolationEvidence,
    ) -> Result<RuntimeNetworkIsolationMeasurement, ProcessingError>,
{
    let actual = validate_config(config)?;
    if !expected.same_identity(&actual) {
        return Err(ProcessingError::OcrRuntimeChanged);
    }
    if verifier(&actual.runtime_programs, &config.network_isolation)? != *isolation {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    Ok(())
}

fn reverify_full_support<F>(
    config: &LocalMineruConfig,
    expected: &ValidatedLocalMineru,
    isolation: &RuntimeNetworkIsolationMeasurement,
    verifier: &F,
) -> Result<(), ProcessingError>
where
    F: Fn(
        &[PathBuf],
        &NetworkIsolationEvidence,
    ) -> Result<RuntimeNetworkIsolationMeasurement, ProcessingError>,
{
    let actual = validate_config_full_support(config)?;
    if !expected.same_identity(&actual) {
        return Err(ProcessingError::OcrRuntimeChanged);
    }
    if verifier(&actual.runtime_programs, &config.network_isolation)? != *isolation {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    Ok(())
}

pub(crate) fn set_platform_environment(command: &mut Command) -> Result<(), ProcessingError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        let root = crate::network_isolation::trusted_windows_directory()?;
        let drive_root = root
            .parent()
            .ok_or(ProcessingError::OcrBackendUnavailable)?;
        let canonical_drive =
            fs::canonicalize(drive_root).map_err(|_| ProcessingError::OcrBackendUnavailable)?;
        let program_files = drive_root.join("Program Files");
        let metadata = fs::symlink_metadata(&program_files)
            .map_err(|_| ProcessingError::OcrBackendUnavailable)?;
        let canonical_program_files =
            fs::canonicalize(&program_files).map_err(|_| ProcessingError::OcrBackendUnavailable)?;
        if !metadata.is_dir()
            || metadata.file_attributes() & 0x400 != 0
            || canonical_program_files.parent() != Some(canonical_drive.as_path())
            || !canonical_program_files
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("Program Files"))
        {
            return Err(ProcessingError::OcrBackendUnavailable);
        }
        command
            .env("SystemRoot", &root)
            .env("WINDIR", root)
            .env("ProgramFiles", canonical_program_files);
    }
    Ok(())
}

fn trace(
    config: &LocalMineruConfig,
    validated: &ValidatedLocalMineru,
    pages: &[u32],
) -> BackendTrace {
    BackendTrace {
        backend: ExtractionBackend::MineruLocal,
        worker_sha256: Some(validated.executable_sha256.clone()),
        model_manifest_sha256: Some(validated.model_manifest_sha256.clone()),
        config_sha256: Some(validated.config_sha256.clone()),
        device: config.device.display_value(),
        page_numbers: pages.to_vec(),
        isolation_verified: true,
        isolation_mechanism: Some(config.network_isolation.mechanism.clone()),
    }
}

fn is_cancelled(cancelled: Option<&Arc<AtomicBool>>) -> bool {
    cancelled.is_some_and(|value| value.load(Ordering::Relaxed))
}

#[derive(Debug)]
struct PinnedOutputFile {
    path: PathBuf,
    file: File,
    size_bytes: u64,
}

fn collect_output_files(
    root: &Path,
    max_files: usize,
    max_bytes: u64,
) -> Result<Vec<PinnedOutputFile>, ProcessingError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    if !root_metadata.is_dir() || is_link_or_reparse(&root_metadata) {
        return Err(ProcessingError::OcrOutputUnsafe);
    }
    let root = fs::canonicalize(root).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    let mut stack = vec![root.clone()];
    let mut files = Vec::new();
    let mut total = 0u64;
    while let Some(directory) = stack.pop() {
        let entries = fs::read_dir(&directory).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
        for entry in entries {
            let entry = entry.map_err(|_| ProcessingError::OcrOutputUnsafe)?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
            if is_link_or_reparse(&metadata) {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            let canonical =
                fs::canonicalize(entry.path()).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
            if !canonical.starts_with(&root) {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            if metadata.is_dir() {
                stack.push(canonical);
            } else if metadata.is_file() {
                if files.len() >= max_files {
                    return Err(ProcessingError::OcrOutputTooLarge);
                }
                let (file, size_bytes) = output_file::open_pinned(&canonical)?;
                total = total
                    .checked_add(size_bytes)
                    .ok_or(ProcessingError::OcrOutputTooLarge)?;
                if total > max_bytes {
                    return Err(ProcessingError::OcrOutputTooLarge);
                }
                files.push(PinnedOutputFile {
                    path: canonical,
                    file,
                    size_bytes,
                });
            } else {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
        }
    }
    Ok(files)
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    let attributes = metadata.file_attributes();
    metadata.file_type().is_symlink()
        || attributes
            & (FILE_ATTRIBUTE_REPARSE_POINT
                | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
            != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn output_tree_sha256(
    root: &Path,
    files: &mut [PinnedOutputFile],
) -> Result<String, ProcessingError> {
    let root = fs::canonicalize(root).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    let mut entries = Vec::with_capacity(files.len());
    for output in files {
        let relative = output
            .path
            .strip_prefix(&root)
            .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
        let relative = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(value) => value
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(ProcessingError::OcrOutputUnsafe),
                _ => Err(ProcessingError::OcrOutputUnsafe),
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        if relative.is_empty() || relative.contains(['\r', '\n', '\0']) {
            return Err(ProcessingError::OcrOutputUnsafe);
        }
        output
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
        let mut hasher = Sha256::new();
        let copied = std::io::copy(&mut output.file, &mut hasher)
            .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
        if copied != output.size_bytes {
            return Err(ProcessingError::OcrOutputUnsafe);
        }
        entries.push((
            relative,
            output.size_bytes,
            format!("{:x}", hasher.finalize()),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ProcessingError::OcrOutputUnsafe);
    }
    let mut canonical = b"la-mineru-output-tree-v1\n".to_vec();
    for (relative, size, hash) in entries {
        canonical.extend_from_slice(relative.as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(size.to_string().as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(hash.as_bytes());
        canonical.push(b'\n');
    }
    Ok(sha256_hex_bytes(&canonical))
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn unique_suffix(files: &[PinnedOutputFile], suffix: &str) -> Result<usize, ProcessingError> {
    let mut matches = files.iter().enumerate().filter(|(_, file)| {
        file.path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.ends_with(suffix))
    });
    let (index, _) = matches.next().ok_or(ProcessingError::OcrOutputIncomplete)?;
    if matches.next().is_some() {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok(index)
}

fn read_bounded(output: &mut PinnedOutputFile, max_bytes: u64) -> Result<Vec<u8>, ProcessingError> {
    if output.size_bytes == 0 || output.size_bytes > max_bytes {
        return Err(ProcessingError::OcrOutputTooLarge);
    }
    output
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(output.size_bytes).map_err(|_| ProcessingError::OcrOutputTooLarge)?,
    );
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(ProcessingError::OcrOutputTooLarge)?;
    output
        .file
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    if bytes.len() as u64 != output.size_bytes {
        return Err(ProcessingError::OcrOutputUnsafe);
    }
    Ok(bytes)
}

mod output_file {
    use crate::types::ProcessingError;
    use std::{fs::File, path::Path};

    pub(super) fn open_pinned(path: &Path) -> Result<(File, u64), ProcessingError> {
        let file = platform::open(path)?;
        let metadata = file
            .metadata()
            .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
        if !metadata.is_file() || platform::unsafe_metadata(&metadata) {
            return Err(ProcessingError::OcrOutputUnsafe);
        }
        platform::validate_handle(&file, path)?;
        Ok((file, metadata.len()))
    }

    #[cfg(windows)]
    mod platform {
        #![allow(unsafe_code)]

        use crate::types::ProcessingError;
        use std::{
            ffi::OsString,
            fs::{File, Metadata, OpenOptions},
            os::windows::{
                ffi::OsStringExt,
                fs::{MetadataExt, OpenOptionsExt},
                io::AsRawHandle,
            },
            path::{Path, PathBuf},
        };
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{
                GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
                FILE_NAME_NORMALIZED, FILE_SHARE_READ, VOLUME_NAME_DOS,
            },
        };

        pub(super) fn open(path: &Path) -> Result<File, ProcessingError> {
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(path)
                .map_err(|_| ProcessingError::OcrOutputUnsafe)
        }

        pub(super) fn unsafe_metadata(metadata: &Metadata) -> bool {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
            const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
            const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
            metadata.file_attributes()
                & (FILE_ATTRIBUTE_REPARSE_POINT
                    | FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0
        }

        pub(super) fn validate_handle(file: &File, expected: &Path) -> Result<(), ProcessingError> {
            let handle = file.as_raw_handle() as HANDLE;
            if handle.is_null() {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            let mut information = BY_HANDLE_FILE_INFORMATION::default();
            if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
                || information.nNumberOfLinks != 1
            {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            let required = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if required == 0 {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            let mut buffer = vec![0u16; required as usize + 1];
            let written = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if written == 0 || written as usize >= buffer.len() {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            let actual = PathBuf::from(OsString::from_wide(&buffer[..written as usize]));
            if normalize(&actual) != normalize(expected) {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            Ok(())
        }

        fn normalize(value: &Path) -> String {
            let rendered = value.to_string_lossy();
            if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
                format!(r"\\{unc}").to_ascii_lowercase()
            } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
                dos.to_ascii_lowercase()
            } else {
                rendered.to_ascii_lowercase()
            }
        }
    }

    #[cfg(not(windows))]
    mod platform {
        use crate::types::ProcessingError;
        use std::{
            fs::{File, Metadata, OpenOptions},
            os::unix::fs::MetadataExt,
            path::Path,
        };

        pub(super) fn open(path: &Path) -> Result<File, ProcessingError> {
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|_| ProcessingError::OcrOutputUnsafe)
        }

        pub(super) fn unsafe_metadata(_metadata: &Metadata) -> bool {
            false
        }

        pub(super) fn validate_handle(
            file: &File,
            _expected: &Path,
        ) -> Result<(), ProcessingError> {
            if file
                .metadata()
                .map_err(|_| ProcessingError::OcrOutputUnsafe)?
                .nlink()
                != 1
            {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
            Ok(())
        }
    }
}
fn parse_middle(
    bytes: &[u8],
    page_count: u32,
    max_page_dimension: f32,
) -> Result<MiddleEvidence, ProcessingError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
    let pages = value
        .get("pdf_info")
        .and_then(Value::as_array)
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    if pages.len()
        != usize::try_from(page_count).map_err(|_| ProcessingError::OcrOutputIncomplete)?
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    let mut page_sizes = Vec::with_capacity(pages.len());
    let mut blocks_by_page = Vec::with_capacity(pages.len());
    for (index, page) in pages.iter().enumerate() {
        if page.get("page_idx").and_then(Value::as_u64) != Some(index as u64) {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        let geometry = page_size(page, max_page_dimension)?;
        let para_blocks = page
            .get("para_blocks")
            .and_then(Value::as_array)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        let discarded_blocks = page
            .get("discarded_blocks")
            .and_then(Value::as_array)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        if para_blocks.len().saturating_add(discarded_blocks.len()) > MAX_CONTENT_ENTRIES {
            return Err(ProcessingError::OcrOutputTooLarge);
        }
        let ordered = para_blocks
            .iter()
            .chain(discarded_blocks.iter())
            .collect::<Vec<_>>();
        blocks_by_page.push(middle_block_evidence(&ordered, geometry)?);
        page_sizes.push(geometry);
    }
    Ok(MiddleEvidence {
        page_sizes,
        blocks_by_page,
    })
}

fn middle_block_evidence(
    blocks: &[&Value],
    geometry: PageGeometry,
) -> Result<Vec<MiddleBlockEvidence>, ProcessingError> {
    let mut result = Vec::new();
    let mut index = 0usize;
    while index < blocks.len() {
        let is_reference = blocks[index].get("type").and_then(Value::as_str) == Some("ref_text");
        let end = if is_reference {
            let mut end = index + 1;
            while end < blocks.len()
                && blocks[end].get("type").and_then(Value::as_str) == Some("ref_text")
            {
                end += 1;
            }
            end
        } else {
            index + 1
        };
        let mut candidates = Vec::new();
        for block in &blocks[index..end] {
            collect_middle_candidates(block, &mut candidates, 0)?;
        }
        if !candidates.is_empty() {
            let bbox = blocks[index]
                .get("bbox")
                .ok_or(ProcessingError::OcrOutputIncomplete)?;
            result.push(MiddleBlockEvidence {
                content_bbox: middle_content_bbox(bbox, geometry)?,
                candidates,
            });
        }
        index = end;
    }
    Ok(result)
}

fn collect_middle_candidates(
    block: &Value,
    output: &mut Vec<MiddleTextCandidate>,
    depth: usize,
) -> Result<(), ProcessingError> {
    if depth > 32 {
        return Err(ProcessingError::OcrOutputTooLarge);
    }
    let block_type = block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let block_confidence = block
        .get("score")
        .map(strict_confidence_value)
        .transpose()?;
    let lines: &[Value] = match block.get("lines") {
        Some(value) => value
            .as_array()
            .ok_or(ProcessingError::OcrOutputIncomplete)?
            .as_slice(),
        None => &[],
    };
    let mut direct = Vec::new();
    for line in lines {
        let spans = line
            .get("spans")
            .and_then(Value::as_array)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        if spans.len().saturating_add(output.len()) > MAX_CONTENT_ENTRIES {
            return Err(ProcessingError::OcrOutputTooLarge);
        }
        for span in spans {
            for key in ["content", "html"] {
                let Some(value) = span.get(key) else {
                    continue;
                };
                let text = value
                    .as_str()
                    .ok_or(ProcessingError::OcrOutputIncomplete)?
                    .trim()
                    .to_owned();
                if text.is_empty() {
                    continue;
                }
                if text.contains('\0') {
                    return Err(ProcessingError::OcrOutputIncomplete);
                }
                let confidence = match span.get("score") {
                    Some(value) => strict_confidence_value(value)?,
                    None if key == "html"
                        && block_type == "table_body"
                        && span.get("type").and_then(Value::as_str) == Some("table") =>
                    {
                        block_confidence.ok_or(ProcessingError::OcrOutputLowConfidence)?
                    }
                    None => return Err(ProcessingError::OcrOutputLowConfidence),
                };
                let candidate = MiddleTextCandidate { text, confidence };
                direct.push(candidate.clone());
                output.push(candidate);
            }
        }
    }
    if direct.len() > 1 {
        let compact_text = direct
            .iter()
            .map(|candidate| candidate.text.as_str())
            .collect::<String>();
        let spaced_text = direct
            .iter()
            .map(|candidate| candidate.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let confidence = direct
            .iter()
            .map(|candidate| candidate.confidence)
            .reduce(f32::min)
            .ok_or(ProcessingError::OcrOutputLowConfidence)?;
        output.push(MiddleTextCandidate {
            text: compact_text.clone(),
            confidence,
        });
        if spaced_text != compact_text {
            output.push(MiddleTextCandidate {
                text: spaced_text,
                confidence,
            });
        }
    }
    if let Some(children) = block.get("blocks") {
        let children = children
            .as_array()
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        for child in children {
            collect_middle_candidates(child, output, depth + 1)?;
        }
    }
    Ok(())
}

fn strict_confidence_value(value: &Value) -> Result<f32, ProcessingError> {
    value
        .as_f64()
        .map(|value| value as f32)
        .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
        .ok_or(ProcessingError::OcrOutputLowConfidence)
}

fn middle_content_bbox(value: &Value, geometry: PageGeometry) -> Result<[u32; 4], ProcessingError> {
    let raw = absolute_bbox(value, geometry)?;
    Ok([
        (raw[0] * 1000.0 / geometry.width) as u32,
        (raw[1] * 1000.0 / geometry.height) as u32,
        (raw[2] * 1000.0 / geometry.width) as u32,
        (raw[3] * 1000.0 / geometry.height) as u32,
    ])
}

fn absolute_bbox(value: &Value, geometry: PageGeometry) -> Result<[f32; 4], ProcessingError> {
    let values = value
        .as_array()
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    if values.len() != 4 {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    let mut raw = [0.0f32; 4];
    for (index, target) in raw.iter_mut().enumerate() {
        *target = values
            .get(index)
            .and_then(Value::as_f64)
            .map(|value| value as f32)
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
    }
    if raw[0] >= raw[2] || raw[1] >= raw[3] || raw[2] > geometry.width || raw[3] > geometry.height {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok(raw)
}

fn page_size(page: &Value, max: f32) -> Result<PageGeometry, ProcessingError> {
    let size = page
        .get("page_size")
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    let (width, height) = if let Some(values) = size.as_array() {
        if values.len() != 2 {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        (
            dimension(values.first().and_then(Value::as_f64), max)?,
            dimension(values.get(1).and_then(Value::as_f64), max)?,
        )
    } else {
        (
            dimension(size.get("width").and_then(Value::as_f64), max)?,
            dimension(size.get("height").and_then(Value::as_f64), max)?,
        )
    };
    Ok(PageGeometry { width, height })
}

fn dimension(value: Option<f64>, max: f32) -> Result<f32, ProcessingError> {
    let value = value.ok_or(ProcessingError::OcrOutputIncomplete)? as f32;
    if !value.is_finite() || value <= 0.0 || value > max {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok(value)
}

fn parse_content_list(
    bytes: &[u8],
    page_count: u32,
    middle: &MiddleEvidence,
    min_confidence: f32,
) -> Result<BTreeMap<u32, Vec<ProcessedSpan>>, ProcessingError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
    let entries = value
        .as_array()
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    if entries.len() > MAX_CONTENT_ENTRIES {
        return Err(ProcessingError::OcrOutputTooLarge);
    }
    let mut pages = (1..=page_count)
        .map(|page| (page, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut previous_page = 0u64;
    let mut used_middle_blocks = BTreeSet::new();
    let mut produced_spans = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let page_index = entry
            .get("page_idx")
            .and_then(Value::as_u64)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        if page_index >= u64::from(page_count) || (index > 0 && page_index < previous_page) {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        previous_page = page_index;
        let page_number =
            u32::try_from(page_index + 1).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
        let texts = content_texts(entry)?;
        if texts.is_empty() {
            let entry_type = entry
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let explicitly_empty_text = entry_type == "text"
                && entry
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.trim().is_empty());
            if matches!(entry_type, "image" | "chart") || explicitly_empty_text {
                if let Some(bbox) = entry.get("bbox") {
                    let _ = content_list_bbox(bbox)?;
                }
                continue;
            }
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        produced_spans = produced_spans
            .checked_add(texts.len())
            .ok_or(ProcessingError::OcrOutputTooLarge)?;
        if produced_spans > MAX_CONTENT_ENTRIES {
            return Err(ProcessingError::OcrOutputTooLarge);
        }
        let (raw_bbox, normalized_bbox) = content_list_bbox(
            entry
                .get("bbox")
                .ok_or(ProcessingError::OcrOutputIncomplete)?,
        )?;
        let page = usize::try_from(page_index).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
        let middle_blocks = middle
            .blocks_by_page
            .get(page)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        let mut associations = Vec::new();
        for (block_index, block) in middle_blocks.iter().enumerate() {
            if block.content_bbox != raw_bbox {
                continue;
            }
            let mut confidences = Vec::with_capacity(texts.len());
            let mut used_candidates = BTreeSet::new();
            let mut valid = true;
            for text in &texts {
                let matches = block
                    .candidates
                    .iter()
                    .enumerate()
                    .filter(|(candidate_index, candidate)| {
                        !used_candidates.contains(candidate_index) && candidate.text == *text
                    })
                    .map(|(candidate_index, candidate)| (candidate_index, candidate.confidence))
                    .collect::<Vec<_>>();
                let [(candidate_index, confidence)] = matches.as_slice() else {
                    valid = false;
                    break;
                };
                used_candidates.insert(*candidate_index);
                confidences.push(*confidence);
            }
            if valid {
                associations.push((block_index, confidences));
            }
        }
        let [(block_index, confidences)] = associations.as_slice() else {
            return Err(ProcessingError::OcrOutputIncomplete);
        };
        if !used_middle_blocks.insert((page_index, *block_index)) {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        let kind = span_kind(entry.get("type").and_then(Value::as_str));
        for (part_index, (text, confidence)) in texts
            .into_iter()
            .zip(confidences.iter().copied())
            .enumerate()
        {
            if text.trim().is_empty()
                || text.contains(['\0', '\u{FFFD}'])
                || sparse_vertical_text(&text, raw_bbox)
            {
                return Err(ProcessingError::OcrOutputIncomplete);
            }
            if confidence < min_confidence {
                return Err(ProcessingError::OcrOutputLowConfidence);
            }
            let span_hash =
                short_hash(format!("{page_number}:{index}:{part_index}:{text}").as_bytes());
            pages
                .get_mut(&page_number)
                .ok_or(ProcessingError::OcrOutputIncomplete)?
                .push(ProcessedSpan {
                    span_id: format!("ocr-{page_number}-{index}-{part_index}-{span_hash}"),
                    text,
                    bbox: Some(normalized_bbox),
                    confidence: Some(confidence),
                    kind,
                    backend: ExtractionBackend::MineruLocal,
                });
        }
    }
    let expected_middle_blocks = middle.blocks_by_page.iter().map(Vec::len).sum::<usize>();
    if used_middle_blocks.len() != expected_middle_blocks
        || middle.page_sizes.len()
            != usize::try_from(page_count).map_err(|_| ProcessingError::OcrOutputIncomplete)?
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok(pages)
}

fn sparse_vertical_text(text: &str, bbox: [u32; 4]) -> bool {
    let glyph_count = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .count() as u64;
    if glyph_count == 0 {
        return true;
    }
    let width = u64::from(bbox[2] - bbox[0]);
    let height = u64::from(bbox[3] - bbox[1]);
    height > width.saturating_mul(glyph_count).saturating_mul(3)
}

fn content_texts(entry: &Value) -> Result<Vec<String>, ProcessingError> {
    let mut texts = Vec::new();
    for key in [
        "text",
        "equation",
        "content",
        "table_body",
        "code_body",
        "chart_body",
    ] {
        if let Some(value) = entry.get(key) {
            let text = value
                .as_str()
                .ok_or(ProcessingError::OcrOutputIncomplete)?
                .trim();
            if !text.is_empty() {
                texts.push(text.to_owned());
            }
        }
    }
    for key in [
        "list_items",
        "image_caption",
        "img_caption",
        "image_footnote",
        "table_caption",
        "table_footnote",
        "chart_caption",
        "chart_footnote",
        "code_caption",
        "code_footnote",
    ] {
        let Some(value) = entry.get(key) else {
            continue;
        };
        let values = value
            .as_array()
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        for value in values {
            let text = value
                .as_str()
                .ok_or(ProcessingError::OcrOutputIncomplete)?
                .trim();
            if !text.is_empty() {
                texts.push(text.to_owned());
            }
        }
    }
    Ok(texts)
}

fn content_list_bbox(value: &Value) -> Result<([u32; 4], [f32; 4]), ProcessingError> {
    let values = value
        .as_array()
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    if values.len() != 4 {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    let mut raw = [0u32; 4];
    for (index, target) in raw.iter_mut().enumerate() {
        *target = values
            .get(index)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value <= 1000)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
    }
    let normalized = [
        raw[0] as f32 / 1000.0,
        raw[1] as f32 / 1000.0,
        raw[2] as f32 / 1000.0,
        raw[3] as f32 / 1000.0,
    ];
    if normalized[0] >= normalized[2]
        || normalized[1] >= normalized[3]
        || !normalized.iter().all(|value| (0.0..=1.0).contains(value))
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok((raw, normalized))
}

fn span_kind(value: Option<&str>) -> SpanKind {
    match value.unwrap_or_default() {
        "title" | "heading" => SpanKind::Heading,
        "table" => SpanKind::Table,
        "equation" | "interline_equation" | "inline_equation" => SpanKind::Formula,
        "image" | "image_caption" => SpanKind::ImageCaption,
        "text" => SpanKind::Text,
        _ => SpanKind::Other,
    }
}

fn short_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(12);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.iter().take(6) {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn parses_complete_content_list_with_normalized_coordinates() {
        let middle = r#"{"pdf_info":[
          {"page_idx":0,"page_size":[100,200],"para_blocks":[{"type":"text","bbox":[10,20,90,180],"lines":[{"spans":[{"type":"text","content":"第一页文本","score":0.98}]}]}],"discarded_blocks":[]},
          {"page_idx":1,"page_size":{"width":200,"height":400},"para_blocks":[{"type":"table_body","score":0.91,"bbox":[20,40,180,360],"lines":[{"spans":[{"type":"table","html":"A|B"}]}]}],"discarded_blocks":[]}
        ]}"#;
        let evidence = parse_middle(middle.as_bytes(), 2, 10_000.0).expect("middle");
        let content = r#"[
          {"page_idx":0,"type":"text","text":"第一页文本","bbox":[100,100,900,900]},
          {"page_idx":1,"type":"table","table_body":"A|B","bbox":[100,100,900,900]}
        ]"#;
        let pages = parse_content_list(content.as_bytes(), 2, &evidence, 0.70).expect("content");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[&1][0].bbox, Some([0.1, 0.1, 0.9, 0.9]));
        assert_eq!(pages[&1][0].confidence, Some(0.98));
        assert_eq!(pages[&2][0].kind, SpanKind::Table);
        assert_eq!(pages[&2][0].confidence, Some(0.91));
    }

    #[test]
    fn page_count_size_and_order_fail_closed() {
        for middle in [
            br#"{"pdf_info":[{"page_idx":0}]}"#.as_slice(),
            br#"{"pdf_info":[{"page_idx":1,"page_size":[100,200]}]}"#.as_slice(),
            br#"{"pdf_info":[{"page_idx":0,"page_size":[0,200]}]}"#.as_slice(),
            br#"{"pdf_info":[{"page_idx":0,"page_size":[1000000,200]}]}"#.as_slice(),
        ] {
            assert_eq!(
                parse_middle(middle, 1, 10_000.0),
                Err(ProcessingError::OcrOutputIncomplete)
            );
        }
        assert_eq!(
            parse_middle(
                br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200]}]}"#,
                2,
                10_000.0
            ),
            Err(ProcessingError::OcrOutputIncomplete)
        );
    }

    #[test]
    fn bbox_confidence_and_content_order_fail_closed() {
        let evidence = MiddleEvidence {
            page_sizes: vec![
                PageGeometry {
                    width: 100.0,
                    height: 200.0,
                },
                PageGeometry {
                    width: 100.0,
                    height: 200.0,
                },
            ],
            blocks_by_page: vec![
                vec![MiddleBlockEvidence {
                    content_bbox: [0, 0, 900, 900],
                    candidates: vec![MiddleTextCandidate {
                        text: "x".to_owned(),
                        confidence: 0.9,
                    }],
                }],
                vec![MiddleBlockEvidence {
                    content_bbox: [0, 0, 900, 900],
                    candidates: vec![MiddleTextCandidate {
                        text: "y".to_owned(),
                        confidence: 0.9,
                    }],
                }],
            ],
        };
        for content in [
            r#"[{"page_idx":0,"type":"text","text":"x"}]"#,
            r#"[{"page_idx":0,"type":"text","text":"mismatch","bbox":[0,0,900,900]}]"#,
            r#"[{"page_idx":0,"type":"text","text":"x","bbox":[0,0,1001,900]}]"#,
            r#"[{"page_idx":0,"type":"text","text":"x","bbox":[900,0,100,900]}]"#,
            r#"[{"page_idx":1,"type":"text","text":"y","bbox":[0,0,900,900]},{"page_idx":0,"type":"text","text":"x","bbox":[0,0,900,900]}]"#,
        ] {
            assert!(parse_content_list(content.as_bytes(), 2, &evidence, 0.70).is_err());
        }
    }

    #[test]
    fn content_list_scores_cannot_replace_missing_or_low_middle_span_confidence() {
        let evidence = MiddleEvidence {
            page_sizes: vec![PageGeometry {
                width: 100.0,
                height: 200.0,
            }],
            blocks_by_page: vec![vec![MiddleBlockEvidence {
                content_bbox: [0, 0, 900, 900],
                candidates: vec![MiddleTextCandidate {
                    text: "x".to_owned(),
                    confidence: 0.2,
                }],
            }]],
        };
        assert_eq!(
            parse_content_list(
                br#"[{"page_idx":0,"type":"text","text":"x","bbox":[0,0,900,900],"score":1.0}]"#,
                1,
                &evidence,
                0.7,
            ),
            Err(ProcessingError::OcrOutputLowConfidence)
        );
        assert_eq!(
            parse_middle(
                br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200],"para_blocks":[{"type":"text","bbox":[0,0,90,180],"lines":[{"spans":[{"type":"text","content":"x"}]}]}],"discarded_blocks":[]}]}"#,
                1,
                10_000.0,
            ),
            Err(ProcessingError::OcrOutputLowConfidence)
        );
    }

    #[test]
    fn unicode_replacement_character_fails_closed_even_with_high_confidence() {
        let middle = parse_middle(
            br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200],"para_blocks":[{"type":"text","bbox":[0,0,90,180],"lines":[{"spans":[{"type":"text","content":"\ufffd","score":0.99}]}]}],"discarded_blocks":[]}] }"#,
            1,
            10_000.0,
        )
        .expect("middle evidence");
        assert_eq!(
            parse_content_list(
                br#"[{"page_idx":0,"type":"text","text":"\ufffd","bbox":[0,0,900,900]}]"#,
                1,
                &middle,
                0.7,
            ),
            Err(ProcessingError::OcrOutputIncomplete)
        );
    }

    #[test]
    fn sparse_vertical_gibberish_fails_closed_even_with_high_confidence() {
        let evidence = MiddleEvidence {
            page_sizes: vec![PageGeometry {
                width: 100.0,
                height: 200.0,
            }],
            blocks_by_page: vec![vec![MiddleBlockEvidence {
                content_bbox: [240, 550, 300, 950],
                candidates: vec![MiddleTextCandidate {
                    text: "xy".to_owned(),
                    confidence: 0.99,
                }],
            }]],
        };
        assert_eq!(
            parse_content_list(
                br#"[{"page_idx":0,"type":"text","text":"xy","bbox":[240,550,300,950]}]"#,
                1,
                &evidence,
                0.7,
            ),
            Err(ProcessingError::OcrOutputIncomplete)
        );
    }

    #[test]
    fn out_of_range_page_is_rejected() {
        let evidence = MiddleEvidence {
            page_sizes: vec![PageGeometry {
                width: 100.0,
                height: 200.0,
            }],
            blocks_by_page: vec![Vec::new()],
        };
        assert_eq!(
            parse_content_list(
                br#"[{"page_idx":1,"type":"text","text":"bad","bbox":[0,0,500,500]}]"#,
                1,
                &evidence,
                0.7
            ),
            Err(ProcessingError::OcrOutputIncomplete)
        );
    }

    #[cfg(windows)]
    #[test]
    fn output_hardlinks_fail_closed() {
        let root = tempfile::tempdir().expect("output root");
        let original = root.path().join("fixture_middle.json");
        let linked = root.path().join("fixture_content_list.json");
        fs::write(&original, b"{}").expect("original");
        fs::hard_link(&original, &linked).expect("hardlink");
        assert!(matches!(
            collect_output_files(root.path(), 10, 1024),
            Err(ProcessingError::OcrOutputUnsafe)
        ));
    }

    #[test]
    fn command_environment_allowlist_does_not_copy_arbitrary_secrets() {
        let mut command = Command::new(std::ffi::OsString::from("unused"));
        command.env_clear();
        command.env("MINERU_MODEL_SOURCE", "local");
        command.env("PATH", "trusted-runtime-only");
        let names = command
            .get_envs()
            .filter_map(|(name, _)| name.to_str())
            .collect::<Vec<_>>();
        assert!(!names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("OPENAI_API_KEY")));
        assert!(names.contains(&"MINERU_MODEL_SOURCE"));
    }

    #[cfg(windows)]
    #[test]
    fn synthetic_worker_e2e_rechecks_protocol_identity_isolation_and_cleanup() {
        use crate::{
            mineru_config::{
                bind_local_mineru_runtime_executable, build_local_mineru_runtime_manifest,
            },
            network_isolation::NetworkIsolationMeasurement,
            types::{
                LocalMineruRuntimeExecutableRole, MineruBackend, NetworkIsolationEvidence,
                NetworkIsolationRuleEvidence, WINDOWS_FIREWALL_ISOLATION_MECHANISM,
            },
            worker_identity_sha256_v1, WorkerDeviceV1, WorkerIdentityV1,
        };
        use std::{
            ffi::OsString,
            process::Command,
            sync::{
                atomic::{AtomicBool, AtomicUsize},
                Arc,
            },
            thread,
            time::Duration,
        };

        const SUCCESS_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic success fixture";
        const CANCEL_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic cancellation fixture";
        const TIMEOUT_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic timeout fixture";
        const ATTACK_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic protocol attack fixture";
        const CRASH_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic crash fixture";
        const INCOMPLETE_INPUT: &[u8] = b"%PDF-1.7 fixed synthetic incomplete fixture";
        const MIDDLE: &[u8] = br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200],"para_blocks":[{"type":"text","bbox":[10,20,90,180],"lines":[{"spans":[{"type":"text","content":"synthetic approved text","score":0.99}]}]}],"discarded_blocks":[]}]}"#;
        const CONTENT: &[u8] = br#"[{"page_idx":0,"type":"text","text":"synthetic approved text","bbox":[100,100,900,900]}]"#;

        fn fixture_output_hash() -> String {
            let entries = [
                ("synthetic/fixture_content_list.json", CONTENT),
                ("synthetic/fixture_middle.json", MIDDLE),
            ];
            let mut canonical = b"la-mineru-output-tree-v1\n".to_vec();
            for (relative, bytes) in entries {
                canonical.extend_from_slice(relative.as_bytes());
                canonical.push(b'\n');
                canonical.extend_from_slice(bytes.len().to_string().as_bytes());
                canonical.push(b'\n');
                canonical.extend_from_slice(sha256_hex_bytes(bytes).as_bytes());
                canonical.push(b'\n');
            }
            sha256_hex_bytes(&canonical)
        }

        fn protocol_policy_hash(bytes: &[u8]) -> String {
            sha256_hex_bytes(bytes)
        }

        fn write_support_manifest(component_root: &Path) -> PathBuf {
            const CRITICAL: [&str; 16] = [
                "worker/lawyer_assistance_mineru_worker/__init__.py",
                "worker/lawyer_assistance_mineru_worker/main.py",
                "worker/lawyer_assistance_mineru_worker/output_document.py",
                "worker/lawyer_assistance_mineru_worker/protocol.py",
                "worker/lawyer_assistance_mineru_worker/runtime.py",
                "worker/lawyer_assistance_mineru_worker/single_process.py",
                "worker/lawyer_assistance_mineru_worker/support_manifest.py",
                "worker/mineru-worker._pth",
                "worker/python312._pth",
                "worker/python312.dll",
                "worker/sitecustomize.py",
                "python/Lib/os.py",
                "python/Lib/site.py",
                "runtime/site-packages/mineru/__init__.py",
                "runtime/site-packages/pypdfium2/__init__.py",
                "runtime/site-packages/torch/__init__.py",
            ];
            let mut files = Vec::new();
            let mut tree = b"la-mineru-support-tree-v1\n".to_vec();
            let mut support_files = CRITICAL.to_vec();
            support_files.push("runtime/site-packages/mineru/noncritical_runtime.py");
            support_files.sort_unstable();
            for relative in support_files {
                let path = relative
                    .split('/')
                    .fold(component_root.to_path_buf(), |path, part| path.join(part));
                fs::create_dir_all(path.parent().expect("support parent"))
                    .expect("support directory");
                let bytes = format!("synthetic support fixture: {relative}\n").into_bytes();
                fs::write(&path, &bytes).expect("support file");
                let digest = sha256_hex_bytes(&bytes);
                tree.extend_from_slice(relative.as_bytes());
                tree.push(b'\n');
                tree.extend_from_slice(bytes.len().to_string().as_bytes());
                tree.push(b'\n');
                tree.extend_from_slice(digest.as_bytes());
                tree.push(b'\n');
                files.push(serde_json::json!({
                    "relativePath": relative,
                    "sizeBytes": bytes.len(),
                    "sha256": digest,
                }));
            }
            let support_tree_sha256 = sha256_hex_bytes(&tree);
            let support_identity_sha256 = sha256_hex_bytes(
                format!(
                    "la-mineru-support-identity-v1\nla-mineru-worker-v1\n1.0.0\n3.12.13\n3.4.3\n2.8.0+cu128\n{support_tree_sha256}\n"
                )
                .as_bytes(),
            );
            let manifest = component_root
                .join("worker")
                .join("mineru-worker.support-manifest.json");
            fs::write(
                &manifest,
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 1,
                    "manifestVersion": "lawyer-assistance-mineru-support-v1",
                    "selfContained": true,
                    "protocolVersion": "la-mineru-worker-v1",
                    "workerVersion": "1.0.0",
                    "pythonVersion": "3.12.13",
                    "mineruVersion": "3.4.3",
                    "pytorchVersion": "2.8.0+cu128",
                    "supportTreeSha256": support_tree_sha256,
                    "supportIdentitySha256": support_identity_sha256,
                    "criticalFiles": CRITICAL,
                    "files": files,
                }))
                .expect("support manifest json"),
            )
            .expect("support manifest");
            manifest
        }

        let root = tempfile::tempdir().expect("root");
        let component = root.path().join("component");
        let runtime = component.join("worker");
        let models = root.path().join("models");
        let jobs = root.path().join("jobs");
        fs::create_dir_all(&runtime).expect("runtime");
        fs::create_dir(&models).expect("models");
        fs::create_dir(&jobs).expect("jobs");

        let source = root.path().join("synthetic-worker.rs");
        let runtime_versions_sha256 = protocol_policy_hash(
            b"la-mineru-runtime-versions-v1\nsynthetic-worker-1.0.0\n3.12.4\n3.4.3\n2.7.1\nnone\nsynthetic-cpu-1\nsynthetic-model-1\n",
        );
        let offline_policy_sha256 = protocol_policy_hash(
            b"la-mineru-offline-env-v1\nMINERU_MODEL_SOURCE=local\nHF_HUB_OFFLINE=1\nTRANSFORMERS_OFFLINE=1\nHF_DATASETS_OFFLINE=1\nHF_HUB_DISABLE_TELEMETRY=1\nPIP_NO_INDEX=1\nPYTHONNOUSERSITE=1\nPYTHONSAFEPATH=1\nPYTHONDONTWRITEBYTECODE=1\nDO_NOT_TRACK=1\nNO_PROXY=*\nHTTP_PROXY=http://127.0.0.1:9\nHTTPS_PROXY=http://127.0.0.1:9\nALL_PROXY=socks5://127.0.0.1:9\n",
        );
        let job_policy_sha256 = protocol_policy_hash(
            b"la-mineru-windows-job-v1\nactive-process-limit=1\nkill-on-close=true\nsuspended-before-assign=true\n",
        );
        let worker_source = r####"
use std::{env, fs, io::{self, BufRead, Write}, path::PathBuf, process::{self, Command}, time::{SystemTime, UNIX_EPOCH}};

const PROTOCOL: &str = "la-mineru-worker-v1";
const CPU_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SUCCESS_HASH: &str = "__SUCCESS_HASH__";
const CANCEL_HASH: &str = "__CANCEL_HASH__";
const TIMEOUT_HASH: &str = "__TIMEOUT_HASH__";
const ATTACK_HASH: &str = "__ATTACK_HASH__";
const CRASH_HASH: &str = "__CRASH_HASH__";
const INCOMPLETE_HASH: &str = "__INCOMPLETE_HASH__";
const OUTPUT_HASH: &str = "__OUTPUT_HASH__";
const RUNTIME_VERSIONS_HASH: &str = "__RUNTIME_VERSIONS_HASH__";
const OFFLINE_POLICY_HASH: &str = "__OFFLINE_POLICY_HASH__";
const JOB_POLICY_HASH: &str = "__JOB_POLICY_HASH__";
const MIDDLE: &[u8] = br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200],"para_blocks":[{"type":"text","bbox":[10,20,90,180],"lines":[{"spans":[{"type":"text","content":"synthetic approved text","score":0.99}]}]}],"discarded_blocks":[]}]}"#;
const CONTENT: &[u8] = br#"[{"page_idx":0,"type":"text","text":"synthetic approved text","bbox":[100,100,900,900]}]"#;

fn field(line: &str, name: &str) -> String {
    let marker = format!("\"{}\":\"", name);
    let start = line.find(&marker).expect("missing protocol field") + marker.len();
    let tail = &line[start..];
    tail[..tail.find('"').expect("unterminated protocol field")].to_owned()
}

fn emit(value: &str) {
    let mut stdout = io::stdout().lock();
    stdout.write_all(value.as_bytes()).expect("stdout");
    stdout.write_all(b"\n").expect("newline");
    stdout.flush().expect("flush");
}

fn environment(name: &str) -> String {
    env::var(name).expect("missing fixed host environment")
}

fn device() -> String {
    format!("{{\"kind\":\"cpu\",\"hardware_fingerprint_sha256\":\"{}\"}}", CPU_HASH)
}

fn identity() -> String {
    [
        "{\"worker_version\":\"synthetic-worker-1.0.0\",\"worker_sha256\":\"",
        &environment("LA_MINERU_WORKER_SHA256"),
        "\",\"python_version\":\"3.12.4\",\"mineru_version\":\"3.4.3\",\"pytorch_version\":\"2.7.1\",\"cuda_runtime_version\":\"none\",\"gpu_driver_version\":\"synthetic-cpu-1\",\"actual_device\":",
        &device(),
        ",\"model_version\":\"synthetic-model-1\",\"model_manifest_sha256\":\"",
        &environment("LA_MINERU_MODEL_MANIFEST_SHA256"),
        "\",\"config_sha256\":\"",
        &environment("LA_MINERU_CONFIG_SHA256"),
        "\"}",
    ].concat()
}

fn hello(line: &str) {
    emit(&[
        "{\"message_type\":\"hello\",\"protocol_version\":\"", PROTOCOL,
        "\",\"request_id\":\"", &field(line, "request_id"),
        "\",\"status\":\"ok\",\"identity\":", &identity(),
        ",\"reason_codes\":[]}",
    ].concat());
}

fn health(line: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs().to_string();
    let checks = [
        ("worker_integrity", environment("LA_MINERU_WORKER_SHA256")),
        ("config_integrity", environment("LA_MINERU_CONFIG_SHA256")),
        ("model_integrity", environment("LA_MINERU_MODEL_MANIFEST_SHA256")),
        ("support_integrity", environment("LA_MINERU_SUPPORT_IDENTITY_SHA256")),
        ("runtime_versions", RUNTIME_VERSIONS_HASH.to_owned()),
        ("gpu_runtime", CPU_HASH.to_owned()),
        ("offline_flags", OFFLINE_POLICY_HASH.to_owned()),
        ("os_network_isolation", environment("LA_MINERU_ISOLATION_EVIDENCE_SHA256")),
        ("job_root_confinement", JOB_POLICY_HASH.to_owned()),
    ];
    let checks = checks.into_iter().map(|(name, hash)| format!(
        "{{\"check_id\":\"{}\",\"passed\":true,\"evidence_sha256\":\"{}\",\"reason_codes\":[]}}",
        name, hash
    )).collect::<Vec<_>>().join(",");
    emit(&[
        "{\"message_type\":\"health\",\"protocol_version\":\"", PROTOCOL,
        "\",\"request_id\":\"", &field(line, "request_id"),
        "\",\"status\":\"ok\",\"report\":{\"checked_at_unix\":", &now,
        ",\"case_material_loaded\":false,\"checks\":[", &checks,
        "]},\"reason_codes\":[]}",
    ].concat());
}

fn progress(request_id: &str, job_id: &str, stage: &str, completed: u32) {
    emit(&format!(
        "{{\"message_type\":\"progress\",\"protocol_version\":\"{}\",\"request_id\":\"{}\",\"job_id\":\"{}\",\"stage\":\"{}\",\"completed_pages\":{},\"total_pages\":1,\"elapsed_ms\":{},\"reason_codes\":[]}}",
        PROTOCOL, request_id, job_id, stage, completed, if completed == 0 { 1 } else { 2 }
    ));
}

fn cancel(line: &str) {
    emit(&[
        "{\"message_type\":\"cancel\",\"protocol_version\":\"", PROTOCOL,
        "\",\"request_id\":\"", &field(line, "request_id"),
        "\",\"job_id\":\"", &field(line, "job_id"),
        "\",\"status\":\"ok\",\"reason_codes\":[]}",
    ].concat());
}

fn ocr(line: &str, input: &mut impl BufRead) {
    let request_id = field(line, "request_id");
    let job_id = field(line, "job_id");
    let document_id = field(line, "document_id");
    let source_hash = field(line, "source_sha256");
    let parameters_hash = field(line, "processing_parameters_sha256");
    progress(&request_id, &job_id, "accepted", 0);
    if source_hash == ATTACK_HASH {
        emit(&format!("{{\"message_type\":\"progress\",\"protocol_version\":\"{}\",\"request_id\":\"{}\",\"job_id\":\"{}\",\"stage\":\"ocr\",\"completed_pages\":0,\"total_pages\":1,\"elapsed_ms\":2,\"reason_codes\":[],\"unexpected\":true}}", PROTOCOL, request_id, job_id));
        loop { std::thread::park(); }
    }
    if source_hash == CRASH_HASH { process::exit(77); }
    if source_hash == CANCEL_HASH || source_hash == TIMEOUT_HASH {
        let mut control = String::new();
        input.read_line(&mut control).expect("cancel read");
        cancel(control.trim_end());
        loop { std::thread::park(); }
    }

    fs::create_dir_all("output/synthetic").expect("output directory");
    fs::write("output/synthetic/fixture_middle.json", MIDDLE).expect("middle");
    fs::write("output/synthetic/fixture_content_list.json", CONTENT).expect("content");
    progress(&request_id, &job_id, "finalizing", 1);
    let pages = if source_hash == INCOMPLETE_HASH {
        "[]".to_owned()
    } else {
        [
            "[{\"page_index\":0,\"width_micropoints\":1000000,\"height_micropoints\":2000000,\"rotation_degrees\":0,\"page_image_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"status\":\"ok\",\"blocks\":[{\"block_id\":\"blk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"block_type\":\"text\",\"reading_order\":0,\"raw_text_ref\":\"obj_cccccccccccccccccccccccccccccccc\",\"normalized_text\":\"synthetic approved text\",\"bbox\":{\"left_micropoints\":100000,\"top_micropoints\":200000,\"right_micropoints\":900000,\"bottom_micropoints\":800000},\"polygon\":[{\"x_micropoints\":100000,\"y_micropoints\":200000},{\"x_micropoints\":900000,\"y_micropoints\":200000},{\"x_micropoints\":900000,\"y_micropoints\":800000},{\"x_micropoints\":100000,\"y_micropoints\":800000}],\"coordinate_system\":\"page_micropoints\",\"ocr_confidence_ppm\":990000,\"layout_confidence_ppm\":990000,\"confidence_available\":true,\"source_locator\":{\"page_index\":0,\"source_block_index\":0},\"visual_classification\":\"textual\"}],\"coverage_ppm\":1000000,\"minimum_ocr_confidence_ppm\":990000,\"mean_ocr_confidence_ppm\":990000,\"visual_risks\":[],\"warnings\":[],\"completeness\":{\"dimensions_verified\":true,\"page_image_hash_verified\":true,\"reading_order_contiguous\":true,\"geometry_validated\":true,\"confidences_complete\":true,\"visual_regions_classified\":true,\"output_tree_confined\":true,\"passed\":true}}]"
        ].concat()
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs().to_string();
    let device = device();
    let document = [
        "{\"protocol_version\":\"", PROTOCOL, "\",\"document_id\":\"", &document_id,
        "\",\"source_sha256\":\"", &source_hash, "\",\"input_unmodified_sha256\":\"", &source_hash,
        "\",\"page_count\":1,\"pages\":", &pages,
        ",\"provenance\":{\"worker_version\":\"synthetic-worker-1.0.0\",\"worker_sha256\":\"", &environment("LA_MINERU_WORKER_SHA256"),
        "\",\"protocol_version\":\"", PROTOCOL,
        "\",\"python_version\":\"3.12.4\",\"mineru_version\":\"3.4.3\",\"pytorch_version\":\"2.7.1\",\"cuda_runtime_version\":\"none\",\"gpu_driver_version\":\"synthetic-cpu-1\",\"requested_device\":", &device,
        ",\"actual_device\":", &device,
        ",\"model_version\":\"synthetic-model-1\",\"model_manifest_sha256\":\"", &environment("LA_MINERU_MODEL_MANIFEST_SHA256"),
        "\",\"config_sha256\":\"", &environment("LA_MINERU_CONFIG_SHA256"),
        "\",\"isolation_evidence_id\":\"", &environment("LA_MINERU_ISOLATION_EVIDENCE_ID"),
        "\",\"isolation_evidence_sha256\":\"", &environment("LA_MINERU_ISOLATION_EVIDENCE_SHA256"),
        "\",\"qualification_report_id\":\"", &environment("LA_MINERU_QUALIFICATION_REPORT_ID"),
        "\",\"processing_parameters_sha256\":\"", &parameters_hash,
        "\",\"started_at_unix\":", &now,
        ",\"duration_ms\":2},\"warnings\":[],\"completeness\":{\"input_hash_verified\":true,\"page_count_verified\":true,\"pages_contiguous\":true,\"block_ids_unique\":true,\"all_pages_complete\":true,\"provenance_complete\":true,\"output_tree_confined\":true,\"passed\":true},\"output_sha256\":\"", OUTPUT_HASH, "\"}"
    ].concat();
    emit(&[
        "{\"message_type\":\"ocr\",\"protocol_version\":\"", PROTOCOL,
        "\",\"request_id\":\"", &request_id, "\",\"job_id\":\"", &job_id,
        "\",\"payload\":{\"status\":\"completed\",\"document\":", &document, "}}"
    ].concat());
}

fn main() {
    let cmd = PathBuf::from(env::var_os("SystemRoot").expect("SystemRoot")).join("System32").join("cmd.exe");
    if Command::new(cmd).args(["/C", "exit 0"]).status().is_ok() {
        process::exit(90);
    }
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = String::new();
        if input.read_line(&mut line).expect("stdin") == 0 { break; }
        let line = line.trim_end();
        match field(line, "message_type").as_str() {
            "hello" => hello(line),
            "health" => health(line),
            "ocr" => ocr(line, &mut input),
            "cancel" => cancel(line),
            "shutdown" => {
                emit(&[
                    "{\"message_type\":\"shutdown\",\"protocol_version\":\"", PROTOCOL,
                    "\",\"request_id\":\"", &field(line, "request_id"),
                    "\",\"status\":\"ok\",\"reason_codes\":[]}",
                ].concat());
                break;
            }
            _ => process::exit(78),
        }
    }
}
"####
            .replace("__SUCCESS_HASH__", &sha256_hex_bytes(SUCCESS_INPUT))
            .replace("__CANCEL_HASH__", &sha256_hex_bytes(CANCEL_INPUT))
            .replace("__TIMEOUT_HASH__", &sha256_hex_bytes(TIMEOUT_INPUT))
            .replace("__ATTACK_HASH__", &sha256_hex_bytes(ATTACK_INPUT))
            .replace("__CRASH_HASH__", &sha256_hex_bytes(CRASH_INPUT))
            .replace("__INCOMPLETE_HASH__", &sha256_hex_bytes(INCOMPLETE_INPUT))
            .replace("__OUTPUT_HASH__", &fixture_output_hash())
            .replace("__RUNTIME_VERSIONS_HASH__", &runtime_versions_sha256)
            .replace("__OFFLINE_POLICY_HASH__", &offline_policy_sha256)
            .replace("__JOB_POLICY_HASH__", &job_policy_sha256);
        fs::write(&source, worker_source).expect("worker source");
        let worker = runtime.join("mineru-worker.exe");
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
        let compile = Command::new(rustc)
            .arg("--edition=2021")
            .arg("-O")
            .arg(&source)
            .arg("-o")
            .arg(&worker)
            .stdin(Stdio::null())
            .output()
            .expect("compile synthetic worker");
        assert!(
            compile.status.success(),
            "synthetic worker compiler failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let worker_pdb = worker.with_extension("pdb");
        if worker_pdb.exists() {
            fs::remove_file(&worker_pdb).expect("remove compiler-only PDB from runtime fixture");
        }

        let support_manifest = write_support_manifest(&component);
        let worker_canonical = fs::canonicalize(&worker).expect("canonical worker");
        let runtime_binding = bind_local_mineru_runtime_executable(
            &worker,
            LocalMineruRuntimeExecutableRole::Launcher,
        )
        .expect("bind runtime");
        let runtime_manifest_claims = build_local_mineru_runtime_manifest(
            "synthetic-1",
            std::slice::from_ref(&runtime_binding),
        )
        .expect("build runtime manifest");
        let runtime_manifest = root.path().join("runtime-manifest.json");
        fs::write(
            &runtime_manifest,
            serde_json::to_vec(&runtime_manifest_claims).expect("runtime manifest"),
        )
        .expect("runtime manifest write");

        let model = models.join("model.bin");
        fs::write(&model, b"fixed-model").expect("model");
        let model_manifest = models.join("model-manifest.json");
        fs::write(
            &model_manifest,
            serde_json::to_vec(&serde_json::json!({
                "version": "synthetic-1",
                "files": [{
                    "relativePath": "model.bin",
                    "sha256": file_sha256(&model),
                    "sizeBytes": fs::metadata(&model).expect("model metadata").len()
                }]
            }))
            .expect("model manifest"),
        )
        .expect("model manifest write");
        let tools_config = root.path().join("mineru.json");
        fs::write(
            &tools_config,
            serde_json::to_vec(&serde_json::json!({
                "models-dir": {"pipeline": models.to_str().expect("models path")}
            }))
            .expect("tools config"),
        )
        .expect("tools config write");

        let identity = WorkerIdentityV1 {
            worker_version: "synthetic-worker-1.0.0".to_owned(),
            worker_sha256: file_sha256(&worker),
            python_version: "3.12.4".to_owned(),
            mineru_version: "3.4.3".to_owned(),
            pytorch_version: "2.7.1".to_owned(),
            cuda_runtime_version: "none".to_owned(),
            gpu_driver_version: "synthetic-cpu-1".to_owned(),
            actual_device: WorkerDeviceV1::Cpu {
                hardware_fingerprint_sha256: "c".repeat(64),
            },
            model_version: "synthetic-model-1".to_owned(),
            model_manifest_sha256: file_sha256(&model_manifest),
            config_sha256: file_sha256(&tools_config),
        };
        let config = LocalMineruConfig {
            executable: worker.clone(),
            expected_executable_sha256: identity.worker_sha256.clone(),
            runtime_executables: vec![runtime_binding],
            runtime_manifest: runtime_manifest.clone(),
            expected_runtime_manifest_sha256: file_sha256(&runtime_manifest),
            support_manifest: support_manifest.clone(),
            expected_support_manifest_sha256: file_sha256(&support_manifest),
            mineru_config: tools_config.clone(),
            expected_config_sha256: identity.config_sha256.clone(),
            model_root: models,
            model_manifest: model_manifest.clone(),
            expected_model_manifest_sha256: identity.model_manifest_sha256.clone(),
            temporary_root: jobs.clone(),
            backend: MineruBackend::Pipeline,
            device: DeviceSelection::Cpu,
            language: "ch".to_owned(),
            timeout_ms: 30_000,
            max_output_bytes: 4 * 1024 * 1024,
            strict_offline: true,
            network_isolation: NetworkIsolationEvidence {
                verified: true,
                mechanism: WINDOWS_FIREWALL_ISOLATION_MECHANISM.to_owned(),
                checked_at_unix: 1,
                rules: vec![NetworkIsolationRuleEvidence {
                    program_path: worker.clone(),
                    firewall_rule_name: "Synthetic-Test-Rule".to_owned(),
                    expected_policy_sha256: "f".repeat(64),
                }],
            },
            qualification_report_id: format!("qrep_{}", "a".repeat(32)),
            expected_worker_identity_sha256: worker_identity_sha256_v1(&identity)
                .expect("identity hash"),
        };
        let measurement = RuntimeNetworkIsolationMeasurement {
            schema_version: 1,
            measurements: vec![NetworkIsolationMeasurement {
                schema_version: 1,
                rule_name: "Synthetic-Test-Rule".to_owned(),
                program_path: worker.to_string_lossy().to_string(),
                policy_sha256: "f".repeat(64),
            }],
            bundle_sha256: "e".repeat(64),
        };
        let run = |bytes: &[u8],
                   config: &LocalMineruConfig,
                   cancelled: Option<&Arc<AtomicBool>>|
         -> Result<MineruRun, ProcessingError> {
            run_local_mineru_with_verifier(
                bytes,
                1,
                &[1],
                config,
                &ProcessingLimits::default(),
                cancelled,
                |programs, _| {
                    assert_eq!(programs, std::slice::from_ref(&worker_canonical));
                    Ok(measurement.clone())
                },
            )
        };

        let result = run(SUCCESS_INPUT, &config, None).expect("protocol worker success");
        assert_eq!(result.spans_by_page[&1][0].text, "synthetic approved text");
        assert_eq!(result.spans_by_page[&1][0].confidence, Some(0.99));
        assert!(jobs.read_dir().expect("jobs").next().is_none());

        let post_run_tamper_calls = AtomicUsize::new(0);
        let undeclared_support_file = component
            .join("runtime")
            .join("site-packages")
            .join("mineru")
            .join("injected_after_preflight.py");
        let post_run_tamper = run_local_mineru_with_verifier(
            SUCCESS_INPUT,
            1,
            &[1],
            &config,
            &ProcessingLimits::default(),
            None,
            |_, _| {
                if post_run_tamper_calls.fetch_add(1, Ordering::Relaxed) == 1 {
                    fs::write(&undeclared_support_file, b"undeclared runtime injection\n")
                        .expect("inject undeclared support file");
                }
                Ok(measurement.clone())
            },
        );
        assert!(matches!(
            post_run_tamper,
            Err(ProcessingError::OcrRuntimeUntrusted)
        ));
        assert!(jobs.read_dir().expect("jobs").next().is_none());
        fs::remove_file(&undeclared_support_file).expect("remove injected support file");

        let mut identity_drift = config.clone();
        identity_drift.expected_worker_identity_sha256 = "9".repeat(64);
        assert!(matches!(
            run(SUCCESS_INPUT, &identity_drift, None),
            Err(ProcessingError::OcrWorkerIdentityMismatch)
        ));
        assert!(matches!(
            run(ATTACK_INPUT, &config, None),
            Err(ProcessingError::OcrWorkerProtocolViolation)
        ));
        assert!(matches!(
            run(CRASH_INPUT, &config, None),
            Err(ProcessingError::OcrWorkerProtocolViolation)
        ));
        assert!(matches!(
            run(INCOMPLETE_INPUT, &config, None),
            Err(ProcessingError::OcrWorkerProtocolViolation)
        ));

        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_trigger = Arc::clone(&cancellation);
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            cancellation_trigger.store(true, Ordering::Relaxed);
        });
        assert!(matches!(
            run(CANCEL_INPUT, &config, Some(&cancellation)),
            Err(ProcessingError::Cancelled)
        ));
        trigger.join().expect("cancellation trigger");

        let mut timeout = config.clone();
        timeout.timeout_ms = 1_000;
        assert!(matches!(
            run(TIMEOUT_INPUT, &timeout, None),
            Err(ProcessingError::OcrTimeout)
        ));

        let drift_calls = AtomicUsize::new(0);
        let drift = run_local_mineru_with_verifier(
            SUCCESS_INPUT,
            1,
            &[1],
            &config,
            &ProcessingLimits::default(),
            None,
            |_, _| {
                let mut current = measurement.clone();
                if drift_calls.fetch_add(1, Ordering::Relaxed) > 0 {
                    current.bundle_sha256 = "d".repeat(64);
                }
                Ok(current)
            },
        );
        assert!(matches!(
            drift,
            Err(ProcessingError::OcrWorkerIsolationUnverified)
        ));
        assert!(jobs.read_dir().expect("jobs").next().is_none());

        let noncritical_support_file = component
            .join("runtime")
            .join("site-packages")
            .join("mineru")
            .join("noncritical_runtime.py");
        fs::write(
            &noncritical_support_file,
            b"tampered noncritical support fixture\n",
        )
        .expect("tamper noncritical support file");
        assert!(matches!(
            run(SUCCESS_INPUT, &config, None),
            Err(ProcessingError::OcrRuntimeUntrusted)
        ));
        assert!(jobs.read_dir().expect("jobs").next().is_none());
    }

    #[test]
    #[ignore = "requires repository-generated output from the installed local MinerU runtime"]
    fn machine_generated_output_uses_the_production_parser() {
        let output_root = std::env::var_os("LA_SYNTHETIC_MINERU_OUTPUT_ROOT")
            .map(PathBuf::from)
            .expect("set LA_SYNTHETIC_MINERU_OUTPUT_ROOT to a synthetic MinerU output directory");
        let limits = ProcessingLimits::default();
        let output_limit = limits.max_output_bytes;
        let mut files = collect_output_files(&output_root, limits.max_output_files, output_limit)
            .expect("safe MinerU output tree");
        let content_index = unique_suffix(&files, "_content_list.json").expect("content list");
        let middle_index = unique_suffix(&files, "_middle.json").expect("middle json");
        let content = read_bounded(&mut files[content_index], output_limit).expect("content bytes");
        let middle = read_bounded(&mut files[middle_index], output_limit).expect("middle bytes");
        let middle_value: Value = serde_json::from_slice(&middle).expect("middle json syntax");
        let page_count = u32::try_from(
            middle_value
                .get("pdf_info")
                .and_then(Value::as_array)
                .expect("middle pdf_info")
                .len(),
        )
        .expect("page count");
        assert!(
            page_count > 0,
            "machine fixture must contain at least one page"
        );

        let evidence = parse_middle(&middle, page_count, limits.max_page_dimension)
            .expect("production middle parser");
        let parsed = parse_content_list(&content, page_count, &evidence, limits.min_ocr_confidence)
            .and_then(|pages| {
                if pages.values().any(Vec::is_empty) {
                    Err(ProcessingError::OcrOutputIncomplete)
                } else {
                    Ok(pages)
                }
            });
        if std::env::var_os("LA_SYNTHETIC_MINERU_EXPECT_FAILURE").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            assert!(
                matches!(
                    parsed,
                    Err(ProcessingError::OcrOutputIncomplete)
                        | Err(ProcessingError::OcrOutputLowConfidence)
                ),
                "unreadable synthetic OCR output must fail closed"
            );
            return;
        }
        let pages = parsed.expect("production content parser");
        assert_eq!(pages.len(), page_count as usize);
        assert!(pages.values().flatten().all(|span| {
            span.confidence
                .is_some_and(|confidence| confidence >= limits.min_ocr_confidence)
        }));

        if let Some(markers) = std::env::var_os("LA_SYNTHETIC_MINERU_EXPECTED_MARKERS") {
            let recognized = pages
                .values()
                .flatten()
                .map(|span| span.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            for marker in markers.to_string_lossy().split('|') {
                let marker = marker.trim();
                if !marker.is_empty() {
                    assert!(
                        recognized.contains(marker),
                        "production parser output is missing synthetic marker: {marker}"
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    fn file_sha256(path: &Path) -> String {
        format!(
            "{:x}",
            Sha256::digest(fs::read(path).expect("hash fixture"))
        )
    }
}
