use crate::{
    mineru_config::{validate_config, ValidatedLocalMineru},
    types::{
        BackendTrace, DeviceSelection, ExtractionBackend, LocalMineruConfig, ProcessedSpan,
        ProcessingError, ProcessingLimits, SpanKind,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) struct MineruRun {
    pub spans_by_page: BTreeMap<u32, Vec<ProcessedSpan>>,
    pub trace: BackendTrace,
}

pub(crate) fn run_local_mineru(
    pdf_bytes: &[u8],
    page_count: u32,
    required_pages: &[u32],
    config: &LocalMineruConfig,
    limits: &ProcessingLimits,
    cancelled: Option<&Arc<AtomicBool>>,
) -> Result<MineruRun, ProcessingError> {
    let validated = validate_config(config)?;
    if is_cancelled(cancelled) {
        return Err(ProcessingError::Cancelled);
    }
    let job = tempfile::Builder::new()
        .prefix("la-ocr-")
        .tempdir_in(&config.temporary_root)
        .map_err(|_| ProcessingError::OcrFailed)?;
    let input_path = job.path().join("input.pdf");
    let output_path = job.path().join("output");
    fs::write(&input_path, pdf_bytes).map_err(|_| ProcessingError::OcrFailed)?;
    fs::create_dir(&output_path).map_err(|_| ProcessingError::OcrFailed)?;

    let mut command = Command::new(&config.executable);
    command
        .arg("-p")
        .arg(&input_path)
        .arg("-o")
        .arg(&output_path)
        .arg("-m")
        .arg("ocr")
        .arg("-b")
        .arg(config.backend.cli_value())
        .arg("-l")
        .arg(&config.language)
        .current_dir(job.path())
        .env_clear()
        .env("MINERU_MODEL_SOURCE", "local")
        .env("MINERU_TOOLS_CONFIG_JSON", &config.mineru_config)
        .env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("HF_DATASETS_OFFLINE", "1")
        .env("DO_NOT_TRACK", "1")
        .env("NO_COLOR", "1")
        .env("TEMP", job.path())
        .env("TMP", job.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    copy_runtime_environment(&mut command);
    match &config.device {
        DeviceSelection::Auto => {}
        DeviceSelection::Cpu => {
            command.env("CUDA_VISIBLE_DEVICES", "");
        }
        DeviceSelection::Cuda { indices } => {
            command.env(
                "CUDA_VISIBLE_DEVICES",
                indices
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }

    let mut child = command
        .spawn()
        .map_err(|_| ProcessingError::OcrBackendUnavailable)?;
    let started = Instant::now();
    let timeout = Duration::from_millis(config.timeout_ms);
    let status = loop {
        if is_cancelled(cancelled) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessingError::Cancelled);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessingError::OcrTimeout);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessingError::OcrFailed);
            }
        }
    };
    if !status.success() {
        return Err(ProcessingError::OcrFailed);
    }

    let output_limit = config.max_output_bytes.min(limits.max_output_bytes);
    let files = collect_output_files(&output_path, limits.max_output_files, output_limit)?;
    let content_path = unique_suffix(&files, "_content_list.json")?;
    let middle_path = unique_suffix(&files, "_middle.json")?;
    let content = read_bounded(content_path, output_limit)?;
    let middle = read_bounded(middle_path, output_limit)?;
    let page_sizes = parse_middle(&middle, page_count)?;
    let all_spans = parse_content_list(&content, page_count, &page_sizes)?;
    let required = required_pages
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if required.iter().any(|page| *page == 0 || *page > page_count) {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    let spans_by_page = all_spans
        .into_iter()
        .filter(|(page, _)| required.contains(page))
        .collect::<BTreeMap<_, _>>();
    if required
        .iter()
        .any(|page| !spans_by_page.contains_key(page))
    {
        return Err(ProcessingError::OcrOutputIncomplete);
    }

    Ok(MineruRun {
        spans_by_page,
        trace: trace(config, validated, required_pages),
    })
}

fn copy_runtime_environment(command: &mut Command) {
    for name in [
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "PATH",
        "CUDA_PATH",
        "CUDA_HOME",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn trace(
    config: &LocalMineruConfig,
    validated: ValidatedLocalMineru,
    pages: &[u32],
) -> BackendTrace {
    BackendTrace {
        backend: ExtractionBackend::MineruLocal,
        worker_sha256: Some(validated.executable_sha256),
        model_manifest_sha256: Some(validated.model_manifest_sha256),
        config_sha256: Some(validated.config_sha256),
        device: config.device.display_value(),
        page_numbers: pages.to_vec(),
        isolation_verified: config.network_isolation.verified,
        isolation_mechanism: config
            .network_isolation
            .verified
            .then(|| config.network_isolation.mechanism.clone()),
    }
}

fn is_cancelled(cancelled: Option<&Arc<AtomicBool>>) -> bool {
    cancelled.is_some_and(|value| value.load(Ordering::Relaxed))
}

fn collect_output_files(
    root: &Path,
    max_files: usize,
    max_bytes: u64,
) -> Result<Vec<PathBuf>, ProcessingError> {
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
            if metadata.file_type().is_symlink() {
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
                total = total
                    .checked_add(metadata.len())
                    .ok_or(ProcessingError::OcrOutputTooLarge)?;
                if total > max_bytes {
                    return Err(ProcessingError::OcrOutputTooLarge);
                }
                files.push(canonical);
                if files.len() > max_files {
                    return Err(ProcessingError::OcrOutputTooLarge);
                }
            } else {
                return Err(ProcessingError::OcrOutputUnsafe);
            }
        }
    }
    Ok(files)
}

fn unique_suffix<'a>(files: &'a [PathBuf], suffix: &str) -> Result<&'a Path, ProcessingError> {
    let matches = files
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(ProcessingError::OcrOutputIncomplete);
    }
    Ok(matches[0].as_path())
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ProcessingError> {
    let metadata = fs::metadata(path).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    if metadata.len() > max_bytes {
        return Err(ProcessingError::OcrOutputTooLarge);
    }
    let mut file = File::open(path).map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| ProcessingError::OcrOutputTooLarge)?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| ProcessingError::OcrOutputUnsafe)?;
    if u64::try_from(bytes.len()).map_err(|_| ProcessingError::OcrOutputTooLarge)? > max_bytes {
        return Err(ProcessingError::OcrOutputTooLarge);
    }
    Ok(bytes)
}

fn parse_middle(bytes: &[u8], page_count: u32) -> Result<Vec<Option<(f32, f32)>>, ProcessingError> {
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
    let mut result = Vec::with_capacity(pages.len());
    for (index, page) in pages.iter().enumerate() {
        if page
            .get("page_idx")
            .and_then(Value::as_u64)
            .is_some_and(|actual| actual != index as u64)
        {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        result.push(page_size(page));
    }
    Ok(result)
}

fn page_size(page: &Value) -> Option<(f32, f32)> {
    let size = page.get("page_size")?;
    if let Some(values) = size.as_array() {
        let width = finite_positive(values.first()?.as_f64()?)?;
        let height = finite_positive(values.get(1)?.as_f64()?)?;
        return Some((width, height));
    }
    let width = finite_positive(size.get("width")?.as_f64()?)?;
    let height = finite_positive(size.get("height")?.as_f64()?)?;
    Some((width, height))
}

fn finite_positive(value: f64) -> Option<f32> {
    let value = value as f32;
    (value.is_finite() && value > 0.0).then_some(value)
}

fn parse_content_list(
    bytes: &[u8],
    page_count: u32,
    page_sizes: &[Option<(f32, f32)>],
) -> Result<BTreeMap<u32, Vec<ProcessedSpan>>, ProcessingError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
    let entries = value
        .as_array()
        .ok_or(ProcessingError::OcrOutputIncomplete)?;
    let mut pages = (1..=page_count)
        .map(|page| (page, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for (index, entry) in entries.iter().enumerate() {
        let page_index = entry
            .get("page_idx")
            .and_then(Value::as_u64)
            .ok_or(ProcessingError::OcrOutputIncomplete)?;
        if page_index >= u64::from(page_count) {
            return Err(ProcessingError::OcrOutputIncomplete);
        }
        let page_number =
            u32::try_from(page_index + 1).map_err(|_| ProcessingError::OcrOutputIncomplete)?;
        let Some(text) = content_text(entry) else {
            continue;
        };
        if text.trim().is_empty() || text.contains('\0') {
            continue;
        }
        let page_size = usize::try_from(page_index)
            .ok()
            .and_then(|page| page_sizes.get(page))
            .copied()
            .flatten();
        let bbox = entry
            .get("bbox")
            .and_then(|value| normalized_bbox(value, page_size));
        let confidence = entry
            .get("score")
            .and_then(Value::as_f64)
            .map(|value| value as f32)
            .filter(|value| value.is_finite() && (0.0..=1.0).contains(value));
        let kind = span_kind(entry.get("type").and_then(Value::as_str));
        let span_hash = short_hash(format!("{page_number}:{index}:{text}").as_bytes());
        let span = ProcessedSpan {
            span_id: format!("ocr-{page_number}-{index}-{span_hash}"),
            text,
            bbox,
            confidence,
            kind,
            backend: ExtractionBackend::MineruLocal,
        };
        pages
            .get_mut(&page_number)
            .ok_or(ProcessingError::OcrOutputIncomplete)?
            .push(span);
    }
    Ok(pages)
}

fn content_text(entry: &Value) -> Option<String> {
    for key in ["text", "table_body", "equation", "content"] {
        if let Some(text) = entry.get(key).and_then(Value::as_str) {
            return Some(text.to_owned());
        }
    }
    for key in ["image_caption", "img_caption"] {
        if let Some(values) = entry.get(key).and_then(Value::as_array) {
            let joined = values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            if !joined.is_empty() {
                return Some(joined);
            }
        }
    }
    None
}

fn normalized_bbox(value: &Value, page_size: Option<(f32, f32)>) -> Option<[f32; 4]> {
    let (width, height) = page_size?;
    let values = value.as_array()?;
    if values.len() != 4 {
        return None;
    }
    let mut raw = [0.0f32; 4];
    for (index, target) in raw.iter_mut().enumerate() {
        *target = values.get(index)?.as_f64()? as f32;
        if !target.is_finite() || *target < 0.0 {
            return None;
        }
    }
    let normalized = [
        raw[0] / width,
        raw[1] / height,
        raw[2] / width,
        raw[3] / height,
    ];
    (normalized[0] <= normalized[2]
        && normalized[1] <= normalized[3]
        && normalized.iter().all(|value| (0.0..=1.0).contains(value)))
    .then_some(normalized)
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

    #[test]
    fn parses_complete_content_list_with_normalized_coordinates() {
        let middle = br#"{"pdf_info":[{"page_idx":0,"page_size":[100,200]},{"page_idx":1,"page_size":{"width":200,"height":400}}]}"#;
        let sizes = parse_middle(middle, 2).expect("middle");
        let content = r#"[
          {"page_idx":0,"type":"text","text":"第一页文本","bbox":[10,20,90,180],"score":0.98},
          {"page_idx":1,"type":"table","table_body":"A|B","bbox":[0,0,200,400]}
        ]"#;
        let pages = parse_content_list(content.as_bytes(), 2, &sizes).expect("content");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[&1][0].bbox, Some([0.1, 0.1, 0.9, 0.9]));
        assert_eq!(pages[&2][0].kind, SpanKind::Table);
    }

    #[test]
    fn missing_page_manifest_or_out_of_range_page_is_rejected() {
        assert_eq!(
            parse_middle(br#"{"pdf_info":[{"page_idx":0}]}"#, 2),
            Err(ProcessingError::OcrOutputIncomplete)
        );
        let sizes = vec![None];
        assert_eq!(
            parse_content_list(br#"[{"page_idx":1,"text":"bad"}]"#, 1, &sizes),
            Err(ProcessingError::OcrOutputIncomplete)
        );
    }

    #[test]
    fn command_environment_allowlist_does_not_copy_arbitrary_secrets() {
        let mut command = Command::new(std::ffi::OsString::from("unused"));
        command.env_clear();
        copy_runtime_environment(&mut command);
        command.env("MINERU_MODEL_SOURCE", "local");
        let names = command
            .get_envs()
            .filter_map(|(name, _)| name.to_str())
            .collect::<Vec<_>>();
        assert!(!names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("OPENAI_API_KEY")));
        assert!(names.contains(&"MINERU_MODEL_SOURCE"));
    }
}
