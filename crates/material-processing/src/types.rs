use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MATERIAL_PROCESSING_VERSION: &str = "lawyer-assistance-material-processing-v1";
pub const RASTER_TO_PDF_TRANSFORM_VERSION: &str = "lawyer-assistance-raster-to-pdf-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RasterImageFormat {
    Png,
    Jpeg,
}

impl RasterImageFormat {
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}

/// Evidence for the deterministic, in-memory image-to-PDF transform used only
/// to feed the isolated OCR worker. Both hashes are retained so an approval is
/// bound to the original image rather than merely to its derived PDF wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputTransformTrace {
    pub schema_version: u16,
    pub transform_version: String,
    pub source_media_type: String,
    pub source_sha256: String,
    pub processing_media_type: String,
    pub processing_sha256: String,
    pub pixel_width: u32,
    pub pixel_height: u32,
}
pub const WINDOWS_FIREWALL_ISOLATION_MECHANISM: &str = "windows_defender_firewall_program_block_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrMode {
    Off,
    AutoLocal,
    ForceLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageExtractionDecision {
    NativeAccepted,
    LocalOcrRequired,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityReasonCode {
    NativeTextHealthy,
    TooLittleText,
    LowPrintableRatio,
    ExcessReplacementCharacters,
    SuspiciousReadingOrder,
    VisualContentPresent,
    PageAnnotationsPresent,
    InteractiveFormPresent,
    OcrLowResolution,
    OcrLowConfidence,
    ForcedLocalOcr,
    OcrDisabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextLayerAssessment {
    pub page_number: u32,
    pub non_whitespace_chars: u32,
    pub printable_ratio: f32,
    pub replacement_char_ratio: f32,
    pub cjk_ratio: f32,
    pub reading_order_score: f32,
    pub decision: PageExtractionDecision,
    pub reason_codes: Vec<QualityReasonCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionBackend {
    NativeText,
    MineruLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Text,
    Heading,
    Table,
    Formula,
    ImageCaption,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessedSpan {
    pub span_id: String,
    pub text: String,
    pub bbox: Option<[f32; 4]>,
    pub confidence: Option<f32>,
    pub kind: SpanKind,
    pub backend: ExtractionBackend,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessedPage {
    pub page_number: u32,
    pub assessment: TextLayerAssessment,
    pub spans: Vec<ProcessedSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackendTrace {
    pub backend: ExtractionBackend,
    pub worker_sha256: Option<String>,
    pub model_manifest_sha256: Option<String>,
    pub config_sha256: Option<String>,
    pub device: String,
    pub page_numbers: Vec<u32>,
    pub isolation_verified: bool,
    pub isolation_mechanism: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessedDocument {
    pub processing_version: String,
    pub source_sha256: String,
    pub media_type: String,
    pub page_count: u32,
    pub backend_trace: Vec<BackendTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_transform: Option<InputTransformTrace>,
    pub pages: Vec<ProcessedPage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MineruBackend {
    Pipeline,
    HybridEngine,
    VlmEngine,
}

impl MineruBackend {
    pub const fn cli_value(self) -> &'static str {
        match self {
            Self::Pipeline => "pipeline",
            Self::HybridEngine => "hybrid-engine",
            Self::VlmEngine => "vlm-engine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceSelection {
    Auto,
    Cpu,
    Cuda { indices: Vec<u32> },
}

impl DeviceSelection {
    pub fn display_value(&self) -> String {
        match self {
            Self::Auto => "auto".to_owned(),
            Self::Cpu => "cpu".to_owned(),
            Self::Cuda { indices } => {
                let joined = indices
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("cuda:{joined}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMineruRuntimeExecutableRole {
    Launcher,
    Executable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMineruRuntimeExecutable {
    pub path: PathBuf,
    pub expected_sha256: String,
    pub expected_size_bytes: u64,
    pub role: LocalMineruRuntimeExecutableRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMineruRuntimeManifestV1 {
    pub schema_version: u16,
    pub version: String,
    pub executables: Vec<LocalMineruRuntimeManifestExecutableV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMineruRuntimeManifestExecutableV1 {
    pub path_sha256: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub role: LocalMineruRuntimeExecutableRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIsolationRuleEvidence {
    pub program_path: PathBuf,
    pub firewall_rule_name: String,
    pub expected_policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIsolationEvidence {
    /// Legacy qualification bit. Production execution never trusts this bit
    /// without re-measuring every active Windows Firewall rule.
    pub verified: bool,
    pub mechanism: String,
    pub checked_at_unix: u64,
    pub rules: Vec<NetworkIsolationRuleEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMineruConfig {
    pub executable: PathBuf,
    pub expected_executable_sha256: String,
    pub runtime_executables: Vec<LocalMineruRuntimeExecutable>,
    pub runtime_manifest: PathBuf,
    pub expected_runtime_manifest_sha256: String,
    pub support_manifest: PathBuf,
    pub expected_support_manifest_sha256: String,
    pub mineru_config: PathBuf,
    pub expected_config_sha256: String,
    pub model_root: PathBuf,
    pub model_manifest: PathBuf,
    pub expected_model_manifest_sha256: String,
    pub temporary_root: PathBuf,
    pub backend: MineruBackend,
    pub device: DeviceSelection,
    pub language: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub strict_offline: bool,
    pub network_isolation: NetworkIsolationEvidence,
    /// App-signed qualification report binding. This is an opaque local ID;
    /// it is never a path and is never accepted from a document or renderer.
    pub qualification_report_id: String,
    /// SHA-256 of the canonical `hello` identity captured during the current
    /// app qualification. Production execution rejects any identity drift.
    pub expected_worker_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessingLimits {
    pub max_input_bytes: usize,
    pub max_pages: usize,
    pub max_page_stream_bytes: usize,
    pub max_output_files: usize,
    pub max_output_bytes: u64,
    pub min_native_chars: usize,
    pub min_printable_ratio: f32,
    pub max_replacement_ratio: f32,
    pub min_reading_order_score: f32,
    pub min_ocr_confidence: f32,
    pub max_page_dimension: f32,
}

impl Default for ProcessingLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 20 * 1024 * 1024,
            max_pages: 200,
            max_page_stream_bytes: 16 * 1024 * 1024,
            max_output_files: 10_000,
            max_output_bytes: 64 * 1024 * 1024,
            min_native_chars: 20,
            min_printable_ratio: 0.90,
            max_replacement_ratio: 0.02,
            min_reading_order_score: 0.50,
            min_ocr_confidence: 0.70,
            max_page_dimension: 100_000.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessingError {
    InvalidInput,
    InputTooLarge,
    InvalidRasterImage,
    RasterImageDimensionsExceeded,
    CorruptPdf,
    EncryptedPdf,
    PageLimitExceeded,
    PageContentLimitExceeded,
    OcrRequired,
    OcrDisabled,
    OcrBackendUnavailable,
    OcrWorkerUntrusted,
    OcrWorkerIsolationUnverified,
    OcrProcessContainmentUnavailable,
    OcrConfigUnsafe,
    OcrRuntimeUntrusted,
    OcrRuntimeChanged,
    OcrWorkerProtocolViolation,
    OcrWorkerUnhealthy,
    OcrWorkerIdentityMismatch,
    OcrModelUntrusted,
    OcrTimeout,
    OcrFailed,
    OcrOutputUnsafe,
    OcrOutputTooLarge,
    OcrOutputIncomplete,
    OcrOutputLowConfidence,
    OcrCleanupFailed,
    Cancelled,
}

impl ProcessingError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_material",
            Self::InputTooLarge => "material_too_large",
            Self::InvalidRasterImage => "invalid_raster_image",
            Self::RasterImageDimensionsExceeded => "raster_image_dimensions_exceeded",
            Self::CorruptPdf => "corrupt_pdf",
            Self::EncryptedPdf => "encrypted_pdf",
            Self::PageLimitExceeded => "pdf_page_limit_exceeded",
            Self::PageContentLimitExceeded => "pdf_content_limit_exceeded",
            Self::OcrRequired => "ocr_required",
            Self::OcrDisabled => "ocr_disabled",
            Self::OcrBackendUnavailable => "ocr_backend_unavailable",
            Self::OcrWorkerUntrusted => "ocr_worker_untrusted",
            Self::OcrWorkerIsolationUnverified => "ocr_worker_isolation_unverified",
            Self::OcrProcessContainmentUnavailable => "ocr_process_containment_unavailable",
            Self::OcrConfigUnsafe => "ocr_config_unsafe",
            Self::OcrRuntimeUntrusted => "ocr_runtime_untrusted",
            Self::OcrRuntimeChanged => "ocr_runtime_changed",
            Self::OcrWorkerProtocolViolation => "ocr_worker_protocol_violation",
            Self::OcrWorkerUnhealthy => "ocr_worker_unhealthy",
            Self::OcrWorkerIdentityMismatch => "ocr_worker_identity_mismatch",
            Self::OcrModelUntrusted => "ocr_model_untrusted",
            Self::OcrTimeout => "ocr_timeout",
            Self::OcrFailed => "ocr_failed",
            Self::OcrOutputUnsafe => "ocr_output_unsafe",
            Self::OcrOutputTooLarge => "ocr_output_too_large",
            Self::OcrOutputIncomplete => "ocr_output_incomplete",
            Self::OcrOutputLowConfidence => "ocr_output_low_confidence",
            Self::OcrCleanupFailed => "ocr_cleanup_failed",
            Self::Cancelled => "processing_cancelled",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "The material is not a supported PDF.",
            Self::InputTooLarge => "The material exceeds the processing size limit.",
            Self::InvalidRasterImage => "The PNG or JPEG image is malformed or unsupported.",
            Self::RasterImageDimensionsExceeded => {
                "The image dimensions exceed the safe local OCR limit."
            }
            Self::CorruptPdf => "The PDF is malformed or unsupported.",
            Self::EncryptedPdf => "Encrypted PDFs cannot be processed.",
            Self::PageLimitExceeded => "The PDF exceeds the page limit.",
            Self::PageContentLimitExceeded => "A PDF page exceeds the safe extraction limit.",
            Self::OcrRequired => "Local OCR is required before this material can be used.",
            Self::OcrDisabled => "Local OCR is disabled.",
            Self::OcrBackendUnavailable => "The configured local OCR worker is unavailable.",
            Self::OcrWorkerUntrusted => "The local OCR worker did not pass integrity validation.",
            Self::OcrWorkerIsolationUnverified => {
                "The local OCR worker network isolation has not been verified."
            }
            Self::OcrProcessContainmentUnavailable => {
                "The local OCR worker process tree could not be contained."
            }
            Self::OcrConfigUnsafe => "The local OCR configuration is unsafe.",
            Self::OcrRuntimeUntrusted => "The local OCR runtime allowlist did not pass validation.",
            Self::OcrRuntimeChanged => "The local OCR runtime identity changed during execution.",
            Self::OcrWorkerProtocolViolation => {
                "The local OCR worker violated the versioned IPC protocol."
            }
            Self::OcrWorkerUnhealthy => {
                "The local OCR worker did not pass the bound protocol health checks."
            }
            Self::OcrWorkerIdentityMismatch => {
                "The local OCR worker protocol identity changed after qualification."
            }
            Self::OcrModelUntrusted => "The local OCR model pack did not pass validation.",
            Self::OcrTimeout => "Local OCR exceeded its time limit.",
            Self::OcrFailed => "Local OCR failed.",
            Self::OcrOutputUnsafe => "Local OCR produced an unsafe output tree.",
            Self::OcrOutputTooLarge => "Local OCR output exceeds the size limit.",
            Self::OcrOutputIncomplete => "Local OCR output does not cover every required page.",
            Self::OcrOutputLowConfidence => {
                "Local OCR output contains missing or low-confidence text."
            }
            Self::OcrCleanupFailed => "Local OCR temporary artifacts could not be removed.",
            Self::Cancelled => "Material processing was cancelled.",
        }
    }
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ProcessingError {}
