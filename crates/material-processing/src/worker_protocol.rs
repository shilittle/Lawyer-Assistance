//! Strict, local-only IPC schema for the managed MinerU worker.
//!
//! The wire protocol deliberately exposes opaque identifiers rather than
//! paths. Deserialisation rejects unknown fields and output validation is
//! performed again by the host; a worker's successful exit status or
//! self-reported completeness is never sufficient on its own.

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

pub const MINERU_WORKER_PROTOCOL_V1: &str = "la-mineru-worker-v1";
pub const MAX_PPM: u32 = 1_000_000;

/// An integer confidence or coverage value in parts per million.
///
/// Floating point values are intentionally not accepted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ppm(u32);

impl Ppm {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(MAX_PPM);

    pub const fn new(value: u32) -> Option<Self> {
        if value <= MAX_PPM {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Ppm {
    type Error = PpmOutOfRange;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(PpmOutOfRange)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpmOutOfRange;

impl fmt::Display for PpmOutOfRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ppm value must be in the inclusive range 0..=1000000")
    }
}

impl std::error::Error for PpmOutOfRange {}

impl Serialize for Ppm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for Ppm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PpmVisitor;

        impl Visitor<'_> for PpmVisitor {
            type Value = Ppm;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an integer in the inclusive range 0..=1000000")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = u32::try_from(value)
                    .map_err(|_| E::invalid_value(de::Unexpected::Unsigned(value), &self))?;
                Ppm::new(value).ok_or_else(|| {
                    E::invalid_value(de::Unexpected::Unsigned(u64::from(value)), &self)
                })
            }
        }

        deserializer.deserialize_u32(PpmVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequestV1 {
    Hello {
        protocol_version: String,
        request_id: String,
    },
    Health {
        protocol_version: String,
        request_id: String,
    },
    Ocr {
        protocol_version: String,
        request_id: String,
        job_id: String,
        document_id: String,
        input_id: String,
        expected_output_id: String,
        source_sha256: String,
        processing_parameters_sha256: String,
        expected_page_count: u32,
    },
    Cancel {
        protocol_version: String,
        request_id: String,
        job_id: String,
    },
    Shutdown {
        protocol_version: String,
        request_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerResponseV1 {
    Hello {
        protocol_version: String,
        request_id: String,
        status: WorkerStatusV1,
        identity: Box<WorkerIdentityV1>,
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
    Health {
        protocol_version: String,
        request_id: String,
        status: WorkerStatusV1,
        report: WorkerHealthV1,
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
    Ocr {
        protocol_version: String,
        request_id: String,
        job_id: String,
        payload: OcrResponsePayloadV1,
    },
    Progress {
        protocol_version: String,
        request_id: String,
        job_id: String,
        stage: WorkerProgressStageV1,
        completed_pages: u32,
        total_pages: u32,
        elapsed_ms: u64,
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
    Cancel {
        protocol_version: String,
        request_id: String,
        job_id: String,
        status: WorkerStatusV1,
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
    Shutdown {
        protocol_version: String,
        request_id: String,
        status: WorkerStatusV1,
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatusV1 {
    Ok,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OcrResponsePayloadV1 {
    Completed {
        document: Box<OcrDocumentV1>,
    },
    Blocked {
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
    Cancelled {
        reason_codes: Vec<WorkerReasonCodeV1>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProgressStageV1 {
    Accepted,
    LoadingModels,
    RenderingPages,
    LayoutAnalysis,
    Ocr,
    ValidatingOutput,
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerReasonCodeV1 {
    CancelledByHost,
    ComponentIntegrityFailed,
    ConfigIntegrityFailed,
    GpuUnavailable,
    InputHashMismatch,
    IsolationUnverified,
    ModelIntegrityFailed,
    OutputIncomplete,
    OutputTreeUnsafe,
    ProtocolMismatch,
    QualificationInvalid,
    ResourceLimitExceeded,
    RuntimeUnhealthy,
    WorkerFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentityV1 {
    pub worker_version: String,
    pub worker_sha256: String,
    pub python_version: String,
    pub mineru_version: String,
    pub pytorch_version: String,
    pub cuda_runtime_version: String,
    pub gpu_driver_version: String,
    pub actual_device: WorkerDeviceV1,
    pub model_version: String,
    pub model_manifest_sha256: String,
    pub config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerDeviceV1 {
    Cpu {
        hardware_fingerprint_sha256: String,
    },
    Cuda {
        indices: Vec<u16>,
        hardware_fingerprint_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHealthV1 {
    pub checked_at_unix: u64,
    pub case_material_loaded: bool,
    pub checks: Vec<WorkerHealthCheckV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHealthCheckV1 {
    pub check_id: WorkerHealthCheckIdV1,
    pub passed: bool,
    pub evidence_sha256: String,
    pub reason_codes: Vec<WorkerReasonCodeV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealthCheckIdV1 {
    WorkerIntegrity,
    ConfigIntegrity,
    ModelIntegrity,
    RuntimeVersions,
    GpuRuntime,
    OfflineFlags,
    OsNetworkIsolation,
    JobRootConfinement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrDocumentV1 {
    pub protocol_version: String,
    pub document_id: String,
    pub source_sha256: String,
    pub input_unmodified_sha256: String,
    pub page_count: u32,
    pub pages: Vec<OcrPageV1>,
    pub provenance: OcrProvenanceV1,
    pub warnings: Vec<OcrWarningV1>,
    pub completeness: OcrDocumentCompletenessV1,
    pub output_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrPageV1 {
    pub page_index: u32,
    pub width_micropoints: u64,
    pub height_micropoints: u64,
    pub rotation_degrees: u16,
    pub page_image_sha256: String,
    pub status: OcrPageStatusV1,
    pub blocks: Vec<OcrBlockV1>,
    pub coverage_ppm: Ppm,
    pub minimum_ocr_confidence_ppm: Ppm,
    pub mean_ocr_confidence_ppm: Ppm,
    pub visual_risks: Vec<OcrVisualRiskV1>,
    pub warnings: Vec<OcrWarningV1>,
    pub completeness: OcrPageCompletenessV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrPageStatusV1 {
    Ok,
    VerifiedBlank,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrBlockV1 {
    pub block_id: String,
    pub block_type: OcrBlockTypeV1,
    pub reading_order: u32,
    pub raw_text_ref: String,
    pub normalized_text: String,
    pub bbox: OcrBoundingBoxV1,
    pub polygon: Vec<OcrPointV1>,
    pub coordinate_system: OcrCoordinateSystemV1,
    pub ocr_confidence_ppm: Ppm,
    pub layout_confidence_ppm: Ppm,
    pub confidence_available: bool,
    pub source_locator: OcrSourceLocatorV1,
    pub visual_classification: OcrVisualClassificationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrBlockTypeV1 {
    Text,
    Heading,
    Table,
    Formula,
    ImageCaption,
    Seal,
    Signature,
    Handwriting,
    Screenshot,
    Illustration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrCoordinateSystemV1 {
    PageMicropoints,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrBoundingBoxV1 {
    pub left_micropoints: u64,
    pub top_micropoints: u64,
    pub right_micropoints: u64,
    pub bottom_micropoints: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrPointV1 {
    pub x_micropoints: u64,
    pub y_micropoints: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrSourceLocatorV1 {
    pub page_index: u32,
    pub source_block_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrVisualClassificationV1 {
    Textual,
    Table,
    Formula,
    NonSensitiveIllustration,
    Seal,
    Signature,
    Handwriting,
    Screenshot,
    ComplexTable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrVisualRiskV1 {
    Seal,
    Signature,
    Handwriting,
    Screenshot,
    ComplexTable,
    UnknownVisualRegion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrWarningV1 {
    ComplexLayout,
    LowContrast,
    PartialTextLine,
    SuspectedBlank,
    UnsupportedGlyph,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrPageCompletenessV1 {
    pub dimensions_verified: bool,
    pub page_image_hash_verified: bool,
    pub reading_order_contiguous: bool,
    pub geometry_validated: bool,
    pub confidences_complete: bool,
    pub visual_regions_classified: bool,
    pub output_tree_confined: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrDocumentCompletenessV1 {
    pub input_hash_verified: bool,
    pub page_count_verified: bool,
    pub pages_contiguous: bool,
    pub block_ids_unique: bool,
    pub all_pages_complete: bool,
    pub provenance_complete: bool,
    pub output_tree_confined: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrProvenanceV1 {
    pub worker_version: String,
    pub worker_sha256: String,
    pub protocol_version: String,
    pub python_version: String,
    pub mineru_version: String,
    pub pytorch_version: String,
    pub cuda_runtime_version: String,
    pub gpu_driver_version: String,
    pub requested_device: WorkerDeviceV1,
    pub actual_device: WorkerDeviceV1,
    pub model_version: String,
    pub model_manifest_sha256: String,
    pub config_sha256: String,
    pub isolation_evidence_id: String,
    pub isolation_evidence_sha256: String,
    pub qualification_report_id: String,
    pub processing_parameters_sha256: String,
    pub started_at_unix: u64,
    pub duration_ms: u64,
}

/// Values independently observed or fixed by the host before it accepts OCR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcrValidationExpectationV1 {
    pub document_id: String,
    pub source_sha256: String,
    pub input_unmodified_sha256: String,
    pub page_count: u32,
    pub output_sha256: String,
    pub worker_sha256: String,
    pub model_manifest_sha256: String,
    pub config_sha256: String,
    pub processing_parameters_sha256: String,
    pub isolation_evidence_id: String,
    pub isolation_evidence_sha256: String,
    pub qualification_report_id: String,
    pub output_tree_confined: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OcrIntegrityError {
    ProtocolMismatch,
    InvalidOpaqueId,
    InvalidHash,
    ExpectationMismatch,
    PageCountInvalid,
    PageOrderInvalid,
    PageDimensionsInvalid,
    PageRotationInvalid,
    PageBlocked,
    BlankPageInvalid,
    EmptyPageInvalid,
    BlockCountInvalid,
    DuplicateBlockId,
    ReadingOrderInvalid,
    TextInvalid,
    GeometryInvalid,
    ConfidenceUnavailable,
    ConfidenceSummaryMismatch,
    UnknownVisualRegion,
    VisualClassificationInvalid,
    CompletenessFailed,
    ProvenanceIncomplete,
    ProgressInvalid,
    HealthInvalid,
    ReasonCodesInvalid,
}

impl OcrIntegrityError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProtocolMismatch => "ocr_protocol_mismatch",
            Self::InvalidOpaqueId => "ocr_invalid_opaque_id",
            Self::InvalidHash => "ocr_invalid_hash",
            Self::ExpectationMismatch => "ocr_expectation_mismatch",
            Self::PageCountInvalid => "ocr_page_count_invalid",
            Self::PageOrderInvalid => "ocr_page_order_invalid",
            Self::PageDimensionsInvalid => "ocr_page_dimensions_invalid",
            Self::PageRotationInvalid => "ocr_page_rotation_invalid",
            Self::PageBlocked => "ocr_page_blocked",
            Self::BlankPageInvalid => "ocr_blank_page_invalid",
            Self::EmptyPageInvalid => "ocr_empty_page_invalid",
            Self::BlockCountInvalid => "ocr_block_count_invalid",
            Self::DuplicateBlockId => "ocr_duplicate_block_id",
            Self::ReadingOrderInvalid => "ocr_reading_order_invalid",
            Self::TextInvalid => "ocr_text_invalid",
            Self::GeometryInvalid => "ocr_geometry_invalid",
            Self::ConfidenceUnavailable => "ocr_confidence_unavailable",
            Self::ConfidenceSummaryMismatch => "ocr_confidence_summary_mismatch",
            Self::UnknownVisualRegion => "ocr_unknown_visual_region",
            Self::VisualClassificationInvalid => "ocr_visual_classification_invalid",
            Self::CompletenessFailed => "ocr_completeness_failed",
            Self::ProvenanceIncomplete => "ocr_provenance_incomplete",
            Self::ProgressInvalid => "ocr_progress_invalid",
            Self::HealthInvalid => "ocr_health_invalid",
            Self::ReasonCodesInvalid => "ocr_reason_codes_invalid",
        }
    }
}

impl fmt::Display for OcrIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for OcrIntegrityError {}
