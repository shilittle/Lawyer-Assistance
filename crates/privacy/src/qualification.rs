//! Strict, local-only parsing for MinerU OCR qualification evidence.
//!
//! The PowerShell qualification script proves only that a fixed synthetic
//! canary can be processed. This module deliberately does not treat that as
//! production authorization unless the report also carries the explicit local
//! network, model-trust, and case-OCR authorization gates.

use crate::risk_engine::QualificationSnapshotV1;
use crate::vnext::Sha256Hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const LOCAL_MINERU_QUALIFICATION_SCHEMA_VERSION: u16 = 1;
pub const LOCAL_MINERU_SYNTHETIC_SCOPE: &str = "fixed_synthetic_canary_only";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruQualificationReportV1 {
    pub schema_version: u16,
    pub run_id: String,
    pub completed_at_utc: String,
    pub qualified: bool,
    pub scope: String,
    pub safety: LocalMineruSafetyEvidenceV1,
    pub invocation: LocalMineruInvocationEvidenceV1,
    pub mineru: LocalMineruBinaryEvidenceV1,
    pub gpu: LocalMineruGpuEvidenceV1,
    pub hashes: LocalMineruHashEvidenceV1,
    pub verification: LocalMineruVerificationEvidenceV1,
    pub retention: LocalMineruRetentionEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruSafetyEvidenceV1 {
    pub accepts_user_case_input: bool,
    pub generated_image_only_pdf: bool,
    pub local_model_source_forced: bool,
    pub hugging_face_and_transformers_offline_forced: bool,
    pub invalid_outbound_proxy_forced: bool,
    pub loopback_api_may_start: bool,
    pub network_isolation_enforced: bool,
    pub network_isolation_reason: String,
    pub app_auto_enable_authorized: bool,
    pub production_case_ocr_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruInvocationEvidenceV1 {
    pub profile: String,
    pub method: String,
    pub backend: String,
    pub language: String,
    pub cuda_visible_devices: String,
    pub exit_code: i32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruBinaryEvidenceV1 {
    pub version: String,
    pub command_sha256: Sha256Hex,
    pub launcher_sha256: Sha256Hex,
    pub tools_config_sha256: Sha256Hex,
    pub model_manifest_sha256: Option<Sha256Hex>,
    pub model_manifest_provided: bool,
    pub model_manifest_trust_established: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruGpuEvidenceV1 {
    pub nvidia_smi_sha256: Sha256Hex,
    pub selected_cuda_device: u32,
    pub devices: Vec<LocalMineruGpuDeviceEvidenceV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruGpuDeviceEvidenceV1 {
    pub index: u32,
    pub name: String,
    pub driver_version: String,
    #[serde(rename = "memoryMiB")]
    pub memory_mib: u32,
    pub descriptor_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruHashEvidenceV1 {
    pub script_sha256: Sha256Hex,
    pub generated_input_sha256: Sha256Hex,
    pub expected_text_sha256: Sha256Hex,
    pub content_list_sha256: Sha256Hex,
    pub middle_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruVerificationEvidenceV1 {
    pub output_resolved_within_isolated_root: bool,
    pub page_count: u32,
    pub page_indices: Vec<u32>,
    pub page_size: Vec<u32>,
    pub exact_verified_text_entries: u32,
    pub output_file_count: u32,
    pub output_bytes: u64,
    pub isolated_job_file_count: u32,
    pub isolated_job_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMineruRetentionEvidenceV1 {
    pub keep_artifacts_requested: bool,
    pub artifacts_retained: bool,
    pub artifact_path_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualificationReportError {
    InvalidJson,
    InvalidSchema,
    UnsafeLocator,
    UnboundedOrUnexpectedOutput,
    UnsafeSyntheticCanary,
    CaseInputAccepted,
}

impl std::fmt::Display for QualificationReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJson => "qualification report is not strict JSON",
            Self::InvalidSchema => "qualification report schema is invalid",
            Self::UnsafeLocator => "qualification report contains a path, URL, or external locator",
            Self::UnboundedOrUnexpectedOutput => "qualification report output bounds are invalid",
            Self::UnsafeSyntheticCanary => "qualification report does not match the fixed canary",
            Self::CaseInputAccepted => "qualification report accepted user case input",
        })
    }
}

impl std::error::Error for QualificationReportError {}

pub fn parse_local_mineru_qualification_report(
    bytes: &[u8],
    expected_worker_sha256: Option<&Sha256Hex>,
    expected_model_manifest_sha256: Option<&Sha256Hex>,
    expires_at_unix: Option<u64>,
) -> Result<QualificationSnapshotV1, QualificationReportError> {
    let value = serde_json::from_slice::<Value>(bytes)
        .map_err(|_| QualificationReportError::InvalidJson)?;
    reject_external_locators(&value)?;
    let report = serde_json::from_value::<LocalMineruQualificationReportV1>(value)
        .map_err(|_| QualificationReportError::InvalidSchema)?;
    report.validate_fixed_synthetic_canary()?;

    let report_sha256 = Sha256Hex::parse(crate::sha256_hex(bytes))
        .map_err(|_| QualificationReportError::InvalidSchema)?;
    let worker_matches =
        expected_worker_sha256.is_some_and(|expected| expected == &report.mineru.command_sha256);
    let model_matches = expected_model_manifest_sha256.is_some_and(|expected| {
        report
            .mineru
            .model_manifest_sha256
            .as_ref()
            .is_some_and(|actual| actual == expected)
    });
    let exact_worker_model_match = worker_matches && model_matches;

    Ok(QualificationSnapshotV1 {
        qualification_report_id: Some(report.run_id),
        qualification_report_sha256: Some(report_sha256),
        processing_chain_qualified: report.qualified
            && report.scope == LOCAL_MINERU_SYNTHETIC_SCOPE
            && exact_worker_model_match,
        exact_worker_model_match,
        network_isolation_enforced: report.safety.network_isolation_enforced,
        model_manifest_trust_established: report.mineru.model_manifest_trust_established,
        production_case_ocr_authorized: report.safety.production_case_ocr_authorized,
        expires_at_unix,
        revoked: false,
    })
}

impl LocalMineruQualificationReportV1 {
    fn validate_fixed_synthetic_canary(&self) -> Result<(), QualificationReportError> {
        if self.schema_version != LOCAL_MINERU_QUALIFICATION_SCHEMA_VERSION
            || !is_lower_hex(&self.run_id, 32)
            || !self.completed_at_utc.ends_with('Z')
            || self.scope != LOCAL_MINERU_SYNTHETIC_SCOPE
            || self.invocation.method != "ocr"
            || self.invocation.backend != "pipeline"
            || self.invocation.language != "ch"
            || self.invocation.cuda_visible_devices != "0"
            || self.invocation.exit_code != 0
            || self.mineru.version != "3.4.3"
        {
            return Err(QualificationReportError::InvalidSchema);
        }
        if self.safety.accepts_user_case_input {
            return Err(QualificationReportError::CaseInputAccepted);
        }
        if !self.safety.generated_image_only_pdf
            || !self.safety.local_model_source_forced
            || !self.safety.hugging_face_and_transformers_offline_forced
            || !self.safety.invalid_outbound_proxy_forced
        {
            return Err(QualificationReportError::UnsafeSyntheticCanary);
        }
        if self.gpu.devices.is_empty() || self.gpu.devices.len() > 16 {
            return Err(QualificationReportError::UnsafeSyntheticCanary);
        }
        let mut indices = std::collections::BTreeSet::new();
        for device in &self.gpu.devices {
            let descriptor = crate::sha256_hex(
                format!(
                    "{}|{}|{}|{}",
                    device.index, device.name, device.driver_version, device.memory_mib
                )
                .as_bytes(),
            );
            if !indices.insert(device.index)
                || !valid_gpu_name(&device.name)
                || device.memory_mib < 1024
                || !valid_nvidia_driver_version(&device.driver_version)
                || device.descriptor_sha256.as_str() != descriptor
            {
                return Err(QualificationReportError::UnsafeSyntheticCanary);
            }
        }
        let selected = self
            .gpu
            .devices
            .iter()
            .filter(|device| device.index == self.gpu.selected_cuda_device)
            .collect::<Vec<_>>();
        if self.gpu.selected_cuda_device != 0
            || selected.len() != 1
            || selected[0].memory_mib < 6144
        {
            return Err(QualificationReportError::UnsafeSyntheticCanary);
        }
        if self.verification.page_count != 3
            || self.verification.page_indices != [0, 1, 2]
            || self.verification.page_size != [595, 841]
            || self.verification.exact_verified_text_entries != 24
            || !self.verification.output_resolved_within_isolated_root
            || self.verification.output_file_count == 0
            || self.verification.output_file_count > 128
            || self.verification.output_bytes == 0
            || self.verification.output_bytes > 512 * 1024 * 1024
            || self.verification.isolated_job_file_count == 0
            || self.verification.isolated_job_file_count > 512
            || self.verification.isolated_job_bytes == 0
            || self.verification.isolated_job_bytes > 1024 * 1024 * 1024
        {
            return Err(QualificationReportError::UnboundedOrUnexpectedOutput);
        }
        if self.retention.artifact_path_recorded {
            return Err(QualificationReportError::UnsafeLocator);
        }
        if self.mineru.model_manifest_provided != self.mineru.model_manifest_sha256.is_some() {
            return Err(QualificationReportError::InvalidSchema);
        }
        Ok(())
    }
}

fn reject_external_locators(value: &Value) -> Result<(), QualificationReportError> {
    match value {
        Value::String(value) => {
            if contains_external_locator(value) {
                Err(QualificationReportError::UnsafeLocator)
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_external_locators(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                reject_external_locators(value)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn contains_external_locator(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("file://")
        || lower.contains("ssh://")
        || lower.contains("s3://")
        || value.contains("\\\\")
        || value.contains(":\\")
        || value.contains(":/")
        || value.starts_with('/')
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_nvidia_driver_version(value: &str) -> bool {
    let segments = value.split('.').collect::<Vec<_>>();
    (2..=4).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 5
                && segment.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_gpu_name(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == value
        && (3..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn hash(seed: u8) -> String {
        std::iter::repeat_n(
            char::from_digit((seed % 16) as u32, 16).expect("hex seed"),
            64,
        )
        .collect()
    }

    fn report() -> Value {
        let descriptor = crate::sha256_hex(b"0|NVIDIA GeForce RTX 5090|572.70|32607");
        json!({
            "schemaVersion": 1,
            "runId": "0123456789abcdef0123456789abcdef",
            "completedAtUtc": "2026-07-21T01:02:03Z",
            "qualified": true,
            "scope": LOCAL_MINERU_SYNTHETIC_SCOPE,
            "safety": {
                "acceptsUserCaseInput": false,
                "generatedImageOnlyPdf": true,
                "localModelSourceForced": true,
                "huggingFaceAndTransformersOfflineForced": true,
                "invalidOutboundProxyForced": true,
                "loopbackApiMayStart": true,
                "networkIsolationEnforced": false,
                "networkIsolationReason": "environment flags and invalid proxies are not an OS-level outbound block",
                "appAutoEnableAuthorized": false,
                "productionCaseOcrAuthorized": false
            },
            "invocation": {
                "profile": "mineru -p <generated-canary> -o <isolated-output> -m ocr -b pipeline -l ch",
                "method": "ocr",
                "backend": "pipeline",
                "language": "ch",
                "cudaVisibleDevices": "0",
                "exitCode": 0,
                "durationMs": 1000
            },
            "mineru": {
                "version": "3.4.3",
                "commandSha256": hash(1),
                "launcherSha256": hash(2),
                "toolsConfigSha256": hash(3),
                "modelManifestSha256": hash(4),
                "modelManifestProvided": true,
                "modelManifestTrustEstablished": false
            },
            "gpu": {
                "nvidiaSmiSha256": hash(5),
                "selectedCudaDevice": 0,
                "devices": [{
                    "index": 0,
                    "name": "NVIDIA GeForce RTX 5090",
                    "driverVersion": "572.70",
                    "memoryMiB": 32607,
                    "descriptorSha256": descriptor
                }]
            },
            "hashes": {
                "scriptSha256": hash(6),
                "generatedInputSha256": hash(7),
                "expectedTextSha256": hash(8),
                "contentListSha256": hash(9),
                "middleSha256": hash(10)
            },
            "verification": {
                "outputResolvedWithinIsolatedRoot": true,
                "pageCount": 3,
                "pageIndices": [0, 1, 2],
                "pageSize": [595, 841],
                "exactVerifiedTextEntries": 24,
                "outputFileCount": 3,
                "outputBytes": 4096,
                "isolatedJobFileCount": 5,
                "isolatedJobBytes": 8192
            },
            "retention": {
                "keepArtifactsRequested": false,
                "artifactsRetained": false,
                "artifactPathRecorded": false
            }
        })
    }

    #[test]
    fn synthetic_report_with_false_environment_gates_never_authorizes_production_ocr() {
        let bytes = serde_json::to_vec(&report()).expect("json");
        let worker = Sha256Hex::parse(hash(1)).expect("worker hash");
        let model = Sha256Hex::parse(hash(4)).expect("model hash");

        let snapshot =
            parse_local_mineru_qualification_report(&bytes, Some(&worker), Some(&model), Some(42))
                .expect("report parses");

        assert_eq!(
            snapshot.qualification_report_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(snapshot.processing_chain_qualified);
        assert!(snapshot.exact_worker_model_match);
        assert!(!snapshot.network_isolation_enforced);
        assert!(!snapshot.model_manifest_trust_established);
        assert!(!snapshot.production_case_ocr_authorized);
    }

    #[test]
    fn qualified_true_without_exact_worker_model_match_remains_unqualified() {
        let bytes = serde_json::to_vec(&report()).expect("json");
        let worker = Sha256Hex::parse(hash(11)).expect("worker hash");
        let model = Sha256Hex::parse(hash(12)).expect("model hash");

        let snapshot =
            parse_local_mineru_qualification_report(&bytes, Some(&worker), Some(&model), Some(42))
                .expect("report parses");

        assert!(!snapshot.processing_chain_qualified);
        assert!(!snapshot.exact_worker_model_match);
    }

    #[test]
    fn report_with_user_case_input_or_external_locator_is_rejected() {
        let mut case_input = report();
        case_input["safety"]["acceptsUserCaseInput"] = json!(true);
        let bytes = serde_json::to_vec(&case_input).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::CaseInputAccepted)
        );

        let mut locator = report();
        locator["gpu"]["devices"][0]["diagnosticPath"] = json!("C:\\Users\\case.pdf");
        let bytes = serde_json::to_vec(&locator).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnsafeLocator)
        );
    }

    #[test]
    fn unbounded_output_and_unknown_fields_fail_closed() {
        let mut unbounded = report();
        unbounded["verification"]["outputFileCount"] = json!(129);
        let bytes = serde_json::to_vec(&unbounded).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnboundedOrUnexpectedOutput)
        );

        let mut unknown = report();
        unknown["freeMetadata"] = json!({"anything": "goes"});
        let bytes = serde_json::to_vec(&unknown).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::InvalidSchema)
        );
    }

    #[test]
    fn single_page_or_inexact_canary_text_count_fails_closed() {
        let mut single_page = report();
        single_page["verification"]["pageCount"] = json!(1);
        single_page["verification"]["pageIndices"] = json!([0]);
        let bytes = serde_json::to_vec(&single_page).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnboundedOrUnexpectedOutput)
        );

        let mut inexact_text = report();
        inexact_text["verification"]["exactVerifiedTextEntries"] = json!(23);
        let bytes = serde_json::to_vec(&inexact_text).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnboundedOrUnexpectedOutput)
        );
    }

    #[test]
    fn invalid_or_unbound_gpu_descriptor_fails_closed() {
        let mut unsupported_gpu = report();
        unsupported_gpu["gpu"]["devices"][0]["memoryMiB"] = json!(4096);
        unsupported_gpu["gpu"]["devices"][0]["descriptorSha256"] =
            json!(crate::sha256_hex(b"0|NVIDIA GeForce RTX 5090|572.70|4096"));
        let bytes = serde_json::to_vec(&unsupported_gpu).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnsafeSyntheticCanary)
        );

        let mut wrong_descriptor = report();
        wrong_descriptor["gpu"]["devices"][0]["descriptorSha256"] = json!(hash(15));
        let bytes = serde_json::to_vec(&wrong_descriptor).expect("json");
        assert_eq!(
            parse_local_mineru_qualification_report(&bytes, None, None, Some(42)),
            Err(QualificationReportError::UnsafeSyntheticCanary)
        );
    }
}
