use crate::privacy_manager::{LocalOcrStatus, OcrMode as ConfigOcrMode, PrivacyConfig};
use file_ingest::FileFormat;
use material_processing::{
    approved_text_sha256, reconstruct_approved_text_pdf, ApprovedTextPage, BackendTrace,
    ExtractionBackend, LocalMineruConfig, OcrMode, PageExtractionDecision, ProcessedSpan,
    ProcessingError, ProcessingLimits, QualityReasonCode, SafePdfArtifact, SafePdfExportError,
    SafePdfExportLimits, SafePdfExportRequest, SpanKind, TextLayerAssessment,
};
use material_processing::{InputTransformTrace, RasterImageFormat};
use privacy::risk_engine::{
    DocumentAssessmentV1, PageAssessmentV1, QualificationSnapshotV1, RequestedApprovalRoute,
    RiskPolicyV1,
};
use privacy::vnext::{
    canonical_json_v1, AutoApprovalPolicyMode, CaseId, ConfidencePpm, FindingSeverity, MaterialId,
    PrivacyFindingV1, Sha256Hex, WorkspaceInstanceId,
};
use privacy::{
    scan_residual, sha256_hex, vault_store::VaultIsolationStatusV1, ActiveReceiptVerification,
    BindingCreationSource, BindingLifecycleContext, CleanupReportV1, DataClassification,
    DestinationKind, DestinationScope, EgressCandidate, EgressPolicyEngine, LifecycleError,
    PrivacyCaseId, PrivacyEgressAuditRecord, PrivacyLifecycle, PrivacyStore, PrivacyStoreError,
    PrivacyStoreSchemaStatus, ProjectId, ProjectPrivacyCaseBindingError,
    ProjectPrivacyCaseBindingStore, ReceiptSigner, RedactionOptions, RedactionReceiptClaims,
    RedactionSummary, Redactor, RegisterPrivacyMaterial, ReviewActionV1, ReviewSessionInputV1,
    ReviewSessionV1, ReviewState, ReviewStateViewV1, SaveReviewDraft, SaveRiskReviewRevision,
    SensitiveMappingEntryV1, SensitiveMappingPayloadV1, VaultCleanupReportV1,
    VerifiedReviewActionContextV1, LOGICAL_ERASURE_DISCLOSURE, REDACTION_VERSION,
};
use providers::{
    windows_credentials::WindowsCredentialStore, ApiSecret, CredentialStore, ProviderCredentialKey,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};

mod approved_case_projection;
mod approved_provider;
pub(crate) mod approved_workspace;
mod case_assistant;
mod case_dictionary_store;
mod case_material_migration;
mod case_materials;
mod lifecycle_admin;
mod local_detection;
mod project_deletion;
mod provider_qualification;
mod safe_derived;
mod vault_broker;
pub(crate) use approved_case_projection::{
    V031ApprovedProjectionSourceProof, V031PrivacyV6TerminalProof,
};
#[allow(unused_imports)]
pub use approved_provider::{
    ApproveApprovedProviderTaskRequest, ApproveApprovedProviderTaskResponse,
    ApprovedProviderOutput, ApprovedProviderOutputSummary, ApprovedProviderPriorOutputRef,
    ApprovedProviderTask, DispatchApprovedProviderRequest, DispatchApprovedProviderResponse,
    ListApprovedProviderOutputsRequest, LoadApprovedProviderOutputRequest,
    RevokeApprovedProviderOutputRequest,
};
pub(crate) use case_assistant::{
    CaseAssistantDispatchOutputKind, CaseAssistantDispatchRequest, CaseAssistantDispatchResponse,
};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use case_material_migration::BackfillFailurePoint;
pub(crate) use case_material_migration::{
    reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only,
    V031BindingMaterialTerminalProof, V031CaseMigrationCheckpointSourceProof,
};
pub use case_materials::{
    ApplyCaseRedactionRiskReviewActionRequest, ApproveCaseRedactionReviewRequest,
    AssignUnassignedCaseMaterialRequest, AssignUnassignedCaseMaterialResponse, CaseMaterialSummary,
    CaseRedactionGenerationSummary, CaseRedactionReviewView,
    CaseRedactionRiskReviewRevisionRequest, DeleteCaseRedactionReviewRequest,
    ExportApprovedCaseRedactionRequest, ListCaseMaterialsRequest,
    ListCaseRedactionGenerationsRequest, ListUnassignedCaseMaterialsRequest,
    LoadCaseRedactionReviewRequest, PrepareCaseMaterialRequest, PrepareCaseMaterialResponse,
    UnassignedCaseMaterialSummary,
};
pub(crate) use lifecycle_admin::{
    apply_observed_pending_privacy_restore, observe_current_privacy_profile_read_only,
    observe_pending_privacy_restore_read_only, CurrentPrivacyProfileObservation,
    CurrentPrivacyProfileProof, PendingPrivacyRestoreGate, PendingPrivacyRestoreObservation,
};
pub use lifecycle_admin::{
    BackupIdRequest, CleanupReportView, DestroyMappingKeyRequest, LifecycleStatusRequest,
    LifecycleStatusView, RetentionPolicyView, RevealMappingRequest, RevealMappingResponse,
    RevokeMappingRequest, RotateMappingKeyRequest, RunRetentionSweepRequest, SetLegalHoldRequest,
    SetRetentionPolicyRequest, StagePrivacyRestoreRequest, VerifiedBackupView,
};
pub use provider_qualification::{
    ProviderQualificationRequest, ProviderQualificationRunRequest, ProviderQualificationStatus,
};
pub use safe_derived::{export_reason, ExportApprovedPrivacyReviewRequest, SafeExportFormat};
#[allow(unused_imports)]
pub(crate) use vault_broker::{
    load_v031_vault_historical_target_from_checkpoint_read_only,
    load_v031_vault_target_component_read_only, observe_current_vault_read_only,
    observe_v031_vault_target_absent_read_only, observe_v031_vault_target_namespace_read_only,
    prepare_v031_vault_target_component, verify_v031_vault_target_component_read_only,
    CurrentVaultObservation, CurrentVaultProof, V031VaultHistoricalTargetRecord,
    V031VaultTargetAbsentGate, V031VaultTargetComponentError, V031VaultTargetComponentGate,
    V031VaultTargetIncompleteGate, V031VaultTargetNamespaceObservation,
};
#[cfg(test)]
pub(crate) use vault_broker::{
    prepare_v031_vault_target_component_with_writer_failure_for_test,
    V031VaultTargetWriterFailurePoint,
};

const PRIVACY_DIRECTORY_NAME: &str = "privacy";
const PRIVACY_DATABASE_NAME: &str = "privacy-workflow.sqlite";
const MAX_SELECTED_FILE_BYTES: u64 = file_ingest::MAX_FILE_BYTES as u64;
const FILE_INGEST_PROCESSING_VERSION: &str = "lawyer-assistance-file-ingest-v1";
const POLICY_ID: &str = "cn-legal-default";
const POLICY_VERSION: u32 = 1;
const REVIEW_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const RISK_WORKFLOW_STATE_SCHEMA_VERSION: &str = "privacy-risk-workflow-state-v1";
const APPROVED_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const RECEIPT_KEY_VERSION: u32 = 1;
const RECEIPT_KEY_SERVICE: &str = "LawyerAssistancePrivacy";
const RECEIPT_KEY_PROVIDER: &str = "redaction-receipt-signing";
const RECEIPT_KEY_ACCOUNT: &str = "v1";
#[allow(dead_code)]
const LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER: &str = "local-safe-pdf-export-v1";
#[allow(dead_code)]
const LOCAL_SAFE_PDF_PURPOSE: &str = "local_safe_pdf_export";
const MAX_FORBIDDEN_CANARIES: usize = 10_000;
const MAX_SINGLE_CANARY_BYTES: usize = 16 * 1024;
const MAX_TOTAL_CANARY_BYTES: usize = 4 * 1024 * 1024;
const MIN_RECEIPT_TTL_SECONDS: u64 = 5 * 60;
const MAX_RECEIPT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyWorkflowError {
    code: &'static str,
    message: String,
}

impl PrivacyWorkflowError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: providers::redact_sensitive(&message.into()),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    fn processing(error: ProcessingError) -> Self {
        let message = match error {
            ProcessingError::OcrDisabled => {
                "该 PDF 缺少可用文本层，而本地 OCR 已关闭；材料未处理。"
            }
            ProcessingError::OcrBackendUnavailable => {
                "该 PDF 需要 OCR，但本地 MinerU、模型完整性与网络隔离尚未全部认证；材料未处理。"
            }
            ProcessingError::OcrWorkerIsolationUnverified => {
                "本地 OCR 的网络隔离没有认证；材料未处理。"
            }
            ProcessingError::OcrWorkerUntrusted | ProcessingError::OcrModelUntrusted => {
                "本地 OCR 组件或模型未通过完整性认证；材料未处理。"
            }
            ProcessingError::OcrRequired => "该 PDF 需要本地 OCR；材料未处理。",
            ProcessingError::InputTooLarge => "所选 PDF 超过本地处理大小上限。",
            ProcessingError::PageLimitExceeded => "所选 PDF 超过配置的最大页数。",
            ProcessingError::EncryptedPdf => "暂不处理加密 PDF。",
            ProcessingError::CorruptPdf | ProcessingError::InvalidInput => {
                "所选文件不是可安全解析的 PDF。"
            }
            _ => "本地 PDF 处理失败；未进行远程或云端回退。",
        };
        Self::new(error.code(), message)
    }

    fn store(error: PrivacyStoreError) -> Self {
        Self::new(error.code(), "本机隐私数据库操作失败。")
    }

    fn lifecycle(error: LifecycleError) -> Self {
        Self::new(error.code(), "本机隐私生命周期操作失败。")
    }

    fn vault(error: privacy::vault_store::VaultStoreError) -> Self {
        Self::new(
            error.code(),
            "本机加密案卷库操作失败；未进行明文或网络回退。",
        )
    }

    fn project_case_binding(error: ProjectPrivacyCaseBindingError) -> Self {
        Self::new(error.code(), "案件与隐私工作区身份绑定校验失败。")
    }
}

fn ensure_standalone_restore_lineage_safe(
    app_local_data_directory: &Path,
) -> Result<(), PrivacyWorkflowError> {
    crate::commands::application_backup::ensure_standalone_restore_is_lineage_safe(
        app_local_data_directory,
    )
    .map_err(|error| {
        PrivacyWorkflowError::new("privacy_restore_requires_five_components", error.message)
    })
}

impl fmt::Display for PrivacyWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PrivacyWorkflowError {}

pub type PreparePrivacyMaterialRequest = PrepareCaseMaterialRequest;
pub type PreparePrivacyMaterialResponse = PrepareCaseMaterialResponse;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
pub struct LoadPrivacyReviewRequest {
    pub redaction_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyPrivacyRiskReviewActionRequest {
    pub redaction_id: String,
    pub expected_revision: u64,
    pub actor: String,
    pub edited_pages: Vec<EditedRedactedPage>,
    pub action: ReviewActionV1,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyRiskReviewRevisionRequest {
    pub redaction_id: String,
    pub expected_revision: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeletePrivacyReviewRequest {
    pub redaction_id: String,
    pub expected_source_sha256: String,
    pub expected_extraction_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeletePrivacyReviewResponse {
    pub deleted: bool,
}

/// Public-safe pointer to the real encrypted mapping revision. It contains no mapping plaintext
/// and is intended for exact downstream binding (for example, a future approved-MCP ticket).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct CurrentMappingRevisionBindingV1 {
    pub mapping_id: String,
    pub revision: u64,
    pub mapping_revision_hash: Sha256Hex,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewPageView {
    pub page_number: u32,
    pub locator: String,
    pub assessment: TextLayerAssessment,
    pub original_text: String,
    pub redacted_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyReviewView {
    pub redaction_id: String,
    pub material_id: String,
    pub case_id: Option<String>,
    pub vault_object_id: Option<String>,
    pub vault_object_version: Option<u64>,
    pub vault_isolation: Option<VaultIsolationStatusV1>,
    pub source_display_name: String,
    pub source_sha256: String,
    pub extraction_sha256: String,
    pub suggested_redacted_content_sha256: String,
    pub processing_version: String,
    pub media_type: String,
    pub page_count: u32,
    pub input_transform: Option<InputTransformTrace>,
    pub backend_trace: Vec<BackendTrace>,
    pub summary: RedactionSummary,
    pub review_state: String,
    pub pages: Vec<ReviewPageView>,
    pub risk_review: Option<ReviewStateViewV1>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedPrivacyReviewSelection {
    pub redaction_id: String,
    pub material_id: String,
    pub project_id: String,
    pub approved_payload_sha256: String,
    pub mcp_publish_approved: bool,
    pub mcp_publish_approval_expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveReviewForApprovedWorkspaceRequest {
    pub redaction_id: String,
    pub expected_approved_payload_sha256: String,
    pub reviewer: String,
    pub ttl_seconds: u64,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApproveReviewForApprovedWorkspaceResponse {
    pub receipt_id: String,
    pub approved_payload_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub destination_identifier: String,
    pub purpose: String,
    pub mcp_publish_approved: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditedRedactedPage {
    pub page_number: u32,
    pub redacted_text: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptDestinationInput {
    pub kind: DestinationKind,
    pub identifier: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovePrivacyReviewRequest {
    pub redaction_id: String,
    #[serde(default)]
    pub expected_risk_revision: Option<u64>,
    pub expected_suggested_redacted_sha256: String,
    pub edited_pages: Vec<EditedRedactedPage>,
    pub reviewer: String,
    pub destination: ReceiptDestinationInput,
    pub purpose: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovePrivacyReviewResponse {
    pub receipt_id: String,
    #[serde(skip_serializing)]
    pub receipt_token: String,
    #[serde(skip_serializing)]
    pub approved_payload_json: String,
    pub approved_payload_sha256: String,
    pub redacted_content_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub destination: DestinationScope,
    pub purpose: String,
    pub transport_enforcement: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportApprovedReviewPdfRequest {
    pub redaction_id: String,
    pub receipt_token: String,
    pub approved_payload_json: String,
    pub destination: ReceiptDestinationInput,
    pub purpose: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct BuiltSafePdf {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub approved_text_sha256: String,
    pub extracted_text_sha256: String,
    pub output_page_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredReviewPage {
    page_number: u32,
    locator: String,
    assessment: TextLayerAssessment,
    spans: Vec<ProcessedSpan>,
    original_text: String,
    suggested_redacted_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredReviewPayload {
    schema_version: u16,
    material_id: String,
    redaction_id: String,
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    vault_object_id: Option<String>,
    #[serde(default)]
    vault_object_version: Option<u64>,
    #[serde(default)]
    vault_isolation: Option<VaultIsolationStatusV1>,
    /// Sensitive filenames remain inside the encrypted review payload. Public SQLite rows keep
    /// only `source_name_sha256`.
    #[serde(default)]
    source_display_name: String,
    source_sha256: String,
    extraction_sha256: String,
    suggested_redacted_content_sha256: String,
    processing_version: String,
    media_type: String,
    page_count: u32,
    #[serde(default)]
    input_transform: Option<InputTransformTrace>,
    backend_trace: Vec<BackendTrace>,
    summary: RedactionSummary,
    forbidden_canaries: Vec<String>,
    pages: Vec<StoredReviewPage>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalExtractedDocument {
    processing_version: String,
    source_sha256: String,
    media_type: String,
    page_count: u32,
    backend_trace: Vec<BackendTrace>,
    input_transform: Option<InputTransformTrace>,
    segments: Vec<LocalExtractedSegment>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalExtractedSegment {
    page_number: u32,
    locator: String,
    assessment: TextLayerAssessment,
    spans: Vec<ProcessedSpan>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalRedactedContent<'a> {
    schema_version: u16,
    pages: &'a [CanonicalRedactedPage],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalRedactedPage {
    page_number: u32,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovedPayload<'a> {
    schema_version: u16,
    source_sha256: &'a str,
    extraction_sha256: &'a str,
    media_type: &'a str,
    pages: &'a [CanonicalRedactedPage],
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicationTargetBindingV1<'a> {
    schema_version: &'static str,
    destination_kind: &'a DestinationKind,
    destination_identifier: &'a str,
    purpose: &'a str,
    approved_payload_sha256: &'a str,
    redacted_content_sha256: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedApprovedPayload {
    schema_version: u16,
    source_sha256: String,
    extraction_sha256: String,
    media_type: String,
    pages: Vec<CanonicalRedactedPage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRiskWorkflowStateV1 {
    schema_version: String,
    session: ReviewSessionV1,
    current_pages: Vec<CanonicalRedactedPage>,
    undo_pages: Vec<Vec<CanonicalRedactedPage>>,
    redo_pages: Vec<Vec<CanonicalRedactedPage>>,
}

struct PrepareMaterialBytesInput<'a> {
    bytes: &'a [u8],
    source_display_name: String,
    config: &'a PrivacyConfig,
    ocr_status: &'a LocalOcrStatus,
    mineru_config: Option<&'a LocalMineruConfig>,
    ocr_qualification: Option<&'a QualificationSnapshotV1>,
    custom_terms: Vec<String>,
    vault_binding: Option<&'a vault_broker::VaultImportBinding>,
}
#[derive(Clone, Copy)]
pub struct LocalOcrExecutionContext<'a> {
    pub mineru_config: Option<&'a LocalMineruConfig>,
    pub qualification: Option<&'a QualificationSnapshotV1>,
}

#[derive(Clone)]
pub struct PrivacyWorkflowManager {
    shared: Arc<PrivacyWorkflowShared>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031Step8PrivacyMaintenanceReport {
    pub(crate) cutoff_unix: u64,
    pub(crate) retention_cleanup: CleanupReportV1,
    pub(crate) vault_cleanup: VaultCleanupReportV1,
    pub(crate) pending_project_deletions_after: u64,
    pub(crate) pending_retention_cleanups_after: u64,
    pub(crate) pending_vault_prepared_after: u64,
    pub(crate) pending_vault_committed_after: u64,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct V031Step8ExpiredVaultObjectFixture {
    binding: vault_broker::VaultAuxBinding,
    plaintext: Vec<u8>,
}

#[cfg(test)]
impl V031Step8ExpiredVaultObjectFixture {
    pub(crate) fn case_id(&self) -> &CaseId {
        &self.binding.case_id
    }

    pub(crate) fn object_id(&self) -> &privacy::vnext::ObjectId {
        &self.binding.object_id
    }

    pub(crate) const fn object_version(&self) -> u64 {
        self.binding.object_version
    }

    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// These names describe the frozen durable crash boundaries verbatim.
#[allow(clippy::enum_variant_names)]
pub(crate) enum V031Step8MaintenanceFailurePoint {
    AfterRetentionPreparedBeforeInvalidation,
    AfterRetentionCommittedBeforeVault,
    AfterVaultPreparedBeforeCommit,
    AfterVaultCommittedBeforeFinalize,
    AfterVaultPhysicalPurgeBeforeJournalCommit,
}

pub(crate) trait V031Step8MaintenanceFailureInjector: Send + Sync {
    fn should_fail(&self, point: V031Step8MaintenanceFailurePoint) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopV031Step8MaintenanceFailureInjector;

impl V031Step8MaintenanceFailureInjector for NoopV031Step8MaintenanceFailureInjector {
    fn should_fail(&self, _point: V031Step8MaintenanceFailurePoint) -> bool {
        false
    }
}

pub(crate) trait ApprovedPublicationInvalidator: Send + Sync {
    fn invalidate_case(
        &self,
        case_id: &CaseId,
        reason_code: &'static str,
    ) -> Result<u64, &'static str>;

    fn invalidate_material(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        reason_code: &'static str,
    ) -> Result<u64, &'static str>;

    fn invalidate_all(&self, reason_code: &'static str) -> Result<u64, &'static str>;

    /// Revokes and physically cleans only approved artifacts bound to the supplied App-local
    /// redaction generations. Retention must never widen this operation to a case or workspace.
    fn invalidate_lifecycle_bindings(
        &self,
        lifecycle_binding_ids: &BTreeSet<String>,
        reason_code: &'static str,
    ) -> Result<u64, &'static str>;
}

struct PrivacyWorkflowShared {
    database_path: PathBuf,
    user_database_path: PathBuf,
    workspace_instance_id: WorkspaceInstanceId,
    provider_qualification_root: PathBuf,
    vault_broker: Arc<dyn vault_broker::VaultBroker>,
    approved_publication_invalidator: Option<Arc<dyn ApprovedPublicationInvalidator>>,
    operation_gate: Mutex<()>,
    mapping_reveal_authorizations: Mutex<BTreeMap<String, u64>>,
    receipt_signer_override: Mutex<Option<ReceiptSigner>>,
    provider_qualification_key_override:
        Mutex<Option<Arc<dyn provider_qualification::ProviderQualificationKeyProvider>>>,
    now_unix_override: Mutex<Option<u64>>,
    schema_upgrade_required: AtomicBool,
}

pub(crate) struct ApplicationBackupPrivacyGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl fmt::Debug for PrivacyWorkflowManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyWorkflowManager")
            .field("database", &"<local-privacy-store>")
            .finish()
    }
}

#[cfg(test)]
pub(crate) fn test_workspace_instance_id() -> WorkspaceInstanceId {
    WorkspaceInstanceId::parse("ws_90909090909090909090909090909090")
        .expect("static test workspace identifier")
}
impl PrivacyWorkflowManager {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(
        app_local_data_directory: PathBuf,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, PrivacyWorkflowError> {
        Self::new_internal(app_local_data_directory, workspace_instance_id, None, false)
    }

    #[allow(dead_code)]
    pub(crate) fn new_with_approved_publication_invalidator(
        app_local_data_directory: PathBuf,
        workspace_instance_id: WorkspaceInstanceId,
        invalidator: Arc<dyn ApprovedPublicationInvalidator>,
    ) -> Result<Self, PrivacyWorkflowError> {
        Self::new_internal(
            app_local_data_directory,
            workspace_instance_id,
            Some(invalidator),
            false,
        )
    }

    pub(crate) fn new_for_application_startup_with_approved_publication_invalidator(
        app_local_data_directory: PathBuf,
        workspace_instance_id: WorkspaceInstanceId,
        invalidator: Arc<dyn ApprovedPublicationInvalidator>,
    ) -> Result<Self, PrivacyWorkflowError> {
        Self::new_internal(
            app_local_data_directory,
            workspace_instance_id,
            Some(invalidator),
            true,
        )
    }

    fn new_internal(
        app_local_data_directory: PathBuf,
        workspace_instance_id: WorkspaceInstanceId,
        approved_publication_invalidator: Option<Arc<dyn ApprovedPublicationInvalidator>>,
        defer_startup_maintenance: bool,
    ) -> Result<Self, PrivacyWorkflowError> {
        let user_database_path = database::user_database_path(&app_local_data_directory);
        let directory = app_local_data_directory.join(PRIVACY_DIRECTORY_NAME);
        let privacy_directory_present = match fs::symlink_metadata(&directory) {
            Ok(_) => {
                validate_ordinary_directory(&directory)?;
                true
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && defer_startup_maintenance =>
            {
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&directory).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_store_unavailable",
                        "本机隐私数据库目录无法创建。",
                    )
                })?;
                validate_ordinary_directory(&directory)?;
                true
            }
            Err(_) => {
                return Err(PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "The local privacy directory could not be inspected.",
                ))
            }
        };
        if privacy_directory_present
            && lifecycle_admin::observe_pending_privacy_restore_read_only(
                &app_local_data_directory,
            )? != lifecycle_admin::PendingPrivacyRestoreObservation::Absent
        {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_requires_startup_router",
                "An authenticated Privacy restore must be applied by startup arbitration before a workflow manager is constructed.",
            ));
        }
        let vault_broker: Arc<dyn vault_broker::VaultBroker> = if defer_startup_maintenance {
            Arc::new(
                vault_broker::LocalEncryptedVaultBroker::open_for_application_startup(
                    &app_local_data_directory,
                    workspace_instance_id.clone(),
                )
                .map_err(PrivacyWorkflowError::vault)?,
            )
        } else {
            Arc::new(
                vault_broker::LocalEncryptedVaultBroker::initialize(
                    &app_local_data_directory,
                    workspace_instance_id.clone(),
                )
                .map_err(PrivacyWorkflowError::vault)?,
            )
        };
        let manager = Self {
            shared: Arc::new(PrivacyWorkflowShared {
                database_path: directory.join(PRIVACY_DATABASE_NAME),
                user_database_path,
                workspace_instance_id,
                provider_qualification_root: directory.join("provider-qualification"),
                vault_broker,
                approved_publication_invalidator,
                operation_gate: Mutex::new(()),
                mapping_reveal_authorizations: Mutex::new(BTreeMap::new()),
                receipt_signer_override: Mutex::new(None),
                provider_qualification_key_override: Mutex::new(None),
                now_unix_override: Mutex::new(None),
                schema_upgrade_required: AtomicBool::new(false),
            }),
        };
        let schema_status = manager.preflight_privacy_store_schema_read_only()?;
        if matches!(
            schema_status,
            PrivacyStoreSchemaStatus::UpgradeRequired { .. }
        ) {
            manager
                .shared
                .schema_upgrade_required
                .store(true, Ordering::Release);
            validate_ordinary_database_file(&manager.shared.database_path)?;
            return Ok(manager);
        }
        if defer_startup_maintenance {
            if !matches!(schema_status, PrivacyStoreSchemaStatus::Empty) {
                validate_ordinary_database_file(&manager.shared.database_path)?;
            }
            return Ok(manager);
        }
        let mut connection = manager.open_connection()?;
        manager.run_startup_maintenance(&mut connection)?;
        drop(connection);
        validate_ordinary_database_file(&manager.shared.database_path)?;
        Ok(manager)
    }

    fn run_startup_maintenance(
        &self,
        connection: &mut Connection,
    ) -> Result<(), PrivacyWorkflowError> {
        let now_unix = unix_now()?;
        self.shared
            .vault_broker
            .recover_cleanups(now_unix)
            .map_err(PrivacyWorkflowError::vault)?;
        let lifecycle = PrivacyLifecycle::initialize(
            connection,
            self.shared.workspace_instance_id.clone(),
            now_unix,
        )
        .map_err(PrivacyWorkflowError::lifecycle)?;
        self.recover_pending_project_deletions_unlocked(connection)?;
        self.recover_prepared_retention_sweeps(
            &lifecycle,
            connection,
            now_unix,
            "privacy_retention_startup_recovery",
        )?;
        self.run_retention_sweep_with_publication_invalidation(
            &lifecycle,
            connection,
            &format!("cln_{}", Uuid::new_v4().simple()),
            now_unix,
            "privacy_retention_startup_cleanup",
        )?;
        self.shared
            .vault_broker
            .run_or_resume_expired_cleanup(&format!("cln_{}", Uuid::new_v4().simple()), now_unix)
            .map_err(PrivacyWorkflowError::vault)?;
        Ok(())
    }

    pub(super) fn invalidate_case_publications(
        &self,
        case_id: &CaseId,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyWorkflowError> {
        self.shared
            .approved_publication_invalidator
            .as_ref()
            .map(|invalidator| invalidator.invalidate_case(case_id, reason_code))
            .transpose()
            .map_err(approved_publication_invalidation_error)
            .map(|count| count.unwrap_or(0))
    }

    fn invalidate_material_publications(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyWorkflowError> {
        self.shared
            .approved_publication_invalidator
            .as_ref()
            .map(|invalidator| invalidator.invalidate_material(case_id, material_id, reason_code))
            .transpose()
            .map_err(approved_publication_invalidation_error)
            .map(|count| count.unwrap_or(0))
    }

    pub(super) fn invalidate_all_publications(
        &self,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyWorkflowError> {
        self.shared
            .approved_publication_invalidator
            .as_ref()
            .map(|invalidator| invalidator.invalidate_all(reason_code))
            .transpose()
            .map_err(approved_publication_invalidation_error)
            .map(|count| count.unwrap_or(0))
    }

    fn invalidate_lifecycle_bindings(
        &self,
        lifecycle_binding_ids: &BTreeSet<String>,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyWorkflowError> {
        if lifecycle_binding_ids.is_empty() {
            return Ok(0);
        }
        self.shared
            .approved_publication_invalidator
            .as_ref()
            .map(|invalidator| {
                invalidator.invalidate_lifecycle_bindings(lifecycle_binding_ids, reason_code)
            })
            .transpose()
            .map_err(approved_publication_invalidation_error)
            .map(|count| count.unwrap_or(0))
    }

    fn run_retention_sweep_with_publication_invalidation(
        &self,
        lifecycle: &PrivacyLifecycle,
        connection: &mut Connection,
        cleanup_id: &str,
        now_unix: u64,
        reason_code: &'static str,
    ) -> Result<privacy::CleanupReportV1, PrivacyWorkflowError> {
        lifecycle
            .prepare_retention_sweep(connection, cleanup_id, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let lifecycle_binding_ids = lifecycle
            .revalidate_prepared_retention_sweep_for_external_invalidation(
                connection, cleanup_id, now_unix,
            )
            .map_err(PrivacyWorkflowError::lifecycle)?
            .ok_or_else(|| PrivacyWorkflowError::lifecycle(LifecycleError::CleanupIntegrity))?;
        self.invalidate_lifecycle_bindings(&lifecycle_binding_ids, reason_code)?;
        lifecycle
            .commit_retention_sweep(connection, cleanup_id, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    fn recover_prepared_retention_sweeps(
        &self,
        lifecycle: &PrivacyLifecycle,
        connection: &mut Connection,
        recovered_at_unix: u64,
        reason_code: &'static str,
    ) -> Result<Vec<privacy::CleanupReportV1>, PrivacyWorkflowError> {
        let cleanup_ids = prepared_retention_cleanup_ids(connection)?;
        let mut reports = Vec::with_capacity(cleanup_ids.len());
        for cleanup_id in cleanup_ids {
            let Some(lifecycle_binding_ids) = lifecycle
                .revalidate_prepared_retention_sweep_for_external_invalidation(
                    connection,
                    &cleanup_id,
                    recovered_at_unix,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?
            else {
                continue;
            };
            self.invalidate_lifecycle_bindings(&lifecycle_binding_ids, reason_code)?;
            reports.push(
                lifecycle
                    .commit_retention_sweep(connection, &cleanup_id, recovered_at_unix)
                    .map_err(PrivacyWorkflowError::lifecycle)?,
            );
        }
        Ok(reports)
    }

    fn gate(&self) -> MutexGuard<'_, ()> {
        self.shared
            .operation_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn begin_application_backup_pair(&self) -> ApplicationBackupPrivacyGuard<'_> {
        ApplicationBackupPrivacyGuard {
            _guard: self.gate(),
        }
    }

    pub(crate) fn export_encrypted_vault_backup_locked(
        &self,
        _guard: &ApplicationBackupPrivacyGuard<'_>,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError> {
        self.shared.vault_broker.export_encrypted_backup()
    }

    fn privacy_lifecycle(
        &self,
        connection: &Connection,
    ) -> Result<PrivacyLifecycle, PrivacyWorkflowError> {
        PrivacyLifecycle::open(connection, self.shared.workspace_instance_id.clone())
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    fn receipt_signer(&self) -> Result<ReceiptSigner, PrivacyWorkflowError> {
        let override_signer = self
            .shared
            .receipt_signer_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        override_signer.map_or_else(load_or_create_receipt_signer, Ok)
    }

    fn current_unix(&self) -> Result<u64, PrivacyWorkflowError> {
        let override_now = *self
            .shared
            .now_unix_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        override_now.map_or_else(unix_now, Ok)
    }

    #[cfg(test)]
    pub(crate) fn set_test_runtime(&self, signer: ReceiptSigner, now_unix: u64) {
        *self
            .shared
            .receipt_signer_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(signer);
        *self
            .shared
            .now_unix_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now_unix);
    }

    #[cfg(test)]
    pub(crate) fn seed_v031_step8_expired_vault_object_for_test(
        &self,
        case_id: CaseId,
        plaintext: Vec<u8>,
    ) -> Result<V031Step8ExpiredVaultObjectFixture, PrivacyWorkflowError> {
        let binding = self
            .shared
            .vault_broker
            .seal_aux_payload(&case_id, "v031-step8-expired-fixture", &plaintext, 1)
            .map_err(PrivacyWorkflowError::vault)?;
        self.shared
            .vault_broker
            .bind_aux_retention(&binding, 2, false, 1, 1)
            .map_err(PrivacyWorkflowError::vault)?;
        Ok(V031Step8ExpiredVaultObjectFixture { binding, plaintext })
    }

    #[cfg(test)]
    pub(crate) fn read_v031_step8_vault_object_for_test(
        &self,
        fixture: &V031Step8ExpiredVaultObjectFixture,
    ) -> Result<Vec<u8>, PrivacyWorkflowError> {
        self.shared
            .vault_broker
            .read_aux_payload(&fixture.binding)
            .map(|lease| lease.content().to_vec())
            .map_err(PrivacyWorkflowError::vault)
    }

    #[cfg(test)]
    fn set_test_provider_qualification_keys(
        &self,
        keys: Arc<dyn provider_qualification::ProviderQualificationKeyProvider>,
    ) {
        *self
            .shared
            .provider_qualification_key_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(keys);
    }

    #[cfg(test)]
    fn set_test_now(&self, now_unix: u64) {
        *self
            .shared
            .now_unix_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now_unix);
    }

    fn open_raw_connection(&self) -> Result<Connection, PrivacyWorkflowError> {
        let connection = Connection::open(&self.shared.database_path).map_err(|_| {
            PrivacyWorkflowError::new("privacy_store_unavailable", "本机隐私数据库无法打开。")
        })?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA recursive_triggers=ON;
                 PRAGMA synchronous=FULL;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "本机隐私数据库无法进入安全模式。",
                )
            })?;
        Ok(connection)
    }

    fn preflight_privacy_store_schema_read_only(
        &self,
    ) -> Result<PrivacyStoreSchemaStatus, PrivacyWorkflowError> {
        match fs::symlink_metadata(&self.shared.database_path) {
            Ok(_) => validate_ordinary_database_file(&self.shared.database_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PrivacyStoreSchemaStatus::Empty);
            }
            Err(_) => {
                return Err(PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "The local privacy database could not be inspected.",
                ));
            }
        }
        let connection = Connection::open_with_flags(
            &self.shared.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_unavailable",
                "The local privacy database could not be opened read-only.",
            )
        })?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "The local privacy database read-only preflight could not be configured.",
                )
            })?;
        connection
            .execute_batch(
                "PRAGMA query_only=ON;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "The local privacy database could not enter read-only preflight mode.",
                )
            })?;
        PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)
    }

    fn open_connection(&self) -> Result<Connection, PrivacyWorkflowError> {
        let mut connection = self.open_raw_connection()?;
        if self.shared.schema_upgrade_required.load(Ordering::Acquire) {
            return match PrivacyStore::preflight_schema(&connection)
                .map_err(PrivacyWorkflowError::store)?
            {
                PrivacyStoreSchemaStatus::UpgradeRequired { .. } => Err(PrivacyWorkflowError::new(
                    "privacy_store_backup_required",
                    "The privacy store must be backed up before its schema can be upgraded.",
                )),
                PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::Current => {
                    Err(PrivacyWorkflowError::new(
                        "privacy_store_schema_state_changed",
                        "The privacy store schema changed while the upgrade gate was active.",
                    ))
                }
            };
        }
        PrivacyStore::initialize(&connection).map_err(PrivacyWorkflowError::store)?;
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        case_materials::initialize_assignment_schema(&mut connection)?;
        vault_broker::initialize_vault_link_schema(&connection)
            .map_err(PrivacyWorkflowError::vault)?;
        case_dictionary_store::initialize_schema(&connection)?;
        project_deletion::initialize_schema(&connection)?;
        Ok(connection)
    }

    pub(crate) fn privacy_store_schema_upgrade_required(&self) -> bool {
        self.shared.schema_upgrade_required.load(Ordering::Acquire)
    }

    pub(crate) fn vault_startup_write_required(&self) -> bool {
        self.shared.vault_broker.startup_write_required()
    }

    pub(crate) fn startup_vault_present(&self) -> bool {
        self.shared.vault_broker.startup_vault_present()
    }

    /// Authorizes creation of a brand-new canonical user database only when no
    /// pre-existing Privacy or Vault identity can be orphaned by doing so.
    pub(crate) fn preflight_fresh_user_database_initialization(
        &self,
    ) -> Result<(), PrivacyWorkflowError> {
        let _guard = self.gate();
        if self.shared.user_database_path.exists() {
            return Err(PrivacyWorkflowError::new(
                "case_material_source_state_changed",
                "The user database appeared while fresh-start initialization was being authorized.",
            ));
        }
        if self.startup_vault_present()
            || !matches!(
                self.preflight_privacy_store_schema_read_only()?,
                PrivacyStoreSchemaStatus::Empty
            )
        {
            return Err(PrivacyWorkflowError::new(
                "case_material_source_missing_with_history",
                "A new user database cannot be created while Privacy or Vault history already exists.",
            ));
        }
        Ok(())
    }

    /// Runs only after the complete read-only migration preflight succeeds.
    /// It creates an empty Vault/Privacy baseline when that component did not
    /// previously exist so the coordinated five-component backup can include
    /// all components. Existing legacy schemas are deliberately not upgraded.
    pub(crate) fn prepare_startup_storage_after_preflight(
        &self,
    ) -> Result<(), PrivacyWorkflowError> {
        let _guard = self.gate();
        let directory = self.shared.database_path.parent().ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_store_unavailable",
                "The local privacy database has no controlled parent directory.",
            )
        })?;
        match fs::symlink_metadata(directory) {
            Ok(_) => validate_ordinary_directory(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(directory).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_store_unavailable",
                        "The local privacy directory could not be created after preflight.",
                    )
                })?;
                validate_ordinary_directory(directory)?;
            }
            Err(_) => {
                return Err(PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "The local privacy directory could not be inspected after preflight.",
                ))
            }
        }
        self.shared
            .vault_broker
            .prepare_for_migration_backup_after_preflight()
            .map_err(PrivacyWorkflowError::vault)?;
        if matches!(
            self.preflight_privacy_store_schema_read_only()?,
            PrivacyStoreSchemaStatus::Empty
        ) {
            let mut connection = self.open_raw_connection()?;
            PrivacyStore::initialize(&connection).map_err(PrivacyWorkflowError::store)?;
            PrivacyLifecycle::initialize(
                &mut connection,
                self.shared.workspace_instance_id.clone(),
                self.current_unix()?,
            )
            .map_err(PrivacyWorkflowError::lifecycle)?;
            ProjectPrivacyCaseBindingStore::initialize(&mut connection)
                .map_err(PrivacyWorkflowError::project_case_binding)?;
            case_materials::initialize_assignment_schema(&mut connection)?;
            vault_broker::initialize_vault_link_schema(&connection)
                .map_err(PrivacyWorkflowError::vault)?;
            case_dictionary_store::initialize_schema(&connection)?;
            project_deletion::initialize_schema(&connection)?;
        }
        Ok(())
    }

    pub(crate) fn upgrade_privacy_store_schema_after_backup(
        &self,
    ) -> Result<(), PrivacyWorkflowError> {
        let _guard = self.gate();
        let mut connection = self.open_raw_connection()?;
        if self.privacy_store_schema_upgrade_required() {
            PrivacyStore::upgrade_schema_after_backup(&connection)
                .map_err(PrivacyWorkflowError::store)?;
            PrivacyLifecycle::initialize(
                &mut connection,
                self.shared.workspace_instance_id.clone(),
                self.current_unix()?,
            )
            .map_err(PrivacyWorkflowError::lifecycle)?;
        }
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        case_materials::initialize_assignment_schema(&mut connection)?;
        vault_broker::initialize_vault_link_schema(&connection)
            .map_err(PrivacyWorkflowError::vault)?;
        case_dictionary_store::initialize_schema(&connection)?;
        project_deletion::initialize_schema(&connection)?;
        self.shared
            .vault_broker
            .upgrade_schema_after_backup()
            .map_err(PrivacyWorkflowError::vault)?;
        let privacy_schema_upgrade_required = matches!(
            PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)?,
            PrivacyStoreSchemaStatus::UpgradeRequired { .. }
        );
        self.shared
            .schema_upgrade_required
            .store(privacy_schema_upgrade_required, Ordering::Release);
        Ok(())
    }

    pub(crate) fn complete_application_startup_maintenance(
        &self,
    ) -> Result<(), PrivacyWorkflowError> {
        let _guard = self.gate();
        let mut connection = self.open_connection()?;
        self.run_startup_maintenance(&mut connection)
    }

    /// Performs the frozen Step-8 Privacy recovery/retention work with stable,
    /// lineage-derived cleanup identifiers and cutoff. Re-entry resumes or
    /// verifies the same durable journals and never creates a second cleanup.
    #[cfg(test)]
    pub(crate) fn complete_v031_step8_privacy_maintenance(
        &self,
        cutoff_unix: u64,
        retention_cleanup_id: &str,
        vault_cleanup_id: &str,
    ) -> Result<V031Step8PrivacyMaintenanceReport, PrivacyWorkflowError> {
        self.complete_v031_step8_privacy_maintenance_with_failure_injector(
            cutoff_unix,
            retention_cleanup_id,
            vault_cleanup_id,
            &NoopV031Step8MaintenanceFailureInjector,
        )
    }

    pub(crate) fn complete_v031_step8_privacy_maintenance_with_failure_injector(
        &self,
        cutoff_unix: u64,
        retention_cleanup_id: &str,
        vault_cleanup_id: &str,
        failure_injector: &dyn V031Step8MaintenanceFailureInjector,
    ) -> Result<V031Step8PrivacyMaintenanceReport, PrivacyWorkflowError> {
        if cutoff_unix == 0 {
            return Err(v031_step8_maintenance_error());
        }
        let _guard = self.gate();
        let mut connection = self.open_connection()?;
        self.shared
            .vault_broker
            .recover_cleanups(cutoff_unix)
            .map_err(PrivacyWorkflowError::vault)?;
        let lifecycle = PrivacyLifecycle::initialize(
            &mut connection,
            self.shared.workspace_instance_id.clone(),
            cutoff_unix,
        )
        .map_err(PrivacyWorkflowError::lifecycle)?;
        self.recover_pending_project_deletions_unlocked(&mut connection)?;
        self.recover_prepared_retention_sweeps(
            &lifecycle,
            &mut connection,
            cutoff_unix,
            "privacy_v031_step8_retention_recovery",
        )?;
        let retention_cleanup = self.run_or_resume_v031_step8_retention_cleanup(
            &lifecycle,
            &mut connection,
            retention_cleanup_id,
            cutoff_unix,
            failure_injector,
        )?;
        if failure_injector
            .should_fail(V031Step8MaintenanceFailurePoint::AfterRetentionCommittedBeforeVault)
        {
            return Err(v031_step8_maintenance_error());
        }
        let vault_cleanup = self
            .shared
            .vault_broker
            .run_or_resume_expired_cleanup_with_failure_injector(
                vault_cleanup_id,
                cutoff_unix,
                failure_injector,
            )
            .map_err(PrivacyWorkflowError::vault)?;

        let pending_project_deletions_after =
            self.recover_pending_project_deletions_unlocked(&mut connection)?;
        let pending_retention_cleanups_after =
            u64::try_from(prepared_retention_cleanup_ids(&connection)?.len())
                .map_err(|_| v031_step8_maintenance_error())?;
        let vault_status = self
            .shared
            .vault_broker
            .inspect_cleanup_status_read_only()
            .map_err(PrivacyWorkflowError::vault)?;
        if pending_project_deletions_after != 0
            || pending_retention_cleanups_after != 0
            || vault_status.prepared_count != 0
            || vault_status.committed_count != 0
            || retention_cleanup.cleanup_id != retention_cleanup_id
            || retention_cleanup.state != "committed"
            || retention_cleanup.started_at_unix != cutoff_unix
            || retention_cleanup.completed_at_unix != cutoff_unix
            || vault_cleanup.cleanup_id != vault_cleanup_id
            || vault_cleanup.state != "purged"
            || vault_cleanup.started_at_unix != cutoff_unix
            || vault_cleanup.completed_at_unix != cutoff_unix
            || vault_cleanup.quarantine_paths_pending != 0
        {
            return Err(v031_step8_maintenance_error());
        }
        Ok(V031Step8PrivacyMaintenanceReport {
            cutoff_unix,
            retention_cleanup,
            vault_cleanup,
            pending_project_deletions_after,
            pending_retention_cleanups_after,
            pending_vault_prepared_after: vault_status.prepared_count,
            pending_vault_committed_after: vault_status.committed_count,
        })
    }

    fn run_or_resume_v031_step8_retention_cleanup(
        &self,
        lifecycle: &PrivacyLifecycle,
        connection: &mut Connection,
        cleanup_id: &str,
        cutoff_unix: u64,
        failure_injector: &dyn V031Step8MaintenanceFailureInjector,
    ) -> Result<CleanupReportV1, PrivacyWorkflowError> {
        let existing = connection
            .query_row(
                "SELECT state,started_at_unix,completed_at_unix,candidate_count,
                        removed_count,keys_destroyed,event_hash,erasure_disclosure
                 FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                [cleanup_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| v031_step8_maintenance_error())?;
        let Some((
            state,
            started_at,
            completed_at,
            candidate_count,
            removed_count,
            keys_destroyed,
            event_hash,
            erasure_disclosure,
        )) = existing
        else {
            lifecycle
                .prepare_retention_sweep(connection, cleanup_id, cutoff_unix)
                .map_err(PrivacyWorkflowError::lifecycle)?;
            if failure_injector.should_fail(
                V031Step8MaintenanceFailurePoint::AfterRetentionPreparedBeforeInvalidation,
            ) {
                return Err(v031_step8_maintenance_error());
            }
            let lifecycle_binding_ids = lifecycle
                .revalidate_prepared_retention_sweep_for_external_invalidation(
                    connection,
                    cleanup_id,
                    cutoff_unix,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?
                .ok_or_else(v031_step8_maintenance_error)?;
            self.invalidate_lifecycle_bindings(
                &lifecycle_binding_ids,
                "privacy_v031_step8_retention_cleanup",
            )?;
            return lifecycle
                .commit_retention_sweep(connection, cleanup_id, cutoff_unix)
                .map_err(PrivacyWorkflowError::lifecycle);
        };
        if u64::try_from(started_at).ok() != Some(cutoff_unix) {
            return Err(v031_step8_maintenance_error());
        }
        if state == "prepared" {
            let lifecycle_binding_ids = lifecycle
                .revalidate_prepared_retention_sweep_for_external_invalidation(
                    connection,
                    cleanup_id,
                    cutoff_unix,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?
                .ok_or_else(v031_step8_maintenance_error)?;
            self.invalidate_lifecycle_bindings(
                &lifecycle_binding_ids,
                "privacy_v031_step8_retention_cleanup",
            )?;
            return lifecycle
                .commit_retention_sweep(connection, cleanup_id, cutoff_unix)
                .map_err(PrivacyWorkflowError::lifecycle);
        }
        if state != "committed"
            || completed_at.and_then(|value| u64::try_from(value).ok()) != Some(cutoff_unix)
            || candidate_count < 0
            || removed_count < 0
            || keys_destroyed < 0
            || removed_count > candidate_count
            || event_hash.len() != 64
            || erasure_disclosure != LOGICAL_ERASURE_DISCLOSURE
        {
            return Err(v031_step8_maintenance_error());
        }
        lifecycle
            .verify_cleanup_journal(connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        Ok(CleanupReportV1 {
            cleanup_id: cleanup_id.to_owned(),
            state,
            candidates: u64::try_from(candidate_count)
                .map_err(|_| v031_step8_maintenance_error())?,
            removed: u64::try_from(removed_count).map_err(|_| v031_step8_maintenance_error())?,
            keys_destroyed: u64::try_from(keys_destroyed)
                .map_err(|_| v031_step8_maintenance_error())?,
            started_at_unix: cutoff_unix,
            completed_at_unix: cutoff_unix,
            event_hash,
            erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE,
        })
    }

    fn parse_project_id(&self, value: String) -> Result<ProjectId, PrivacyWorkflowError> {
        ProjectId::parse(value).map_err(PrivacyWorkflowError::project_case_binding)
    }

    fn ensure_project_exists(&self, project_id: &ProjectId) -> Result<(), PrivacyWorkflowError> {
        let connection = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "case_material_source_unavailable",
                    "案件数据库无法以只读方式核验。",
                )
            })?;
        let exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM projects WHERE project_id=?1
                 )",
                [project_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "case_material_source_unavailable",
                    "案件身份无法从只读案件数据库核验。",
                )
            })?;
        if !exists {
            return Err(PrivacyWorkflowError::new(
                "case_project_not_found",
                "指定案件不存在或已被删除。",
            ));
        }
        Ok(())
    }

    fn resolve_or_create_privacy_case_id(
        &self,
        connection: &mut Connection,
        project_id: &ProjectId,
        creation_source: BindingCreationSource,
        migration_id: Option<String>,
    ) -> Result<PrivacyCaseId, PrivacyWorkflowError> {
        project_deletion::ensure_project_accepts_privacy_writes(connection, project_id)?;
        let lifecycle_context = BindingLifecycleContext::new(
            creation_source,
            format!("bind_{}", Uuid::new_v4().simple()),
            migration_id,
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        ProjectPrivacyCaseBindingStore::resolve_or_create(
            connection,
            project_id,
            &lifecycle_context,
        )
        .map_err(PrivacyWorkflowError::project_case_binding)
    }

    #[cfg(test)]
    pub fn prepare_selected_material(
        &self,
        path: &Path,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        mineru_config: Option<&LocalMineruConfig>,
        requested_case_id: Option<String>,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        self.prepare_selected_material_with_qualification(
            path,
            config,
            ocr_status,
            LocalOcrExecutionContext {
                mineru_config,
                qualification: None,
            },
            requested_case_id,
            custom_terms,
        )
    }

    pub fn prepare_selected_material_with_qualification(
        &self,
        path: &Path,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        ocr_execution: LocalOcrExecutionContext<'_>,
        requested_case_id: Option<String>,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let LocalOcrExecutionContext {
            mineru_config,
            qualification: ocr_qualification,
        } = ocr_execution;
        let case_id = requested_case_id
            .map_or_else(
                || CaseId::parse(format!("case_{}", Uuid::new_v4().simple())),
                CaseId::parse,
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "invalid_case_id",
                    "案件标识无效；必须使用 App 生成的匿名 caseId。",
                )
            })?;
        let _gate = self.gate();
        self.prepare_selected_material_for_identity_locked(
            path,
            config,
            ocr_status,
            mineru_config,
            ocr_qualification,
            None,
            case_id,
            custom_terms,
        )
    }

    pub fn prepare_case_selected_material_with_qualification(
        &self,
        path: &Path,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        ocr_execution: LocalOcrExecutionContext<'_>,
        requested_project_id: String,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let project_id = self.parse_project_id(requested_project_id)?;
        let LocalOcrExecutionContext {
            mineru_config,
            qualification: ocr_qualification,
        } = ocr_execution;
        let _gate = self.gate();
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        let mut connection = self.open_connection()?;
        let privacy_case_id = self.resolve_or_create_privacy_case_id(
            &mut connection,
            &project_id,
            BindingCreationSource::LifecycleInitialization,
            None,
        )?;
        drop(connection);
        let result = self.prepare_selected_material_for_identity_locked(
            path,
            config,
            ocr_status,
            mineru_config,
            ocr_qualification,
            Some(project_id.as_str()),
            privacy_case_id.into_case_id(),
            custom_terms,
        );
        match result {
            Ok(review) => {
                project_guard.commit()?;
                Ok(review)
            }
            Err(error) => {
                project_guard.rollback();
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_selected_material_for_identity_locked(
        &self,
        path: &Path,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        mineru_config: Option<&LocalMineruConfig>,
        ocr_qualification: Option<&QualificationSnapshotV1>,
        project_id: Option<&str>,
        case_id: CaseId,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let (source_bytes, source_display_name) = read_bounded_selected_material(path)?;
        let source_bytes = vault_broker::ZeroizingBytes::new(source_bytes);
        let material_id = MaterialId::parse(format!("mat_{}", Uuid::new_v4().simple()))
            .expect("generated material identifiers satisfy the opaque-id contract");
        let source_media_type = file_ingest::detect_format(&source_display_name)
            .map_err(ingest_error)?
            .mime_type();
        let now_unix = self.current_unix()?;
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let policy = lifecycle
            .retention_policy(&connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let expires_at_unix = now_unix
            .checked_add(policy.review_retention_seconds)
            .ok_or_else(|| {
                PrivacyWorkflowError::new("invalid_retention", "原件保留期限超出范围。")
            })?;
        let isolation = self
            .shared
            .vault_broker
            .isolation_status()
            .map_err(PrivacyWorkflowError::vault)?;
        validate_vault_isolation(&isolation)?;
        let binding = self
            .shared
            .vault_broker
            .import_source(vault_broker::ImportSourceRequest {
                case_id: &case_id,
                material_id: &material_id,
                original_file_name: &source_display_name,
                original_source_path: path,
                original_media_type: source_media_type,
                content: &source_bytes,
                imported_at_unix: now_unix,
            })
            .map_err(PrivacyWorkflowError::vault)?;
        self.shared
            .vault_broker
            .bind_retention(&binding, expires_at_unix, false, policy.revision, now_unix)
            .map_err(PrivacyWorkflowError::vault)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| PrivacyWorkflowError::new("privacy_store_busy", "本机隐私数据库繁忙。"))?;
        let source_name_sha256 = sha256_hex(source_display_name.as_bytes());
        PrivacyStore::register_material(
            &transaction,
            &RegisterPrivacyMaterial {
                material_id: material_id.as_str(),
                project_id,
                attachment_id: Some(binding.object_id.as_str()),
                source_sha256: binding.source_sha256.as_str(),
                source_name_sha256: &source_name_sha256,
                media_type: source_media_type,
                page_count: None,
            },
        )
        .map_err(PrivacyWorkflowError::store)?;
        PrivacyStore::set_material_display_name(
            &transaction,
            material_id.as_str(),
            Some(1),
            &source_display_name,
        )
        .map_err(PrivacyWorkflowError::store)?;
        vault_broker::persist_vault_import(
            &transaction,
            &binding,
            expires_at_unix,
            policy.revision,
            now_unix,
        )
        .map_err(PrivacyWorkflowError::vault)?;
        transaction.commit().map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_commit_failed",
                "加密原件与本机材料索引未能原子登记；原件仍受 Vault 保留期保护。",
            )
        })?;
        drop(connection);
        drop(source_bytes);

        let source_lease = self
            .shared
            .vault_broker
            .read_source(&binding)
            .map_err(PrivacyWorkflowError::vault)?;
        let result = self.prepare_material_bytes_bound(PrepareMaterialBytesInput {
            bytes: source_lease.content(),
            source_display_name,
            config,
            ocr_status,
            mineru_config,
            custom_terms,
            ocr_qualification,
            vault_binding: Some(&binding),
        });
        drop(source_lease);
        match result {
            Ok(review) => Ok(review),
            Err(error) => {
                let connection = self.open_connection()?;
                vault_broker::mark_vault_processing_failed(&connection, &material_id, error.code())
                    .map_err(PrivacyWorkflowError::vault)?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn prepare_material_bytes(
        &self,
        bytes: &[u8],
        source_display_name: String,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        mineru_config: Option<&LocalMineruConfig>,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        self.prepare_material_bytes_bound(PrepareMaterialBytesInput {
            bytes,
            source_display_name,
            config,
            ocr_status,
            mineru_config,
            custom_terms,
            ocr_qualification: None,
            vault_binding: None,
        })
    }

    fn prepare_material_bytes_bound(
        &self,
        input: PrepareMaterialBytesInput<'_>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let PrepareMaterialBytesInput {
            bytes,
            source_display_name,
            config,
            ocr_status,
            mineru_config,
            custom_terms,
            ocr_qualification,
            vault_binding,
        } = input;
        let processed = extract_local_material(
            bytes,
            &source_display_name,
            config,
            ocr_status,
            mineru_config,
        )?;
        let vault_isolation = if let Some(binding) = vault_binding {
            if processed.source_sha256 != binding.source_sha256.as_str()
                || bytes.len() as u64 != binding.content_bytes
            {
                return Err(PrivacyWorkflowError::new(
                    "vault_source_mismatch",
                    "Vault 解密原件与导入时的哈希或长度不一致；处理已停止。",
                ));
            }
            let status = self
                .shared
                .vault_broker
                .isolation_status()
                .map_err(PrivacyWorkflowError::vault)?;
            validate_vault_isolation(&status)?;
            Some(status)
        } else {
            None
        };

        let options = RedactionOptions {
            custom_terms,
            ..RedactionOptions::default()
        }
        .validated()
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "invalid_custom_redaction_term",
                "自定义敏感词为空、过长或数量超限。",
            )
        })?;
        let dictionary_custom_terms = options.custom_terms.clone();
        let mut redactor = Redactor::new(options);
        let original_texts = processed
            .segments
            .iter()
            .map(|page| {
                page.spans
                    .iter()
                    .map(|span| span.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect::<Vec<_>>();

        // Discovery does not increment final counts; it learns aliases from
        // every page before any page is emitted.
        redactor
            .discover_across(original_texts.iter().map(String::as_str))
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "discovered_term_limit_exceeded",
                    "材料中检测到的敏感实体数量或总大小超过本机安全上限，处理已停止。",
                )
            })?;

        let mut stored_pages = Vec::with_capacity(processed.segments.len());
        let mut canonical_pages = Vec::with_capacity(processed.segments.len());
        for (page, original_text) in processed.segments.iter().zip(original_texts) {
            let redacted_text = redactor.redact(&original_text);
            canonical_pages.push(CanonicalRedactedPage {
                page_number: page.page_number,
                text: redacted_text.clone(),
            });
            stored_pages.push(StoredReviewPage {
                page_number: page.page_number,
                locator: page.locator.clone(),
                assessment: page.assessment.clone(),
                spans: page.spans.clone(),
                original_text,
                suggested_redacted_text: redacted_text,
            });
        }
        let summary = redactor.summary();
        let mapping_entries = redactor
            .detected_alias_mappings()
            .into_iter()
            .map(|entry| {
                let (alias, sensitive_value) = entry.into_parts();
                SensitiveMappingEntryV1 {
                    alias,
                    sensitive_value,
                }
            })
            .collect::<Vec<_>>();
        let mapping_payload = if mapping_entries.is_empty() {
            None
        } else {
            Some(
                SensitiveMappingPayloadV1::new(mapping_entries)
                    .map_err(PrivacyWorkflowError::lifecycle)?,
            )
        };
        let normalized_original = normalize_for_canary_scan(
            &stored_pages
                .iter()
                .map(|page| page.original_text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let forbidden_canaries = redactor
            .detected_sensitive_values()
            .into_iter()
            .filter(|value| {
                let normalized = normalize_for_canary_scan(value);
                !normalized.is_empty() && normalized_original.contains(&normalized)
            })
            .collect::<Vec<_>>();
        validate_forbidden_canaries(&forbidden_canaries)?;
        preflight_safe_pdf_delivery(&canonical_pages, &forbidden_canaries)?;
        let extraction_bytes = serde_json::to_vec(&processed).map_err(|_| {
            PrivacyWorkflowError::new(
                "canonicalization_failed",
                "本地提取结果无法进行确定性哈希。",
            )
        })?;
        let extraction_sha256 = sha256_hex(&extraction_bytes);
        let suggested_bytes = canonical_redacted_bytes(&canonical_pages)?;
        let suggested_redacted_content_sha256 = sha256_hex(&suggested_bytes);
        let material_id = vault_binding.map_or_else(
            || format!("mat_{}", Uuid::new_v4().simple()),
            |binding| binding.material_id.as_str().to_owned(),
        );
        let redaction_id = format!("red_{}", Uuid::new_v4().simple());
        let stored = StoredReviewPayload {
            schema_version: REVIEW_PAYLOAD_SCHEMA_VERSION,
            material_id: material_id.clone(),
            redaction_id: redaction_id.clone(),
            case_id: vault_binding.map(|binding| binding.case_id.as_str().to_owned()),
            vault_object_id: vault_binding.map(|binding| binding.object_id.as_str().to_owned()),
            vault_object_version: vault_binding.map(|binding| binding.object_version),
            vault_isolation,
            source_display_name: source_display_name.clone(),
            source_sha256: processed.source_sha256.clone(),
            extraction_sha256: extraction_sha256.clone(),
            suggested_redacted_content_sha256: suggested_redacted_content_sha256.clone(),
            processing_version: processed.processing_version.clone(),
            media_type: processed.media_type.clone(),
            page_count: processed.page_count,
            backend_trace: processed.backend_trace.clone(),
            input_transform: processed.input_transform.clone(),
            summary,
            pages: stored_pages,
            forbidden_canaries,
        };
        let protected_plaintext = serde_json::to_vec(&stored).map_err(|_| {
            PrivacyWorkflowError::new("review_payload_invalid", "本地审阅数据无法序列化。")
        })?;

        let now_unix = self.current_unix()?;
        let case_dictionary = if let Some(case_id) = stored.case_id.as_ref() {
            let case_id = CaseId::parse(case_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_identity_invalid",
                    "The case-bound dictionary identity is invalid.",
                )
            })?;
            let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_identity_invalid",
                    "The dictionary material identity is invalid.",
                )
            })?;
            Some(case_dictionary_store::ensure_case_dictionary(
                self,
                &case_id,
                &material_id,
                &dictionary_custom_terms,
                now_unix,
            )?)
        } else {
            None
        };
        let detector_run = stored
            .case_id
            .as_ref()
            .map(|_| {
                local_detection::run_local_detectors(
                    self,
                    &stored,
                    mineru_config,
                    ocr_qualification,
                    now_unix,
                    case_dictionary.as_ref().ok_or_else(|| {
                        PrivacyWorkflowError::new(
                            "privacy_case_dictionary_missing",
                            "The case dictionary evidence is unavailable.",
                        )
                    })?,
                )
            })
            .transpose()?;
        let risk_state = initial_risk_workflow_state(
            &stored,
            detector_run.as_ref(),
            case_dictionary.as_ref(),
            now_unix,
        )?;
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| PrivacyWorkflowError::new("privacy_store_busy", "本机隐私数据库繁忙。"))?;
        let source_name_sha256 = sha256_hex(source_display_name.as_bytes());
        if let Some(binding) = vault_binding {
            vault_broker::complete_vault_material_processing(
                &transaction,
                binding,
                &stored.media_type,
                stored.page_count,
            )
            .map_err(PrivacyWorkflowError::vault)?;
        } else {
            PrivacyStore::register_material(
                &transaction,
                &RegisterPrivacyMaterial {
                    material_id: &material_id,
                    project_id: None,
                    attachment_id: None,
                    source_sha256: &stored.source_sha256,
                    source_name_sha256: &source_name_sha256,
                    media_type: &stored.media_type,
                    page_count: Some(stored.page_count),
                },
            )
            .map_err(PrivacyWorkflowError::store)?;
            PrivacyStore::set_material_display_name(
                &transaction,
                &material_id,
                Some(1),
                &source_display_name,
            )
            .map_err(PrivacyWorkflowError::store)?;
        }
        let unresolved_high_risk_count = risk_state
            .as_ref()
            .map(|state| {
                state
                    .session
                    .findings
                    .iter()
                    .filter(|finding| {
                        matches!(
                            finding.severity,
                            FindingSeverity::P0Blocking | FindingSeverity::P1High
                        )
                    })
                    .count()
            })
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(u32::MAX);
        PrivacyStore::save_review_draft(
            &transaction,
            &SaveReviewDraft {
                redaction_id: &redaction_id,
                material_id: &material_id,
                extraction_sha256: &extraction_sha256,
                redacted_content_sha256: &suggested_redacted_content_sha256,
                policy_id: POLICY_ID,
                policy_version: POLICY_VERSION,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count,
                review_payload_plaintext: &protected_plaintext,
            },
        )
        .map_err(PrivacyWorkflowError::store)?;
        if let Some(state) = risk_state.as_ref() {
            append_risk_revision(&transaction, state, 0)?;
        }
        lifecycle
            .bind_redaction_retention(&transaction, &redaction_id, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        if let Some(payload) = mapping_payload.as_ref() {
            lifecycle
                .save_mapping_revision_in_transaction(
                    &transaction,
                    &format!("map_{}", Uuid::new_v4().simple()),
                    &redaction_id,
                    1,
                    payload,
                    now_unix,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?;
        }
        transaction.commit().map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_commit_failed",
                "本机审阅、保留期与加密映射未能原子提交。",
            )
        })?;
        let mut view = stored_to_view(stored, "review_required")?;
        view.risk_review = risk_state
            .as_ref()
            .map(|state| state.session.view().map_err(review_session_error))
            .transpose()?;
        Ok(view)
    }

    #[allow(dead_code)]
    pub fn load_review(
        &self,
        redaction_id: &str,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.load_review_unlocked(redaction_id)
    }

    #[allow(dead_code)]
    pub fn load_latest_review(&self) -> Result<Option<PrivacyReviewView>, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let redaction_id = connection
            .query_row(
                "SELECT generation.redaction_id
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.revocation_state='active'
                   AND generation.revoked_at IS NULL
                   AND material.deleted_at IS NULL
                 ORDER BY generation.rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new("privacy_store_database_error", "最近审阅记录无法读取。")
            })?;
        drop(connection);
        redaction_id
            .map(|identifier| self.load_review_unlocked(&identifier))
            .transpose()
    }

    pub fn list_approved_review_selections(
        &self,
    ) -> Result<Vec<ApprovedPrivacyReviewSelection>, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT generation.redaction_id,generation.approved_payload_sha256
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.review_state='approved'
                   AND generation.approved_payload_sha256 IS NOT NULL
                   AND generation.unresolved_high_risk_count=0
                   AND generation.generation_status='ready'
                   AND generation.revocation_state='active'
                   AND generation.revoked_at IS NULL
                   AND material.project_id IS NOT NULL
                   AND material.source_kind='vault'
                   AND material.migration_status='ready'
                   AND material.state IN ('approved','outbound_ready')
                   AND material.deleted_at IS NULL
                 ORDER BY generation.rowid DESC LIMIT 256",
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "Approved review metadata could not be indexed.",
                )
            })?;
        let indexed = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "Approved review metadata could not be indexed.",
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "Approved review metadata could not be indexed.",
                )
            })?;
        drop(statement);

        let mut selections = Vec::with_capacity(indexed.len());
        for (redaction_id, approved_payload_sha256) in indexed {
            let (authorization, project_guard) =
                self.begin_live_case_redaction_authorization(&redaction_id, true)?;
            let loaded = PrivacyStore::load_review_draft(&connection, &redaction_id)
                .map_err(PrivacyWorkflowError::store)?;
            if loaded.review_state != "approved" {
                continue;
            }
            let stored: StoredReviewPayload =
                serde_json::from_slice(&loaded.review_payload_plaintext).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "review_payload_invalid",
                        "Approved review metadata could not be verified.",
                    )
                })?;
            validate_loaded_review(&loaded, &stored)?;
            let approved_pages = stored
                .pages
                .iter()
                .map(|page| CanonicalRedactedPage {
                    page_number: page.page_number,
                    text: page.suggested_redacted_text.clone(),
                })
                .collect::<Vec<_>>();
            let canonical_approved_payload = serde_json::to_vec(&ApprovedPayload {
                schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
                source_sha256: &stored.source_sha256,
                extraction_sha256: &stored.extraction_sha256,
                media_type: &stored.media_type,
                pages: &approved_pages,
            })
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "Approved review payload could not be canonicalized.",
                )
            })?;
            if sha256_hex(&canonical_approved_payload) != approved_payload_sha256 {
                return Err(PrivacyWorkflowError::new(
                    "review_payload_mismatch",
                    "Approved review payload does not match its protected approval index.",
                ));
            }
            let mcp_publish_approval_expires_at_unix = self
                .active_approved_workspace_receipt_expiry(
                    &connection,
                    &redaction_id,
                    &canonical_approved_payload,
                )?;
            let Some(case_id) = stored.case_id else {
                continue;
            };
            CaseId::parse(case_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "Approved review case binding is invalid.",
                )
            })?;
            MaterialId::parse(loaded.material_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "Approved review material binding is invalid.",
                )
            })?;
            Sha256Hex::parse(approved_payload_sha256.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "Approved review payload binding is invalid.",
                )
            })?;
            project_guard.commit()?;
            selections.push(ApprovedPrivacyReviewSelection {
                redaction_id,
                material_id: loaded.material_id,
                project_id: authorization.project_id.as_str().to_owned(),
                approved_payload_sha256,
                mcp_publish_approved: mcp_publish_approval_expires_at_unix.is_some(),
                mcp_publish_approval_expires_at_unix,
            });
        }
        Ok(selections)
    }

    fn active_approved_workspace_receipt_expiry(
        &self,
        connection: &Connection,
        redaction_id: &str,
        approved_payload: &[u8],
    ) -> Result<Option<u64>, PrivacyWorkflowError> {
        let destination = DestinationScope {
            kind: DestinationKind::ExternalMcpHost,
            identifier: privacy::workspace::APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
        };
        let protected_token = connection
            .query_row(
                "SELECT signed_token FROM privacy_receipts
                 WHERE redaction_id=?1 AND destination_kind='external_mcp_host'
                   AND destination_identifier_sha256=?2 AND purpose=?3
                   AND revoked_at_unix IS NULL
                 ORDER BY issued_at_unix DESC,receipt_id DESC LIMIT 1",
                rusqlite::params![
                    redaction_id,
                    sha256_hex(destination.identifier.as_bytes()),
                    privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "Approved workspace receipt status could not be read.",
                )
            })?;
        let Some(protected_token) = protected_token else {
            return Ok(None);
        };
        let Ok(token_bytes) = privacy::unprotect_local(&protected_token) else {
            return Ok(None);
        };
        let Ok(token) = std::str::from_utf8(&token_bytes) else {
            return Ok(None);
        };
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let receipt = match PrivacyStore::verify_active_receipt_token(
            connection,
            &signer,
            &ActiveReceiptVerification {
                redaction_id,
                signed_token: token,
                approved_payload,
                destination: &destination,
                purpose: privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE,
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        ) {
            Ok(receipt) => receipt,
            Err(_) => return Ok(None),
        };
        Ok(receipt
            .claims
            .expires_at_unix
            .filter(|expires_at| *expires_at > now_unix))
    }

    pub fn approve_review_for_approved_workspace(
        &self,
        request: ApproveReviewForApprovedWorkspaceRequest,
    ) -> Result<ApproveReviewForApprovedWorkspaceResponse, PrivacyWorkflowError> {
        if !request.confirmed
            || !valid_identifier(&request.redaction_id)
            || !valid_hash(&request.expected_approved_payload_sha256)
        {
            return Err(PrivacyWorkflowError::new(
                "approved_workspace_approval_confirmation_required",
                "Explicit confirmation of the exact approved MCP publication is required.",
            ));
        }
        let reviewer = request.reviewer.trim().to_owned();
        let expected_payload_sha256 = request.expected_approved_payload_sha256.clone();
        let _gate = self.gate();
        let (authorization, project_guard) =
            self.begin_live_case_redaction_authorization(&request.redaction_id, true)?;
        let approval_request = {
            let connection = self.open_connection()?;
            let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
                .map_err(PrivacyWorkflowError::store)?;
            if loaded.review_state != "approved" || loaded.unresolved_high_risk_count != 0 {
                return Err(PrivacyWorkflowError::new(
                    "redaction_not_approved",
                    "Only a current, fully approved case-bound review can be approved for MCP publication.",
                ));
            }
            let stored: StoredReviewPayload =
                serde_json::from_slice(&loaded.review_payload_plaintext).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "review_payload_invalid",
                        "The approved review payload could not be verified.",
                    )
                })?;
            validate_loaded_review(&loaded, &stored)?;
            self.verify_stored_vault_source(&connection, &stored)?;
            let case_id = stored.case_id.as_ref().ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "approved_workspace_case_binding_required",
                    "Approved MCP publication requires an exact case-bound review.",
                )
            })?;
            CaseId::parse(case_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "The approved review case binding is invalid.",
                )
            })?;
            let pages = stored
                .pages
                .iter()
                .map(|page| CanonicalRedactedPage {
                    page_number: page.page_number,
                    text: page.suggested_redacted_text.clone(),
                })
                .collect::<Vec<_>>();
            reject_normalized_canaries(&pages, &stored.forbidden_canaries)?;
            let canonical_payload = serde_json::to_vec(&ApprovedPayload {
                schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
                source_sha256: &stored.source_sha256,
                extraction_sha256: &stored.extraction_sha256,
                media_type: &stored.media_type,
                pages: &pages,
            })
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "canonicalization_failed",
                    "The approved MCP payload could not be canonicalized.",
                )
            })?;
            let canonical_payload_sha256 = sha256_hex(&canonical_payload);
            let indexed_payload_sha256 = connection
                .query_row(
                    "SELECT approved_payload_sha256 FROM privacy_redactions
                     WHERE redaction_id=?1 AND review_state='approved'",
                    [&request.redaction_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_store_database_error",
                        "The approved MCP payload binding could not be read.",
                    )
                })?
                .flatten();
            if indexed_payload_sha256.as_deref() != Some(canonical_payload_sha256.as_str())
                || canonical_payload_sha256 != expected_payload_sha256
            {
                return Err(PrivacyWorkflowError::new(
                    "approved_payload_mismatch",
                    "The approved review changed before MCP publication approval.",
                ));
            }
            let redacted_content_sha256 = sha256_hex(&canonical_redacted_bytes(&pages)?);
            if redacted_content_sha256 != loaded.redacted_content_sha256 {
                return Err(PrivacyWorkflowError::new(
                    "review_payload_mismatch",
                    "The approved review pages do not match the current protected review index.",
                ));
            }
            let risk = self.load_risk_state_unlocked(&connection, &request.redaction_id)?;
            if risk.session.redacted_content_sha256.as_str() != redacted_content_sha256
                || !risk.session.detector_run_completed
                || risk.session.document_risk.total_p0 != 0
                || risk.session.document_risk.total_p1 != 0
                || !risk.session.residual_scan.passed
                || risk.session.rejected
            {
                return Err(PrivacyWorkflowError::new(
                    "privacy_risk_gates_blocked",
                    "The latest risk review revision does not permit approved MCP publication.",
                ));
            }
            ApprovePrivacyReviewRequest {
                redaction_id: request.redaction_id.clone(),
                expected_risk_revision: Some(risk.session.revision),
                expected_suggested_redacted_sha256: loaded.redacted_content_sha256,
                edited_pages: pages
                    .into_iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.text,
                    })
                    .collect(),
                reviewer,
                destination: ReceiptDestinationInput {
                    kind: DestinationKind::ExternalMcpHost,
                    identifier: privacy::workspace::APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
                },
                purpose: privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
                ttl_seconds: request.ttl_seconds,
            }
        };
        let approved = self.approve_review_unlocked(approval_request, Some(&authorization))?;
        if approved.approved_payload_sha256 != expected_payload_sha256
            || approved.destination.kind != DestinationKind::ExternalMcpHost
            || approved.destination.identifier
                != privacy::workspace::APPROVED_WORKSPACE_DESTINATION_SCOPE
            || approved.purpose != privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE
        {
            return Err(PrivacyWorkflowError::new(
                "approved_workspace_receipt_invalid",
                "The approved MCP publication receipt has an invalid fixed binding.",
            ));
        }
        project_guard.commit()?;
        Ok(ApproveReviewForApprovedWorkspaceResponse {
            receipt_id: approved.receipt_id,
            approved_payload_sha256: approved.approved_payload_sha256,
            issued_at_unix: approved.issued_at_unix,
            expires_at_unix: approved.expires_at_unix,
            destination_identifier: approved.destination.identifier,
            purpose: approved.purpose,
            mcp_publish_approved: true,
        })
    }

    #[allow(dead_code)]
    pub fn delete_review(
        &self,
        request: DeletePrivacyReviewRequest,
    ) -> Result<DeletePrivacyReviewResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.delete_review_unlocked(request, None)
    }

    fn delete_review_unlocked(
        &self,
        request: DeletePrivacyReviewRequest,
        case_authorization: Option<&case_materials::CaseRedactionAuthorization>,
    ) -> Result<DeletePrivacyReviewResponse, PrivacyWorkflowError> {
        if !valid_identifier(&request.redaction_id)
            || !valid_hash(&request.expected_source_sha256)
            || !valid_hash(&request.expected_extraction_sha256)
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_delete_request",
                "待删除审阅的标识或预期哈希无效。",
            ));
        }

        let mut connection = self.open_connection()?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&connection, authorization)?;
        }
        let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let (source_sha256, deleted_at) = connection
            .query_row(
                "SELECT source_sha256,deleted_at
                 FROM privacy_materials WHERE material_id=?1",
                [&loaded.material_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "待删除原件身份无法核验。",
                )
            })?;
        if request.expected_source_sha256 != source_sha256
            || request.expected_extraction_sha256 != loaded.extraction_sha256
        {
            return Err(PrivacyWorkflowError::new(
                "redaction_stale",
                "审阅记录已变化，请重新载入后再删除。",
            ));
        }
        if deleted_at.is_some() {
            return Ok(DeletePrivacyReviewResponse { deleted: false });
        }
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| {
                PrivacyWorkflowError::new("review_payload_invalid", "本机审阅数据无法解密或解析。")
            })?;
        validate_loaded_review(&loaded, &stored)?;
        let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_review_identity_invalid",
                "The review material identity is invalid.",
            )
        })?;
        let generation_ids = {
            let mut statement = connection
                .prepare(
                    "SELECT redaction_id FROM privacy_redactions
                     WHERE material_id=?1 ORDER BY generation_number",
                )
                .map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_store_database_error",
                        "The material generation history cannot be read for deletion.",
                    )
                })?;
            let rows = statement
                .query_map([material_id.as_str()], |row| row.get::<_, String>(0))
                .map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_store_database_error",
                        "The material generation history cannot be read for deletion.",
                    )
                })?;
            rows.collect::<Result<BTreeSet<_>, _>>().map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "The material generation history cannot be read for deletion.",
                )
            })?
        };
        if generation_ids.is_empty() {
            return Err(PrivacyWorkflowError::new(
                "privacy_store_database_error",
                "The material has no revocable generation history.",
            ));
        }
        let vault_binding = self.verify_stored_vault_source(&connection, &stored)?;
        if case_authorization.is_some() && vault_binding.is_none() {
            return Err(PrivacyWorkflowError::new(
                "vault_reference_mismatch",
                "A case material is missing its exact Vault source reference; deletion was refused.",
            ));
        }
        let (binding_count, legal_hold_count, policy_revision) = connection
            .query_row(
                "SELECT COUNT(binding.redaction_id),
                        COALESCE(SUM(CASE WHEN binding.legal_hold=1 THEN 1 ELSE 0 END),0),
                        COALESCE(MAX(binding.policy_revision),0)
                 FROM privacy_redactions AS generation
                 LEFT JOIN privacy_retention_bindings AS binding
                   ON binding.redaction_id=generation.redaction_id
                 WHERE generation.material_id=?1",
                [material_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "retention_binding_unavailable",
                    "Material retention and legal-hold state cannot be verified; deletion was refused.",
                )
            })?;
        if usize::try_from(binding_count).ok() != Some(generation_ids.len()) || policy_revision <= 0
        {
            return Err(PrivacyWorkflowError::new(
                "retention_binding_unavailable",
                "Every material generation must have a valid retention binding before deletion.",
            ));
        }
        if legal_hold_count != 0 {
            return Err(PrivacyWorkflowError::new(
                "legal_hold_active",
                "The case material is under legal hold and cannot be deleted.",
            ));
        }

        if let Some(binding) = vault_binding.as_ref() {
            self.invalidate_material_publications(
                &binding.case_id,
                &material_id,
                "case_material_deleted",
            )?;
            self.invalidate_lifecycle_bindings(&generation_ids, "case_material_deleted")?;
        }
        let now_unix = self.current_unix()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        for redaction_id in &generation_ids {
            for output in lifecycle
                .list_approved_outputs(&connection, redaction_id)
                .map_err(PrivacyWorkflowError::lifecycle)?
                .into_iter()
                .filter(|output| !output.revoked)
            {
                lifecycle
                    .revoke_approved_output(&connection, &output.output_id, now_unix)
                    .map_err(PrivacyWorkflowError::lifecycle)?;
            }
        }
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&connection, authorization)?;
        }
        let deleted = match PrivacyStore::tombstone_redaction_material_exact(
            &mut connection,
            &request.redaction_id,
            &request.expected_source_sha256,
            &request.expected_extraction_sha256,
            now_unix,
        ) {
            Ok(deleted) => deleted,
            Err(PrivacyStoreError::Conflict) => {
                return Err(PrivacyWorkflowError::new(
                    "redaction_stale",
                    "审阅记录已变化，请重新载入后再删除。",
                ));
            }
            Err(error) => return Err(PrivacyWorkflowError::store(error)),
        };
        Ok(DeletePrivacyReviewResponse { deleted })
    }

    fn load_review_unlocked(
        &self,
        redaction_id: &str,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let connection = self.open_connection()?;
        let available = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM privacy_redactions AS generation
                   JOIN privacy_materials AS material
                     ON material.material_id=generation.material_id
                   WHERE generation.redaction_id=?1
                     AND generation.revocation_state='active'
                     AND generation.revoked_at IS NULL
                     AND material.deleted_at IS NULL
                 )",
                [redaction_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "The requested review availability cannot be verified.",
                )
            })?;
        if !available {
            return Err(PrivacyWorkflowError::new(
                "redaction_not_available",
                "The requested review is deleted, revoked, or unavailable.",
            ));
        }
        let loaded = PrivacyStore::load_review_draft(&connection, redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "本机审阅数据损坏或版本不受支持。",
                )
            })?;
        if stored.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
            || stored.redaction_id != loaded.redaction_id
            || stored.material_id != loaded.material_id
            || stored.extraction_sha256 != loaded.extraction_sha256
            || stored.suggested_redacted_content_sha256 != loaded.redacted_content_sha256
        {
            return Err(PrivacyWorkflowError::new(
                "review_payload_mismatch",
                "本机审阅数据与哈希索引不一致。",
            ));
        }
        let risk_review = PrivacyStore::load_latest_risk_review_revision(&connection, redaction_id)
            .map_err(PrivacyWorkflowError::store)?
            .map(|revision| {
                decode_risk_state(&revision)?
                    .session
                    .view()
                    .map_err(review_session_error)
            })
            .transpose()?;
        let mut view = stored_to_view(stored, &loaded.review_state)?;
        view.risk_review = risk_review;
        Ok(view)
    }
    fn verify_stored_vault_source(
        &self,
        connection: &Connection,
        stored: &StoredReviewPayload,
    ) -> Result<Option<vault_broker::VaultImportBinding>, PrivacyWorkflowError> {
        let binding =
            vault_broker::load_vault_binding_for_material(connection, &stored.material_id)
                .map_err(PrivacyWorkflowError::vault)?;
        match (
            binding,
            stored.case_id.as_deref(),
            stored.vault_object_id.as_deref(),
            stored.vault_object_version,
            stored.vault_isolation.as_ref(),
        ) {
            (None, None, None, None, None) => Ok(None),
            (Some(binding), Some(case_id), Some(object_id), Some(version), Some(_))
                if binding.case_id.as_str() == case_id
                    && binding.object_id.as_str() == object_id
                    && binding.object_version == version
                    && binding.source_sha256.as_str() == stored.source_sha256 =>
            {
                let status = self
                    .shared
                    .vault_broker
                    .isolation_status()
                    .map_err(PrivacyWorkflowError::vault)?;
                validate_vault_isolation(&status)?;
                let lease = self
                    .shared
                    .vault_broker
                    .read_source(&binding)
                    .map_err(PrivacyWorkflowError::vault)?;
                if sha256_hex(lease.content()) != stored.source_sha256 {
                    return Err(PrivacyWorkflowError::new(
                        "vault_source_mismatch",
                        "批准前 Vault 原件完整性复核失败；批准已拒绝。",
                    ));
                }
                drop(lease);
                Ok(Some(binding))
            }
            _ => Err(PrivacyWorkflowError::new(
                "vault_reference_mismatch",
                "审阅记录与 Vault 原件引用不一致；操作已拒绝。",
            )),
        }
    }
    #[allow(dead_code)]
    pub fn load_risk_review(
        &self,
        redaction_id: &str,
    ) -> Result<ReviewStateViewV1, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        self.load_risk_state_unlocked(&connection, redaction_id)?
            .session
            .view()
            .map_err(review_session_error)
    }

    #[allow(dead_code)]
    pub(crate) fn current_mapping_revision_binding(
        &self,
        redaction_id: &str,
    ) -> Result<Option<CurrentMappingRevisionBindingV1>, PrivacyWorkflowError> {
        let _gate = self.gate();
        if !valid_identifier(redaction_id) {
            return Err(PrivacyWorkflowError::new(
                "privacy_mapping_revision_request_invalid",
                "The mapping revision request is invalid.",
            ));
        }
        let connection = self.open_connection()?;
        let row = connection
            .query_row(
                "SELECT mapping_id,revision,mapping_revision_sha256
                 FROM privacy_sensitive_mappings
                 WHERE redaction_id=?1 AND revoked_at_unix IS NULL
                 ORDER BY revision DESC,created_at_unix DESC,mapping_id ASC LIMIT 1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_query_failed",
                    "The encrypted mapping revision could not be queried.",
                )
            })?;
        row.map(|(mapping_id, revision, hash)| {
            if !valid_identifier(&mapping_id) {
                return Err(PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping revision metadata is invalid.",
                ));
            }
            Ok(CurrentMappingRevisionBindingV1 {
                mapping_id,
                revision: u64::try_from(revision).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_mapping_revision_invalid",
                        "The encrypted mapping revision metadata is invalid.",
                    )
                })?,
                mapping_revision_hash: Sha256Hex::parse(hash).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_mapping_revision_invalid",
                        "The encrypted mapping revision hash is invalid.",
                    )
                })?,
            })
        })
        .transpose()
    }

    fn load_risk_state_unlocked(
        &self,
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<StoredRiskWorkflowStateV1, PrivacyWorkflowError> {
        let loaded = PrivacyStore::load_latest_risk_review_revision(connection, redaction_id)
            .map_err(PrivacyWorkflowError::store)?
            .ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "privacy_risk_state_missing",
                    "This review has no persisted production risk revision.",
                )
            })?;
        decode_risk_state(&loaded)
    }

    pub fn apply_risk_review_action(
        &self,
        request: ApplyPrivacyRiskReviewActionRequest,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.apply_risk_review_action_unlocked(request, None)
    }

    fn apply_risk_review_action_unlocked(
        &self,
        request: ApplyPrivacyRiskReviewActionRequest,
        case_authorization: Option<&case_materials::CaseRedactionAuthorization>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        if !valid_identifier(&request.redaction_id)
            || request.expected_revision == 0
            || request.actor.trim().is_empty()
            || request.actor.trim().len() > 128
            || request.actor.chars().any(char::is_control)
        {
            return Err(PrivacyWorkflowError::new(
                "privacy_review_input_invalid",
                "Risk review action metadata is invalid.",
            ));
        }
        let mut connection = self.open_connection()?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&connection, authorization)?;
        }
        let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let mut stored: StoredReviewPayload =
            serde_json::from_slice(&loaded.review_payload_plaintext).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "The protected editable review payload cannot be decoded.",
                )
            })?;
        validate_loaded_review(&loaded, &stored)?;
        self.verify_stored_vault_source(&connection, &stored)?;
        let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_case_dictionary_missing",
                "A production risk review must remain case-bound.",
            )
        })?)
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_review_identity_invalid",
                "The risk review case identity is invalid.",
            )
        })?;
        let current_dictionary =
            case_dictionary_store::load_required_case_dictionary(&connection, self, &case_id)?;
        let mut state = self.load_risk_state_unlocked(&connection, &request.redaction_id)?;
        verify_dictionary_revision(&state.session, &current_dictionary)?;
        if state.session.revision != request.expected_revision {
            return Err(PrivacyWorkflowError::new(
                "privacy_review_revision_conflict",
                "Risk review revision changed; reload before applying the action.",
            ));
        }
        let now_unix = self.current_unix()?;
        let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_review_identity_invalid",
                "The risk review material identity is invalid.",
            )
        })?;
        let pending_dictionary = if let ReviewActionV1::AddToDictionary {
            finding_id,
            category,
            required,
        } = &request.action
        {
            let finding = state
                .session
                .findings
                .iter()
                .find(|finding| finding.finding_id.as_str() == finding_id)
                .ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "privacy_review_finding_not_found",
                        "The dictionary action references a missing finding.",
                    )
                })?;
            let secret = case_dictionary_store::load_finding_secret(
                &connection,
                self,
                &case_id,
                &request.redaction_id,
                finding,
            )?;
            case_dictionary_store::prepare_add_finding_revision(
                self,
                &current_dictionary,
                &material_id,
                secret.as_str(),
                *category,
                *required,
                now_unix,
            )?
        } else {
            None
        };
        let action_dictionary = pending_dictionary
            .as_ref()
            .map(case_dictionary_store::PendingCaseDictionaryRevisionV1::snapshot)
            .unwrap_or(&current_dictionary);
        let edited_pages = normalize_edited_pages(&stored, request.edited_pages)?;
        reject_normalized_canaries(&edited_pages, &stored.forbidden_canaries)?;
        let page_texts = edited_pages
            .iter()
            .map(|page| page.text.clone())
            .collect::<Vec<_>>();
        let residual_scan = case_dictionary_store::scan_residuals(
            action_dictionary,
            &page_texts,
            &stored.source_display_name,
        )?;
        let redacted_bytes = canonical_redacted_bytes(&edited_pages)?;
        let redacted_sha = Sha256Hex::parse(sha256_hex(&redacted_bytes)).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Edited redacted content hash is invalid.",
            )
        })?;
        let provenance_hash = Sha256Hex::parse(sha256_hex(
            format!(
                "privacy-review-action-v1\0{}\0{}\0{}",
                request.redaction_id,
                request.expected_revision,
                redacted_sha.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Review action provenance is invalid.",
            )
        })?;
        let actor_hash =
            Sha256Hex::parse(sha256_hex(request.actor.trim().as_bytes())).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_input_invalid",
                    "Reviewer identity hash is invalid.",
                )
            })?;
        if state.undo_pages.len() == privacy::MAX_REVIEW_HISTORY {
            state.undo_pages.remove(0);
        }
        state.undo_pages.push(state.current_pages.clone());
        state.redo_pages.clear();
        state.session.assessment.dictionary_entities_stable =
            dictionary_entities_stable_after_action(&state.session, &request.action);
        state
            .session
            .apply_action(
                request.expected_revision,
                &request.action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor_hash,
                    occurred_at_unix: now_unix,
                    verified_redacted_content_sha256: &redacted_sha,
                    provenance_hash: &provenance_hash,
                    residual_scan: &residual_scan,
                    dictionary_revision_hash: Some(action_dictionary.revision_hash()),
                },
            )
            .map_err(review_session_error)?;
        state.current_pages = edited_pages;
        install_risk_pages_in_review(&mut stored, &state.current_pages)?;
        stored.suggested_redacted_content_sha256 = redacted_sha.as_str().to_owned();
        let review_payload = serde_json::to_vec(&stored).map_err(|_| {
            PrivacyWorkflowError::new(
                "review_payload_invalid",
                "Updated review payload cannot be serialized.",
            )
        })?;
        let unresolved = state
            .session
            .document_risk
            .total_p0
            .saturating_add(state.session.document_risk.total_p1);
        if pending_dictionary.is_some() {
            self.invalidate_case_publications(&case_id, "case_dictionary_revision_changed")?;
        } else {
            self.invalidate_material_publications(
                &case_id,
                &material_id,
                "risk_review_revision_changed",
            )?;
        }
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| {
                PrivacyWorkflowError::new("privacy_store_busy", "Risk review store is busy.")
            })?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&transaction, authorization)?;
        }
        if let Some(pending) = pending_dictionary.as_ref() {
            case_dictionary_store::commit_pending_revision(&transaction, pending)?;
        }
        PrivacyStore::update_review_draft_exact(
            &transaction,
            &request.redaction_id,
            &loaded.redacted_content_sha256,
            redacted_sha.as_str(),
            unresolved,
            &review_payload,
        )
        .map_err(PrivacyWorkflowError::store)?;
        append_risk_revision(&transaction, &state, request.expected_revision)?;
        transaction.commit().map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_commit_failed",
                "Editable pages and the risk revision were not committed atomically.",
            )
        })?;
        let mut view = stored_to_view(stored, &loaded.review_state)?;
        view.risk_review = Some(state.session.view().map_err(review_session_error)?);
        Ok(view)
    }

    #[allow(dead_code)]
    pub fn undo_risk_review(
        &self,
        request: PrivacyRiskReviewRevisionRequest,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        self.move_risk_review_history(request, false)
    }

    #[allow(dead_code)]
    pub fn redo_risk_review(
        &self,
        request: PrivacyRiskReviewRevisionRequest,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        self.move_risk_review_history(request, true)
    }

    #[allow(dead_code)]
    fn move_risk_review_history(
        &self,
        request: PrivacyRiskReviewRevisionRequest,
        redo: bool,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.move_risk_review_history_unlocked(request, redo, None)
    }

    fn move_risk_review_history_unlocked(
        &self,
        request: PrivacyRiskReviewRevisionRequest,
        redo: bool,
        case_authorization: Option<&case_materials::CaseRedactionAuthorization>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        if !valid_identifier(&request.redaction_id) || request.expected_revision == 0 {
            return Err(PrivacyWorkflowError::new(
                "privacy_review_input_invalid",
                "Risk review history request is invalid.",
            ));
        }
        let mut connection = self.open_connection()?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&connection, authorization)?;
        }
        let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let mut stored: StoredReviewPayload =
            serde_json::from_slice(&loaded.review_payload_plaintext).map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "Review payload cannot be decoded.",
                )
            })?;
        validate_loaded_review(&loaded, &stored)?;
        self.verify_stored_vault_source(&connection, &stored)?;
        let mut state = self.load_risk_state_unlocked(&connection, &request.redaction_id)?;
        let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_case_dictionary_missing",
                "A production risk review must remain case-bound.",
            )
        })?)
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_review_identity_invalid",
                "The risk review case identity is invalid.",
            )
        })?;
        let dictionary =
            case_dictionary_store::load_required_case_dictionary(&connection, self, &case_id)?;
        verify_dictionary_revision(&state.session, &dictionary)?;
        if state.session.revision != request.expected_revision {
            return Err(PrivacyWorkflowError::new(
                "privacy_review_revision_conflict",
                "Risk review revision changed; reload before changing history.",
            ));
        }
        let target_pages = if redo {
            state.redo_pages.pop()
        } else {
            state.undo_pages.pop()
        }
        .ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_review_history_unavailable",
                "The requested risk review history entry is unavailable.",
            )
        })?;
        if redo {
            if state.undo_pages.len() == privacy::MAX_REVIEW_HISTORY {
                state.undo_pages.remove(0);
            }
            state.undo_pages.push(state.current_pages.clone());
        } else {
            if state.redo_pages.len() == privacy::MAX_REVIEW_HISTORY {
                state.redo_pages.remove(0);
            }
            state.redo_pages.push(state.current_pages.clone());
        }
        let now_unix = self.current_unix()?;
        if redo {
            state
                .session
                .redo(request.expected_revision, now_unix)
                .map_err(review_session_error)?;
        } else {
            state
                .session
                .undo(request.expected_revision, now_unix)
                .map_err(review_session_error)?;
        }
        verify_dictionary_revision(&state.session, &dictionary)?;
        state.current_pages = target_pages;
        validate_risk_state(&state, state.session.revision)?;
        install_risk_pages_in_review(&mut stored, &state.current_pages)?;
        stored.suggested_redacted_content_sha256 =
            state.session.redacted_content_sha256.as_str().to_owned();
        let review_payload = serde_json::to_vec(&stored).map_err(|_| {
            PrivacyWorkflowError::new(
                "review_payload_invalid",
                "Review payload cannot be serialized.",
            )
        })?;
        let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_review_identity_invalid",
                "The risk review material identity is invalid.",
            )
        })?;
        self.invalidate_material_publications(
            &case_id,
            &material_id,
            "risk_review_revision_changed",
        )?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| {
                PrivacyWorkflowError::new("privacy_store_busy", "Risk review store is busy.")
            })?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&transaction, authorization)?;
        }
        PrivacyStore::update_review_draft_exact(
            &transaction,
            &request.redaction_id,
            &loaded.redacted_content_sha256,
            state.session.redacted_content_sha256.as_str(),
            state
                .session
                .document_risk
                .total_p0
                .saturating_add(state.session.document_risk.total_p1),
            &review_payload,
        )
        .map_err(PrivacyWorkflowError::store)?;
        append_risk_revision(&transaction, &state, request.expected_revision)?;
        transaction.commit().map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_commit_failed",
                "Review pages and history revision were not committed atomically.",
            )
        })?;
        let mut view = stored_to_view(stored, &loaded.review_state)?;
        view.risk_review = Some(state.session.view().map_err(review_session_error)?);
        Ok(view)
    }
    /// Renderer-facing approval entry point. External Provider and MCP scopes
    /// must use their dedicated, fixed-purpose approval commands instead.
    #[allow(dead_code)]
    pub fn approve_local_safe_export_review(
        &self,
        request: ApprovePrivacyReviewRequest,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.approve_local_safe_export_review_unlocked(request, None)
    }

    fn approve_local_safe_export_review_unlocked(
        &self,
        request: ApprovePrivacyReviewRequest,
        case_authorization: Option<&case_materials::CaseRedactionAuthorization>,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        if request.destination.kind != DestinationKind::VerifiedLocalProvider {
            return Err(PrivacyWorkflowError::new(
                "dedicated_approval_required",
                "External Provider and MCP destinations require their dedicated approval flow.",
            ));
        }
        self.approve_review_unlocked(request, case_authorization)
    }

    #[allow(dead_code)]
    pub fn approve_review(
        &self,
        request: ApprovePrivacyReviewRequest,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.approve_review_unlocked(request, None)
    }

    fn approve_review_unlocked(
        &self,
        request: ApprovePrivacyReviewRequest,
        case_authorization: Option<&case_materials::CaseRedactionAuthorization>,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        validate_approval_request(&request)?;
        let connection = self.open_connection()?;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&connection, authorization)?;
        }
        let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        if request.expected_suggested_redacted_sha256 != loaded.redacted_content_sha256 {
            return Err(PrivacyWorkflowError::new(
                "redaction_stale",
                "审阅草稿哈希已变化，请重新载入后再批准。",
            ));
        }
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| {
                PrivacyWorkflowError::new("review_payload_invalid", "本机审阅数据无法解密或解析。")
            })?;
        validate_loaded_review(&loaded, &stored)?;
        self.verify_stored_vault_source(&connection, &stored)?;

        let edited_pages = normalize_edited_pages(&stored, request.edited_pages)?;
        reject_normalized_canaries(&edited_pages, &stored.forbidden_canaries)?;
        let redacted_content_bytes = canonical_redacted_bytes(&edited_pages)?;
        let redacted_content_sha256 = sha256_hex(&redacted_content_bytes);
        let approved = ApprovedPayload {
            schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
            source_sha256: &stored.source_sha256,
            extraction_sha256: &stored.extraction_sha256,
            media_type: &stored.media_type,
            pages: &edited_pages,
        };
        let approved_payload = serde_json::to_vec(&approved).map_err(|_| {
            PrivacyWorkflowError::new("canonicalization_failed", "获批载荷无法进行确定性序列化。")
        })?;
        let residual = scan_residual(&approved_payload).map_err(|error| {
            PrivacyWorkflowError::new(error.code(), "获批载荷无法完成残留敏感信息扫描。")
        })?;
        if !residual.passed {
            return Err(PrivacyWorkflowError::new(
                "residual_sensitive_content",
                format!(
                    "人工修改后的载荷仍含高置信敏感标识，批准已拒绝；仅记录类别计数：{:?}",
                    residual.counts
                ),
            ));
        }
        if matches!(
            &request.destination.kind,
            DestinationKind::VerifiedLocalProvider
        ) {
            let destination = DestinationScope {
                kind: request.destination.kind.clone(),
                identifier: request.destination.identifier.trim().to_owned(),
            };
            let format = SafeExportFormat::from_scope(&destination, request.purpose.trim())
                .ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "approval_scope_unsupported",
                        "本机安全导出目标或用途不受支持。",
                    )
                })?;
            safe_derived::preflight_safe_export_delivery(
                format,
                &edited_pages,
                &stored.forbidden_canaries,
            )?;
        }
        let approved_payload_sha256 = sha256_hex(&approved_payload);
        let reviewer_sha256 = sha256_hex(request.reviewer.trim().as_bytes());
        let destination = DestinationScope {
            kind: request.destination.kind,
            identifier: request.destination.identifier.trim().to_owned(),
        };
        let now_unix = self.current_unix()?;
        let expires_at_unix = now_unix.checked_add(request.ttl_seconds).ok_or_else(|| {
            PrivacyWorkflowError::new("invalid_receipt_ttl", "回执有效期超出范围。")
        })?;
        let publication_bound_risk = if stored.case_id.is_some() {
            let expected_revision = request.expected_risk_revision.ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "privacy_review_revision_required",
                    "The exact risk review revision is required before approval.",
                )
            })?;
            let mut state = self.load_risk_state_unlocked(&connection, &request.redaction_id)?;
            if state.session.revision != expected_revision
                || state.session.redacted_content_sha256.as_str() != redacted_content_sha256
            {
                return Err(PrivacyWorkflowError::new(
                    "privacy_review_revision_conflict",
                    "Risk review revision or edited content changed; reload and save the risk review before approval.",
                ));
            }
            let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "privacy_case_dictionary_missing",
                    "Approval requires a current case dictionary binding.",
                )
            })?)
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_identity_invalid",
                    "The approval case identity is invalid.",
                )
            })?;
            let dictionary =
                case_dictionary_store::load_required_case_dictionary(&connection, self, &case_id)?;
            verify_dictionary_revision(&state.session, &dictionary)?;
            let approved_page_texts = edited_pages
                .iter()
                .map(|page| page.text.clone())
                .collect::<Vec<_>>();
            let bound_residual = case_dictionary_store::scan_residuals(
                &dictionary,
                &approved_page_texts,
                &stored.source_display_name,
            )?;
            if !bound_residual.passed
                || bound_residual.evidence_hash != state.session.residual_scan.evidence_hash
            {
                return Err(PrivacyWorkflowError::new(
                    "privacy_residual_evidence_conflict",
                    "The current dictionary or source-name residual evidence does not match the approved revision.",
                ));
            }
            let target_claims = PublicationTargetBindingV1 {
                schema_version: "privacy-publication-target-binding-v1",
                destination_kind: &destination.kind,
                destination_identifier: &destination.identifier,
                purpose: request.purpose.trim(),
                approved_payload_sha256: &approved_payload_sha256,
                redacted_content_sha256: &redacted_content_sha256,
            };
            let target_bytes = canonical_json_v1(&target_claims).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_publication_target_invalid",
                    "The exact publication target cannot be canonicalized.",
                )
            })?;
            let target_hash = Sha256Hex::parse(sha256_hex(&target_bytes)).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_publication_target_invalid",
                    "The exact publication target hash is invalid.",
                )
            })?;
            let risk_policy = state.session.risk_policy.clone();
            let qualification = state.session.qualification.clone();
            state
                .session
                .bind_publication_context(
                    expected_revision,
                    target_hash,
                    RequestedApprovalRoute::Human,
                    risk_policy,
                    qualification,
                    now_unix,
                )
                .map_err(review_session_error)?;
            let risk_view = state.session.view().map_err(review_session_error)?;
            let blockers = risk_view
                .hard_gates
                .iter()
                .filter(|gate| {
                    gate.blocking
                        && !gate.passed
                        && !matches!(
                            gate.gate_id.as_str(),
                            "calibrated_policy"
                                | "approval_mode_allows_automatic"
                                | "organization_policy_allows_automatic"
                        )
                })
                .map(|gate| gate.gate_id.clone())
                .collect::<Vec<_>>();
            if !state.session.detector_run_completed
                || !blockers.is_empty()
                || state.session.document_risk.total_p0 != 0
                || state.session.document_risk.total_p1 != 0
                || !state.session.residual_scan.passed
                || state.session.rejected
            {
                return Err(PrivacyWorkflowError::new(
                    "privacy_risk_gates_blocked",
                    format!(
                        "Production risk gates block approval: {}.",
                        if blockers.is_empty() {
                            "detector_or_residual_evidence".to_owned()
                        } else {
                            blockers.join(",")
                        }
                    ),
                ));
            }
            Some(state)
        } else {
            if request.expected_risk_revision.is_some() {
                return Err(PrivacyWorkflowError::new(
                    "privacy_risk_state_missing",
                    "A risk revision was supplied for a legacy review without a production risk session.",
                ));
            }
            None
        };
        if let Some(case_id) = stored.case_id.as_ref() {
            let case_id = CaseId::parse(case_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_identity_invalid",
                    "The approval case identity is invalid.",
                )
            })?;
            let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_review_identity_invalid",
                    "The approval material identity is invalid.",
                )
            })?;
            self.invalidate_material_publications(
                &case_id,
                &material_id,
                "review_approval_revision_changed",
            )?;
        }
        self.privacy_lifecycle(&connection)?
            .bind_redaction_retention(&connection, &request.redaction_id, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let mut approved_stored = stored.clone();
        approved_stored.suggested_redacted_content_sha256 = redacted_content_sha256.clone();
        for (stored_page, approved_page) in approved_stored.pages.iter_mut().zip(&edited_pages) {
            stored_page.suggested_redacted_text = approved_page.text.clone();
        }
        let approved_review_payload_plaintext =
            serde_json::to_vec(&approved_stored).map_err(|_| {
                PrivacyWorkflowError::new("review_payload_invalid", "最终获批审阅数据无法序列化。")
            })?;
        let signer = self.receipt_signer()?;

        let mut mutable_connection = connection;
        if let Some(authorization) = case_authorization {
            self.revalidate_case_redaction_authorization(&mutable_connection, authorization)?;
        }
        let approval_result = if let Some(state) = publication_bound_risk.as_ref() {
            let state_plaintext = encode_risk_state(state)?;
            let risk_sha256 = state.session.risk_sha256().map_err(review_session_error)?;
            let hard_gate_sha256 = state
                .session
                .hard_gate_sha256()
                .map_err(review_session_error)?;
            let expected_previous_revision =
                state.session.revision.checked_sub(1).ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "privacy_review_revision_conflict",
                        "The publication-bound risk revision is invalid.",
                    )
                })?;
            PrivacyStore::approve_review_with_risk_revision(
                &mut mutable_connection,
                &privacy::ApproveReviewWithRiskRevision {
                    redaction_id: &request.redaction_id,
                    expected_redacted_sha256: &request.expected_suggested_redacted_sha256,
                    approved_redacted_content_sha256: &redacted_content_sha256,
                    approved_payload_sha256: &approved_payload_sha256,
                    reviewed_by_sha256: &reviewer_sha256,
                    approved_review_payload_plaintext: &approved_review_payload_plaintext,
                    approved_payload_plaintext: &approved_payload,
                    risk_revision: SaveRiskReviewRevision {
                        redaction_id: &request.redaction_id,
                        expected_previous_revision,
                        risk_sha256: &risk_sha256,
                        hard_gate_sha256: &hard_gate_sha256,
                        action_code: &state.session.last_action_code,
                        reason_codes: &state.session.document_risk.reason_codes,
                        state_plaintext: &state_plaintext,
                    },
                },
            )
        } else {
            PrivacyStore::approve_review(
                &mut mutable_connection,
                &request.redaction_id,
                &request.expected_suggested_redacted_sha256,
                &redacted_content_sha256,
                &approved_payload_sha256,
                &reviewer_sha256,
                &approved_review_payload_plaintext,
            )
        };
        match approval_result {
            Ok(()) => {}
            Err(PrivacyStoreError::Conflict) => {
                let already_approved = mutable_connection
                    .query_row(
                        "SELECT approved_payload_sha256 FROM privacy_redactions
                         WHERE redaction_id=?1 AND review_state='approved'",
                        [&request.redaction_id],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()
                    .map_err(|_| {
                        PrivacyWorkflowError::new(
                            "privacy_store_database_error",
                            "批准状态无法核验。",
                        )
                    })?
                    .flatten();
                if already_approved.as_deref() != Some(approved_payload_sha256.as_str()) {
                    return Err(PrivacyWorkflowError::new(
                        "redaction_stale",
                        "审阅状态或获批载荷已变化，请重新载入。",
                    ));
                }
            }
            Err(error) => return Err(PrivacyWorkflowError::store(error)),
        }

        let receipt = signer
            .issue(RedactionReceiptClaims {
                receipt_id: format!("rct_{}", Uuid::new_v4().simple()),
                source_sha256: vec![stored.source_sha256.clone()],
                extraction_sha256: stored.extraction_sha256.clone(),
                redacted_content_sha256: redacted_content_sha256.clone(),
                approved_payload_sha256: approved_payload_sha256.clone(),
                policy_id: POLICY_ID.to_owned(),
                policy_version: POLICY_VERSION,
                detector_version: REDACTION_VERSION.to_owned(),
                destination: destination.clone(),
                purpose: request.purpose.trim().to_owned(),
                unresolved_high_risk_count: 0,
                review_state: ReviewState::Approved,
                issued_at_unix: now_unix,
                expires_at_unix: Some(expires_at_unix),
                key_version: RECEIPT_KEY_VERSION,
            })
            .map_err(|error| PrivacyWorkflowError::new(error.code(), "本机签名回执生成失败。"))?;
        let receipt_token = signer
            .encode_token(&receipt)
            .map_err(|error| PrivacyWorkflowError::new(error.code(), "本机签名回执编码失败。"))?;

        let engine = EgressPolicyEngine::new(signer.clone(), POLICY_ID, POLICY_VERSION)
            .map_err(|error| PrivacyWorkflowError::new(error.code(), "本机隐私策略初始化失败。"))?;
        let (authorization, mut audit) = engine.authorize_with_audit(&EgressCandidate {
            payload: &approved_payload,
            classification: privacy::DataClassification::CaseRedactedApproved,
            destination: &destination,
            purpose: request.purpose.trim(),
            receipt: Some(&receipt),
            now_unix,
        });
        authorization.map_err(|error| {
            PrivacyWorkflowError::new(error.code(), "签名回执未通过本机精确载荷复核。")
        })?;
        audit.reason_code = "local_receipt_authorization_only".to_owned();
        PrivacyStore::append_egress_audit(
            &mut mutable_connection,
            &format!("audit_{}", Uuid::new_v4().simple()),
            &audit,
        )
        .map_err(PrivacyWorkflowError::store)?;
        PrivacyStore::persist_receipt(
            &mut mutable_connection,
            &request.redaction_id,
            &signer,
            &receipt,
            &receipt_token,
            &approved_payload,
            now_unix,
        )
        .map_err(PrivacyWorkflowError::store)?;

        let approved_payload_json = String::from_utf8(approved_payload).map_err(|_| {
            PrivacyWorkflowError::new("canonicalization_failed", "获批载荷不是 UTF-8。")
        })?;
        Ok(ApprovePrivacyReviewResponse {
            receipt_id: receipt.claims.receipt_id,
            receipt_token,
            approved_payload_json,
            approved_payload_sha256,
            redacted_content_sha256,
            issued_at_unix: now_unix,
            expires_at_unix,
            destination,
            purpose: request.purpose.trim().to_owned(),
            transport_enforcement: "active_receipt_persisted_exact_destination",
        })
    }

    #[allow(dead_code)]
    pub fn record_safe_pdf_export_cancellation(
        &self,
        request: &ExportApprovedReviewPdfRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        let destination = DestinationScope {
            kind: request.destination.kind.clone(),
            identifier: request.destination.identifier.trim().to_owned(),
        };
        if !valid_identifier(&request.redaction_id)
            || request.receipt_token.len() > 65_536
            || request.approved_payload_json.len() > 16 * 1024 * 1024
            || !matches!(destination.kind, DestinationKind::VerifiedLocalProvider)
            || destination.identifier != LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER
            || request.purpose.trim() != LOCAL_SAFE_PDF_PURPOSE
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "The cancelled local safe-export request is invalid.",
            ));
        }
        let signer = self.receipt_signer()?;
        let receipt = signer
            .decode_token(&request.receipt_token)
            .map_err(|error| {
                PrivacyWorkflowError::new(
                    error.code(),
                    "The cancelled local safe-export receipt is invalid.",
                )
            })?;
        let approved_payload_sha256 = sha256_hex(request.approved_payload_json.as_bytes());
        if receipt.claims.destination != destination
            || receipt.claims.purpose != request.purpose.trim()
            || receipt.claims.approved_payload_sha256 != approved_payload_sha256
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "The cancelled local safe-export request does not match its signed receipt.",
            ));
        }
        let mut connection = self.open_connection()?;
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: self.current_unix()?,
            classification: DataClassification::CaseRedactedApproved,
            destination_kind: destination.kind,
            destination_identifier_sha256: sha256_hex(destination.identifier.as_bytes()),
            purpose: request.purpose.trim().to_owned(),
            payload_sha256: approved_payload_sha256,
            payload_bytes: request.approved_payload_json.len(),
            policy_id: POLICY_ID.to_owned(),
            policy_version: POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: Some(receipt.claims.receipt_id),
            residual_counts: BTreeMap::new(),
            allowed: false,
            reason_code: "local_safe_pdf_export_cancelled".to_owned(),
        };
        PrivacyStore::append_egress_audit(
            &mut connection,
            &format!("audit_{}", Uuid::new_v4().simple()),
            &audit,
        )
        .map_err(PrivacyWorkflowError::store)?;
        Ok(())
    }
    #[allow(dead_code)]
    pub fn record_safe_pdf_export_event(
        &self,
        request: &ExportApprovedReviewPdfRequest,
        built: &BuiltSafePdf,
        allowed: bool,
        reason_code: &str,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        let destination = DestinationScope {
            kind: request.destination.kind.clone(),
            identifier: request.destination.identifier.trim().to_owned(),
        };
        if request.receipt_token.len() > 65_536
            || request.approved_payload_json.len() > 16 * 1024 * 1024
            || !valid_identifier(reason_code)
            || !valid_hash(&built.sha256)
            || built.bytes.is_empty()
            || built.bytes.len() > SafePdfExportLimits::default().max_output_bytes
            || !matches!(destination.kind, DestinationKind::VerifiedLocalProvider)
            || destination.identifier != LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER
            || request.purpose.trim() != LOCAL_SAFE_PDF_PURPOSE
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "The local safe-export audit event is invalid.",
            ));
        }
        let signer = self.receipt_signer()?;
        let receipt = signer
            .decode_token(&request.receipt_token)
            .map_err(|error| {
                PrivacyWorkflowError::new(
                    error.code(),
                    "The local safe-export audit receipt is invalid.",
                )
            })?;
        if receipt.claims.destination != destination
            || receipt.claims.purpose != request.purpose.trim()
            || receipt.claims.approved_payload_sha256
                != sha256_hex(request.approved_payload_json.as_bytes())
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "The local safe-export audit event does not match its signed receipt.",
            ));
        }
        let mut connection = self.open_connection()?;
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: self.current_unix()?,
            classification: DataClassification::CaseRedactedApproved,
            destination_kind: destination.kind,
            destination_identifier_sha256: sha256_hex(destination.identifier.as_bytes()),
            purpose: request.purpose.trim().to_owned(),
            payload_sha256: built.sha256.clone(),
            payload_bytes: built.bytes.len(),
            policy_id: POLICY_ID.to_owned(),
            policy_version: POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: Some(receipt.claims.receipt_id),
            residual_counts: BTreeMap::new(),
            allowed,
            reason_code: reason_code.to_owned(),
        };
        PrivacyStore::append_egress_audit(
            &mut connection,
            &format!("audit_{}", Uuid::new_v4().simple()),
            &audit,
        )
        .map_err(PrivacyWorkflowError::store)?;
        Ok(())
    }
    #[allow(dead_code)]
    pub fn verify_safe_pdf_authorization(
        &self,
        request: &ExportApprovedReviewPdfRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        if !valid_identifier(&request.redaction_id)
            || request.receipt_token.len() > 65_536
            || request.approved_payload_json.len() > 16 * 1024 * 1024
            || !valid_identifier(request.destination.identifier.trim())
            || !valid_identifier(request.purpose.trim())
            || !matches!(
                &request.destination.kind,
                DestinationKind::VerifiedLocalProvider
            )
            || request.destination.identifier.trim() != LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER
            || request.purpose.trim() != LOCAL_SAFE_PDF_PURPOSE
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_request",
                "The safe export request receipt, target, purpose, or payload is invalid.",
            ));
        }
        let destination = DestinationScope {
            kind: request.destination.kind.clone(),
            identifier: request.destination.identifier.trim().to_owned(),
        };
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let connection = self.open_connection()?;
        PrivacyStore::verify_active_receipt_token(
            &connection,
            &signer,
            &ActiveReceiptVerification {
                redaction_id: &request.redaction_id,
                signed_token: &request.receipt_token,
                approved_payload: request.approved_payload_json.as_bytes(),
                destination: &destination,
                purpose: request.purpose.trim(),
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        )
        .map_err(|error| {
            PrivacyWorkflowError::new(
                error.code(),
                "The safe export receipt failed the final local active-receipt verification.",
            )
        })?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn build_safe_pdf(
        &self,
        request: ExportApprovedReviewPdfRequest,
    ) -> Result<BuiltSafePdf, PrivacyWorkflowError> {
        let _gate = self.gate();
        if !valid_identifier(&request.redaction_id)
            || request.receipt_token.len() > 65_536
            || request.approved_payload_json.len() > 16 * 1024 * 1024
            || !valid_identifier(request.destination.identifier.trim())
            || !valid_identifier(request.purpose.trim())
            || !matches!(
                &request.destination.kind,
                DestinationKind::VerifiedLocalProvider
            )
            || request.destination.identifier.trim() != LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER
            || request.purpose.trim() != LOCAL_SAFE_PDF_PURPOSE
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_request",
                "安全导出请求的回执、目标、用途或载荷无效。",
            ));
        }
        let destination = DestinationScope {
            kind: request.destination.kind,
            identifier: request.destination.identifier.trim().to_owned(),
        };
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let connection = self.open_connection()?;
        PrivacyStore::verify_active_receipt_token(
            &connection,
            &signer,
            &ActiveReceiptVerification {
                redaction_id: &request.redaction_id,
                signed_token: &request.receipt_token,
                approved_payload: request.approved_payload_json.as_bytes(),
                destination: &destination,
                purpose: request.purpose.trim(),
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        )
        .map_err(|error| {
            PrivacyWorkflowError::new(
                error.code(),
                "安全导出回执未通过本机持久化、撤销、精确载荷、目标、用途或有效期复核。",
            )
        })?;

        let loaded = PrivacyStore::load_review_draft(&connection, &request.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        if loaded.review_state != "approved" {
            return Err(PrivacyWorkflowError::new(
                "redaction_not_approved",
                "当前材料尚未处于获批状态。",
            ));
        }
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "安全导出无法读取受保护审阅数据。",
                )
            })?;
        validate_loaded_review(&loaded, &stored)?;
        self.verify_stored_vault_source(&connection, &stored)?;
        let approved: OwnedApprovedPayload = serde_json::from_str(&request.approved_payload_json)
            .map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_payload_invalid",
                "获批载荷不是严格规范的本机 JSON。",
            )
        })?;
        if approved.schema_version != APPROVED_PAYLOAD_SCHEMA_VERSION
            || approved.source_sha256 != stored.source_sha256
            || approved.extraction_sha256 != stored.extraction_sha256
            || approved.media_type != stored.media_type
            || approved.pages.len() != stored.pages.len()
        {
            return Err(PrivacyWorkflowError::new(
                "redaction_stale",
                "获批载荷与受保护审阅来源不一致。",
            ));
        }
        reject_normalized_canaries(&approved.pages, &stored.forbidden_canaries)?;
        let residual =
            scan_residual(request.approved_payload_json.as_bytes()).map_err(|error| {
                PrivacyWorkflowError::new(error.code(), "安全导出前残留敏感信息扫描失败。")
            })?;
        if !residual.passed {
            return Err(PrivacyWorkflowError::new(
                "residual_sensitive_content",
                "获批载荷在当前 detector 下仍含高置信敏感标识。",
            ));
        }
        if stored.forbidden_canaries.is_empty() {
            return Err(PrivacyWorkflowError::new(
                "safe_export_missing_canary",
                "没有可用于输出复检的源敏感 canary，安全导出保持关闭。",
            ));
        }
        let pages = approved
            .pages
            .into_iter()
            .map(|page| ApprovedTextPage {
                page_number: page.page_number,
                text: page.text,
            })
            .collect::<Vec<_>>();
        let approved_text_hash = approved_text_sha256(&pages).map_err(safe_export_error)?;
        let SafePdfArtifact {
            bytes,
            sha256,
            approved_text_sha256,
            extracted_text_sha256,
            output_page_count,
            ..
        } = reconstruct_approved_text_pdf(
            &SafePdfExportRequest {
                approved_text_sha256: approved_text_hash,
                pages,
                forbidden_canaries: stored.forbidden_canaries,
            },
            SafePdfExportLimits::default(),
        )
        .map_err(safe_export_error)?;
        Ok(BuiltSafePdf {
            bytes,
            sha256,
            approved_text_sha256,
            extracted_text_sha256,
            output_page_count,
        })
    }
}

fn preflight_safe_pdf_delivery(
    pages: &[CanonicalRedactedPage],
    forbidden_canaries: &[String],
) -> Result<(), PrivacyWorkflowError> {
    let approved_pages = pages
        .iter()
        .map(|page| ApprovedTextPage {
            page_number: page.page_number,
            text: page.text.clone(),
        })
        .collect::<Vec<_>>();
    let approved_text_hash = approved_text_sha256(&approved_pages).map_err(safe_export_error)?;
    reconstruct_approved_text_pdf(
        &SafePdfExportRequest {
            approved_text_sha256: approved_text_hash,
            pages: approved_pages,
            forbidden_canaries: forbidden_canaries.to_vec(),
        },
        SafePdfExportLimits::default(),
    )
    .map_err(safe_export_error)?;
    Ok(())
}
fn install_risk_pages_in_review(
    stored: &mut StoredReviewPayload,
    pages: &[CanonicalRedactedPage],
) -> Result<(), PrivacyWorkflowError> {
    if stored.pages.len() != pages.len() {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_state_invalid",
            "Risk review page count does not match the editable review.",
        ));
    }
    for (stored_page, page) in stored.pages.iter_mut().zip(pages) {
        if stored_page.page_number != page.page_number {
            return Err(PrivacyWorkflowError::new(
                "privacy_risk_state_invalid",
                "Risk review page identity changed.",
            ));
        }
        stored_page.suggested_redacted_text = page.text.clone();
    }
    Ok(())
}
fn initial_risk_workflow_state(
    stored: &StoredReviewPayload,
    detector_run: Option<&local_detection::CompletedDetectorRunV1>,
    dictionary: Option<&case_dictionary_store::CaseDictionarySnapshotV1>,
    now_unix: u64,
) -> Result<Option<StoredRiskWorkflowStateV1>, PrivacyWorkflowError> {
    let Some(case_id) = stored.case_id.as_ref() else {
        return Ok(None);
    };
    let case_id = CaseId::parse(case_id.clone()).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_review_identity_invalid",
            "Risk review case identity is invalid.",
        )
    })?;
    let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_review_identity_invalid",
            "Risk review material identity is invalid.",
        )
    })?;
    let detector_run = detector_run.ok_or_else(|| {
        PrivacyWorkflowError::new(
            "privacy_detector_run_missing",
            "A Vault-bound case review requires a completed local detector run.",
        )
    })?;
    let dictionary = dictionary.ok_or_else(|| {
        PrivacyWorkflowError::new(
            "privacy_case_dictionary_missing",
            "A case-bound review requires current encrypted dictionary evidence.",
        )
    })?;
    if dictionary.case_id() != &case_id
        || dictionary.revision_hash() != &detector_run.dictionary_revision_hash
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_case_dictionary_revision_conflict",
            "The detector and review dictionary revisions do not match.",
        ));
    }
    let current_pages = stored
        .pages
        .iter()
        .map(|page| CanonicalRedactedPage {
            page_number: page.page_number,
            text: page.suggested_redacted_text.clone(),
        })
        .collect::<Vec<_>>();
    let current_page_texts = current_pages
        .iter()
        .map(|page| page.text.clone())
        .collect::<Vec<_>>();
    let residual_scan = case_dictionary_store::scan_residuals(
        dictionary,
        &current_page_texts,
        &stored.source_display_name,
    )?;
    let mut pages = stored
        .pages
        .iter()
        .enumerate()
        .map(|(page_index, page)| page_assessment_from_stored(page_index, page))
        .collect::<Result<Vec<_>, _>>()?;
    apply_findings_to_page_assessments(&mut pages, &detector_run.findings)?;
    let provenance_hash = Sha256Hex::parse(sha256_hex(
        format!(
            "privacy-initial-review-v2\0{}\0{}\0{}\0{}",
            stored.source_sha256,
            stored.extraction_sha256,
            stored.suggested_redacted_content_sha256,
            detector_run.detector_evidence_hash.as_str(),
        )
        .as_bytes(),
    ))
    .map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_risk_evidence_invalid",
            "Risk provenance hash is invalid.",
        )
    })?;
    let policy_sha256 = Sha256Hex::parse(sha256_hex(b"privacy-app-manual-fail-closed-policy-v1"))
        .map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_risk_policy_invalid",
            "Risk policy hash is invalid.",
        )
    })?;
    let risk_policy = RiskPolicyV1 {
        policy_id: "privacy-app-manual-fail-closed-v1".to_owned(),
        policy_version: 1,
        policy_sha256,
        minimum_ocr_confidence_ppm: ConfidencePpm::new(900_000).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_policy_invalid",
                "OCR confidence policy is invalid.",
            )
        })?,
        minimum_ocr_coverage_ppm: ConfidencePpm::new(950_000).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_policy_invalid",
                "OCR coverage policy is invalid.",
            )
        })?,
        maximum_quick_review_p2: 0,
        auto_approval_mode: AutoApprovalPolicyMode::Disabled,
        production_automatic_enabled: false,
        calibrated_for_automatic: false,
        calibration_evidence_sha256: None,
        organization_allows_automatic: false,
    };
    // This gate concerns required dictionary-matched entities, not whether a
    // dictionary feature exists globally. With no dictionary match it is
    // vacuously satisfied; every actual dictionary match must be resolved.
    let required_dictionary_entities_stable = detector_run.findings.iter().all(|finding| {
        !finding.case_dictionary_match
            || matches!(
                finding.severity,
                FindingSeverity::P3Resolved | FindingSeverity::Informational
            )
    });
    let deterministic_high_risk_fields_resolved = !detector_run.findings.iter().any(|finding| {
        matches!(
            finding.severity,
            FindingSeverity::P0Blocking | FindingSeverity::P1High
        )
    });
    let assessment = DocumentAssessmentV1 {
        pages,
        finding_summary_hash: detector_run.finding_summary_hash.clone(),
        dictionary_entities_stable: required_dictionary_entities_stable,
        deterministic_high_risk_fields_resolved,
        independent_residual_scan_passed: residual_scan.passed,
        independent_residual_scan_hash: Some(residual_scan.evidence_hash.clone()),
        provenance_receiptable: true,
        provenance_hash: Some(provenance_hash),
        publication_target_fixed: false,
        publication_target_hash: None,
        requested_approval_route: RequestedApprovalRoute::Human,
        calibration_evidence_version: Some(
            detector_run.model_attestation.calibration_version.clone(),
        ),
    };
    let session = ReviewSessionV1::new(ReviewSessionInputV1 {
        redaction_id: stored.redaction_id.clone(),
        case_id,
        material_id,
        document_version: 1,
        detector_run_completed: true,
        redacted_content_sha256: Sha256Hex::parse(stored.suggested_redacted_content_sha256.clone())
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_risk_evidence_invalid",
                    "Redacted content hash is invalid.",
                )
            })?,
        dictionary_revision_hash: Some(dictionary.revision_hash().clone()),
        findings: detector_run.findings.clone(),
        assessment,
        residual_scan,
        risk_policy,
        qualification: detector_run.qualification.clone(),
        created_at_unix: now_unix,
    })
    .map_err(review_session_error)?;
    Ok(Some(StoredRiskWorkflowStateV1 {
        schema_version: RISK_WORKFLOW_STATE_SCHEMA_VERSION.to_owned(),
        session,
        current_pages,
        undo_pages: Vec::new(),
        redo_pages: Vec::new(),
    }))
}

fn apply_findings_to_page_assessments(
    pages: &mut [PageAssessmentV1],
    findings: &[PrivacyFindingV1],
) -> Result<(), PrivacyWorkflowError> {
    for finding in findings {
        let page_index = usize::try_from(finding.page_index).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Finding page index is out of range.",
            )
        })?;
        let page = pages.get_mut(page_index).ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Finding references a missing review page.",
            )
        })?;
        let severity_count = match finding.severity {
            FindingSeverity::P0Blocking => &mut page.p0_count,
            FindingSeverity::P1High => &mut page.p1_count,
            FindingSeverity::P2Medium => &mut page.p2_count,
            FindingSeverity::P3Resolved | FindingSeverity::Informational => &mut page.p3_count,
        };
        *severity_count = severity_count.checked_add(1).ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Finding severity count overflowed.",
            )
        })?;
        if !matches!(
            finding.severity,
            FindingSeverity::P3Resolved | FindingSeverity::Informational
        ) {
            let count = page
                .unresolved_entity_counts
                .entry(finding.entity_type)
                .or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "privacy_risk_evidence_invalid",
                    "Unresolved entity count overflowed.",
                )
            })?;
        }
        if finding
            .reason_codes
            .iter()
            .any(|reason| reason == "detector_or_location_conflict")
        {
            page.detector_conflict_count =
                page.detector_conflict_count.checked_add(1).ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "privacy_risk_evidence_invalid",
                        "Detector conflict count overflowed.",
                    )
                })?;
        }
        let mut reason_codes = page.reason_codes.iter().cloned().collect::<BTreeSet<_>>();
        reason_codes.extend(finding.reason_codes.iter().cloned());
        page.reason_codes = reason_codes.into_iter().collect();
    }
    Ok(())
}

fn page_assessment_from_stored(
    page_index: usize,
    page: &StoredReviewPage,
) -> Result<PageAssessmentV1, PrivacyWorkflowError> {
    let page_index = u32::try_from(page_index).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_risk_evidence_invalid",
            "Page index is out of range.",
        )
    })?;
    let ocr_used = page
        .spans
        .iter()
        .any(|span| span.backend == ExtractionBackend::MineruLocal);
    let mut confidences = page
        .spans
        .iter()
        .filter_map(|span| span.confidence)
        .map(confidence_ppm)
        .collect::<Result<Vec<_>, _>>()?;
    confidences.sort_unstable();
    let (ocr_min_ppm, ocr_mean_ppm, ocr_p10_ppm, coverage_ppm) = if ocr_used {
        let min = confidences.first().copied();
        let mean = if confidences.is_empty() {
            None
        } else {
            let sum = confidences
                .iter()
                .map(|value| u64::from(value.get()))
                .sum::<u64>();
            ConfidencePpm::new(u32::try_from(sum / confidences.len() as u64).unwrap_or(0)).ok()
        };
        let p10 = if confidences.is_empty() {
            None
        } else {
            Some(confidences[(confidences.len() - 1) / 10])
        };
        let coverage = if page.spans.is_empty() {
            0
        } else {
            u32::try_from(
                (confidences.len() as u64).saturating_mul(1_000_000) / page.spans.len() as u64,
            )
            .unwrap_or(0)
        };
        (
            min,
            mean,
            p10,
            ConfidencePpm::new(coverage).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_risk_evidence_invalid",
                    "OCR coverage is invalid.",
                )
            })?,
        )
    } else {
        (
            None,
            None,
            None,
            ConfidencePpm::new(1_000_000).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_risk_evidence_invalid",
                    "Native coverage is invalid.",
                )
            })?,
        )
    };
    let mut visual = BTreeSet::new();
    for reason in &page.assessment.reason_codes {
        match reason {
            QualityReasonCode::VisualContentPresent => {
                visual.insert("generic_visual_content".to_owned());
            }
            QualityReasonCode::PageAnnotationsPresent => {
                visual.insert("page_annotations".to_owned());
            }
            QualityReasonCode::InteractiveFormPresent => {
                visual.insert("interactive_form".to_owned());
            }
            QualityReasonCode::OcrLowResolution => {
                visual.insert("ocr_low_resolution".to_owned());
            }
            QualityReasonCode::OcrLowConfidence => {
                visual.insert("ocr_low_confidence".to_owned());
            }
            _ => {}
        }
    }
    Ok(PageAssessmentV1 {
        page_index,
        p0_count: 0,
        p1_count: 0,
        p2_count: 0,
        p3_count: 0,
        ocr_used,
        ocr_min_ppm,
        ocr_mean_ppm,
        ocr_p10_ppm,
        coverage_ppm,
        unknown_long_number_count: 0,
        unresolved_entity_counts: BTreeMap::new(),
        unresolved_visual_risks: visual.into_iter().collect(),
        completeness_passed: !page.spans.is_empty()
            && !matches!(page.assessment.decision, PageExtractionDecision::Blocked),
        detector_conflict_count: 0,
        cluster_inconsistency_count: 0,
        reason_codes: Vec::new(),
    })
}

fn confidence_ppm(value: f32) -> Result<ConfidencePpm, PrivacyWorkflowError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_evidence_invalid",
            "OCR confidence is outside the verified range.",
        ));
    }
    ConfidencePpm::new((value * 1_000_000.0).round() as u32).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_risk_evidence_invalid",
            "OCR confidence is invalid.",
        )
    })
}

fn review_session_error(error: privacy::ReviewSessionError) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        error.code(),
        "Local risk review state failed strict validation.",
    )
}

fn approved_publication_invalidation_error(code: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        code,
        "Existing approved publications could not be revoked before the privacy revision changed.",
    )
}

fn v031_step8_maintenance_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "v031_step8_privacy_maintenance_failed",
        "The frozen upgrade cleanup journal could not be resumed or verified.",
    )
}

fn prepared_retention_cleanup_ids(
    connection: &Connection,
) -> Result<Vec<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT cleanup_id FROM privacy_cleanup_journal
             WHERE state='prepared' ORDER BY cleanup_id",
        )
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_cleanup_state_unavailable",
                "Pending retention cleanup state could not be inspected.",
            )
        })?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_cleanup_state_unavailable",
                "Pending retention cleanup state could not be inspected.",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_cleanup_state_unavailable",
                "Pending retention cleanup state could not be inspected.",
            )
        })?;
    Ok(rows)
}

fn encode_risk_state(state: &StoredRiskWorkflowStateV1) -> Result<Vec<u8>, PrivacyWorkflowError> {
    validate_risk_state(state, state.session.revision)?;
    serde_json::to_vec(state).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_risk_state_invalid",
            "Risk review state cannot be serialized.",
        )
    })
}

fn decode_risk_state(
    loaded: &privacy::LoadedRiskReviewRevision,
) -> Result<StoredRiskWorkflowStateV1, PrivacyWorkflowError> {
    let state: StoredRiskWorkflowStateV1 = serde_json::from_slice(&loaded.state_plaintext)
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_state_invalid",
                "Persisted risk review state failed strict decoding.",
            )
        })?;
    validate_risk_state(&state, loaded.revision)?;
    if state.session.risk_sha256().map_err(review_session_error)? != loaded.risk_sha256
        || state
            .session
            .hard_gate_sha256()
            .map_err(review_session_error)?
            != loaded.hard_gate_sha256
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_state_tampered",
            "Persisted risk review hashes do not match the protected state.",
        ));
    }
    Ok(state)
}

fn validate_risk_state(
    state: &StoredRiskWorkflowStateV1,
    expected_revision: u64,
) -> Result<(), PrivacyWorkflowError> {
    if state.schema_version != RISK_WORKFLOW_STATE_SCHEMA_VERSION
        || state.session.revision != expected_revision
        || state.undo_pages.len() > privacy::MAX_REVIEW_HISTORY
        || state.redo_pages.len() > privacy::MAX_REVIEW_HISTORY
        || state.current_pages.len() != state.session.assessment.pages.len()
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_state_invalid",
            "Risk review revision or page history is inconsistent.",
        ));
    }
    state.session.validate().map_err(review_session_error)?;
    let bytes = canonical_redacted_bytes(&state.current_pages)?;
    if sha256_hex(&bytes) != state.session.redacted_content_sha256.as_str() {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_state_tampered",
            "Risk review page bytes do not match the protected revision hash.",
        ));
    }
    Ok(())
}

fn verify_dictionary_revision(
    session: &ReviewSessionV1,
    dictionary: &case_dictionary_store::CaseDictionarySnapshotV1,
) -> Result<(), PrivacyWorkflowError> {
    if session.case_id != *dictionary.case_id()
        || session.dictionary_revision_hash.as_ref() != Some(dictionary.revision_hash())
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_case_dictionary_revision_conflict",
            "The case dictionary changed after this risk revision; rerun detection and review before approval.",
        ));
    }
    Ok(())
}

fn dictionary_entities_stable_after_action(
    session: &ReviewSessionV1,
    action: &ReviewActionV1,
) -> bool {
    session.findings.iter().all(|finding| {
        let becomes_dictionary_entry = matches!(
            action,
            ReviewActionV1::AddToDictionary { finding_id, .. }
                if finding.finding_id.as_str() == finding_id
        );
        if (!finding.case_dictionary_match && !becomes_dictionary_entry)
            || !matches!(
                finding.resolution_state,
                privacy::vnext::ReviewResolution::Unresolved
                    | privacy::vnext::ReviewResolution::Revoked
            )
        {
            return true;
        }
        match action {
            ReviewActionV1::AcceptReplacement {
                finding_id,
                apply_cluster,
            }
            | ReviewActionV1::ChangePlaceholder {
                finding_id,
                apply_cluster,
                ..
            } => {
                finding.finding_id.as_str() == finding_id
                    || (*apply_cluster
                        && session
                            .findings
                            .iter()
                            .find(|candidate| candidate.finding_id.as_str() == finding_id)
                            .and_then(|candidate| candidate.cluster_id.as_ref())
                            == finding.cluster_id.as_ref())
            }
            ReviewActionV1::ChangeEntityType { finding_id, .. }
            | ReviewActionV1::MarkNotSensitive { finding_id }
            | ReviewActionV1::SplitCluster { finding_id } => {
                finding.finding_id.as_str() == finding_id
            }
            ReviewActionV1::MergeClusters { cluster_ids } => finding
                .cluster_id
                .as_ref()
                .is_some_and(|cluster| cluster_ids.iter().any(|value| value == cluster.as_str())),
            _ => false,
        }
    })
}

fn append_risk_revision(
    connection: &Connection,
    state: &StoredRiskWorkflowStateV1,
    expected_previous_revision: u64,
) -> Result<(), PrivacyWorkflowError> {
    let state_plaintext = encode_risk_state(state)?;
    let risk_sha256 = state.session.risk_sha256().map_err(review_session_error)?;
    let hard_gate_sha256 = state
        .session
        .hard_gate_sha256()
        .map_err(review_session_error)?;
    PrivacyStore::append_risk_review_revision(
        connection,
        &SaveRiskReviewRevision {
            redaction_id: &state.session.redaction_id,
            expected_previous_revision,
            risk_sha256: &risk_sha256,
            hard_gate_sha256: &hard_gate_sha256,
            action_code: &state.session.last_action_code,
            reason_codes: &state.session.document_risk.reason_codes,
            state_plaintext: &state_plaintext,
        },
    )
    .map(|_| ())
    .map_err(PrivacyWorkflowError::store)
}
fn validate_vault_isolation(status: &VaultIsolationStatusV1) -> Result<(), PrivacyWorkflowError> {
    if status.isolation_level != "windows_current_user_encrypted_vault"
        || !status.private_acl_enforced
        || !status.content_indexing_disabled
        || !status.encrypted_at_rest
        || status.broker_boundary != "in_process_vault_broker_interface_v1"
        || status.same_user_process_limitation
            != "same_user_processes_are_not_technically_excluded_without_a_service_identity"
    {
        return Err(PrivacyWorkflowError::new(
            "vault_isolation_unverified",
            "Vault 加密、专用 ACL、索引禁用或 Broker 边界未通过实时核验。",
        ));
    }
    Ok(())
}
fn canonical_redacted_bytes(
    pages: &[CanonicalRedactedPage],
) -> Result<Vec<u8>, PrivacyWorkflowError> {
    serde_json::to_vec(&CanonicalRedactedContent {
        schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
        pages,
    })
    .map_err(|_| {
        PrivacyWorkflowError::new("canonicalization_failed", "脱敏页无法进行确定性序列化。")
    })
}

fn stored_to_view(
    stored: StoredReviewPayload,
    review_state: &str,
) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
    if stored.page_count as usize != stored.pages.len() {
        return Err(PrivacyWorkflowError::new(
            "review_payload_mismatch",
            "审阅页数与本地提取摘要不一致。",
        ));
    }
    let source_display_name = if stored.source_display_name.trim().is_empty() {
        "Local material".to_owned()
    } else {
        stored.source_display_name.clone()
    };
    let pages = stored
        .pages
        .into_iter()
        .map(|page| ReviewPageView {
            page_number: page.page_number,
            locator: page.locator,
            assessment: page.assessment,
            original_text: page.original_text,
            redacted_text: page.suggested_redacted_text,
        })
        .collect();
    Ok(PrivacyReviewView {
        redaction_id: stored.redaction_id,
        material_id: stored.material_id,
        case_id: stored.case_id,
        vault_object_id: stored.vault_object_id,
        vault_object_version: stored.vault_object_version,
        vault_isolation: stored.vault_isolation,
        source_display_name,
        source_sha256: stored.source_sha256,
        extraction_sha256: stored.extraction_sha256,
        suggested_redacted_content_sha256: stored.suggested_redacted_content_sha256,
        processing_version: stored.processing_version,
        media_type: stored.media_type,
        page_count: stored.page_count,
        backend_trace: stored.backend_trace,
        input_transform: stored.input_transform,
        summary: stored.summary,
        review_state: review_state.to_owned(),
        pages,
        risk_review: None,
    })
}

fn validate_loaded_review(
    loaded: &privacy::LoadedReviewDraft,
    stored: &StoredReviewPayload,
) -> Result<(), PrivacyWorkflowError> {
    if stored.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
        || stored.redaction_id != loaded.redaction_id
        || stored.material_id != loaded.material_id
        || stored.extraction_sha256 != loaded.extraction_sha256
        || stored.suggested_redacted_content_sha256 != loaded.redacted_content_sha256
        || stored.source_sha256.len() != 64
        || stored.page_count as usize != stored.pages.len()
    {
        return Err(PrivacyWorkflowError::new(
            "review_payload_mismatch",
            "审阅数据与受保护哈希索引不一致。",
        ));
    }
    Ok(())
}

fn approval_destination_supported(destination: &ReceiptDestinationInput, purpose: &str) -> bool {
    match &destination.kind {
        DestinationKind::ExternalProvider | DestinationKind::ExternalMcpHost => {
            valid_identifier(destination.identifier.trim()) && valid_identifier(purpose)
        }
        DestinationKind::VerifiedLocalProvider => {
            let scope = DestinationScope {
                kind: DestinationKind::VerifiedLocalProvider,
                identifier: destination.identifier.trim().to_owned(),
            };
            SafeExportFormat::from_scope(&scope, purpose).is_some()
        }
    }
}
fn validate_approval_request(
    request: &ApprovePrivacyReviewRequest,
) -> Result<(), PrivacyWorkflowError> {
    if !valid_identifier(&request.redaction_id)
        || !valid_hash(&request.expected_suggested_redacted_sha256)
        || !valid_identifier(request.reviewer.trim())
        || !valid_identifier(request.destination.identifier.trim())
        || !valid_identifier(request.purpose.trim())
        || !approval_destination_supported(&request.destination, request.purpose.trim())
        || !(MIN_RECEIPT_TTL_SECONDS..=MAX_RECEIPT_TTL_SECONDS).contains(&request.ttl_seconds)
    {
        return Err(PrivacyWorkflowError::new(
            "invalid_approval_request",
            "批准人、固定本机导出目标、用途、草稿哈希或有效期无效。",
        ));
    }
    if request.edited_pages.is_empty()
        || request.edited_pages.len() > SafePdfExportLimits::default().max_source_pages
    {
        return Err(PrivacyWorkflowError::new(
            "invalid_approval_request",
            "必须提交完整且数量受限的逐页脱敏文本。",
        ));
    }
    Ok(())
}

fn normalize_edited_pages(
    stored: &StoredReviewPayload,
    edited_pages: Vec<EditedRedactedPage>,
) -> Result<Vec<CanonicalRedactedPage>, PrivacyWorkflowError> {
    let safe_limits = SafePdfExportLimits::default();
    if edited_pages.len() != stored.pages.len() {
        return Err(PrivacyWorkflowError::new(
            "review_page_mismatch",
            "批准请求必须包含全部审阅页。",
        ));
    }
    let mut edited = edited_pages;
    edited.sort_by_key(|page| page.page_number);
    let mut total_bytes = 0usize;
    let mut result = Vec::with_capacity(edited.len());
    for (expected, page) in stored.pages.iter().zip(edited) {
        if page.page_number != expected.page_number
            || page.redacted_text.len() > safe_limits.max_page_text_bytes
        {
            return Err(PrivacyWorkflowError::new(
                "review_page_mismatch",
                "脱敏页编号、数量或大小不一致。",
            ));
        }
        total_bytes = total_bytes
            .checked_add(page.redacted_text.len())
            .ok_or_else(|| {
                PrivacyWorkflowError::new("review_payload_too_large", "脱敏文本总量超限。")
            })?;
        if total_bytes > safe_limits.max_total_text_bytes {
            return Err(PrivacyWorkflowError::new(
                "review_payload_too_large",
                "脱敏文本总量超过安全 PDF 可交付上限。",
            ));
        }
        result.push(CanonicalRedactedPage {
            page_number: page.page_number,
            text: page.redacted_text,
        });
    }
    Ok(result)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_now() -> Result<u64, PrivacyWorkflowError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PrivacyWorkflowError::new("clock_invalid", "本机时钟无效，无法签发回执。"))
}

fn load_or_create_receipt_signer() -> Result<ReceiptSigner, PrivacyWorkflowError> {
    let store = WindowsCredentialStore::with_service_prefix(RECEIPT_KEY_SERVICE);
    let key = ProviderCredentialKey::new(RECEIPT_KEY_PROVIDER, RECEIPT_KEY_ACCOUNT);
    let key_hex = match store.read_api_key(&key).map_err(|_| {
        PrivacyWorkflowError::new(
            "receipt_key_unavailable",
            "Windows 凭据管理器无法读取本机回执签名密钥。",
        )
    })? {
        Some(secret) => secret.expose_secret().to_owned(),
        None => {
            let generated = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            store
                .write_api_key(&key, ApiSecret::new(generated.clone()))
                .map_err(|_| {
                    PrivacyWorkflowError::new(
                        "receipt_key_unavailable",
                        "Windows 凭据管理器无法保存本机回执签名密钥。",
                    )
                })?;
            generated
        }
    };
    let key_bytes = decode_32_byte_hex(&key_hex).ok_or_else(|| {
        PrivacyWorkflowError::new(
            "receipt_key_invalid",
            "Windows 凭据管理器中的回执签名密钥格式无效。",
        )
    })?;
    ReceiptSigner::new(key_bytes)
        .map_err(|error| PrivacyWorkflowError::new(error.code(), "回执签名密钥无效。"))
}

fn decode_32_byte_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(output)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn read_bounded_selected_material(path: &Path) -> Result<(Vec<u8>, String), PrivacyWorkflowError> {
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(PrivacyWorkflowError::new(
            "filesystem_rejected",
            "案件原件必须位于本机非网络磁盘；UNC 和映射网络盘已拒绝。",
        ));
    }
    let display_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.len() <= file_ingest::MAX_FILE_NAME_BYTES)
        .ok_or_else(|| PrivacyWorkflowError::new("invalid_file_name", "所选材料文件名无效。"))?
        .to_owned();
    file_ingest::detect_format(&display_name).map_err(ingest_error)?;
    let selected_metadata = fs::symlink_metadata(path)
        .map_err(|_| PrivacyWorkflowError::new("material_unavailable", "所选材料无法读取。"))?;
    validate_selected_file_metadata(&selected_metadata)?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| PrivacyWorkflowError::new("material_unavailable", "所选材料无法安全打开。"))?;
    if !crate::privacy_manager::opened_file_resolves_to_ordinary_local(&file) {
        return Err(PrivacyWorkflowError::new(
            "filesystem_rejected",
            "The selected material did not resolve to an ordinary file on a local fixed disk.",
        ));
    }
    let opened_metadata = file.metadata().map_err(|_| {
        PrivacyWorkflowError::new("material_unavailable", "所选材料元数据无法读取。")
    })?;
    validate_selected_file_metadata(&opened_metadata)?;
    if selected_metadata.len() != opened_metadata.len() {
        return Err(PrivacyWorkflowError::new(
            "material_changed",
            "所选材料在打开期间发生变化，请重新选择。",
        ));
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    (&mut file)
        .take(MAX_SELECTED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PrivacyWorkflowError::new("material_unavailable", "所选材料无法完整读取。"))?;
    if bytes.len() as u64 != opened_metadata.len() {
        return Err(PrivacyWorkflowError::new(
            "material_changed",
            "所选材料在读取期间发生变化，请重新选择。",
        ));
    }
    let after_metadata = file.metadata().map_err(|_| {
        PrivacyWorkflowError::new("material_unavailable", "所选材料读取后无法核验。")
    })?;
    if after_metadata.len() != opened_metadata.len()
        || after_metadata.last_write_time() != opened_metadata.last_write_time()
    {
        return Err(PrivacyWorkflowError::new(
            "material_changed",
            "所选材料在读取期间发生变化，请重新选择。",
        ));
    }
    Ok((bytes, display_name))
}

fn validate_selected_file_metadata(metadata: &fs::Metadata) -> Result<(), PrivacyWorkflowError> {
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::privacy_manager::has_cloud_recall_attributes(metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_SELECTED_FILE_BYTES
    {
        return Err(PrivacyWorkflowError::new(
            "filesystem_rejected",
            "所选材料必须是非空、大小受限且非链接/reparse point/云端占位的本地普通文件。",
        ));
    }
    Ok(())
}

fn validate_ordinary_directory(path: &Path) -> Result<(), PrivacyWorkflowError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        PrivacyWorkflowError::new("privacy_store_unavailable", "本机隐私目录无法核验。")
    })?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PrivacyWorkflowError::new(
            "filesystem_rejected",
            "本机隐私目录不能是链接或 reparse point。",
        ));
    }
    Ok(())
}

fn validate_ordinary_database_file(path: &Path) -> Result<(), PrivacyWorkflowError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        PrivacyWorkflowError::new("privacy_store_unavailable", "本机隐私数据库无法核验。")
    })?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PrivacyWorkflowError::new(
            "filesystem_rejected",
            "本机隐私数据库不能是链接或 reparse point。",
        ));
    }
    Ok(())
}

fn extract_local_material(
    bytes: &[u8],
    source_name: &str,
    config: &PrivacyConfig,
    ocr_status: &LocalOcrStatus,
    mineru_config: Option<&LocalMineruConfig>,
) -> Result<LocalExtractedDocument, PrivacyWorkflowError> {
    let format = file_ingest::detect_format(source_name).map_err(ingest_error)?;
    match format {
        FileFormat::Pdf => extract_pdf_material(bytes, config, ocr_status, mineru_config),
        FileFormat::Png => extract_raster_material(
            bytes,
            RasterImageFormat::Png,
            config,
            ocr_status,
            mineru_config,
        ),
        FileFormat::Jpeg => extract_raster_material(
            bytes,
            RasterImageFormat::Jpeg,
            config,
            ocr_status,
            mineru_config,
        ),
        FileFormat::Docx | FileFormat::Txt | FileFormat::Markdown => {
            extract_segmented_material(bytes, source_name)
        }
    }
}

fn extract_pdf_material(
    bytes: &[u8],
    config: &PrivacyConfig,
    ocr_status: &LocalOcrStatus,
    mineru_config: Option<&LocalMineruConfig>,
) -> Result<LocalExtractedDocument, PrivacyWorkflowError> {
    if !config.ocr.strict_offline
        || !config.ocr.forbid_cloud_fallback
        || !config.ocr.forbid_remote_upload
        || !config.ocr.forbid_telemetry
    {
        return Err(PrivacyWorkflowError::new(
            "unsafe_ocr_configuration",
            "真实案件必须保持严格离线，并禁止云端回退、远端上传和遥测。",
        ));
    }
    if config.ocr.mode == ConfigOcrMode::ForceLocal
        && (!ocr_status.integrity_verified || !ocr_status.network_isolation_verified)
    {
        return Err(PrivacyWorkflowError::new(
            "ocr_worker_isolation_unverified",
            "强制 OCR 被阻断：本地组件完整性或网络隔离尚未认证。",
        ));
    }
    let ocr_mode = match config.ocr.mode {
        ConfigOcrMode::Off => OcrMode::Off,
        ConfigOcrMode::AutoLocal => OcrMode::AutoLocal,
        ConfigOcrMode::ForceLocal => OcrMode::ForceLocal,
    };
    let limits = ProcessingLimits {
        max_input_bytes: MAX_SELECTED_FILE_BYTES as usize,
        max_pages: config.ocr.max_pages as usize,
        ..ProcessingLimits::default()
    };
    let processed = material_processing::process_pdf(bytes, ocr_mode, mineru_config, limits)
        .map_err(PrivacyWorkflowError::processing)?;
    if processed.source_sha256 != sha256_hex(bytes) {
        return Err(PrivacyWorkflowError::new(
            "source_hash_mismatch",
            "本地提取结果与所选文件哈希不一致。",
        ));
    }
    let segments = processed
        .pages
        .into_iter()
        .map(|page| LocalExtractedSegment {
            page_number: page.page_number,
            locator: format!("page:{}", page.page_number),
            assessment: page.assessment,
            spans: page.spans,
        })
        .collect::<Vec<_>>();
    Ok(LocalExtractedDocument {
        processing_version: processed.processing_version,
        source_sha256: processed.source_sha256,
        media_type: processed.media_type,
        page_count: processed.page_count,
        backend_trace: processed.backend_trace,
        input_transform: processed.input_transform,
        segments,
    })
}

fn extract_raster_material(
    bytes: &[u8],
    format: RasterImageFormat,
    config: &PrivacyConfig,
    ocr_status: &LocalOcrStatus,
    mineru_config: Option<&LocalMineruConfig>,
) -> Result<LocalExtractedDocument, PrivacyWorkflowError> {
    if !config.ocr.strict_offline
        || !config.ocr.forbid_cloud_fallback
        || !config.ocr.forbid_remote_upload
        || !config.ocr.forbid_telemetry
    {
        return Err(PrivacyWorkflowError::new(
            "unsafe_ocr_configuration",
            "图片案件材料必须保持严格离线，并禁止云端回退、远端上传和遥测。",
        ));
    }
    if config.ocr.mode != ConfigOcrMode::Off
        && (!ocr_status.integrity_verified || !ocr_status.network_isolation_verified)
    {
        return Err(PrivacyWorkflowError::new(
            "ocr_worker_isolation_unverified",
            "图片必须使用已认证且已验证网络隔离的本地 OCR 组件。",
        ));
    }
    let ocr_mode = match config.ocr.mode {
        ConfigOcrMode::Off => OcrMode::Off,
        ConfigOcrMode::AutoLocal => OcrMode::AutoLocal,
        ConfigOcrMode::ForceLocal => OcrMode::ForceLocal,
    };
    let limits = ProcessingLimits {
        max_input_bytes: MAX_SELECTED_FILE_BYTES as usize,
        max_pages: config.ocr.max_pages as usize,
        ..ProcessingLimits::default()
    };
    let processed =
        material_processing::process_raster_image(bytes, format, ocr_mode, mineru_config, limits)
            .map_err(PrivacyWorkflowError::processing)?;
    let expected_source_sha256 = sha256_hex(bytes);
    let transform = processed.input_transform.as_ref().ok_or_else(|| {
        PrivacyWorkflowError::new(
            "input_transform_missing",
            "图片 OCR 结果缺少原图到处理 PDF 的本地转换证据。",
        )
    })?;
    if processed.source_sha256 != expected_source_sha256
        || processed.media_type != format.media_type()
        || processed.page_count != 1
        || processed.pages.len() != 1
        || transform.schema_version != 1
        || transform.transform_version != material_processing::RASTER_TO_PDF_TRANSFORM_VERSION
        || transform.source_media_type != format.media_type()
        || transform.source_sha256 != expected_source_sha256
        || transform.processing_media_type != "application/pdf"
        || !valid_hash(&transform.processing_sha256)
        || transform.processing_sha256 == transform.source_sha256
        || transform.pixel_width == 0
        || transform.pixel_height == 0
    {
        return Err(PrivacyWorkflowError::new(
            "input_transform_mismatch",
            "图片原件、确定性处理 PDF 与 OCR 结果的证据绑定不一致。",
        ));
    }
    let segments = processed
        .pages
        .into_iter()
        .map(|page| LocalExtractedSegment {
            page_number: page.page_number,
            locator: format!("page:{}", page.page_number),
            assessment: page.assessment,
            spans: page.spans,
        })
        .collect::<Vec<_>>();
    Ok(LocalExtractedDocument {
        processing_version: processed.processing_version,
        source_sha256: processed.source_sha256,
        media_type: processed.media_type,
        page_count: processed.page_count,
        backend_trace: processed.backend_trace,
        input_transform: processed.input_transform,
        segments,
    })
}
fn extract_segmented_material(
    bytes: &[u8],
    source_name: &str,
) -> Result<LocalExtractedDocument, PrivacyWorkflowError> {
    let extracted = file_ingest::ingest_bytes(source_name, bytes).map_err(ingest_error)?;
    if extracted.sha256_hex != sha256_hex(bytes) || extracted.segments.is_empty() {
        return Err(PrivacyWorkflowError::new(
            "source_hash_mismatch",
            "本地材料提取结果为空或与源文件哈希不一致。",
        ));
    }
    let mut page_numbers = Vec::with_capacity(extracted.segments.len());
    let mut segments = Vec::with_capacity(extracted.segments.len());
    for (index, segment) in extracted.segments.into_iter().enumerate() {
        let page_number = u32::try_from(index + 1).map_err(|_| {
            PrivacyWorkflowError::new("segment_limit_exceeded", "材料段落数量超过本地上限。")
        })?;
        page_numbers.push(page_number);
        let text_hash = sha256_hex(segment.text.as_bytes());
        segments.push(LocalExtractedSegment {
            page_number,
            locator: segment.locator,
            assessment: synthetic_assessment(page_number, &segment.text),
            spans: vec![ProcessedSpan {
                span_id: format!("ingest-{page_number}-{}", &text_hash[..12]),
                text: segment.text,
                bbox: None,
                confidence: None,
                kind: SpanKind::Text,
                backend: ExtractionBackend::NativeText,
            }],
        });
    }
    let page_count = u32::try_from(segments.len()).map_err(|_| {
        PrivacyWorkflowError::new("segment_limit_exceeded", "材料段落数量超过本地上限。")
    })?;
    Ok(LocalExtractedDocument {
        processing_version: FILE_INGEST_PROCESSING_VERSION.to_owned(),
        source_sha256: extracted.sha256_hex,
        media_type: extracted.mime_type,
        page_count,
        input_transform: None,
        backend_trace: vec![BackendTrace {
            backend: ExtractionBackend::NativeText,
            worker_sha256: None,
            model_manifest_sha256: None,
            config_sha256: None,
            device: "cpu".to_owned(),
            page_numbers,
            isolation_verified: true,
            isolation_mechanism: Some("in_process_no_network_code_path".to_owned()),
        }],
        segments,
    })
}

fn synthetic_assessment(page_number: u32, text: &str) -> TextLayerAssessment {
    let characters = text.chars().count().max(1);
    let non_whitespace_chars = text.chars().filter(|value| !value.is_whitespace()).count();
    let replacement_characters = text.chars().filter(|value| *value == '\u{fffd}').count();
    let cjk_characters = text
        .chars()
        .filter(|value| matches!(*value as u32, 0x3400..=0x9fff))
        .count();
    TextLayerAssessment {
        page_number,
        non_whitespace_chars: u32::try_from(non_whitespace_chars).unwrap_or(u32::MAX),
        printable_ratio: 1.0,
        replacement_char_ratio: replacement_characters as f32 / characters as f32,
        cjk_ratio: cjk_characters as f32 / characters as f32,
        reading_order_score: 1.0,
        decision: PageExtractionDecision::NativeAccepted,
        reason_codes: vec![QualityReasonCode::NativeTextHealthy],
    }
}

fn ingest_error(error: file_ingest::IngestError) -> PrivacyWorkflowError {
    let message = match error {
        file_ingest::IngestError::NonTextPdf => {
            "该 PDF 缺少文本层，必须通过已认证的本地 OCR 处理。"
        }
        file_ingest::IngestError::EncryptedDocx => "暂不处理加密 DOCX。",
        file_ingest::IngestError::ActiveContentNotAllowed => {
            "DOCX 包含活动或嵌入内容，已在本机拒绝。"
        }
        file_ingest::IngestError::InvalidUtf8 => "TXT/Markdown 必须是有效 UTF-8。",
        _ => "所选材料未通过本地格式、大小或安全结构校验。",
    };
    PrivacyWorkflowError::new(error.code(), message)
}

fn safe_export_error(_error: SafePdfExportError) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "safe_pdf_export_failed",
        "安全 PDF 重建或输出复检失败；未生成可保存文件。",
    )
}

fn validate_forbidden_canaries(canaries: &[String]) -> Result<(), PrivacyWorkflowError> {
    if canaries.is_empty() || canaries.len() > MAX_FORBIDDEN_CANARIES {
        return Err(PrivacyWorkflowError::new(
            "canary_limit_exceeded",
            "未发现可复检的敏感 canary，或 canary 数量超过安全导出上限。",
        ));
    }
    let mut total_bytes = 0usize;
    for canary in canaries {
        if canary.trim().is_empty() || canary.len() > MAX_SINGLE_CANARY_BYTES {
            return Err(PrivacyWorkflowError::new(
                "canary_limit_exceeded",
                "敏感 canary 为空或单项大小超过安全导出上限。",
            ));
        }
        total_bytes = total_bytes.checked_add(canary.len()).ok_or_else(|| {
            PrivacyWorkflowError::new(
                "canary_limit_exceeded",
                "敏感 canary 总大小超过本机处理上限。",
            )
        })?;
        if total_bytes > MAX_TOTAL_CANARY_BYTES {
            return Err(PrivacyWorkflowError::new(
                "canary_limit_exceeded",
                "敏感 canary 总大小超过本机处理上限。",
            ));
        }
    }
    Ok(())
}

fn reject_normalized_canaries(
    pages: &[CanonicalRedactedPage],
    forbidden_canaries: &[String],
) -> Result<(), PrivacyWorkflowError> {
    let normalized_pages = pages
        .iter()
        .map(|page| normalize_for_canary_scan(&page.text))
        .collect::<Vec<_>>();
    for canary in forbidden_canaries {
        let normalized_canary = normalize_for_canary_scan(canary);
        if !normalized_canary.is_empty()
            && normalized_pages
                .iter()
                .any(|page| page.contains(&normalized_canary))
        {
            return Err(PrivacyWorkflowError::new(
                "forbidden_canary_present",
                "人工修改后的载荷重新出现了源敏感信息，批准或导出已拒绝。",
            ));
        }
    }
    Ok(())
}

fn normalize_for_canary_scan(value: &str) -> String {
    value
        .nfkc()
        .filter(|character| {
            !matches!(
                *character,
                '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
            )
        })
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_manager::LocalOcrStatusCode;
    use lopdf::{
        content::{Content, Operation},
        dictionary, Document, Object, Stream,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tempfile::TempDir;

    const TEST_NOW: u64 = 1_700_000_000;

    #[derive(Default)]
    struct TogglePublicationInvalidator {
        fail: AtomicBool,
        case_calls: AtomicU64,
        material_calls: AtomicU64,
    }

    impl ApprovedPublicationInvalidator for TogglePublicationInvalidator {
        fn invalidate_case(
            &self,
            _case_id: &CaseId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.case_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err("approved_workspace_invalidation_injected_failure")
            } else {
                Ok(0)
            }
        }

        fn invalidate_material(
            &self,
            _case_id: &CaseId,
            _material_id: &MaterialId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.material_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err("approved_workspace_invalidation_injected_failure")
            } else {
                Ok(0)
            }
        }

        fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_lifecycle_bindings(
            &self,
            _lifecycle_binding_ids: &BTreeSet<String>,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            if self.fail.load(Ordering::SeqCst) {
                Err("approved_workspace_invalidation_injected_failure")
            } else {
                Ok(0)
            }
        }
    }

    fn local_ocr_status() -> LocalOcrStatus {
        LocalOcrStatus {
            code: LocalOcrStatusCode::Disabled,
            message: "test".to_owned(),
            worker_version: None,
            model_version: None,
            worker_sha256: None,
            model_manifest_sha256: None,
            worker_present: false,
            model_directory_present: false,
            integrity_verified: false,
            network_isolation_verified: false,
            worker_protocol_version: None,
            worker_protocol_identity_sha256: None,
            worker_health_evidence_sha256: None,
            python_version: None,
            mineru_version: None,
            pytorch_version: None,
            cuda_runtime_version: None,
            gpu_driver_version: None,
        }
    }

    fn manager_with_test_signer() -> (TempDir, PrivacyWorkflowManager, ReceiptSigner) {
        let directory = tempfile::tempdir().expect("temp privacy directory");
        database::ensure_user_database(directory.path()).expect("test user database");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("privacy manager");
        let signer = ReceiptSigner::new([7u8; 32]).expect("test receipt signer");
        manager.set_test_runtime(signer.clone(), TEST_NOW);
        (directory, manager, signer)
    }

    #[test]
    fn v031_step8_privacy_maintenance_reuses_exact_lineage_journals() {
        let (directory, manager, _signer) = manager_with_test_signer();
        let cutoff = TEST_NOW;
        let retention_id = "cln_dddddddddddddddddddddddddddddddd";
        let vault_id = "cln_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        let privacy_before = manager
            .open_connection()
            .expect("Privacy before Step-8 maintenance");
        privacy::compute_privacy_v6_manifests_read_only(&privacy_before)
            .expect("Step-8 starts from the exact full Privacy-v6 schema");
        drop(privacy_before);

        let first = manager
            .complete_v031_step8_privacy_maintenance(cutoff, retention_id, vault_id)
            .expect("first deterministic Step-8 maintenance");
        let privacy_after = manager
            .open_connection()
            .expect("Privacy after Step-8 maintenance");
        privacy::compute_privacy_v6_manifests_read_only(&privacy_after)
            .expect("Step-8 preserves the exact full Privacy-v6 schema");
        drop(privacy_after);
        let repeated = manager
            .complete_v031_step8_privacy_maintenance(cutoff, retention_id, vault_id)
            .expect("repeated Step-8 maintenance verifies the same journals");
        assert_eq!(repeated, first);
        assert_eq!(first.retention_cleanup.cleanup_id, retention_id);
        assert_eq!(first.retention_cleanup.state, "committed");
        assert_eq!(first.vault_cleanup.cleanup_id, vault_id);
        assert_eq!(first.vault_cleanup.state, "purged");
        assert_eq!(first.pending_project_deletions_after, 0);
        assert_eq!(first.pending_retention_cleanups_after, 0);
        assert_eq!(first.pending_vault_prepared_after, 0);
        assert_eq!(first.pending_vault_committed_after, 0);

        let privacy = manager.open_connection().expect("Privacy journal database");
        privacy::compute_privacy_v6_manifests_read_only(&privacy)
            .expect("Step-8 replay preserves the exact full Privacy-v6 schema");
        assert_eq!(
            privacy
                .query_row(
                    "SELECT COUNT(*) FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                    [retention_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("Privacy cleanup journal cardinality"),
            1
        );
        drop(privacy);
        let vault_database = directory
            .path()
            .join(vault_broker::VAULT_ROOT_DIRECTORY)
            .join("vault-state.sqlite");
        let vault = Connection::open(vault_database).expect("Vault journal database");
        assert_eq!(
            vault
                .query_row(
                    "SELECT COUNT(*) FROM vault_cleanup_journal WHERE cleanup_id=?1",
                    [vault_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("Vault cleanup journal cardinality"),
            1
        );
        drop(vault);

        assert_eq!(
            manager
                .complete_v031_step8_privacy_maintenance(cutoff + 1, retention_id, vault_id)
                .expect_err("a lineage cleanup ID cannot be rebound to another cutoff")
                .code(),
            "v031_step8_privacy_maintenance_failed"
        );
    }

    fn file_tree_hashes(root: &Path) -> BTreeMap<String, String> {
        fn visit(base: &Path, directory: &Path, output: &mut BTreeMap<String, String>) {
            for entry in fs::read_dir(directory).expect("read test tree") {
                let entry = entry.expect("test tree entry");
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("test tree metadata");
                assert!(!metadata.file_type().is_symlink());
                if metadata.is_dir() {
                    visit(base, &path, output);
                } else if metadata.is_file() {
                    let relative = path
                        .strip_prefix(base)
                        .expect("relative test path")
                        .to_string_lossy()
                        .replace('\\', "/");
                    output.insert(
                        relative,
                        sha256_hex(&fs::read(&path).expect("read test file")),
                    );
                }
            }
        }
        let mut output = BTreeMap::new();
        visit(root, root, &mut output);
        output
    }

    #[test]
    fn application_startup_constructor_does_not_upgrade_legacy_privacy_or_vault() {
        let directory = tempfile::tempdir().expect("startup gate directory");
        database::ensure_user_database(directory.path()).expect("canonical user database");
        let initialized = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("initialize synthetic current stores");
        drop(initialized);

        let privacy_database = directory
            .path()
            .join(PRIVACY_DIRECTORY_NAME)
            .join(PRIVACY_DATABASE_NAME);
        Connection::open(&privacy_database)
            .expect("open privacy fixture")
            .execute(
                "UPDATE privacy_schema_metadata SET value='4' WHERE key='schema_version'",
                [],
            )
            .expect("downgrade privacy fixture marker");

        let vault_database = directory
            .path()
            .join(vault_broker::VAULT_ROOT_DIRECTORY)
            .join("vault-state.sqlite");
        let vault = Connection::open(&vault_database).expect("open Vault fixture");
        vault
            .execute_batch(
                "DROP TRIGGER IF EXISTS trg_vault_cleanup_purged_no_update;
                 DROP TRIGGER IF EXISTS trg_vault_cleanup_no_delete;
                 DROP INDEX IF EXISTS idx_vault_retention_expiry;
                 DROP TABLE IF EXISTS vault_cleanup_candidates;
                 DROP TABLE IF EXISTS vault_cleanup_journal;
                 DROP TABLE IF EXISTS vault_object_retention;
                 DROP TABLE IF EXISTS vault_lifecycle_meta;
                 UPDATE vault_meta SET schema_version=1 WHERE singleton=1;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("create synthetic legacy Vault");
        drop(vault);

        let before = file_tree_hashes(directory.path());
        let pending =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(TogglePublicationInvalidator::default()),
            )
            .expect("read-only application startup open");
        assert!(pending.privacy_store_schema_upgrade_required());
        assert!(pending.vault_startup_write_required());
        assert!(pending
            .case_material_migration_required()
            .expect("read-only migration probe"));
        assert_eq!(file_tree_hashes(directory.path()), before);
    }

    #[test]
    fn application_startup_rejects_unmarked_nonempty_privacy_store_without_writing() {
        let directory = tempfile::tempdir().expect("startup gate directory");
        database::ensure_user_database(directory.path()).expect("canonical user database");
        let privacy_directory = directory.path().join(PRIVACY_DIRECTORY_NAME);
        fs::create_dir_all(&privacy_directory).expect("privacy directory");
        let privacy_database = privacy_directory.join(PRIVACY_DATABASE_NAME);
        Connection::open(&privacy_database)
            .expect("open unmarked privacy fixture")
            .execute_batch(
                "CREATE TABLE historical_private_rows(
                    row_id TEXT PRIMARY KEY,
                    protected_payload BLOB NOT NULL
                 );
                 INSERT INTO historical_private_rows(row_id,protected_payload)
                 VALUES('historical-row',X'01020304');",
            )
            .expect("create unmarked nonempty privacy fixture");

        let before = file_tree_hashes(directory.path());
        let error =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(TogglePublicationInvalidator::default()),
            )
            .expect_err("unmarked nonempty Privacy store must fail closed");

        assert_eq!(error.code(), "privacy_store_schema_unsupported");
        assert_eq!(file_tree_hashes(directory.path()), before);
        assert!(!directory
            .path()
            .join(vault_broker::VAULT_ROOT_DIRECTORY)
            .exists());
    }

    #[test]
    fn fresh_user_database_is_authorized_only_without_privacy_or_vault_history() {
        let fresh_directory = tempfile::tempdir().expect("fresh startup directory");
        let fresh =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                fresh_directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(TogglePublicationInvalidator::default()),
            )
            .expect("open fresh startup workflow");
        fresh
            .preflight_fresh_user_database_initialization()
            .expect("fresh empty stores authorize a new user database");
        assert!(!database::user_database_path(fresh_directory.path()).exists());
        assert!(
            !fresh_directory.path().join(PRIVACY_DIRECTORY_NAME).exists(),
            "startup preflight must not create an empty Privacy target directory"
        );

        let historical_directory = tempfile::tempdir().expect("historical startup directory");
        database::ensure_user_database(historical_directory.path())
            .expect("historical canonical user database");
        let historical = PrivacyWorkflowManager::new(
            historical_directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("initialize historical stores");
        drop(historical);
        fs::remove_file(database::user_database_path(historical_directory.path()))
            .expect("simulate missing user database");
        let before = file_tree_hashes(historical_directory.path());
        let pending =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                historical_directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(TogglePublicationInvalidator::default()),
            )
            .expect("read-only historical startup open");
        let error = pending
            .preflight_fresh_user_database_initialization()
            .expect_err("existing Privacy or Vault history blocks a replacement user database");
        assert_eq!(error.code(), "case_material_source_missing_with_history");
        assert_eq!(file_tree_hashes(historical_directory.path()), before);
    }

    fn prepare_text(
        manager: &PrivacyWorkflowManager,
        source_name: &str,
        text: &str,
    ) -> PrivacyReviewView {
        manager
            .prepare_material_bytes(
                text.as_bytes(),
                source_name.to_owned(),
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                Vec::new(),
            )
            .expect("prepare local text review")
    }

    fn prepare_case_text(
        manager: &PrivacyWorkflowManager,
        source_name: &str,
        text: &str,
        case_id: &str,
    ) -> PrivacyReviewView {
        prepare_case_text_with_terms(manager, source_name, text, case_id, Vec::new())
    }

    fn prepare_case_text_with_terms(
        manager: &PrivacyWorkflowManager,
        source_name: &str,
        text: &str,
        case_id: &str,
        custom_terms: Vec<String>,
    ) -> PrivacyReviewView {
        let privacy_case_id =
            PrivacyCaseId::parse(case_id.to_owned()).expect("strict test Privacy CaseId");
        let mut privacy_connection = manager.open_connection().expect("privacy database");
        let project_id =
            ProjectPrivacyCaseBindingStore::reverse_resolve(&privacy_connection, &privacy_case_id)
                .expect("resolve test project binding")
                .unwrap_or_else(|| {
                    let project_id =
                        ProjectId::parse(format!("case-test-{}", Uuid::new_v4().simple()))
                            .expect("strict test ProjectId");
                    let app_local_data_directory = manager
                        .shared
                        .user_database_path
                        .parent()
                        .expect("test user database has an App-local parent");
                    let user_database_path =
                        database::ensure_user_database(app_local_data_directory)
                            .expect("initialize test user database");
                    let user_connection = database::open_user_database(&user_database_path)
                        .expect("open test user database");
                    database::upsert_case_project(
                        &user_connection,
                        &database::CaseProjectRow {
                            project_id: project_id.as_str().to_owned(),
                            title: "Synthetic privacy workflow case".to_owned(),
                            case_type: "civil".to_owned(),
                            status: "active".to_owned(),
                            opened_on: None,
                            summary: String::new(),
                            created_at: String::new(),
                            updated_at: String::new(),
                        },
                    )
                    .expect("insert synthetic case project");
                    drop(user_connection);
                    let lifecycle_context = BindingLifecycleContext::new(
                        BindingCreationSource::LegacyMigration,
                        format!("bind-test-{}", Uuid::new_v4().simple()),
                        Some("privacy-workflow-test-binding-v1".to_owned()),
                    )
                    .expect("test binding context");
                    ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
                        &mut privacy_connection,
                        &project_id,
                        &privacy_case_id,
                        &lifecycle_context,
                    )
                    .expect("bind exact test ProjectId and Privacy CaseId");
                    project_id
                });
        drop(privacy_connection);
        let source_directory = tempfile::tempdir().expect("temporary case source");
        let source_path = source_directory.path().join(source_name);
        fs::write(&source_path, text).expect("write synthetic case source");
        manager
            .prepare_case_selected_material_with_qualification(
                &source_path,
                &PrivacyConfig::default(),
                &local_ocr_status(),
                LocalOcrExecutionContext {
                    mineru_config: None,
                    qualification: None,
                },
                project_id.as_str().to_owned(),
                custom_terms,
            )
            .expect("prepare Vault-bound case text")
    }

    fn confirm_case_review(
        manager: &PrivacyWorkflowManager,
        review: &PrivacyReviewView,
        suffix: &str,
    ) -> PrivacyReviewView {
        let target_pages = edited_pages(review, suffix);
        let finding_ids = review
            .risk_review
            .as_ref()
            .expect("initial risk revision")
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        let mut current = review.clone();
        for finding_id in finding_ids {
            let revision = current
                .risk_review
                .as_ref()
                .expect("current finding revision")
                .revision;
            current = manager
                .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                    redaction_id: current.redaction_id.clone(),
                    expected_revision: revision,
                    actor: "local-reviewer".to_owned(),
                    edited_pages: target_pages.clone(),
                    action: ReviewActionV1::AcceptReplacement {
                        finding_id,
                        apply_cluster: false,
                    },
                })
                .expect("accept detected replacement");
        }
        let revision = current
            .risk_review
            .as_ref()
            .expect("resolved finding revision")
            .revision;
        manager
            .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                redaction_id: current.redaction_id.clone(),
                expected_revision: revision,
                actor: "local-reviewer".to_owned(),
                edited_pages: target_pages,
                action: ReviewActionV1::ConfirmEditedOutput,
            })
            .expect("confirm edited output")
    }

    fn edited_pages(review: &PrivacyReviewView, suffix: &str) -> Vec<EditedRedactedPage> {
        review
            .pages
            .iter()
            .map(|page| EditedRedactedPage {
                page_number: page.page_number,
                redacted_text: format!("{}{}", page.redacted_text, suffix),
            })
            .collect()
    }

    fn approval_request(
        review: &PrivacyReviewView,
        edited_pages: Vec<EditedRedactedPage>,
    ) -> ApprovePrivacyReviewRequest {
        ApprovePrivacyReviewRequest {
            redaction_id: review.redaction_id.clone(),
            expected_risk_revision: None,
            expected_suggested_redacted_sha256: review.suggested_redacted_content_sha256.clone(),
            edited_pages,
            reviewer: "local-reviewer".to_owned(),
            destination: ReceiptDestinationInput {
                kind: DestinationKind::VerifiedLocalProvider,
                identifier: LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER.to_owned(),
            },
            purpose: LOCAL_SAFE_PDF_PURPOSE.to_owned(),
            ttl_seconds: 3_600,
        }
    }

    fn export_request(
        review: &PrivacyReviewView,
        approval: &ApprovePrivacyReviewResponse,
    ) -> ExportApprovedReviewPdfRequest {
        ExportApprovedReviewPdfRequest {
            redaction_id: review.redaction_id.clone(),
            receipt_token: approval.receipt_token.clone(),
            approved_payload_json: approval.approved_payload_json.clone(),
            destination: ReceiptDestinationInput {
                kind: DestinationKind::VerifiedLocalProvider,
                identifier: LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER.to_owned(),
            },
            purpose: LOCAL_SAFE_PDF_PURPOSE.to_owned(),
        }
    }
    fn deletion_request(review: &PrivacyReviewView) -> DeletePrivacyReviewRequest {
        DeletePrivacyReviewRequest {
            redaction_id: review.redaction_id.clone(),
            expected_source_sha256: review.source_sha256.clone(),
            expected_extraction_sha256: review.extraction_sha256.clone(),
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[test]
    fn vault_bound_case_runs_real_local_ner_without_public_raw_value() {
        const RAW_PERSON: &str = "\u{5f20}\u{4e09}";
        let (directory, manager, _signer) = manager_with_test_signer();
        let source_path = directory.path().join("synthetic-local-ner-case.txt");
        fs::write(
            &source_path,
            format!("\u{539f}\u{544a}\u{ff1a}{RAW_PERSON}\u{3002}"),
        )
        .expect("write synthetic NER case material");

        let review = manager
            .prepare_selected_material(
                &source_path,
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                Some("case_34343434343434343434343434343434".to_owned()),
                Vec::new(),
            )
            .expect("prepare Vault-bound NER material");
        let risk = review.risk_review.as_ref().expect("risk review");
        assert!(risk.detector_run_completed);
        let person_finding = risk
            .findings
            .iter()
            .find(|finding| finding.entity_type == privacy::vnext::EntityType::PersonName)
            .expect("person finding from local model");
        assert!(person_finding
            .detector_sources
            .iter()
            .any(|source| source == "local_ner"));
        assert!(person_finding
            .model_versions
            .contains_key("local_ner_manifest_sha256"));
        let public_risk = serde_json::to_vec(risk).expect("serialize public risk view");
        assert!(!contains_bytes(&public_risk, RAW_PERSON.as_bytes()));

        let vault_root = directory.path().join(vault_broker::VAULT_ROOT_DIRECTORY);
        let mut pending = vec![vault_root];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path).expect("enumerate Vault") {
                let entry = entry.expect("Vault entry");
                if entry.file_type().expect("Vault entry type").is_dir() {
                    pending.push(entry.path());
                } else {
                    let bytes = fs::read(entry.path()).expect("read encrypted Vault artifact");
                    assert!(!contains_bytes(&bytes, RAW_PERSON.as_bytes()));
                }
            }
        }
    }

    #[test]
    fn selected_material_is_vault_backed_reverified_and_tombstoned_under_retention() {
        const RAW_CANARY: &str = "SYNTHETIC_SELECTED_VAULT_PRIVATE_CANARY";
        const SOURCE_NAME: &str = "synthetic-selected-private.txt";
        let (directory, manager, _signer) = manager_with_test_signer();
        let source_path = directory.path().join(SOURCE_NAME);
        fs::write(&source_path, format!("case party: {RAW_CANARY}"))
            .expect("write synthetic selected material");

        let review = manager
            .prepare_selected_material(
                &source_path,
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                Some("case_12121212121212121212121212121212".to_owned()),
                vec![RAW_CANARY.to_owned()],
            )
            .expect("prepare selected material through encrypted vault");
        assert_eq!(
            review.case_id.as_deref(),
            Some("case_12121212121212121212121212121212")
        );
        assert!(review
            .vault_object_id
            .as_deref()
            .is_some_and(|id| id.starts_with("obj_")));
        assert_eq!(review.vault_object_version, Some(1));
        let isolation = review
            .vault_isolation
            .as_ref()
            .expect("vault isolation evidence");
        assert!(isolation.private_acl_enforced);
        assert!(isolation.content_indexing_disabled);
        assert!(isolation.encrypted_at_rest);
        assert!(!isolation.strong_service_identity_boundary);

        let vault_root = directory.path().join(vault_broker::VAULT_ROOT_DIRECTORY);
        let mut pending = vec![vault_root];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path).expect("enumerate vault") {
                let entry = entry.expect("vault entry");
                if entry.file_type().expect("vault entry type").is_dir() {
                    pending.push(entry.path());
                } else {
                    let bytes = fs::read(entry.path()).expect("read encrypted vault artifact");
                    assert!(!contains_bytes(&bytes, RAW_CANARY.as_bytes()));
                    assert!(!contains_bytes(&bytes, SOURCE_NAME.as_bytes()));
                }
            }
        }

        let reviewed = confirm_case_review(&manager, &review, "");
        let reviewed_risk = reviewed
            .risk_review
            .as_ref()
            .expect("confirmed risk revision");
        let mut request = approval_request(&reviewed, edited_pages(&reviewed, ""));
        request.expected_risk_revision = Some(reviewed_risk.revision);
        let approval = manager
            .approve_review(request)
            .expect("approval revalidates the encrypted source and exact risk revision");
        assert!(!approval.receipt_id.is_empty());
        let connection = manager.open_connection().expect("privacy connection");
        let binding =
            vault_broker::load_vault_binding_for_redaction(&connection, &review.redaction_id)
                .expect("vault link query")
                .expect("vault link");
        drop(connection);

        let deleted = manager
            .delete_review(deletion_request(&review))
            .expect("tombstone review and revoke every live capability");
        assert!(deleted.deleted);
        assert!(
            source_path.exists(),
            "the user-selected original is never deleted"
        );
        let retained_source = manager
            .shared
            .vault_broker
            .read_source(&binding)
            .expect("encrypted Vault source remains governed by retention");
        drop(retained_source);
        assert!(manager.load_review(&review.redaction_id).is_err());
    }
    #[test]
    fn prepare_atomically_persists_encrypted_mapping_and_retention() {
        const RAW_SYNTHETIC_TERM: &str = "synthetic-private-party";
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = manager
            .prepare_material_bytes(
                format!("case party: {RAW_SYNTHETIC_TERM}").as_bytes(),
                "synthetic-mapping.txt".to_owned(),
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                vec![RAW_SYNTHETIC_TERM.to_owned()],
            )
            .expect("prepare synthetic mapping review");

        let mut connection = manager.open_connection().expect("privacy connection");
        let (mapping_id, ciphertext): (String, Vec<u8>) = connection
            .query_row(
                "SELECT mapping_id,ciphertext FROM privacy_sensitive_mappings
                 WHERE redaction_id=?1 AND revision=1",
                [&review.redaction_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("encrypted mapping revision 1");
        assert!(!contains_bytes(&ciphertext, RAW_SYNTHETIC_TERM.as_bytes()));
        let retention_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_retention_bindings
                 WHERE redaction_id=?1 AND legal_hold=0",
                [&review.redaction_id],
                |row| row.get(0),
            )
            .expect("retention binding");
        assert_eq!(retention_count, 1);

        let lifecycle = manager
            .privacy_lifecycle(&connection)
            .expect("privacy lifecycle");
        let access_id = "access_synthetic_mapping_reveal";
        let purpose = "synthetic_mapping_reveal";
        let payload = lifecycle
            .load_mapping_revision(
                &mut connection,
                &mapping_id,
                &privacy::MappingAccessContextV1 {
                    access_id,
                    redaction_id: &review.redaction_id,
                    purpose,
                    now_unix: TEST_NOW,
                    private_mapping_access_authorized: true,
                },
            )
            .expect("authorized mapping reveal");
        assert!(payload
            .entries
            .iter()
            .any(|entry| entry.sensitive_value == RAW_SYNTHETIC_TERM));
        assert!(!format!("{payload:?}").contains(RAW_SYNTHETIC_TERM));
        drop(payload);
        drop(connection);
        let current_mapping = manager
            .current_mapping_revision_binding(&review.redaction_id)
            .expect("query real mapping revision")
            .expect("current mapping revision");
        assert_eq!(current_mapping.mapping_id, mapping_id);
        assert_eq!(current_mapping.revision, 1);
    }

    #[test]
    fn case_custom_term_is_vault_encrypted_revision_bound_and_used_by_dictionary_detector() {
        const CASE_ID: &str = "case_61616161616161616161616161616161";
        const SUBJECT: &str = "SYNTHETIC_SUBJECT_ALPHA";
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text_with_terms(
            &manager,
            "dictionary-subject.txt",
            &format!("Protected case subject: {SUBJECT}."),
            CASE_ID,
            vec![SUBJECT.to_owned()],
        );
        let risk = review.risk_review.as_ref().expect("risk review");
        assert!(risk.findings.iter().any(|finding| {
            finding.case_dictionary_match
                && finding
                    .detector_sources
                    .iter()
                    .any(|source| source == "case_dictionary")
        }));

        let connection = manager.open_connection().expect("privacy connection");
        let case_id = CaseId::parse(CASE_ID.to_owned()).expect("case id");
        let dictionary =
            case_dictionary_store::load_required_case_dictionary(&connection, &manager, &case_id)
                .expect("encrypted dictionary");
        let state = manager
            .load_risk_state_unlocked(&connection, &review.redaction_id)
            .expect("risk state");
        assert_eq!(
            state.session.dictionary_revision_hash.as_ref(),
            Some(dictionary.revision_hash())
        );
        drop(connection);
        let raw_database = fs::read(&manager.shared.database_path).expect("read public database");
        assert!(!contains_bytes(&raw_database, SUBJECT.as_bytes()));
    }

    #[test]
    fn source_display_name_is_protected_and_blocks_independent_residual_scan() {
        const SOURCE_NAME: &str = "SYNTHETIC_SOURCE_CASE.txt";
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            SOURCE_NAME,
            "Referenced upload SYNTHETIC_SOURCE_CASE.txt, contact 13800138000.",
            "case_62626262626262626262626262626262",
        );
        assert_eq!(review.source_display_name, SOURCE_NAME);
        let residual = &review
            .risk_review
            .as_ref()
            .expect("risk review")
            .residual_scan;
        assert!(!residual.passed);
        assert!(residual
            .reason_codes
            .iter()
            .any(|reason| reason == "residual_source_name"));

        let raw_database = fs::read(&manager.shared.database_path).expect("read public database");
        assert!(!contains_bytes(&raw_database, SOURCE_NAME.as_bytes()));
        let restored = manager
            .load_review(&review.redaction_id)
            .expect("load protected display name");
        assert_eq!(restored.source_display_name, SOURCE_NAME);
    }

    #[test]
    fn add_to_dictionary_commits_real_vault_revision_and_future_actions_reverify_it() {
        const RAW_VALUE: &str = "13800138000";
        const CASE_ID: &str = "case_63636363636363636363636363636363";
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            "dictionary-action.txt",
            &format!("Contact phone: {RAW_VALUE}."),
            CASE_ID,
        );
        let initial = review.risk_review.as_ref().expect("initial risk");
        let finding_id = initial
            .findings
            .first()
            .expect("detected phone finding")
            .finding_id
            .clone();
        let updated = manager
            .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                redaction_id: review.redaction_id.clone(),
                expected_revision: initial.revision,
                actor: "dictionary-reviewer".to_owned(),
                edited_pages: edited_pages(&review, ""),
                action: ReviewActionV1::AddToDictionary {
                    finding_id,
                    category: privacy::case_dictionary::DictionaryCategoryV1::ContactInformation,
                    required: true,
                },
            })
            .expect("persist dictionary action and risk revision atomically");
        let updated_risk = updated.risk_review.as_ref().expect("updated risk");
        assert!(updated_risk
            .findings
            .iter()
            .any(|finding| finding.case_dictionary_match));

        let connection = manager.open_connection().expect("privacy connection");
        let case_id = CaseId::parse(CASE_ID.to_owned()).expect("case id");
        let dictionary =
            case_dictionary_store::load_required_case_dictionary(&connection, &manager, &case_id)
                .expect("updated encrypted dictionary");
        let state = manager
            .load_risk_state_unlocked(&connection, &review.redaction_id)
            .expect("updated risk state");
        assert_eq!(dictionary.revision(), 2);
        verify_dictionary_revision(&state.session, &dictionary).expect("exact revision binding");
        drop(connection);
        let raw_database = fs::read(&manager.shared.database_path).expect("read public database");
        assert!(!contains_bytes(&raw_database, RAW_VALUE.as_bytes()));
    }

    #[test]
    fn stale_dictionary_revision_blocks_review_action_and_approval() {
        const CASE_ID: &str = "case_64646464646464646464646464646464";
        const DRIFT_TERM: &str = "SYNTHETIC_DICTIONARY_DRIFT";
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            "dictionary-drift.txt",
            "Contact phone: 13800138000.",
            CASE_ID,
        );
        let case_id = CaseId::parse(CASE_ID.to_owned()).expect("case id");
        let material_id = MaterialId::parse(review.material_id.clone()).expect("material id");
        case_dictionary_store::ensure_case_dictionary(
            &manager,
            &case_id,
            &material_id,
            &[DRIFT_TERM.to_owned()],
            TEST_NOW + 1,
        )
        .expect("advance real dictionary head");

        let risk = review.risk_review.as_ref().expect("stale risk");
        let action_error = manager
            .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                redaction_id: review.redaction_id.clone(),
                expected_revision: risk.revision,
                actor: "dictionary-reviewer".to_owned(),
                edited_pages: edited_pages(&review, ""),
                action: ReviewActionV1::ConfirmEditedOutput,
            })
            .expect_err("stale dictionary action must fail closed");
        assert_eq!(
            action_error.code(),
            "privacy_case_dictionary_revision_conflict"
        );

        let mut approval = approval_request(&review, edited_pages(&review, ""));
        approval.expected_risk_revision = Some(risk.revision);
        let approval_error = manager
            .approve_review(approval)
            .expect_err("stale dictionary approval must fail closed");
        assert_eq!(
            approval_error.code(),
            "privacy_case_dictionary_revision_conflict"
        );
        let raw_database = fs::read(&manager.shared.database_path).expect("read public database");
        assert!(!contains_bytes(&raw_database, DRIFT_TERM.as_bytes()));
    }

    #[test]
    fn publication_invalidation_failure_preserves_dictionary_revision() {
        const CASE_ID: &str = "case_67676767676767676767676767676767";
        const BLOCKED_TERM: &str = "SYNTHETIC_BLOCKED_DICTIONARY_VALUE";
        let directory = tempfile::tempdir().expect("temp privacy directory");
        let invalidator = Arc::new(TogglePublicationInvalidator::default());
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
            invalidator.clone(),
        )
        .expect("privacy manager with invalidator");
        manager.set_test_runtime(
            ReceiptSigner::new([31_u8; 32]).expect("test signer"),
            TEST_NOW,
        );
        let review = prepare_case_text(
            &manager,
            "invalidation-failure.txt",
            "Synthetic contact phone: 13800138000.",
            CASE_ID,
        );
        let case_id = CaseId::parse(CASE_ID.to_owned()).expect("case id");
        let material_id = MaterialId::parse(review.material_id).expect("material id");
        let connection = manager.open_connection().expect("privacy database");
        let before =
            case_dictionary_store::load_required_case_dictionary(&connection, &manager, &case_id)
                .expect("initial dictionary");
        drop(connection);

        invalidator.fail.store(true, Ordering::SeqCst);
        let error = match case_dictionary_store::ensure_case_dictionary(
            &manager,
            &case_id,
            &material_id,
            &[BLOCKED_TERM.to_owned()],
            TEST_NOW + 1,
        ) {
            Ok(_) => panic!("failed publication revocation must block dictionary mutation"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            "approved_workspace_invalidation_injected_failure"
        );
        assert!(invalidator.case_calls.load(Ordering::SeqCst) >= 2);

        let connection = manager.open_connection().expect("privacy database");
        let after =
            case_dictionary_store::load_required_case_dictionary(&connection, &manager, &case_id)
                .expect("dictionary after blocked mutation");
        assert_eq!(after.revision(), before.revision());
        assert_eq!(after.revision_hash(), before.revision_hash());
        let raw_database = fs::read(&manager.shared.database_path).expect("read public database");
        assert!(!contains_bytes(&raw_database, BLOCKED_TERM.as_bytes()));
    }

    fn pdf_with_text(text: Option<&str>) -> Vec<u8> {
        let mut document = Document::with_version("1.5");
        let pages_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = document.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let operations = text.map_or_else(Vec::new, |value| {
            vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
                Operation::new("Td", vec![20.into(), 100.into()]),
                Operation::new("Tj", vec![Object::string_literal(value)]),
                Operation::new("ET", vec![]),
            ]
        });
        let content = Content { operations }.encode().expect("encode content");
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 300.into(), 300.into()],
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).expect("save PDF");
        bytes
    }

    fn tiny_rgba_png() -> Vec<u8> {
        vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ]
    }

    #[test]
    fn normalized_canaries_reject_plain_obfuscated_and_nfkc_equivalents() {
        for value in ["张三", "张\u{200b} 三", "张、三", "张- 三"] {
            let pages = vec![CanonicalRedactedPage {
                page_number: 1,
                text: value.to_owned(),
            }];
            let error = reject_normalized_canaries(&pages, &["张三".to_owned()])
                .expect_err("obfuscated source name must be rejected");
            assert_eq!(error.code(), "forbidden_canary_present");
        }

        let full_width = vec![CanonicalRedactedPage {
            page_number: 1,
            text: "a-b 1\u{200b}2".to_owned(),
        }];
        assert_eq!(
            reject_normalized_canaries(&full_width, &["ＡＢ１２".to_owned()])
                .expect_err("NFKC-equivalent canary")
                .code(),
            "forbidden_canary_present"
        );
        assert!(reject_normalized_canaries(
            &[CanonicalRedactedPage {
                page_number: 1,
                text: "[姓名1]".to_owned(),
            }],
            &["张三".to_owned()],
        )
        .is_ok());
    }

    #[test]
    fn canary_limits_fail_before_an_undeliverable_review_is_persisted() {
        let too_many = (0..=MAX_FORBIDDEN_CANARIES)
            .map(|index| format!("canary-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_forbidden_canaries(&too_many)
                .expect_err("too many canaries")
                .code(),
            "canary_limit_exceeded"
        );
        assert_eq!(
            validate_forbidden_canaries(&[])
                .expect_err("missing output canary")
                .code(),
            "canary_limit_exceeded"
        );
    }

    #[test]
    fn absent_custom_term_cannot_manufacture_a_source_canary() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let error = manager
            .prepare_material_bytes(
                b"A general procedural note without personal identifiers.",
                "absent-custom.txt".to_owned(),
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                vec!["case-secret-never-present".to_owned()],
            )
            .expect_err("an absent custom term must not create a canary");
        assert_eq!(error.code(), "canary_limit_exceeded");
    }

    #[test]
    fn approval_rejects_more_pages_than_safe_pdf_can_deliver() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_text(&manager, "page-limit.txt", "原告：张三。");
        let pages = (1..=SafePdfExportLimits::default().max_source_pages + 1)
            .map(|page_number| EditedRedactedPage {
                page_number: page_number as u32,
                redacted_text: "[姓名1]".to_owned(),
            })
            .collect();
        let error = validate_approval_request(&approval_request(&review, pages))
            .expect_err("501-page approval must fail before receipt issuance");
        assert_eq!(error.code(), "invalid_approval_request");
    }

    #[test]
    fn renderer_generic_approval_rejects_external_provider_and_mcp_scopes() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_text(&manager, "dedicated-approval.txt", "原告：张三。");
        for (kind, identifier, purpose) in [
            (
                DestinationKind::ExternalProvider,
                "provider-main",
                "case_summary",
            ),
            (
                DestinationKind::ExternalMcpHost,
                "approved-case-workspace",
                "approved_material_read",
            ),
        ] {
            let mut request = approval_request(&review, edited_pages(&review, ""));
            request.destination = ReceiptDestinationInput {
                kind,
                identifier: identifier.to_owned(),
            };
            request.purpose = purpose.to_owned();
            let error = manager
                .approve_local_safe_export_review(request)
                .expect_err("external scopes must use their dedicated approval entry point");
            assert_eq!(error.code(), "dedicated_approval_required");
        }
    }

    #[test]
    fn safe_pdf_preflight_catches_output_expansion_before_receipt_issuance() {
        let pages = (1..=17)
            .map(|page_number| CanonicalRedactedPage {
                page_number,
                text: "x".repeat(500 * 1024),
            })
            .collect::<Vec<_>>();
        let error = preflight_safe_pdf_delivery(&pages, &["never-present".to_owned()])
            .expect_err("UTF-16 hex expansion must respect the final PDF byte cap");
        assert_eq!(error.code(), "safe_pdf_export_failed");
    }
    #[test]
    fn later_labeled_name_redacts_an_earlier_text_segment() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let mut lines = vec!["张三先提交了申请材料。".to_owned()];
        for index in 2..=40 {
            lines.push(format!("普通事实说明第{index}行。"));
        }
        lines.push("原告：张三，现申请继续审理。".to_owned());
        let review = prepare_text(&manager, "cross-page.txt", &lines.join("\n"));

        assert_eq!(review.pages.len(), 2);
        assert!(!review.pages[0].redacted_text.contains("张三"));
        assert!(review.pages[0].redacted_text.contains("[姓名1]"));
        assert!(!review.pages[1].redacted_text.contains("张三"));
        assert_eq!(review.summary.counts.get("person_name"), Some(&2));
    }

    #[test]
    fn scanned_pdf_fails_closed_without_a_verified_local_ocr_backend() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let bytes = pdf_with_text(None);
        let mut off = PrivacyConfig::default();
        off.ocr.mode = ConfigOcrMode::Off;
        let error = manager
            .prepare_material_bytes(
                &bytes,
                "scan.pdf".to_owned(),
                &off,
                &local_ocr_status(),
                None,
                Vec::new(),
            )
            .expect_err("OCR-off scan must fail");
        assert_eq!(error.code(), "ocr_disabled");

        let mut auto = PrivacyConfig::default();
        auto.ocr.mode = ConfigOcrMode::AutoLocal;
        let error = manager
            .prepare_material_bytes(
                &bytes,
                "scan.pdf".to_owned(),
                &auto,
                &local_ocr_status(),
                None,
                Vec::new(),
            )
            .expect_err("unverified local OCR must fail");
        assert_eq!(error.code(), "ocr_backend_unavailable");
    }

    #[test]
    fn png_material_requires_verified_isolated_local_ocr() {
        let bytes = tiny_rgba_png();
        let mut off = PrivacyConfig::default();
        off.ocr.mode = ConfigOcrMode::Off;
        let error = extract_local_material(&bytes, "scan.png", &off, &local_ocr_status(), None)
            .expect_err("OCR-off PNG must fail");
        assert_eq!(error.code(), "ocr_disabled");

        let mut auto = PrivacyConfig::default();
        auto.ocr.mode = ConfigOcrMode::AutoLocal;
        let error = extract_local_material(&bytes, "scan.png", &auto, &local_ocr_status(), None)
            .expect_err("unverified PNG OCR must fail");
        assert_eq!(error.code(), "ocr_worker_isolation_unverified");

        let error = extract_local_material(&bytes, "renamed.jpg", &off, &local_ocr_status(), None)
            .expect_err("extension and image bytes must agree");
        assert_eq!(error.code(), "invalid_raster_image");
    }

    #[test]
    fn manual_canary_reintroduction_is_rejected_before_receipt_issuance() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_text(&manager, "canary.txt", "原告：张三，联系电话13800138000。");
        assert!(review.pages[0].redacted_text.contains("[姓名1]"));

        for replacement in ["张三", "张\u{200b} 三", "张、三"] {
            let pages = review
                .pages
                .iter()
                .map(|page| EditedRedactedPage {
                    page_number: page.page_number,
                    redacted_text: page.redacted_text.replace("[姓名1]", replacement),
                })
                .collect();
            let error = manager
                .approve_review(approval_request(&review, pages))
                .expect_err("source name may not be restored");
            assert_eq!(error.code(), "forbidden_canary_present");
        }
        assert_eq!(
            manager
                .load_review(&review.redaction_id)
                .expect("review remains available")
                .review_state,
            "review_required"
        );
    }

    #[test]
    fn edited_approval_restart_receipt_binding_and_safe_pdf_are_end_to_end() {
        const RESTART_SAFE_NOW: u64 = 4_000_000_000;
        let (directory, manager, signer) = manager_with_test_signer();
        manager.set_test_runtime(signer.clone(), RESTART_SAFE_NOW);
        let source_name = "极密案件-张三.txt";
        let source_text = "原告：张三，联系电话13800138000。";
        let review = prepare_case_text(
            &manager,
            source_name,
            source_text,
            "case_45454545454545454545454545454545",
        );
        let review = confirm_case_review(&manager, &review, "\n人工已逐项复核。");
        let risk = review
            .risk_review
            .as_ref()
            .expect("confirmed risk revision");
        let mut request = approval_request(&review, edited_pages(&review, ""));
        request.expected_risk_revision = Some(risk.revision);
        let approval = manager
            .approve_review(request)
            .expect("approve manually edited content");

        let raw_database = fs::read(&manager.shared.database_path).expect("read privacy DB");
        assert!(!contains_bytes(&raw_database, source_name.as_bytes()));
        assert!(!contains_bytes(&raw_database, source_text.as_bytes()));
        assert!(!contains_bytes(
            &raw_database,
            approval.receipt_token.as_bytes()
        ));
        assert!(!contains_bytes(
            &raw_database,
            approval.approved_payload_json.as_bytes()
        ));

        let loaded = manager
            .load_review(&review.redaction_id)
            .expect("load approved review");
        assert_eq!(loaded.review_state, "approved");
        assert!(loaded.pages[0].redacted_text.ends_with("人工已逐项复核。"));
        assert_eq!(
            loaded.suggested_redacted_content_sha256,
            approval.redacted_content_sha256
        );

        drop(manager);
        let restarted = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("restart manager");
        restarted.set_test_runtime(signer.clone(), RESTART_SAFE_NOW);
        let restored = restarted
            .load_review(&review.redaction_id)
            .expect("restore final approved pages after restart");
        assert!(restored.pages[0]
            .redacted_text
            .ends_with("人工已逐项复核。"));
        assert_eq!(
            restored.suggested_redacted_content_sha256,
            approval.redacted_content_sha256
        );

        let mut reissue_request = approval_request(
            &restored,
            restored
                .pages
                .iter()
                .map(|page| EditedRedactedPage {
                    page_number: page.page_number,
                    redacted_text: page.redacted_text.clone(),
                })
                .collect(),
        );
        reissue_request.expected_risk_revision = Some(
            restored
                .risk_review
                .as_ref()
                .expect("restored risk revision")
                .revision,
        );
        let reissued = restarted
            .approve_review(reissue_request)
            .expect("reissue exact approved payload after restart");
        let base = export_request(&restored, &reissued);
        let artifact = restarted
            .build_safe_pdf(base.clone())
            .expect("build receipt-bound safe PDF");
        assert!(artifact.bytes.starts_with(b"%PDF-"));
        assert!(artifact.output_page_count >= 1);
        restarted
            .verify_safe_pdf_authorization(&base)
            .expect("final active receipt verification");
        restarted
            .record_safe_pdf_export_cancellation(&base)
            .expect("record cancelled export without plaintext or path");
        restarted
            .record_safe_pdf_export_event(
                &base,
                &artifact,
                false,
                "local_safe_pdf_export_attempt_pending",
            )
            .expect("record pending export attempt");
        restarted
            .record_safe_pdf_export_event(&base, &artifact, true, "local_safe_pdf_export_succeeded")
            .expect("record successful export outcome");
        let audit_connection = restarted.open_connection().expect("open audit DB");
        let audited_events = audit_connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(allowed),0) FROM privacy_egress_audit
                 WHERE payload_sha256=?1 AND receipt_id=?2
                   AND purpose=?3
                   AND reason_code IN (
                     'local_safe_pdf_export_attempt_pending',
                     'local_safe_pdf_export_succeeded'
                   )",
                rusqlite::params![
                    &artifact.sha256,
                    &reissued.receipt_id,
                    LOCAL_SAFE_PDF_PURPOSE
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("query hash-only export audit");
        assert_eq!(audited_events, (2, 1));
        let cancelled_events = audit_connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_egress_audit
                 WHERE payload_sha256=?1 AND receipt_id=?2
                   AND purpose=?3 AND allowed=0
                   AND reason_code='local_safe_pdf_export_cancelled'",
                rusqlite::params![
                    sha256_hex(base.approved_payload_json.as_bytes()),
                    &reissued.receipt_id,
                    LOCAL_SAFE_PDF_PURPOSE
                ],
                |row| row.get::<_, i64>(0),
            )
            .expect("query hash-only cancellation audit");
        assert_eq!(cancelled_events, 1);
        drop(audit_connection);

        let mut payload_changed = base.clone();
        payload_changed.approved_payload_json.push(' ');
        assert_eq!(
            restarted
                .build_safe_pdf(payload_changed)
                .expect_err("one-byte payload change must fail")
                .code(),
            "redaction_receipt_invalid"
        );

        let mut target_changed = base.clone();
        target_changed.destination.identifier = "different-local-target".to_owned();
        assert_eq!(
            restarted
                .build_safe_pdf(target_changed)
                .expect_err("target change must fail")
                .code(),
            "invalid_safe_export_request"
        );

        let mut purpose_changed = base.clone();
        purpose_changed.purpose = "different_purpose".to_owned();
        assert_eq!(
            restarted
                .build_safe_pdf(purpose_changed)
                .expect_err("purpose change must fail")
                .code(),
            "invalid_safe_export_request"
        );

        let mut token_changed = base.clone();
        let mut token_bytes = token_changed.receipt_token.into_bytes();
        let last = token_bytes.last_mut().expect("token byte");
        *last = if *last == b'a' { b'b' } else { b'a' };
        token_changed.receipt_token = String::from_utf8(token_bytes).expect("ASCII token");
        assert_eq!(
            restarted
                .build_safe_pdf(token_changed)
                .expect_err("token replacement must fail")
                .code(),
            "redaction_receipt_invalid"
        );

        restarted.set_test_now(reissued.expires_at_unix + 1);
        assert_eq!(
            restarted
                .build_safe_pdf(base.clone())
                .expect_err("expired receipt must fail")
                .code(),
            "redaction_receipt_expired"
        );
        restarted.set_test_now(RESTART_SAFE_NOW);

        let receipt = signer
            .decode_token(&reissued.receipt_token)
            .expect("decode test receipt");
        let connection = restarted.open_connection().expect("open privacy DB");
        PrivacyStore::revoke_receipt(
            &connection,
            &receipt.claims.receipt_id,
            RESTART_SAFE_NOW + 1,
        )
        .expect("revoke receipt");
        drop(connection);
        assert_eq!(
            restarted
                .build_safe_pdf(base)
                .expect_err("revoked receipt must fail")
                .code(),
            "redaction_receipt_revoked"
        );
    }

    #[test]
    fn deleting_review_tombstones_and_revokes_while_preserving_protected_history_and_audit() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            "delete-review.txt",
            "Client phone 13800138000.",
            "case_56565656565656565656565656565656",
        );
        let review = confirm_case_review(&manager, &review, " reviewed.");
        let risk = review
            .risk_review
            .as_ref()
            .expect("confirmed risk revision");
        let mut request = approval_request(&review, edited_pages(&review, ""));
        request.expected_risk_revision = Some(risk.revision);
        let approval = manager
            .approve_review(request)
            .expect("approve review before deletion");
        let old_export = export_request(&review, &approval);

        let audit_before = {
            let connection = manager.open_connection().expect("open privacy DB");
            connection
                .query_row(
                    "SELECT COUNT(*),MAX(event_hash) FROM privacy_egress_audit",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .expect("read audit before deletion")
        };
        assert!(audit_before.0 > 0);

        let mut stale = deletion_request(&review);
        stale.expected_source_sha256 = "0".repeat(64);
        assert_eq!(
            manager
                .delete_review(stale)
                .expect_err("hash mismatch must not delete")
                .code(),
            "redaction_stale"
        );
        manager
            .load_review(&review.redaction_id)
            .expect("stale deletion leaves review intact");

        assert_eq!(
            manager
                .delete_review(deletion_request(&review))
                .expect("delete exact review"),
            DeletePrivacyReviewResponse { deleted: true }
        );

        let connection = manager.open_connection().expect("reopen privacy DB");
        let protected_counts = connection
            .query_row(
                "SELECT
                 (SELECT COUNT(*) FROM privacy_materials),
                 (SELECT COUNT(*) FROM privacy_redactions),
                 (SELECT COUNT(*) FROM privacy_receipts)",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("read protected row counts");
        assert_eq!(protected_counts, (1, 1, 1));
        let retained_state = connection
            .query_row(
                "SELECT material.deleted_at IS NOT NULL,material.state,
                        generation.revocation_state,generation.revoked_at IS NOT NULL,
                        receipt.revoked_at_unix IS NOT NULL,
                        (SELECT COUNT(*) FROM privacy_risk_review_revisions
                         WHERE redaction_id=generation.redaction_id)
                 FROM privacy_materials AS material
                 JOIN privacy_redactions AS generation
                   ON generation.material_id=material.material_id
                 JOIN privacy_receipts AS receipt
                   ON receipt.redaction_id=generation.redaction_id
                 WHERE generation.redaction_id=?1",
                [&review.redaction_id],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .expect("read retained tombstone and revocation state");
        assert_eq!(
            (
                retained_state.0,
                retained_state.1,
                retained_state.2,
                retained_state.3,
                retained_state.4,
            ),
            (true, "revoked".to_owned(), "revoked".to_owned(), true, true,)
        );
        assert!(retained_state.5 > 0);
        let audit_after = connection
            .query_row(
                "SELECT COUNT(*),MAX(event_hash) FROM privacy_egress_audit",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .expect("read audit after deletion");
        assert_eq!(audit_after, audit_before);
        drop(connection);

        assert!(manager.load_latest_review().expect("load latest").is_none());
        assert!(manager.load_review(&review.redaction_id).is_err());
        assert_eq!(
            manager
                .build_safe_pdf(old_export)
                .expect_err("deleted receipt must no longer authorize export")
                .code(),
            "redaction_receipt_revoked"
        );
        assert_eq!(
            manager
                .delete_review(deletion_request(&review))
                .expect("repeat deletion is idempotent"),
            DeletePrivacyReviewResponse { deleted: false }
        );
    }

    #[test]
    fn safe_export_approval_is_not_mcp_approval_and_dedicated_receipt_expires_closed() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            "approved-mcp.txt",
            "Synthetic client 13800138000.",
            "case_78787878787878787878787878787878",
        );
        let review = confirm_case_review(&manager, &review, " reviewed.");
        let risk = review
            .risk_review
            .as_ref()
            .expect("confirmed risk revision");
        let mut safe_request = approval_request(&review, edited_pages(&review, ""));
        safe_request.expected_risk_revision = Some(risk.revision);
        let safe_approval = manager
            .approve_review(safe_request)
            .expect("ordinary safe export approval");

        let selections = manager
            .list_approved_review_selections()
            .expect("list after ordinary approval");
        let selection = selections
            .iter()
            .find(|selection| selection.redaction_id == review.redaction_id)
            .expect("approved review selection");
        assert_eq!(
            selection.approved_payload_sha256,
            safe_approval.approved_payload_sha256
        );
        assert!(!selection.mcp_publish_approved);
        assert!(selection.mcp_publish_approval_expires_at_unix.is_none());

        let base = ApproveReviewForApprovedWorkspaceRequest {
            redaction_id: review.redaction_id.clone(),
            expected_approved_payload_sha256: safe_approval.approved_payload_sha256.clone(),
            reviewer: "mcp-reviewer".to_owned(),
            ttl_seconds: 3_600,
            confirmed: false,
        };
        assert!(manager
            .approve_review_for_approved_workspace(base.clone())
            .is_err());
        let mut stale = base.clone();
        stale.confirmed = true;
        stale.expected_approved_payload_sha256 = "0".repeat(64);
        assert!(manager
            .approve_review_for_approved_workspace(stale)
            .is_err());

        let mut exact = base;
        exact.confirmed = true;
        let approved = manager
            .approve_review_for_approved_workspace(exact)
            .expect("dedicated approved MCP approval");
        assert!(approved.mcp_publish_approved);
        assert_eq!(
            approved.destination_identifier,
            privacy::workspace::APPROVED_WORKSPACE_DESTINATION_SCOPE
        );
        assert_eq!(
            approved.purpose,
            privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE
        );
        let response_wire = serde_json::to_string(&approved).expect("serialize safe metadata");
        for forbidden in ["receiptToken", "approvedPayloadJson", "redactedText"] {
            assert!(!response_wire.contains(forbidden));
        }

        let selections = manager
            .list_approved_review_selections()
            .expect("list after dedicated approval");
        let selection = selections
            .iter()
            .find(|selection| selection.redaction_id == review.redaction_id)
            .expect("approved MCP selection");
        assert!(selection.mcp_publish_approved);
        assert_eq!(
            selection.mcp_publish_approval_expires_at_unix,
            Some(approved.expires_at_unix)
        );
        let source = manager
            .load_approved_generation_source(
                &review.redaction_id,
                &approved.approved_payload_sha256,
            )
            .expect("dedicated receipt authorizes approved generation source");
        assert!(source.case_dictionary_terms.is_empty());
        assert_eq!(
            source.source_terms.as_slice(),
            ["approved-mcp.txt", "approved-mcp"]
        );
        assert!(source
            .raw_canary_terms
            .iter()
            .any(|value| value == "13800138000"));
        assert!(!String::from_utf8_lossy(&source.approved_payload).contains("13800138000"));
        let current_mapping = manager
            .current_mapping_revision_binding(&review.redaction_id)
            .expect("current mapping binding")
            .expect("mapping exists for detected phone number");
        assert_ne!(
            source.mapping_revision_hash,
            current_mapping.mapping_revision_hash
        );
        assert_eq!(source.dictionary_revision_hash.as_str().len(), 64);
        assert_eq!(source.source_name_sha256.as_str().len(), 64);
        assert_eq!(source.source_revision_hash.as_str().len(), 64);
        drop(source);

        let connection = manager.open_connection().expect("privacy database");
        let original_source_name_hash = connection
            .query_row(
                "SELECT source_name_sha256 FROM privacy_materials WHERE material_id=?1",
                [&review.material_id],
                |row| row.get::<_, String>(0),
            )
            .expect("source-name hash");
        connection
            .execute(
                "UPDATE privacy_materials
                 SET source_name_sha256=?2,row_version=row_version+1
                 WHERE material_id=?1",
                rusqlite::params![&review.material_id, "0".repeat(64)],
            )
            .expect("inject source-name drift");
        drop(connection);
        assert_eq!(
            manager
                .load_approved_generation_source(
                    &review.redaction_id,
                    &approved.approved_payload_sha256,
                )
                .expect_err("source-name drift must block publication")
                .code(),
            "approved_generation_source_name_mismatch"
        );
        let connection = manager.open_connection().expect("privacy database");
        connection
            .execute(
                "UPDATE privacy_materials
                 SET source_name_sha256=?2,row_version=row_version+1
                 WHERE material_id=?1",
                rusqlite::params![&review.material_id, original_source_name_hash],
            )
            .expect("restore source-name binding");
        let (mapping_expires_at, mapping_key_version) = connection
            .query_row(
                "SELECT expires_at_unix,key_version FROM privacy_sensitive_mappings
                 WHERE redaction_id=?1 ORDER BY revision DESC LIMIT 1",
                [&review.redaction_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("mapping expiry and key");
        drop(connection);

        manager.set_test_now(u64::try_from(mapping_expires_at).expect("mapping expiry"));
        assert_eq!(
            manager
                .load_approved_generation_source(
                    &review.redaction_id,
                    &approved.approved_payload_sha256,
                )
                .expect_err("expired mapping must block publication")
                .code(),
            "privacy_mapping_revision_expired"
        );
        manager.set_test_now(TEST_NOW);

        let connection = manager.open_connection().expect("privacy database");
        connection
            .execute(
                "UPDATE privacy_mapping_keys SET state='revoked',revoked_at_unix=?2
                 WHERE key_version=?1",
                rusqlite::params![mapping_key_version, i64::try_from(TEST_NOW + 1).unwrap()],
            )
            .expect("inject mapping-key revocation");
        drop(connection);
        assert_eq!(
            manager
                .load_approved_generation_source(
                    &review.redaction_id,
                    &approved.approved_payload_sha256,
                )
                .expect_err("revoked mapping key must block publication")
                .code(),
            "privacy_mapping_key_revoked"
        );

        manager.set_test_now(approved.expires_at_unix + 1);
        let expired = manager
            .list_approved_review_selections()
            .expect("list after expiry");
        assert!(!expired[0].mcp_publish_approved);
        assert!(expired[0].mcp_publish_approval_expires_at_unix.is_none());
    }

    #[test]
    fn gated_publish_blocks_concurrent_delete_receipt_revoke_and_edit_until_commit() {
        use std::{sync::mpsc, thread, time::Duration};

        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_case_text(
            &manager,
            "approved-mcp-race.txt",
            "Synthetic client 13800138000.",
            "case_79797979797979797979797979797979",
        );
        let review = confirm_case_review(&manager, &review, " reviewed.");
        let risk = review
            .risk_review
            .as_ref()
            .expect("confirmed risk revision");
        let mut safe_request = approval_request(&review, edited_pages(&review, ""));
        safe_request.expected_risk_revision = Some(risk.revision);
        let safe_approval = manager
            .approve_review(safe_request)
            .expect("ordinary approval before dedicated approval");
        let dedicated = manager
            .approve_review_for_approved_workspace(ApproveReviewForApprovedWorkspaceRequest {
                redaction_id: review.redaction_id.clone(),
                expected_approved_payload_sha256: safe_approval.approved_payload_sha256.clone(),
                reviewer: "mcp-race-reviewer".to_owned(),
                ttl_seconds: 3_600,
                confirmed: true,
            })
            .expect("dedicated approval before race");
        let current = manager
            .load_review(&review.redaction_id)
            .expect("current approved review");
        let current_revision = current
            .risk_review
            .as_ref()
            .expect("current risk revision")
            .revision;
        let publish_project_id = manager
            .list_approved_review_selections()
            .expect("resolve application project identity")
            .into_iter()
            .find(|selection| selection.redaction_id == review.redaction_id)
            .expect("approved review project selection")
            .project_id;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publish_manager = manager.clone();
        let publish_redaction_id = review.redaction_id.clone();
        let publish_hash = dedicated.approved_payload_sha256.clone();
        let expected_hash = publish_hash.clone();
        let publish_thread = thread::spawn(move || {
            publish_manager
                .with_approved_generation_source_publish(
                    &publish_project_id,
                    &publish_redaction_id,
                    &publish_hash,
                    |_project_id, _privacy_case_id, source| {
                        entered_tx.send(()).expect("announce publish commit");
                        release_rx.recv().expect("release publish commit");
                        Ok::<String, &'static str>(source.approved_payload_sha256)
                    },
                )
                .expect("final source verification")
                .expect("synthetic commit")
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("publish entered guarded commit");

        let (ready_tx, ready_rx) = mpsc::channel();
        let (delete_done_tx, delete_done_rx) = mpsc::channel();
        let delete_manager = manager.clone();
        let delete_request = deletion_request(&review);
        let delete_ready = ready_tx.clone();
        let delete_thread = thread::spawn(move || {
            delete_ready.send(()).expect("delete ready");
            delete_done_tx
                .send(delete_manager.delete_review(delete_request).is_ok())
                .expect("delete result");
        });

        let (edit_done_tx, edit_done_rx) = mpsc::channel();
        let edit_manager = manager.clone();
        let edit_ready = ready_tx.clone();
        let edit_request = ApplyPrivacyRiskReviewActionRequest {
            redaction_id: review.redaction_id.clone(),
            expected_revision: current_revision,
            actor: "concurrent-editor".to_owned(),
            edited_pages: edited_pages(&current, ""),
            action: ReviewActionV1::RejectPublication,
        };
        let edit_thread = thread::spawn(move || {
            edit_ready.send(()).expect("edit ready");
            edit_done_tx
                .send(edit_manager.apply_risk_review_action(edit_request).is_ok())
                .expect("edit result");
        });

        let (revoke_done_tx, revoke_done_rx) = mpsc::channel();
        let revoke_manager = manager.clone();
        let receipt_id = dedicated.receipt_id;
        let revoke_thread = thread::spawn(move || {
            ready_tx.send(()).expect("revoke ready");
            let revoked = {
                let _gate = revoke_manager.gate();
                revoke_manager.open_connection().is_ok_and(|connection| {
                    PrivacyStore::revoke_receipt(&connection, &receipt_id, TEST_NOW + 1).is_ok()
                })
            };
            revoke_done_tx.send(revoked).expect("revoke result");
        });

        for _ in 0..3 {
            ready_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("race contender ready");
        }
        thread::sleep(Duration::from_millis(75));
        assert!(delete_done_rx.try_recv().is_err());
        assert!(edit_done_rx.try_recv().is_err());
        assert!(revoke_done_rx.try_recv().is_err());

        release_tx.send(()).expect("release guarded publish");
        assert_eq!(publish_thread.join().expect("join publish"), expected_hash);
        assert!(delete_done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("delete terminal result"));
        let _ = edit_done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("edit terminal result");
        let _ = revoke_done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("revoke terminal result");
        delete_thread.join().expect("join delete");
        edit_thread.join().expect("join edit");
        revoke_thread.join().expect("join revoke");
    }

    #[test]
    fn unc_case_source_is_rejected_before_filesystem_access() {
        let error = read_bounded_selected_material(Path::new(r"\\server\share\raw-case.pdf"))
            .expect_err("UNC source must be rejected");
        assert_eq!(error.code(), "filesystem_rejected");
    }
}
