use crate::privacy_manager::{LocalOcrStatus, OcrMode as ConfigOcrMode, PrivacyConfig};
use file_ingest::FileFormat;
use material_processing::{
    approved_text_sha256, reconstruct_approved_text_pdf, ApprovedTextPage, BackendTrace,
    ExtractionBackend, OcrMode, PageExtractionDecision, ProcessedSpan, ProcessingError,
    ProcessingLimits, QualityReasonCode, SafePdfArtifact, SafePdfExportError, SafePdfExportLimits,
    SafePdfExportRequest, SpanKind, TextLayerAssessment,
};
use privacy::{
    scan_residual, sha256_hex, ActiveReceiptVerification, DataClassification, DestinationKind,
    DestinationScope, EgressCandidate, EgressPolicyEngine, PrivacyEgressAuditRecord, PrivacyStore,
    PrivacyStoreError, ReceiptSigner, RedactionOptions, RedactionReceiptClaims, RedactionSummary,
    Redactor, RegisterPrivacyMaterial, ReviewState, SaveReviewDraft, REDACTION_VERSION,
};
use providers::{
    windows_credentials::WindowsCredentialStore, ApiSecret, CredentialStore, ProviderCredentialKey,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};

const PRIVACY_DIRECTORY_NAME: &str = "privacy";
const PRIVACY_DATABASE_NAME: &str = "privacy-workflow.sqlite";
const MAX_SELECTED_FILE_BYTES: u64 = file_ingest::MAX_FILE_BYTES as u64;
const FILE_INGEST_PROCESSING_VERSION: &str = "lawyer-assistance-file-ingest-v1";
const POLICY_ID: &str = "cn-legal-default";
const POLICY_VERSION: u32 = 1;
const REVIEW_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const APPROVED_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const RECEIPT_KEY_VERSION: u32 = 1;
const RECEIPT_KEY_SERVICE: &str = "LawyerAssistancePrivacy";
const RECEIPT_KEY_PROVIDER: &str = "redaction-receipt-signing";
const RECEIPT_KEY_ACCOUNT: &str = "v1";
const LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER: &str = "local-safe-pdf-export-v1";
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
}

impl fmt::Display for PrivacyWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PrivacyWorkflowError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparePrivacyMaterialRequest {
    #[serde(default)]
    pub custom_terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparePrivacyMaterialResponse {
    pub cancelled: bool,
    pub review: Option<PrivacyReviewView>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadPrivacyReviewRequest {
    pub redaction_id: String,
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
    pub source_display_name: String,
    pub source_sha256: String,
    pub extraction_sha256: String,
    pub suggested_redacted_content_sha256: String,
    pub processing_version: String,
    pub media_type: String,
    pub page_count: u32,
    pub backend_trace: Vec<BackendTrace>,
    pub summary: RedactionSummary,
    pub review_state: String,
    pub pages: Vec<ReviewPageView>,
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
    pub receipt_token: String,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportApprovedReviewPdfRequest {
    pub redaction_id: String,
    pub receipt_token: String,
    pub approved_payload_json: String,
    pub destination: ReceiptDestinationInput,
    pub purpose: String,
}

#[derive(Debug)]
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
    source_sha256: String,
    extraction_sha256: String,
    suggested_redacted_content_sha256: String,
    processing_version: String,
    media_type: String,
    page_count: u32,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedApprovedPayload {
    schema_version: u16,
    source_sha256: String,
    extraction_sha256: String,
    media_type: String,
    pages: Vec<CanonicalRedactedPage>,
}

#[derive(Clone)]
pub struct PrivacyWorkflowManager {
    shared: Arc<PrivacyWorkflowShared>,
}

struct PrivacyWorkflowShared {
    database_path: PathBuf,
    operation_gate: Mutex<()>,
    receipt_signer_override: Mutex<Option<ReceiptSigner>>,
    now_unix_override: Mutex<Option<u64>>,
}

impl fmt::Debug for PrivacyWorkflowManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyWorkflowManager")
            .field("database", &"<local-privacy-store>")
            .finish()
    }
}

impl PrivacyWorkflowManager {
    pub fn new(app_local_data_directory: PathBuf) -> Result<Self, PrivacyWorkflowError> {
        let directory = app_local_data_directory.join(PRIVACY_DIRECTORY_NAME);
        fs::create_dir_all(&directory).map_err(|_| {
            PrivacyWorkflowError::new("privacy_store_unavailable", "本机隐私数据库目录无法创建。")
        })?;
        validate_ordinary_directory(&directory)?;
        let manager = Self {
            shared: Arc::new(PrivacyWorkflowShared {
                database_path: directory.join(PRIVACY_DATABASE_NAME),
                operation_gate: Mutex::new(()),
                receipt_signer_override: Mutex::new(None),
                now_unix_override: Mutex::new(None),
            }),
        };
        let connection = manager.open_connection()?;
        PrivacyStore::initialize(&connection).map_err(PrivacyWorkflowError::store)?;
        drop(connection);
        validate_ordinary_database_file(&manager.shared.database_path)?;
        Ok(manager)
    }

    fn gate(&self) -> MutexGuard<'_, ()> {
        self.shared
            .operation_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    fn set_test_runtime(&self, signer: ReceiptSigner, now_unix: u64) {
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
    fn set_test_now(&self, now_unix: u64) {
        *self
            .shared
            .now_unix_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now_unix);
    }

    fn open_connection(&self) -> Result<Connection, PrivacyWorkflowError> {
        let connection = Connection::open(&self.shared.database_path).map_err(|_| {
            PrivacyWorkflowError::new("privacy_store_unavailable", "本机隐私数据库无法打开。")
        })?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=DELETE;
                 PRAGMA synchronous=FULL;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_unavailable",
                    "本机隐私数据库无法进入安全模式。",
                )
            })?;
        PrivacyStore::initialize(&connection).map_err(PrivacyWorkflowError::store)?;
        Ok(connection)
    }

    pub fn prepare_selected_material(
        &self,
        path: &Path,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let _gate = self.gate();
        let (bytes, source_display_name) = read_bounded_selected_material(path)?;
        self.prepare_material_bytes(
            &bytes,
            source_display_name,
            config,
            ocr_status,
            custom_terms,
        )
    }

    fn prepare_material_bytes(
        &self,
        bytes: &[u8],
        source_display_name: String,
        config: &PrivacyConfig,
        ocr_status: &LocalOcrStatus,
        custom_terms: Vec<String>,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let processed = extract_local_material(bytes, &source_display_name, config, ocr_status)?;

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
        let material_id = format!("mat_{}", Uuid::new_v4().simple());
        let redaction_id = format!("red_{}", Uuid::new_v4().simple());
        let stored = StoredReviewPayload {
            schema_version: REVIEW_PAYLOAD_SCHEMA_VERSION,
            material_id: material_id.clone(),
            redaction_id: redaction_id.clone(),
            source_sha256: processed.source_sha256.clone(),
            extraction_sha256: extraction_sha256.clone(),
            suggested_redacted_content_sha256: suggested_redacted_content_sha256.clone(),
            processing_version: processed.processing_version.clone(),
            media_type: processed.media_type.clone(),
            page_count: processed.page_count,
            backend_trace: processed.backend_trace.clone(),
            summary,
            pages: stored_pages,
            forbidden_canaries,
        };
        let protected_plaintext = serde_json::to_vec(&stored).map_err(|_| {
            PrivacyWorkflowError::new("review_payload_invalid", "本地审阅数据无法序列化。")
        })?;

        let connection = self.open_connection()?;
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .map_err(|_| PrivacyWorkflowError::new("privacy_store_busy", "本机隐私数据库繁忙。"))?;
        let source_name_sha256 = sha256_hex(source_display_name.as_bytes());
        let store_result = (|| -> Result<(), PrivacyStoreError> {
            PrivacyStore::register_material(
                &connection,
                &RegisterPrivacyMaterial {
                    material_id: &material_id,
                    project_id: None,
                    attachment_id: None,
                    source_sha256: &stored.source_sha256,
                    source_name_sha256: &source_name_sha256,
                    media_type: &stored.media_type,
                    page_count: Some(stored.page_count),
                },
            )?;
            PrivacyStore::save_review_draft(
                &connection,
                &SaveReviewDraft {
                    redaction_id: &redaction_id,
                    material_id: &material_id,
                    extraction_sha256: &extraction_sha256,
                    redacted_content_sha256: &suggested_redacted_content_sha256,
                    policy_id: POLICY_ID,
                    policy_version: POLICY_VERSION,
                    detector_version: REDACTION_VERSION,
                    unresolved_high_risk_count: 0,
                    review_payload_plaintext: &protected_plaintext,
                },
            )
        })();
        match store_result {
            Ok(()) => connection.execute_batch("COMMIT;").map_err(|_| {
                PrivacyWorkflowError::new("privacy_store_commit_failed", "本机审阅数据未能提交。")
            })?,
            Err(error) => {
                let _ = connection.execute_batch("ROLLBACK;");
                return Err(PrivacyWorkflowError::store(error));
            }
        }
        stored_to_view(stored, "review_required", source_display_name)
    }

    pub fn load_review(
        &self,
        redaction_id: &str,
    ) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.load_review_unlocked(redaction_id)
    }

    pub fn load_latest_review(&self) -> Result<Option<PrivacyReviewView>, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let redaction_id = connection
            .query_row(
                "SELECT redaction_id FROM privacy_redactions ORDER BY rowid DESC LIMIT 1",
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

    pub fn delete_review(
        &self,
        request: DeletePrivacyReviewRequest,
    ) -> Result<DeletePrivacyReviewResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
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
        let deleted = match PrivacyStore::delete_redaction_material_exact(
            &mut connection,
            &request.redaction_id,
            &request.expected_source_sha256,
            &request.expected_extraction_sha256,
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
        stored_to_view(
            stored,
            &loaded.review_state,
            "本机材料（名称未持久化）".to_owned(),
        )
    }

    pub fn approve_review(
        &self,
        request: ApprovePrivacyReviewRequest,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
        validate_approval_request(&request)?;
        let connection = self.open_connection()?;
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
        preflight_safe_pdf_delivery(&edited_pages, &stored.forbidden_canaries)?;
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
        match PrivacyStore::approve_review(
            &mut mutable_connection,
            &request.redaction_id,
            &request.expected_suggested_redacted_sha256,
            &redacted_content_sha256,
            &approved_payload_sha256,
            &reviewer_sha256,
            &approved_review_payload_plaintext,
        ) {
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
            transport_enforcement: "local_receipt_issued_provider_transport_not_fully_gated",
        })
    }

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
    source_display_name: String,
) -> Result<PrivacyReviewView, PrivacyWorkflowError> {
    if stored.page_count as usize != stored.pages.len() {
        return Err(PrivacyWorkflowError::new(
            "review_payload_mismatch",
            "审阅页数与本地提取摘要不一致。",
        ));
    }
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
        source_display_name,
        source_sha256: stored.source_sha256,
        extraction_sha256: stored.extraction_sha256,
        suggested_redacted_content_sha256: stored.suggested_redacted_content_sha256,
        processing_version: stored.processing_version,
        media_type: stored.media_type,
        page_count: stored.page_count,
        backend_trace: stored.backend_trace,
        summary: stored.summary,
        review_state: review_state.to_owned(),
        pages,
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

fn validate_approval_request(
    request: &ApprovePrivacyReviewRequest,
) -> Result<(), PrivacyWorkflowError> {
    if !valid_identifier(&request.redaction_id)
        || !valid_hash(&request.expected_suggested_redacted_sha256)
        || !valid_identifier(request.reviewer.trim())
        || !valid_identifier(request.destination.identifier.trim())
        || !valid_identifier(request.purpose.trim())
        || !matches!(
            &request.destination.kind,
            DestinationKind::VerifiedLocalProvider
        )
        || request.destination.identifier.trim() != LOCAL_SAFE_PDF_DESTINATION_IDENTIFIER
        || request.purpose.trim() != LOCAL_SAFE_PDF_PURPOSE
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
) -> Result<LocalExtractedDocument, PrivacyWorkflowError> {
    let format = file_ingest::detect_format(source_name).map_err(ingest_error)?;
    match format {
        FileFormat::Pdf => extract_pdf_material(bytes, config, ocr_status),
        FileFormat::Docx | FileFormat::Txt | FileFormat::Markdown => {
            extract_segmented_material(bytes, source_name)
        }
    }
}

fn extract_pdf_material(
    bytes: &[u8],
    config: &PrivacyConfig,
    ocr_status: &LocalOcrStatus,
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
    // No certified worker manifest/firewall evidence is yet represented in
    // settings. Healthy text layers remain local; OCR-required pages fail.
    let processed = material_processing::process_pdf(bytes, ocr_mode, None, limits)
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
    use tempfile::TempDir;

    const TEST_NOW: u64 = 1_700_000_000;

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
        }
    }

    fn manager_with_test_signer() -> (TempDir, PrivacyWorkflowManager, ReceiptSigner) {
        let directory = tempfile::tempdir().expect("temp privacy directory");
        let manager =
            PrivacyWorkflowManager::new(directory.path().to_path_buf()).expect("privacy manager");
        let signer = ReceiptSigner::new([7u8; 32]).expect("test receipt signer");
        manager.set_test_runtime(signer.clone(), TEST_NOW);
        (directory, manager, signer)
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
                Vec::new(),
            )
            .expect("prepare local text review")
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
                Vec::new(),
            )
            .expect_err("unverified local OCR must fail");
        assert_eq!(error.code(), "ocr_backend_unavailable");
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
        let (directory, manager, signer) = manager_with_test_signer();
        let source_name = "极密案件-张三.txt";
        let source_text = "原告：张三，联系电话13800138000。";
        let review = prepare_text(&manager, source_name, source_text);
        let edited = edited_pages(&review, "\n人工已逐项复核。");
        let approval = manager
            .approve_review(approval_request(&review, edited))
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
        let restarted =
            PrivacyWorkflowManager::new(directory.path().to_path_buf()).expect("restart manager");
        restarted.set_test_runtime(signer.clone(), TEST_NOW);
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

        let reissued = restarted
            .approve_review(approval_request(
                &restored,
                restored
                    .pages
                    .iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.redacted_text.clone(),
                    })
                    .collect(),
            ))
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
        restarted.set_test_now(TEST_NOW);

        let receipt = signer
            .decode_token(&reissued.receipt_token)
            .expect("decode test receipt");
        let connection = restarted.open_connection().expect("open privacy DB");
        PrivacyStore::revoke_receipt(&connection, &receipt.claims.receipt_id, TEST_NOW + 1)
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
    fn deleting_review_revokes_receipts_removes_protected_state_and_preserves_audit() {
        let (_directory, manager, _signer) = manager_with_test_signer();
        let review = prepare_text(&manager, "delete-review.txt", "Client phone 13800138000.");
        let approval = manager
            .approve_review(approval_request(
                &review,
                edited_pages(&review, " reviewed."),
            ))
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
        assert_eq!(protected_counts, (0, 0, 0));
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
            "redaction_receipt_invalid"
        );
        assert_eq!(
            manager
                .delete_review(deletion_request(&review))
                .expect("repeat deletion is idempotent"),
            DeletePrivacyReviewResponse { deleted: false }
        );
    }

    #[test]
    fn unc_case_source_is_rejected_before_filesystem_access() {
        let error = read_bounded_selected_material(Path::new(r"\\server\share\raw-case.pdf"))
            .expect_err("UNC source must be rejected");
        assert_eq!(error.code(), "filesystem_rejected");
    }
}
