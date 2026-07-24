use super::{
    reject_normalized_canaries, valid_hash, valid_identifier, validate_loaded_review,
    ApprovedPayload, CanonicalRedactedPage, PrivacyWorkflowError, PrivacyWorkflowManager,
    StoredReviewPayload, APPROVED_PAYLOAD_SCHEMA_VERSION, POLICY_ID, POLICY_VERSION,
    RECEIPT_KEY_VERSION,
};
use material_processing::{
    approved_text_sha256, reconstruct_approved_text_docx, reconstruct_approved_text_markdown,
    reconstruct_approved_text_pdf, reconstruct_approved_text_txt,
    verify_approved_text_derived_bytes, verify_approved_text_pdf_bytes, ApprovedTextPage,
    SafeDerivedFormat, SafePdfExportLimits, SafePdfExportRequest,
};
use privacy::{
    scan_residual, sha256_hex, unprotect_local, ActiveReceiptVerification, DataClassification,
    DestinationKind, DestinationScope, PrivacyEgressAuditRecord, PrivacyStore, REDACTION_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{compiler_fence, Ordering},
};
use uuid::Uuid;

const PDF_MEDIA_TYPE: &str = "application/pdf";
const MAX_RECEIPT_TOKEN_BYTES: usize = 65_536;
const MAX_APPROVED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeExportFormat {
    Pdf,
    Txt,
    Markdown,
    Docx,
}

impl SafeExportFormat {
    pub const ALL: [Self; 4] = [Self::Pdf, Self::Txt, Self::Markdown, Self::Docx];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Txt => "txt",
            Self::Markdown => "markdown",
            Self::Docx => "docx",
        }
    }

    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Txt => "txt",
            Self::Markdown => "md",
            Self::Docx => "docx",
        }
    }

    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Pdf => PDF_MEDIA_TYPE,
            Self::Txt => "text/plain; charset=utf-8",
            Self::Markdown => "text/markdown; charset=utf-8",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }
    }

    #[must_use]
    pub const fn destination_identifier(self) -> &'static str {
        match self {
            Self::Pdf => "local-safe-pdf-export-v1",
            Self::Txt => "local-safe-txt-export-v1",
            Self::Markdown => "local-safe-markdown-export-v1",
            Self::Docx => "local-safe-docx-export-v1",
        }
    }

    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Pdf => "local_safe_pdf_export",
            Self::Txt => "local_safe_txt_export",
            Self::Markdown => "local_safe_markdown_export",
            Self::Docx => "local_safe_docx_export",
        }
    }

    #[must_use]
    pub const fn default_file_name(self) -> &'static str {
        match self {
            Self::Pdf => "已脱敏材料.pdf",
            Self::Txt => "已脱敏材料.txt",
            Self::Markdown => "已脱敏材料.md",
            Self::Docx => "已脱敏材料.docx",
        }
    }

    #[must_use]
    pub const fn dialog_filter_label(self) -> &'static str {
        match self {
            Self::Pdf => "PDF 文档",
            Self::Txt => "纯文本文档",
            Self::Markdown => "Markdown 文档",
            Self::Docx => "Word 文档",
        }
    }

    #[must_use]
    pub fn destination(self) -> DestinationScope {
        DestinationScope {
            kind: DestinationKind::VerifiedLocalProvider,
            identifier: self.destination_identifier().to_owned(),
        }
    }

    #[must_use]
    pub fn matches_scope(self, destination: &DestinationScope, purpose: &str) -> bool {
        matches!(destination.kind, DestinationKind::VerifiedLocalProvider)
            && destination.identifier == self.destination_identifier()
            && purpose == self.purpose()
    }

    #[must_use]
    pub fn from_scope(destination: &DestinationScope, purpose: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| format.matches_scope(destination, purpose))
    }

    const fn derived(self) -> Option<SafeDerivedFormat> {
        match self {
            Self::Pdf => None,
            Self::Txt => Some(SafeDerivedFormat::Txt),
            Self::Markdown => Some(SafeDerivedFormat::Markdown),
            Self::Docx => Some(SafeDerivedFormat::Docx),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportApprovedPrivacyReviewRequest {
    pub redaction_id: String,
    pub format: SafeExportFormat,
}

struct RestoredSafeExportAuthorization {
    redaction_id: String,
    format: SafeExportFormat,
    destination: DestinationScope,
    purpose: String,
    approved_payload_json: String,
    approved_payload_sha256: String,
    receipt_token: String,
    receipt_id: String,
}

pub struct BuiltSafeExport {
    pub format: SafeExportFormat,
    pub media_type: String,
    pub file_extension: String,
    pub bytes: Vec<u8>,
    pub artifact_sha256: String,
    pub approved_text_sha256: String,
    pub reopened_text_sha256: String,
    pub source_page_count: u32,
    pub output_page_count: u32,
    authorization: RestoredSafeExportAuthorization,
    verification_request: SafePdfExportRequest,
}

impl fmt::Debug for BuiltSafeExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltSafeExport")
            .field("format", &self.format)
            .field("media_type", &self.media_type)
            .field("file_extension", &self.file_extension)
            .field(
                "bytes",
                &format_args!("[REDACTED; {} bytes]", self.bytes.len()),
            )
            .field("source_page_count", &self.source_page_count)
            .field("output_page_count", &self.output_page_count)
            .field("authorization", &"[REDACTED]")
            .field("verification_request", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RestoredSafeExportAuthorization {
    fn drop(&mut self) {
        volatile_zeroize_string(&mut self.redaction_id);
        volatile_zeroize_string(&mut self.destination.identifier);
        volatile_zeroize_string(&mut self.purpose);
        volatile_zeroize_string(&mut self.approved_payload_json);
        volatile_zeroize_string(&mut self.approved_payload_sha256);
        volatile_zeroize_string(&mut self.receipt_token);
        volatile_zeroize_string(&mut self.receipt_id);
    }
}

impl Drop for BuiltSafeExport {
    fn drop(&mut self) {
        volatile_zeroize_bytes(&mut self.bytes);
        volatile_zeroize_string(&mut self.artifact_sha256);
        volatile_zeroize_string(&mut self.approved_text_sha256);
        volatile_zeroize_string(&mut self.reopened_text_sha256);
        volatile_zeroize_string(&mut self.verification_request.approved_text_sha256);
        for page in &mut self.verification_request.pages {
            volatile_zeroize_string(&mut page.text);
        }
        for canary in &mut self.verification_request.forbidden_canaries {
            volatile_zeroize_string(canary);
        }
    }
}

fn volatile_zeroize_string(value: &mut String) {
    // SAFETY: bytes are replaced only with zero, which is valid UTF-8, before
    // the String is cleared. The allocation remains exclusively borrowed.
    let bytes = unsafe { value.as_bytes_mut() };
    for byte in bytes {
        // SAFETY: byte points into the exclusively borrowed String allocation.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    value.clear();
}

fn volatile_zeroize_bytes(value: &mut Vec<u8>) {
    for byte in value.iter_mut() {
        // SAFETY: byte points into the exclusively borrowed Vec allocation.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    value.clear();
}

#[derive(Debug, Clone)]
struct BuiltArtifactCore {
    media_type: String,
    bytes: Vec<u8>,
    artifact_sha256: String,
    approved_text_sha256: String,
    reopened_text_sha256: String,
    source_page_count: u32,
    output_page_count: u32,
}

impl PrivacyWorkflowManager {
    /// Restore exact approved state and the newest active format-bound receipt.
    /// The frontend supplies no token, approved JSON, destination, purpose or path.
    pub fn build_safe_export(
        &self,
        request: &ExportApprovedPrivacyReviewRequest,
    ) -> Result<BuiltSafeExport, PrivacyWorkflowError> {
        let _gate = self.gate();
        validate_export_request(request)?;
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let connection = self.open_connection()?;
        let (authorization, verification_request) =
            self.restore_safe_export_authorization(&connection, &signer, now_unix, request)?;
        let core = build_artifact(request.format, &verification_request)?;
        Ok(BuiltSafeExport {
            format: request.format,
            media_type: core.media_type,
            file_extension: request.format.file_extension().to_owned(),
            bytes: core.bytes,
            artifact_sha256: core.artifact_sha256,
            approved_text_sha256: core.approved_text_sha256,
            reopened_text_sha256: core.reopened_text_sha256,
            source_page_count: core.source_page_count,
            output_page_count: core.output_page_count,
            authorization,
            verification_request,
        })
    }

    pub fn verify_safe_export_authorization(
        &self,
        built: &BuiltSafeExport,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        validate_built_export(built)?;
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let connection = self.open_connection()?;
        verify_authorization(&connection, &signer, now_unix, &built.authorization)
    }

    /// Reopen bytes read from the final installed path and compare all evidence.
    pub fn verify_installed_safe_export(
        &self,
        built: &BuiltSafeExport,
        installed_bytes: &[u8],
    ) -> Result<(), PrivacyWorkflowError> {
        validate_built_export(built)?;
        if sha256_hex(installed_bytes) != built.artifact_sha256 {
            return Err(PrivacyWorkflowError::new(
                "export_verify_failed",
                "安全导出文件安装后哈希不一致。",
            ));
        }
        let residual = scan_residual(built.authorization.approved_payload_json.as_bytes())
            .map_err(|error| {
                PrivacyWorkflowError::new(
                    error.code(),
                    "安全导出安装后无法复核获批载荷的残留敏感信息。",
                )
            })?;
        if !residual.passed {
            return Err(PrivacyWorkflowError::new(
                "residual_sensitive_content",
                "安全导出安装后复核发现获批载荷含高置信敏感标识。",
            ));
        }
        verify_artifact_bytes(
            built.format,
            installed_bytes,
            &built.verification_request,
            &BuiltArtifactCore {
                media_type: built.media_type.clone(),
                bytes: Vec::new(),
                artifact_sha256: built.artifact_sha256.clone(),
                approved_text_sha256: built.approved_text_sha256.clone(),
                reopened_text_sha256: built.reopened_text_sha256.clone(),
                source_page_count: built.source_page_count,
                output_page_count: built.output_page_count,
            },
        )
    }

    /// Audit cancellation without storing the selected path or plaintext.
    pub fn record_safe_export_cancellation(
        &self,
        request: &ExportApprovedPrivacyReviewRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        validate_export_request(request)?;
        let signer = self.receipt_signer()?;
        let now_unix = self.current_unix()?;
        let mut connection = self.open_connection()?;
        let (authorization, _) =
            self.restore_safe_export_authorization(&connection, &signer, now_unix, request)?;
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: now_unix,
            classification: DataClassification::CaseRedactedApproved,
            destination_kind: authorization.destination.kind.clone(),
            destination_identifier_sha256: sha256_hex(
                authorization.destination.identifier.as_bytes(),
            ),
            purpose: authorization.purpose.clone(),
            payload_sha256: authorization.approved_payload_sha256.clone(),
            payload_bytes: authorization.approved_payload_json.len(),
            policy_id: POLICY_ID.to_owned(),
            policy_version: POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: Some(authorization.receipt_id.clone()),
            residual_counts: BTreeMap::new(),
            allowed: false,
            reason_code: export_reason(request.format, "cancelled"),
        };
        PrivacyStore::append_egress_audit(
            &mut connection,
            &format!("audit_{}", Uuid::new_v4().simple()),
            &audit,
        )
        .map(|_| ())
        .map_err(PrivacyWorkflowError::store)
    }

    pub fn record_safe_export_event(
        &self,
        built: &BuiltSafeExport,
        allowed: bool,
        reason_code: &str,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        validate_built_export(built)?;
        if !valid_identifier(reason_code) {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "安全导出审计原因代码无效。",
            ));
        }
        let signer = self.receipt_signer()?;
        let receipt = signer
            .decode_token(&built.authorization.receipt_token)
            .map_err(|error| {
                PrivacyWorkflowError::new(error.code(), "安全导出审计回执无法解码。")
            })?;
        if receipt.claims.receipt_id != built.authorization.receipt_id
            || receipt.claims.destination != built.authorization.destination
            || receipt.claims.purpose != built.authorization.purpose
            || receipt.claims.approved_payload_sha256 != built.authorization.approved_payload_sha256
        {
            return Err(PrivacyWorkflowError::new(
                "invalid_safe_export_audit",
                "安全导出审计事件与签名回执不一致。",
            ));
        }
        let mut connection = self.open_connection()?;
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: self.current_unix()?,
            classification: DataClassification::CaseRedactedApproved,
            destination_kind: built.authorization.destination.kind.clone(),
            destination_identifier_sha256: sha256_hex(
                built.authorization.destination.identifier.as_bytes(),
            ),
            purpose: built.authorization.purpose.clone(),
            payload_sha256: built.artifact_sha256.clone(),
            payload_bytes: built.bytes.len(),
            policy_id: POLICY_ID.to_owned(),
            policy_version: POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: Some(built.authorization.receipt_id.clone()),
            residual_counts: BTreeMap::new(),
            allowed,
            reason_code: reason_code.to_owned(),
        };
        PrivacyStore::append_egress_audit(
            &mut connection,
            &format!("audit_{}", Uuid::new_v4().simple()),
            &audit,
        )
        .map(|_| ())
        .map_err(PrivacyWorkflowError::store)
    }

    fn restore_safe_export_authorization(
        &self,
        connection: &Connection,
        signer: &privacy::ReceiptSigner,
        now_unix: u64,
        request: &ExportApprovedPrivacyReviewRequest,
    ) -> Result<(RestoredSafeExportAuthorization, SafePdfExportRequest), PrivacyWorkflowError> {
        let loaded = PrivacyStore::load_review_draft(connection, &request.redaction_id)
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
                    "安全导出无法读取受保护的最终批准代。",
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
        reject_normalized_canaries(&approved_pages, &stored.forbidden_canaries)?;
        if stored.forbidden_canaries.is_empty() {
            return Err(PrivacyWorkflowError::new(
                "safe_export_missing_canary",
                "受保护批准代缺少源敏感 canary，安全导出保持关闭。",
            ));
        }
        let approved = ApprovedPayload {
            schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
            source_sha256: &stored.source_sha256,
            extraction_sha256: &stored.extraction_sha256,
            media_type: &stored.media_type,
            pages: &approved_pages,
        };
        let approved_payload = serde_json::to_vec(&approved).map_err(|_| {
            PrivacyWorkflowError::new("canonicalization_failed", "最终批准代无法确定性重建。")
        })?;
        if approved_payload.is_empty() || approved_payload.len() > MAX_APPROVED_PAYLOAD_BYTES {
            return Err(PrivacyWorkflowError::new(
                "approved_payload_invalid",
                "最终批准代大小无效。",
            ));
        }
        let residual = scan_residual(&approved_payload).map_err(|error| {
            PrivacyWorkflowError::new(error.code(), "安全导出前残留敏感信息扫描失败。")
        })?;
        if !residual.passed {
            return Err(PrivacyWorkflowError::new(
                "residual_sensitive_content",
                "最终批准代在当前 detector 下仍含高置信敏感标识。",
            ));
        }
        let approved_payload_sha256 = sha256_hex(&approved_payload);
        let indexed_hash = connection
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
                    "最终批准代哈希索引无法读取。",
                )
            })?
            .flatten()
            .ok_or_else(|| {
                PrivacyWorkflowError::new("redaction_not_approved", "最终批准代没有获批哈希索引。")
            })?;
        if indexed_hash != approved_payload_sha256 {
            return Err(PrivacyWorkflowError::new(
                "redaction_stale",
                "受保护批准代与获批哈希索引不一致。",
            ));
        }

        let destination = request.format.destination();
        let purpose = request.format.purpose().to_owned();
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| PrivacyWorkflowError::new("clock_invalid", "本机时钟超出数据库范围。"))?;
        let destination_identifier_sha256 = sha256_hex(destination.identifier.as_bytes());
        let selected = connection
            .query_row(
                "SELECT signed_token,receipt_id FROM privacy_receipts
                 WHERE redaction_id=?1
                   AND destination_kind='verified_local_provider'
                   AND destination_identifier_sha256=?2
                   AND purpose=?3 AND payload_sha256=?4
                   AND revoked_at_unix IS NULL AND expires_at_unix>?5
                 ORDER BY issued_at_unix DESC,receipt_id DESC LIMIT 1",
                params![
                    &request.redaction_id,
                    &destination_identifier_sha256,
                    &purpose,
                    &approved_payload_sha256,
                    now_i64,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "活动本机导出回执无法读取。",
                )
            })?
            .ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "redaction_receipt_invalid",
                    "未找到与所选格式精确绑定的活动本机导出回执；请重新批准该格式。",
                )
            })?;
        let token_bytes = unprotect_local(&selected.0).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_store_protected_blob_error",
                "活动本机导出回执无法解密。",
            )
        })?;
        if token_bytes.len() > MAX_RECEIPT_TOKEN_BYTES {
            return Err(PrivacyWorkflowError::new(
                "redaction_receipt_invalid",
                "活动本机导出回执大小无效。",
            ));
        }
        let receipt_token = String::from_utf8(token_bytes).map_err(|_| {
            PrivacyWorkflowError::new("redaction_receipt_invalid", "活动本机导出回执编码无效。")
        })?;
        let receipt = PrivacyStore::verify_active_receipt_token(
            connection,
            signer,
            &ActiveReceiptVerification {
                redaction_id: &request.redaction_id,
                signed_token: &receipt_token,
                approved_payload: &approved_payload,
                destination: &destination,
                purpose: &purpose,
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        )
        .map_err(|error| {
            PrivacyWorkflowError::new(
                error.code(),
                "活动本机导出回执未通过持久化、撤销、载荷、目标、用途或有效期复核。",
            )
        })?;
        if receipt.claims.receipt_id != selected.1 {
            return Err(PrivacyWorkflowError::new(
                "redaction_receipt_invalid",
                "活动本机导出回执身份与索引不一致。",
            ));
        }
        let pages = approved_pages
            .into_iter()
            .map(|page| ApprovedTextPage {
                page_number: page.page_number,
                text: page.text,
            })
            .collect::<Vec<_>>();
        let approved_text_hash = approved_text_sha256(&pages).map_err(derived_export_error)?;
        let approved_payload_json = String::from_utf8(approved_payload).map_err(|_| {
            PrivacyWorkflowError::new("canonicalization_failed", "最终批准代不是 UTF-8。")
        })?;
        Ok((
            RestoredSafeExportAuthorization {
                redaction_id: request.redaction_id.clone(),
                format: request.format,
                destination,
                purpose,
                approved_payload_json,
                approved_payload_sha256,
                receipt_token,
                receipt_id: receipt.claims.receipt_id,
            },
            SafePdfExportRequest {
                approved_text_sha256: approved_text_hash,
                pages,
                forbidden_canaries: stored.forbidden_canaries,
            },
        ))
    }
}

fn verify_authorization(
    connection: &Connection,
    signer: &privacy::ReceiptSigner,
    now_unix: u64,
    authorization: &RestoredSafeExportAuthorization,
) -> Result<(), PrivacyWorkflowError> {
    if !authorization
        .format
        .matches_scope(&authorization.destination, &authorization.purpose)
        || authorization.approved_payload_sha256
            != sha256_hex(authorization.approved_payload_json.as_bytes())
    {
        return Err(PrivacyWorkflowError::new(
            "invalid_safe_export_request",
            "安全导出的持久化授权绑定无效。",
        ));
    }
    PrivacyStore::verify_active_receipt_token(
        connection,
        signer,
        &ActiveReceiptVerification {
            redaction_id: &authorization.redaction_id,
            signed_token: &authorization.receipt_token,
            approved_payload: authorization.approved_payload_json.as_bytes(),
            destination: &authorization.destination,
            purpose: &authorization.purpose,
            now_unix,
            expected_key_version: RECEIPT_KEY_VERSION,
        },
    )
    .map_err(|error| {
        PrivacyWorkflowError::new(error.code(), "安全导出回执未通过最终活动状态复核。")
    })?;
    Ok(())
}

fn validate_export_request(
    request: &ExportApprovedPrivacyReviewRequest,
) -> Result<(), PrivacyWorkflowError> {
    if !valid_identifier(&request.redaction_id) {
        return Err(PrivacyWorkflowError::new(
            "invalid_safe_export_request",
            "安全导出请求的脱敏记录标识无效。",
        ));
    }
    Ok(())
}

fn validate_built_export(built: &BuiltSafeExport) -> Result<(), PrivacyWorkflowError> {
    if built.bytes.is_empty()
        || built.bytes.len() > SafePdfExportLimits::default().max_output_bytes
        || !valid_hash(&built.artifact_sha256)
        || !valid_hash(&built.approved_text_sha256)
        || !valid_hash(&built.reopened_text_sha256)
        || built.file_extension != built.format.file_extension()
        || built.media_type != built.format.media_type()
        || built.authorization.format != built.format
        || !built.format.matches_scope(
            &built.authorization.destination,
            &built.authorization.purpose,
        )
        || sha256_hex(&built.bytes) != built.artifact_sha256
    {
        return Err(PrivacyWorkflowError::new(
            "invalid_safe_export_artifact",
            "安全导出产物证据无效。",
        ));
    }
    Ok(())
}

fn build_artifact(
    format: SafeExportFormat,
    request: &SafePdfExportRequest,
) -> Result<BuiltArtifactCore, PrivacyWorkflowError> {
    let limits = SafePdfExportLimits::default();
    if format == SafeExportFormat::Pdf {
        let artifact =
            reconstruct_approved_text_pdf(request, limits).map_err(derived_export_error)?;
        let source_page_count = u32::try_from(request.pages.len())
            .map_err(|_| PrivacyWorkflowError::new("safe_export_failed", "安全导出源页数超限。"))?;
        return Ok(BuiltArtifactCore {
            media_type: artifact.media_type,
            bytes: artifact.bytes,
            artifact_sha256: artifact.sha256,
            approved_text_sha256: artifact.approved_text_sha256,
            reopened_text_sha256: artifact.extracted_text_sha256,
            source_page_count,
            output_page_count: artifact.output_page_count,
        });
    }
    let derived = match format {
        SafeExportFormat::Txt => reconstruct_approved_text_txt(request, limits),
        SafeExportFormat::Markdown => reconstruct_approved_text_markdown(request, limits),
        SafeExportFormat::Docx => reconstruct_approved_text_docx(request, limits),
        SafeExportFormat::Pdf => unreachable!("PDF handled above"),
    }
    .map_err(derived_export_error)?;
    Ok(BuiltArtifactCore {
        media_type: derived.evidence.media_type,
        bytes: derived.bytes,
        artifact_sha256: derived.evidence.artifact_sha256,
        approved_text_sha256: derived.evidence.approved_text_sha256,
        reopened_text_sha256: derived.evidence.reopened_text_sha256,
        source_page_count: derived.evidence.source_page_count,
        output_page_count: derived.evidence.source_page_count,
    })
}

fn verify_artifact_bytes(
    format: SafeExportFormat,
    bytes: &[u8],
    request: &SafePdfExportRequest,
    expected: &BuiltArtifactCore,
) -> Result<(), PrivacyWorkflowError> {
    let limits = SafePdfExportLimits::default();
    let (
        media_type,
        artifact_sha256,
        approved_text_hash,
        reopened_hash,
        source_count,
        output_count,
    ) = if format == SafeExportFormat::Pdf {
        let verified =
            verify_approved_text_pdf_bytes(bytes, request, limits).map_err(derived_export_error)?;
        (
            verified.media_type,
            verified.sha256,
            verified.approved_text_sha256,
            verified.extracted_text_sha256,
            u32::try_from(request.pages.len()).map_err(|_| {
                PrivacyWorkflowError::new("safe_export_failed", "安全导出源页数超限。")
            })?,
            verified.output_page_count,
        )
    } else {
        let verified = verify_approved_text_derived_bytes(
            format.derived().expect("derived format"),
            bytes,
            request,
            limits,
        )
        .map_err(derived_export_error)?;
        (
            verified.media_type,
            verified.artifact_sha256,
            verified.approved_text_sha256,
            verified.reopened_text_sha256,
            verified.source_page_count,
            verified.source_page_count,
        )
    };
    if media_type != expected.media_type
        || artifact_sha256 != expected.artifact_sha256
        || approved_text_hash != expected.approved_text_sha256
        || reopened_hash != expected.reopened_text_sha256
        || source_count != expected.source_page_count
        || output_count != expected.output_page_count
    {
        return Err(PrivacyWorkflowError::new(
            "export_verify_failed",
            "安全导出文件安装后重读证据与构建证据不一致。",
        ));
    }
    Ok(())
}

pub(crate) fn preflight_safe_export_delivery(
    format: SafeExportFormat,
    pages: &[CanonicalRedactedPage],
    forbidden_canaries: &[String],
) -> Result<(), PrivacyWorkflowError> {
    let pages = pages
        .iter()
        .map(|page| ApprovedTextPage {
            page_number: page.page_number,
            text: page.text.clone(),
        })
        .collect::<Vec<_>>();
    let approved_text_hash = approved_text_sha256(&pages).map_err(derived_export_error)?;
    build_artifact(
        format,
        &SafePdfExportRequest {
            approved_text_sha256: approved_text_hash,
            pages,
            forbidden_canaries: forbidden_canaries.to_vec(),
        },
    )?;
    Ok(())
}

#[must_use]
pub fn export_reason(format: SafeExportFormat, outcome: &str) -> String {
    format!("local_safe_{}_export_{}", format.code(), outcome)
}

fn derived_export_error(_error: material_processing::SafePdfExportError) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "safe_export_failed",
        "安全派生文书重建或严格重读复检失败；未返回可保存文件。",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig};
    use crate::privacy_workflow::{
        ApplyPrivacyRiskReviewActionRequest, ApprovePrivacyReviewRequest, EditedRedactedPage,
        ReceiptDestinationInput,
    };
    use privacy::{ReceiptSigner, ReviewActionV1};
    use std::fs;

    fn synthetic_request() -> SafePdfExportRequest {
        let pages = vec![
            ApprovedTextPage {
                page_number: 1,
                text: "原告：[姓名1]\n请求依法处理。".to_owned(),
            },
            ApprovedTextPage {
                page_number: 2,
                text: "证据编号：[敏感信息1]".to_owned(),
            },
        ];
        SafePdfExportRequest {
            approved_text_sha256: approved_text_sha256(&pages).expect("approved hash"),
            pages,
            forbidden_canaries: vec!["SYNTHETIC-SOURCE-CANARY-9Q7X".to_owned()],
        }
    }

    #[test]
    fn every_format_has_a_unique_fixed_scope_and_extension() {
        let mut identifiers = std::collections::BTreeSet::new();
        let mut purposes = std::collections::BTreeSet::new();
        for format in SafeExportFormat::ALL {
            assert!(identifiers.insert(format.destination_identifier()));
            assert!(purposes.insert(format.purpose()));
            let destination = format.destination();
            assert_eq!(
                SafeExportFormat::from_scope(&destination, format.purpose()),
                Some(format)
            );
            assert_eq!(
                format.default_file_name().split('.').next(),
                Some("已脱敏材料")
            );
        }
    }

    #[test]
    fn ipc_request_rejects_frontend_receipts_payloads_and_destinations() {
        let value = serde_json::json!({
            "redactionId": "red_1",
            "format": "docx",
        });
        let request: ExportApprovedPrivacyReviewRequest =
            serde_json::from_value(value).expect("minimal request");
        assert_eq!(request.format, SafeExportFormat::Docx);
        for forbidden_field in [
            ("receiptToken", serde_json::json!("rct_v1.secret")),
            ("approvedPayloadJson", serde_json::json!("{}")),
            ("purpose", serde_json::json!("attacker_selected")),
            ("destination", serde_json::json!({"identifier":"attacker"})),
            ("path", serde_json::json!("C:/case/raw.pdf")),
        ] {
            let mut tampered = serde_json::json!({
                "redactionId": "red_1",
                "format": "pdf",
            });
            tampered[forbidden_field.0] = forbidden_field.1;
            assert!(
                serde_json::from_value::<ExportApprovedPrivacyReviewRequest>(tampered).is_err()
            );
        }
    }

    #[test]
    fn every_format_is_reopened_and_tampering_fails() {
        let request = synthetic_request();
        for format in SafeExportFormat::ALL {
            let built = build_artifact(format, &request).expect("build synthetic artifact");
            verify_artifact_bytes(format, &built.bytes, &request, &built)
                .expect("strict reopen succeeds");
            let mut tampered = built.bytes.clone();
            tampered.push(b'X');
            assert!(verify_artifact_bytes(format, &tampered, &request, &built).is_err());
        }
    }

    fn local_ocr_status() -> LocalOcrStatus {
        LocalOcrStatus {
            code: LocalOcrStatusCode::Disabled,
            message: "synthetic-test".to_owned(),
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

    #[test]
    fn restart_restores_all_approved_formats_and_active_receipts_without_frontend_secrets() {
        const RESTART_SAFE_NOW: u64 = 4_000_000_000;
        let directory = tempfile::tempdir().expect("temp privacy directory");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            crate::privacy_workflow::test_workspace_instance_id(),
        )
        .expect("privacy workflow manager");
        let signer = ReceiptSigner::new([23_u8; 32]).expect("test signer");
        manager.set_test_runtime(signer.clone(), RESTART_SAFE_NOW);
        let source_directory = tempfile::tempdir().expect("synthetic source directory");
        let mut approvals = Vec::new();
        for (index, format) in SafeExportFormat::ALL.into_iter().enumerate() {
            let source_path = source_directory
                .path()
                .join(format!("synthetic-safe-export-{}.txt", format.code()));
            fs::write(&source_path, "原告：张三，联系电话13800138000。")
                .expect("write synthetic case source");
            let review = manager
                .prepare_selected_material(
                    &source_path,
                    &PrivacyConfig::default(),
                    &local_ocr_status(),
                    None,
                    Some(format!("case_{:032x}", index + 100)),
                    Vec::new(),
                )
                .expect("prepare Vault-bound synthetic material");
            let edited_pages = review
                .pages
                .iter()
                .map(|page| EditedRedactedPage {
                    page_number: page.page_number,
                    redacted_text: format!("{}\n人工复核完成。", page.redacted_text),
                })
                .collect::<Vec<_>>();
            let finding_ids = review
                .risk_review
                .as_ref()
                .expect("initial risk revision")
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            let mut reviewed = review.clone();
            for finding_id in finding_ids {
                let revision = reviewed
                    .risk_review
                    .as_ref()
                    .expect("current finding revision")
                    .revision;
                reviewed = manager
                    .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                        redaction_id: reviewed.redaction_id.clone(),
                        expected_revision: revision,
                        actor: "synthetic-reviewer".to_owned(),
                        edited_pages: edited_pages.clone(),
                        action: ReviewActionV1::AcceptReplacement {
                            finding_id,
                            apply_cluster: false,
                        },
                    })
                    .expect("accept detected replacement");
            }
            let revision = reviewed
                .risk_review
                .as_ref()
                .expect("resolved finding revision")
                .revision;
            let reviewed = manager
                .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                    redaction_id: reviewed.redaction_id.clone(),
                    expected_revision: revision,
                    actor: "synthetic-reviewer".to_owned(),
                    edited_pages: edited_pages.clone(),
                    action: ReviewActionV1::ConfirmEditedOutput,
                })
                .expect("confirm edited output");
            let risk = reviewed
                .risk_review
                .as_ref()
                .expect("confirmed risk revision");
            let approval = manager
                .approve_review(ApprovePrivacyReviewRequest {
                    redaction_id: reviewed.redaction_id.clone(),
                    expected_risk_revision: Some(risk.revision),
                    expected_suggested_redacted_sha256: reviewed
                        .suggested_redacted_content_sha256
                        .clone(),
                    edited_pages,
                    reviewer: "synthetic-reviewer".to_owned(),
                    destination: ReceiptDestinationInput {
                        kind: DestinationKind::VerifiedLocalProvider,
                        identifier: format.destination_identifier().to_owned(),
                    },
                    purpose: format.purpose().to_owned(),
                    ttl_seconds: 3_600,
                })
                .unwrap_or_else(|error| panic!("approve {} destination: {error}", format.code()));
            approvals.push((format, reviewed.redaction_id, approval));
        }
        drop(manager);

        let restarted = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            crate::privacy_workflow::test_workspace_instance_id(),
        )
        .expect("restart workflow manager");
        restarted.set_test_runtime(signer, RESTART_SAFE_NOW);
        for (format, redaction_id, approval) in approvals {
            let request = ExportApprovedPrivacyReviewRequest {
                redaction_id,
                format,
            };
            let serialized = serde_json::to_string(&request).expect("serialize request");
            assert!(!serialized.contains(&approval.receipt_token));
            assert!(!serialized.contains(&approval.approved_payload_json));
            assert!(!serialized.contains(format.destination_identifier()));
            assert!(!serialized.contains(format.purpose()));

            let built = restarted
                .build_safe_export(&request)
                .unwrap_or_else(|error| panic!("restore and build {}: {error}", format.code()));
            let debug = format!("{built:?}");
            assert!(debug.contains("[REDACTED]"));
            for secret in [
                approval.receipt_token.as_str(),
                approval.approved_payload_json.as_str(),
            ] {
                assert!(!debug.contains(secret));
            }
            assert_eq!(built.format, format);
            assert_eq!(built.media_type, format.media_type());
            assert_eq!(built.file_extension, format.file_extension());
            assert_eq!(built.authorization.receipt_id, approval.receipt_id);
            assert_eq!(built.authorization.destination, format.destination());
            assert_eq!(built.authorization.purpose, format.purpose());
            restarted
                .verify_safe_export_authorization(&built)
                .unwrap_or_else(|error| panic!("verify {} authorization: {error}", format.code()));
            restarted
                .verify_installed_safe_export(&built, &built.bytes)
                .unwrap_or_else(|error| panic!("strictly reopen {}: {error}", format.code()));
            restarted
                .record_safe_export_cancellation(&request)
                .unwrap_or_else(|error| panic!("audit {} cancellation: {error}", format.code()));

            let connection = restarted.open_connection().expect("open audit database");
            let reason = export_reason(format, "cancelled");
            let count = connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_egress_audit
                     WHERE receipt_id=?1 AND reason_code=?2",
                    rusqlite::params![approval.receipt_id, reason],
                    |row| row.get::<_, u32>(0),
                )
                .expect("query cancellation audit");
            assert_eq!(count, 1, "missing {} cancellation audit", format.code());
        }
    }
}
