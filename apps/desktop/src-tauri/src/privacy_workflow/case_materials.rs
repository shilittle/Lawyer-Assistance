use super::{
    project_deletion, valid_identifier, validate_loaded_review, validate_vault_isolation,
    ApplyPrivacyRiskReviewActionRequest, ApprovePrivacyReviewRequest, ApprovePrivacyReviewResponse,
    DeletePrivacyReviewRequest, DeletePrivacyReviewResponse, EditedRedactedPage,
    ExportApprovedPrivacyReviewRequest, PrivacyReviewView, PrivacyRiskReviewRevisionRequest,
    PrivacyWorkflowError, PrivacyWorkflowManager, ReceiptDestinationInput, ReviewPageView,
    SafeExportFormat, StoredReviewPayload,
};
use material_processing::{BackendTrace, InputTransformTrace};
use privacy::vnext::{DocumentRiskV1, MaterialId};
use privacy::{
    sha256_hex, unprotect_local, BindingCreationSource, BindingLifecycleContext, HardGateViewV1,
    PrivacyCaseId, PrivacyFindingViewV1, PrivacyStore, ProjectId, ProjectPrivacyCaseBindingStore,
    RedactionSummary, ResidualSummaryViewV1, ReviewActionV1, ReviewStateViewV1,
    VisualRiskResolutionV1, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(test)]
#[path = "case_materials_tests.rs"]
mod tests;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareCaseMaterialRequest {
    pub project_id: String,
    #[serde(default)]
    pub custom_terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCaseMaterialResponse {
    pub cancelled: bool,
    pub review: Option<CaseRedactionReviewView>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListCaseMaterialsRequest {
    pub project_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListUnassignedCaseMaterialsRequest {
    pub project_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignUnassignedCaseMaterialRequest {
    pub project_id: String,
    pub material_id: String,
    pub expected_row_version: u64,
    pub actor: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListCaseRedactionGenerationsRequest {
    pub project_id: String,
    pub material_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadCaseRedactionReviewRequest {
    pub project_id: String,
    pub redaction_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyCaseRedactionRiskReviewActionRequest {
    pub project_id: String,
    pub redaction_id: String,
    pub expected_revision: u64,
    pub actor: String,
    pub edited_pages: Vec<EditedRedactedPage>,
    pub action: ReviewActionV1,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseRedactionRiskReviewRevisionRequest {
    pub project_id: String,
    pub redaction_id: String,
    pub expected_revision: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveCaseRedactionReviewRequest {
    pub project_id: String,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteCaseRedactionReviewRequest {
    pub project_id: String,
    pub redaction_id: String,
    pub expected_source_sha256: String,
    pub expected_extraction_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportApprovedCaseRedactionRequest {
    pub project_id: String,
    pub redaction_id: String,
    pub format: SafeExportFormat,
}

impl ExportApprovedCaseRedactionRequest {
    pub fn legacy_request(&self) -> ExportApprovedPrivacyReviewRequest {
        ExportApprovedPrivacyReviewRequest {
            redaction_id: self.redaction_id.clone(),
            format: self.format,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaseMaterialSummary {
    pub project_id: String,
    pub material_id: String,
    pub display_name: String,
    pub media_type: Option<String>,
    pub source_kind: String,
    pub extraction_status: String,
    pub migration_status: String,
    pub state: String,
    pub latest_review_state: Option<String>,
    pub latest_generation_status: Option<String>,
    pub latest_revocation_state: Option<String>,
    pub generation_count: u64,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnassignedCaseMaterialSummary {
    pub material_id: String,
    pub display_name: String,
    pub media_type: Option<String>,
    pub source_kind: String,
    pub extraction_status: String,
    pub migration_status: String,
    pub state: String,
    pub generation_count: u64,
    pub historical_identity: String,
    pub assignable: bool,
    pub row_version: u64,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssignUnassignedCaseMaterialResponse {
    pub assignment_id: String,
    pub project_id: String,
    pub material_id: String,
    pub assignment_mode: String,
    pub binding_action: String,
    pub material_row_version: u64,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaseRedactionGenerationSummary {
    pub project_id: String,
    pub material_id: String,
    pub redaction_id: String,
    pub generation_number: u64,
    pub generation_status: String,
    pub review_state: String,
    pub risk_revision: u64,
    pub approved_payload_sha256: Option<String>,
    pub approved_at: Option<String>,
    pub revocation_state: String,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRedactionRiskReviewView {
    pub schema_version: String,
    pub redaction_id: String,
    pub project_id: String,
    pub material_id: String,
    pub document_version: u64,
    pub detector_run_completed: bool,
    pub revision: u64,
    pub document_risk: DocumentRiskV1,
    pub hard_gates: Vec<HardGateViewV1>,
    pub findings: Vec<PrivacyFindingViewV1>,
    pub residual_scan: ResidualSummaryViewV1,
    pub visual_risk_resolutions: Vec<VisualRiskResolutionV1>,
    pub can_undo: bool,
    pub can_redo: bool,
    pub rejected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRedactionReviewView {
    pub project_id: String,
    pub generation_number: u64,
    pub redaction_id: String,
    pub material_id: String,
    pub vault_object_id: Option<String>,
    pub vault_object_version: Option<u64>,
    pub vault_isolation: Option<privacy::vault_store::VaultIsolationStatusV1>,
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
    pub risk_review: Option<CaseRedactionRiskReviewView>,
}

#[derive(Debug)]
pub(super) struct CaseRedactionScope {
    project_id: ProjectId,
    material_id: MaterialId,
    generation_number: u64,
    privacy_case_id: PrivacyCaseId,
}

#[derive(Debug)]
pub(super) struct CaseRedactionAuthorization {
    pub(super) project_id: ProjectId,
    redaction_id: String,
}

#[derive(Debug)]
struct PersistedCaseRedactionScope {
    material_id: String,
    project_id: Option<String>,
    source_kind: String,
    migration_status: String,
    material_state: String,
    deleted_at: Option<String>,
    attachment_id: Option<String>,
    source_sha256: Option<String>,
    media_type: Option<String>,
    page_count: Option<i64>,
    generation_number: i64,
    generation_status: String,
    review_state: String,
    revocation_state: String,
    revoked_at: Option<String>,
    vault_case_id: Option<String>,
    vault_object_id: Option<String>,
    vault_object_version: Option<i64>,
    vault_source_sha256: Option<String>,
    vault_import_state: Option<String>,
    vault_failure_code: Option<String>,
}

pub(super) struct CaseProjectReadGuard {
    connection: Connection,
    active: bool,
}

impl CaseProjectReadGuard {
    pub(super) fn commit(mut self) -> Result<(), PrivacyWorkflowError> {
        self.connection
            .execute_batch("COMMIT")
            .map_err(|_| case_project_read_guard_error())?;
        self.active = false;
        Ok(())
    }

    pub(super) fn rollback(mut self) {
        let _ = self.connection.execute_batch("ROLLBACK");
        self.active = false;
    }
}

impl Drop for CaseProjectReadGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.connection.execute_batch("ROLLBACK");
        }
    }
}

pub(super) fn initialize_assignment_schema(
    connection: &mut Connection,
) -> Result<(), PrivacyWorkflowError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| case_material_assignment_store_error())?;
    privacy::initialize_case_material_assignment_schema(&transaction)
        .map_err(PrivacyWorkflowError::store)?;
    validate_assignment_schema(&transaction)?;
    transaction
        .commit()
        .map_err(|_| case_material_assignment_store_error())
}

fn validate_assignment_schema(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    let schema_version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key=?1",
            [privacy::CASE_MATERIAL_ASSIGNMENT_SCHEMA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| case_material_assignment_store_error())?;
    if schema_version.as_deref() != Some(privacy::CASE_MATERIAL_ASSIGNMENT_SCHEMA_VERSION) {
        return Err(case_material_assignment_store_error());
    }
    let object_count = connection
        .query_row(
            "SELECT COUNT(*)
             FROM sqlite_master
             WHERE (type='table' AND name='case_material_assignment_audit')
                OR (
                    type='trigger'
                    AND name IN (
                        'trg_case_material_assignment_audit_no_update',
                        'trg_case_material_assignment_audit_no_delete',
                        'trg_case_material_assignment_audit_no_replace',
                        'trg_case_material_assignment_audit_scope_match'
                    )
                )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| case_material_assignment_store_error())?;
    if object_count != 5 {
        return Err(case_material_assignment_store_error());
    }
    for (name, canonical_sql) in [
        (
            "trg_case_material_assignment_audit_no_update",
            privacy::ASSIGNMENT_AUDIT_NO_UPDATE_TRIGGER_SQL,
        ),
        (
            "trg_case_material_assignment_audit_no_delete",
            privacy::ASSIGNMENT_AUDIT_NO_DELETE_TRIGGER_SQL,
        ),
        (
            "trg_case_material_assignment_audit_no_replace",
            privacy::ASSIGNMENT_AUDIT_NO_REPLACE_TRIGGER_SQL,
        ),
        (
            "trg_case_material_assignment_audit_scope_match",
            privacy::ASSIGNMENT_AUDIT_SCOPE_MATCH_TRIGGER_SQL,
        ),
    ] {
        let stored_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| case_material_assignment_store_error())?;
        if normalize_assignment_schema_sql(&stored_sql)
            != normalize_assignment_schema_sql(canonical_sql)
        {
            return Err(case_material_assignment_store_error());
        }
    }
    validate_assignment_audit_chain(connection)
}

fn normalize_assignment_schema_sql(sql: &str) -> String {
    let normalized = sql
        .trim()
        .trim_end_matches(';')
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    normalized
        .strip_prefix("create trigger if not exists ")
        .map_or(normalized.clone(), |suffix| {
            format!("create trigger {suffix}")
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentAuditCanonical<'a> {
    assignment_id: &'a str,
    material_id: &'a str,
    project_id: &'a str,
    privacy_case_id: &'a str,
    assignment_mode: &'a str,
    binding_action: &'a str,
    actor_sha256: &'a str,
    expected_material_row_version: u64,
    assigned_material_row_version: u64,
    previous_migration_status: &'a str,
    previous_state: &'a str,
    result: &'static str,
}

#[derive(Debug)]
struct StoredAssignmentAudit {
    assignment_id: String,
    material_id: String,
    project_id: String,
    privacy_case_id: String,
    assignment_mode: String,
    binding_action: String,
    assigned_material_row_version: u64,
}

fn assignment_audit_hash(
    audit: &AssignmentAuditCanonical<'_>,
    previous_event_hash: &str,
) -> Result<String, PrivacyWorkflowError> {
    let canonical =
        serde_json::to_vec(audit).map_err(|_| case_material_assignment_store_error())?;
    let mut chained = Vec::with_capacity(previous_event_hash.len() + canonical.len() + 1);
    chained.extend_from_slice(previous_event_hash.as_bytes());
    chained.push(0);
    chained.extend_from_slice(&canonical);
    Ok(sha256_hex(&chained))
}

fn validate_assignment_audit_chain(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT assignment_id,material_id,project_id,privacy_case_id,
                    assignment_mode,binding_action,actor_sha256,
                    expected_material_row_version,assigned_material_row_version,
                    previous_migration_status,previous_state,previous_event_hash,event_hash
             FROM case_material_assignment_audit
             ORDER BY rowid ASC",
        )
        .map_err(|_| case_material_assignment_store_error())?;
    let rows = statement
        .query_map([], |row| {
            let expected = row.get::<_, i64>(7)?;
            let assigned = row.get::<_, i64>(8)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                expected,
                assigned,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
            ))
        })
        .map_err(|_| case_material_assignment_store_error())?;
    let mut previous = String::new();
    for row in rows {
        let (
            assignment_id,
            material_id,
            project_id,
            privacy_case_id,
            assignment_mode,
            binding_action,
            actor_sha256,
            expected,
            assigned,
            previous_migration_status,
            previous_state,
            stored_previous_hash,
            event_hash,
        ) = row.map_err(|_| case_material_assignment_store_error())?;
        let expected =
            u64::try_from(expected).map_err(|_| case_material_assignment_store_error())?;
        let assigned =
            u64::try_from(assigned).map_err(|_| case_material_assignment_store_error())?;
        let audit = AssignmentAuditCanonical {
            assignment_id: &assignment_id,
            material_id: &material_id,
            project_id: &project_id,
            privacy_case_id: &privacy_case_id,
            assignment_mode: &assignment_mode,
            binding_action: &binding_action,
            actor_sha256: &actor_sha256,
            expected_material_row_version: expected,
            assigned_material_row_version: assigned,
            previous_migration_status: &previous_migration_status,
            previous_state: &previous_state,
            result: "assigned",
        };
        if ProjectId::parse(project_id.as_str()).is_err()
            || MaterialId::parse(material_id.as_str()).is_err()
            || PrivacyCaseId::parse(privacy_case_id.as_str()).is_err()
            || !matches!(
                assignment_mode.as_str(),
                "initialize_null_case" | "preserve_historical_case"
            )
            || !matches!(binding_action.as_str(), "created" | "reused")
            || !is_lower_hex_hash(&actor_sha256)
            || previous_migration_status != "unassigned"
            || assigned != expected.saturating_add(1)
            || stored_previous_hash != previous
            || assignment_audit_hash(&audit, &previous)? != event_hash
            || !assignment_audit_scope_is_valid(
                connection,
                &material_id,
                &project_id,
                &privacy_case_id,
            )?
        {
            return Err(case_material_assignment_store_error());
        }
        previous = event_hash;
    }
    Ok(())
}

fn assignment_audit_scope_is_valid(
    connection: &Connection,
    material_id: &str,
    project_id: &str,
    privacy_case_id: &str,
) -> Result<bool, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT
                NOT EXISTS(
                    SELECT 1 FROM privacy_materials WHERE material_id=?1
                )
                OR (
                    EXISTS(
                        SELECT 1
                        FROM privacy_materials
                        WHERE material_id=?1 AND project_id=?2
                    )
                    AND EXISTS(
                        SELECT 1
                        FROM project_privacy_case_bindings
                        WHERE project_id=?2 AND privacy_case_id=?3
                    )
                )",
            params![material_id, project_id, privacy_case_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| case_material_assignment_store_error())
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl PrivacyWorkflowManager {
    pub fn list_case_materials(
        &self,
        request: ListCaseMaterialsRequest,
    ) -> Result<Vec<CaseMaterialSummary>, PrivacyWorkflowError> {
        self.list_case_materials_with_hook(request, || {})
    }

    #[cfg(test)]
    pub(super) fn list_case_materials_with_test_hook<F>(
        &self,
        request: ListCaseMaterialsRequest,
        after_project_guard: F,
    ) -> Result<Vec<CaseMaterialSummary>, PrivacyWorkflowError>
    where
        F: FnOnce(),
    {
        self.list_case_materials_with_hook(request, after_project_guard)
    }

    fn list_case_materials_with_hook<F>(
        &self,
        request: ListCaseMaterialsRequest,
        after_project_guard: F,
    ) -> Result<Vec<CaseMaterialSummary>, PrivacyWorkflowError>
    where
        F: FnOnce(),
    {
        let project_id = self.parse_project_id(request.project_id)?;
        let _gate = self.gate();
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        after_project_guard();
        let connection = self.open_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT
                    material.material_id,
                    material.protected_display_name,
                    material.display_name_sha256,
                    material.display_name_protection_scheme,
                    material.media_type,
                    material.source_kind,
                    material.extraction_status,
                    material.migration_status,
                    material.state,
                    (
                        SELECT generation.review_state
                        FROM privacy_redactions AS generation
                        WHERE generation.material_id=material.material_id
                        ORDER BY generation.generation_number DESC
                        LIMIT 1
                    ),
                    (
                        SELECT generation.generation_status
                        FROM privacy_redactions AS generation
                        WHERE generation.material_id=material.material_id
                        ORDER BY generation.generation_number DESC
                        LIMIT 1
                    ),
                    (
                        SELECT generation.revocation_state
                        FROM privacy_redactions AS generation
                        WHERE generation.material_id=material.material_id
                        ORDER BY generation.generation_number DESC
                        LIMIT 1
                    ),
                    (
                        SELECT COUNT(*)
                        FROM privacy_redactions AS generation
                        WHERE generation.material_id=material.material_id
                    ),
                    material.updated_at,
                    material.deleted_at,
                    vault.case_id
                 FROM privacy_materials AS material
                 LEFT JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.project_id=?1
                 ORDER BY material.updated_at DESC,material.material_id ASC",
            )
            .map_err(|_| case_material_store_error())?;
        let mut rows = statement
            .query([project_id.as_str()])
            .map_err(|_| case_material_store_error())?;
        let mut materials = Vec::new();
        while let Some(row) = rows.next().map_err(|_| case_material_store_error())? {
            let material_id = row
                .get::<_, String>(0)
                .map_err(|_| case_material_store_error())?;
            let protected_display_name = row
                .get::<_, Option<Vec<u8>>>(1)
                .map_err(|_| case_material_store_error())?;
            let display_name_sha256 = row
                .get::<_, Option<String>>(2)
                .map_err(|_| case_material_store_error())?;
            let display_name_scheme = row
                .get::<_, Option<String>>(3)
                .map_err(|_| case_material_store_error())?;
            let media_type = row
                .get::<_, Option<String>>(4)
                .map_err(|_| case_material_store_error())?;
            let source_kind = row
                .get::<_, String>(5)
                .map_err(|_| case_material_store_error())?;
            let extraction_status = row
                .get::<_, String>(6)
                .map_err(|_| case_material_store_error())?;
            let migration_status = row
                .get::<_, String>(7)
                .map_err(|_| case_material_store_error())?;
            let state = row
                .get::<_, String>(8)
                .map_err(|_| case_material_store_error())?;
            let latest_review_state = row
                .get::<_, Option<String>>(9)
                .map_err(|_| case_material_store_error())?;
            let latest_generation_status = row
                .get::<_, Option<String>>(10)
                .map_err(|_| case_material_store_error())?;
            let latest_revocation_state = row
                .get::<_, Option<String>>(11)
                .map_err(|_| case_material_store_error())?;
            let generation_count = row
                .get::<_, i64>(12)
                .ok()
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(case_material_store_error)?;
            let updated_at = row
                .get::<_, String>(13)
                .map_err(|_| case_material_store_error())?;
            let deleted_at = row
                .get::<_, Option<String>>(14)
                .map_err(|_| case_material_store_error())?;
            let vault_case_id = row
                .get::<_, Option<String>>(15)
                .map_err(|_| case_material_store_error())?;

            if source_kind == "vault" && migration_status == "ready" && deleted_at.is_none() {
                let privacy_case_id = PrivacyCaseId::parse(vault_case_id.ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "case_material_vault_binding_invalid",
                        "案件材料缺少可验证的 Vault 身份绑定。",
                    )
                })?)
                .map_err(super::PrivacyWorkflowError::project_case_binding)?;
                ProjectPrivacyCaseBindingStore::validate_pair(
                    &connection,
                    &project_id,
                    &privacy_case_id,
                )
                .map_err(super::PrivacyWorkflowError::project_case_binding)?;
            }
            let display_name = decode_display_name(
                protected_display_name,
                display_name_sha256,
                display_name_scheme,
                &migration_status,
            )?;
            materials.push(CaseMaterialSummary {
                project_id: project_id.as_str().to_owned(),
                material_id,
                display_name,
                media_type,
                source_kind,
                extraction_status,
                migration_status,
                state,
                latest_review_state,
                latest_generation_status,
                latest_revocation_state,
                generation_count,
                updated_at,
                deleted_at,
            });
        }
        drop(rows);
        drop(statement);
        project_guard.commit()?;
        Ok(materials)
    }

    pub fn list_unassigned_case_materials(
        &self,
        request: ListUnassignedCaseMaterialsRequest,
    ) -> Result<Vec<UnassignedCaseMaterialSummary>, PrivacyWorkflowError> {
        let project_id = self.parse_project_id(request.project_id)?;
        let _gate = self.gate();
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        let connection = self.open_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT material.material_id,material.protected_display_name,
                        material.display_name_sha256,
                        material.display_name_protection_scheme,material.media_type,
                        material.source_kind,material.extraction_status,
                        material.migration_status,material.state,
                        (SELECT COUNT(*) FROM privacy_redactions AS generation
                         WHERE generation.material_id=material.material_id),
                        CASE
                          WHEN material.legacy_case_id IS NOT NULL
                            OR vault.case_id IS NOT NULL
                          THEN 'preserved'
                          ELSE 'missing'
                        END,
                        material.row_version,material.updated_at,material.deleted_at
                 FROM privacy_materials AS material
                 LEFT JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.project_id IS NULL
                   AND material.migration_status IN (
                       'unassigned','blocked','legacy_reference'
                   )
                 ORDER BY material.updated_at DESC,material.material_id ASC",
            )
            .map_err(|_| case_material_store_error())?;
        let mut rows = statement
            .query([])
            .map_err(|_| case_material_store_error())?;
        let mut materials = Vec::new();
        while let Some(row) = rows.next().map_err(|_| case_material_store_error())? {
            let migration_status = row
                .get::<_, String>(7)
                .map_err(|_| case_material_store_error())?;
            let deleted_at = row
                .get::<_, Option<String>>(13)
                .map_err(|_| case_material_store_error())?;
            let source_kind = row
                .get::<_, String>(5)
                .map_err(|_| case_material_store_error())?;
            let generation_count = u64::try_from(
                row.get::<_, i64>(9)
                    .map_err(|_| case_material_store_error())?,
            )
            .map_err(|_| case_material_store_error())?;
            let row_version = u64::try_from(
                row.get::<_, i64>(11)
                    .map_err(|_| case_material_store_error())?,
            )
            .map_err(|_| case_material_store_error())?;
            materials.push(UnassignedCaseMaterialSummary {
                material_id: row
                    .get::<_, String>(0)
                    .map_err(|_| case_material_store_error())?,
                display_name: decode_display_name(
                    row.get::<_, Option<Vec<u8>>>(1)
                        .map_err(|_| case_material_store_error())?,
                    row.get::<_, Option<String>>(2)
                        .map_err(|_| case_material_store_error())?,
                    row.get::<_, Option<String>>(3)
                        .map_err(|_| case_material_store_error())?,
                    &migration_status,
                )?,
                media_type: row
                    .get::<_, Option<String>>(4)
                    .map_err(|_| case_material_store_error())?,
                source_kind: source_kind.clone(),
                extraction_status: row
                    .get::<_, String>(6)
                    .map_err(|_| case_material_store_error())?,
                migration_status: migration_status.clone(),
                state: row
                    .get::<_, String>(8)
                    .map_err(|_| case_material_store_error())?,
                generation_count,
                historical_identity: row
                    .get::<_, String>(10)
                    .map_err(|_| case_material_store_error())?,
                assignable: migration_status == "unassigned"
                    && deleted_at.is_none()
                    && generation_count > 0
                    && assignment_material_state_is_assignable(
                        &row.get::<_, String>(8)
                            .map_err(|_| case_material_store_error())?,
                    )
                    && matches!(source_kind.as_str(), "vault" | "local_review"),
                row_version,
                updated_at: row
                    .get::<_, String>(12)
                    .map_err(|_| case_material_store_error())?,
                deleted_at,
            });
        }
        drop(rows);
        drop(statement);
        project_guard.commit()?;
        Ok(materials)
    }

    pub fn assign_unassigned_case_material(
        &self,
        request: AssignUnassignedCaseMaterialRequest,
    ) -> Result<AssignUnassignedCaseMaterialResponse, PrivacyWorkflowError> {
        let project_id = self.parse_project_id(request.project_id)?;
        let material_id = MaterialId::parse(request.material_id)
            .map_err(|_| case_material_assignment_request_error())?;
        let actor = request.actor.trim();
        if actor.is_empty()
            || actor.len() > 128
            || actor.chars().any(char::is_control)
            || request.expected_row_version > i64::MAX as u64
        {
            return Err(case_material_assignment_request_error());
        }
        let assignment_id = assignment_id(&material_id, &project_id);
        let actor_sha256 = sha256_hex(actor.as_bytes());
        let _gate = self.gate();
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| case_material_assignment_store_error())?;
        project_deletion::ensure_project_accepts_privacy_writes(&transaction, &project_id)?;

        let material = load_assignment_material(&transaction, &material_id)?;
        if material.project_id.as_deref() == Some(project_id.as_str()) {
            let replay = load_assignment_audit(&transaction, &material_id)?
                .ok_or_else(case_material_assignment_conflict_error)?;
            if replay.assignment_id != assignment_id
                || replay.project_id != project_id.as_str()
                || replay.material_id != material_id.as_str()
            {
                return Err(case_material_assignment_conflict_error());
            }
            ProjectPrivacyCaseBindingStore::validate_pair(
                &transaction,
                &project_id,
                &PrivacyCaseId::parse(replay.privacy_case_id.clone())
                    .map_err(PrivacyWorkflowError::project_case_binding)?,
            )
            .map_err(PrivacyWorkflowError::project_case_binding)?;
            transaction
                .commit()
                .map_err(|_| case_material_assignment_store_error())?;
            project_guard.commit()?;
            return Ok(AssignUnassignedCaseMaterialResponse {
                assignment_id: replay.assignment_id,
                project_id: replay.project_id,
                material_id: replay.material_id,
                assignment_mode: replay.assignment_mode,
                binding_action: replay.binding_action,
                material_row_version: replay.assigned_material_row_version,
                idempotent_replay: true,
            });
        }
        if material.project_id.is_some()
            || material.migration_status != "unassigned"
            || material.deleted_at.is_some()
            || !assignment_material_state_is_assignable(&material.state)
            || !matches!(material.source_kind.as_str(), "vault" | "local_review")
        {
            return Err(case_material_assignment_conflict_error());
        }
        if material.row_version != request.expected_row_version {
            return Err(case_material_assignment_revision_error());
        }

        let mut candidates = BTreeSet::new();
        if let Some(value) = material.legacy_case_id.as_deref() {
            candidates.insert(parse_assignment_case_id(value)?);
        }
        if let Some(value) = material.vault_case_id.as_deref() {
            candidates.insert(parse_assignment_case_id(value)?);
        }
        let redaction_ids = load_assignment_redaction_ids(&transaction, &material_id)?;
        if redaction_ids.is_empty() {
            return Err(case_material_assignment_identity_error());
        }
        let mut reviews = Vec::with_capacity(redaction_ids.len());
        let mut saw_null_review_case = false;
        for redaction_id in redaction_ids {
            let loaded = PrivacyStore::load_review_draft(&transaction, &redaction_id)
                .map_err(PrivacyWorkflowError::store)?;
            let stored: StoredReviewPayload =
                serde_json::from_slice(&loaded.review_payload_plaintext)
                    .map_err(|_| case_material_assignment_identity_error())?;
            validate_loaded_review(&loaded, &stored)?;
            match stored.case_id.as_deref() {
                Some(value) => {
                    candidates.insert(parse_assignment_case_id(value)?);
                }
                None => saw_null_review_case = true,
            }
            let has_any_vault_field = stored.vault_object_id.is_some()
                || stored.vault_object_version.is_some()
                || stored.vault_isolation.is_some();
            if has_any_vault_field {
                if material.source_kind != "vault"
                    || stored.case_id.is_none()
                    || stored.vault_object_id.is_none()
                    || stored.vault_object_version.is_none()
                    || stored.vault_isolation.is_none()
                {
                    return Err(case_material_assignment_identity_error());
                }
                self.verify_stored_vault_source(&transaction, &stored)?;
            } else if material.source_kind == "vault" {
                return Err(case_material_assignment_identity_error());
            }
            reviews.push((loaded, stored));
        }
        if candidates.len() > 1 || (!candidates.is_empty() && saw_null_review_case) {
            return Err(case_material_assignment_ambiguous_error());
        }
        if material.source_kind == "vault" && material.vault_case_id.is_none() {
            return Err(case_material_assignment_identity_error());
        }

        let existing_binding = ProjectPrivacyCaseBindingStore::resolve(&transaction, &project_id)
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        if existing_binding.is_none()
            && target_has_unbound_privacy_state(&transaction, &project_id)?
        {
            return Err(case_material_assignment_target_state_error());
        }
        let (privacy_case_id, assignment_mode, binding_action) =
            if let Some(candidate) = candidates.into_iter().next() {
                let binding_action = if existing_binding.is_some() {
                    "reused"
                } else {
                    "created"
                };
                if let Some(bound) = existing_binding {
                    if bound != candidate {
                        return Err(case_material_assignment_vault_rebind_error());
                    }
                    ProjectPrivacyCaseBindingStore::validate_pair(
                        &transaction,
                        &project_id,
                        &candidate,
                    )
                    .map_err(PrivacyWorkflowError::project_case_binding)?;
                } else {
                    let context = assignment_binding_context(
                        BindingCreationSource::LegacyMigration,
                        &assignment_id,
                    )?;
                    ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
                        &transaction,
                        &project_id,
                        &candidate,
                        &context,
                    )
                    .map_err(PrivacyWorkflowError::project_case_binding)?;
                }
                (candidate, "preserve_historical_case", binding_action)
            } else {
                if material.source_kind != "local_review"
                    || assignment_has_risk_history(&transaction, &material_id)?
                    || reviews
                        .iter()
                        .any(|(loaded, _)| loaded.review_state != "review_required")
                {
                    return Err(case_material_assignment_identity_error());
                }
                let binding_action = if existing_binding.is_some() {
                    "reused"
                } else {
                    "created"
                };
                let context = assignment_binding_context(
                    BindingCreationSource::LifecycleInitialization,
                    &assignment_id,
                )?;
                let resolved = ProjectPrivacyCaseBindingStore::resolve_or_create_in_transaction(
                    &transaction,
                    &project_id,
                    &context,
                )
                .map_err(PrivacyWorkflowError::project_case_binding)?;
                for (loaded, mut stored) in reviews {
                    stored.case_id = Some(resolved.as_str().to_owned());
                    let plaintext = serde_json::to_vec(&stored)
                        .map_err(|_| case_material_assignment_identity_error())?;
                    PrivacyStore::update_review_draft_exact(
                        &transaction,
                        &loaded.redaction_id,
                        &loaded.redacted_content_sha256,
                        &loaded.redacted_content_sha256,
                        loaded.unresolved_high_risk_count,
                        &plaintext,
                    )
                    .map_err(PrivacyWorkflowError::store)?;
                }
                (resolved, "initialize_null_case", binding_action)
            };

        let assigned_row_version = transaction
            .query_row(
                "UPDATE privacy_materials
                 SET project_id=?2,
                     legacy_case_id=COALESCE(legacy_case_id,?3),
                     migration_status='ready',
                     updated_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=?1
                   AND project_id IS NULL
                   AND migration_status='unassigned'
                   AND deleted_at IS NULL
                   AND row_version=?4
                 RETURNING row_version",
                params![
                    material_id.as_str(),
                    project_id.as_str(),
                    if assignment_mode == "preserve_historical_case" {
                        Some(privacy_case_id.as_str())
                    } else {
                        None
                    },
                    i64::try_from(request.expected_row_version)
                        .map_err(|_| case_material_assignment_request_error())?,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| case_material_assignment_store_error())?
            .ok_or_else(case_material_assignment_revision_error)?;
        let assigned_row_version = u64::try_from(assigned_row_version)
            .map_err(|_| case_material_assignment_store_error())?;
        let previous_event_hash = transaction
            .query_row(
                "SELECT event_hash FROM case_material_assignment_audit
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| case_material_assignment_store_error())?
            .unwrap_or_default();
        let audit = AssignmentAuditCanonical {
            assignment_id: &assignment_id,
            material_id: material_id.as_str(),
            project_id: project_id.as_str(),
            privacy_case_id: privacy_case_id.as_str(),
            assignment_mode,
            binding_action,
            actor_sha256: &actor_sha256,
            expected_material_row_version: request.expected_row_version,
            assigned_material_row_version: assigned_row_version,
            previous_migration_status: &material.migration_status,
            previous_state: &material.state,
            result: "assigned",
        };
        let event_hash = assignment_audit_hash(&audit, &previous_event_hash)?;
        transaction
            .execute(
                "INSERT INTO case_material_assignment_audit(
                    assignment_id,material_id,project_id,privacy_case_id,
                    assignment_mode,binding_action,actor_sha256,
                    expected_material_row_version,assigned_material_row_version,
                    previous_migration_status,previous_state,previous_event_hash,
                    event_hash,result
                 ) VALUES(
                    ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'assigned'
                 )",
                params![
                    assignment_id,
                    material_id.as_str(),
                    project_id.as_str(),
                    privacy_case_id.as_str(),
                    assignment_mode,
                    binding_action,
                    actor_sha256,
                    i64::try_from(request.expected_row_version)
                        .map_err(|_| case_material_assignment_request_error())?,
                    i64::try_from(assigned_row_version)
                        .map_err(|_| case_material_assignment_store_error())?,
                    material.migration_status,
                    material.state,
                    previous_event_hash,
                    event_hash,
                ],
            )
            .map_err(|_| case_material_assignment_store_error())?;
        transaction
            .commit()
            .map_err(|_| case_material_assignment_store_error())?;
        project_guard.commit()?;
        Ok(AssignUnassignedCaseMaterialResponse {
            assignment_id,
            project_id: project_id.as_str().to_owned(),
            material_id: material_id.as_str().to_owned(),
            assignment_mode: assignment_mode.to_owned(),
            binding_action: binding_action.to_owned(),
            material_row_version: assigned_row_version,
            idempotent_replay: false,
        })
    }

    pub fn list_case_redaction_generations(
        &self,
        request: ListCaseRedactionGenerationsRequest,
    ) -> Result<Vec<CaseRedactionGenerationSummary>, PrivacyWorkflowError> {
        self.list_case_redaction_generations_with_hook(request, || {})
    }

    #[cfg(test)]
    pub(super) fn list_case_redaction_generations_with_test_hook<F>(
        &self,
        request: ListCaseRedactionGenerationsRequest,
        after_project_guard: F,
    ) -> Result<Vec<CaseRedactionGenerationSummary>, PrivacyWorkflowError>
    where
        F: FnOnce(),
    {
        self.list_case_redaction_generations_with_hook(request, after_project_guard)
    }

    fn list_case_redaction_generations_with_hook<F>(
        &self,
        request: ListCaseRedactionGenerationsRequest,
        after_project_guard: F,
    ) -> Result<Vec<CaseRedactionGenerationSummary>, PrivacyWorkflowError>
    where
        F: FnOnce(),
    {
        let project_id = self.parse_project_id(request.project_id)?;
        let material_id = MaterialId::parse(request.material_id)
            .map_err(|_| PrivacyWorkflowError::new("invalid_material_id", "案件材料标识无效。"))?;
        let _gate = self.gate();
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        after_project_guard();
        let connection = self.open_connection()?;
        let owner = connection
            .query_row(
                "SELECT material.project_id,material.source_kind,
                        material.migration_status,material.deleted_at,vault.case_id
                 FROM privacy_materials AS material
                 LEFT JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.material_id=?1",
                [material_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| case_material_store_error())?
            .ok_or_else(|| {
                PrivacyWorkflowError::new("case_material_not_found", "案件材料不存在。")
            })?;
        if owner.0.as_deref() != Some(project_id.as_str()) {
            return Err(case_material_scope_error());
        }
        if owner.1 == "vault" && owner.2 == "ready" && owner.3.is_none() {
            let privacy_case_id = PrivacyCaseId::parse(owner.4.ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "case_material_vault_binding_invalid",
                    "案件材料缺少可验证的 Vault 身份绑定。",
                )
            })?)
            .map_err(super::PrivacyWorkflowError::project_case_binding)?;
            ProjectPrivacyCaseBindingStore::validate_pair(
                &connection,
                &project_id,
                &privacy_case_id,
            )
            .map_err(super::PrivacyWorkflowError::project_case_binding)?;
        }
        let mut statement = connection
            .prepare(
                "SELECT redaction_id,generation_number,generation_status,review_state,risk_revision,
                        approved_payload_sha256,approved_at,revocation_state,revoked_at,created_at
                 FROM privacy_redactions
                 WHERE material_id=?1
                 ORDER BY generation_number DESC",
            )
            .map_err(|_| case_material_store_error())?;
        let rows = statement
            .query_map([material_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|_| case_material_store_error())?;
        let generations = rows
            .map(|row| {
                let (
                    redaction_id,
                    generation_number,
                    generation_status,
                    review_state,
                    risk_revision,
                    approved_payload_sha256,
                    approved_at,
                    revocation_state,
                    revoked_at,
                    created_at,
                ) = row.map_err(|_| case_material_store_error())?;
                Ok(CaseRedactionGenerationSummary {
                    project_id: project_id.as_str().to_owned(),
                    material_id: material_id.as_str().to_owned(),
                    redaction_id,
                    generation_number: u64::try_from(generation_number)
                        .map_err(|_| case_material_store_error())?,
                    generation_status,
                    review_state,
                    risk_revision: u64::try_from(risk_revision)
                        .map_err(|_| case_material_store_error())?,
                    approved_payload_sha256,
                    approved_at,
                    revocation_state,
                    revoked_at,
                    created_at,
                })
            })
            .collect::<Result<Vec<_>, PrivacyWorkflowError>>()?;
        drop(statement);
        project_guard.commit()?;
        Ok(generations)
    }

    pub fn load_case_redaction_review(
        &self,
        request: LoadCaseRedactionReviewRequest,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        self.with_case_redaction_scope(
            request.project_id,
            request.redaction_id,
            || {},
            |authorization| {
                let review = self.load_review_unlocked(&authorization.redaction_id)?;
                self.case_redaction_review_view_for_authorization(authorization, review)
            },
        )
    }

    pub fn apply_case_redaction_risk_review_action(
        &self,
        request: ApplyCaseRedactionRiskReviewActionRequest,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        let legacy_request = ApplyPrivacyRiskReviewActionRequest {
            redaction_id: request.redaction_id,
            expected_revision: request.expected_revision,
            actor: request.actor,
            edited_pages: request.edited_pages,
            action: request.action,
        };
        self.with_case_redaction_scope(
            request.project_id,
            legacy_request.redaction_id.clone(),
            || {},
            |authorization| {
                let review =
                    self.apply_risk_review_action_unlocked(legacy_request, Some(authorization))?;
                self.case_redaction_review_view_for_authorization(authorization, review)
            },
        )
    }

    pub fn undo_case_redaction_risk_review(
        &self,
        request: CaseRedactionRiskReviewRevisionRequest,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        let legacy_request = PrivacyRiskReviewRevisionRequest {
            redaction_id: request.redaction_id,
            expected_revision: request.expected_revision,
        };
        self.with_case_redaction_scope(
            request.project_id,
            legacy_request.redaction_id.clone(),
            || {},
            |authorization| {
                let review = self.move_risk_review_history_unlocked(
                    legacy_request,
                    false,
                    Some(authorization),
                )?;
                self.case_redaction_review_view_for_authorization(authorization, review)
            },
        )
    }

    pub fn redo_case_redaction_risk_review(
        &self,
        request: CaseRedactionRiskReviewRevisionRequest,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        let legacy_request = PrivacyRiskReviewRevisionRequest {
            redaction_id: request.redaction_id,
            expected_revision: request.expected_revision,
        };
        self.with_case_redaction_scope(
            request.project_id,
            legacy_request.redaction_id.clone(),
            || {},
            |authorization| {
                let review = self.move_risk_review_history_unlocked(
                    legacy_request,
                    true,
                    Some(authorization),
                )?;
                self.case_redaction_review_view_for_authorization(authorization, review)
            },
        )
    }

    pub fn approve_case_redaction_review(
        &self,
        request: ApproveCaseRedactionReviewRequest,
    ) -> Result<ApprovePrivacyReviewResponse, PrivacyWorkflowError> {
        let legacy_request = ApprovePrivacyReviewRequest {
            redaction_id: request.redaction_id,
            expected_risk_revision: request.expected_risk_revision,
            expected_suggested_redacted_sha256: request.expected_suggested_redacted_sha256,
            edited_pages: request.edited_pages,
            reviewer: request.reviewer,
            destination: request.destination,
            purpose: request.purpose,
            ttl_seconds: request.ttl_seconds,
        };
        self.with_case_redaction_scope(
            request.project_id,
            legacy_request.redaction_id.clone(),
            || {},
            |authorization| {
                self.approve_local_safe_export_review_unlocked(legacy_request, Some(authorization))
            },
        )
    }

    pub fn delete_case_redaction_review(
        &self,
        request: DeleteCaseRedactionReviewRequest,
    ) -> Result<DeletePrivacyReviewResponse, PrivacyWorkflowError> {
        let legacy_request = DeletePrivacyReviewRequest {
            redaction_id: request.redaction_id,
            expected_source_sha256: request.expected_source_sha256,
            expected_extraction_sha256: request.expected_extraction_sha256,
        };
        self.with_case_redaction_scope(
            request.project_id,
            legacy_request.redaction_id.clone(),
            || {},
            |authorization| self.delete_review_unlocked(legacy_request, Some(authorization)),
        )
    }

    pub(crate) fn validate_case_export_scope(
        &self,
        request: &ExportApprovedCaseRedactionRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        self.with_case_redaction_scope(
            request.project_id.clone(),
            request.redaction_id.clone(),
            || {},
            |_| Ok(()),
        )
    }

    pub(crate) fn with_case_safe_export_authorization<T, Error, Install>(
        &self,
        request: &ExportApprovedCaseRedactionRequest,
        built: &super::safe_derived::BuiltSafeExport,
        install: Install,
    ) -> Result<T, Error>
    where
        Error: From<PrivacyWorkflowError>,
        Install: FnOnce() -> Result<T, Error>,
    {
        let _gate = self.gate();
        let project_id = self
            .parse_project_id(request.project_id.clone())
            .map_err(Error::from)?;
        let project_guard = self
            .begin_case_project_read_guard(&project_id)
            .map_err(Error::from)?;
        let connection = self.open_connection().map_err(Error::from)?;
        self.validate_case_redaction_scope_on_connection(
            &connection,
            &project_id,
            &request.redaction_id,
        )
        .map_err(Error::from)?;
        self.verify_safe_export_authorization_for_redaction_unlocked(built, &request.redaction_id)
            .map_err(Error::from)?;
        match install() {
            Ok(value) => {
                project_guard.commit().map_err(Error::from)?;
                Ok(value)
            }
            Err(error) => {
                project_guard.rollback();
                Err(error)
            }
        }
    }

    pub(crate) fn case_redaction_review_view(
        &self,
        requested_project_id: String,
        review: PrivacyReviewView,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        let scope =
            self.validate_case_redaction_scope(&requested_project_id, &review.redaction_id)?;
        self.case_redaction_review_view_from_scope(scope, review)
    }

    fn case_redaction_review_view_for_authorization(
        &self,
        authorization: &CaseRedactionAuthorization,
        review: PrivacyReviewView,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        let connection = self.open_connection()?;
        let scope = self.revalidate_case_redaction_authorization(&connection, authorization)?;
        self.case_redaction_review_view_from_scope(scope, review)
    }

    fn case_redaction_review_view_from_scope(
        &self,
        scope: CaseRedactionScope,
        review: PrivacyReviewView,
    ) -> Result<CaseRedactionReviewView, PrivacyWorkflowError> {
        if review.material_id != scope.material_id.as_str()
            || review.case_id.as_deref() != Some(scope.privacy_case_id.as_str())
        {
            return Err(case_material_scope_error());
        }
        let risk_review = review
            .risk_review
            .map(|risk| case_risk_review(scope.project_id.as_str(), &scope, risk))
            .transpose()?;
        Ok(CaseRedactionReviewView {
            project_id: scope.project_id.as_str().to_owned(),
            generation_number: scope.generation_number,
            redaction_id: review.redaction_id,
            material_id: review.material_id,
            vault_object_id: review.vault_object_id,
            vault_object_version: review.vault_object_version,
            vault_isolation: review.vault_isolation,
            source_display_name: review.source_display_name,
            source_sha256: review.source_sha256,
            extraction_sha256: review.extraction_sha256,
            suggested_redacted_content_sha256: review.suggested_redacted_content_sha256,
            processing_version: review.processing_version,
            media_type: review.media_type,
            page_count: review.page_count,
            input_transform: review.input_transform,
            backend_trace: review.backend_trace,
            summary: review.summary,
            review_state: review.review_state,
            pages: review.pages,
            risk_review,
        })
    }

    fn validate_case_redaction_scope(
        &self,
        requested_project_id: &str,
        redaction_id: &str,
    ) -> Result<CaseRedactionScope, PrivacyWorkflowError> {
        let project_id = self.parse_project_id(requested_project_id.to_owned())?;
        self.ensure_project_exists(&project_id)?;
        let connection = self.open_connection()?;
        self.validate_case_redaction_scope_on_connection(&connection, &project_id, redaction_id)
    }

    pub(super) fn revalidate_case_redaction_authorization(
        &self,
        connection: &rusqlite::Connection,
        authorization: &CaseRedactionAuthorization,
    ) -> Result<CaseRedactionScope, PrivacyWorkflowError> {
        self.validate_case_redaction_scope_on_connection(
            connection,
            &authorization.project_id,
            &authorization.redaction_id,
        )
    }

    /// Establishes the project-side read lock and validates every unified
    /// material/generation/Vault/binding predicate required before an external
    /// Provider or approved-workspace operation.
    ///
    /// The caller must already hold the workflow operation gate and must keep
    /// the returned project guard alive through the final transport or durable
    /// publication commit.
    pub(super) fn begin_live_case_redaction_authorization(
        &self,
        redaction_id: &str,
        require_approved: bool,
    ) -> Result<(CaseRedactionAuthorization, CaseProjectReadGuard), PrivacyWorkflowError> {
        if !valid_identifier(redaction_id) {
            return Err(PrivacyWorkflowError::new(
                "case_redaction_not_found",
                "案件脱敏代次不存在。",
            ));
        }
        let connection = self.open_connection()?;
        let persisted_project_id = connection
            .query_row(
                "SELECT material.project_id
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.redaction_id=?1",
                [redaction_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| case_material_store_error())?
            .flatten()
            .ok_or_else(case_material_blocked_error)?;
        let project_id = self.parse_project_id(persisted_project_id)?;
        drop(connection);

        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        let connection = self.open_connection()?;
        self.validate_case_redaction_scope_on_connection(&connection, &project_id, redaction_id)?;
        if require_approved {
            let approved = connection
                .query_row(
                    "SELECT review_state,approved_payload_sha256,
                            unresolved_high_risk_count
                     FROM privacy_redactions
                     WHERE redaction_id=?1",
                    [redaction_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(|_| case_material_store_error())?;
            if approved.0 != "approved" || approved.1.is_none() || approved.2 != 0 {
                return Err(PrivacyWorkflowError::new(
                    "redaction_not_approved",
                    "只有当前、完整批准且风险已清零的案件脱敏代次可用于外发。",
                ));
            }
        }
        Ok((
            CaseRedactionAuthorization {
                project_id,
                redaction_id: redaction_id.to_owned(),
            },
            project_guard,
        ))
    }

    fn with_case_redaction_scope<T, BeforeOperation, Operation>(
        &self,
        requested_project_id: String,
        redaction_id: String,
        before_operation: BeforeOperation,
        operation: Operation,
    ) -> Result<T, PrivacyWorkflowError>
    where
        BeforeOperation: FnOnce(),
        Operation: FnOnce(&CaseRedactionAuthorization) -> Result<T, PrivacyWorkflowError>,
    {
        let _gate = self.gate();
        let project_id = self.parse_project_id(requested_project_id)?;
        let project_guard = self.begin_case_project_read_guard(&project_id)?;
        let connection = self.open_connection()?;
        let scope = self.validate_case_redaction_scope_on_connection(
            &connection,
            &project_id,
            &redaction_id,
        )?;
        drop(connection);
        let authorization = CaseRedactionAuthorization {
            project_id: scope.project_id,
            redaction_id,
        };
        before_operation();
        match operation(&authorization) {
            Ok(value) => {
                project_guard.commit()?;
                Ok(value)
            }
            Err(error) => {
                project_guard.rollback();
                Err(error)
            }
        }
    }

    pub(super) fn begin_case_project_read_guard(
        &self,
        project_id: &ProjectId,
    ) -> Result<CaseProjectReadGuard, PrivacyWorkflowError> {
        let connection = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| case_project_read_guard_error())?;
        database::validate_open_user_database(&connection)
            .map_err(|_| case_project_read_guard_error())?;
        let journal_mode = connection
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .map_err(|_| case_project_read_guard_error())?;
        if journal_mode.eq_ignore_ascii_case("wal") {
            return Err(PrivacyWorkflowError::new(
                "case_material_source_unavailable",
                "案件数据库不是可锁定案件身份的 canonical rollback-journal 存储。",
            ));
        }
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|_| case_project_read_guard_error())?;
        let exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM projects WHERE project_id=?1
                 )",
                [project_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| case_project_read_guard_error())?;
        if !exists {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(PrivacyWorkflowError::new(
                "case_project_not_found",
                "指定案件不存在或已被删除。",
            ));
        }
        Ok(CaseProjectReadGuard {
            connection,
            active: true,
        })
    }

    fn validate_case_redaction_scope_on_connection(
        &self,
        connection: &rusqlite::Connection,
        project_id: &ProjectId,
        redaction_id: &str,
    ) -> Result<CaseRedactionScope, PrivacyWorkflowError> {
        project_deletion::ensure_project_accepts_privacy_writes(connection, project_id)?;
        let privacy_case_id = ProjectPrivacyCaseBindingStore::resolve(connection, project_id)
            .map_err(super::PrivacyWorkflowError::project_case_binding)?
            .ok_or_else(case_material_scope_error)?;
        ProjectPrivacyCaseBindingStore::validate_pair(connection, project_id, &privacy_case_id)
            .map_err(super::PrivacyWorkflowError::project_case_binding)?;
        let row = connection
            .query_row(
                "SELECT material.material_id,material.project_id,material.source_kind,
                        material.migration_status,material.state,material.deleted_at,
                        material.attachment_id,material.source_sha256,
                        material.media_type,material.page_count,
                        generation.generation_number,generation.generation_status,
                        generation.review_state,generation.revocation_state,
                        generation.revoked_at,
                        vault.case_id,vault.object_id,vault.object_version,
                        vault.source_sha256,vault.import_state,vault.failure_code
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 LEFT JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE generation.redaction_id=?1",
                [redaction_id],
                |row| {
                    Ok(PersistedCaseRedactionScope {
                        material_id: row.get(0)?,
                        project_id: row.get(1)?,
                        source_kind: row.get(2)?,
                        migration_status: row.get(3)?,
                        material_state: row.get(4)?,
                        deleted_at: row.get(5)?,
                        attachment_id: row.get(6)?,
                        source_sha256: row.get(7)?,
                        media_type: row.get(8)?,
                        page_count: row.get(9)?,
                        generation_number: row.get(10)?,
                        generation_status: row.get(11)?,
                        review_state: row.get(12)?,
                        revocation_state: row.get(13)?,
                        revoked_at: row.get(14)?,
                        vault_case_id: row.get(15)?,
                        vault_object_id: row.get(16)?,
                        vault_object_version: row.get(17)?,
                        vault_source_sha256: row.get(18)?,
                        vault_import_state: row.get(19)?,
                        vault_failure_code: row.get(20)?,
                    })
                },
            )
            .optional()
            .map_err(|_| case_material_store_error())?
            .ok_or_else(|| {
                PrivacyWorkflowError::new("case_redaction_not_found", "案件脱敏代次不存在。")
            })?;
        if row.project_id.as_deref() != Some(project_id.as_str()) {
            return Err(case_material_scope_error());
        }
        if !matches!(row.source_kind.as_str(), "vault" | "local_review")
            || row.migration_status != "ready"
            || !matches!(
                row.material_state.as_str(),
                "review_required" | "approved" | "outbound_ready"
            )
            || row.deleted_at.is_some()
            || row.generation_number <= 0
            || row.generation_status != "ready"
            || !matches!(row.review_state.as_str(), "review_required" | "approved")
            || row.revocation_state != "active"
            || row.revoked_at.is_some()
        {
            return Err(case_material_blocked_error());
        }
        let material_id =
            MaterialId::parse(row.material_id.clone()).map_err(|_| case_material_store_error())?;
        let generation_number =
            u64::try_from(row.generation_number).map_err(|_| case_material_store_error())?;
        if row.source_kind == "vault" {
            let persisted_vault_case_id =
                PrivacyCaseId::parse(row.vault_case_id.clone().ok_or_else(|| {
                    PrivacyWorkflowError::new(
                        "case_material_vault_binding_invalid",
                        "案件脱敏代次缺少 Vault 身份。",
                    )
                })?)
                .map_err(super::PrivacyWorkflowError::project_case_binding)?;
            ProjectPrivacyCaseBindingStore::validate_pair(
                connection,
                project_id,
                &persisted_vault_case_id,
            )
            .map_err(super::PrivacyWorkflowError::project_case_binding)?;
        }

        let loaded = PrivacyStore::load_review_draft(connection, redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| case_material_scope_error())?;
        validate_loaded_review(&loaded, &stored)?;
        let source_sha256 = row
            .source_sha256
            .as_deref()
            .ok_or_else(case_material_scope_error)?;
        let media_type = row
            .media_type
            .as_deref()
            .ok_or_else(case_material_scope_error)?;
        let page_count = u32::try_from(row.page_count.ok_or_else(case_material_scope_error)?)
            .map_err(|_| case_material_scope_error())?;
        if stored.case_id.as_deref() != Some(privacy_case_id.as_str())
            || stored.material_id != row.material_id
            || stored.redaction_id != redaction_id
            || stored.source_sha256 != source_sha256
            || stored.media_type != media_type
            || stored.page_count != page_count
        {
            return Err(case_material_scope_error());
        }
        match row.source_kind.as_str() {
            "vault" => {
                let object_id = row
                    .vault_object_id
                    .as_deref()
                    .ok_or_else(case_material_scope_error)?;
                let object_version = u64::try_from(
                    row.vault_object_version
                        .ok_or_else(case_material_scope_error)?,
                )
                .map_err(|_| case_material_scope_error())?;
                if row.vault_case_id.as_deref() != Some(privacy_case_id.as_str())
                    || row.vault_source_sha256.as_deref() != Some(source_sha256)
                    || row.vault_import_state.as_deref() != Some("review_ready")
                    || row.vault_failure_code.is_some()
                    || stored.vault_object_id.as_deref() != Some(object_id)
                    || stored.vault_object_version != Some(object_version)
                {
                    return Err(case_material_scope_error());
                }
                validate_vault_isolation(
                    stored
                        .vault_isolation
                        .as_ref()
                        .ok_or_else(case_material_scope_error)?,
                )?;
            }
            "local_review" => {
                if row.attachment_id.is_some()
                    || row.vault_case_id.is_some()
                    || row.vault_object_id.is_some()
                    || row.vault_object_version.is_some()
                    || row.vault_source_sha256.is_some()
                    || row.vault_import_state.is_some()
                    || row.vault_failure_code.is_some()
                    || stored.vault_object_id.is_some()
                    || stored.vault_object_version.is_some()
                    || stored.vault_isolation.is_some()
                {
                    return Err(case_material_scope_error());
                }
            }
            _ => return Err(case_material_blocked_error()),
        }

        Ok(CaseRedactionScope {
            project_id: project_id.clone(),
            material_id,
            generation_number,
            privacy_case_id,
        })
    }
}

#[derive(Debug)]
struct AssignmentMaterial {
    project_id: Option<String>,
    legacy_case_id: Option<String>,
    source_kind: String,
    migration_status: String,
    state: String,
    deleted_at: Option<String>,
    row_version: u64,
    vault_case_id: Option<String>,
}

fn load_assignment_material(
    connection: &Connection,
    material_id: &MaterialId,
) -> Result<AssignmentMaterial, PrivacyWorkflowError> {
    let row = connection
        .query_row(
            "SELECT material.project_id,material.legacy_case_id,
                    material.source_kind,material.migration_status,
                    material.state,material.deleted_at,material.row_version,
                    vault.case_id
             FROM privacy_materials AS material
             LEFT JOIN privacy_vault_material_refs AS vault
               ON vault.material_id=material.material_id
             WHERE material.material_id=?1",
            [material_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| case_material_assignment_store_error())?
        .ok_or_else(case_material_assignment_not_found_error)?;
    Ok(AssignmentMaterial {
        project_id: row.0,
        legacy_case_id: row.1,
        source_kind: row.2,
        migration_status: row.3,
        state: row.4,
        deleted_at: row.5,
        row_version: u64::try_from(row.6).map_err(|_| case_material_assignment_store_error())?,
        vault_case_id: row.7,
    })
}

fn load_assignment_redaction_ids(
    connection: &Connection,
    material_id: &MaterialId,
) -> Result<Vec<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT redaction_id
             FROM privacy_redactions
             WHERE material_id=?1
             ORDER BY generation_number ASC,redaction_id ASC",
        )
        .map_err(|_| case_material_assignment_store_error())?;
    let rows = statement
        .query_map([material_id.as_str()], |row| row.get::<_, String>(0))
        .map_err(|_| case_material_assignment_store_error())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| case_material_assignment_store_error())
}

fn load_assignment_audit(
    connection: &Connection,
    material_id: &MaterialId,
) -> Result<Option<StoredAssignmentAudit>, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT assignment_id,material_id,project_id,privacy_case_id,
                    assignment_mode,binding_action,assigned_material_row_version
             FROM case_material_assignment_audit
             WHERE material_id=?1",
            [material_id.as_str()],
            |row| {
                let assigned = row.get::<_, i64>(6)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    assigned,
                ))
            },
        )
        .optional()
        .map_err(|_| case_material_assignment_store_error())?
        .map(|row| {
            Ok(StoredAssignmentAudit {
                assignment_id: row.0,
                material_id: row.1,
                project_id: row.2,
                privacy_case_id: row.3,
                assignment_mode: row.4,
                binding_action: row.5,
                assigned_material_row_version: u64::try_from(row.6)
                    .map_err(|_| case_material_assignment_store_error())?,
            })
        })
        .transpose()
}

fn assignment_id(material_id: &MaterialId, project_id: &ProjectId) -> String {
    format!(
        "asn_{}",
        sha256_hex(
            format!(
                "case-material-assignment-v1\0{}\0{}",
                material_id.as_str(),
                project_id.as_str()
            )
            .as_bytes()
        )
    )
}

fn assignment_binding_context(
    source: BindingCreationSource,
    assignment_id: &str,
) -> Result<BindingLifecycleContext, PrivacyWorkflowError> {
    BindingLifecycleContext::new(
        source,
        format!("bind_{assignment_id}"),
        match source {
            BindingCreationSource::LegacyMigration => {
                Some("case_material_manual_assignment_v1".to_owned())
            }
            BindingCreationSource::LifecycleInitialization => None,
        },
    )
    .map_err(PrivacyWorkflowError::project_case_binding)
}

fn parse_assignment_case_id(value: &str) -> Result<PrivacyCaseId, PrivacyWorkflowError> {
    PrivacyCaseId::parse(value.to_owned()).map_err(|_| case_material_assignment_identity_error())
}

fn target_has_unbound_privacy_state(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<bool, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT
                EXISTS(
                    SELECT 1 FROM privacy_materials WHERE project_id=?1
                )
                OR EXISTS(
                    SELECT 1 FROM case_material_selections WHERE project_id=?1
                )
                OR EXISTS(
                    SELECT 1 FROM case_material_assignment_audit WHERE project_id=?1
                )
                OR EXISTS(
                    SELECT 1 FROM project_deletion_journal WHERE project_id=?1
                )
                OR EXISTS(
                    SELECT 1
                    FROM privacy_vault_material_refs AS vault
                    JOIN privacy_materials AS material
                      ON material.material_id=vault.material_id
                    WHERE material.project_id=?1
                )",
            [project_id.as_str()],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| case_material_assignment_store_error())
}

fn assignment_has_risk_history(
    connection: &Connection,
    material_id: &MaterialId,
) -> Result<bool, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM privacy_risk_review_revisions AS revision
                JOIN privacy_redactions AS generation
                  ON generation.redaction_id=revision.redaction_id
                WHERE generation.material_id=?1
             )",
            [material_id.as_str()],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| case_material_assignment_store_error())
}

fn assignment_material_state_is_assignable(state: &str) -> bool {
    !matches!(state, "blocked" | "stale" | "revoked" | "failed")
}

fn case_risk_review(
    project_id: &str,
    scope: &CaseRedactionScope,
    risk: ReviewStateViewV1,
) -> Result<CaseRedactionRiskReviewView, PrivacyWorkflowError> {
    if risk.case_id != scope.privacy_case_id.as_str()
        || risk.material_id != scope.material_id.as_str()
    {
        return Err(case_material_scope_error());
    }
    Ok(CaseRedactionRiskReviewView {
        schema_version: risk.schema_version,
        redaction_id: risk.redaction_id,
        project_id: project_id.to_owned(),
        material_id: risk.material_id,
        document_version: risk.document_version,
        detector_run_completed: risk.detector_run_completed,
        revision: risk.revision,
        document_risk: risk.document_risk,
        hard_gates: risk.hard_gates,
        findings: risk.findings,
        residual_scan: risk.residual_scan,
        visual_risk_resolutions: risk.visual_risk_resolutions,
        can_undo: risk.can_undo,
        can_redo: risk.can_redo,
        rejected: risk.rejected,
    })
}

fn decode_display_name(
    protected: Option<Vec<u8>>,
    expected_sha256: Option<String>,
    scheme: Option<String>,
    migration_status: &str,
) -> Result<String, PrivacyWorkflowError> {
    match (protected, expected_sha256, scheme) {
        (Some(protected), Some(expected_sha256), Some(scheme))
            if scheme == LOCAL_PROTECTION_SCHEME =>
        {
            let plaintext = unprotect_local(&protected).map_err(|_| {
                PrivacyWorkflowError::new(
                    "case_material_display_name_invalid",
                    "案件材料展示名无法解密。",
                )
            })?;
            if sha256_hex(&plaintext) != expected_sha256 {
                return Err(PrivacyWorkflowError::new(
                    "case_material_display_name_invalid",
                    "案件材料展示名哈希校验失败。",
                ));
            }
            String::from_utf8(plaintext).map_err(|_| {
                PrivacyWorkflowError::new(
                    "case_material_display_name_invalid",
                    "案件材料展示名编码无效。",
                )
            })
        }
        (None, None, None)
            if matches!(
                migration_status,
                "unassigned" | "legacy_reference" | "blocked"
            ) =>
        {
            Ok(if migration_status == "unassigned" {
                "未归属本地材料".to_owned()
            } else {
                "迁移问题材料".to_owned()
            })
        }
        _ => Err(PrivacyWorkflowError::new(
            "case_material_display_name_invalid",
            "案件材料缺少受保护展示名。",
        )),
    }
}

fn case_material_store_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new("case_material_store_failed", "案件材料目录读取失败。")
}

fn case_material_assignment_store_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_store_failed",
        "未归属材料归入审计无法安全读写。",
    )
}

fn case_material_assignment_request_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_request_invalid",
        "材料、案件、版本或操作人信息无效。",
    )
}

fn case_material_assignment_not_found_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_not_found",
        "指定的未归属材料不存在。",
    )
}

fn case_material_assignment_conflict_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_conflict",
        "材料已归属其他案件、状态不允许归入，或既有审计不匹配。",
    )
}

fn case_material_assignment_revision_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_revision_conflict",
        "材料版本已变化；请刷新未归属材料列表后重试。",
    )
}

fn case_material_assignment_identity_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_identity_invalid",
        "材料的历史 Privacy/Vault 身份不完整或无法验证；归入已阻断。",
    )
}

fn case_material_assignment_ambiguous_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_identity_ambiguous",
        "材料存在多个或混合缺失的历史 PrivacyCaseId 候选；系统不会猜测归属。",
    )
}

fn case_material_assignment_target_state_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_target_state_conflict",
        "目标案件尚无正式绑定，但已存在未绑定的 Privacy/Vault/材料状态；归入已阻断。",
    )
}

fn case_material_assignment_vault_rebind_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_assignment_requires_vault_rebind",
        "目标案件绑定与历史 Vault 身份不同；系统不会改写或静默重绑 Vault case_id。",
    )
}

fn case_project_read_guard_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_source_unavailable",
        "案件数据库无法建立并保持只读案件身份快照。",
    )
}

fn case_material_scope_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_scope_mismatch",
        "材料或脱敏代次不属于指定案件。",
    )
}

fn case_material_blocked_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_unavailable",
        "材料尚未完成迁移、已撤销、已删除或处于阻断状态。",
    )
}
