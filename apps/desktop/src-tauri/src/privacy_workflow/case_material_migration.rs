//! Coordinated Phase-3 backfill for the unified case-material model.
//!
//! The migration deliberately treats `user.sqlite` as an immutable source. All
//! durable writes (bindings, unified material projections, protected legacy
//! references, and append-preserving migration evidence) are made in the
//! Privacy database only.

use super::{
    validate_loaded_review, validate_vault_isolation, vault_broker, PrivacyWorkflowError,
    PrivacyWorkflowManager, StoredReviewPayload, APPROVED_PAYLOAD_SCHEMA_VERSION,
    REVIEW_PAYLOAD_SCHEMA_VERSION,
};
use privacy::{
    protect_local, sha256_hex, unprotect_local, BindingCreationSource, BindingLifecycleContext,
    PrivacyCaseId, PrivacyLifecycle, PrivacyStore, PrivacyStoreSchemaStatus, ProjectId,
    ProjectPrivacyCaseBindingError, ProjectPrivacyCaseBindingStore, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{
    params, types::ValueRef, Connection, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};
use uuid::Uuid;

pub(crate) const CASE_MATERIAL_MIGRATION_ID: &str = "case-material-unification-v1";
pub(crate) const PROJECT_CASE_BINDING_MIGRATION_ID: &str = "project-privacy-case-binding-v1";

const SOURCE_STORE_USER: &str = "user.sqlite";
const SOURCE_STORE_PRIVACY: &str = "privacy-workflow.sqlite";
const MATERIAL_ID_DOMAIN: &[u8] = b"case-material-migration-v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"case-material-source-fingerprint-v1\0";
const RISK_REVISION_PROFILE: &str = "privacy-risk-review-revision-v1";
const MAX_SOURCE_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CaseMaterialMigrationReport {
    pub privacy_materials_migrated: u64,
    pub redaction_generations_migrated: u64,
    pub case_files_migrated: u64,
    pub legacy_references: u64,
    pub blocked: u64,
    pub bindings_created_or_verified: u64,
    pub idempotent_noops: u64,
    pub source_unchanged_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceProof {
    file_sha256: String,
    schema_manifest_sha256: String,
    project_primary_keys_sha256: String,
    case_file_primary_keys_sha256: String,
    attachment_primary_keys_sha256: String,
    source_rows_sha256: String,
    wal_file_sha256: Option<String>,
    data_version: i64,
}

#[derive(Debug, Clone)]
struct ProjectSource {
    project_id: String,
    title: String,
    case_type: String,
    status: String,
    opened_on: Option<String>,
    summary: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct CaseFileSource {
    file_id: String,
    project_id: String,
    title: String,
    file_type: String,
    storage_reference: String,
    summary: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    attachment_id: String,
    project_id: Option<String>,
    original_name: String,
    extension: String,
    detected_mime: String,
    sha256: String,
    size_bytes: i64,
    extraction_status: String,
    extracted_text_sha256: Option<String>,
    segments_json_sha256: String,
    error_code: Option<String>,
    created_at: String,
}

#[derive(Debug)]
struct UserSnapshot {
    projects: BTreeMap<String, ProjectSource>,
    case_files: Vec<CaseFileSource>,
    attachments: BTreeMap<String, AttachmentSource>,
}

#[derive(Debug, Clone)]
struct PrivacyMaterialSource {
    material_id: String,
    project_id: Option<String>,
    legacy_case_id: Option<String>,
    attachment_id: Option<String>,
    protected_display_name: Option<Vec<u8>>,
    display_name_sha256: Option<String>,
    display_name_protection_scheme: Option<String>,
    source_sha256: Option<String>,
    source_name_sha256: Option<String>,
    media_type: Option<String>,
    page_count: Option<i64>,
    source_kind: String,
    extraction_status: String,
    migration_status: String,
    state: String,
    row_version: i64,
    created_at: String,
    updated_at: String,
    deleted_at: Option<String>,
    vault_binding: Option<vault_broker::VaultImportBinding>,
    redactions: Vec<PrivacyRedactionSource>,
}

#[derive(Debug, Clone)]
struct HistoricalVaultRef {
    case_id: String,
    object_id: String,
    object_version: i64,
    source_sha256: String,
    envelope_sha256: String,
    content_bytes: i64,
    import_state: String,
    failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProjectDeletionEvidenceScope {
    schema_version: String,
    project_id: String,
    privacy_case_id: Option<String>,
    material_ids: Vec<String>,
    generation_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct PrivacyRedactionSource {
    redaction_id: String,
    material_id: String,
    generation_number: i64,
    generation_status: String,
    extraction_sha256: String,
    redacted_content_sha256: String,
    approved_payload_sha256: Option<String>,
    policy_id: String,
    policy_version: i64,
    detector_version: String,
    unresolved_high_risk_count: i64,
    review_state: String,
    risk_revision: i64,
    protected_review_blob: Vec<u8>,
    protection_scheme: String,
    reviewed_by_sha256: Option<String>,
    approved_at: Option<String>,
    revocation_state: String,
    revoked_at: Option<String>,
    row_version: i64,
    created_at: String,
    reviewed_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ValidatedRedaction {
    source: PrivacyRedactionSource,
    verified_risk_revision: Option<i64>,
    generation_status: &'static str,
    error_code: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct PrivacyMaterialPlan {
    source: PrivacyMaterialSource,
    privacy_case_id: Option<PrivacyCaseId>,
    provenance_projects: BTreeSet<String>,
    display_name: Option<String>,
    redactions: Vec<ValidatedRedaction>,
    validation_error: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct MaterialProjection {
    project_id: Option<String>,
    legacy_case_id: Option<String>,
    source_kind: &'static str,
    migration_status: &'static str,
    state: String,
    display_name: Option<String>,
    error_code: Option<&'static str>,
}

#[derive(Debug, Default)]
struct CleanupAuthorizationSnapshot {
    redactions: BTreeMap<String, (String, i64)>,
    tombstoned_material_ids: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct LedgerEntry {
    source_fingerprint: String,
    target_material_id: String,
    target_redaction_id: Option<String>,
    assigned_generation_number: Option<i64>,
    result_state: String,
}

struct BindingCandidateGraph {
    projects_by_case: BTreeMap<String, BTreeSet<String>>,
    cases_by_project: BTreeMap<String, BTreeSet<String>>,
    blocked_projects: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerWrite {
    Inserted,
    EventAppended,
    Noop,
}

#[derive(Debug)]
enum AttachmentResolution<'a> {
    Exact(&'a AttachmentSource),
    Legacy(&'static str),
    Blocked(&'static str),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalApprovedPayload<'a> {
    schema_version: u16,
    source_sha256: &'a str,
    extraction_sha256: &'a str,
    media_type: &'a str,
    pages: Vec<CanonicalApprovedPage<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalApprovedPage<'a> {
    page_number: u32,
    text: &'a str,
}

impl PrivacyWorkflowManager {
    /// Strictly read-only startup probe. It returns `false` only when the
    /// persisted source manifest, all source-row fingerprints, terminal ledger
    /// targets, and project/case bindings still satisfy the migration contract.
    pub(crate) fn case_material_migration_required(&self) -> Result<bool, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| source_snapshot_error())?;
        database::validate_open_user_database(&user).map_err(|_| source_snapshot_error())?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;
        let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
        let result = (|| {
            let snapshot = UserSnapshot::load(&user)?;
            preflight_vault_state(self)?;
            let schema_status = self.preflight_privacy_store_schema_read_only()?;
            if schema_status == PrivacyStoreSchemaStatus::Empty {
                preflight_empty_privacy_vault_inventory(self)?;
                return Ok(true);
            }
            let privacy = open_privacy_read_only(&self.shared.database_path)?;
            if !self.startup_vault_present() {
                preflight_missing_vault_privacy_identity(&privacy)?;
            }
            if matches!(
                schema_status,
                PrivacyStoreSchemaStatus::UpgradeRequired { .. }
            ) {
                preflight_privacy_integrity_and_cleanup(&privacy)?;
                return Ok(true);
            }
            preflight_privacy_store(&privacy)?;
            if self.vault_startup_write_required() {
                return Ok(true);
            }
            if !source_manifest_terminal_matches(&privacy, &before.persistent_fingerprint())? {
                return Ok(true);
            }

            let cleanup = load_cleanup_authorization_snapshot(self, &privacy)?;
            let plans = load_migration_plans(self, &privacy, &snapshot, &cleanup)?;
            let graph = binding_candidate_graph(&snapshot, &plans);
            for plan in &plans {
                if !privacy_plan_terminal_matches(
                    &privacy,
                    &snapshot,
                    plan,
                    &graph.blocked_projects,
                )? {
                    return Ok(true);
                }
            }
            for case_file in &snapshot.case_files {
                if !case_file_terminal_matches(
                    self,
                    &privacy,
                    &snapshot,
                    self.shared.workspace_instance_id.as_str(),
                    case_file,
                )? {
                    return Ok(true);
                }
            }
            for source in snapshot.projects.values() {
                if !project_binding_terminal_matches(
                    &privacy,
                    source,
                    graph.cases_by_project.get(source.project_id.as_str()),
                )? {
                    return Ok(true);
                }
            }
            validate_target_invariants(&privacy, &snapshot, &cleanup)?;
            Ok(false)
        })();
        let after = SourceProof::capture(&self.shared.user_database_path, &user);
        let _ = user.execute_batch("ROLLBACK");
        match (result, after) {
            (Ok(value), Ok(after)) if after == before => Ok(value),
            (Ok(_), Ok(_)) => Err(migration_error(
                "case_material_source_changed",
                "The read-only user database changed during the migration probe.",
            )),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Runs the target backfill after the caller has successfully installed and
    /// verified the coordinated five-component backup and, when necessary,
    /// explicitly upgraded the Privacy store to schema v5.
    #[allow(dead_code)]
    pub(crate) fn run_case_material_migration_after_backup(
        &self,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let source_fingerprint = self.case_material_migration_source_fingerprint()?;
        self.run_case_material_migration_after_backup_for_source(&source_fingerprint)
    }

    /// Captures only the semantic migration source identity. Unrelated user
    /// database rows do not invalidate a completed migration or a backup token.
    pub(crate) fn case_material_migration_source_fingerprint(
        &self,
    ) -> Result<String, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| source_snapshot_error())?;
        database::validate_open_user_database(&user).map_err(|_| source_snapshot_error())?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;
        let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
        let fingerprint = before.persistent_fingerprint();
        let after = SourceProof::capture(&self.shared.user_database_path, &user);
        let _ = user.execute_batch("ROLLBACK");
        match after {
            Ok(after) if after == before => Ok(fingerprint),
            Ok(_) => Err(migration_error(
                "case_material_source_changed",
                "The read-only user database changed while its migration identity was captured.",
            )),
            Err(error) => Err(error),
        }
    }

    /// Runs the backfill only for the exact semantic source identity sealed into
    /// the coordinated backup. The comparison happens inside the pinned user
    /// read transaction before any target database is opened for writes.
    pub(crate) fn run_case_material_migration_after_backup_for_source(
        &self,
        expected_source_fingerprint: &str,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        if self.privacy_store_schema_upgrade_required() || self.vault_startup_write_required() {
            return Err(migration_error(
                "privacy_store_backup_required",
                "The case-material migration cannot run before the coordinated backup and all required storage schema upgrades.",
            ));
        }

        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| {
                migration_error(
                    "case_material_source_unavailable",
                    "The user database could not be opened as a read-only migration source.",
                )
            })?;
        database::validate_open_user_database(&user).map_err(|_| {
            migration_error(
                "case_material_source_schema_invalid",
                "The read-only user database does not match the canonical schema contract.",
            )
        })?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;

        let result = (|| {
            let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
            if before.persistent_fingerprint() != expected_source_fingerprint {
                return Err(migration_error(
                    "case_material_backup_source_mismatch",
                    "The migration source no longer matches the semantic identity sealed into the coordinated backup.",
                ));
            }
            let snapshot = UserSnapshot::load(&user)?;
            let mut privacy = self.open_connection()?;
            preflight_privacy_store(&privacy)?;
            preflight_vault_state(self)?;

            let mut report = run_backfill(
                self,
                &mut privacy,
                &user,
                &self.shared.user_database_path,
                &before,
                &snapshot,
                &self.shared.workspace_instance_id,
            )?;
            report.source_unchanged_verified = true;
            Ok(report)
        })();

        let _ = user.execute_batch("ROLLBACK");
        result
    }
}

impl SourceProof {
    fn capture(path: &Path, connection: &Connection) -> Result<Self, PrivacyWorkflowError> {
        Ok(Self {
            file_sha256: file_sha256(path)?,
            schema_manifest_sha256: query_manifest(
                connection,
                "SELECT type,name,tbl_name,COALESCE(sql,'')
                 FROM sqlite_master
                 ORDER BY type,name,tbl_name,COALESCE(sql,'')",
                4,
            )?,
            project_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT project_id FROM projects ORDER BY project_id",
            )?,
            case_file_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT file_id FROM case_files ORDER BY file_id",
            )?,
            attachment_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT attachment_id FROM attachments ORDER BY attachment_id",
            )?,
            source_rows_sha256: source_rows_manifest(connection)?,
            wal_file_sha256: sqlite_sidecar_sha256(path, "-wal")?,
            data_version: connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| source_snapshot_error())?,
        })
    }

    fn persistent_fingerprint(&self) -> String {
        let mut fingerprint = Fingerprint::new(b"user-source-manifest");
        fingerprint.text(&self.schema_manifest_sha256);
        fingerprint.text(&self.project_primary_keys_sha256);
        fingerprint.text(&self.case_file_primary_keys_sha256);
        fingerprint.text(&self.attachment_primary_keys_sha256);
        fingerprint.text(&self.source_rows_sha256);
        fingerprint.finish()
    }
}

impl UserSnapshot {
    fn load(connection: &Connection) -> Result<Self, PrivacyWorkflowError> {
        let projects = {
            let mut statement = connection
                .prepare(
                    "SELECT project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                     FROM projects ORDER BY project_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    let source = ProjectSource {
                        project_id: row.get(0)?,
                        title: row.get(1)?,
                        case_type: row.get(2)?,
                        status: row.get(3)?,
                        opened_on: row.get(4)?,
                        summary: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    };
                    Ok((source.project_id.clone(), source))
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        let case_files = {
            let mut statement = connection
                .prepare(
                    "SELECT file_id,project_id,title,file_type,storage_reference,summary,created_at
                     FROM case_files ORDER BY file_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    Ok(CaseFileSource {
                        file_id: row.get(0)?,
                        project_id: row.get(1)?,
                        title: row.get(2)?,
                        file_type: row.get(3)?,
                        storage_reference: row.get(4)?,
                        summary: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        let attachments = {
            let mut statement = connection
                .prepare(
                    "SELECT attachment_id,project_id,original_name,extension,detected_mime,sha256,
                            size_bytes,extraction_status,extracted_text,segments_json,error_code,
                            created_at
                     FROM attachments ORDER BY attachment_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    let extracted_text = row.get::<_, Option<String>>(8)?;
                    let segments_json = row.get::<_, String>(9)?;
                    let source = AttachmentSource {
                        attachment_id: row.get(0)?,
                        project_id: row.get(1)?,
                        original_name: row.get(2)?,
                        extension: row.get(3)?,
                        detected_mime: row.get(4)?,
                        sha256: row.get(5)?,
                        size_bytes: row.get(6)?,
                        extraction_status: row.get(7)?,
                        extracted_text_sha256: extracted_text
                            .as_deref()
                            .map(|value| sha256_hex(value.as_bytes())),
                        segments_json_sha256: sha256_hex(segments_json.as_bytes()),
                        error_code: row.get(10)?,
                        created_at: row.get(11)?,
                    };
                    Ok((source.attachment_id.clone(), source))
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        Ok(Self {
            projects,
            case_files,
            attachments,
        })
    }

    fn exact_attachment_provenance_projects(
        &self,
        source_sha256: &str,
        source_name_sha256: &str,
    ) -> BTreeSet<String> {
        let attachment_ids = self
            .attachments
            .values()
            .filter(|attachment| {
                attachment.sha256 == source_sha256
                    && sha256_hex(attachment.original_name.as_bytes()) == source_name_sha256
            })
            .map(|attachment| attachment.attachment_id.as_str())
            .collect::<BTreeSet<_>>();
        self.case_files
            .iter()
            .filter_map(|case_file| {
                let resolution = self.resolve_attachment(case_file);
                match resolution {
                    AttachmentResolution::Exact(attachment)
                        if attachment_ids.contains(attachment.attachment_id.as_str()) =>
                    {
                        Some(case_file.project_id.clone())
                    }
                    _ => None,
                }
            })
            .collect()
    }

    fn resolve_attachment<'a>(&'a self, case_file: &CaseFileSource) -> AttachmentResolution<'a> {
        let raw = case_file.storage_reference.as_str();
        if raw.is_empty() {
            return AttachmentResolution::Legacy("legacy_reference_empty");
        }
        let candidates = attachment_reference_candidate_ids(raw)
            .into_iter()
            .filter_map(|identifier| self.attachments.get(identifier))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return AttachmentResolution::Legacy("legacy_reference_unresolved");
        }
        if candidates.len() != 1 {
            return AttachmentResolution::Blocked("attachment_reference_ambiguous");
        }
        let attachment = candidates[0];
        match attachment.project_id.as_deref() {
            Some(owner) if owner == case_file.project_id => AttachmentResolution::Exact(attachment),
            Some(_) => AttachmentResolution::Blocked("attachment_project_conflict"),
            None => AttachmentResolution::Blocked("attachment_owner_unknown"),
        }
    }
}

fn assert_read_only_source(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    let query_only: i64 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(|_| source_snapshot_error())?;
    if query_only != 1 || !connection.is_autocommit() {
        return Err(source_snapshot_error());
    }
    Ok(())
}

fn preflight_privacy_store(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    if PrivacyStore::preflight_schema(connection).map_err(PrivacyWorkflowError::store)?
        != PrivacyStoreSchemaStatus::Current
    {
        return Err(migration_error(
            "privacy_store_schema_upgrade_required",
            "The case-material coordinator accepts only the backed-up unified Privacy schema.",
        ));
    }
    preflight_privacy_integrity_and_cleanup(connection)?;
    let orphaned: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM privacy_redactions AS redaction
                LEFT JOIN privacy_materials AS material
                  ON material.material_id=redaction.material_id
                WHERE material.material_id IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    let vault_conflict: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM privacy_vault_material_refs AS vault
                JOIN privacy_materials AS material
                  ON material.material_id=vault.material_id
                WHERE vault.source_sha256<>material.source_sha256
                   OR vault.object_version<=0
                   OR vault.import_state NOT IN(
                       'vault_committed','review_ready','processing_failed','revoked'
                   )
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if orphaned || vault_conflict {
        return Err(privacy_preflight_error());
    }
    Ok(())
}

fn preflight_privacy_integrity_and_cleanup(
    connection: &Connection,
) -> Result<(), PrivacyWorkflowError> {
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_preflight_error())?;
    if integrity != "ok" {
        return Err(privacy_preflight_error());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| privacy_preflight_error())?;
    if foreign_keys
        .query([])
        .map_err(|_| privacy_preflight_error())?
        .next()
        .map_err(|_| privacy_preflight_error())?
        .is_some()
    {
        return Err(privacy_preflight_error());
    }
    let cleanup_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_cleanup_journal'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    let pending_cleanup = cleanup_table_exists
        && connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_cleanup_journal WHERE state='prepared'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| cleanup_preflight_error())?;
    if pending_cleanup {
        return Err(cleanup_pending_error());
    }
    Ok(())
}

fn preflight_vault_state(manager: &PrivacyWorkflowManager) -> Result<(), PrivacyWorkflowError> {
    if !manager.startup_vault_present() {
        return Ok(());
    }
    let status = manager
        .shared
        .vault_broker
        .inspect_cleanup_status_read_only()
        .map_err(|_| cleanup_preflight_error())?;
    if status.has_unfinished_cleanup() {
        return Err(cleanup_pending_error());
    }
    let isolation = manager
        .shared
        .vault_broker
        .isolation_status()
        .map_err(PrivacyWorkflowError::vault)?;
    validate_vault_isolation(&isolation)?;
    Ok(())
}

fn preflight_empty_privacy_vault_inventory(
    manager: &PrivacyWorkflowManager,
) -> Result<(), PrivacyWorkflowError> {
    let inventory = manager
        .shared
        .vault_broker
        .inspect_inventory_read_only()
        .map_err(PrivacyWorkflowError::vault)?;
    if !inventory.is_empty() {
        return Err(migration_error(
            "case_material_unbound_vault_inventory",
            "An existing non-empty Vault cannot be paired with an empty Privacy identity store.",
        ));
    }
    Ok(())
}

fn preflight_missing_vault_privacy_identity(
    connection: &Connection,
) -> Result<(), PrivacyWorkflowError> {
    let vault_ref_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_vault_material_refs'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if vault_ref_table_exists {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_vault_material_refs",
                [],
                |row| row.get(0),
            )
            .map_err(|_| privacy_preflight_error())?;
        if count != 0 {
            return Err(missing_vault_history_error());
        }
    }
    let material_source_kind_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('privacy_materials')
                WHERE name='source_kind'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if material_source_kind_exists {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_materials WHERE source_kind='vault'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| privacy_preflight_error())?;
        if count != 0 {
            return Err(missing_vault_history_error());
        }
    }
    let mut statement = connection
        .prepare("SELECT redaction_id FROM privacy_redactions ORDER BY redaction_id")
        .map_err(|_| privacy_preflight_error())?;
    let redaction_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_preflight_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_preflight_error())?;
    drop(statement);
    for redaction_id in redaction_ids {
        let loaded = PrivacyStore::load_review_draft(connection, &redaction_id)
            .map_err(|_| missing_vault_history_error())?;
        let payload: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| missing_vault_history_error())?;
        if payload.vault_object_id.is_some()
            || payload.vault_object_version.is_some()
            || payload.vault_isolation.is_some()
        {
            return Err(missing_vault_history_error());
        }
    }
    Ok(())
}

fn open_privacy_read_only(path: &Path) -> Result<Connection, PrivacyWorkflowError> {
    super::validate_ordinary_database_file(path)?;
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| privacy_migration_store_error())?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA query_only=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let query_only: i64 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(|_| privacy_migration_store_error())?;
    if query_only != 1 {
        return Err(privacy_migration_store_error());
    }
    Ok(connection)
}

fn run_backfill(
    manager: &PrivacyWorkflowManager,
    privacy: &mut Connection,
    user_connection: &Connection,
    user_database_path: &Path,
    expected_source_proof: &SourceProof,
    user: &UserSnapshot,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
    let transaction = privacy
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| privacy_migration_store_error())?;
    let cleanup = load_cleanup_authorization_snapshot(manager, &transaction)?;
    let mut plans = load_migration_plans(manager, &transaction, user, &cleanup)?;
    let mut report = CaseMaterialMigrationReport::default();

    let blocked_binding_projects =
        backfill_recovered_bindings(&transaction, user, &plans, &mut report)?;

    for plan in &mut plans {
        migrate_privacy_material(
            manager,
            &transaction,
            user,
            plan,
            &blocked_binding_projects,
            &mut report,
        )?;
    }

    create_bindings_for_projects_without_privacy_state(
        &transaction,
        user,
        &plans,
        &blocked_binding_projects,
        &mut report,
    )?;

    for case_file in &user.case_files {
        migrate_case_file(
            manager,
            &transaction,
            user,
            workspace_instance_id.as_str(),
            case_file,
            &mut report,
        )?;
    }
    validate_target_invariants(&transaction, user, &cleanup)?;
    preflight_vault_state(manager)?;
    for binding in plans
        .iter()
        .filter_map(|plan| plan.source.vault_binding.as_ref())
    {
        validate_vault_binding_content(manager, binding)?;
    }
    let final_source_proof = SourceProof::capture(user_database_path, user_connection)?;
    if &final_source_proof != expected_source_proof {
        return Err(migration_error(
            "case_material_source_changed",
            "The read-only user database changed during migration; the complete target transaction was rolled back.",
        ));
    }
    record_source_manifest(&transaction, &final_source_proof, &mut report)?;
    transaction
        .commit()
        .map_err(|_| privacy_migration_store_error())?;
    Ok(report)
}

fn load_privacy_sources(
    connection: &Connection,
) -> Result<Vec<PrivacyMaterialSource>, PrivacyWorkflowError> {
    let mut material_statement = connection
        .prepare(
            "SELECT material_id,project_id,legacy_case_id,attachment_id,
                    protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,migration_status,
                    state,row_version,created_at,updated_at,deleted_at
             FROM privacy_materials
             ORDER BY material_id",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let material_rows = material_statement
        .query_map([], |row| {
            Ok(PrivacyMaterialSource {
                material_id: row.get(0)?,
                project_id: row.get(1)?,
                legacy_case_id: row.get(2)?,
                attachment_id: row.get(3)?,
                protected_display_name: row.get(4)?,
                display_name_sha256: row.get(5)?,
                display_name_protection_scheme: row.get(6)?,
                source_sha256: row.get(7)?,
                source_name_sha256: row.get(8)?,
                media_type: row.get(9)?,
                page_count: row.get(10)?,
                source_kind: row.get(11)?,
                extraction_status: row.get(12)?,
                migration_status: row.get(13)?,
                state: row.get(14)?,
                row_version: row.get(15)?,
                created_at: row.get(16)?,
                updated_at: row.get(17)?,
                deleted_at: row.get(18)?,
                vault_binding: None,
                redactions: Vec::new(),
            })
        })
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    drop(material_statement);

    let mut sources = Vec::with_capacity(material_rows.len());
    for mut material in material_rows {
        material.vault_binding =
            vault_broker::load_vault_binding_for_material(connection, &material.material_id)
                .map_err(PrivacyWorkflowError::vault)?;
        let mut redaction_statement = connection
            .prepare(
                "SELECT redaction_id,material_id,generation_number,generation_status,
                        extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                        policy_id,policy_version,detector_version,unresolved_high_risk_count,
                        review_state,risk_revision,protected_review_blob,protection_scheme,
                        reviewed_by_sha256,approved_at,revocation_state,revoked_at,row_version,
                        created_at,reviewed_at
                 FROM privacy_redactions
                 WHERE material_id=?1
                 ORDER BY generation_number,redaction_id",
            )
            .map_err(|_| privacy_migration_store_error())?;
        material.redactions = redaction_statement
            .query_map([&material.material_id], |row| {
                Ok(PrivacyRedactionSource {
                    redaction_id: row.get(0)?,
                    material_id: row.get(1)?,
                    generation_number: row.get(2)?,
                    generation_status: row.get(3)?,
                    extraction_sha256: row.get(4)?,
                    redacted_content_sha256: row.get(5)?,
                    approved_payload_sha256: row.get(6)?,
                    policy_id: row.get(7)?,
                    policy_version: row.get(8)?,
                    detector_version: row.get(9)?,
                    unresolved_high_risk_count: row.get(10)?,
                    review_state: row.get(11)?,
                    risk_revision: row.get(12)?,
                    protected_review_blob: row.get(13)?,
                    protection_scheme: row.get(14)?,
                    reviewed_by_sha256: row.get(15)?,
                    approved_at: row.get(16)?,
                    revocation_state: row.get(17)?,
                    revoked_at: row.get(18)?,
                    row_version: row.get(19)?,
                    created_at: row.get(20)?,
                    reviewed_at: row.get(21)?,
                })
            })
            .map_err(|_| privacy_migration_store_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| privacy_migration_store_error())?;
        sources.push(material);
    }
    Ok(sources)
}

fn load_migration_plans(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<Vec<PrivacyMaterialPlan>, PrivacyWorkflowError> {
    let mut plans = Vec::new();
    for source in load_privacy_sources(connection)?
        .into_iter()
        .filter(|source| matches!(source.source_kind.as_str(), "vault" | "local_review"))
    {
        if completed_project_deletion_tombstone(connection, user, &source, cleanup)?
            || completed_retention_tombstone(connection, user, &source, cleanup)?
        {
            continue;
        }
        plans.push(validate_privacy_material(
            manager, connection, user, source,
        )?);
    }
    Ok(plans)
}

fn load_cleanup_authorization_snapshot(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
) -> Result<CleanupAuthorizationSnapshot, PrivacyWorkflowError> {
    let lifecycle =
        PrivacyLifecycle::open(connection, manager.shared.workspace_instance_id.clone())
            .map_err(|_| migration_target_mismatch())?;
    let verified = lifecycle
        .cleanup_authorization_snapshot(connection)
        .map_err(|_| migration_target_mismatch())?;
    let mut redactions = BTreeMap::new();
    for entry in verified.redactions {
        if redactions
            .insert(
                entry.redaction_id,
                (entry.material_id, entry.generation_number),
            )
            .is_some()
        {
            return Err(migration_target_mismatch());
        }
    }
    Ok(CleanupAuthorizationSnapshot {
        redactions,
        tombstoned_material_ids: verified.tombstoned_material_ids.into_iter().collect(),
    })
}

fn historical_vault_ref(
    connection: &Connection,
    material_id: &str,
) -> Result<Option<HistoricalVaultRef>, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT case_id,object_id,object_version,source_sha256,envelope_sha256,
                    content_bytes,import_state,failure_code
             FROM privacy_vault_material_refs
             WHERE material_id=?1",
            [material_id],
            |row| {
                Ok(HistoricalVaultRef {
                    case_id: row.get(0)?,
                    object_id: row.get(1)?,
                    object_version: row.get(2)?,
                    source_sha256: row.get(3)?,
                    envelope_sha256: row.get(4)?,
                    content_bytes: row.get(5)?,
                    import_state: row.get(6)?,
                    failure_code: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())
}

fn valid_historical_vault_ref(source: &PrivacyMaterialSource, vault: &HistoricalVaultRef) -> bool {
    PrivacyCaseId::parse(vault.case_id.clone()).is_ok()
        && valid_prefixed_hex_id(&vault.object_id, "obj_")
        && vault.object_version > 0
        && valid_hash(&vault.source_sha256)
        && valid_hash(&vault.envelope_sha256)
        && vault.content_bytes > 0
        && source.source_sha256.as_deref() == Some(vault.source_sha256.as_str())
}

fn valid_prefixed_hex_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn completed_retention_tombstone(
    connection: &Connection,
    user: &UserSnapshot,
    source: &PrivacyMaterialSource,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<bool, PrivacyWorkflowError> {
    if !source.redactions.is_empty()
        || source.state != "revoked"
        || source
            .deleted_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
    {
        return Ok(false);
    }
    let ledger_references_material: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM case_material_migration_ledger
                WHERE migration_id=?1 AND target_material_id=?2
             )",
            params![CASE_MATERIAL_MIGRATION_ID, source.material_id],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if !ledger_references_material {
        return Ok(false);
    }
    if source.protected_display_name.is_some()
        || source.display_name_sha256.is_some()
        || source.display_name_protection_scheme.is_some()
    {
        return Err(migration_target_mismatch());
    }
    if !cleanup
        .tombstoned_material_ids
        .contains(&source.material_id)
    {
        return Err(migration_target_mismatch());
    }
    let vault = historical_vault_ref(connection, &source.material_id)?;
    match (source.source_kind.as_str(), vault.as_ref()) {
        ("vault", Some(vault))
            if valid_historical_vault_ref(source, vault)
                && vault.import_state == "revoked"
                && vault.failure_code.as_deref() == Some("retention_expired") => {}
        ("local_review", None) => {}
        _ => return Err(migration_target_mismatch()),
    }
    if let Some(project_value) = source.project_id.as_deref() {
        if !user.projects.contains_key(project_value) {
            return Err(migration_target_mismatch());
        }
        let project = ProjectId::parse(project_value.to_owned())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .ok_or_else(migration_target_mismatch)?;
        ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id)
            .map_err(|_| migration_target_mismatch())?;
        if source
            .legacy_case_id
            .as_deref()
            .is_some_and(|legacy| legacy != case_id.as_str())
        {
            return Err(migration_target_mismatch());
        }
        if vault
            .as_ref()
            .is_some_and(|vault| vault.case_id != case_id.as_str())
        {
            return Err(migration_target_mismatch());
        }
    }
    if let Some(legacy_case_id) = source.legacy_case_id.as_deref() {
        if PrivacyCaseId::parse(legacy_case_id.to_owned()).is_err()
            || vault
                .as_ref()
                .is_some_and(|vault| legacy_case_id != vault.case_id)
        {
            return Err(migration_target_mismatch());
        }
    }
    Ok(true)
}

fn completed_project_deletion_tombstone(
    connection: &Connection,
    user: &UserSnapshot,
    source: &PrivacyMaterialSource,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<bool, PrivacyWorkflowError> {
    let Some(project_value) = source.project_id.as_deref() else {
        return Ok(false);
    };
    if user.projects.contains_key(project_value) {
        return Ok(false);
    }
    let journal = connection
        .query_row(
            "SELECT privacy_case_id,scope_json,scope_sha256,state,completed_at_unix
             FROM project_deletion_journal
             WHERE project_id=?1",
            [project_value],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| migration_target_mismatch())?
        .ok_or_else(migration_target_mismatch)?;
    if journal.3 != "completed" || journal.4.is_none() {
        return Err(migration_target_mismatch());
    }
    let scope = serde_json::from_str::<ProjectDeletionEvidenceScope>(&journal.1)
        .map_err(|_| migration_target_mismatch())?;
    let canonical_scope = serde_json::to_vec(&scope).map_err(|_| migration_target_mismatch())?;
    if canonical_scope != journal.1.as_bytes()
        || sha256_hex(&canonical_scope) != journal.2
        || scope.schema_version != "project-deletion-journal-v1"
        || scope.project_id != project_value
        || scope.privacy_case_id != journal.0
        || !strictly_sorted_unique_scope(&scope.material_ids)
        || !strictly_sorted_unique_scope(&scope.generation_ids)
        || scope
            .material_ids
            .iter()
            .chain(scope.generation_ids.iter())
            .any(|value| !valid_scope_identifier(value))
        || !scope.material_ids.contains(&source.material_id)
    {
        return Err(migration_target_mismatch());
    }
    let case_value = scope
        .privacy_case_id
        .as_deref()
        .ok_or_else(migration_target_mismatch)?;
    let project = ProjectId::parse(project_value.to_owned())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let case_id = PrivacyCaseId::parse(case_value.to_owned())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    if ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
        .as_ref()
        != Some(&case_id)
        || ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id).is_err()
        || source.state != "revoked"
        || source
            .deleted_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
        || source
            .legacy_case_id
            .as_deref()
            .is_some_and(|legacy| legacy != case_value)
    {
        return Err(migration_target_mismatch());
    }
    let current_materials = collect_string_set(
        connection,
        "SELECT material_id FROM privacy_materials
         WHERE project_id=?1 ORDER BY material_id",
        project_value,
    )?;
    let current_generations = collect_string_set(
        connection,
        "SELECT generation.redaction_id
         FROM privacy_redactions AS generation
         JOIN privacy_materials AS material
           ON material.material_id=generation.material_id
         WHERE material.project_id=?1
         ORDER BY generation.redaction_id",
        project_value,
    )?;
    let mut covered_generations = current_generations.clone();
    if scope
        .generation_ids
        .iter()
        .any(|redaction_id| !current_generations.contains(redaction_id))
    {
        for redaction_id in scope
            .generation_ids
            .iter()
            .filter(|redaction_id| !current_generations.contains(*redaction_id))
        {
            let evidence = cleanup
                .redactions
                .get(redaction_id)
                .ok_or_else(migration_target_mismatch)?;
            if !scope.material_ids.contains(&evidence.0) {
                return Err(migration_target_mismatch());
            }
            covered_generations.insert(redaction_id.clone());
        }
    }
    if current_materials != scope.material_ids.iter().cloned().collect()
        || covered_generations != scope.generation_ids.iter().cloned().collect()
    {
        return Err(migration_target_mismatch());
    }
    let retention_cleanup_authorized = source.redactions.is_empty()
        && cleanup
            .tombstoned_material_ids
            .contains(&source.material_id);
    if retention_cleanup_authorized
        && (source.protected_display_name.is_some()
            || source.display_name_sha256.is_some()
            || source.display_name_protection_scheme.is_some())
    {
        return Err(migration_target_mismatch());
    }
    let vault = historical_vault_ref(connection, &source.material_id)?;
    match (source.source_kind.as_str(), vault.as_ref()) {
        ("vault", Some(vault))
            if valid_historical_vault_ref(source, vault)
                && vault.case_id == case_value
                && vault.import_state == "revoked"
                && (vault.failure_code.as_deref() == Some("project_deleted")
                    || (vault.failure_code.as_deref() == Some("retention_expired")
                        && retention_cleanup_authorized)) => {}
        ("local_review", None) => {}
        _ => return Err(migration_target_mismatch()),
    }
    validate_project_deletion_payloads(connection, source, case_value, vault.as_ref())?;
    Ok(true)
}

fn validate_project_deletion_payloads(
    connection: &Connection,
    source: &PrivacyMaterialSource,
    case_id: &str,
    vault: Option<&HistoricalVaultRef>,
) -> Result<(), PrivacyWorkflowError> {
    let existing_display = decode_existing_display_name(source)?;
    let mut payload_displays = BTreeSet::new();
    for redaction in &source.redactions {
        let revocation_valid = match (
            redaction.revocation_state.as_str(),
            redaction.revoked_at.as_deref(),
        ) {
            ("revoked", Some(value)) => sqlite_datetime_is_valid(connection, value),
            ("revoked_legacy_time_unknown", None) => true,
            _ => false,
        };
        if !revocation_valid {
            return Err(migration_target_mismatch());
        }
        let loaded = PrivacyStore::load_review_draft(connection, &redaction.redaction_id)
            .map_err(|_| migration_target_mismatch())?;
        let payload =
            serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext)
                .map_err(|_| migration_target_mismatch())?;
        if validate_loaded_review(&loaded, &payload).is_err()
            || payload.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
            || payload.case_id.as_deref() != Some(case_id)
            || payload.source_sha256 != source.source_sha256.as_deref().unwrap_or("")
            || payload.media_type != source.media_type.as_deref().unwrap_or("")
            || source.page_count != Some(i64::from(payload.page_count))
            || payload.page_count as usize != payload.pages.len()
        {
            return Err(migration_target_mismatch());
        }
        match vault {
            Some(vault)
                if payload.vault_object_id.as_deref() == Some(vault.object_id.as_str())
                    && payload.vault_object_version == u64::try_from(vault.object_version).ok() => {
            }
            None if payload.vault_object_id.is_none() && payload.vault_object_version.is_none() => {
            }
            _ => return Err(migration_target_mismatch()),
        }
        payload_displays.insert(payload.source_display_name.clone());
        let verified_risk_revision =
            validate_risk_revision_chain(connection, &redaction.redaction_id)?;
        if redaction.review_state == "approved" {
            validate_approved_generation(
                connection,
                redaction,
                &payload,
                Some(verified_risk_revision),
            )?;
        }
    }
    if payload_displays.len() > 1
        || payload_displays
            .first()
            .is_some_and(|display| existing_display.as_deref() != Some(display.as_str()))
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn collect_string_set(
    connection: &Connection,
    query: &str,
    parameter: &str,
) -> Result<BTreeSet<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(query)
        .map_err(|_| migration_target_mismatch())?;
    let values = statement
        .query_map([parameter], |row| row.get::<_, String>(0))
        .map_err(|_| migration_target_mismatch())?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| migration_target_mismatch())?;
    Ok(values)
}

fn strictly_sorted_unique_scope(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}

fn valid_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_privacy_material(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    source: PrivacyMaterialSource,
) -> Result<PrivacyMaterialPlan, PrivacyWorkflowError> {
    let mut validation_error = None;
    let mut redactions = Vec::with_capacity(source.redactions.len());
    let mut case_values = BTreeSet::new();
    let mut display_values = BTreeSet::new();
    let mut vault_tuples = BTreeSet::new();

    if source
        .source_sha256
        .as_deref()
        .is_none_or(|value| !valid_hash(value))
        || source
            .source_name_sha256
            .as_deref()
            .is_none_or(|value| !valid_hash(value))
        || source.media_type.as_deref().is_none_or(str::is_empty)
    {
        validation_error = Some("privacy_material_source_invalid");
    }

    for redaction_source in source.redactions.iter().cloned() {
        let mut generation_error = None;
        let loaded = PrivacyStore::load_review_draft(connection, &redaction_source.redaction_id);
        let payload = match loaded {
            Ok(loaded) => {
                let decoded =
                    serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext);
                match decoded {
                    Ok(payload) => {
                        if validate_loaded_review(&loaded, &payload).is_err()
                            || payload.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
                            || payload.source_sha256
                                != source.source_sha256.as_deref().unwrap_or("")
                            || payload.media_type != source.media_type.as_deref().unwrap_or("")
                            || source.page_count != Some(i64::from(payload.page_count))
                            || payload.page_count as usize != payload.pages.len()
                        {
                            generation_error = Some("privacy_payload_mismatch");
                            None
                        } else {
                            if let Some(case_id) = payload.case_id.as_deref() {
                                case_values.insert(case_id.to_owned());
                            }
                            display_values.insert(payload.source_display_name.clone());
                            vault_tuples.insert((
                                payload.case_id.clone(),
                                payload.vault_object_id.clone(),
                                payload.vault_object_version,
                                payload.source_sha256.clone(),
                            ));
                            let vault_identity_valid = if source.vault_binding.is_some() {
                                manager
                                    .verify_stored_vault_source(connection, &payload)
                                    .is_ok()
                            } else {
                                payload.vault_object_id.is_none()
                                    && payload.vault_object_version.is_none()
                                    && payload.vault_isolation.is_none()
                            };
                            if !vault_identity_valid {
                                generation_error = Some("privacy_vault_binding_invalid");
                            }
                            Some(payload)
                        }
                    }
                    Err(_) => {
                        generation_error = Some("privacy_payload_invalid");
                        None
                    }
                }
            }
            Err(_) => {
                generation_error = Some("privacy_payload_unprotect_failed");
                None
            }
        };

        let verified_risk_revision =
            match validate_risk_revision_chain(connection, &redaction_source.redaction_id) {
                Ok(revision) => Some(revision),
                Err(_) => {
                    generation_error.get_or_insert("privacy_risk_chain_invalid");
                    None
                }
            };

        if let Some(payload) = payload.as_ref() {
            if redaction_source.review_state == "approved"
                && validate_approved_generation(
                    connection,
                    &redaction_source,
                    payload,
                    verified_risk_revision,
                )
                .is_err()
            {
                generation_error.get_or_insert("privacy_approved_generation_invalid");
            }
        } else if redaction_source.review_state == "approved" {
            generation_error.get_or_insert("privacy_approved_generation_invalid");
        }
        let revocation_valid = match (
            redaction_source.review_state.as_str(),
            redaction_source.revocation_state.as_str(),
            redaction_source.revoked_at.as_deref(),
        ) {
            ("revoked", "revoked_legacy_time_unknown", None) => true,
            (_, "active", None) if redaction_source.review_state != "revoked" => true,
            (_, "revoked", Some(value)) => sqlite_datetime_is_valid(connection, value),
            _ => false,
        };
        if !revocation_valid {
            generation_error.get_or_insert("privacy_generation_revocation_invalid");
        }

        let generation_status = if generation_error.is_some() {
            "blocked"
        } else if !valid_redaction_id(&redaction_source.redaction_id) {
            "legacy_id"
        } else {
            "ready"
        };
        if generation_error.is_some() {
            validation_error.get_or_insert("privacy_material_generation_invalid");
        }
        redactions.push(ValidatedRedaction {
            source: redaction_source,
            verified_risk_revision,
            generation_status,
            error_code: generation_error,
        });
    }

    if case_values.len() > 1 || display_values.len() > 1 || vault_tuples.len() > 1 {
        validation_error = Some("privacy_material_payload_conflict");
    }
    let privacy_case_id = if case_values.len() == 1 {
        let value = case_values
            .first()
            .expect("one case value was checked")
            .clone();
        match PrivacyCaseId::parse(value) {
            Ok(case_id) => Some(case_id),
            Err(_) => {
                validation_error = Some("privacy_case_id_invalid");
                None
            }
        }
    } else {
        source
            .vault_binding
            .as_ref()
            .map(|binding| PrivacyCaseId::from(binding.case_id.clone()))
    };

    if let (Some(legacy), Some(case_id)) =
        (source.legacy_case_id.as_deref(), privacy_case_id.as_ref())
    {
        if legacy != case_id.as_str() {
            validation_error = Some("privacy_legacy_case_conflict");
        }
    }
    if let (Some(vault), Some(case_id)) = (source.vault_binding.as_ref(), privacy_case_id.as_ref())
    {
        if vault.case_id.as_str() != case_id.as_str()
            || source.source_sha256.as_deref() != Some(vault.source_sha256.as_str())
        {
            validation_error = Some("privacy_vault_binding_invalid");
        } else if validate_vault_binding_content(manager, vault).is_err() {
            validation_error = Some("privacy_vault_source_invalid");
        }
    } else if source.vault_binding.is_some() != privacy_case_id.is_some()
        && source.vault_binding.is_some()
    {
        validation_error = Some("privacy_vault_case_missing");
    }

    let display_name = if display_values.len() == 1 {
        display_values.first().cloned().filter(|value| {
            !value.is_empty() && value.len() <= 4_096 && !value.chars().any(char::is_control)
        })
    } else {
        None
    };
    let display_name = match (
        decode_existing_display_name(&source),
        display_name,
        source.redactions.is_empty(),
    ) {
        (Ok(Some(existing)), Some(payload), _) if existing != payload => {
            validation_error = Some("privacy_display_name_conflict");
            Some(existing)
        }
        (Ok(Some(existing)), _, _) => Some(existing),
        (Ok(None), payload @ Some(_), _) => payload,
        (Ok(None), None, true) => None,
        (Ok(None), None, false) => {
            validation_error = Some("privacy_display_name_invalid");
            None
        }
        (Err(_), _, _) => {
            validation_error = Some("privacy_display_name_invalid");
            None
        }
    };

    let provenance_projects = if validation_error.is_none() {
        match (
            source.source_sha256.as_deref(),
            source.source_name_sha256.as_deref(),
        ) {
            (Some(source_hash), Some(name_hash)) => {
                user.exact_attachment_provenance_projects(source_hash, name_hash)
            }
            _ => BTreeSet::new(),
        }
    } else {
        BTreeSet::new()
    };

    Ok(PrivacyMaterialPlan {
        source,
        privacy_case_id,
        provenance_projects,
        display_name,
        redactions,
        validation_error,
    })
}

fn decode_existing_display_name(
    source: &PrivacyMaterialSource,
) -> Result<Option<String>, PrivacyWorkflowError> {
    match (
        source.protected_display_name.as_deref(),
        source.display_name_sha256.as_deref(),
        source.display_name_protection_scheme.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(protected), Some(expected), Some(LOCAL_PROTECTION_SCHEME)) => {
            let plaintext = unprotect_local(protected).map_err(|_| {
                migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display name failed authentication.",
                )
            })?;
            if sha256_hex(&plaintext) != expected {
                return Err(migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display-name hash did not match.",
                ));
            }
            String::from_utf8(plaintext).map(Some).map_err(|_| {
                migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display name was not valid UTF-8.",
                )
            })
        }
        _ => Err(migration_error(
            "privacy_display_name_invalid",
            "A material display-name protection tuple was incomplete.",
        )),
    }
}

fn validate_vault_binding_content(
    manager: &PrivacyWorkflowManager,
    binding: &vault_broker::VaultImportBinding,
) -> Result<(), PrivacyWorkflowError> {
    let lease = manager
        .shared
        .vault_broker
        .read_source(binding)
        .map_err(PrivacyWorkflowError::vault)?;
    let valid = sha256_hex(lease.content()) == binding.source_sha256.as_str()
        && u64::try_from(lease.content().len()).ok() == Some(binding.content_bytes);
    drop(lease);
    if valid {
        Ok(())
    } else {
        Err(migration_error(
            "privacy_vault_source_invalid",
            "The exact Vault object failed source identity validation.",
        ))
    }
}

fn validate_risk_revision_chain(
    connection: &Connection,
    redaction_id: &str,
) -> Result<i64, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT revision,state_sha256,risk_sha256,hard_gate_sha256,action_code,
                    reason_codes_json,protected_state_blob,protection_scheme,
                    previous_revision_hash,revision_hash
             FROM privacy_risk_review_revisions
             WHERE redaction_id=?1
             ORDER BY revision",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let rows = statement
        .query_map([redaction_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    let mut previous_hash = String::new();
    let mut expected_revision = 1_i64;
    for (
        revision,
        state_sha256,
        risk_sha256,
        hard_gate_sha256,
        action_code,
        reason_codes_json,
        protected,
        protection_scheme,
        stored_previous_hash,
        revision_hash,
    ) in rows
    {
        let reasons = serde_json::from_str::<Vec<String>>(&reason_codes_json)
            .map_err(|_| risk_chain_error())?;
        if revision != expected_revision
            || stored_previous_hash != previous_hash
            || protection_scheme != LOCAL_PROTECTION_SCHEME
            || !valid_hash(&state_sha256)
            || !valid_hash(&risk_sha256)
            || !valid_hash(&hard_gate_sha256)
            || reasons.iter().any(|value| value.is_empty())
        {
            return Err(risk_chain_error());
        }
        let plaintext = unprotect_local(&protected).map_err(|_| risk_chain_error())?;
        if sha256_hex(&plaintext) != state_sha256 {
            return Err(risk_chain_error());
        }
        let protected_sha256 = sha256_hex(&protected);
        let expected_hash = sha256_hex(
            format!(
                "{RISK_REVISION_PROFILE}\0{redaction_id}\0{revision}\0{state_sha256}\0{risk_sha256}\0{hard_gate_sha256}\0{action_code}\0{reason_codes_json}\0{protected_sha256}\0{stored_previous_hash}"
            )
            .as_bytes(),
        );
        if expected_hash != revision_hash {
            return Err(risk_chain_error());
        }
        previous_hash = revision_hash;
        expected_revision += 1;
    }
    Ok(expected_revision - 1)
}

fn validate_approved_generation(
    connection: &Connection,
    source: &PrivacyRedactionSource,
    payload: &StoredReviewPayload,
    verified_risk_revision: Option<i64>,
) -> Result<(), PrivacyWorkflowError> {
    let approved_hash = source
        .approved_payload_sha256
        .as_deref()
        .filter(|value| valid_hash(value))
        .ok_or_else(approved_generation_error)?;
    let risk_revision = verified_risk_revision
        .filter(|revision| *revision > 0)
        .ok_or_else(approved_generation_error)?;
    if source.unresolved_high_risk_count != 0
        || source.risk_revision != risk_revision
        || source
            .reviewed_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
        || source.approved_at.as_deref() != source.reviewed_at.as_deref()
    {
        return Err(approved_generation_error());
    }
    let canonical = serde_json::to_vec(&CanonicalApprovedPayload {
        schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
        source_sha256: &payload.source_sha256,
        extraction_sha256: &payload.extraction_sha256,
        media_type: &payload.media_type,
        pages: payload
            .pages
            .iter()
            .map(|page| CanonicalApprovedPage {
                page_number: page.page_number,
                text: &page.suggested_redacted_text,
            })
            .collect(),
    })
    .map_err(|_| approved_generation_error())?;
    if sha256_hex(&canonical) != approved_hash {
        return Err(approved_generation_error());
    }
    Ok(())
}

fn sqlite_datetime_is_valid(connection: &Connection, value: &str) -> bool {
    connection
        .query_row("SELECT datetime(?1) IS NOT NULL", [value], |row| {
            row.get::<_, bool>(0)
        })
        .unwrap_or(false)
}

fn valid_redaction_id(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("red_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn approved_generation_error() -> PrivacyWorkflowError {
    migration_error(
        "privacy_approved_generation_invalid",
        "An approved historical generation failed payload, timestamp, or risk-chain validation.",
    )
}

fn risk_chain_error() -> PrivacyWorkflowError {
    migration_error(
        "privacy_risk_chain_invalid",
        "A historical risk-review hash chain failed validation.",
    )
}

fn privacy_migration_store_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_migration_store_failed",
        "The case-material migration could not read or update the Privacy store.",
    )
}

fn binding_candidate_graph(
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
) -> BindingCandidateGraph {
    let mut projects_by_case = BTreeMap::<String, BTreeSet<String>>::new();
    let mut cases_by_project = BTreeMap::<String, BTreeSet<String>>::new();
    for plan in plans {
        let Some(case_id) = plan.privacy_case_id.as_ref() else {
            continue;
        };
        if plan.validation_error.is_some() {
            continue;
        }
        for project_id in &plan.provenance_projects {
            if user.projects.contains_key(project_id) {
                projects_by_case
                    .entry(case_id.as_str().to_owned())
                    .or_default()
                    .insert(project_id.clone());
                cases_by_project
                    .entry(project_id.clone())
                    .or_default()
                    .insert(case_id.as_str().to_owned());
            }
        }
    }

    let mut blocked_projects = BTreeSet::new();
    for (case_id, projects) in &projects_by_case {
        if projects.len() > 1 {
            blocked_projects.extend(projects.iter().cloned());
        }
        if PrivacyCaseId::parse(case_id.clone()).is_err() {
            blocked_projects.extend(projects.iter().cloned());
        }
    }
    for (project_id, cases) in &cases_by_project {
        if cases.len() > 1 {
            blocked_projects.insert(project_id.clone());
        }
    }
    BindingCandidateGraph {
        projects_by_case,
        cases_by_project,
        blocked_projects,
    }
}

fn backfill_recovered_bindings(
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
    report: &mut CaseMaterialMigrationReport,
) -> Result<BTreeSet<String>, PrivacyWorkflowError> {
    let BindingCandidateGraph {
        projects_by_case,
        cases_by_project,
        mut blocked_projects,
    } = binding_candidate_graph(user, plans);
    for projects in projects_by_case
        .values()
        .filter(|projects| projects.len() > 1)
    {
        for project_id in projects {
            record_binding_result(
                transaction,
                user.projects
                    .get(project_id)
                    .expect("candidate project came from the user snapshot"),
                &project_binding_fingerprint(
                    user.projects
                        .get(project_id)
                        .expect("candidate project came from the user snapshot"),
                    cases_by_project.get(project_id),
                ),
                None,
                "blocked",
                Some("ambiguous_legacy_binding"),
                report,
            )?;
        }
    }
    for (project_id, cases) in &cases_by_project {
        if cases.len() > 1 {
            record_binding_result(
                transaction,
                user.projects
                    .get(project_id)
                    .expect("candidate project came from the user snapshot"),
                &project_binding_fingerprint(
                    user.projects
                        .get(project_id)
                        .expect("candidate project came from the user snapshot"),
                    Some(cases),
                ),
                None,
                "blocked",
                Some("ambiguous_legacy_binding"),
                report,
            )?;
        }
    }

    let proposals = projects_by_case
        .iter()
        .filter_map(|(case_id, projects)| {
            let project_id = projects.first()?;
            if projects.len() == 1
                && cases_by_project
                    .get(project_id)
                    .is_some_and(|cases| cases.len() == 1)
                && !blocked_projects.contains(project_id)
            {
                Some((project_id.clone(), case_id.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for (project_value, case_value) in proposals {
        let project = ProjectId::parse(project_value.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id =
            PrivacyCaseId::parse(case_value).map_err(PrivacyWorkflowError::project_case_binding)?;
        let context = BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            deterministic_binding_audit_id(&project, Some(&case_id)),
            Some(PROJECT_CASE_BINDING_MIGRATION_ID.to_owned()),
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        match ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
            transaction,
            &project,
            &case_id,
            &context,
        ) {
            Ok(bound) => {
                let source = user
                    .projects
                    .get(project.as_str())
                    .expect("binding proposal came from a user project");
                let fingerprint =
                    project_binding_fingerprint(source, cases_by_project.get(project.as_str()));
                record_binding_result(
                    transaction,
                    source,
                    &fingerprint,
                    Some(&bound),
                    "migrated",
                    None,
                    report,
                )?;
            }
            Err(
                ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict
                | ProjectPrivacyCaseBindingError::AmbiguousLegacyBinding,
            ) => {
                blocked_projects.insert(project_value.clone());
                let source = user
                    .projects
                    .get(&project_value)
                    .expect("binding proposal came from a user project");
                let fingerprint =
                    project_binding_fingerprint(source, cases_by_project.get(&project_value));
                record_binding_result(
                    transaction,
                    source,
                    &fingerprint,
                    None,
                    "blocked",
                    Some("project_privacy_case_conflict"),
                    report,
                )?;
            }
            Err(error) => return Err(PrivacyWorkflowError::project_case_binding(error)),
        }
    }

    // Existing bindings remain authoritative. Record the source-to-binding
    // verification even when this migration did not create the pair.
    for source in user.projects.values() {
        let project = ProjectId::parse(source.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        if let Some(case_id) = ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
        {
            if ProjectPrivacyCaseBindingStore::reverse_resolve(transaction, &case_id)
                .map_err(PrivacyWorkflowError::project_case_binding)?
                .as_ref()
                != Some(&project)
            {
                return Err(migration_error(
                    "project_privacy_case_binding_conflict",
                    "A persisted project/privacy case binding failed reverse uniqueness validation.",
                ));
            }
            let fingerprint = project_binding_fingerprint(
                source,
                cases_by_project.get(source.project_id.as_str()),
            );
            record_binding_result(
                transaction,
                source,
                &fingerprint,
                Some(&case_id),
                "migrated",
                None,
                report,
            )?;
        }
    }
    Ok(blocked_projects)
}

fn create_bindings_for_projects_without_privacy_state(
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
    blocked_projects: &BTreeSet<String>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let mut privacy_state_projects = blocked_projects.clone();
    for plan in plans {
        privacy_state_projects.extend(plan.provenance_projects.iter().cloned());
        if let Some(project_id) = plan.source.project_id.as_ref() {
            privacy_state_projects.insert(project_id.clone());
        }
    }
    for source in user.projects.values() {
        let project = ProjectId::parse(source.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        if ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .is_some()
        {
            continue;
        }
        if privacy_state_projects.contains(project.as_str()) {
            let fingerprint = project_binding_fingerprint(source, None);
            record_binding_result(
                transaction,
                source,
                &fingerprint,
                None,
                "blocked",
                Some("project_privacy_case_unbound"),
                report,
            )?;
            continue;
        }
        let context = BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            deterministic_binding_audit_id(&project, None),
            Some(PROJECT_CASE_BINDING_MIGRATION_ID.to_owned()),
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve_or_create_in_transaction(
            transaction,
            &project,
            &context,
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        let fingerprint = project_binding_fingerprint(source, None);
        record_binding_result(
            transaction,
            source,
            &fingerprint,
            Some(&case_id),
            "migrated",
            None,
            report,
        )?;
    }
    Ok(())
}

fn record_binding_result(
    transaction: &Transaction<'_>,
    source: &ProjectSource,
    source_fingerprint: &str,
    case_id: Option<&PrivacyCaseId>,
    result_state: &'static str,
    error_code: Option<&'static str>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let target = binding_target_id(&source.project_id);
    let invariant_valid = match case_id {
        Some(case_id) => {
            let project = ProjectId::parse(source.project_id.clone())
                .map_err(PrivacyWorkflowError::project_case_binding)?;
            ProjectPrivacyCaseBindingStore::validate_pair(transaction, &project, case_id).is_ok()
        }
        None => result_state == "blocked",
    };
    if !invariant_valid {
        return Err(migration_target_mismatch());
    }
    let write = record_ledger(
        transaction,
        PROJECT_CASE_BINDING_MIGRATION_ID,
        SOURCE_STORE_USER,
        "projects",
        &source.project_id,
        source_fingerprint,
        &target,
        None,
        None,
        result_state,
        error_code,
    )?;
    match write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            if result_state == "blocked" {
                report.blocked += 1;
            } else {
                report.bindings_created_or_verified += 1;
            }
        }
    }
    Ok(())
}

fn record_source_manifest(
    transaction: &Transaction<'_>,
    proof: &SourceProof,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let fingerprint = proof.persistent_fingerprint();
    let write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "source_manifest",
        SOURCE_STORE_USER,
        &fingerprint,
        "source_manifest_v1",
        None,
        None,
        "migrated",
        None,
    )?;
    if write == LedgerWrite::Noop {
        report.idempotent_noops += 1;
    }
    Ok(())
}

fn project_binding_fingerprint(
    source: &ProjectSource,
    candidates: Option<&BTreeSet<String>>,
) -> String {
    let mut fingerprint = Fingerprint::new(b"user-project-binding");
    fingerprint.text(&source.project_id);
    fingerprint.text(&source.title);
    fingerprint.text(&source.case_type);
    fingerprint.text(&source.status);
    fingerprint.optional_text(source.opened_on.as_deref());
    fingerprint.text(&source.summary);
    fingerprint.text(&source.created_at);
    fingerprint.text(&source.updated_at);
    for candidate in candidates.into_iter().flatten() {
        fingerprint.text(candidate);
    }
    fingerprint.finish()
}

fn source_manifest_terminal_matches(
    connection: &Connection,
    source_fingerprint: &str,
) -> Result<bool, PrivacyWorkflowError> {
    let Some((ledger, result_state)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "source_manifest",
        SOURCE_STORE_USER,
        source_fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_material_id != "source_manifest_v1"
        || ledger.target_redaction_id.is_some()
        || ledger.assigned_generation_number.is_some()
        || result_state != "migrated"
    {
        return Err(migration_target_mismatch());
    }
    Ok(true)
}

fn privacy_plan_terminal_matches(
    connection: &Connection,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
) -> Result<bool, PrivacyWorkflowError> {
    let projection = privacy_material_projection(connection, user, plan, blocked_binding_projects)?;
    let material_result = if projection.migration_status == "blocked" {
        "blocked"
    } else {
        "migrated"
    };
    let Some((material_ledger, effective_result)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_PRIVACY,
        "privacy_materials",
        &plan.source.material_id,
        &privacy_material_fingerprint(&plan.source),
    )?
    else {
        return Ok(false);
    };
    if material_ledger.target_material_id != plan.source.material_id
        || material_ledger.target_redaction_id.is_some()
        || material_ledger.assigned_generation_number.is_some()
        || effective_result != material_result
    {
        return Err(migration_target_mismatch());
    }
    validate_material_projection_target(connection, &plan.source.material_id, &projection)?;

    for redaction in &plan.redactions {
        let final_status = if projection.migration_status == "blocked" {
            "blocked"
        } else {
            redaction.generation_status
        };
        let result_state = if final_status == "blocked" {
            "blocked"
        } else {
            "migrated"
        };
        let Some((ledger, effective_result)) = effective_ledger_entry(
            connection,
            CASE_MATERIAL_MIGRATION_ID,
            SOURCE_STORE_PRIVACY,
            "privacy_redactions",
            &redaction.source.redaction_id,
            &privacy_redaction_fingerprint(redaction),
        )?
        else {
            return Ok(false);
        };
        if ledger.target_material_id != plan.source.material_id
            || ledger.target_redaction_id.as_deref() != Some(redaction.source.redaction_id.as_str())
            || ledger.assigned_generation_number != Some(redaction.source.generation_number)
            || effective_result != result_state
        {
            return Err(migration_target_mismatch());
        }
        validate_redaction_projection_target(connection, redaction, final_status)?;
    }
    Ok(true)
}

fn project_binding_terminal_matches(
    connection: &Connection,
    source: &ProjectSource,
    candidates: Option<&BTreeSet<String>>,
) -> Result<bool, PrivacyWorkflowError> {
    let fingerprint = project_binding_fingerprint(source, candidates);
    let Some((ledger, effective_result)) = effective_ledger_entry(
        connection,
        PROJECT_CASE_BINDING_MIGRATION_ID,
        SOURCE_STORE_USER,
        "projects",
        &source.project_id,
        &fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_material_id != binding_target_id(&source.project_id)
        || ledger.target_redaction_id.is_some()
        || ledger.assigned_generation_number.is_some()
    {
        return Err(migration_target_mismatch());
    }
    let project = ProjectId::parse(source.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    match ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
    {
        Some(case_id) => {
            if effective_result != "migrated"
                || ProjectPrivacyCaseBindingStore::reverse_resolve(connection, &case_id)
                    .map_err(PrivacyWorkflowError::project_case_binding)?
                    .as_ref()
                    != Some(&project)
                || ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id)
                    .is_err()
            {
                return Err(migration_target_mismatch());
            }
        }
        None if effective_result == "blocked" => {}
        None => return Ok(false),
    }
    Ok(true)
}

fn deterministic_binding_audit_id(project: &ProjectId, case_id: Option<&PrivacyCaseId>) -> String {
    let mut fingerprint = Fingerprint::new(b"project-case-binding-audit");
    fingerprint.text(PROJECT_CASE_BINDING_MIGRATION_ID);
    fingerprint.text(project.as_str());
    fingerprint.optional_text(case_id.map(PrivacyCaseId::as_str));
    format!("bindmig_{}", &fingerprint.finish()[..32])
}

fn binding_target_id(project_id: &str) -> String {
    let mut fingerprint = Fingerprint::new(b"project-case-binding-target");
    fingerprint.text(project_id);
    format!("binding_{}", &fingerprint.finish()[..32])
}

#[allow(clippy::too_many_arguments)]
fn record_ledger(
    transaction: &Transaction<'_>,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    source_fingerprint: &str,
    target_material_id: &str,
    target_redaction_id: Option<&str>,
    assigned_generation_number: Option<i64>,
    result_state: &str,
    error_code: Option<&str>,
) -> Result<LedgerWrite, PrivacyWorkflowError> {
    if source_key.is_empty()
        || source_key.len() > MAX_SOURCE_ID_BYTES
        || !valid_hash(source_fingerprint)
    {
        return Err(privacy_migration_store_error());
    }
    let existing = load_ledger(
        transaction,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?;
    if let Some(existing) = existing {
        if existing.target_material_id != target_material_id
            || existing.target_redaction_id.as_deref() != target_redaction_id
            || existing.assigned_generation_number != assigned_generation_number
        {
            return Err(migration_target_mismatch());
        }
        let (effective_fingerprint, effective_result) = effective_ledger_state(
            transaction,
            migration_id,
            source_store,
            source_table,
            source_key,
        )?
        .unwrap_or((existing.source_fingerprint, existing.result_state));
        if effective_fingerprint == source_fingerprint && effective_result == result_state {
            return Ok(LedgerWrite::Noop);
        }
        insert_migration_event(
            transaction,
            migration_id,
            source_store,
            source_table,
            source_key,
            if effective_fingerprint == source_fingerprint {
                "blocked_resolution"
            } else {
                "source_changed"
            },
            Some(source_fingerprint),
            Some(target_material_id),
            target_redaction_id,
            assigned_generation_number,
            Some(result_state),
            error_code,
        )?;
        return Ok(LedgerWrite::EventAppended);
    }

    transaction
        .execute(
            "INSERT INTO case_material_migration_ledger(
                migration_id,source_store,source_table,source_key,source_fingerprint,
                target_material_id,target_redaction_id,assigned_generation_number,
                result_state,error_code,started_at,completed_at
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            params![
                migration_id,
                source_store,
                source_table,
                source_key,
                source_fingerprint,
                target_material_id,
                target_redaction_id,
                assigned_generation_number,
                result_state,
                error_code,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    insert_migration_event(
        transaction,
        migration_id,
        source_store,
        source_table,
        source_key,
        "completed",
        Some(source_fingerprint),
        Some(target_material_id),
        target_redaction_id,
        assigned_generation_number,
        Some(result_state),
        error_code,
    )?;
    Ok(LedgerWrite::Inserted)
}

fn effective_ledger_state(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
) -> Result<Option<(String, String)>, PrivacyWorkflowError> {
    let Some(ledger) = load_ledger(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    let event = connection
        .query_row(
            "SELECT source_fingerprint,result_state
             FROM case_material_migration_events
             WHERE migration_id=?1 AND source_store=?2 AND source_table=?3
               AND source_key=?4 AND source_fingerprint IS NOT NULL
               AND result_state IS NOT NULL
             ORDER BY rowid DESC LIMIT 1",
            params![migration_id, source_store, source_table, source_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    Ok(Some(event.unwrap_or((
        ledger.source_fingerprint,
        ledger.result_state,
    ))))
}

fn effective_ledger_entry(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    expected_fingerprint: &str,
) -> Result<Option<(LedgerEntry, String)>, PrivacyWorkflowError> {
    let Some(ledger) = load_ledger(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    let Some((effective_fingerprint, effective_result)) = effective_ledger_state(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    if effective_fingerprint != expected_fingerprint {
        return Ok(None);
    }
    Ok(Some((ledger, effective_result)))
}

fn load_ledger(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
) -> Result<Option<LedgerEntry>, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT source_fingerprint,target_material_id,target_redaction_id,
                    assigned_generation_number,result_state
             FROM case_material_migration_ledger
             WHERE migration_id=?1 AND source_store=?2 AND source_table=?3 AND source_key=?4",
            params![migration_id, source_store, source_table, source_key],
            |row| {
                Ok(LedgerEntry {
                    source_fingerprint: row.get(0)?,
                    target_material_id: row.get(1)?,
                    target_redaction_id: row.get(2)?,
                    assigned_generation_number: row.get(3)?,
                    result_state: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())
}

#[allow(clippy::too_many_arguments)]
fn insert_migration_event(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    event_type: &str,
    source_fingerprint: Option<&str>,
    target_material_id: Option<&str>,
    target_redaction_id: Option<&str>,
    assigned_generation_number: Option<i64>,
    result_state: Option<&str>,
    error_code: Option<&str>,
) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute(
            "INSERT INTO case_material_migration_events(
                migration_event_id,migration_id,source_store,source_table,source_key,
                event_type,source_fingerprint,target_material_id,target_redaction_id,
                assigned_generation_number,result_state,error_code,occurred_at
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,CURRENT_TIMESTAMP)",
            params![
                format!("migev_{}", Uuid::new_v4().simple()),
                migration_id,
                source_store,
                source_table,
                source_key,
                event_type,
                source_fingerprint,
                target_material_id,
                target_redaction_id,
                assigned_generation_number,
                result_state,
                error_code,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn migration_target_mismatch() -> PrivacyWorkflowError {
    migration_error(
        "case_material_migration_target_mismatch",
        "An idempotent migration ledger no longer matches its exact target identity.",
    )
}

fn migrate_privacy_material(
    _manager: &PrivacyWorkflowManager,
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let projection =
        privacy_material_projection(transaction, user, plan, blocked_binding_projects)?;
    let material_fingerprint = privacy_material_fingerprint(&plan.source);
    let current_fingerprint =
        privacy_material_fingerprint_from_connection(transaction, &plan.source.material_id)?;
    if current_fingerprint != material_fingerprint {
        return Err(migration_error(
            "privacy_material_source_changed",
            "A Privacy material changed during its optimistic migration batch.",
        ));
    }

    apply_privacy_material_projection(transaction, &plan.source, &projection)?;
    let material_result = if projection.migration_status == "blocked" {
        "blocked"
    } else {
        "migrated"
    };
    validate_material_projection_target(transaction, &plan.source.material_id, &projection)?;
    let material_write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_PRIVACY,
        "privacy_materials",
        &plan.source.material_id,
        &material_fingerprint,
        &plan.source.material_id,
        None,
        None,
        material_result,
        projection.error_code,
    )?;

    let mut redaction_writes = Vec::with_capacity(plan.redactions.len());
    for redaction in &plan.redactions {
        let final_status = if projection.migration_status == "blocked" {
            "blocked"
        } else {
            redaction.generation_status
        };
        apply_redaction_projection(transaction, redaction, final_status)?;
        validate_redaction_projection_target(transaction, redaction, final_status)?;
        let fingerprint = privacy_redaction_fingerprint(redaction);
        let result_state = if final_status == "blocked" {
            "blocked"
        } else {
            "migrated"
        };
        let error_code = if projection.migration_status == "blocked" {
            projection.error_code
        } else if final_status == "legacy_id" {
            Some("legacy_redaction_id")
        } else {
            redaction.error_code
        };
        redaction_writes.push((
            record_ledger(
                transaction,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_PRIVACY,
                "privacy_redactions",
                &redaction.source.redaction_id,
                &fingerprint,
                &plan.source.material_id,
                Some(&redaction.source.redaction_id),
                Some(redaction.source.generation_number),
                result_state,
                error_code,
            )?,
            result_state,
        ));
    }
    match material_write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            report.privacy_materials_migrated += 1;
            if material_result == "blocked" {
                report.blocked += 1;
            }
        }
    }
    for (write, result_state) in redaction_writes {
        match write {
            LedgerWrite::Noop => report.idempotent_noops += 1,
            LedgerWrite::Inserted | LedgerWrite::EventAppended => {
                report.redaction_generations_migrated += 1;
                if result_state == "blocked" {
                    report.blocked += 1;
                }
            }
        }
    }
    Ok(())
}

fn privacy_material_projection(
    connection: &Connection,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
) -> Result<MaterialProjection, PrivacyWorkflowError> {
    let source_kind = if plan.source.vault_binding.is_some() {
        "vault"
    } else {
        "local_review"
    };
    let existing_legacy_case_id = plan.source.legacy_case_id.clone();
    let unassigned_legacy_case_id = existing_legacy_case_id.clone().or_else(|| {
        plan.privacy_case_id
            .as_ref()
            .map(|case_id| case_id.as_str().to_owned())
    });
    if let Some(error_code) = plan.validation_error {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id.clone(),
            source_kind,
            migration_status: "blocked",
            state: "blocked".to_owned(),
            display_name: plan.display_name.clone(),
            error_code: Some(error_code),
        });
    }

    if let Some(project_value) = plan.source.project_id.as_ref() {
        let project = match ProjectId::parse(project_value.clone()) {
            Ok(project) if user.projects.contains_key(project.as_str()) => project,
            _ => {
                return Ok(MaterialProjection {
                    project_id: None,
                    legacy_case_id: unassigned_legacy_case_id.clone(),
                    source_kind,
                    migration_status: "blocked",
                    state: "blocked".to_owned(),
                    display_name: plan.display_name.clone(),
                    error_code: Some("privacy_project_id_invalid"),
                });
            }
        };
        if blocked_binding_projects.contains(project.as_str()) {
            return Ok(MaterialProjection {
                project_id: None,
                legacy_case_id: unassigned_legacy_case_id.clone(),
                source_kind,
                migration_status: "blocked",
                state: "blocked".to_owned(),
                display_name: plan.display_name.clone(),
                error_code: Some("ambiguous_legacy_binding"),
            });
        }
        let binding_valid = match plan.privacy_case_id.as_ref() {
            Some(case_id) => {
                ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, case_id).is_ok()
            }
            None if plan.source.vault_binding.is_none() => {
                ProjectPrivacyCaseBindingStore::resolve(connection, &project)
                    .map_err(PrivacyWorkflowError::project_case_binding)?
                    .is_some()
            }
            None => false,
        };
        if !binding_valid {
            return Ok(MaterialProjection {
                project_id: None,
                legacy_case_id: unassigned_legacy_case_id.clone(),
                source_kind,
                migration_status: "blocked",
                state: "blocked".to_owned(),
                display_name: plan.display_name.clone(),
                error_code: Some("project_privacy_case_binding_conflict"),
            });
        }
        return Ok(MaterialProjection {
            project_id: Some(project.as_str().to_owned()),
            legacy_case_id: existing_legacy_case_id.clone(),
            source_kind,
            migration_status: "ready",
            state: plan.source.state.clone(),
            display_name: plan.display_name.clone(),
            error_code: None,
        });
    }

    let Some(case_id) = plan.privacy_case_id.as_ref() else {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: existing_legacy_case_id.clone(),
            source_kind,
            migration_status: "unassigned",
            state: plan.source.state.clone(),
            display_name: plan.display_name.clone(),
            error_code: Some("privacy_case_unassigned"),
        });
    };
    let project = ProjectPrivacyCaseBindingStore::reverse_resolve(connection, case_id)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let Some(project) = project else {
        let ambiguous = plan.provenance_projects.len() > 1
            || plan
                .provenance_projects
                .iter()
                .any(|value| blocked_binding_projects.contains(value));
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id.clone(),
            source_kind,
            migration_status: if ambiguous { "blocked" } else { "unassigned" },
            state: if ambiguous {
                "blocked".to_owned()
            } else {
                plan.source.state.clone()
            },
            display_name: plan.display_name.clone(),
            error_code: Some(if ambiguous {
                "ambiguous_legacy_binding"
            } else {
                "privacy_case_unassigned"
            }),
        });
    };
    if !user.projects.contains_key(project.as_str())
        || blocked_binding_projects.contains(project.as_str())
        || (!plan.provenance_projects.is_empty()
            && !plan.provenance_projects.contains(project.as_str()))
    {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id,
            source_kind,
            migration_status: "blocked",
            state: "blocked".to_owned(),
            display_name: plan.display_name.clone(),
            error_code: Some("project_privacy_case_binding_conflict"),
        });
    }
    ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, case_id)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    Ok(MaterialProjection {
        project_id: Some(project.as_str().to_owned()),
        legacy_case_id: existing_legacy_case_id,
        source_kind,
        migration_status: "ready",
        state: plan.source.state.clone(),
        display_name: plan.display_name.clone(),
        error_code: None,
    })
}

fn apply_privacy_material_projection(
    transaction: &Transaction<'_>,
    source: &PrivacyMaterialSource,
    projection: &MaterialProjection,
) -> Result<(), PrivacyWorkflowError> {
    let (protected_display_name, display_name_sha256, display_name_scheme) =
        match projection.display_name.as_deref() {
            Some(display_name)
                if source.display_name_sha256.as_deref()
                    == Some(sha256_hex(display_name.as_bytes()).as_str())
                    && source.protected_display_name.is_some()
                    && source.display_name_protection_scheme.as_deref()
                        == Some(LOCAL_PROTECTION_SCHEME) =>
            {
                (
                    source.protected_display_name.clone(),
                    source.display_name_sha256.clone(),
                    source.display_name_protection_scheme.clone(),
                )
            }
            Some(display_name) => (
                Some(protect_local(display_name.as_bytes()).map_err(|_| {
                    migration_error(
                        "privacy_display_name_protection_failed",
                        "A migrated material display name could not be protected.",
                    )
                })?),
                Some(sha256_hex(display_name.as_bytes())),
                Some(LOCAL_PROTECTION_SCHEME.to_owned()),
            ),
            None => (
                source.protected_display_name.clone(),
                source.display_name_sha256.clone(),
                source.display_name_protection_scheme.clone(),
            ),
        };
    let changed = source.project_id.as_deref() != projection.project_id.as_deref()
        || source.legacy_case_id.as_deref() != projection.legacy_case_id.as_deref()
        || source.source_kind != projection.source_kind
        || source.migration_status != projection.migration_status
        || source.state != projection.state
        || source.protected_display_name != protected_display_name
        || source.display_name_sha256 != display_name_sha256
        || source.display_name_protection_scheme != display_name_scheme;
    if !changed {
        return Ok(());
    }

    let bypass_approved_source_trigger = source.source_kind != projection.source_kind
        && transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_redactions
                    WHERE material_id=?1 AND review_state='approved'
                 )",
                [&source.material_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| privacy_migration_store_error())?;
    if bypass_approved_source_trigger {
        transaction
            .execute_batch("DROP TRIGGER trg_privacy_material_approved_source_immutable;")
            .map_err(|_| privacy_migration_store_error())?;
    }
    let update_result = transaction
        .execute(
            "UPDATE privacy_materials
             SET project_id=?2,legacy_case_id=?3,protected_display_name=?4,
                 display_name_sha256=?5,display_name_protection_scheme=?6,
                 source_kind=?7,migration_status=?8,state=?9,
                 updated_at=updated_at,row_version=row_version+1
             WHERE material_id=?1 AND row_version=?10",
            params![
                source.material_id,
                projection.project_id,
                projection.legacy_case_id,
                protected_display_name,
                display_name_sha256,
                display_name_scheme,
                projection.source_kind,
                projection.migration_status,
                projection.state,
                source.row_version,
            ],
        )
        .map_err(|_| privacy_migration_store_error());
    if bypass_approved_source_trigger {
        recreate_approved_source_trigger(transaction)?;
    }
    if update_result? != 1 {
        return Err(migration_error(
            "privacy_material_source_changed",
            "A Privacy material changed during its optimistic migration update.",
        ));
    }
    Ok(())
}

fn recreate_approved_source_trigger(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute_batch(
            "CREATE TRIGGER trg_privacy_material_approved_source_immutable
             BEFORE UPDATE ON privacy_materials
             WHEN EXISTS(
                 SELECT 1 FROM privacy_redactions
                 WHERE material_id=OLD.material_id AND review_state='approved'
             )
             AND (
                 NEW.source_sha256 IS NOT OLD.source_sha256
                 OR NEW.source_kind IS NOT OLD.source_kind
             )
             BEGIN
                 SELECT RAISE(ABORT, 'approved generation source identity is immutable');
             END;",
        )
        .map_err(|_| privacy_migration_store_error())
}

fn apply_redaction_projection(
    transaction: &Transaction<'_>,
    redaction: &ValidatedRedaction,
    final_status: &str,
) -> Result<(), PrivacyWorkflowError> {
    let source = &redaction.source;
    let target_risk_revision = redaction
        .verified_risk_revision
        .unwrap_or(source.risk_revision);
    let update_risk =
        source.review_state != "approved" && source.risk_revision != target_risk_revision;
    if source.generation_status == final_status && !update_risk {
        return Ok(());
    }
    let changed = transaction
        .execute(
            "UPDATE privacy_redactions
             SET generation_status=?2,
                 risk_revision=CASE WHEN review_state='approved' THEN risk_revision ELSE ?3 END,
                 row_version=row_version+1
             WHERE redaction_id=?1 AND row_version=?4",
            params![
                source.redaction_id,
                final_status,
                target_risk_revision,
                source.row_version,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    if changed != 1 {
        return Err(migration_error(
            "privacy_redaction_source_changed",
            "A Privacy redaction changed during its optimistic migration update.",
        ));
    }
    Ok(())
}

fn validate_material_projection_target(
    connection: &Connection,
    material_id: &str,
    projection: &MaterialProjection,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,legacy_case_id,source_kind,migration_status,state,
                    display_name_sha256
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(|_| privacy_migration_store_error())?;
    let expected_display_hash = projection
        .display_name
        .as_deref()
        .map(|value| sha256_hex(value.as_bytes()));
    if target.0.as_deref() != projection.project_id.as_deref()
        || target.1.as_deref() != projection.legacy_case_id.as_deref()
        || target.2 != projection.source_kind
        || target.3 != projection.migration_status
        || target.4 != projection.state
        || (expected_display_hash.is_some() && target.5 != expected_display_hash)
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn validate_redaction_projection_target(
    connection: &Connection,
    redaction: &ValidatedRedaction,
    final_status: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT material_id,generation_number,generation_status,risk_revision,
                    review_state,revocation_state,revoked_at
             FROM privacy_redactions WHERE redaction_id=?1",
            [&redaction.source.redaction_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(|_| privacy_migration_store_error())?;
    let expected_risk = if redaction.source.review_state == "approved" {
        redaction.source.risk_revision
    } else {
        redaction
            .verified_risk_revision
            .unwrap_or(redaction.source.risk_revision)
    };
    if target.0 != redaction.source.material_id
        || target.1 != redaction.source.generation_number
        || target.2 != final_status
        || target.3 != expected_risk
        || target.4 != redaction.source.review_state
        || target.5 != redaction.source.revocation_state
        || target.6 != redaction.source.revoked_at
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn privacy_material_fingerprint(source: &PrivacyMaterialSource) -> String {
    let mut fingerprint = Fingerprint::new(b"privacy-material");
    fingerprint.text(&source.material_id);
    fingerprint.optional_text(source.attachment_id.as_deref());
    fingerprint.optional_text(source.source_sha256.as_deref());
    fingerprint.optional_text(source.source_name_sha256.as_deref());
    fingerprint.optional_text(source.media_type.as_deref());
    if let Some(value) = source.page_count {
        fingerprint.integer(value);
    } else {
        fingerprint.optional(None);
    }
    fingerprint.text(&source.extraction_status);
    fingerprint.text(&source.created_at);
    fingerprint.text(&source.updated_at);
    fingerprint.optional_text(source.deleted_at.as_deref());
    if let Some(vault) = source.vault_binding.as_ref() {
        fingerprint.text(vault.case_id.as_str());
        fingerprint.text(vault.object_id.as_str());
        fingerprint.integer(i64::try_from(vault.object_version).unwrap_or(i64::MAX));
        fingerprint.text(vault.source_sha256.as_str());
        fingerprint.text(vault.envelope_sha256.as_str());
        fingerprint.integer(i64::try_from(vault.content_bytes).unwrap_or(i64::MAX));
    }
    fingerprint.finish()
}

fn privacy_material_fingerprint_from_connection(
    connection: &Connection,
    material_id: &str,
) -> Result<String, PrivacyWorkflowError> {
    let mut sources = load_privacy_sources_for_one(connection, material_id)?;
    if sources.len() != 1 {
        return Err(migration_target_mismatch());
    }
    let source = sources.pop().expect("one source was checked");
    Ok(privacy_material_fingerprint(&source))
}

fn load_privacy_sources_for_one(
    connection: &Connection,
    material_id: &str,
) -> Result<Vec<PrivacyMaterialSource>, PrivacyWorkflowError> {
    // Reuse the canonical loader and retain a single exact source. The app
    // operation gate keeps this bounded scan stable while the row is checked.
    Ok(load_privacy_sources(connection)?
        .into_iter()
        .filter(|source| source.material_id == material_id)
        .collect())
}

fn privacy_redaction_fingerprint(redaction: &ValidatedRedaction) -> String {
    let source = &redaction.source;
    let mut fingerprint = Fingerprint::new(b"privacy-redaction");
    fingerprint.text(&source.redaction_id);
    fingerprint.text(&source.material_id);
    fingerprint.integer(source.generation_number);
    fingerprint.text(&source.extraction_sha256);
    fingerprint.text(&source.redacted_content_sha256);
    fingerprint.optional_text(source.approved_payload_sha256.as_deref());
    fingerprint.text(&source.policy_id);
    fingerprint.integer(source.policy_version);
    fingerprint.text(&source.detector_version);
    fingerprint.integer(source.unresolved_high_risk_count);
    fingerprint.text(&source.review_state);
    fingerprint.text(&sha256_hex(&source.protected_review_blob));
    fingerprint.text(&source.protection_scheme);
    fingerprint.optional_text(source.reviewed_by_sha256.as_deref());
    fingerprint.optional_text(source.approved_at.as_deref());
    fingerprint.text(&source.revocation_state);
    fingerprint.optional_text(source.revoked_at.as_deref());
    fingerprint.integer(redaction.verified_risk_revision.unwrap_or(-1));
    fingerprint.text(&source.created_at);
    fingerprint.optional_text(source.reviewed_at.as_deref());
    fingerprint.finish()
}

fn migrate_case_file(
    manager: &PrivacyWorkflowManager,
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    workspace_instance_id: &str,
    case_file: &CaseFileSource,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let project = ProjectId::parse(case_file.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    if !user.projects.contains_key(project.as_str())
        || ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .is_none()
    {
        return Err(migration_error(
            "case_file_project_binding_missing",
            "A CaseFile source project has no valid persistent Privacy case binding.",
        ));
    }
    let resolution = user.resolve_attachment(case_file);
    let source_fingerprint = case_file_fingerprint(case_file, user, &resolution);
    let deterministic_target =
        deterministic_case_file_material_id(workspace_instance_id, &case_file.file_id);
    let (target_material_id, result_state, error_code, is_legacy) = match resolution {
        AttachmentResolution::Exact(attachment) => {
            match reusable_privacy_material(manager, transaction, &project, case_file, attachment)?
            {
                Some(material_id) => (material_id, "migrated", None, false),
                None => (deterministic_target.clone(), "migrated", None, false),
            }
        }
        AttachmentResolution::Legacy(error) => (
            deterministic_target.clone(),
            "legacy_reference",
            Some(error),
            true,
        ),
        AttachmentResolution::Blocked(error) => {
            (deterministic_target.clone(), "blocked", Some(error), true)
        }
    };

    match resolution {
        AttachmentResolution::Exact(attachment) => {
            if target_material_id == deterministic_target {
                ensure_user_attachment_target(
                    transaction,
                    case_file,
                    attachment,
                    &target_material_id,
                )?;
            } else {
                validate_reused_material_target(
                    transaction,
                    project.as_str(),
                    attachment,
                    &target_material_id,
                )?;
            }
        }
        AttachmentResolution::Legacy(_) | AttachmentResolution::Blocked(_) => {
            ensure_legacy_reference_target(
                transaction,
                case_file,
                &target_material_id,
                result_state,
                error_code.expect("legacy and blocked resolutions have an error code"),
            )?;
        }
    }
    let ledger_write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "case_files",
        &case_file.file_id,
        &source_fingerprint,
        &target_material_id,
        None,
        None,
        result_state,
        error_code,
    )?;
    match ledger_write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            report.case_files_migrated += 1;
            if is_legacy {
                report.legacy_references += 1;
            }
            if result_state == "blocked" {
                report.blocked += 1;
            }
        }
    }
    Ok(())
}

fn reusable_privacy_material(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    project: &ProjectId,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
) -> Result<Option<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT material.material_id
             FROM privacy_materials AS material
             JOIN privacy_vault_material_refs AS vault
               ON vault.material_id=material.material_id
             WHERE material.project_id=?1
               AND material.source_sha256=?2
               AND material.source_kind='vault'
               AND material.migration_status='ready'
               AND material.deleted_at IS NULL
               AND vault.import_state IN('vault_committed','review_ready','processing_failed')
               AND EXISTS(
                   SELECT 1 FROM case_material_migration_ledger AS ledger
                   WHERE ledger.migration_id=?3
                     AND ledger.source_store=?4
                     AND ledger.source_table='privacy_materials'
                     AND ledger.source_key=material.material_id
                     AND ledger.result_state='migrated'
               )
             ORDER BY material.material_id",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let candidates = statement
        .query_map(
            params![
                project.as_str(),
                attachment.sha256,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_PRIVACY
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    if candidates.len() != 1 {
        return Ok(None);
    }
    let material_id = candidates[0].clone();
    let conflicting_source: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM case_material_migration_ledger
                WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
                  AND target_material_id=?3 AND source_key<>?4
             )",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                material_id,
                case_file.file_id,
            ],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if conflicting_source {
        return Ok(None);
    }
    let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
        .ok_or_else(migration_target_mismatch)?;
    let binding = vault_broker::load_vault_binding_for_material(connection, &material_id)
        .map_err(PrivacyWorkflowError::vault)?
        .ok_or_else(migration_target_mismatch)?;
    if binding.case_id.as_str() != case_id.as_str()
        || binding.source_sha256.as_str() != attachment.sha256
    {
        return Ok(None);
    }
    validate_vault_binding_content(manager, &binding)?;
    Ok(Some(material_id))
}

fn ensure_user_attachment_target(
    transaction: &Transaction<'_>,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let existing = transaction
        .query_row(
            "SELECT project_id,attachment_id,source_sha256,source_name_sha256,media_type,
                    source_kind,extraction_status,migration_status,state,display_name_sha256,
                    row_version
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    let source_name_sha256 = sha256_hex(attachment.original_name.as_bytes());
    let display_name_sha256 = sha256_hex(case_file.title.as_bytes());
    if let Some(existing) = existing {
        if existing.0.as_deref() != Some(case_file.project_id.as_str())
            || existing.1.as_deref() != Some(attachment.attachment_id.as_str())
            || existing.5 != "user_attachment"
            || existing.7 != "ready"
            || existing.8 != "registered"
        {
            return Err(migration_target_mismatch());
        }
        let projection_changed = existing.2.as_deref() != Some(attachment.sha256.as_str())
            || existing.3.as_deref() != Some(source_name_sha256.as_str())
            || existing.4.as_deref() != Some(attachment.detected_mime.as_str())
            || existing.6 != attachment.extraction_status
            || existing.9.as_deref() != Some(display_name_sha256.as_str());
        if projection_changed {
            let has_generation: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM privacy_redactions WHERE material_id=?1
                     )",
                    [material_id],
                    |row| row.get(0),
                )
                .map_err(|_| privacy_migration_store_error())?;
            if has_generation {
                return Err(migration_target_mismatch());
            }
            let protected_display_name =
                protect_local(case_file.title.as_bytes()).map_err(|_| {
                    migration_error(
                        "case_file_display_name_protection_failed",
                        "A changed CaseFile title could not be protected for the unified material index.",
                    )
                })?;
            let changed = transaction
                .execute(
                    "UPDATE privacy_materials
                     SET protected_display_name=?2,display_name_sha256=?3,
                         display_name_protection_scheme=?4,source_sha256=?5,
                         source_name_sha256=?6,media_type=?7,extraction_status=?8,
                         row_version=row_version+1
                     WHERE material_id=?1 AND row_version=?9
                       AND source_kind='user_attachment'
                       AND migration_status='ready' AND state='registered'",
                    params![
                        material_id,
                        protected_display_name,
                        display_name_sha256,
                        LOCAL_PROTECTION_SCHEME,
                        attachment.sha256,
                        source_name_sha256,
                        attachment.detected_mime,
                        attachment.extraction_status,
                        existing.10,
                    ],
                )
                .map_err(|_| privacy_migration_store_error())?;
            if changed != 1 {
                return Err(migration_target_mismatch());
            }
        }
        return Ok(());
    }
    let protected_display_name = protect_local(case_file.title.as_bytes()).map_err(|_| {
        migration_error(
            "case_file_display_name_protection_failed",
            "A CaseFile title could not be protected for the unified material index.",
        )
    })?;
    transaction
        .execute(
            "INSERT INTO privacy_materials(
                material_id,project_id,attachment_id,protected_display_name,
                display_name_sha256,display_name_protection_scheme,source_sha256,
                source_name_sha256,media_type,page_count,source_kind,extraction_status,
                migration_status,state,row_version,created_at,updated_at,deleted_at
             ) VALUES(
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,'user_attachment',?10,
                'ready','registered',1,?11,?11,NULL
             )",
            params![
                material_id,
                case_file.project_id,
                attachment.attachment_id,
                protected_display_name,
                display_name_sha256,
                LOCAL_PROTECTION_SCHEME,
                attachment.sha256,
                source_name_sha256,
                attachment.detected_mime,
                attachment.extraction_status,
                case_file.created_at,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn validate_reused_material_target(
    connection: &Connection,
    project_id: &str,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let valid: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM privacy_materials
                WHERE material_id=?1 AND project_id=?2 AND source_sha256=?3
                  AND source_kind='vault' AND migration_status='ready'
                  AND deleted_at IS NULL
             )",
            params![material_id, project_id, attachment.sha256],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if valid {
        Ok(())
    } else {
        Err(migration_target_mismatch())
    }
}

fn case_file_terminal_matches(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    workspace_instance_id: &str,
    case_file: &CaseFileSource,
) -> Result<bool, PrivacyWorkflowError> {
    let project = ProjectId::parse(case_file.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let Some(_) = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
    else {
        return Ok(false);
    };
    let resolution = user.resolve_attachment(case_file);
    let fingerprint = case_file_fingerprint(case_file, user, &resolution);
    let Some((ledger, effective_result)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "case_files",
        &case_file.file_id,
        &fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_redaction_id.is_some() || ledger.assigned_generation_number.is_some() {
        return Err(migration_target_mismatch());
    }
    let deterministic_target =
        deterministic_case_file_material_id(workspace_instance_id, &case_file.file_id);
    match resolution {
        AttachmentResolution::Exact(attachment) => {
            if effective_result != "migrated" {
                return Err(migration_target_mismatch());
            }
            let expected_target =
                reusable_privacy_material(manager, connection, &project, case_file, attachment)?
                    .unwrap_or_else(|| deterministic_target.clone());
            if ledger.target_material_id != expected_target {
                return Err(migration_target_mismatch());
            }
            if expected_target == deterministic_target {
                validate_user_attachment_terminal_target(
                    connection,
                    case_file,
                    attachment,
                    &expected_target,
                )?;
            } else {
                validate_reused_material_target(
                    connection,
                    project.as_str(),
                    attachment,
                    &expected_target,
                )?;
            }
        }
        AttachmentResolution::Legacy(error) => {
            if effective_result != "legacy_reference"
                || ledger.target_material_id != deterministic_target
            {
                return Err(migration_target_mismatch());
            }
            validate_legacy_reference_terminal_target(
                connection,
                case_file,
                &deterministic_target,
                "legacy_reference",
                error,
            )?;
        }
        AttachmentResolution::Blocked(error) => {
            if effective_result != "blocked" || ledger.target_material_id != deterministic_target {
                return Err(migration_target_mismatch());
            }
            validate_legacy_reference_terminal_target(
                connection,
                case_file,
                &deterministic_target,
                "blocked",
                error,
            )?;
        }
    }
    Ok(true)
}

fn validate_user_attachment_terminal_target(
    connection: &Connection,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,attachment_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,media_type,
                    page_count,source_kind,extraction_status,migration_status,state,deleted_at
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let display = target
        .2
        .as_deref()
        .ok_or_else(migration_target_mismatch)
        .and_then(|protected| {
            unprotect_local(protected).map_err(|_| migration_target_mismatch())
        })?;
    if target.0.as_deref() != Some(case_file.project_id.as_str())
        || target.1.as_deref() != Some(attachment.attachment_id.as_str())
        || display != case_file.title.as_bytes()
        || target.3.as_deref() != Some(sha256_hex(case_file.title.as_bytes()).as_str())
        || target.4.as_deref() != Some(LOCAL_PROTECTION_SCHEME)
        || target.5.as_deref() != Some(attachment.sha256.as_str())
        || target.6.as_deref() != Some(sha256_hex(attachment.original_name.as_bytes()).as_str())
        || target.7.as_deref() != Some(attachment.detected_mime.as_str())
        || target.8.is_some()
        || target.9 != "user_attachment"
        || target.10 != attachment.extraction_status
        || target.11 != "ready"
        || target.12 != "registered"
        || target.13.is_some()
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn validate_legacy_reference_terminal_target(
    connection: &Connection,
    case_file: &CaseFileSource,
    material_id: &str,
    migration_status: &str,
    error_code: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,attachment_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,media_type,
                    page_count,source_kind,extraction_status,migration_status,state,deleted_at
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let display = target
        .2
        .as_deref()
        .ok_or_else(migration_target_mismatch)
        .and_then(|protected| {
            unprotect_local(protected).map_err(|_| migration_target_mismatch())
        })?;
    if target.0.as_deref() != Some(case_file.project_id.as_str())
        || target.1.is_some()
        || display != case_file.title.as_bytes()
        || target.3.as_deref() != Some(sha256_hex(case_file.title.as_bytes()).as_str())
        || target.4.as_deref() != Some(LOCAL_PROTECTION_SCHEME)
        || target.5.is_some()
        || target.6.is_some()
        || target.7.is_some()
        || target.8.is_some()
        || target.9 != "legacy_reference"
        || target.10 != error_code
        || target.11 != migration_status
        || target.12 != "blocked"
        || target.13.is_some()
    {
        return Err(migration_target_mismatch());
    }
    let reference = connection
        .query_row(
            "SELECT legacy_reference_id,material_id,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
             FROM case_material_legacy_references
             WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
               AND source_key=?3",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let storage_reference =
        unprotect_local(&reference.2).map_err(|_| migration_target_mismatch())?;
    if reference.0 != legacy_reference_id(&case_file.file_id)
        || reference.1 != material_id
        || storage_reference != case_file.storage_reference.as_bytes()
        || reference.3 != sha256_hex(case_file.storage_reference.as_bytes())
        || reference.4 != LOCAL_PROTECTION_SCHEME
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn ensure_legacy_reference_target(
    transaction: &Transaction<'_>,
    case_file: &CaseFileSource,
    material_id: &str,
    result_state: &str,
    error_code: &str,
) -> Result<(), PrivacyWorkflowError> {
    let migration_status = if result_state == "blocked" {
        "blocked"
    } else {
        "legacy_reference"
    };
    let display_name_sha256 = sha256_hex(case_file.title.as_bytes());
    let existing = transaction
        .query_row(
            "SELECT project_id,source_kind,extraction_status,migration_status,state,
                    display_name_sha256
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    if let Some(existing) = existing {
        if existing.0.as_deref() != Some(case_file.project_id.as_str())
            || existing.1 != "legacy_reference"
            || existing.2 != error_code
            || existing.3 != migration_status
            || existing.4 != "blocked"
            || existing.5.as_deref() != Some(display_name_sha256.as_str())
        {
            return Err(migration_target_mismatch());
        }
    } else {
        let protected_display_name = protect_local(case_file.title.as_bytes()).map_err(|_| {
            migration_error(
                "case_file_display_name_protection_failed",
                "A CaseFile title could not be protected for the unified material index.",
            )
        })?;
        transaction
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,migration_status,
                    state,row_version,created_at,updated_at,deleted_at
                 ) VALUES(
                    ?1,?2,?3,?4,?5,NULL,NULL,NULL,NULL,'legacy_reference',?6,?7,
                    'blocked',1,?8,?8,NULL
                 )",
                params![
                    material_id,
                    case_file.project_id,
                    protected_display_name,
                    display_name_sha256,
                    LOCAL_PROTECTION_SCHEME,
                    error_code,
                    migration_status,
                    case_file.created_at,
                ],
            )
            .map_err(|_| privacy_migration_store_error())?;
    }

    let reference_hash = sha256_hex(case_file.storage_reference.as_bytes());
    let existing_reference = transaction
        .query_row(
            "SELECT storage_reference_sha256,protection_scheme
             FROM case_material_legacy_references
             WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
               AND source_key=?3",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    if let Some((stored_hash, scheme)) = existing_reference {
        if stored_hash != reference_hash || scheme != LOCAL_PROTECTION_SCHEME {
            return Err(migration_target_mismatch());
        }
        return Ok(());
    }
    let protected_reference =
        protect_local(case_file.storage_reference.as_bytes()).map_err(|_| {
            migration_error(
                "legacy_reference_protection_failed",
                "A legacy CaseFile storage reference could not be protected.",
            )
        })?;
    transaction
        .execute(
            "INSERT INTO case_material_legacy_references(
                legacy_reference_id,material_id,migration_id,source_store,source_table,
                source_key,protected_storage_reference_blob,storage_reference_sha256,
                protection_scheme
             ) VALUES(?1,?2,?3,?4,'case_files',?5,?6,?7,?8)",
            params![
                legacy_reference_id(&case_file.file_id),
                material_id,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
                protected_reference,
                reference_hash,
                LOCAL_PROTECTION_SCHEME,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn case_file_fingerprint(
    case_file: &CaseFileSource,
    user: &UserSnapshot,
    resolution: &AttachmentResolution<'_>,
) -> String {
    let mut fingerprint = Fingerprint::new(b"user-case-file");
    fingerprint.text(&case_file.file_id);
    fingerprint.text(&case_file.project_id);
    fingerprint.text(&case_file.title);
    fingerprint.text(&case_file.file_type);
    fingerprint.text(&case_file.storage_reference);
    fingerprint.text(&case_file.summary);
    fingerprint.text(&case_file.created_at);
    match resolution {
        AttachmentResolution::Exact(attachment) => {
            append_attachment_fingerprint(&mut fingerprint, attachment);
        }
        AttachmentResolution::Legacy(error) | AttachmentResolution::Blocked(error) => {
            fingerprint.text(error);
            for attachment in matching_attachment_candidates(user, case_file) {
                append_attachment_fingerprint(&mut fingerprint, attachment);
            }
        }
    }
    fingerprint.finish()
}

fn matching_attachment_candidates<'a>(
    user: &'a UserSnapshot,
    case_file: &CaseFileSource,
) -> Vec<&'a AttachmentSource> {
    attachment_reference_candidate_ids(&case_file.storage_reference)
        .into_iter()
        .filter_map(|identifier| user.attachments.get(identifier))
        .collect()
}

fn attachment_reference_candidate_ids(raw: &str) -> BTreeSet<&str> {
    let mut identifiers = BTreeSet::from([raw]);
    let mut remainder = raw;
    let mut prefix_count = 0_u8;
    while let Some(stripped) = remainder.strip_prefix("attachment:") {
        prefix_count = prefix_count.saturating_add(1);
        remainder = stripped;
        if prefix_count > 2 {
            return identifiers;
        }
    }
    if prefix_count >= 1 {
        identifiers.insert(
            raw.strip_prefix("attachment:")
                .expect("a counted prefix must strip"),
        );
    }
    if prefix_count == 2 {
        identifiers.insert(remainder);
    }
    identifiers
}

fn append_attachment_fingerprint(fingerprint: &mut Fingerprint, attachment: &AttachmentSource) {
    fingerprint.text(&attachment.attachment_id);
    fingerprint.optional_text(attachment.project_id.as_deref());
    fingerprint.text(&attachment.original_name);
    fingerprint.text(&attachment.extension);
    fingerprint.text(&attachment.detected_mime);
    fingerprint.text(&attachment.sha256);
    fingerprint.integer(attachment.size_bytes);
    fingerprint.text(&attachment.extraction_status);
    fingerprint.optional_text(attachment.extracted_text_sha256.as_deref());
    fingerprint.text(&attachment.segments_json_sha256);
    fingerprint.optional_text(attachment.error_code.as_deref());
    fingerprint.text(&attachment.created_at);
}

fn deterministic_case_file_material_id(workspace_instance_id: &str, file_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MATERIAL_ID_DOMAIN);
    hasher.update(workspace_instance_id.as_bytes());
    hasher.update(b"\0user.sqlite\0case_files\0");
    hasher.update(file_id.as_bytes());
    format!("mat_{}", &format!("{:x}", hasher.finalize())[..32])
}

fn legacy_reference_id(file_id: &str) -> String {
    let mut fingerprint = Fingerprint::new(b"legacy-reference");
    fingerprint.text(CASE_MATERIAL_MIGRATION_ID);
    fingerprint.text(file_id);
    format!("legacyref_{}", &fingerprint.finish()[..32])
}

fn validate_target_invariants(
    connection: &Connection,
    user: &UserSnapshot,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<(), PrivacyWorkflowError> {
    for case_file in &user.case_files {
        let covered: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM case_material_migration_ledger
                    WHERE migration_id=?1 AND source_store=?2
                      AND source_table='case_files' AND source_key=?3
                      AND result_state IN('migrated','legacy_reference','blocked')
                 )",
                params![
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    case_file.file_id
                ],
                |row| row.get(0),
            )
            .map_err(|_| privacy_migration_store_error())?;
        if !covered {
            return Err(migration_target_mismatch());
        }
    }
    let bad_generations: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM privacy_redactions
                WHERE generation_number<=0
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if bad_generations {
        return Err(migration_target_mismatch());
    }
    let missing_material_target: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM case_material_migration_ledger AS ledger
                LEFT JOIN privacy_materials AS material
                  ON material.material_id=ledger.target_material_id
                WHERE ledger.migration_id=?1
                  AND ledger.source_table<>'source_manifest'
                  AND material.material_id IS NULL
             )",
            [CASE_MATERIAL_MIGRATION_ID],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if missing_material_target {
        return Err(migration_target_mismatch());
    }
    let missing_redaction_targets = {
        let mut statement = connection
            .prepare(
                "SELECT ledger.target_redaction_id,ledger.target_material_id,
                        ledger.assigned_generation_number
                 FROM case_material_migration_ledger AS ledger
                 LEFT JOIN privacy_redactions AS redaction
                   ON redaction.redaction_id=ledger.target_redaction_id
                  AND redaction.material_id=ledger.target_material_id
                  AND redaction.generation_number=ledger.assigned_generation_number
                 WHERE ledger.migration_id=?1
                   AND ledger.target_redaction_id IS NOT NULL
                   AND redaction.redaction_id IS NULL
                 ORDER BY ledger.target_redaction_id",
            )
            .map_err(|_| privacy_migration_store_error())?;
        let targets = statement
            .query_map([CASE_MATERIAL_MIGRATION_ID], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| privacy_migration_store_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| privacy_migration_store_error())?;
        targets
    };
    if !missing_redaction_targets.is_empty() {
        for (redaction_id, material_id, generation_number) in missing_redaction_targets {
            if cleanup.redactions.get(&redaction_id) != Some(&(material_id, generation_number)) {
                return Err(migration_target_mismatch());
            }
        }
    }
    let privacy_sources = load_privacy_sources(connection)?;
    let mut project_statement = connection
        .prepare(
            "SELECT DISTINCT project_id
             FROM privacy_materials
             WHERE migration_status='ready' AND project_id IS NOT NULL",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let ready_projects = project_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    for project_value in ready_projects {
        if !user.projects.contains_key(&project_value) {
            let project_sources = privacy_sources
                .iter()
                .filter(|source| {
                    source.project_id.as_deref() == Some(project_value.as_str())
                        && source.migration_status == "ready"
                })
                .collect::<Vec<_>>();
            if project_sources.is_empty() {
                return Err(migration_target_mismatch());
            }
            for source in project_sources {
                if !completed_project_deletion_tombstone(connection, user, source, cleanup)? {
                    return Err(migration_target_mismatch());
                }
            }
            continue;
        }
        let project =
            ProjectId::parse(project_value).map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .ok_or_else(migration_target_mismatch)?;
        let conflict: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM privacy_materials AS material
                    JOIN privacy_vault_material_refs AS vault
                      ON vault.material_id=material.material_id
                    WHERE material.project_id=?1 AND material.migration_status='ready'
                      AND material.source_kind='vault' AND vault.case_id<>?2
                 )",
                params![project.as_str(), case_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| privacy_migration_store_error())?;
        if conflict {
            return Err(migration_target_mismatch());
        }
    }
    Ok(())
}

fn query_manifest(
    connection: &Connection,
    sql: &str,
    columns: usize,
) -> Result<String, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| source_snapshot_error())?;
    let mut rows = statement.query([]).map_err(|_| source_snapshot_error())?;
    let mut fingerprint = Fingerprint::new(b"sqlite-manifest");
    while let Some(row) = rows.next().map_err(|_| source_snapshot_error())? {
        for index in 0..columns {
            match row.get_ref(index).map_err(|_| source_snapshot_error())? {
                ValueRef::Null => fingerprint.optional(None),
                ValueRef::Integer(value) => fingerprint.value(&value.to_be_bytes()),
                ValueRef::Real(value) => fingerprint.value(&value.to_bits().to_be_bytes()),
                ValueRef::Text(value) | ValueRef::Blob(value) => fingerprint.value(value),
            }
        }
    }
    Ok(fingerprint.finish())
}

fn primary_key_manifest(
    connection: &Connection,
    sql: &str,
) -> Result<String, PrivacyWorkflowError> {
    query_manifest(connection, sql, 1)
}

fn source_rows_manifest(connection: &Connection) -> Result<String, PrivacyWorkflowError> {
    let projects = query_manifest(
        connection,
        "SELECT project_id,title,case_type,status,opened_on,summary,created_at,updated_at
         FROM projects ORDER BY project_id",
        8,
    )?;
    let case_files = query_manifest(
        connection,
        "SELECT file_id,project_id,title,file_type,storage_reference,summary,created_at
         FROM case_files ORDER BY file_id",
        7,
    )?;
    let attachments = query_manifest(
        connection,
        "SELECT attachment_id,project_id,original_name,extension,detected_mime,sha256,
                size_bytes,extraction_status,extracted_text,segments_json,error_code,created_at
         FROM attachments ORDER BY attachment_id",
        12,
    )?;
    let mut fingerprint = Fingerprint::new(b"user-source-rows");
    fingerprint.text(&projects);
    fingerprint.text(&case_files);
    fingerprint.text(&attachments);
    Ok(fingerprint.finish())
}

fn file_sha256(path: &Path) -> Result<String, PrivacyWorkflowError> {
    let file = File::open(path).map_err(|_| source_snapshot_error())?;
    hash_open_file(file)
}

fn sqlite_sidecar_sha256(
    database_path: &Path,
    suffix: &str,
) -> Result<Option<String>, PrivacyWorkflowError> {
    let mut sidecar = database_path.as_os_str().to_os_string();
    sidecar.push(suffix);
    match File::open(Path::new(&sidecar)) {
        Ok(file) => hash_open_file(file).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(source_snapshot_error()),
    }
}

fn hash_open_file(mut file: File) -> Result<String, PrivacyWorkflowError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| source_snapshot_error())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct Fingerprint {
    hasher: Sha256,
}

impl Fingerprint {
    fn new(profile: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update((profile.len() as u64).to_be_bytes());
        hasher.update(profile);
        Self { hasher }
    }

    fn value(&mut self, value: &[u8]) {
        self.hasher.update([1]);
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
    }

    fn text(&mut self, value: &str) {
        self.value(value.as_bytes());
    }

    fn integer(&mut self, value: i64) {
        self.value(&value.to_be_bytes());
    }

    fn optional(&mut self, value: Option<&[u8]>) {
        match value {
            Some(value) => self.value(value),
            None => self.hasher.update([0]),
        }
    }

    fn optional_text(&mut self, value: Option<&str>) {
        self.optional(value.map(str::as_bytes));
    }

    fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}

fn migration_error(code: &'static str, message: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(code, message)
}

fn source_snapshot_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_source_snapshot_failed",
        "The immutable user-database migration snapshot could not be verified.",
    )
}

fn privacy_preflight_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_privacy_preflight_failed",
        "The Privacy database failed migration integrity or referential checks.",
    )
}

fn cleanup_preflight_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_cleanup_preflight_failed",
        "Pending cleanup state could not be verified without modifying the Privacy or Vault stores.",
    )
}

fn cleanup_pending_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_cleanup_pending",
        "The case-material migration is blocked until prepared or committed cleanup work reaches a terminal state.",
    )
}

fn missing_vault_history_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_vault_missing_with_history",
        "The Vault is missing while the Privacy store still contains Vault-bound historical identity.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig},
        privacy_workflow::{
            test_workspace_instance_id, ApprovedPublicationInvalidator, LocalOcrExecutionContext,
            PrivacyReviewView,
        },
    };
    use privacy::{
        vault_store::{VaultPrivateMetadataInputV1, VaultStore},
        vnext::{CaseId, MaterialId},
        ReceiptSigner, RetentionPolicyV1,
    };
    use rusqlite::Connection;
    use serde_json::json;
    use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};

    const PROJECT_A: &str = "case-migration-project-a";
    const PROJECT_B: &str = "case-migration-project-b";

    struct NoopPublicationInvalidator;

    impl ApprovedPublicationInvalidator for NoopPublicationInvalidator {
        fn invalidate_case(
            &self,
            _case_id: &CaseId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_material(
            &self,
            _case_id: &CaseId,
            _material_id: &MaterialId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_lifecycle_bindings(
            &self,
            _lifecycle_binding_ids: &BTreeSet<String>,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        user_database_path: PathBuf,
        manager: PrivacyWorkflowManager,
    }

    impl Fixture {
        fn new(projects: &[&str]) -> Self {
            let directory = tempfile::tempdir().expect("migration fixture directory");
            let user_database_path =
                database::ensure_user_database(directory.path()).expect("canonical user database");
            let connection =
                database::open_user_database(&user_database_path).expect("open user database");
            for project_id in projects {
                insert_project(&connection, project_id);
            }
            drop(connection);
            let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("privacy manager");
            manager.set_test_runtime(
                ReceiptSigner::new([29_u8; 32]).expect("migration test signer"),
                1_800_000_000,
            );
            Self {
                _directory: directory,
                user_database_path,
                manager,
            }
        }

        fn user_connection(&self) -> Connection {
            database::open_user_database(&self.user_database_path)
                .expect("writable user database fixture")
        }

        fn add_attachment(
            &self,
            attachment_id: &str,
            project_id: Option<&str>,
            original_name: &str,
            content: &[u8],
        ) {
            let connection = self.user_connection();
            database::insert_attachment(
                &connection,
                &database::NewAttachmentRow {
                    attachment_id: attachment_id.to_owned(),
                    project_id: project_id.map(str::to_owned),
                    original_name: original_name.to_owned(),
                    extension: "txt".to_owned(),
                    detected_mime: "text/plain".to_owned(),
                    sha256: sha256_hex(content),
                    size_bytes: i64::try_from(content.len()).expect("small fixture"),
                    content_blob: content.to_vec(),
                    extraction_status: "succeeded".to_owned(),
                    extracted_text: Some(String::from_utf8_lossy(content).into_owned()),
                    segments_json: "[]".to_owned(),
                    error_code: None,
                },
            )
            .expect("insert attachment");
        }

        fn add_case_file(
            &self,
            file_id: &str,
            project_id: &str,
            title: &str,
            storage_reference: &str,
        ) {
            database::upsert_case_file(
                &self.user_connection(),
                &database::CaseFileRow {
                    file_id: file_id.to_owned(),
                    project_id: project_id.to_owned(),
                    title: title.to_owned(),
                    file_type: "evidence".to_owned(),
                    storage_reference: storage_reference.to_owned(),
                    summary: "fixture summary".to_owned(),
                    created_at: String::new(),
                },
            )
            .expect("insert case file");
        }

        fn prepare_project_material(
            &self,
            project_id: &str,
            source_name: &str,
        ) -> PrivacyReviewView {
            let path = self._directory.path().join(source_name);
            fs::write(
                &path,
                "Synthetic project material: Alice Example, 13800138000.",
            )
            .expect("write project material");
            self.manager
                .prepare_case_selected_material_with_qualification(
                    &path,
                    &PrivacyConfig::default(),
                    &local_ocr_status(),
                    LocalOcrExecutionContext {
                        mineru_config: None,
                        qualification: None,
                    },
                    project_id.to_owned(),
                    Vec::new(),
                )
                .expect("prepare project material")
        }
    }

    fn local_ocr_status() -> LocalOcrStatus {
        LocalOcrStatus {
            code: LocalOcrStatusCode::Disabled,
            message: "disabled for migration lifecycle fixture".to_owned(),
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

    fn expire_project_generation(fixture: &Fixture, redaction_id: &str, cleanup_id: &str) {
        let mut connection = fixture.manager.open_connection().expect("privacy store");
        let changed = connection
            .execute(
                "UPDATE privacy_retention_bindings
                 SET expires_at_unix=1799999999
                 WHERE redaction_id=?1",
                [redaction_id],
            )
            .expect("expire project generation");
        assert_eq!(changed, 1);
        let lifecycle =
            PrivacyLifecycle::open(&connection, test_workspace_instance_id()).expect("lifecycle");
        lifecycle
            .run_retention_sweep(&mut connection, cleanup_id, 1_800_000_001)
            .expect("project generation retention cleanup");
    }

    fn project_material_provenance(
        fixture: &Fixture,
        material_id: &str,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        i64,
    ) {
        fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .query_row(
                "SELECT material.project_id,material.source_kind,material.source_sha256,
                        vault.case_id,vault.object_id,vault.object_version,
                        vault.source_sha256,vault.envelope_sha256,vault.content_bytes
                 FROM privacy_materials AS material
                 JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.material_id=?1",
                [material_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .expect("project material provenance")
    }

    fn exercise_project_deletion_retention_order(
        retention_first: bool,
        tamper_retained_provenance: bool,
    ) {
        let fixture = Fixture::new(&[PROJECT_A]);
        if !retention_first {
            fixture
                .manager
                .run_case_material_migration_after_backup()
                .expect("projects-only migration before new material");
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("projects-only terminal probe"));
        }
        let review = fixture.prepare_project_material(
            PROJECT_A,
            if retention_first {
                "retention-before-project-delete.txt"
            } else {
                "project-delete-before-retention.txt"
            },
        );
        if retention_first {
            fixture
                .manager
                .run_case_material_migration_after_backup()
                .expect("initial project material migration");
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("initial project material terminal probe"));
        }
        let provenance_before = project_material_provenance(&fixture, &review.material_id);
        let evidence_before: (i64, i64) = fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM case_material_migration_ledger
                    WHERE target_material_id=?1),
                   (SELECT COUNT(*) FROM case_material_migration_events
                    WHERE target_material_id=?1)",
                [&review.material_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("material migration evidence");
        if !retention_first {
            assert_eq!(
                evidence_before,
                (0, 0),
                "post-migration material must exercise the project-deletion tombstone branch"
            );
        }

        if retention_first {
            expire_project_generation(
                &fixture,
                &review.redaction_id,
                "cln_dddddddddddddddddddddddddddddddd",
            );
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("retention-before-delete is terminal"));
        }

        assert!(fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_A)
            .expect("delete project"));
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("project source deletion changes the source manifest"));
        let deletion_report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("project deletion migration restart");
        assert_eq!(deletion_report.privacy_materials_migrated, 0);
        assert_eq!(deletion_report.redaction_generations_migrated, 0);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("project deletion tombstone is terminal"));

        if !retention_first {
            let deletion_state = fixture
                .manager
                .open_connection()
                .expect("privacy after project deletion")
                .query_row(
                    "SELECT material.project_id,material.source_kind,material.state,
                            material.deleted_at IS NOT NULL,vault.import_state,
                            vault.failure_code
                     FROM privacy_materials AS material
                     JOIN privacy_vault_material_refs AS vault
                       ON vault.material_id=material.material_id
                     WHERE material.material_id=?1",
                    [&review.material_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .expect("project deletion tombstone");
            assert_eq!(
                deletion_state,
                (
                    PROJECT_A.to_owned(),
                    "vault".to_owned(),
                    "revoked".to_owned(),
                    true,
                    "revoked".to_owned(),
                    Some("project_deleted".to_owned()),
                )
            );
            expire_project_generation(
                &fixture,
                &review.redaction_id,
                "cln_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            );
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("delete-before-retention composed tombstone is terminal"));
        }

        let connection = fixture.manager.open_connection().expect("final privacy");
        let final_state = connection
            .query_row(
                "SELECT material.state,material.deleted_at IS NOT NULL,
                        material.protected_display_name,material.display_name_sha256,
                        material.display_name_protection_scheme,
                        vault.import_state,vault.failure_code
                 FROM privacy_materials AS material
                 JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.material_id=?1",
                [&review.material_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .expect("composed tombstone");
        assert_eq!(final_state.0, "revoked");
        assert!(final_state.1);
        assert_eq!(
            (final_state.2, final_state.3, final_state.4),
            (None, None, None)
        );
        assert_eq!(final_state.5, "revoked");
        assert_eq!(final_state.6.as_deref(), Some("retention_expired"));
        drop(connection);
        assert_eq!(
            project_material_provenance(&fixture, &review.material_id),
            provenance_before
        );
        let evidence_after: (i64, i64) = fixture
            .manager
            .open_connection()
            .expect("privacy evidence")
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM case_material_migration_ledger
                    WHERE target_material_id=?1),
                   (SELECT COUNT(*) FROM case_material_migration_events
                    WHERE target_material_id=?1)",
                [&review.material_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("final material migration evidence");
        assert_eq!(evidence_after, evidence_before);
        if tamper_retained_provenance {
            fixture
                .manager
                .open_connection()
                .expect("privacy provenance tamper")
                .execute(
                    "UPDATE privacy_materials
                     SET source_name_sha256=?2,row_version=row_version+1
                     WHERE material_id=?1",
                    params![
                        review.material_id,
                        sha256_hex(b"tampered retained provenance")
                    ],
                )
                .expect("simulate retained provenance drift");
            let error = fixture
                .manager
                .case_material_migration_required()
                .expect_err("retained provenance drift must fail closed");
            assert_eq!(error.code(), "case_material_migration_target_mismatch");
        }
    }

    fn insert_project(connection: &Connection, project_id: &str) {
        database::upsert_case_project(
            connection,
            &database::CaseProjectRow {
                project_id: project_id.to_owned(),
                title: format!("Project {project_id}"),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("insert project");
    }

    #[test]
    fn empty_databases_finish_with_persistent_read_only_terminal_probe() {
        let fixture = Fixture::new(&[]);
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("initial probe"));
        let user_before = fs::read(&fixture.user_database_path).expect("user bytes before");
        let report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("empty migration");
        assert!(report.source_unchanged_verified);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("user bytes after"),
            user_before
        );

        let privacy_before =
            fs::read(&fixture.manager.shared.database_path).expect("privacy bytes before probe");
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("terminal probe"));
        assert_eq!(
            fs::read(&fixture.manager.shared.database_path).expect("privacy bytes after probe"),
            privacy_before,
            "the startup probe must be strictly read-only"
        );
    }

    #[test]
    fn unrelated_user_rows_do_not_change_semantic_source_or_repeat_migration() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let fingerprint = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("initial semantic fingerprint");
        fixture
            .manager
            .run_case_material_migration_after_backup_for_source(&fingerprint)
            .expect("initial fingerprint-bound migration");
        fixture
            .user_connection()
            .execute(
                "INSERT INTO conversations(conversation_id,project_id,title,status)
                 VALUES('conversation-unrelated',NULL,'Unrelated assistant chat','open')",
                [],
            )
            .expect("insert unrelated assistant row");

        assert_eq!(
            fixture
                .manager
                .case_material_migration_source_fingerprint()
                .expect("fingerprint after unrelated write"),
            fingerprint
        );
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("unrelated write must not require migration"));
    }

    #[test]
    fn source_table_change_updates_semantic_fingerprint_and_rejects_stale_backup_token() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let fingerprint = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("initial semantic fingerprint");
        fixture
            .user_connection()
            .execute(
                "UPDATE projects SET title='Changed migration source'
                 WHERE project_id=?1",
                [PROJECT_A],
            )
            .expect("change source table");
        let changed = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("changed semantic fingerprint");
        assert_ne!(changed, fingerprint);

        let error = fixture
            .manager
            .run_case_material_migration_after_backup_for_source(&fingerprint)
            .expect_err("stale backup source token must fail");
        assert_eq!(error.code(), "case_material_backup_source_mismatch");
        let privacy = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            privacy
                .query_row(
                    "SELECT COUNT(*) FROM project_privacy_case_bindings",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("binding count"),
            0
        );
        assert_eq!(
            privacy
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("ledger count"),
            0
        );
    }

    #[test]
    fn empty_privacy_rejects_existing_nonempty_vault_inventory_without_writes() {
        let directory = tempfile::tempdir().expect("empty Privacy inventory fixture");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("canonical user database");
        let user = database::open_user_database(&user_database_path).expect("open user database");
        insert_project(&user, PROJECT_A);
        drop(user);
        let vault_root = directory.path().join(vault_broker::VAULT_ROOT_DIRECTORY);
        let vault = VaultStore::initialize(&vault_root, test_workspace_instance_id())
            .expect("initialize existing Vault");
        let case_id =
            CaseId::parse("case_44444444444444444444444444444444").expect("synthetic Vault case");
        vault
            .create_source_object(
                &case_id,
                VaultPrivateMetadataInputV1 {
                    original_file_name: "unbound-existing.pdf".to_owned(),
                    original_source_path: None,
                    original_media_type: "application/pdf".to_owned(),
                    imported_at_unix: 100,
                },
                b"unbound existing Vault content",
                100,
            )
            .expect("create existing Vault inventory");
        vault
            .prepare_encrypted_backup_snapshot()
            .expect("checkpoint Vault inventory");
        drop(vault);
        let vault_database = vault_root.join("vault-state.sqlite");
        let before_database = fs::read(&vault_database).expect("Vault before startup probe");

        let manager =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("deferred manager");
        let error = manager
            .case_material_migration_required()
            .expect_err("unbound Vault inventory must fail closed");

        assert_eq!(error.code(), "case_material_unbound_vault_inventory");
        assert_eq!(
            fs::read(&vault_database).expect("Vault after startup probe"),
            before_database
        );
        assert!(!manager.shared.database_path.exists());
    }

    #[test]
    fn privacy_prepared_cleanup_blocks_migration_without_mutating_the_store() {
        let fixture = Fixture::new(&[]);
        let connection = fixture.manager.open_connection().expect("privacy store");
        connection
            .execute(
                "INSERT INTO privacy_cleanup_journal(
                    cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                    candidate_count,removed_count,keys_destroyed,error_code,
                    previous_event_hash,event_hash,erasure_disclosure
                 ) VALUES(
                    'cln_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'prepared',1,100,NULL,0,0,0,NULL,'','',?1
                 )",
                [privacy::LOGICAL_ERASURE_DISCLOSURE],
            )
            .expect("insert pending privacy cleanup");
        drop(connection);
        let database = &fixture.manager.shared.database_path;
        let before = fs::read(database).expect("privacy bytes before blocked probe");
        let modified = fs::metadata(database)
            .expect("privacy metadata before blocked probe")
            .modified()
            .expect("privacy mtime before blocked probe");

        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("prepared privacy cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(database).expect("privacy bytes after blocked probe"),
            before
        );
        assert_eq!(
            fs::metadata(database)
                .expect("privacy metadata after blocked probe")
                .modified()
                .expect("privacy mtime after blocked probe"),
            modified
        );
    }

    #[test]
    fn vault_prepared_and_committed_cleanup_block_without_mutating_vault_database() {
        let fixture = Fixture::new(&[]);
        let vault_database = fixture
            .user_database_path
            .parent()
            .expect("application root")
            .join(vault_broker::VAULT_ROOT_DIRECTORY)
            .join("vault-state.sqlite");
        let connection = Connection::open(&vault_database).expect("vault fixture database");
        connection
            .execute(
                "INSERT INTO vault_cleanup_journal(
                    cleanup_id,state,started_at_unix,completed_at_unix,candidate_count,
                    removed_count,key_records_destroyed,previous_event_hash,event_hash,
                    erasure_disclosure
                 ) VALUES(
                    'cln_cccccccccccccccccccccccccccccccc',
                    'prepared',100,NULL,0,0,0,'','',?1
                 )",
                [privacy::VAULT_LOGICAL_ERASURE_DISCLOSURE],
            )
            .expect("insert prepared Vault cleanup");
        drop(connection);
        let prepared_bytes = fs::read(&vault_database).expect("prepared Vault bytes");
        let prepared_modified = fs::metadata(&vault_database)
            .expect("prepared Vault metadata")
            .modified()
            .expect("prepared Vault mtime");
        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("prepared Vault cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(&vault_database).expect("Vault bytes after prepared probe"),
            prepared_bytes
        );
        assert_eq!(
            fs::metadata(&vault_database)
                .expect("Vault metadata after prepared probe")
                .modified()
                .expect("Vault mtime after prepared probe"),
            prepared_modified
        );

        let connection = Connection::open(&vault_database).expect("Vault committed fixture");
        connection
            .execute(
                "UPDATE vault_cleanup_journal
                 SET state='committed',completed_at_unix=101
                 WHERE cleanup_id='cln_cccccccccccccccccccccccccccccccc'
                   AND state='prepared'",
                [],
            )
            .expect("mark Vault cleanup committed");
        drop(connection);
        let committed_bytes = fs::read(&vault_database).expect("committed Vault bytes");
        let committed_modified = fs::metadata(&vault_database)
            .expect("committed Vault metadata")
            .modified()
            .expect("committed Vault mtime");
        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("committed Vault cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(&vault_database).expect("Vault bytes after committed probe"),
            committed_bytes
        );
        assert_eq!(
            fs::metadata(&vault_database)
                .expect("Vault metadata after committed probe")
                .modified()
                .expect("Vault mtime after committed probe"),
            committed_modified
        );
    }

    #[test]
    fn projects_only_receive_distinct_random_persistent_bindings_and_rerun_is_noop() {
        let fixture = Fixture::new(&[PROJECT_A, PROJECT_B]);
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("projects-only migration");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let project_a = ProjectId::parse(PROJECT_A).expect("project A");
        let project_b = ProjectId::parse(PROJECT_B).expect("project B");
        let case_a = ProjectPrivacyCaseBindingStore::resolve(&connection, &project_a)
            .expect("resolve A")
            .expect("binding A");
        let case_b = ProjectPrivacyCaseBindingStore::resolve(&connection, &project_b)
            .expect("resolve B")
            .expect("binding B");
        assert_ne!(case_a, case_b);
        assert!(case_a.as_str().starts_with("case_"));
        assert!(case_b.as_str().starts_with("case_"));
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("completed probe"));

        let second = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("idempotent rerun");
        assert_eq!(second.bindings_created_or_verified, 0);
        assert!(second.idempotent_noops >= 3);
        let connection = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_a)
                .expect("resolve A again"),
            Some(case_a)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM project_privacy_case_bindings",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("binding count"),
            2
        );
    }

    #[test]
    fn exact_attachment_and_legacy_case_files_migrate_without_copying_source_blob() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-exact",
            Some(PROJECT_A),
            "original-private-name.txt",
            b"exact attachment bytes",
        );
        fixture.add_case_file(
            "file-exact",
            PROJECT_A,
            "用户材料标题",
            "attachment:attachment:attachment-exact",
        );
        fixture.add_case_file(
            "file-legacy",
            PROJECT_A,
            "旧引用",
            r"C:\historical\never-read.txt",
        );
        let source_before = fs::read(&fixture.user_database_path).expect("source before");
        let report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("case-file migration");
        assert_eq!(report.case_files_migrated, 2);
        assert_eq!(report.legacy_references, 1);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("source after"),
            source_before
        );

        let connection = fixture.manager.open_connection().expect("privacy store");
        let exact_id = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-exact",
        );
        let exact = connection
            .query_row(
                "SELECT project_id,attachment_id,source_kind,migration_status,state,source_sha256
                 FROM privacy_materials WHERE material_id=?1",
                [&exact_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .expect("exact target");
        assert_eq!(exact.0, PROJECT_A);
        assert_eq!(exact.1, "attachment-exact");
        assert_eq!(exact.2, "user_attachment");
        assert_eq!(exact.3, "ready");
        assert_eq!(exact.4, "registered");
        assert_eq!(exact.5, sha256_hex(b"exact attachment bytes"));

        let legacy_id = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-legacy",
        );
        let protected = connection
            .query_row(
                "SELECT reference.protected_storage_reference_blob
                 FROM case_material_legacy_references AS reference
                 JOIN privacy_materials AS material
                   ON material.material_id=reference.material_id
                 WHERE reference.material_id=?1
                   AND material.source_kind='legacy_reference'
                   AND material.migration_status='legacy_reference'",
                [&legacy_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("protected legacy provenance");
        assert_eq!(
            unprotect_local(&protected).expect("unprotect legacy provenance"),
            br"C:\historical\never-read.txt"
        );
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("case-file terminal probe"));
    }

    #[test]
    fn changed_case_file_appends_source_changed_event_and_updates_exact_projection() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-source-change",
            Some(PROJECT_A),
            "source-change.txt",
            b"stable source bytes",
        );
        fixture.add_case_file(
            "file-source-change",
            PROJECT_A,
            "初始标题",
            "attachment:attachment-source-change",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("initial migration");

        fixture.add_case_file(
            "file-source-change",
            PROJECT_A,
            "更新后的标题",
            "attachment:attachment-source-change",
        );
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("changed source requires migration"));
        let source_before = fs::read(&fixture.user_database_path).expect("changed source before");
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("source-changed migration");
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("changed source after"),
            source_before
        );

        let connection = fixture.manager.open_connection().expect("privacy store");
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-source-change",
        );
        let (event_type, material_id, protected_display_name, display_hash): (
            String,
            String,
            Vec<u8>,
            String,
        ) = connection
            .query_row(
                "SELECT event.event_type,material.material_id,material.protected_display_name,
                            material.display_name_sha256
                     FROM case_material_migration_events AS event
                     JOIN privacy_materials AS material
                       ON material.material_id=event.target_material_id
                     WHERE event.migration_id=?1 AND event.source_store=?2
                       AND event.source_table='case_files'
                       AND event.source_key='file-source-change'
                     ORDER BY event.rowid DESC LIMIT 1",
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("source-changed event");
        assert_eq!(event_type, "source_changed");
        assert_eq!(material_id, target);
        assert_eq!(
            unprotect_local(&protected_display_name).expect("updated protected display"),
            "更新后的标题".as_bytes()
        );
        assert_eq!(display_hash, sha256_hex("更新后的标题".as_bytes()));
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("updated terminal probe"));
    }

    #[test]
    fn repeat_probe_fails_closed_when_exact_target_projection_drifts() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-target-drift",
            Some(PROJECT_A),
            "target-drift.txt",
            b"target drift bytes",
        );
        fixture.add_case_file(
            "file-target-drift",
            PROJECT_A,
            "目标漂移",
            "attachment:attachment-target-drift",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("initial migration");
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-target-drift",
        );
        fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .execute(
                "UPDATE privacy_materials
                 SET display_name_sha256=?2,row_version=row_version+1
                 WHERE material_id=?1",
                params![target, sha256_hex(b"tampered display")],
            )
            .expect("tamper target projection");

        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("target drift must fail closed");
        assert_eq!(error.code(), "case_material_migration_target_mismatch");
    }

    #[test]
    fn ambiguous_attachment_reference_is_blocked_without_guessing() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment:ambiguous",
            Some(PROJECT_A),
            "first.txt",
            b"first",
        );
        fixture.add_attachment("ambiguous", Some(PROJECT_A), "second.txt", b"second");
        fixture.add_case_file(
            "file-ambiguous",
            PROJECT_A,
            "歧义引用",
            "attachment:ambiguous",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("ambiguous migration is terminal, not fatal");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let result = connection
            .query_row(
                "SELECT ledger.result_state,ledger.error_code,material.migration_status
                 FROM case_material_migration_ledger AS ledger
                 JOIN privacy_materials AS material
                   ON material.material_id=ledger.target_material_id
                 WHERE ledger.migration_id=?1 AND ledger.source_store=?2
                   AND ledger.source_table='case_files' AND ledger.source_key='file-ambiguous'",
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("blocked ledger");
        assert_eq!(
            result,
            (
                "blocked".to_owned(),
                "attachment_reference_ambiguous".to_owned(),
                "blocked".to_owned()
            )
        );
    }

    #[test]
    fn cross_project_and_ownerless_exact_attachments_are_blocked_with_stable_codes() {
        let fixture = Fixture::new(&[PROJECT_A, PROJECT_B]);
        fixture.add_attachment(
            "attachment-cross-project",
            Some(PROJECT_B),
            "cross-project.txt",
            b"cross project",
        );
        fixture.add_attachment("attachment-ownerless", None, "ownerless.txt", b"ownerless");
        fixture.add_case_file(
            "file-cross-project",
            PROJECT_A,
            "跨项目附件",
            "attachment:attachment-cross-project",
        );
        fixture.add_case_file(
            "file-ownerless",
            PROJECT_A,
            "无归属附件",
            "attachment:attachment-ownerless",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("ownership conflicts are terminal blocked rows");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let mut statement = connection
            .prepare(
                "SELECT source_key,error_code,result_state
                 FROM case_material_migration_ledger
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='case_files'
                 ORDER BY source_key",
            )
            .expect("ownership ledgers");
        let rows = statement
            .query_map(
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("query ownership ledgers")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect ownership ledgers");
        assert_eq!(
            rows,
            vec![
                (
                    "file-cross-project".to_owned(),
                    "attachment_project_conflict".to_owned(),
                    "blocked".to_owned()
                ),
                (
                    "file-ownerless".to_owned(),
                    "attachment_owner_unknown".to_owned(),
                    "blocked".to_owned()
                ),
            ]
        );
        drop(statement);
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("blocked ownership terminal probe"));
    }

    #[test]
    fn valid_v4_history_is_upgraded_only_explicitly_then_backfilled_with_stable_generation() {
        let directory = tempfile::tempdir().expect("legacy fixture");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let privacy_directory = directory.path().join("privacy");
        fs::create_dir_all(&privacy_directory).expect("privacy directory");
        let privacy_path = privacy_directory.join("privacy-workflow.sqlite");
        create_valid_v4_history(&privacy_path);

        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("legacy-compatible manager");
        assert!(manager.privacy_store_schema_upgrade_required());
        assert!(manager
            .case_material_migration_required()
            .expect("v4 requires migration"));
        let unchanged_version: String = Connection::open(&privacy_path)
            .expect("legacy database")
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("legacy version");
        assert_eq!(unchanged_version, "4");

        manager
            .upgrade_privacy_store_schema_after_backup()
            .expect("explicit post-backup upgrade");
        let user_before = fs::read(&user_database_path).expect("user source before");
        manager
            .run_case_material_migration_after_backup()
            .expect("valid history backfill");
        assert_eq!(
            fs::read(&user_database_path).expect("user source after"),
            user_before
        );
        let connection = manager.open_connection().expect("upgraded privacy store");
        let material = connection
            .query_row(
                "SELECT project_id,legacy_case_id,migration_status,display_name_sha256
                 FROM privacy_materials WHERE material_id='mat_legacyvalid00000000000000000000'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .expect("legacy material");
        assert_eq!(material.0, None);
        assert_eq!(
            material.1.as_deref(),
            Some("case_99999999999999999999999999999999")
        );
        assert_eq!(material.2, "unassigned");
        assert_eq!(
            material.3.as_deref(),
            Some(sha256_hex("历史材料.pdf".as_bytes()).as_str())
        );
        let generation = connection
            .query_row(
                "SELECT generation_number,generation_status,risk_revision
                 FROM privacy_redactions
                 WHERE redaction_id='red_11111111111111111111111111111111'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("legacy generation");
        assert_eq!(generation, (1, "ready".to_owned(), 0));
        drop(connection);
        assert!(!manager
            .case_material_migration_required()
            .expect("legacy orphan identity is a terminal no-op"));
        let connection = manager.open_connection().expect("privacy store");
        assert!(connection
            .execute(
                "UPDATE privacy_materials
                 SET legacy_case_id=?2,row_version=row_version+1
                 WHERE material_id=?1",
                params![
                    "mat_legacyvalid00000000000000000000",
                    format!("case_{}", "8".repeat(32))
                ],
            )
            .is_err());
        drop(connection);
        assert!(!manager
            .case_material_migration_required()
            .expect("blocked tamper preserves terminal state"));
    }

    #[test]
    fn committed_retention_cleanup_is_a_read_only_noop_and_tamper_fails_closed() {
        let directory = tempfile::tempdir().expect("retention migration fixture");
        let _user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let privacy_directory = directory.path().join("privacy");
        fs::create_dir_all(&privacy_directory).expect("privacy directory");
        let privacy_path = privacy_directory.join("privacy-workflow.sqlite");
        create_valid_v4_history(&privacy_path);
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("legacy-compatible manager");
        manager
            .upgrade_privacy_store_schema_after_backup()
            .expect("upgrade retention fixture");
        manager
            .run_case_material_migration_after_backup()
            .expect("migrate retention fixture");

        let mut connection = manager.open_connection().expect("privacy store");
        let lifecycle =
            PrivacyLifecycle::open(&connection, test_workspace_instance_id()).expect("lifecycle");
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "migration-retention-test".to_owned(),
                    review_retention_seconds: 10,
                    mapping_retention_seconds: 10,
                    receipt_grace_seconds: 0,
                    backup_retention_seconds: 20,
                    revision: current.revision + 1,
                    updated_at_unix: 1_900_000_000,
                },
            )
            .expect("short retention policy");
        lifecycle
            .bind_redaction_retention(
                &connection,
                "red_11111111111111111111111111111111",
                1_900_000_001,
            )
            .expect("bind migrated generation");
        let ledger_before: (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger),
                    (SELECT COUNT(*) FROM case_material_migration_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("migration evidence before retention");
        let cleanup_id = "cln_cccccccccccccccccccccccccccccccc";
        lifecycle
            .run_retention_sweep(&mut connection, cleanup_id, 1_900_000_020)
            .expect("commit migrated retention cleanup");
        let tombstone = connection
            .query_row(
                "SELECT legacy_case_id,source_kind,state,deleted_at IS NOT NULL,
                        protected_display_name,display_name_sha256,
                        display_name_protection_scheme
                 FROM privacy_materials
                 WHERE material_id='mat_legacyvalid00000000000000000000'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .expect("retention tombstone");
        assert_eq!(
            tombstone.0.as_deref(),
            Some("case_99999999999999999999999999999999")
        );
        assert_eq!(tombstone.1, "local_review");
        assert_eq!(tombstone.2, "revoked");
        assert!(tombstone.3);
        assert_eq!((tombstone.4, tombstone.5, tombstone.6), (None, None, None));
        assert!(connection
            .execute(
                "UPDATE privacy_cleanup_candidates SET expected_sha256=?2
                 WHERE cleanup_id=?1 AND target_kind='redaction'",
                params![cleanup_id, sha256_hex(b"blocked candidate tamper")],
            )
            .is_err());
        drop(connection);

        assert!(!manager
            .case_material_migration_required()
            .expect("authorized retention is a terminal read-only no-op"));
        let connection = manager.open_connection().expect("privacy after probe");
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM case_material_migration_ledger),
                        (SELECT COUNT(*) FROM case_material_migration_events)",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("migration evidence after retention probe"),
            ledger_before
        );
        connection
            .execute_batch(
                "DROP TRIGGER trg_privacy_cleanup_candidate_one_way;
                 UPDATE privacy_cleanup_candidates
                 SET expected_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE cleanup_id='cln_cccccccccccccccccccccccccccccccc'
                   AND target_kind='redaction';",
            )
            .expect("simulate storage-level cleanup evidence tamper");
        drop(connection);
        let error = manager
            .case_material_migration_required()
            .expect_err("tampered cleanup evidence must fail closed");
        assert_eq!(error.code(), "case_material_migration_target_mismatch");
    }

    #[test]
    fn retention_then_project_deletion_preserves_historical_provenance_and_restarts_noop() {
        exercise_project_deletion_retention_order(true, false);
    }

    #[test]
    fn project_deletion_then_retention_preserves_scope_and_rejects_provenance_drift() {
        exercise_project_deletion_retention_order(false, true);
    }

    #[test]
    fn project_with_unbound_privacy_state_records_stable_terminal_blocked_binding() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let user_connection = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("read user database");
        let user = UserSnapshot::load(&user_connection).expect("load user snapshot");
        let source = user.projects.get(PROJECT_A).expect("project source");
        let blocked_projects = BTreeSet::from([PROJECT_A.to_owned()]);
        let mut connection = fixture.manager.open_connection().expect("privacy database");
        let mut first_report = CaseMaterialMigrationReport::default();
        let transaction = connection.transaction().expect("privacy transaction");
        create_bindings_for_projects_without_privacy_state(
            &transaction,
            &user,
            &[],
            &blocked_projects,
            &mut first_report,
        )
        .expect("record terminal blocked binding");
        transaction.commit().expect("commit terminal binding");
        assert_eq!(first_report.blocked, 1);
        assert!(project_binding_terminal_matches(&connection, source, None)
            .expect("terminal blocked binding satisfies the project probe"));

        let terminal = connection
            .query_row(
                "SELECT result_state,error_code
                 FROM case_material_migration_ledger
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='projects' AND source_key=?3",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .expect("project binding terminal ledger");
        assert_eq!(
            terminal,
            (
                "blocked".to_owned(),
                Some("project_privacy_case_unbound".to_owned())
            )
        );
        let before_counts = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3),
                    (SELECT COUNT(*) FROM case_material_migration_events
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3)",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("project binding evidence counts");

        let mut second_report = CaseMaterialMigrationReport::default();
        let transaction = connection
            .transaction()
            .expect("repeat privacy transaction");
        create_bindings_for_projects_without_privacy_state(
            &transaction,
            &user,
            &[],
            &blocked_projects,
            &mut second_report,
        )
        .expect("repeat terminal blocked binding");
        transaction.commit().expect("commit idempotent repeat");
        assert_eq!(second_report.idempotent_noops, 1);
        let after_counts = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3),
                    (SELECT COUNT(*) FROM case_material_migration_events
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3)",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("stable project binding evidence counts");
        assert_eq!(after_counts, before_counts);
    }

    #[test]
    fn target_without_ledger_is_adopted_as_interrupted_recovery() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-recovery",
            Some(PROJECT_A),
            "recovery.txt",
            b"recovery",
        );
        fixture.add_case_file(
            "file-recovery",
            PROJECT_A,
            "恢复材料",
            "attachment:attachment-recovery",
        );
        let user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("read user snapshot");
        let snapshot = UserSnapshot::load(&user).expect("load source snapshot");
        let case_file = snapshot
            .case_files
            .iter()
            .find(|source| source.file_id == "file-recovery")
            .expect("recovery case file");
        let attachment = match snapshot.resolve_attachment(case_file) {
            AttachmentResolution::Exact(attachment) => attachment,
            _ => panic!("fixture must resolve exactly"),
        };
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-recovery",
        );
        let mut privacy = fixture.manager.open_connection().expect("privacy store");
        let transaction = privacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("target transaction");
        ensure_user_attachment_target(&transaction, case_file, attachment, &target)
            .expect("simulate committed target");
        transaction.commit().expect("commit target without ledger");
        drop(privacy);

        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("recover interrupted target");
        let connection = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_materials WHERE material_id=?1",
                    [&target],
                    |row| row.get::<_, i64>(0),
                )
                .expect("target count"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='case_files' AND source_key='file-recovery'",
                    params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                    |row| row.get::<_, i64>(0),
                )
                .expect("recovered ledger"),
            1
        );
    }

    #[test]
    fn changed_source_proof_rolls_back_the_complete_target_transaction() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-proof-rollback",
            Some(PROJECT_A),
            "proof-rollback.txt",
            b"proof rollback",
        );
        fixture.add_case_file(
            "file-proof-rollback",
            PROJECT_A,
            "旧快照标题",
            "attachment:attachment-proof-rollback",
        );

        let stale_user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("stale read-only source");
        stale_user
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .expect("stale source transaction");
        let stale_proof = SourceProof::capture(&fixture.user_database_path, &stale_user)
            .expect("stale source proof");
        let stale_snapshot = UserSnapshot::load(&stale_user).expect("stale source snapshot");
        stale_user
            .execute_batch("ROLLBACK")
            .expect("close stale source transaction");
        drop(stale_user);

        fixture.add_case_file(
            "file-proof-rollback",
            PROJECT_A,
            "并发更新标题",
            "attachment:attachment-proof-rollback",
        );
        let current_user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("current read-only source");
        current_user
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .expect("current source transaction");
        let mut privacy = fixture.manager.open_connection().expect("privacy store");
        let error = run_backfill(
            &fixture.manager,
            &mut privacy,
            &current_user,
            &fixture.user_database_path,
            &stale_proof,
            &stale_snapshot,
            &test_workspace_instance_id(),
        )
        .expect_err("stale source proof must roll back the target transaction");
        assert_eq!(error.code(), "case_material_source_changed");
        current_user
            .execute_batch("ROLLBACK")
            .expect("close current source transaction");
        drop(privacy);

        let connection = fixture.manager.open_connection().expect("privacy store");
        let counts: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_bindings),
                    (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                    (SELECT COUNT(*) FROM case_material_migration_ledger),
                    (SELECT COUNT(*) FROM privacy_materials)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("rolled-back target counts");
        assert_eq!(counts, (0, 0, 0, 0));
    }

    fn create_valid_v4_history(path: &Path) {
        let source_sha256 = sha256_hex(b"legacy source");
        let extraction_sha256 = sha256_hex(b"legacy extraction");
        let redacted_sha256 = sha256_hex(b"legacy redacted");
        let payload = serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "materialId": "mat_legacyvalid00000000000000000000",
            "redactionId": "red_11111111111111111111111111111111",
            "caseId": "case_99999999999999999999999999999999",
            "sourceDisplayName": "历史材料.pdf",
            "sourceSha256": source_sha256,
            "extractionSha256": extraction_sha256,
            "suggestedRedactedContentSha256": redacted_sha256,
            "processingVersion": "legacy-v1",
            "mediaType": "application/pdf",
            "pageCount": 0,
            "inputTransform": null,
            "backendTrace": [],
            "summary": {
                "total": 0,
                "counts": {},
                "changed": false,
                "manualReviewRequired": false,
                "redactionVersion": "legacy-v1"
            },
            "forbiddenCanaries": [],
            "pages": []
        }))
        .expect("serialize legacy payload");
        let protected = protect_local(&payload).expect("protect legacy payload");
        let connection = Connection::open(path).expect("legacy privacy database");
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version','4');
                 CREATE TABLE privacy_materials(
                    material_id TEXT PRIMARY KEY,project_id TEXT,attachment_id TEXT,
                    source_sha256 TEXT NOT NULL,source_name_sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,page_count INTEGER,state TEXT NOT NULL,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                 );
                 CREATE TABLE privacy_redactions(
                    redaction_id TEXT PRIMARY KEY,material_id TEXT NOT NULL,
                    extraction_sha256 TEXT NOT NULL,redacted_content_sha256 TEXT NOT NULL,
                    approved_payload_sha256 TEXT,policy_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,detector_version TEXT NOT NULL,
                    unresolved_high_risk_count INTEGER NOT NULL,review_state TEXT NOT NULL,
                    protected_review_blob BLOB NOT NULL,protection_scheme TEXT NOT NULL,
                    reviewed_by_sha256 TEXT,created_at TEXT NOT NULL,reviewed_at TEXT,
                    FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id)
                 );",
            )
            .expect("legacy schema");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                    media_type,page_count,state,created_at,updated_at
                 ) VALUES(?1,NULL,NULL,?2,?3,'application/pdf',0,'review_required',
                          '2025-01-01 00:00:00','2025-01-01 00:00:00')",
                params![
                    "mat_legacyvalid00000000000000000000",
                    source_sha256,
                    sha256_hex("历史材料.pdf".as_bytes())
                ],
            )
            .expect("legacy material");
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                    approved_payload_sha256,policy_id,policy_version,detector_version,
                    unresolved_high_risk_count,review_state,protected_review_blob,
                    protection_scheme,reviewed_by_sha256,created_at,reviewed_at
                 ) VALUES(?1,?2,?3,?4,NULL,'policy',1,'detector',0,'review_required',
                          ?5,?6,NULL,'2025-01-01 00:00:00',NULL)",
                params![
                    "red_11111111111111111111111111111111",
                    "mat_legacyvalid00000000000000000000",
                    extraction_sha256,
                    redacted_sha256,
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                ],
            )
            .expect("legacy redaction");
    }
}
