use super::{
    ensure_standalone_restore_lineage_safe, validate_ordinary_database_file,
    validate_ordinary_directory, vault_broker, ApplicationBackupPrivacyGuard, PrivacyWorkflowError,
    PrivacyWorkflowManager,
};
use privacy::vnext::{CaseId, MaterialId};
use privacy::{
    protect_local, sha256_hex, unprotect_local, BackupExportRequestV1, BackupVerificationContextV1,
    CleanupReportV1, EncryptedPrivacyBackupStore, LifecycleError, MappingAccessContextV1,
    PreMigrationBackupExportContextV1, PreMigrationBackupVerificationContextV1, PrivacyCaseId,
    PrivacyLifecycle, PrivacyStore, PrivacyStoreSchemaStatus, ProjectId,
    ProjectPrivacyCaseBindingStore, RetentionPolicyV1, VerifiedBackupV1,
    LOGICAL_ERASURE_DISCLOSURE,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT,
    },
};

const BACKUP_ROOT_NAME: &str = "encrypted-backups";
const RESTORE_FORMAT_VERSION: u16 = 1;
const MAX_RESTORE_MARKER_BYTES: usize = 128 * 1024;
const MAX_PRIVACY_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
const MAPPING_REVEAL_AUTHORIZATION_TTL_SECONDS: u64 = 30;
const MAX_PENDING_MAPPING_REVEAL_AUTHORIZATIONS: usize = 8;
const INVALIDATE_REASON_MAPPING_REVOKED: &str = "privacy_mapping_revoked";
const INVALIDATE_REASON_MAPPING_KEY_ROTATED: &str = "privacy_mapping_key_rotated";
const INVALIDATE_REASON_MAPPING_KEY_DESTROYED: &str = "privacy_mapping_key_destroyed";
const INVALIDATE_REASON_RETENTION_SWEEP: &str = "privacy_retention_sweep";

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicationInvalidationTargets {
    Exact(BTreeSet<(CaseId, MaterialId)>),
    All,
}
pub const REVOKE_MAPPING_CONFIRMATION: &str = "撤销映射";
pub const ROTATE_MAPPING_KEY_CONFIRMATION: &str = "轮换映射密钥";
pub const DESTROY_MAPPING_KEY_CONFIRMATION: &str = "销毁映射密钥";
pub const RUN_RETENTION_CONFIRMATION: &str = "执行到期清理";
pub const RESTORE_BACKUP_CONFIRMATION: &str = "恢复隐私备份";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicyView {
    pub policy_id: String,
    pub review_retention_seconds: u64,
    pub mapping_retention_seconds: u64,
    pub receipt_grace_seconds: u64,
    pub backup_retention_seconds: u64,
    pub revision: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionBindingView {
    pub redaction_id: String,
    pub expires_at_unix: u64,
    pub legal_hold: bool,
    pub bound_at_unix: u64,
    pub policy_revision: u64,
    pub hold_changed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MappingRevisionView {
    pub mapping_id: String,
    pub redaction_id: String,
    pub revision: u64,
    pub key_version: u64,
    pub mapping_revision_sha256: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MappingKeyView {
    pub key_version: u64,
    pub protected_key_sha256: String,
    pub state: String,
    pub created_at_unix: u64,
    pub retired_at_unix: Option<u64>,
    pub revoked_at_unix: Option<u64>,
    pub destroyed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStatusView {
    pub workspace_instance_id: String,
    pub key_epoch: u64,
    pub retention_policy: RetentionPolicyView,
    pub retention_bindings: Vec<RetentionBindingView>,
    pub mapping_revisions: Vec<MappingRevisionView>,
    pub mapping_keys: Vec<MappingKeyView>,
    pub cleanup_journal_events: u64,
    pub mapping_access_events: u64,
    pub erasure_disclosure: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleStatusRequest {
    pub redaction_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetRetentionPolicyRequest {
    pub review_retention_seconds: u64,
    pub mapping_retention_seconds: u64,
    pub receipt_grace_seconds: u64,
    pub backup_retention_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetLegalHoldRequest {
    pub redaction_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevealMappingRequest {
    pub mapping_id: String,
    pub redaction_id: String,
}

pub(crate) struct MappingRevealAuthorization {
    nonce: String,
    issued_at_unix: u64,
}

impl std::fmt::Debug for MappingRevealAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MappingRevealAuthorization")
            .field("nonce", &"[REDACTED_ONE_TIME_AUTHORIZATION]")
            .field("issued_at_unix", &self.issued_at_unix)
            .finish()
    }
}

impl Drop for MappingRevealAuthorization {
    fn drop(&mut self) {
        zeroize_sensitive_string(&mut self.nonce);
    }
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevealedMappingEntryView {
    pub alias: String,
    pub sensitive_value: String,
}

impl std::fmt::Debug for RevealedMappingEntryView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevealedMappingEntryView")
            .field("alias", &self.alias)
            .field("sensitive_value", &"[REDACTED_SENSITIVE_VALUE]")
            .finish()
    }
}

impl Drop for RevealedMappingEntryView {
    fn drop(&mut self) {
        zeroize_sensitive_string(&mut self.sensitive_value);
    }
}

fn zeroize_sensitive_string(value: &mut str) {
    for byte in unsafe { value.as_bytes_mut() } {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevealMappingResponse {
    pub mapping_id: String,
    pub redaction_id: String,
    pub entries: Vec<RevealedMappingEntryView>,
}

impl std::fmt::Debug for RevealMappingResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevealMappingResponse")
            .field("mapping_id", &self.mapping_id)
            .field("redaction_id", &self.redaction_id)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeMappingRequest {
    pub mapping_id: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateMappingKeyRequest {
    pub confirmation: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestroyMappingKeyRequest {
    pub key_version: u64,
    pub expected_protected_key_sha256: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRetentionSweepRequest {
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReportView {
    pub cleanup_id: String,
    pub state: String,
    pub candidates: u64,
    pub removed: u64,
    pub keys_destroyed: u64,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub event_hash: String,
    pub erasure_disclosure: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupIdRequest {
    pub backup_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagePrivacyRestoreRequest {
    pub backup_id: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedBackupView {
    pub backup_id: String,
    pub workspace_instance_id: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub key_epoch: u64,
    pub database_sha256: String,
    pub envelope_sha256: String,
    pub restart_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingPrivacyRestoreV1 {
    format_version: u16,
    backup_id: String,
    workspace_instance_id: String,
    key_epoch: u64,
    incoming_sha256: String,
    envelope_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingPrivacyRestorePhase {
    Prepared,
    ActiveMovedToRollback,
    InstalledPendingCleanup,
}

/// Path-free authorization produced by the pre-manager startup pass.  The
/// marker is kept private and its `Debug` output never exposes workspace or
/// backup identifiers.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingPrivacyRestoreGate {
    marker: PendingPrivacyRestoreV1,
    marker_protected_sha256: String,
    phase: PendingPrivacyRestorePhase,
}

impl std::fmt::Debug for PendingPrivacyRestoreGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingPrivacyRestoreGate")
            .field("marker_protected_sha256", &self.marker_protected_sha256)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl PendingPrivacyRestoreGate {
    #[cfg(test)]
    pub(crate) fn marker_protected_sha256(&self) -> &str {
        &self.marker_protected_sha256
    }

    #[cfg(test)]
    pub(crate) const fn phase(&self) -> PendingPrivacyRestorePhase {
        self.phase
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingPrivacyRestoreObservation {
    Absent,
    Authenticated(PendingPrivacyRestoreGate),
}

/// Path-free proof that the active Privacy database is the exact current v6
/// schema and that its lifecycle workspace/key binding is internally valid.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CurrentPrivacyProfileProof {
    workspace_instance_id: privacy::vnext::WorkspaceInstanceId,
    key_epoch: u64,
    schema_object_count: u64,
    logical_manifest_sha256: String,
    logical_rows: u64,
    business_manifest_sha256: String,
    business_rows: u64,
}

impl std::fmt::Debug for CurrentPrivacyProfileProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CurrentPrivacyProfileProof")
            .field("workspace_instance_id", &"[AUTHENTICATED_WORKSPACE]")
            .field("key_epoch", &self.key_epoch)
            .field("schema_object_count", &self.schema_object_count)
            .field("logical_manifest_sha256", &self.logical_manifest_sha256)
            .field("logical_rows", &self.logical_rows)
            .field("business_manifest_sha256", &self.business_manifest_sha256)
            .field("business_rows", &self.business_rows)
            .finish()
    }
}

impl CurrentPrivacyProfileProof {
    pub(crate) fn workspace_instance_id(&self) -> &privacy::vnext::WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    #[cfg(test)]
    pub(crate) const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[cfg(test)]
    pub(crate) fn logical_manifest_sha256(&self) -> &str {
        &self.logical_manifest_sha256
    }

    #[cfg(test)]
    pub(crate) fn business_manifest_sha256(&self) -> &str {
        &self.business_manifest_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentPrivacyProfileObservation {
    Absent,
    ExactCurrent(CurrentPrivacyProfileProof),
}

struct PrivacyRestorePaths {
    active: PathBuf,
    incoming: PathBuf,
    marker: PathBuf,
    rollback: PathBuf,
}

pub(crate) struct StagedApplicationPrivacyComponent {
    pub verified: VerifiedBackupView,
    pub privacy_store_schema_version: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationPrivacyRestoreMode {
    Current,
    CoordinatedPreMigration,
}

fn publication_scope_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "privacy_publication_invalidation_scope_unavailable",
        "The affected approved-publication scope could not be verified; the privacy mutation was refused.",
    )
}

fn parse_publication_target(
    connection: &Connection,
    project_id: Option<String>,
    vault_case_id: Option<String>,
    material_id: Option<String>,
) -> Result<(CaseId, MaterialId), ()> {
    let project_id = ProjectId::parse(project_id.ok_or(())?).map_err(|_| ())?;
    let vault_case_id = PrivacyCaseId::parse(vault_case_id.ok_or(())?).map_err(|_| ())?;
    ProjectPrivacyCaseBindingStore::validate_pair(connection, &project_id, &vault_case_id)
        .map_err(|_| ())?;
    let material_id = MaterialId::parse(material_id.ok_or(())?).map_err(|_| ())?;
    Ok((vault_case_id.into_case_id(), material_id))
}

fn mapping_publication_targets(
    connection: &Connection,
    mapping_id: &str,
) -> Result<Option<PublicationInvalidationTargets>, PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT p.project_id,v.case_id,r.material_id
             FROM privacy_sensitive_mappings s
             LEFT JOIN privacy_redactions r ON r.redaction_id=s.redaction_id
             LEFT JOIN privacy_materials p ON p.material_id=r.material_id
             LEFT JOIN privacy_vault_material_refs v ON v.material_id=r.material_id
             WHERE s.mapping_id=?1 AND s.revoked_at_unix IS NULL",
            [mapping_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| publication_scope_error())?;
    Ok(target.map(|(project_case_id, vault_case_id, material_id)| {
        parse_publication_target(connection, project_case_id, vault_case_id, material_id)
            .map_or(PublicationInvalidationTargets::All, |target| {
                PublicationInvalidationTargets::Exact(BTreeSet::from([target]))
            })
    }))
}

fn mapping_key_state(
    connection: &Connection,
    key_version: u64,
) -> Result<Option<String>, PrivacyWorkflowError> {
    let Ok(key_version) = i64::try_from(key_version) else {
        return Ok(None);
    };
    connection
        .query_row(
            "SELECT state FROM privacy_mapping_keys WHERE key_version=?1",
            [key_version],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| publication_scope_error())
}

fn active_mapping_key_version(connection: &Connection) -> Result<u64, PrivacyWorkflowError> {
    let key_version = connection
        .query_row(
            "SELECT active_mapping_key_version FROM privacy_lifecycle_meta WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| publication_scope_error())?;
    u64::try_from(key_version).map_err(|_| publication_scope_error())
}

fn mapping_key_publication_targets(
    connection: &Connection,
    key_version: u64,
) -> Result<PublicationInvalidationTargets, PrivacyWorkflowError> {
    let key_version = i64::try_from(key_version).map_err(|_| publication_scope_error())?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT p.project_id,v.case_id,r.material_id
             FROM privacy_sensitive_mappings s
             LEFT JOIN privacy_redactions r ON r.redaction_id=s.redaction_id
             LEFT JOIN privacy_materials p ON p.material_id=r.material_id
             LEFT JOIN privacy_vault_material_refs v ON v.material_id=r.material_id
             WHERE s.key_version=?1",
        )
        .map_err(|_| publication_scope_error())?;
    let mut rows = statement
        .query([key_version])
        .map_err(|_| publication_scope_error())?;
    let mut targets = BTreeSet::new();
    while let Some(row) = rows.next().map_err(|_| publication_scope_error())? {
        let target = parse_publication_target(
            connection,
            row.get::<_, Option<String>>(0)
                .map_err(|_| publication_scope_error())?,
            row.get::<_, Option<String>>(1)
                .map_err(|_| publication_scope_error())?,
            row.get::<_, Option<String>>(2)
                .map_err(|_| publication_scope_error())?,
        );
        let Ok(target) = target else {
            return Ok(PublicationInvalidationTargets::All);
        };
        targets.insert(target);
    }
    Ok(PublicationInvalidationTargets::Exact(targets))
}

impl PrivacyWorkflowManager {
    fn invalidate_publication_targets(
        &self,
        targets: PublicationInvalidationTargets,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyWorkflowError> {
        match targets {
            PublicationInvalidationTargets::All => self.invalidate_all_publications(reason_code),
            PublicationInvalidationTargets::Exact(targets) => {
                let mut invalidated = 0_u64;
                for (case_id, material_id) in targets {
                    invalidated = invalidated.saturating_add(
                        self.invalidate_material_publications(&case_id, &material_id, reason_code)?,
                    );
                }
                Ok(invalidated)
            }
        }
    }

    pub fn lifecycle_status(
        &self,
        request: LifecycleStatusRequest,
    ) -> Result<LifecycleStatusView, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let policy = lifecycle
            .retention_policy(&connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let bindings = lifecycle
            .list_retention_bindings(&connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let mappings = lifecycle
            .list_mapping_revisions(&connection, request.redaction_id.as_deref())
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let keys = lifecycle
            .list_mapping_keys(&connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        Ok(LifecycleStatusView {
            workspace_instance_id: lifecycle.workspace_instance_id().as_str().to_owned(),
            key_epoch: lifecycle
                .current_key_epoch(&connection)
                .map_err(PrivacyWorkflowError::lifecycle)?,
            retention_policy: RetentionPolicyView::from(policy),
            retention_bindings: bindings
                .into_iter()
                .map(|binding| RetentionBindingView {
                    redaction_id: binding.redaction_id,
                    expires_at_unix: binding.expires_at_unix,
                    legal_hold: binding.legal_hold,
                    bound_at_unix: binding.bound_at_unix,
                    policy_revision: binding.policy_revision,
                    hold_changed_at_unix: binding.hold_changed_at_unix,
                })
                .collect(),
            mapping_revisions: mappings
                .into_iter()
                .map(|mapping| MappingRevisionView {
                    mapping_id: mapping.mapping_id,
                    redaction_id: mapping.redaction_id,
                    revision: mapping.revision,
                    key_version: mapping.key_version,
                    mapping_revision_sha256: mapping.mapping_revision_sha256,
                    created_at_unix: mapping.created_at_unix,
                    expires_at_unix: mapping.expires_at_unix,
                    revoked: mapping.revoked,
                })
                .collect(),
            mapping_keys: keys
                .into_iter()
                .map(|key| MappingKeyView {
                    key_version: key.key_version,
                    protected_key_sha256: key.protected_key_sha256,
                    state: key.state,
                    created_at_unix: key.created_at_unix,
                    retired_at_unix: key.retired_at_unix,
                    revoked_at_unix: key.revoked_at_unix,
                    destroyed_at_unix: key.destroyed_at_unix,
                })
                .collect(),
            cleanup_journal_events: lifecycle
                .verify_cleanup_journal(&connection)
                .map_err(PrivacyWorkflowError::lifecycle)?,
            mapping_access_events: lifecycle
                .verify_mapping_access_audit(&connection)
                .map_err(PrivacyWorkflowError::lifecycle)?,
            erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE.to_owned(),
        })
    }

    pub fn set_retention_policy(
        &self,
        request: SetRetentionPolicyRequest,
    ) -> Result<RetentionPolicyView, PrivacyWorkflowError> {
        let _gate = self.gate();
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let current = lifecycle
            .retention_policy(&connection)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let updated_at_unix = self
            .current_unix()?
            .max(current.updated_at_unix.saturating_add(1));
        let policy = RetentionPolicyV1 {
            policy_id: current.policy_id,
            review_retention_seconds: request.review_retention_seconds,
            mapping_retention_seconds: request.mapping_retention_seconds,
            receipt_grace_seconds: request.receipt_grace_seconds,
            backup_retention_seconds: request.backup_retention_seconds,
            revision: current.revision.saturating_add(1),
            updated_at_unix,
        };
        lifecycle
            .set_retention_policy(&mut connection, &policy)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        Ok(RetentionPolicyView::from(policy))
    }

    pub fn set_redaction_legal_hold(
        &self,
        request: SetLegalHoldRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let binding =
            vault_broker::load_vault_binding_for_redaction(&connection, &request.redaction_id)
                .map_err(PrivacyWorkflowError::vault)?;
        let now = self.current_unix()?;
        if request.enabled {
            if let Some(binding) = binding.as_ref() {
                self.shared
                    .vault_broker
                    .set_legal_hold(binding, true, now)
                    .map_err(PrivacyWorkflowError::vault)?;
            }
            lifecycle
                .set_legal_hold(&connection, &request.redaction_id, true, now)
                .map_err(PrivacyWorkflowError::lifecycle)
        } else {
            lifecycle
                .set_legal_hold(&connection, &request.redaction_id, false, now)
                .map_err(PrivacyWorkflowError::lifecycle)?;
            if let Some(binding) = binding.as_ref() {
                self.shared
                    .vault_broker
                    .set_legal_hold(binding, false, now)
                    .map_err(PrivacyWorkflowError::vault)?;
            }
            Ok(())
        }
    }
    pub(crate) fn issue_mapping_reveal_authorization(
        &self,
    ) -> Result<MappingRevealAuthorization, PrivacyWorkflowError> {
        let now = self.current_unix()?;
        let mut pending = self
            .shared
            .mapping_reveal_authorizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|_, issued_at| {
            now >= *issued_at
                && now <= issued_at.saturating_add(MAPPING_REVEAL_AUTHORIZATION_TTL_SECONDS)
        });
        if pending.len() >= MAX_PENDING_MAPPING_REVEAL_AUTHORIZATIONS {
            return Err(PrivacyWorkflowError::new(
                "privacy_mapping_authorization_capacity",
                "待处理的本机映射显示授权过多；请稍后重试。",
            ));
        }
        for _ in 0..8 {
            let nonce = format!("mra_{}", Uuid::new_v4().simple());
            if pending.contains_key(&nonce) {
                continue;
            }
            pending.insert(nonce.clone(), now);
            return Ok(MappingRevealAuthorization {
                nonce,
                issued_at_unix: now,
            });
        }
        Err(PrivacyWorkflowError::new(
            "privacy_mapping_authorization_unavailable",
            "无法创建一次性本机映射显示授权。",
        ))
    }

    fn consume_mapping_reveal_authorization(
        &self,
        authorization: &MappingRevealAuthorization,
        now_unix: u64,
    ) -> Result<(), PrivacyWorkflowError> {
        let issued_at = self
            .shared
            .mapping_reveal_authorizations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&authorization.nonce);
        if issued_at != Some(authorization.issued_at_unix)
            || now_unix < authorization.issued_at_unix
            || now_unix
                > authorization
                    .issued_at_unix
                    .saturating_add(MAPPING_REVEAL_AUTHORIZATION_TTL_SECONDS)
        {
            return Err(PrivacyWorkflowError::new(
                "privacy_mapping_user_presence_required",
                "敏感映射显示需要新的本机原生确认。",
            ));
        }
        Ok(())
    }

    pub fn reveal_mapping(
        &self,
        request: RevealMappingRequest,
        authorization: MappingRevealAuthorization,
    ) -> Result<RevealMappingResponse, PrivacyWorkflowError> {
        let _gate = self.gate();
        let now_unix = self.current_unix()?;
        self.consume_mapping_reveal_authorization(&authorization, now_unix)?;
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let access_id = format!("access_{}", Uuid::new_v4().simple());
        let payload = lifecycle
            .load_mapping_revision(
                &mut connection,
                &request.mapping_id,
                &MappingAccessContextV1 {
                    access_id: &access_id,
                    redaction_id: &request.redaction_id,
                    purpose: "explicit_local_mapping_reveal",
                    now_unix,
                    private_mapping_access_authorized: true,
                },
            )
            .map_err(PrivacyWorkflowError::lifecycle)?;
        Ok(RevealMappingResponse {
            mapping_id: request.mapping_id,
            redaction_id: request.redaction_id,
            entries: payload
                .entries
                .into_iter()
                .map(|mut entry| RevealedMappingEntryView {
                    alias: std::mem::take(&mut entry.alias),
                    sensitive_value: std::mem::take(&mut entry.sensitive_value),
                })
                .collect(),
        })
    }

    pub fn revoke_mapping(
        &self,
        request: RevokeMappingRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        require_confirmation(&request.confirmation, REVOKE_MAPPING_CONFIRMATION)?;
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let targets = mapping_publication_targets(&connection, &request.mapping_id)?;
        let now_unix = self.current_unix()?;
        if let Some(targets) = targets {
            self.invalidate_publication_targets(targets, INVALIDATE_REASON_MAPPING_REVOKED)?;
        }
        lifecycle
            .revoke_mapping(&connection, &request.mapping_id, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn rotate_mapping_key(
        &self,
        request: RotateMappingKeyRequest,
    ) -> Result<u64, PrivacyWorkflowError> {
        require_confirmation(&request.confirmation, ROTATE_MAPPING_KEY_CONFIRMATION)?;
        let _gate = self.gate();
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let active_key_version = active_mapping_key_version(&connection)?;
        let targets = mapping_key_publication_targets(&connection, active_key_version)?;
        let now_unix = self.current_unix()?;
        self.invalidate_publication_targets(targets, INVALIDATE_REASON_MAPPING_KEY_ROTATED)?;
        lifecycle
            .rotate_mapping_key(&mut connection, now_unix)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn destroy_mapping_key(
        &self,
        request: DestroyMappingKeyRequest,
    ) -> Result<(), PrivacyWorkflowError> {
        require_confirmation(&request.confirmation, DESTROY_MAPPING_KEY_CONFIRMATION)?;
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let now = self.current_unix()?;
        let key_state = mapping_key_state(&connection, request.key_version)?;
        if matches!(key_state.as_deref(), Some("retired" | "revoked")) {
            let targets = mapping_key_publication_targets(&connection, request.key_version)?;
            self.invalidate_publication_targets(targets, INVALIDATE_REASON_MAPPING_KEY_DESTROYED)?;
        }
        lifecycle
            .revoke_mapping_key(&connection, request.key_version, now)
            .or_else(|error| {
                if error == LifecycleError::Conflict {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(PrivacyWorkflowError::lifecycle)?;
        lifecycle
            .destroy_mapping_key(
                &connection,
                request.key_version,
                &request.expected_protected_key_sha256,
                now,
            )
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn run_retention_sweep(
        &self,
        request: RunRetentionSweepRequest,
    ) -> Result<CleanupReportView, PrivacyWorkflowError> {
        require_confirmation(&request.confirmation, RUN_RETENTION_CONFIRMATION)?;
        let _gate = self.gate();
        let mut connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let now = self.current_unix()?;
        self.recover_prepared_retention_sweeps(
            &lifecycle,
            &mut connection,
            now,
            INVALIDATE_REASON_RETENTION_SWEEP,
        )?;
        let report = self.run_retention_sweep_with_publication_invalidation(
            &lifecycle,
            &mut connection,
            &format!("cln_{}", Uuid::new_v4().simple()),
            now,
            INVALIDATE_REASON_RETENTION_SWEEP,
        )?;
        self.shared
            .vault_broker
            .run_or_resume_expired_cleanup(&format!("cln_{}", Uuid::new_v4().simple()), now)
            .map_err(PrivacyWorkflowError::vault)?;
        Ok(CleanupReportView::from(report))
    }
    pub fn create_privacy_backup(&self) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        let guard = self.begin_application_backup_pair();
        self.create_privacy_backup_locked(&guard)
    }

    pub(crate) fn create_privacy_backup_locked(
        &self,
        _guard: &ApplicationBackupPrivacyGuard<'_>,
    ) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        let mut connection = self.open_raw_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let store = self.backup_store()?;
        let now = self.current_unix()?;
        let backup_id = format!("bkp_{}", Uuid::new_v4().simple());
        let request = BackupExportRequestV1 {
            backup_id: &backup_id,
            created_at_unix: now,
            expires_at_unix: None,
        };
        let verified =
            if let Some(schema_version) = self.pre_migration_backup_schema_version(&connection)? {
                store.export_pre_migration_database(
                    &mut connection,
                    &lifecycle,
                    &request,
                    &PreMigrationBackupExportContextV1 {
                        expected_privacy_store_schema_version: schema_version,
                    },
                )
            } else {
                store.export_database(&mut connection, &lifecycle, &request)
            }
            .map_err(PrivacyWorkflowError::lifecycle)?;
        Ok(VerifiedBackupView::from(verified))
    }

    pub fn verify_privacy_backup(
        &self,
        backup_id: &str,
    ) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let context = self.backup_context(&connection, &lifecycle)?;
        self.backup_store()?
            .verify_detached_backup(backup_id, &context)
            .map(VerifiedBackupView::from)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn export_privacy_backup_bundle(
        &self,
        backup_id: &str,
    ) -> Result<Vec<u8>, PrivacyWorkflowError> {
        let guard = self.begin_application_backup_pair();
        self.export_privacy_backup_bundle_locked(&guard, backup_id)
    }

    pub(crate) fn export_privacy_backup_bundle_locked(
        &self,
        _guard: &ApplicationBackupPrivacyGuard<'_>,
        backup_id: &str,
    ) -> Result<Vec<u8>, PrivacyWorkflowError> {
        let connection = self.open_raw_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let store = self.backup_store()?;
        if let Some(schema_version) = self.pre_migration_backup_schema_version(&connection)? {
            let context =
                self.pre_migration_backup_context(&connection, &lifecycle, schema_version)?;
            store
                .export_pre_migration_portable_bundle(backup_id, &context)
                .map_err(PrivacyWorkflowError::lifecycle)
        } else {
            let context = self.backup_context(&connection, &lifecycle)?;
            store
                .export_portable_bundle(backup_id, &context)
                .map_err(PrivacyWorkflowError::lifecycle)
        }
    }

    pub fn import_privacy_backup_bundle(
        &self,
        bytes: &[u8],
    ) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let context = self.backup_context(&connection, &lifecycle)?;
        self.backup_store()?
            .import_portable_bundle(bytes, &context)
            .map(VerifiedBackupView::from)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn revoke_privacy_backup(&self, backup_id: &str) -> Result<(), PrivacyWorkflowError> {
        let guard = self.begin_application_backup_pair();
        self.revoke_privacy_backup_locked(&guard, backup_id)
    }

    pub(crate) fn revoke_privacy_backup_locked(
        &self,
        _guard: &ApplicationBackupPrivacyGuard<'_>,
        backup_id: &str,
    ) -> Result<(), PrivacyWorkflowError> {
        let connection = self.open_raw_connection()?;
        self.backup_store()?
            .revoke_backup(&connection, backup_id, self.current_unix()?)
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    pub fn stage_privacy_restore(
        &self,
        request: StagePrivacyRestoreRequest,
    ) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        require_confirmation(&request.confirmation, RESTORE_BACKUP_CONFIRMATION)?;
        let _gate = self.gate();
        let app_local_data_directory =
            self.shared.user_database_path.parent().ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "privacy_restore_invalid",
                    "The application data directory could not be resolved.",
                )
            })?;
        ensure_standalone_restore_lineage_safe(app_local_data_directory)?;
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let context = self.backup_context(&connection, &lifecycle)?;
        let store = self.backup_store()?;
        let verified = store
            .verify_detached_backup(&request.backup_id, &context)
            .map_err(PrivacyWorkflowError::lifecycle)?;
        let paths = privacy_restore_paths(&self.shared.database_path)?;
        ensure_restore_slot_empty(&paths)?;
        let result = (|| {
            let mut destination = Connection::open(&paths.incoming).map_err(|_| {
                PrivacyWorkflowError::new("privacy_restore_io", "隐私备份恢复暂存数据库无法创建。")
            })?;
            store
                .restore_detached_into_empty_database(
                    &mut destination,
                    &request.backup_id,
                    &context,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?;
            drop(destination);
            validate_restore_database(
                &paths.incoming,
                lifecycle.workspace_instance_id().as_str(),
                verified.key_epoch,
                &verified.database_sha256,
            )?;
            let marker = PendingPrivacyRestoreV1 {
                format_version: RESTORE_FORMAT_VERSION,
                backup_id: request.backup_id,
                workspace_instance_id: lifecycle.workspace_instance_id().as_str().to_owned(),
                key_epoch: verified.key_epoch,
                incoming_sha256: verified.database_sha256.clone(),
                envelope_sha256: verified.envelope_sha256.clone(),
            };
            write_protected_restore_marker(&paths.marker, &marker)?;
            Ok(())
        })();
        finish_privacy_restore_stage(&paths, result)?;
        let mut view = VerifiedBackupView::from(verified);
        view.restart_required = true;
        Ok(view)
    }

    pub(crate) fn workspace_instance_id(&self) -> privacy::vnext::WorkspaceInstanceId {
        self.shared.workspace_instance_id.clone()
    }

    /// Authenticates/imports an encrypted privacy component and restores it only to the fixed
    /// application-pair incoming slot. It deliberately writes no standalone restore marker: the
    /// pair coordinator must commit user and privacy components together or remove both.
    pub(crate) fn stage_application_privacy_component(
        &self,
        expected_backup_id: &str,
        portable_bundle: &[u8],
    ) -> Result<VerifiedBackupView, PrivacyWorkflowError> {
        self.stage_application_privacy_component_internal(
            expected_backup_id,
            portable_bundle,
            ApplicationPrivacyRestoreMode::Current,
            None,
        )
        .map(|staged| staged.verified)
    }

    /// Stages the Privacy component from the coordinated five-component migration backup only.
    ///
    /// This separate entry point is what permits an authenticated v1-v4 snapshot. It never upgrades
    /// the restored database and is intentionally unavailable to standalone Privacy restore or the
    /// historical three-component application restore protocol.
    pub(crate) fn stage_pre_migration_application_privacy_component(
        &self,
        expected_backup_id: &str,
        portable_bundle: &[u8],
    ) -> Result<StagedApplicationPrivacyComponent, PrivacyWorkflowError> {
        self.stage_application_privacy_component_internal(
            expected_backup_id,
            portable_bundle,
            ApplicationPrivacyRestoreMode::CoordinatedPreMigration,
            None,
        )
    }

    /// Migration-only recovery path for an authenticated five-component rollback point whose
    /// original retention window has elapsed. The caller must authenticate the enclosing
    /// application backup and its DPAPI-bound migration identity before using the recorded
    /// creation instant here.
    pub(crate) fn stage_pre_migration_application_privacy_component_for_migration_recovery(
        &self,
        expected_backup_id: &str,
        portable_bundle: &[u8],
        authenticated_created_at_unix: u64,
    ) -> Result<StagedApplicationPrivacyComponent, PrivacyWorkflowError> {
        if authenticated_created_at_unix == 0 {
            return Err(PrivacyWorkflowError::new(
                "application_backup_component_mismatch",
                "The authenticated migration backup creation instant is invalid.",
            ));
        }
        self.stage_application_privacy_component_internal(
            expected_backup_id,
            portable_bundle,
            ApplicationPrivacyRestoreMode::CoordinatedPreMigration,
            Some(authenticated_created_at_unix),
        )
    }

    fn stage_application_privacy_component_internal(
        &self,
        expected_backup_id: &str,
        portable_bundle: &[u8],
        mode: ApplicationPrivacyRestoreMode,
        authenticated_verification_unix: Option<u64>,
    ) -> Result<StagedApplicationPrivacyComponent, PrivacyWorkflowError> {
        let _gate = self.gate();
        let connection = self.open_connection()?;
        let lifecycle = self.privacy_lifecycle(&connection)?;
        let mut context = self.backup_context(&connection, &lifecycle)?;
        if let Some(verification_unix) = authenticated_verification_unix {
            context.now_unix = verification_unix;
        }
        let store = self.backup_store()?;
        let verified = match mode {
            ApplicationPrivacyRestoreMode::Current => {
                match store.import_portable_bundle(portable_bundle, &context) {
                    Ok(verified) => verified,
                    Err(import_error) => {
                        let existing = store.export_portable_bundle(expected_backup_id, &context);
                        match existing {
                            Ok(existing)
                                if sha256_hex(&existing) == sha256_hex(portable_bundle) =>
                            {
                                store
                                    .verify_detached_backup(expected_backup_id, &context)
                                    .map_err(PrivacyWorkflowError::lifecycle)?
                            }
                            _ => return Err(PrivacyWorkflowError::lifecycle(import_error)),
                        }
                    }
                }
            }
            ApplicationPrivacyRestoreMode::CoordinatedPreMigration => store
                .import_portable_bundle_for_coordinated_pre_migration_restore(
                    portable_bundle,
                    &context,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?,
        };
        if verified.backup_id != expected_backup_id {
            return Err(PrivacyWorkflowError::new(
                "application_backup_component_mismatch",
                "组合备份中的隐私组件标识不匹配。",
            ));
        }
        let incoming =
            application_privacy_restore_incoming(self.shared.database_path.parent().ok_or_else(
                || PrivacyWorkflowError::new("application_backup_invalid", "隐私数据库目录无效。"),
            )?);
        if restore_path_is_present(&incoming)? {
            return Err(PrivacyWorkflowError::new(
                "application_restore_conflict",
                "已有组合恢复隐私暂存文件。",
            ));
        }
        let result = (|| {
            let mut destination = Connection::open(&incoming).map_err(|_| {
                PrivacyWorkflowError::new(
                    "application_restore_io",
                    "组合恢复隐私暂存数据库无法创建。",
                )
            })?;
            match mode {
                ApplicationPrivacyRestoreMode::Current => store
                    .restore_detached_into_empty_database(
                        &mut destination,
                        expected_backup_id,
                        &context,
                    )
                    .map_err(PrivacyWorkflowError::lifecycle)?,
                ApplicationPrivacyRestoreMode::CoordinatedPreMigration => store
                    .restore_detached_for_coordinated_pre_migration_restore(
                        &mut destination,
                        expected_backup_id,
                        verified.privacy_store_schema_version,
                        &context,
                    )
                    .map_err(PrivacyWorkflowError::lifecycle)?,
            };
            drop(destination);
            validate_restore_database(
                &incoming,
                lifecycle.workspace_instance_id().as_str(),
                verified.key_epoch,
                &verified.database_sha256,
            )
        })();
        finish_application_privacy_restore_stage(&incoming, result)?;
        let privacy_store_schema_version = verified.privacy_store_schema_version;
        Ok(StagedApplicationPrivacyComponent {
            verified: VerifiedBackupView::from(verified),
            privacy_store_schema_version,
        })
    }

    fn backup_store(&self) -> Result<EncryptedPrivacyBackupStore, PrivacyWorkflowError> {
        let directory = self.shared.database_path.parent().ok_or_else(|| {
            PrivacyWorkflowError::new("privacy_backup_io", "隐私数据库目录无效。")
        })?;
        EncryptedPrivacyBackupStore::initialize(directory.join(BACKUP_ROOT_NAME))
            .map_err(PrivacyWorkflowError::lifecycle)
    }

    fn pre_migration_backup_schema_version(
        &self,
        connection: &Connection,
    ) -> Result<Option<i64>, PrivacyWorkflowError> {
        if !self.privacy_store_schema_upgrade_required() {
            return Ok(None);
        }
        match PrivacyStore::preflight_schema(connection).map_err(PrivacyWorkflowError::store)? {
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version } => Ok(Some(found_version)),
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::Current => {
                Err(PrivacyWorkflowError::new(
                    "privacy_store_schema_state_changed",
                    "The privacy store schema changed while the pre-migration backup gate was active.",
                ))
            }
        }
    }

    fn pre_migration_backup_context<'a>(
        &self,
        connection: &Connection,
        lifecycle: &'a PrivacyLifecycle,
        schema_version: i64,
    ) -> Result<PreMigrationBackupVerificationContextV1<'a>, PrivacyWorkflowError> {
        Ok(PreMigrationBackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle
                .current_key_epoch(connection)
                .map_err(PrivacyWorkflowError::lifecycle)?,
            expected_privacy_store_schema_version: schema_version,
            now_unix: self.current_unix()?,
        })
    }

    fn backup_context<'a>(
        &self,
        connection: &Connection,
        lifecycle: &'a PrivacyLifecycle,
    ) -> Result<BackupVerificationContextV1<'a>, PrivacyWorkflowError> {
        Ok(BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle
                .current_key_epoch(connection)
                .map_err(PrivacyWorkflowError::lifecycle)?,
            now_unix: self.current_unix()?,
        })
    }
}

pub(crate) fn application_privacy_restore_incoming(privacy_directory: &Path) -> PathBuf {
    privacy_directory.join("privacy-workflow.sqlite.application-restore-incoming")
}

/// Performs the current-profile Privacy classification without constructing a
/// workflow/Vault manager.  A present directory with a missing database is a
/// partial state, not a fresh install.
pub(crate) fn observe_current_privacy_profile_read_only(
    app_local_data_directory: &Path,
) -> Result<CurrentPrivacyProfileObservation, PrivacyWorkflowError> {
    let privacy_directory = app_local_data_directory.join(super::PRIVACY_DIRECTORY_NAME);
    match fs::symlink_metadata(&privacy_directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CurrentPrivacyProfileObservation::Absent);
        }
        Err(_) => {
            return Err(PrivacyWorkflowError::new(
                "privacy_current_profile_io",
                "The fixed current Privacy namespace could not be inspected.",
            ));
        }
        Ok(_) => validate_ordinary_directory(&privacy_directory)?,
    }
    if observe_pending_privacy_restore_read_only(app_local_data_directory)?
        != PendingPrivacyRestoreObservation::Absent
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_current_profile_restore_pending",
            "A pending Privacy restore must be applied before current-profile validation.",
        ));
    }

    let database_path = privacy_directory.join(super::PRIVACY_DATABASE_NAME);
    match fs::symlink_metadata(&database_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PrivacyWorkflowError::new(
                "privacy_current_profile_partial",
                "The Privacy namespace exists without its canonical database.",
            ));
        }
        Err(_) => {
            return Err(PrivacyWorkflowError::new(
                "privacy_current_profile_io",
                "The current Privacy database could not be inspected.",
            ));
        }
        Ok(_) => validate_ordinary_database_file(&database_path)?,
    }
    let connection = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_current_profile_invalid",
            "The current Privacy database could not be opened read-only.",
        )
    })?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_current_profile_invalid",
                "The current Privacy database could not enter query-only mode.",
            )
        })?;
    let workspace_value = connection
        .query_row(
            "SELECT workspace_instance_id FROM privacy_lifecycle_meta WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_current_profile_invalid",
                "The current Privacy lifecycle workspace binding is unavailable.",
            )
        })?;
    let workspace_instance_id = privacy::vnext::WorkspaceInstanceId::parse(workspace_value)
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_current_profile_invalid",
                "The current Privacy lifecycle workspace binding is invalid.",
            )
        })?;
    let lifecycle = PrivacyLifecycle::open(&connection, workspace_instance_id.clone())
        .map_err(PrivacyWorkflowError::lifecycle)?;
    let key_epoch = lifecycle
        .current_key_epoch(&connection)
        .map_err(PrivacyWorkflowError::lifecycle)?;
    if key_epoch == 0 {
        return Err(PrivacyWorkflowError::new(
            "privacy_current_profile_invalid",
            "The current Privacy lifecycle key epoch is invalid.",
        ));
    }
    let manifest = privacy::compute_privacy_v6_manifests_read_only(&connection).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_current_profile_invalid",
            "The current Privacy schema or data manifest is invalid.",
        )
    })?;
    validate_ordinary_database_file(&database_path)?;
    Ok(CurrentPrivacyProfileObservation::ExactCurrent(
        CurrentPrivacyProfileProof {
            workspace_instance_id,
            key_epoch,
            schema_object_count: u64::try_from(manifest.schema_object_count).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_current_profile_invalid",
                    "The current Privacy schema object count is unsupported.",
                )
            })?,
            logical_manifest_sha256: manifest.logical_manifest.sha256,
            logical_rows: manifest.logical_manifest.total_row_count,
            business_manifest_sha256: manifest.business_manifest.sha256,
            business_rows: manifest.business_manifest.total_row_count,
        },
    ))
}

/// Classifies the complete fixed standalone-Privacy restore namespace without
/// repairing, deleting, renaming, opening a writable database, or invoking a
/// publication invalidator.  Any unmarked residue or impossible crash state is
/// rejected rather than cleaned during startup arbitration.
pub(crate) fn observe_pending_privacy_restore_read_only(
    app_local_data_directory: &Path,
) -> Result<PendingPrivacyRestoreObservation, PrivacyWorkflowError> {
    let privacy_directory = app_local_data_directory.join(super::PRIVACY_DIRECTORY_NAME);
    match fs::symlink_metadata(&privacy_directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PendingPrivacyRestoreObservation::Absent);
        }
        Err(_) => {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_io",
                "The fixed privacy restore namespace could not be inspected.",
            ));
        }
        Ok(_) => validate_ordinary_directory(&privacy_directory)?,
    }

    let paths = privacy_restore_paths(&privacy_directory.join(super::PRIVACY_DATABASE_NAME))?;
    let marker_present = restore_path_is_present(&paths.marker)?;
    let incoming_present = restore_path_is_present(&paths.incoming)?;
    let active_present = restore_path_is_present(&paths.active)?;
    let rollback_present = restore_path_is_present(&paths.rollback)?;
    let incoming_residue = restore_database_slot_has_any_path(&paths.incoming)?;
    let rollback_residue = restore_database_slot_has_any_path(&paths.rollback)?;

    if !marker_present {
        if incoming_residue || rollback_residue {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_conflict",
                "An unmarked privacy restore residue requires explicit recovery.",
            ));
        }
        return Ok(PendingPrivacyRestoreObservation::Absent);
    }

    ensure_standalone_restore_lineage_safe(app_local_data_directory)?;
    let (marker, marker_protected_sha256) =
        read_protected_restore_marker_with_sha256(&paths.marker)?;
    validate_pending_privacy_restore_marker(&marker)?;

    if !active_present && !rollback_present {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "The pending privacy restore has neither an active nor rollback database.",
        ));
    }
    if incoming_residue && !incoming_present {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "The pending privacy restore has an orphaned incoming SQLite sidecar.",
        ));
    }
    if rollback_residue && !rollback_present {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "The pending privacy restore has an orphaned rollback SQLite sidecar.",
        ));
    }

    let phase = match (incoming_present, active_present, rollback_present) {
        (true, true, false) => {
            validate_restore_file_identity(&paths.active)?;
            ensure_no_database_sidecars(&paths.active)?;
            validate_restore_database(
                &paths.incoming,
                &marker.workspace_instance_id,
                marker.key_epoch,
                &marker.incoming_sha256,
            )?;
            ensure_no_database_sidecars(&paths.incoming)?;
            PendingPrivacyRestorePhase::Prepared
        }
        // Crash after active -> rollback but before incoming -> active.
        (true, false, true) => {
            validate_restore_file_identity(&paths.rollback)?;
            ensure_no_database_sidecars(&paths.rollback)?;
            validate_restore_database(
                &paths.incoming,
                &marker.workspace_instance_id,
                marker.key_epoch,
                &marker.incoming_sha256,
            )?;
            ensure_no_database_sidecars(&paths.incoming)?;
            PendingPrivacyRestorePhase::ActiveMovedToRollback
        }
        // The incoming image is already active; only rollback/marker cleanup
        // may remain.  A rollback file is optional because its removal and the
        // marker removal are separate durable operations.
        (false, true, _) => {
            validate_restore_database(
                &paths.active,
                &marker.workspace_instance_id,
                marker.key_epoch,
                &marker.incoming_sha256,
            )?;
            ensure_no_database_sidecars(&paths.active)?;
            if rollback_present {
                validate_restore_file_identity(&paths.rollback)?;
                ensure_no_database_sidecars(&paths.rollback)?;
            }
            PendingPrivacyRestorePhase::InstalledPendingCleanup
        }
        _ => {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_conflict",
                "The pending privacy restore has an impossible component state.",
            ));
        }
    };

    Ok(PendingPrivacyRestoreObservation::Authenticated(
        PendingPrivacyRestoreGate {
            marker,
            marker_protected_sha256,
            phase,
        },
    ))
}

/// Consumes only a gate obtained by the read-only startup observation.  The
/// entire namespace is observed again before the first mutation, closing the
/// classification/apply race.
pub(crate) fn apply_observed_pending_privacy_restore<BeforeApply>(
    app_local_data_directory: &Path,
    expected: &PendingPrivacyRestoreGate,
    before_apply: BeforeApply,
) -> Result<(), PrivacyWorkflowError>
where
    BeforeApply: FnOnce() -> Result<(), PrivacyWorkflowError>,
{
    let observed = observe_pending_privacy_restore_read_only(app_local_data_directory)?;
    if observed != PendingPrivacyRestoreObservation::Authenticated(expected.clone()) {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "The pending privacy restore changed after startup arbitration.",
        ));
    }
    let privacy_directory = app_local_data_directory.join(super::PRIVACY_DIRECTORY_NAME);
    apply_pending_privacy_restore_inner(
        &privacy_directory,
        &expected.marker.workspace_instance_id,
        Some(expected),
        before_apply,
    )?;
    if observe_pending_privacy_restore_read_only(app_local_data_directory)?
        != PendingPrivacyRestoreObservation::Absent
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "The authenticated privacy restore did not reach a clean terminal state.",
        ));
    }
    Ok(())
}

fn apply_pending_privacy_restore_inner<BeforeApply>(
    privacy_directory: &Path,
    workspace_instance_id: &str,
    expected_gate: Option<&PendingPrivacyRestoreGate>,
    before_apply: BeforeApply,
) -> Result<(), PrivacyWorkflowError>
where
    BeforeApply: FnOnce() -> Result<(), PrivacyWorkflowError>,
{
    validate_ordinary_directory(privacy_directory)?;
    let paths = privacy_restore_paths(&privacy_directory.join(super::PRIVACY_DATABASE_NAME))?;
    if expected_gate.is_none() {
        recover_stale_restore_files(&paths, workspace_instance_id)?;
    }
    if !restore_path_is_present(&paths.marker)? {
        return if expected_gate.is_none() {
            Ok(())
        } else {
            Err(PrivacyWorkflowError::new(
                "privacy_restore_conflict",
                "The authenticated privacy restore marker disappeared before apply.",
            ))
        };
    }
    let (marker, marker_protected_sha256) =
        read_protected_restore_marker_with_sha256(&paths.marker)?;
    validate_pending_privacy_restore_marker(&marker)?;
    if marker.workspace_instance_id != workspace_instance_id
        || expected_gate.is_some_and(|expected| {
            expected.marker != marker || expected.marker_protected_sha256 != marker_protected_sha256
        })
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "The pending privacy restore marker does not match the current workspace.",
        ));
    }
    let incoming_present = restore_path_is_present(&paths.incoming)?;
    if incoming_present {
        let active_present = restore_path_is_present(&paths.active)?;
        let rollback_present = restore_path_is_present(&paths.rollback)?;
        if active_present == rollback_present {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_conflict",
                "A pending privacy restore has an impossible active/rollback state.",
            ));
        }
        let preparation = (|| {
            validate_restore_database(
                &paths.incoming,
                workspace_instance_id,
                marker.key_epoch,
                &marker.incoming_sha256,
            )?;
            if active_present {
                validate_restore_file_identity(&paths.active)?;
                ensure_no_database_sidecars(&paths.active)?;
            } else {
                validate_restore_file_identity(&paths.rollback)?;
                ensure_no_database_sidecars(&paths.rollback)?;
            }
            ensure_no_database_sidecars(&paths.incoming)
        })();
        if let Err(error) = preparation {
            return finish_privacy_restore_stage(&paths, Err(error));
        }
    } else if let Err(error) = validate_restore_database(
        &paths.active,
        workspace_instance_id,
        marker.key_epoch,
        &marker.incoming_sha256,
    ) {
        rollback_privacy_restore(&paths)?;
        return Err(error);
    }

    // Only a DPAPI-authenticated marker whose exact incoming (or already
    // installed active) database has passed the workspace/key/hash checks may
    // revoke existing publications. Stray filenames and malformed markers
    // cannot cross this business-state boundary.
    before_apply()?;

    if incoming_present {
        if restore_path_is_present(&paths.active)? {
            if let Err(error) = fs::rename(&paths.active, &paths.rollback) {
                let original = PrivacyWorkflowError::new(
                    "privacy_restore_io",
                    format!(
                        "The active privacy database could not enter the rollback slot: {error}"
                    ),
                );
                return finish_privacy_restore_stage(&paths, Err(original));
            }
            if let Err(error) = validate_restore_file_identity(&paths.rollback) {
                rollback_privacy_restore(&paths)?;
                return Err(error);
            }
        }
        if let Err(error) = fs::rename(&paths.incoming, &paths.active) {
            let original = PrivacyWorkflowError::new(
                "privacy_restore_io",
                format!("The privacy restore database could not be atomically installed: {error}"),
            );
            rollback_privacy_restore(&paths)?;
            return Err(original);
        }
    }
    if let Err(error) = validate_restore_database(
        &paths.active,
        workspace_instance_id,
        marker.key_epoch,
        &marker.incoming_sha256,
    ) {
        rollback_privacy_restore(&paths)?;
        return Err(error);
    }
    remove_restore_database_files(&paths.rollback)?;
    remove_restore_file_if_exists(&paths.marker)?;
    Ok(())
}
fn recover_stale_restore_files(
    paths: &PrivacyRestorePaths,
    workspace_instance_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    if !restore_path_is_present(&paths.marker)? {
        if restore_path_is_present(&paths.rollback)? {
            validate_restore_file_identity(&paths.rollback)?;
            ensure_no_database_sidecars(&paths.rollback)?;
            if restore_path_is_present(&paths.active)? {
                validate_ordinary_database_file(&paths.active)?;
                validate_restore_file_identity(&paths.active)?;
                remove_restore_database_files(&paths.rollback)?;
            } else {
                fs::rename(&paths.rollback, &paths.active).map_err(|_| {
                    PrivacyWorkflowError::new(
                        "privacy_restore_io",
                        "The privacy database could not be recovered from the rollback slot.",
                    )
                })?;
                validate_restore_file_identity(&paths.active)?;
                let connection =
                    Connection::open_with_flags(&paths.active, OpenFlags::SQLITE_OPEN_READ_ONLY)
                        .map_err(|_| {
                            PrivacyWorkflowError::new(
                                "privacy_restore_invalid",
                                "The recovered privacy database could not be read.",
                            )
                        })?;
                PrivacyLifecycle::open(
                    &connection,
                    privacy::vnext::WorkspaceInstanceId::parse(workspace_instance_id).map_err(
                        |_| {
                            PrivacyWorkflowError::new(
                                "privacy_restore_invalid",
                                "The current workspace identifier is invalid.",
                            )
                        },
                    )?,
                )
                .map_err(PrivacyWorkflowError::lifecycle)?;
            }
        }
        remove_restore_database_files(&paths.incoming)?;
    }
    Ok(())
}

fn rollback_privacy_restore(paths: &PrivacyRestorePaths) -> Result<(), PrivacyWorkflowError> {
    if restore_path_is_present(&paths.rollback)? {
        validate_restore_file_identity(&paths.rollback)?;
        ensure_no_database_sidecars(&paths.rollback)?;
        if restore_path_is_present(&paths.active)? {
            remove_restore_database_files(&paths.active)?;
        }
        fs::rename(&paths.rollback, &paths.active).map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_restore_rollback_failed",
                "The original privacy database could not be restored from the rollback slot.",
            )
        })?;
        validate_restore_file_identity(&paths.active)?;
    }
    cleanup_privacy_restore_staging(paths)
}

fn finish_privacy_restore_stage(
    paths: &PrivacyRestorePaths,
    result: Result<(), PrivacyWorkflowError>,
) -> Result<(), PrivacyWorkflowError> {
    match result {
        Ok(()) => Ok(()),
        Err(original) => match cleanup_privacy_restore_staging(paths) {
            Ok(()) => Err(original),
            Err(cleanup_error) => Err(cleanup_error),
        },
    }
}

fn finish_application_privacy_restore_stage(
    incoming: &Path,
    result: Result<(), PrivacyWorkflowError>,
) -> Result<(), PrivacyWorkflowError> {
    match result {
        Ok(()) => Ok(()),
        Err(original) => match remove_restore_database_files(incoming) {
            Ok(()) => Err(original),
            Err(cleanup_error) => Err(cleanup_error),
        },
    }
}

fn cleanup_privacy_restore_staging(
    paths: &PrivacyRestorePaths,
) -> Result<(), PrivacyWorkflowError> {
    let mut cleanup_error = None;
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_database_files(&paths.incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_file_if_exists(&paths.marker),
    );
    cleanup_error.map_or(Ok(()), Err)
}

fn record_cleanup_error(
    slot: &mut Option<PrivacyWorkflowError>,
    result: Result<(), PrivacyWorkflowError>,
) {
    if let Err(error) = result {
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

fn remove_restore_database_files(path: &Path) -> Result<(), PrivacyWorkflowError> {
    let mut cleanup_error = None;
    for candidate in [
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
        path.to_path_buf(),
    ] {
        record_cleanup_error(
            &mut cleanup_error,
            remove_restore_file_if_exists(&candidate),
        );
    }
    cleanup_error.map_or(Ok(()), Err)
}

fn ensure_no_database_sidecars(path: &Path) -> Result<(), PrivacyWorkflowError> {
    for candidate in [
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        if restore_path_is_present(&candidate)? {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_conflict",
                "A SQLite restore component has an unexpected journal or WAL sidecar.",
            ));
        }
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn restore_path_is_present(path: &Path) -> Result<bool, PrivacyWorkflowError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PrivacyWorkflowError::new(
            "privacy_restore_io",
            "A fixed privacy restore path could not be inspected.",
        )),
    }
}

fn restore_database_slot_has_any_path(path: &Path) -> Result<bool, PrivacyWorkflowError> {
    [
        path.to_path_buf(),
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ]
    .into_iter()
    .try_fold(false, |present, candidate| {
        restore_path_is_present(&candidate).map(|candidate_present| present || candidate_present)
    })
}

fn validate_restore_file_identity(path: &Path) -> Result<(), PrivacyWorkflowError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "A fixed privacy restore file could not be inspected.",
        )
    })?;
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || !ordinary_single_link_file(path)
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "A privacy restore file is not an ordinary single-link fixed local file.",
        ));
    }
    Ok(())
}

fn remove_restore_file_if_exists(path: &Path) -> Result<(), PrivacyWorkflowError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(PrivacyWorkflowError::new(
                "privacy_restore_cleanup_failed",
                "A fixed privacy restore path could not be inspected for cleanup.",
            ));
        }
    };
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || !ordinary_single_link_file(path)
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_unsafe_cleanup",
            "Cleanup refused a privacy restore path that is not an ordinary single-link local file.",
        ));
    }
    fs::remove_file(path).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_restore_cleanup_failed",
            "A sensitive privacy restore file could not be removed.",
        )
    })?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(PrivacyWorkflowError::new(
            "privacy_restore_cleanup_failed",
            "A sensitive privacy restore path remains after cleanup.",
        )),
    }
}
fn validate_restore_database(
    path: &Path,
    workspace_instance_id: &str,
    key_epoch: u64,
    expected_sha256: &str,
) -> Result<(), PrivacyWorkflowError> {
    validate_ordinary_database_file(path)?;
    if !ordinary_single_link_file(path)
        || fs::metadata(path).map(|value| value.len()).unwrap_or(0) > MAX_PRIVACY_DATABASE_BYTES
        || file_sha256(path)? != expected_sha256
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "恢复数据库的文件身份、大小或哈希不匹配。",
        ));
    }
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "恢复数据库无法读取。")
        })?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "恢复数据库完整性检查失败。")
        })?;
    let foreign_keys: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "恢复数据库外键检查失败。")
        })?;
    if integrity != "ok" || foreign_keys != 0 {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "恢复数据库未通过 SQLite 完整性或外键检查。",
        ));
    }
    let workspace =
        privacy::vnext::WorkspaceInstanceId::parse(workspace_instance_id).map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "当前工作区标识无效。")
        })?;
    let lifecycle =
        PrivacyLifecycle::open(&connection, workspace).map_err(PrivacyWorkflowError::lifecycle)?;
    if lifecycle
        .current_key_epoch(&connection)
        .map_err(PrivacyWorkflowError::lifecycle)?
        != key_epoch
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "恢复数据库映射密钥 epoch 不匹配。",
        ));
    }
    Ok(())
}

fn ensure_restore_slot_empty(paths: &PrivacyRestorePaths) -> Result<(), PrivacyWorkflowError> {
    if restore_path_is_present(&paths.incoming)?
        || restore_path_is_present(&paths.marker)?
        || restore_path_is_present(&paths.rollback)?
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_conflict",
            "A privacy restore transaction is already pending or requires recovery.",
        ));
    }
    Ok(())
}
fn privacy_restore_paths(active: &Path) -> Result<PrivacyRestorePaths, PrivacyWorkflowError> {
    let parent = active.parent().ok_or_else(|| {
        PrivacyWorkflowError::new("privacy_restore_invalid", "隐私数据库缺少父目录。")
    })?;
    let name = active
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "隐私数据库文件名无效。")
        })?;
    Ok(PrivacyRestorePaths {
        active: active.to_path_buf(),
        incoming: parent.join(format!("{name}.restore-incoming")),
        marker: parent.join(format!("{name}.restore-pending.dpapi")),
        rollback: parent.join(format!("{name}.restore-rollback")),
    })
}

fn write_protected_restore_marker(
    path: &Path,
    marker: &PendingPrivacyRestoreV1,
) -> Result<(), PrivacyWorkflowError> {
    let plaintext = serde_json::to_vec(marker).map_err(|_| {
        PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记无法编码。")
    })?;
    let protected = protect_local(&plaintext).map_err(|_| {
        PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记无法受保护。")
    })?;
    if protected.is_empty() || protected.len() > MAX_RESTORE_MARKER_BYTES {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "隐私恢复标记大小无效。",
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| PrivacyWorkflowError::new("privacy_restore_io", "隐私恢复标记无法创建。"))?;
    if !ordinary_single_link_handle(&file) {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "隐私恢复标记不是本机单链接普通文件。",
        ));
    }
    file.write_all(&protected)
        .map_err(|_| PrivacyWorkflowError::new("privacy_restore_io", "隐私恢复标记无法写入。"))?;
    file.sync_all()
        .map_err(|_| PrivacyWorkflowError::new("privacy_restore_io", "隐私恢复标记无法同步。"))
}

fn read_protected_restore_marker_with_sha256(
    path: &Path,
) -> Result<(PendingPrivacyRestoreV1, String), PrivacyWorkflowError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记无法读取。")
        })?;
    if !ordinary_single_link_handle(&file) {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "隐私恢复标记不是本机单链接普通文件。",
        ));
    }
    let mut protected = Vec::new();
    (&mut file)
        .take((MAX_RESTORE_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut protected)
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记读取失败。")
        })?;
    if protected.is_empty() || protected.len() > MAX_RESTORE_MARKER_BYTES {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "隐私恢复标记大小无效。",
        ));
    }
    let plaintext = unprotect_local(&protected).map_err(|_| {
        PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记认证失败。")
    })?;
    let marker = serde_json::from_slice(&plaintext).map_err(|_| {
        PrivacyWorkflowError::new("privacy_restore_invalid", "隐私恢复标记格式无效。")
    })?;
    Ok((marker, sha256_hex(&protected)))
}

fn validate_pending_privacy_restore_marker(
    marker: &PendingPrivacyRestoreV1,
) -> Result<(), PrivacyWorkflowError> {
    if marker.format_version != RESTORE_FORMAT_VERSION
        || privacy::vnext::WorkspaceInstanceId::parse(&marker.workspace_instance_id).is_err()
        || marker.key_epoch == 0
        || !marker.backup_id.starts_with("bkp_")
        || !is_hash(&marker.incoming_sha256)
        || !is_hash(&marker.envelope_sha256)
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "The pending privacy restore marker is invalid.",
        ));
    }
    Ok(())
}

fn ordinary_single_link_file(path: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .is_ok_and(|file| ordinary_single_link_handle(&file))
}

fn ordinary_single_link_handle(file: &File) -> bool {
    if !crate::privacy_manager::opened_file_resolves_to_ordinary_local(file) {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::privacy_manager::has_cloud_recall_attributes(&metadata)
    {
        return false;
    }
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    !handle.is_null()
        && unsafe { GetFileInformationByHandle(handle, &mut information) } != 0
        && information.nNumberOfLinks == 1
}

fn file_sha256(path: &Path) -> Result<String, PrivacyWorkflowError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "恢复数据库无法读取哈希。")
        })?;
    if !ordinary_single_link_handle(&file) {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "恢复数据库不是本机单链接普通文件。",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PRIVACY_DATABASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            PrivacyWorkflowError::new("privacy_restore_invalid", "恢复数据库无法完整读取。")
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVACY_DATABASE_BYTES {
        return Err(PrivacyWorkflowError::new(
            "privacy_restore_invalid",
            "恢复数据库大小无效。",
        ));
    }
    Ok(sha256_hex(&bytes))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_confirmation(actual: &str, expected: &str) -> Result<(), PrivacyWorkflowError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PrivacyWorkflowError::new(
            "privacy_confirmation_required",
            "该本机敏感操作需要输入界面显示的完整确认短语。",
        ))
    }
}

impl From<RetentionPolicyV1> for RetentionPolicyView {
    fn from(value: RetentionPolicyV1) -> Self {
        Self {
            policy_id: value.policy_id,
            review_retention_seconds: value.review_retention_seconds,
            mapping_retention_seconds: value.mapping_retention_seconds,
            receipt_grace_seconds: value.receipt_grace_seconds,
            backup_retention_seconds: value.backup_retention_seconds,
            revision: value.revision,
            updated_at_unix: value.updated_at_unix,
        }
    }
}

impl From<CleanupReportV1> for CleanupReportView {
    fn from(value: CleanupReportV1) -> Self {
        Self {
            cleanup_id: value.cleanup_id,
            state: value.state,
            candidates: value.candidates,
            removed: value.removed,
            keys_destroyed: value.keys_destroyed,
            started_at_unix: value.started_at_unix,
            completed_at_unix: value.completed_at_unix,
            event_hash: value.event_hash,
            erasure_disclosure: value.erasure_disclosure.to_owned(),
        }
    }
}

impl From<VerifiedBackupV1> for VerifiedBackupView {
    fn from(value: VerifiedBackupV1) -> Self {
        Self {
            backup_id: value.backup_id,
            workspace_instance_id: value.workspace_instance_id.as_str().to_owned(),
            created_at_unix: value.created_at_unix,
            expires_at_unix: value.expires_at_unix,
            key_epoch: value.key_epoch,
            database_sha256: value.database_sha256,
            envelope_sha256: value.envelope_sha256,
            restart_required: false,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::privacy_workflow::{test_workspace_instance_id, ApprovedPublicationInvalidator};
    use std::sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc, Mutex,
    };

    const TEST_PROJECT_ID: &str = "case-lifecycle-project";
    const TEST_CASE_ID: &str = "case_11111111111111111111111111111111";
    const TEST_MATERIAL_ID: &str = "mat_22222222222222222222222222222222";
    const TEST_MAPPING_ID: &str = "map_44444444444444444444444444444444";
    const TEST_REDACTION_ID: &str = "red_33333333333333333333333333333333";
    const HELD_REDACTION_ID: &str = "red_55555555555555555555555555555555";
    const FUTURE_REDACTION_ID: &str = "red_66666666666666666666666666666666";
    const SYNTHETIC_INVALIDATION_FAILURE: &str = "synthetic_publication_invalidation_failed";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum InvalidationCall {
        Case(String, &'static str),
        Material(String, String, &'static str),
        All(&'static str),
        Lifecycle(BTreeSet<String>, &'static str),
    }

    #[derive(Default)]
    struct RecordingInvalidator {
        fail: AtomicBool,
        calls: Mutex<Vec<InvalidationCall>>,
    }

    impl RecordingInvalidator {
        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, AtomicOrdering::SeqCst);
        }

        fn take_calls(&self) -> Vec<InvalidationCall> {
            std::mem::take(
                &mut *self
                    .calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        }

        fn record(&self, call: InvalidationCall) -> Result<u64, &'static str> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(call);
            if self.fail.load(AtomicOrdering::SeqCst) {
                Err(SYNTHETIC_INVALIDATION_FAILURE)
            } else {
                Ok(1)
            }
        }
    }

    impl ApprovedPublicationInvalidator for RecordingInvalidator {
        fn invalidate_case(
            &self,
            case_id: &CaseId,
            reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.record(InvalidationCall::Case(
                case_id.as_str().to_owned(),
                reason_code,
            ))
        }

        fn invalidate_material(
            &self,
            case_id: &CaseId,
            material_id: &MaterialId,
            reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.record(InvalidationCall::Material(
                case_id.as_str().to_owned(),
                material_id.as_str().to_owned(),
                reason_code,
            ))
        }

        fn invalidate_all(&self, reason_code: &'static str) -> Result<u64, &'static str> {
            self.record(InvalidationCall::All(reason_code))
        }

        fn invalidate_lifecycle_bindings(
            &self,
            lifecycle_binding_ids: &BTreeSet<String>,
            reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.record(InvalidationCall::Lifecycle(
                lifecycle_binding_ids.clone(),
                reason_code,
            ))
        }
    }

    fn manager_with_invalidator(
        directory: &tempfile::TempDir,
        invalidator: Arc<RecordingInvalidator>,
    ) -> PrivacyWorkflowManager {
        PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
            invalidator,
        )
        .expect("manager with publication invalidator")
    }

    fn install_mapping_fixture(manager: &PrivacyWorkflowManager) {
        let mut connection = manager.open_connection().expect("privacy connection");
        let project_id = ProjectId::parse(TEST_PROJECT_ID).expect("fixture project id");
        let privacy_case_id = PrivacyCaseId::parse(TEST_CASE_ID).expect("fixture privacy case id");
        let binding_context = privacy::BindingLifecycleContext::new(
            privacy::BindingCreationSource::LegacyMigration,
            "audit-lifecycle-fixture-binding",
            Some("project-privacy-case-binding-v1".to_owned()),
        )
        .expect("fixture binding context");
        ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
            &mut connection,
            &project_id,
            &privacy_case_id,
            &binding_context,
        )
        .expect("fixture project/privacy binding");
        connection
            .execute_batch(
                "INSERT INTO privacy_materials(
                     material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                     media_type,page_count,source_kind,extraction_status,migration_status,state
                 ) VALUES(
                     'mat_22222222222222222222222222222222',
                     'case-lifecycle-project',NULL,
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'text/plain',1,'vault','ready','ready','approved'
                 );
                 INSERT INTO privacy_vault_material_refs(
                     material_id,case_id,object_id,object_version,source_sha256,envelope_sha256,
                     content_bytes,retention_expires_at_unix,retention_policy_revision,
                     bound_at_unix,import_state
                 ) VALUES(
                     'mat_22222222222222222222222222222222',
                     'case_11111111111111111111111111111111',
                     'obj_22222222222222222222222222222222',1,
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'abababababababababababababababababababababababababababababababab',
                     1,2100000000,1,1500000000,'review_ready'
                 );
                 INSERT INTO privacy_redactions(
                     redaction_id,material_id,generation_number,
                     extraction_sha256,redacted_content_sha256,
                     approved_payload_sha256,policy_id,policy_version,detector_version,
                     unresolved_high_risk_count,review_state,protected_review_blob,protection_scheme
                 ) VALUES(
                     'red_33333333333333333333333333333333',
                     'mat_22222222222222222222222222222222',
                     1,
                     'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                     'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                     NULL,
                     'policy-test',1,'detector-test',0,'review_required',X'01',
                     'windows_dpapi_current_user_v1'
                 );
                 INSERT INTO privacy_sensitive_mappings(
                     mapping_id,redaction_id,revision,key_version,nonce,ciphertext,tag,
                     ciphertext_sha256,mapping_revision_sha256,created_at_unix,expires_at_unix
                 ) VALUES(
                     'map_44444444444444444444444444444444',
                     'red_33333333333333333333333333333333',1,1,zeroblob(12),X'01',zeroblob(16),
                     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                     '9999999999999999999999999999999999999999999999999999999999999999',
                     1900000000,2100000000
                 );",
            )
            .expect("mapping fixture");
        PrivacyStore::approve_review(
            &mut connection,
            TEST_REDACTION_ID,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            &sha256_hex(b"lifecycle fixture reviewer"),
            b"lifecycle fixture legacy approval",
        )
        .expect("blocked legacy mapping approval fixture");
    }

    fn install_retention_fixture(manager: &PrivacyWorkflowManager) {
        install_mapping_fixture(manager);
        let mut connection = manager.open_connection().expect("privacy connection");
        connection
            .execute_batch(
                "INSERT INTO privacy_materials(
                     material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                     media_type,page_count,source_kind,extraction_status,migration_status,state
                 ) VALUES
                 ('mat_55555555555555555555555555555555',
                  'case-lifecycle-project',NULL,
                  '1515151515151515151515151515151515151515151515151515151515151515',
                  '2525252525252525252525252525252525252525252525252525252525252525',
                  'text/plain',1,'vault','ready','ready','approved'),
                 ('mat_66666666666666666666666666666666',
                  'case-lifecycle-project',NULL,
                  '1616161616161616161616161616161616161616161616161616161616161616',
                  '2626262626262626262626262626262626262626262626262626262626262626',
                  'text/plain',1,'vault','ready','ready','approved');
                 INSERT INTO privacy_vault_material_refs(
                     material_id,case_id,object_id,object_version,source_sha256,envelope_sha256,
                     content_bytes,retention_expires_at_unix,retention_policy_revision,
                     bound_at_unix,import_state
                 ) VALUES
                 ('mat_55555555555555555555555555555555',
                  'case_11111111111111111111111111111111',
                  'obj_55555555555555555555555555555555',1,
                  '1515151515151515151515151515151515151515151515151515151515151515',
                  '5555555555555555555555555555555555555555555555555555555555555555',
                  1,2100000000,1,1500000000,'review_ready'),
                 ('mat_66666666666666666666666666666666',
                  'case_11111111111111111111111111111111',
                  'obj_66666666666666666666666666666666',1,
                  '1616161616161616161616161616161616161616161616161616161616161616',
                  '6666666666666666666666666666666666666666666666666666666666666666',
                  1,2100000000,1,1500000000,'review_ready');
                 INSERT INTO privacy_redactions(
                     redaction_id,material_id,generation_number,
                     extraction_sha256,redacted_content_sha256,
                     approved_payload_sha256,policy_id,policy_version,detector_version,
                     unresolved_high_risk_count,review_state,protected_review_blob,protection_scheme
                 ) VALUES
                 ('red_55555555555555555555555555555555',
                  'mat_55555555555555555555555555555555',
                  1,
                  '3535353535353535353535353535353535353535353535353535353535353535',
                  '4545454545454545454545454545454545454545454545454545454545454545',
                  NULL,
                  'policy-test',1,'detector-test',0,'review_required',X'01',
                  'windows_dpapi_current_user_v1'),
                 ('red_66666666666666666666666666666666',
                  'mat_66666666666666666666666666666666',
                  1,
                  '3636363636363636363636363636363636363636363636363636363636363636',
                  '4646464646464646464646464646464646464646464646464646464646464646',
                  NULL,
                  'policy-test',1,'detector-test',0,'review_required',X'01',
                  'windows_dpapi_current_user_v1');
                 INSERT INTO privacy_retention_bindings(
                     redaction_id,expires_at_unix,legal_hold,bound_at_unix,
                     policy_revision,hold_changed_at_unix
                 ) VALUES
                 ('red_33333333333333333333333333333333',1600000000,0,1500000000,1,NULL),
                 ('red_55555555555555555555555555555555',1600000000,1,1500000000,1,1600000001),
                 ('red_66666666666666666666666666666666',2100000000,0,1500000000,1,NULL);",
            )
            .expect("retention fixture");
        for (redaction_id, redacted_sha256, approved_payload_sha256) in [
            (
                "red_55555555555555555555555555555555",
                "4545454545454545454545454545454545454545454545454545454545454545",
                "5555555555555555555555555555555555555555555555555555555555555555",
            ),
            (
                "red_66666666666666666666666666666666",
                "4646464646464646464646464646464646464646464646464646464646464646",
                "5656565656565656565656565656565656565656565656565656565656565656",
            ),
        ] {
            PrivacyStore::approve_review(
                &mut connection,
                redaction_id,
                redacted_sha256,
                redacted_sha256,
                approved_payload_sha256,
                &sha256_hex(b"retention fixture reviewer"),
                b"retention fixture legacy approval",
            )
            .expect("blocked legacy retention approval fixture");
        }
    }

    fn one_day_policy() -> SetRetentionPolicyRequest {
        SetRetentionPolicyRequest {
            review_retention_seconds: 86_400,
            mapping_retention_seconds: 86_400,
            receipt_grace_seconds: 3_600,
            backup_retention_seconds: 7 * 86_400,
        }
    }

    #[test]
    fn publication_target_requires_the_persisted_project_privacy_binding() {
        let mut connection = Connection::open_in_memory().expect("in-memory privacy store");
        privacy::PrivacyStore::initialize(&connection).expect("privacy schema");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection).expect("binding schema");
        let project_id = ProjectId::parse("case-lifecycle-project").expect("project id");
        let privacy_case_id = PrivacyCaseId::parse(TEST_CASE_ID).expect("privacy case id");
        let context = privacy::BindingLifecycleContext::new(
            privacy::BindingCreationSource::LegacyMigration,
            "audit-lifecycle-binding",
            Some("project-privacy-case-binding-v1".to_owned()),
        )
        .expect("binding context");
        ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
            &mut connection,
            &project_id,
            &privacy_case_id,
            &context,
        )
        .expect("exact migrated binding");

        let (case_id, material_id) = parse_publication_target(
            &connection,
            Some(project_id.as_str().to_owned()),
            Some(privacy_case_id.as_str().to_owned()),
            Some(TEST_MATERIAL_ID.to_owned()),
        )
        .expect("bound target");
        assert_eq!(case_id.as_str(), TEST_CASE_ID);
        assert_eq!(material_id.as_str(), TEST_MATERIAL_ID);

        assert!(parse_publication_target(
            &connection,
            Some("case-unbound".to_owned()),
            Some(TEST_CASE_ID.to_owned()),
            Some(TEST_MATERIAL_ID.to_owned()),
        )
        .is_err());
        assert!(parse_publication_target(
            &connection,
            Some(project_id.as_str().to_owned()),
            Some("case_99999999999999999999999999999999".to_owned()),
            Some(TEST_MATERIAL_ID.to_owned()),
        )
        .is_err());
        assert!(parse_publication_target(
            &connection,
            None,
            Some(TEST_CASE_ID.to_owned()),
            Some(TEST_MATERIAL_ID.to_owned()),
        )
        .is_err());
        assert!(parse_publication_target(
            &connection,
            Some(project_id.as_str().to_owned()),
            None,
            Some(TEST_MATERIAL_ID.to_owned()),
        )
        .is_err());
    }

    #[test]
    fn pre_migration_backup_gate_exports_legacy_schema_without_upgrading_it() {
        let directory = tempfile::tempdir().expect("app directory");
        let initialized = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("initialize current privacy store");
        drop(initialized);

        let database_path = directory
            .path()
            .join(super::super::PRIVACY_DIRECTORY_NAME)
            .join(super::super::PRIVACY_DATABASE_NAME);
        let connection = Connection::open(&database_path).expect("privacy database");
        connection
            .execute(
                "UPDATE privacy_schema_metadata SET value='4' WHERE key='schema_version'",
                [],
            )
            .expect("mark synthetic legacy schema");
        let schema_before: String = connection
            .query_row(
                "SELECT group_concat(name || ':' || COALESCE(sql,''), '|')
                 FROM (
                    SELECT type,name,sql FROM sqlite_master
                    WHERE type IN ('table','index','trigger')
                    ORDER BY type,name
                 )",
                [],
                |row| row.get(0),
            )
            .expect("schema manifest");
        drop(connection);

        let pending = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("open legacy store in backup-only mode");
        assert!(pending.privacy_store_schema_upgrade_required());
        assert_eq!(
            pending
                .open_connection()
                .expect_err("ordinary access must remain closed before backup")
                .code(),
            "privacy_store_backup_required"
        );

        let backup = pending
            .create_privacy_backup()
            .expect("create authenticated legacy backup");
        let portable = pending
            .export_privacy_backup_bundle(&backup.backup_id)
            .expect("export authenticated legacy bundle");
        assert!(!portable.is_empty());

        let connection = pending
            .open_raw_connection()
            .expect("raw pre-migration inspection");
        assert_eq!(
            PrivacyStore::preflight_schema(&connection).expect("legacy preflight"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 4 }
        );
        let schema_after: String = connection
            .query_row(
                "SELECT group_concat(name || ':' || COALESCE(sql,''), '|')
                 FROM (
                    SELECT type,name,sql FROM sqlite_master
                    WHERE type IN ('table','index','trigger')
                    ORDER BY type,name
                 )",
                [],
                |row| row.get(0),
            )
            .expect("schema manifest after backup");
        assert_eq!(schema_after, schema_before);
        drop(connection);

        pending
            .revoke_privacy_backup(&backup.backup_id)
            .expect("revoke legacy backup through the backup-only path");
    }

    #[test]
    fn destructive_confirmation_is_exact_and_status_contains_no_private_values() {
        assert!(
            require_confirmation(REVOKE_MAPPING_CONFIRMATION, REVOKE_MAPPING_CONFIRMATION).is_ok()
        );
        assert_eq!(
            require_confirmation("撤销映射 ", REVOKE_MAPPING_CONFIRMATION)
                .expect_err("whitespace is not accepted")
                .code(),
            "privacy_confirmation_required"
        );
        let directory = tempfile::tempdir().expect("app directory");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("manager");
        let status = manager
            .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
            .expect("status");
        assert_eq!(status.key_epoch, 1);
        assert_eq!(status.mapping_revisions.len(), 0);
        assert_eq!(status.mapping_keys.len(), 1);
        let json = serde_json::to_string(&status).expect("serialize status");
        assert!(!json.contains("protectedKey\":") && !json.contains("sensitiveValue"));
        assert_eq!(status.erasure_disclosure, LOGICAL_ERASURE_DISCLOSURE);
    }

    #[test]
    fn mapping_reveal_authorization_is_redacted_short_lived_and_single_use() {
        let directory = tempfile::tempdir().expect("app directory");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("manager");
        manager.set_test_now(2_000_000_000);
        let authorization = manager
            .issue_mapping_reveal_authorization()
            .expect("issue authorization");
        let nonce = authorization.nonce.clone();
        let issued_at = authorization.issued_at_unix;
        let debug = format!("{authorization:?}");
        assert!(debug.contains("[REDACTED_ONE_TIME_AUTHORIZATION]"));
        assert!(!debug.contains(&nonce));
        manager
            .consume_mapping_reveal_authorization(&authorization, issued_at)
            .expect("first consume");
        assert_eq!(
            manager
                .consume_mapping_reveal_authorization(&authorization, issued_at)
                .expect_err("authorization must not replay")
                .code(),
            "privacy_mapping_user_presence_required"
        );

        let expired = manager
            .issue_mapping_reveal_authorization()
            .expect("issue expiring authorization");
        assert_eq!(
            manager
                .consume_mapping_reveal_authorization(
                    &expired,
                    expired.issued_at_unix + MAPPING_REVEAL_AUTHORIZATION_TTL_SECONDS + 1,
                )
                .expect_err("expired authorization must fail")
                .code(),
            "privacy_mapping_user_presence_required"
        );
    }

    #[test]
    fn mapping_revoke_invalidates_exact_material_before_mutation() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        manager.set_test_now(2_000_000_000);
        install_mapping_fixture(&manager);

        invalidator.set_fail(true);
        let error = manager
            .revoke_mapping(RevokeMappingRequest {
                mapping_id: TEST_MAPPING_ID.to_owned(),
                confirmation: REVOKE_MAPPING_CONFIRMATION.to_owned(),
            })
            .expect_err("publication invalidation failure must stop mapping revocation");
        assert_eq!(error.code(), SYNTHETIC_INVALIDATION_FAILURE);
        let connection = manager.open_connection().expect("privacy connection");
        let revoked_at = connection
            .query_row(
                "SELECT revoked_at_unix FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                [TEST_MAPPING_ID],
                |row| row.get::<_, Option<i64>>(0),
            )
            .expect("mapping state");
        assert_eq!(revoked_at, None);
        assert_eq!(
            invalidator.take_calls(),
            vec![InvalidationCall::Material(
                TEST_CASE_ID.to_owned(),
                TEST_MATERIAL_ID.to_owned(),
                INVALIDATE_REASON_MAPPING_REVOKED,
            )]
        );

        invalidator.set_fail(false);
        manager
            .revoke_mapping(RevokeMappingRequest {
                mapping_id: TEST_MAPPING_ID.to_owned(),
                confirmation: REVOKE_MAPPING_CONFIRMATION.to_owned(),
            })
            .expect("mapping revocation after publication invalidation");
        let revoked_at = connection
            .query_row(
                "SELECT revoked_at_unix FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                [TEST_MAPPING_ID],
                |row| row.get::<_, Option<i64>>(0),
            )
            .expect("mapping state after revocation");
        assert_eq!(revoked_at, Some(2_000_000_000));
    }

    #[test]
    fn key_rotation_and_destruction_fail_closed_before_key_state_changes() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        manager.set_test_now(2_000_000_000);
        install_mapping_fixture(&manager);

        invalidator.set_fail(true);
        let error = manager
            .rotate_mapping_key(RotateMappingKeyRequest {
                confirmation: ROTATE_MAPPING_KEY_CONFIRMATION.to_owned(),
            })
            .expect_err("publication invalidation failure must stop key rotation");
        assert_eq!(error.code(), SYNTHETIC_INVALIDATION_FAILURE);
        let connection = manager.open_connection().expect("privacy connection");
        let (active_key, key_count): (i64, i64) = connection
            .query_row(
                "SELECT active_mapping_key_version,(SELECT COUNT(*) FROM privacy_mapping_keys)
                 FROM privacy_lifecycle_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("key state after failed rotation");
        assert_eq!((active_key, key_count), (1, 1));
        assert_eq!(
            invalidator.take_calls(),
            vec![InvalidationCall::Material(
                TEST_CASE_ID.to_owned(),
                TEST_MATERIAL_ID.to_owned(),
                INVALIDATE_REASON_MAPPING_KEY_ROTATED,
            )]
        );

        invalidator.set_fail(false);
        assert_eq!(
            manager
                .rotate_mapping_key(RotateMappingKeyRequest {
                    confirmation: ROTATE_MAPPING_KEY_CONFIRMATION.to_owned(),
                })
                .expect("rotate key for destruction fixture"),
            2
        );
        invalidator.take_calls();
        let protected_key_sha256 = connection
            .query_row(
                "SELECT protected_key_sha256 FROM privacy_mapping_keys WHERE key_version=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("retired key hash");

        invalidator.set_fail(true);
        let error = manager
            .destroy_mapping_key(DestroyMappingKeyRequest {
                key_version: 1,
                expected_protected_key_sha256: protected_key_sha256,
                confirmation: DESTROY_MAPPING_KEY_CONFIRMATION.to_owned(),
            })
            .expect_err("publication invalidation failure must stop key destruction");
        assert_eq!(error.code(), SYNTHETIC_INVALIDATION_FAILURE);
        let (state, still_wrapped): (String, bool) = connection
            .query_row(
                "SELECT state,protected_key IS NOT NULL FROM privacy_mapping_keys
                 WHERE key_version=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("key state after failed destruction");
        assert_eq!(state, "retired");
        assert!(still_wrapped);
        assert_eq!(
            invalidator.take_calls(),
            vec![InvalidationCall::Material(
                TEST_CASE_ID.to_owned(),
                TEST_MATERIAL_ID.to_owned(),
                INVALIDATE_REASON_MAPPING_KEY_DESTROYED,
            )]
        );
    }

    #[test]
    fn retention_sweep_is_exact_respects_expiry_and_hold_and_recovers_after_restart() {
        let directory = tempfile::tempdir().expect("app directory");
        let failing = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, failing.clone());
        manager.set_test_now(1_700_000_000);
        install_retention_fixture(&manager);
        failing.set_fail(true);
        let error = manager
            .run_retention_sweep(RunRetentionSweepRequest {
                confirmation: RUN_RETENTION_CONFIRMATION.to_owned(),
            })
            .expect_err("publication invalidation failure must leave a recoverable prepare");
        assert_eq!(error.code(), SYNTHETIC_INVALIDATION_FAILURE);
        assert_eq!(
            failing.take_calls(),
            vec![InvalidationCall::Lifecycle(
                BTreeSet::from([TEST_REDACTION_ID.to_owned()]),
                INVALIDATE_REASON_RETENTION_SWEEP,
            )]
        );
        let connection = manager.open_connection().expect("privacy connection");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_cleanup_journal WHERE state='prepared'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("prepared cleanup count"),
            1
        );
        for redaction_id in [TEST_REDACTION_ID, HELD_REDACTION_ID, FUTURE_REDACTION_ID] {
            assert!(connection
                .query_row(
                    "SELECT 1 FROM privacy_redactions WHERE redaction_id=?1",
                    [redaction_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .expect("redaction state")
                .is_some());
        }
        drop(connection);
        drop(manager);

        let recovering = Arc::new(RecordingInvalidator::default());
        let recovered = manager_with_invalidator(&directory, recovering.clone());
        let connection = recovered
            .open_connection()
            .expect("recovered privacy connection");
        assert_eq!(
            recovering.take_calls(),
            vec![InvalidationCall::Lifecycle(
                BTreeSet::from([TEST_REDACTION_ID.to_owned()]),
                "privacy_retention_startup_recovery",
            )]
        );
        assert!(connection
            .query_row(
                "SELECT 1 FROM privacy_redactions WHERE redaction_id=?1",
                [TEST_REDACTION_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("expired redaction state")
            .is_none());
        for redaction_id in [HELD_REDACTION_ID, FUTURE_REDACTION_ID] {
            assert!(connection
                .query_row(
                    "SELECT 1 FROM privacy_redactions WHERE redaction_id=?1",
                    [redaction_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .expect("protected redaction state")
                .is_some());
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_cleanup_journal WHERE state='prepared'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("prepared cleanup count after recovery"),
            0
        );
    }

    #[test]
    fn retention_crash_recovery_never_invalidates_a_target_placed_on_late_legal_hold() {
        let directory = tempfile::tempdir().expect("app directory");
        let failing = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, failing.clone());
        manager.set_test_now(1_700_000_000);
        install_retention_fixture(&manager);
        failing.set_fail(true);
        manager
            .run_retention_sweep(RunRetentionSweepRequest {
                confirmation: RUN_RETENTION_CONFIRMATION.to_owned(),
            })
            .expect_err("failed invalidation leaves a durable prepared sweep");
        failing.take_calls();
        let connection = manager.open_connection().expect("privacy connection");
        connection
            .execute(
                "DELETE FROM privacy_vault_material_refs WHERE material_id=?1",
                [TEST_MATERIAL_ID],
            )
            .expect("detach the synthetic lifecycle-only fixture from the absent test Vault");
        drop(connection);
        manager
            .set_redaction_legal_hold(SetLegalHoldRequest {
                redaction_id: TEST_REDACTION_ID.to_owned(),
                enabled: true,
            })
            .expect("place the prepared target on a newer legal hold");
        drop(manager);

        let recovering = Arc::new(RecordingInvalidator::default());
        let recovered = manager_with_invalidator(&directory, recovering.clone());
        assert_eq!(
            recovering.take_calls(),
            Vec::<InvalidationCall>::new(),
            "startup recovery must finalize the stale prepare before external invalidation"
        );
        let connection = recovered
            .open_connection()
            .expect("recovered privacy connection");
        assert!(connection
            .query_row(
                "SELECT 1 FROM privacy_redactions WHERE redaction_id=?1",
                [TEST_REDACTION_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("late-held redaction state")
            .is_some());
        let failed_late_hold: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_cleanup_journal
                 WHERE state='failed'
                   AND error_code='privacy_cleanup_retention_precondition_changed'",
                [],
                |row| row.get(0),
            )
            .expect("terminal late-hold cleanup journal");
        assert_eq!(failed_late_hold, 1);
        let held: bool = connection
            .query_row(
                "SELECT legal_hold FROM privacy_retention_bindings WHERE redaction_id=?1",
                [TEST_REDACTION_ID],
                |row| row.get(0),
            )
            .expect("late hold state");
        assert!(held);
    }

    #[test]
    fn standalone_privacy_restore_stage_rejects_existing_unified_lineage_without_staging_files() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager
            .create_privacy_backup()
            .expect("pre-lineage privacy backup");
        install_mapping_fixture(&manager);
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");

        let error = manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id,
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect_err("unified lineage requires a five-component restore");

        assert_eq!(error.code(), "privacy_restore_requires_five_components");
        assert!(invalidator.take_calls().is_empty());
        assert!(!paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
        assert_eq!(
            manager
                .open_connection()
                .expect("current privacy connection")
                .query_row("SELECT COUNT(*) FROM privacy_materials", [], |row| {
                    row.get::<_, u32>(0)
                })
                .expect("current unified lineage"),
            1
        );
    }

    #[test]
    fn pre_manager_current_privacy_profile_is_exact_and_read_only() {
        let absent = tempfile::tempdir().expect("absent app directory");
        assert_eq!(
            observe_current_privacy_profile_read_only(absent.path()).expect("absent observation"),
            CurrentPrivacyProfileObservation::Absent
        );

        let partial = tempfile::tempdir().expect("partial app directory");
        fs::create_dir(partial.path().join(super::super::PRIVACY_DIRECTORY_NAME))
            .expect("partial privacy directory");
        assert_eq!(
            observe_current_privacy_profile_read_only(partial.path())
                .expect_err("present directory without database is partial")
                .code(),
            "privacy_current_profile_partial"
        );

        let directory = tempfile::tempdir().expect("current app directory");
        let workspace = test_workspace_instance_id();
        let manager =
            PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace.clone())
                .expect("current manager");
        let database_path = manager.shared.database_path.clone();
        drop(manager);
        let bytes_before = fs::read(&database_path).expect("Privacy bytes before observation");
        let modified_before = fs::metadata(&database_path)
            .expect("Privacy metadata before observation")
            .modified()
            .expect("Privacy mtime before observation");
        let entries_before = fs::read_dir(database_path.parent().expect("Privacy parent"))
            .expect("Privacy entries before observation")
            .map(|entry| entry.expect("Privacy entry").file_name())
            .collect::<BTreeSet<_>>();

        let CurrentPrivacyProfileObservation::ExactCurrent(proof) =
            observe_current_privacy_profile_read_only(directory.path())
                .expect("exact current Privacy observation")
        else {
            panic!("current Privacy must be exact");
        };
        assert_eq!(proof.workspace_instance_id(), &workspace);
        assert!(proof.key_epoch() > 0);
        assert!(is_hash(proof.logical_manifest_sha256()));
        assert!(is_hash(proof.business_manifest_sha256()));
        assert!(!format!("{proof:?}").contains(workspace.as_str()));
        assert_eq!(
            fs::read(&database_path).expect("Privacy bytes after observation"),
            bytes_before
        );
        assert_eq!(
            fs::metadata(&database_path)
                .expect("Privacy metadata after observation")
                .modified()
                .expect("Privacy mtime after observation"),
            modified_before
        );
        let entries_after = fs::read_dir(database_path.parent().expect("Privacy parent"))
            .expect("Privacy entries after observation")
            .map(|entry| entry.expect("Privacy entry").file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(entries_after, entries_before);
    }

    #[test]
    fn pre_manager_privacy_restore_observation_is_read_only_and_gate_bound() {
        let directory = tempfile::tempdir().expect("app directory");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("manager");
        let backup = manager.create_privacy_backup().expect("privacy backup");
        manager
            .set_retention_policy(one_day_policy())
            .expect("mutate active state");
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id.clone(),
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage restore");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        drop(manager);
        let active_before = fs::read(&paths.active).expect("active before observation");
        let incoming_before = fs::read(&paths.incoming).expect("incoming before observation");
        let marker_before = fs::read(&paths.marker).expect("marker before observation");

        let PendingPrivacyRestoreObservation::Authenticated(gate) =
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("authenticated read-only observation")
        else {
            panic!("pending restore must be observed");
        };
        assert_eq!(gate.phase(), PendingPrivacyRestorePhase::Prepared);
        assert!(is_hash(gate.marker_protected_sha256()));
        let debug = format!("{gate:?}");
        assert!(!debug.contains(&backup.backup_id));
        assert!(!debug.contains(test_workspace_instance_id().as_str()));
        assert_eq!(
            fs::read(&paths.active).expect("active after observation"),
            active_before
        );
        assert_eq!(
            fs::read(&paths.incoming).expect("incoming after observation"),
            incoming_before
        );
        assert_eq!(
            fs::read(&paths.marker).expect("marker after observation"),
            marker_before
        );

        apply_observed_pending_privacy_restore(directory.path(), &gate, || Ok(()))
            .expect("gate-bound apply");
        assert_eq!(
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("terminal observation"),
            PendingPrivacyRestoreObservation::Absent
        );
        assert!(!paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn pre_manager_privacy_restore_resumes_active_to_rollback_crash_window() {
        let directory = tempfile::tempdir().expect("app directory");
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("manager");
        let backup = manager.create_privacy_backup().expect("privacy backup");
        manager
            .set_retention_policy(one_day_policy())
            .expect("mutate active state");
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id,
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage restore");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        drop(manager);
        fs::rename(&paths.active, &paths.rollback).expect("inject active-to-rollback crash");

        let PendingPrivacyRestoreObservation::Authenticated(gate) =
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("crash window authenticates")
        else {
            panic!("crash window must be observed");
        };
        assert_eq!(
            gate.phase(),
            PendingPrivacyRestorePhase::ActiveMovedToRollback
        );
        apply_observed_pending_privacy_restore(directory.path(), &gate, || Ok(()))
            .expect("crash window resumes");
        assert!(paths.active.exists());
        assert!(!paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn pre_manager_privacy_restore_rejects_unmarked_residue_without_cleanup() {
        let directory = tempfile::tempdir().expect("app directory");
        let privacy_directory = directory.path().join(super::super::PRIVACY_DIRECTORY_NAME);
        fs::create_dir(&privacy_directory).expect("privacy directory");
        let paths =
            privacy_restore_paths(&privacy_directory.join(super::super::PRIVACY_DATABASE_NAME))
                .expect("restore paths");
        fs::write(&paths.incoming, b"unmarked restore residue").expect("incoming residue");

        let error = observe_pending_privacy_restore_read_only(directory.path())
            .expect_err("unmarked residue must fail closed");
        assert_eq!(error.code(), "privacy_restore_conflict");
        assert_eq!(
            fs::read(&paths.incoming).expect("residue remains for explicit recovery"),
            b"unmarked restore residue"
        );
    }

    #[test]
    fn startup_privacy_restore_apply_rechecks_lineage_before_any_database_swap() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager
            .create_privacy_backup()
            .expect("pre-lineage privacy backup");
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id,
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage while unified lineage is empty");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        assert!(!paths.rollback.exists());

        install_mapping_fixture(&manager);
        invalidator.take_calls();
        drop(manager);
        let active_before_apply =
            fs::read(&paths.active).expect("active Privacy after late lineage creation");

        let error = observe_pending_privacy_restore_read_only(directory.path())
            .expect_err("startup must recheck late lineage before any restore swap");

        assert_eq!(error.code(), "privacy_restore_requires_five_components");
        assert!(invalidator.take_calls().is_empty());
        assert_eq!(
            fs::read(&paths.active).expect("active Privacy after refused restore"),
            active_before_apply
        );
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        assert!(!paths.rollback.exists());
        let current = Connection::open_with_flags(
            &paths.active,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("read current active Privacy");
        assert_eq!(
            current
                .query_row("SELECT COUNT(*) FROM privacy_materials", [], |row| {
                    row.get::<_, u32>(0)
                })
                .expect("late unified lineage remains current"),
            1
        );
    }

    #[test]
    fn restore_staging_never_invalidates_before_the_protected_marker_is_durable() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager.create_privacy_backup().expect("privacy backup");
        manager
            .set_retention_policy(one_day_policy())
            .expect("mutate active Privacy state after backup");
        invalidator.set_fail(true);
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id.clone(),
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("staging must not cross the publication invalidation boundary");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        assert!(invalidator.take_calls().is_empty());
        let active_before_apply =
            fs::read(&paths.active).expect("active Privacy before committed apply");
        drop(manager);

        let PendingPrivacyRestoreObservation::Authenticated(gate) =
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("pending restore observation")
        else {
            panic!("pending restore must be observed");
        };
        let error = apply_observed_pending_privacy_restore(directory.path(), &gate, || {
            invalidator
                .invalidate_all("privacy_restore_startup_recovery")
                .map(|_| ())
                .map_err(|code| PrivacyWorkflowError::new(code, code))
        })
        .expect_err("post-marker publication invalidation failure must stop the swap");
        assert_eq!(error.code(), SYNTHETIC_INVALIDATION_FAILURE);
        assert_eq!(
            invalidator.take_calls(),
            vec![InvalidationCall::All("privacy_restore_startup_recovery")]
        );
        assert_eq!(
            fs::read(&paths.active).expect("active Privacy after refused apply"),
            active_before_apply
        );
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn application_privacy_component_staging_has_no_pre_marker_invalidation_side_effect() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager.create_privacy_backup().expect("privacy backup");
        let bundle = manager
            .export_privacy_backup_bundle(&backup.backup_id)
            .expect("portable privacy backup");
        invalidator.set_fail(true);

        manager
            .stage_application_privacy_component(&backup.backup_id, &bundle)
            .expect("component staging must not invalidate before its coordinator marker");
        let incoming = application_privacy_restore_incoming(
            manager
                .shared
                .database_path
                .parent()
                .expect("privacy directory"),
        );
        assert!(incoming.exists());
        assert!(invalidator.take_calls().is_empty());
        remove_restore_database_files(&incoming).expect("remove synthetic paired incoming");
    }

    #[test]
    fn startup_router_rejects_unmarked_incoming_without_publication_invalidation() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        drop(manager);
        invalidator.take_calls();
        let active_before = fs::read(&paths.active).expect("active Privacy before residue");
        fs::write(&paths.incoming, b"unmarked synthetic restore residue")
            .expect("write unmarked incoming residue");

        let error = observe_pending_privacy_restore_read_only(directory.path())
            .expect_err("unmarked residue requires explicit recovery");

        assert_eq!(error.code(), "privacy_restore_conflict");
        assert!(invalidator.take_calls().is_empty());
        assert!(paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
        assert_eq!(
            fs::read(&paths.active).expect("active Privacy after residue cleanup"),
            active_before
        );
    }

    #[test]
    fn authenticated_committed_restore_invalidates_then_applies_on_startup() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager.create_privacy_backup().expect("privacy backup");
        let changed = manager
            .set_retention_policy(one_day_policy())
            .expect("change active policy");
        assert_eq!(changed.revision, 2);
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id,
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage authenticated committed restore");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        invalidator.take_calls();
        drop(manager);

        let PendingPrivacyRestoreObservation::Authenticated(gate) =
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("pending restore observation")
        else {
            panic!("pending restore must be observed");
        };
        apply_observed_pending_privacy_restore(directory.path(), &gate, || {
            invalidator
                .invalidate_all("privacy_restore_startup_recovery")
                .map(|_| ())
                .map_err(|code| PrivacyWorkflowError::new(code, code))
        })
        .expect("authenticated restore applies");
        let restarted = PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
            invalidator.clone(),
        )
        .expect("manager opens only after restore terminal state");

        assert_eq!(
            invalidator.take_calls(),
            vec![InvalidationCall::All("privacy_restore_startup_recovery")]
        );
        assert_eq!(
            restarted
                .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
                .expect("restored lifecycle status")
                .retention_policy
                .revision,
            1
        );
        assert!(!paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn tampered_restore_marker_fails_closed_without_business_state_mutation() {
        let directory = tempfile::tempdir().expect("app directory");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = manager_with_invalidator(&directory, invalidator.clone());
        let backup = manager.create_privacy_backup().expect("privacy backup");
        manager
            .set_retention_policy(one_day_policy())
            .expect("change active policy");
        manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id,
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage restore before marker tamper");
        let paths = privacy_restore_paths(&manager.shared.database_path).expect("restore paths");
        invalidator.take_calls();
        drop(manager);
        let active_before = fs::read(&paths.active).expect("active Privacy before marker tamper");
        let mut marker = fs::read(&paths.marker).expect("protected restore marker");
        let last = marker.last_mut().expect("non-empty protected marker");
        *last ^= 0x01;
        fs::write(&paths.marker, marker).expect("tamper protected restore marker");

        let error = observe_pending_privacy_restore_read_only(directory.path())
            .expect_err("tampered marker must fail closed");

        assert_eq!(error.code(), "privacy_restore_invalid");
        assert!(invalidator.take_calls().is_empty());
        assert_eq!(
            fs::read(&paths.active).expect("active Privacy after marker rejection"),
            active_before
        );
        assert!(paths.incoming.exists());
        assert!(paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn encrypted_backup_stage_restart_restore_is_hash_bound_and_crash_recoverable() {
        let directory = tempfile::tempdir().expect("app directory");
        let workspace = test_workspace_instance_id();
        let manager =
            PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace.clone())
                .expect("manager");
        let initial = manager
            .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
            .expect("initial status");
        assert_eq!(initial.retention_policy.revision, 1);
        let backup = manager.create_privacy_backup().expect("encrypted backup");
        let bundle = manager
            .export_privacy_backup_bundle(&backup.backup_id)
            .expect("portable encrypted bundle");
        assert!(!bundle.starts_with(b"SQLite format 3"));
        assert!(!bundle
            .windows(b"privacy_retention_policy".len())
            .any(|window| window == b"privacy_retention_policy"));
        let changed = manager
            .set_retention_policy(one_day_policy())
            .expect("change policy");
        assert_eq!(changed.revision, 2);
        let staged = manager
            .stage_privacy_restore(StagePrivacyRestoreRequest {
                backup_id: backup.backup_id.clone(),
                confirmation: RESTORE_BACKUP_CONFIRMATION.to_owned(),
            })
            .expect("stage restore");
        assert!(staged.restart_required);
        drop(manager);

        let PendingPrivacyRestoreObservation::Authenticated(gate) =
            observe_pending_privacy_restore_read_only(directory.path())
                .expect("pending restore observation")
        else {
            panic!("pending restore must be observed");
        };
        apply_observed_pending_privacy_restore(directory.path(), &gate, || Ok(()))
            .expect("startup applies pending restore");
        let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
            .expect("manager opens after pending restore");
        let restored = restarted
            .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
            .expect("restored status");
        assert_eq!(restored.retention_policy.revision, 1);
        let paths = privacy_restore_paths(&restarted.shared.database_path).expect("paths");
        assert!(!paths.incoming.exists());
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn restore_stage_cleanup_failure_dominates_original_and_rejects_hardlinks() {
        let directory = tempfile::tempdir().expect("privacy directory");
        let paths = privacy_restore_paths(&directory.path().join("privacy-workflow.sqlite"))
            .expect("fixed restore paths");
        let alias = directory.path().join("synthetic-privacy-incoming-hardlink");

        fs::write(&paths.incoming, b"synthetic sensitive privacy restore")
            .expect("write privacy incoming");
        fs::hard_link(&paths.incoming, &alias).expect("create privacy incoming hardlink");
        fs::write(&paths.marker, b"synthetic protected marker").expect("write marker");

        let error = finish_privacy_restore_stage(
            &paths,
            Err(PrivacyWorkflowError::new(
                "synthetic_original_restore_failure",
                "synthetic original failure",
            )),
        )
        .expect_err("unsafe cleanup must dominate the original stage error");

        assert_eq!(error.code(), "privacy_restore_unsafe_cleanup");
        assert!(paths.incoming.exists());
        assert!(alias.exists());
        assert!(!paths.marker.exists());

        fs::remove_file(alias).expect("remove hardlink alias");
        fs::remove_file(paths.incoming).expect("remove hardlinked incoming");
    }
}
