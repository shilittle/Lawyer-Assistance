use super::{V031Step8MaintenanceFailureInjector, V031Step8MaintenanceFailurePoint};
use crate::{
    approved_mcp::V031ApprovedMcpTargetComponentsGate,
    commands::original_migration_backup::OriginalRollbackVerifiedGate,
};
use privacy::{
    fixed_local_file_identity, sha256_hex, validate_fixed_local_directory,
    validate_fixed_local_regular_file,
    vault_store::{
        DecryptedVaultObjectV1, VaultCleanupFailureInjector, VaultCleanupFailurePoint,
        VaultCleanupPendingStatusV1, VaultDatabaseReadOnlyManifestV1, VaultIsolationStatusV1,
        VaultObjectKind, VaultPrivateMetadataInputV1, VaultReadOnlyInventoryV1,
        VaultRetentionBindingV1, VaultStore, VaultStoreError, VAULT_STORE_SCHEMA_VERSION,
    },
    vnext::{
        canonical_json_v1, CaseId, MaterialId, ObjectId, PrivateValueRefV1, Sha256Hex,
        WorkspaceInstanceId,
    },
    VaultCleanupReportV1,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::Serialize;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Read,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        atomic::{compiler_fence, AtomicBool, Ordering},
        Mutex,
    },
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

pub(super) const VAULT_ROOT_DIRECTORY: &str = "case-vault-v2";
const PRIVATE_VALUE_MEDIA_TYPE: &str = "application/vnd.lawyer-assistance.private-values+json";
const PRIVATE_VALUE_OBJECT_NAME: &str = "encrypted-private-values";
const PRIVATE_VALUE_PAYLOAD_VERSION: &str = "private-value-batch-v1";
const MAX_PRIVATE_VALUE_COUNT: usize = 100_000;
const AUX_PAYLOAD_MEDIA_PREFIX: &str = "application/vnd.lawyer-assistance.";
const V031_VAULT_TARGET_EVIDENCE_SCHEMA: &str = "lawyer-assistance-v031-vault-target-component-v1";
const V031_VAULT_SCHEMA_SHA256: &str =
    "2bb9ae40edfa7df30473b8a7627eef4732ac79d4045b62b030eed66faed0fec1";
const MAX_V031_EMPTY_VAULT_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const V031_VAULT_DIRECTORY_NAMES: [&str; 4] = [".quarantine", ".staging", "keys", "objects"];
const V031_VAULT_DATABASE_NAME: &str = "vault-state.sqlite";
const V031_VAULT_WAL_NAME: &str = "vault-state.sqlite-wal";
const V031_VAULT_SHM_NAME: &str = "vault-state.sqlite-shm";
static V031_VAULT_TARGET_OPERATION: Mutex<()> = Mutex::new(());

/// Path-free startup proof that the fixed Vault namespace is the current
/// schema, is bound to the expected workspace, and passed both inventory and
/// live isolation inspection without creating or upgrading storage.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CurrentVaultProof {
    workspace_instance_id: WorkspaceInstanceId,
    schema_version: u32,
    inventory: VaultReadOnlyInventoryV1,
    isolation: VaultIsolationStatusV1,
    schema_sha256: String,
    database_sha256: String,
    layout_sha256: String,
    component_manifest_sha256: String,
}

impl fmt::Debug for CurrentVaultProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentVaultProof")
            .field("workspace_instance_id", &"[AUTHENTICATED_WORKSPACE]")
            .field("schema_version", &self.schema_version)
            .field("inventory", &self.inventory)
            .field("isolation", &self.isolation)
            .field("schema_sha256", &self.schema_sha256)
            .field("database_sha256", &self.database_sha256)
            .field("layout_sha256", &self.layout_sha256)
            .field("component_manifest_sha256", &self.component_manifest_sha256)
            .finish()
    }
}

impl CurrentVaultProof {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    #[cfg(test)]
    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[cfg(test)]
    pub(crate) const fn inventory(&self) -> VaultReadOnlyInventoryV1 {
        self.inventory
    }

    #[cfg(test)]
    pub(crate) fn isolation(&self) -> &VaultIsolationStatusV1 {
        &self.isolation
    }

    pub(crate) fn schema_sha256(&self) -> &str {
        &self.schema_sha256
    }

    pub(crate) fn database_sha256(&self) -> &str {
        &self.database_sha256
    }

    pub(crate) fn layout_sha256(&self) -> &str {
        &self.layout_sha256
    }

    pub(crate) fn component_manifest_sha256(&self) -> &str {
        &self.component_manifest_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The exact branch owns its complete read-only Vault proof as one capability.
#[allow(clippy::large_enum_variant)]
pub(crate) enum CurrentVaultObservation {
    Absent,
    Exact(CurrentVaultProof),
}

/// Classifies the fixed Vault namespace before manager construction. Missing
/// state remains absent; any present partial, legacy, workspace-mismatched, or
/// isolation-invalid state fails closed. The underlying store is opened only
/// through its application-startup read-only path.
pub(crate) fn observe_current_vault_read_only(
    app_local_data_directory: &Path,
    workspace_instance_id: &WorkspaceInstanceId,
) -> Result<CurrentVaultObservation, VaultStoreError> {
    validate_fixed_local_directory(app_local_data_directory)
        .map_err(|_| VaultStoreError::InvalidRoot)?;
    let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CurrentVaultObservation::Absent);
        }
        Err(_) => return Err(VaultStoreError::IoFailed),
        Ok(_) => {
            validate_fixed_local_directory(&root).map_err(|_| VaultStoreError::UnsafeFilesystem)?
        }
    }

    let (store, schema_upgrade_required) =
        VaultStore::open_for_application_startup(&root, workspace_instance_id.clone())?;
    if schema_upgrade_required {
        return Err(VaultStoreError::DatabaseFailed);
    }
    let inventory = store.inspect_inventory_read_only()?;
    let database_manifest = store.inspect_database_manifest_read_only()?;
    if inventory.journal_row_count != database_manifest.journal_row_count
        || inventory.committed_object_count != database_manifest.committed_object_count
        || inventory.committed_object_count > inventory.journal_row_count
    {
        return Err(VaultStoreError::ContentCorrupt);
    }
    let isolation = store.isolation_status()?;
    if isolation.isolation_level != "windows_current_user_encrypted_vault"
        || !isolation.private_acl_enforced
        || !isolation.content_indexing_disabled
        || !isolation.encrypted_at_rest
        || isolation.broker_boundary != "in_process_vault_broker_interface_v1"
        || isolation.strong_service_identity_boundary
        || isolation.same_user_process_limitation
            != "same_user_processes_are_not_technically_excluded_without_a_service_identity"
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }

    let mut component_manifest = v031_validate_current_vault_component(
        app_local_data_directory,
        workspace_instance_id,
        &database_manifest,
    )
    .map_err(|_| VaultStoreError::ContentCorrupt)?;
    component_manifest.key_record_count = inventory.key_record_count;
    component_manifest.object_root_entry_count = inventory.object_root_entry_count;
    if component_manifest.schema_version != VAULT_STORE_SCHEMA_VERSION
        || component_manifest.schema_sha256 != V031_VAULT_SCHEMA_SHA256
        || component_manifest.metadata_rows != 2
        || component_manifest.directory_count != V031_VAULT_DIRECTORY_NAMES.len() as u64
        || !(1..=2).contains(&component_manifest.file_count)
        || component_manifest.business_rows < database_manifest.journal_row_count
    {
        return Err(VaultStoreError::ContentCorrupt);
    }
    if store.inspect_inventory_read_only()? != inventory
        || store.inspect_database_manifest_read_only()? != database_manifest
    {
        return Err(VaultStoreError::ContentCorrupt);
    }
    let component_manifest_sha256 =
        v031_canonical_sha256(&component_manifest).map_err(|_| VaultStoreError::ContentCorrupt)?;

    Ok(CurrentVaultObservation::Exact(CurrentVaultProof {
        workspace_instance_id: workspace_instance_id.clone(),
        schema_version: VAULT_STORE_SCHEMA_VERSION,
        inventory,
        isolation,
        schema_sha256: component_manifest.schema_sha256,
        database_sha256: component_manifest.database_sha256,
        layout_sha256: component_manifest.layout_sha256,
        component_manifest_sha256,
    }))
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031VaultTargetComponentError {
    code: &'static str,
    message: &'static str,
}

impl V031VaultTargetComponentError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Debug for V031VaultTargetComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031VaultTargetComponentError")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for V031VaultTargetComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for V031VaultTargetComponentError {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031VaultTargetComponentGate {
    workspace_instance_id: WorkspaceInstanceId,
    rollback_gate_binding_sha256: String,
    approved_target_components_evidence_sha256: String,
    vault_schema_sha256: String,
    vault_database_sha256: String,
    vault_layout_sha256: String,
    vault_component_manifest_sha256: String,
    evidence_sha256: String,
    schema_version: u32,
    schema_objects: u64,
    metadata_rows: u64,
    business_rows: u64,
    key_record_count: u64,
    object_root_entry_count: u64,
    directory_count: u64,
    file_count: u64,
}

/// Complete non-secret Vault portion of historical Gate2 persisted in the
/// authenticated checkpoint identity. No field in this record is sampled
/// from the evolved live Vault during restart.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031VaultHistoricalTargetRecord {
    pub(crate) schema_version: u32,
    pub(crate) vault_schema_sha256: String,
    pub(crate) vault_database_sha256: String,
    pub(crate) vault_layout_sha256: String,
    pub(crate) vault_component_manifest_sha256: String,
    pub(crate) evidence_sha256: String,
    pub(crate) schema_objects: u64,
    pub(crate) metadata_rows: u64,
    pub(crate) business_rows: u64,
    pub(crate) key_record_count: u64,
    pub(crate) object_root_entry_count: u64,
    pub(crate) directory_count: u64,
    pub(crate) file_count: u64,
}

impl fmt::Debug for V031VaultTargetComponentGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031VaultTargetComponentGate")
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field(
                "rollback_gate_binding_sha256",
                &self.rollback_gate_binding_sha256,
            )
            .field(
                "approved_target_components_evidence_sha256",
                &self.approved_target_components_evidence_sha256,
            )
            .field("vault_schema_sha256", &self.vault_schema_sha256)
            .field("vault_database_sha256", &self.vault_database_sha256)
            .field("vault_layout_sha256", &self.vault_layout_sha256)
            .field(
                "vault_component_manifest_sha256",
                &self.vault_component_manifest_sha256,
            )
            .field("evidence_sha256", &self.evidence_sha256)
            .field("schema_version", &self.schema_version)
            .field("schema_objects", &self.schema_objects)
            .field("metadata_rows", &self.metadata_rows)
            .field("business_rows", &self.business_rows)
            .field("key_record_count", &self.key_record_count)
            .field("object_root_entry_count", &self.object_root_entry_count)
            .field("directory_count", &self.directory_count)
            .field("file_count", &self.file_count)
            .finish()
    }
}

impl V031VaultTargetComponentGate {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub(crate) fn rollback_gate_binding_sha256(&self) -> &str {
        &self.rollback_gate_binding_sha256
    }

    pub(crate) fn approved_target_components_evidence_sha256(&self) -> &str {
        &self.approved_target_components_evidence_sha256
    }

    pub(crate) fn vault_schema_sha256(&self) -> &str {
        &self.vault_schema_sha256
    }

    pub(crate) fn vault_database_sha256(&self) -> &str {
        &self.vault_database_sha256
    }

    pub(crate) fn vault_layout_sha256(&self) -> &str {
        &self.vault_layout_sha256
    }

    pub(crate) fn vault_component_manifest_sha256(&self) -> &str {
        &self.vault_component_manifest_sha256
    }

    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(crate) const fn schema_objects(&self) -> u64 {
        self.schema_objects
    }

    pub(crate) const fn metadata_rows(&self) -> u64 {
        self.metadata_rows
    }

    pub(crate) const fn business_rows(&self) -> u64 {
        self.business_rows
    }

    pub(crate) const fn key_record_count(&self) -> u64 {
        self.key_record_count
    }

    pub(crate) const fn object_root_entry_count(&self) -> u64 {
        self.object_root_entry_count
    }

    pub(crate) const fn directory_count(&self) -> u64 {
        self.directory_count
    }

    pub(crate) const fn file_count(&self) -> u64 {
        self.file_count
    }

    #[cfg(test)]
    pub(crate) fn for_v031_target_components_orchestrator_test(
        workspace_instance_id: WorkspaceInstanceId,
        rollback_gate_binding_sha256: String,
        approved_target_components_evidence_sha256: String,
        discriminator: &[u8],
    ) -> Self {
        let digest = |label: &str| {
            let mut bytes = label.as_bytes().to_vec();
            bytes.extend_from_slice(discriminator);
            sha256_hex(&bytes)
        };
        Self {
            workspace_instance_id,
            rollback_gate_binding_sha256,
            approved_target_components_evidence_sha256,
            vault_schema_sha256: V031_VAULT_SCHEMA_SHA256.to_owned(),
            vault_database_sha256: digest("vault-database"),
            vault_layout_sha256: digest("vault-layout"),
            vault_component_manifest_sha256: digest("vault-component-manifest"),
            evidence_sha256: digest("vault-target-evidence"),
            schema_version: VAULT_STORE_SCHEMA_VERSION,
            schema_objects: 1,
            metadata_rows: 2,
            business_rows: 0,
            key_record_count: 0,
            object_root_entry_count: 0,
            directory_count: V031_VAULT_DIRECTORY_NAMES.len() as u64,
            file_count: 1,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031VaultRollbackEvidence {
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
    original_identity_sha256: String,
    original_bundle_sha256: String,
    original_rollback_receipt_sha256: String,
}

#[derive(Clone, PartialEq, Eq)]
struct V031VaultWriteAuthorization {
    rollback: V031VaultRollbackEvidence,
    rollback_gate_binding_sha256: String,
    workspace_instance_id: WorkspaceInstanceId,
    approved_target_components_evidence_sha256: String,
    approved_credential_manifest_sha256: String,
    approved_workspace_manifest_sha256: String,
    approved_work_products_manifest_sha256: String,
    approved_credential_count: u64,
    approved_business_rows: u64,
    approved_work_product_business_rows: u64,
}

impl V031VaultWriteAuthorization {
    fn from_gates(
        rollback_gate: &OriginalRollbackVerifiedGate,
        approved_gate: &V031ApprovedMcpTargetComponentsGate,
    ) -> Self {
        Self {
            rollback: V031VaultRollbackEvidence {
                lineage_id: rollback_gate.lineage_id().to_owned(),
                envelope_binding_id: rollback_gate.envelope_binding_id().to_owned(),
                source_profile_proof_sha256: rollback_gate.source_profile_proof_sha256().to_owned(),
                original_identity_sha256: rollback_gate.original_identity_sha256().to_owned(),
                original_bundle_sha256: rollback_gate.original_bundle_sha256().to_owned(),
                original_rollback_receipt_sha256: rollback_gate
                    .original_rollback_receipt_sha256()
                    .to_owned(),
            },
            rollback_gate_binding_sha256: approved_gate.rollback_gate_binding_sha256().to_owned(),
            workspace_instance_id: approved_gate.workspace_instance_id().clone(),
            approved_target_components_evidence_sha256: approved_gate.evidence_sha256().to_owned(),
            approved_credential_manifest_sha256: approved_gate
                .credential_manifest_sha256()
                .to_owned(),
            approved_workspace_manifest_sha256: approved_gate
                .approved_workspace_manifest_sha256()
                .to_owned(),
            approved_work_products_manifest_sha256: approved_gate
                .work_products_manifest_sha256()
                .to_owned(),
            approved_credential_count: approved_gate.credential_count(),
            approved_business_rows: approved_gate.approved_business_rows(),
            approved_work_product_business_rows: approved_gate.work_product_business_rows(),
        }
    }

    fn validate(&self) -> Result<(), V031VaultTargetComponentError> {
        for hash in [
            &self.rollback.lineage_id,
            &self.rollback.source_profile_proof_sha256,
            &self.rollback.original_identity_sha256,
            &self.rollback.original_bundle_sha256,
            &self.rollback.original_rollback_receipt_sha256,
            &self.rollback_gate_binding_sha256,
            &self.approved_target_components_evidence_sha256,
            &self.approved_credential_manifest_sha256,
            &self.approved_workspace_manifest_sha256,
            &self.approved_work_products_manifest_sha256,
        ] {
            if !v031_is_lower_sha256(hash) {
                return Err(v031_vault_invalid());
            }
        }
        if !v031_is_workspace_id(&self.rollback.envelope_binding_id)
            || !v031_is_workspace_id(self.workspace_instance_id.as_str())
            || self.rollback.envelope_binding_id == self.workspace_instance_id.as_str()
            || self.approved_credential_count != 4
            || self.approved_business_rows != 0
            || self.approved_work_product_business_rows != 0
            || v031_canonical_sha256(&self.rollback)? != self.rollback_gate_binding_sha256
        {
            return Err(v031_vault_invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031VaultComponentManifest {
    schema_version: u32,
    schema_sha256: String,
    database_sha256: String,
    layout_sha256: String,
    schema_objects: u64,
    metadata_rows: u64,
    business_rows: u64,
    directory_count: u64,
    file_count: u64,
    key_record_count: u64,
    object_root_entry_count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031VaultTargetEvidence<'a> {
    evidence_schema: &'static str,
    lineage_id: &'a str,
    envelope_binding_id: &'a str,
    source_profile_proof_sha256: &'a str,
    original_identity_sha256: &'a str,
    original_bundle_sha256: &'a str,
    original_rollback_receipt_sha256: &'a str,
    rollback_gate_binding_sha256: &'a str,
    approved_workspace_instance_id: &'a str,
    approved_target_components_evidence_sha256: &'a str,
    approved_credential_manifest_sha256: &'a str,
    approved_workspace_manifest_sha256: &'a str,
    approved_work_products_manifest_sha256: &'a str,
    vault_component_manifest_sha256: &'a str,
    vault_schema_sha256: &'a str,
    vault_database_sha256: &'a str,
    vault_layout_sha256: &'a str,
    vault_schema_version: u32,
    vault_metadata_rows: u64,
    vault_business_rows: u64,
    vault_key_record_count: u64,
    vault_object_root_entry_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031VaultLayoutEntry {
    kind: &'static str,
    basename: String,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031VaultSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V031VaultValidationMode {
    AllowIncomplete,
    RequireComplete,
}

trait V031VaultTargetWriterFailureInjector {
    fn after_initialized_before_sync(&self) -> Result<(), V031VaultTargetComponentError> {
        Ok(())
    }
}

struct NoV031VaultTargetWriterFailure;

impl V031VaultTargetWriterFailureInjector for NoV031VaultTargetWriterFailure {}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031VaultTargetWriterFailurePoint {
    AfterInitializedBeforeSync,
}

#[cfg(test)]
impl V031VaultTargetWriterFailureInjector for V031VaultTargetWriterFailurePoint {
    fn after_initialized_before_sync(&self) -> Result<(), V031VaultTargetComponentError> {
        Err(v031_vault_invalid())
    }
}

/// Prepares only the frozen Step 3 Vault target. Possession of both opaque
/// predecessor gates is the sole write authorization.
pub(crate) fn prepare_v031_vault_target_component(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    prepare_v031_vault_target_component_with_authorization(
        app_local_data_directory,
        &V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate),
    )
}

#[cfg(test)]
pub(crate) fn prepare_v031_vault_target_component_with_writer_failure_for_test(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    failure_point: V031VaultTargetWriterFailurePoint,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    prepare_v031_vault_target_component_with_authorization_and_failure_injector(
        app_local_data_directory,
        &V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate),
        &failure_point,
    )
}

fn prepare_v031_vault_target_component_with_authorization(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    prepare_v031_vault_target_component_with_authorization_and_failure_injector(
        app_local_data_directory,
        authorization,
        &NoV031VaultTargetWriterFailure,
    )
}

fn prepare_v031_vault_target_component_with_authorization_and_failure_injector(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
    failure_injector: &dyn V031VaultTargetWriterFailureInjector,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    // Classify the namespace without a writable SQLite handle, then bind that
    // exact opaque observation to the write mutex before continuing.
    let observed = observe_v031_vault_target_namespace_with_authorization_read_only(
        app_local_data_directory,
        authorization,
    )?;
    let _operation = V031_VAULT_TARGET_OPERATION
        .lock()
        .map_err(|_| v031_vault_invalid())?;
    let reobserved = observe_v031_vault_target_namespace_with_authorization_locked_read_only(
        app_local_data_directory,
        authorization,
    )?;
    if reobserved != observed {
        return Err(v031_vault_invalid());
    }
    if let V031VaultTargetNamespaceObservation::Complete(expected) = reobserved {
        let database = app_local_data_directory
            .join(VAULT_ROOT_DIRECTORY)
            .join(V031_VAULT_DATABASE_NAME);
        v031_sync_vault_database(&database)?;
        let loaded = load_v031_vault_target_component_with_authorization_locked_read_only(
            app_local_data_directory,
            authorization,
        )?;
        if loaded != expected {
            return Err(v031_vault_invalid());
        }
        return Ok(loaded);
    }
    authorization.validate()?;
    v031_validate_app_root(app_local_data_directory)?;
    v031_validate_vault_component(
        app_local_data_directory,
        &authorization.workspace_instance_id,
        V031VaultValidationMode::AllowIncomplete,
    )?;

    let vault_root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
    let store = VaultStore::initialize(&vault_root, authorization.workspace_instance_id.clone())
        .map_err(|_| v031_vault_invalid())?;
    let canonical_vault_root = fs::canonicalize(&vault_root).map_err(|_| v031_vault_invalid())?;
    if store.workspace_instance_id() != &authorization.workspace_instance_id
        || store.encrypted_backup_root() != canonical_vault_root
    {
        return Err(v031_vault_invalid());
    }
    drop(store);
    failure_injector.after_initialized_before_sync()?;
    v031_sync_vault_database(&vault_root.join(V031_VAULT_DATABASE_NAME))?;

    let manifest = v031_validate_vault_component(
        app_local_data_directory,
        &authorization.workspace_instance_id,
        V031VaultValidationMode::RequireComplete,
    )?
    .ok_or_else(v031_vault_invalid)?;
    v031_gate_from_manifest(authorization, manifest)
}

/// Re-authenticates the completed Vault target without invoking any initializer,
/// writable SQLite connection, file sync, recovery, or business operation.
pub(crate) fn verify_v031_vault_target_component_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    expected_gate: &V031VaultTargetComponentGate,
) -> Result<(), V031VaultTargetComponentError> {
    verify_v031_vault_target_component_with_authorization_read_only(
        app_local_data_directory,
        &V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate),
        expected_gate,
    )
}

/// Rebuilds the opaque Vault target gate from immutable schema, identity,
/// layout, and zero-inventory evidence without opening the production store.
pub(crate) fn load_v031_vault_target_component_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    load_v031_vault_target_component_with_authorization_read_only(
        app_local_data_directory,
        &V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate),
    )
}

/// Rebuilds the historical empty Vault Gate2 from the checkpoint record and
/// the independently reconstructed Approved Gate2. The current Vault tree is
/// intentionally not opened: later stage-specific proof loaders authenticate
/// its legally evolved business state.
pub(crate) fn load_v031_vault_historical_target_from_checkpoint_read_only(
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    record: &V031VaultHistoricalTargetRecord,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    let authorization = V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate);
    authorization.validate()?;
    if record.schema_version != VAULT_STORE_SCHEMA_VERSION
        || record.metadata_rows != 2
        || record.business_rows != 0
        || record.key_record_count != 0
        || record.object_root_entry_count != 0
        || record.directory_count != V031_VAULT_DIRECTORY_NAMES.len() as u64
        || record.file_count != 1
    {
        return Err(v031_vault_nonempty());
    }
    let manifest = V031VaultComponentManifest {
        schema_version: record.schema_version,
        schema_sha256: record.vault_schema_sha256.clone(),
        database_sha256: record.vault_database_sha256.clone(),
        layout_sha256: record.vault_layout_sha256.clone(),
        schema_objects: record.schema_objects,
        metadata_rows: record.metadata_rows,
        business_rows: record.business_rows,
        directory_count: record.directory_count,
        file_count: record.file_count,
        key_record_count: record.key_record_count,
        object_root_entry_count: record.object_root_entry_count,
    };
    let gate = v031_gate_from_manifest(&authorization, manifest)?;
    if gate.vault_component_manifest_sha256 != record.vault_component_manifest_sha256
        || gate.evidence_sha256 != record.evidence_sha256
    {
        return Err(v031_vault_invalid());
    }
    Ok(gate)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031VaultTargetAbsentGate {
    _private: (),
}

impl fmt::Debug for V031VaultTargetAbsentGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("V031VaultTargetAbsentGate").finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031VaultTargetIncompleteGate {
    workspace_instance_id: WorkspaceInstanceId,
    rollback_gate_binding_sha256: String,
    approved_target_components_evidence_sha256: String,
    vault_namespace_present: bool,
    vault_layout_sha256: String,
}

impl fmt::Debug for V031VaultTargetIncompleteGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031VaultTargetIncompleteGate")
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field(
                "rollback_gate_binding_sha256",
                &self.rollback_gate_binding_sha256,
            )
            .field(
                "approved_target_components_evidence_sha256",
                &self.approved_target_components_evidence_sha256,
            )
            .field("vault_namespace_present", &self.vault_namespace_present)
            .field("vault_layout_sha256", &self.vault_layout_sha256)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum V031VaultTargetNamespaceObservation {
    Incomplete(V031VaultTargetIncompleteGate),
    Complete(V031VaultTargetComponentGate),
}

/// Proves that Vault has not started while the preceding Approved target is
/// still incomplete.  Production ordering never permits a Vault basename at
/// this point, including an otherwise empty directory.
pub(crate) fn observe_v031_vault_target_absent_read_only(
    app_local_data_directory: &Path,
) -> Result<V031VaultTargetAbsentGate, V031VaultTargetComponentError> {
    let _operation = V031_VAULT_TARGET_OPERATION
        .lock()
        .map_err(|_| v031_vault_invalid())?;
    v031_validate_app_root(app_local_data_directory)?;
    match fs::symlink_metadata(app_local_data_directory.join(VAULT_ROOT_DIRECTORY)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(V031VaultTargetAbsentGate { _private: () })
        }
        Err(_) | Ok(_) => Err(v031_vault_invalid()),
    }
}

/// Authenticates every fixed `AllowIncomplete` Vault layout reachable after
/// the Approved target is complete.  A complete manifest is promoted to the
/// existing write predecessor gate; a partial layout remains a distinct opaque
/// observation and cannot authorize any later migration stage.
pub(crate) fn observe_v031_vault_target_namespace_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
) -> Result<V031VaultTargetNamespaceObservation, V031VaultTargetComponentError> {
    observe_v031_vault_target_namespace_with_authorization_read_only(
        app_local_data_directory,
        &V031VaultWriteAuthorization::from_gates(rollback_gate, approved_gate),
    )
}

fn observe_v031_vault_target_namespace_with_authorization_read_only(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
) -> Result<V031VaultTargetNamespaceObservation, V031VaultTargetComponentError> {
    let _operation = V031_VAULT_TARGET_OPERATION
        .lock()
        .map_err(|_| v031_vault_invalid())?;
    observe_v031_vault_target_namespace_with_authorization_locked_read_only(
        app_local_data_directory,
        authorization,
    )
}

fn observe_v031_vault_target_namespace_with_authorization_locked_read_only(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
) -> Result<V031VaultTargetNamespaceObservation, V031VaultTargetComponentError> {
    authorization.validate()?;
    let observed = v031_validate_vault_component(
        app_local_data_directory,
        &authorization.workspace_instance_id,
        V031VaultValidationMode::AllowIncomplete,
    )?;
    let vault_layout_sha256 = v031_incomplete_vault_layout_sha256(app_local_data_directory)?;
    let Some(manifest) = observed else {
        return Ok(V031VaultTargetNamespaceObservation::Incomplete(
            V031VaultTargetIncompleteGate {
                workspace_instance_id: authorization.workspace_instance_id.clone(),
                rollback_gate_binding_sha256: authorization.rollback_gate_binding_sha256.clone(),
                approved_target_components_evidence_sha256: authorization
                    .approved_target_components_evidence_sha256
                    .clone(),
                vault_namespace_present: fs::symlink_metadata(
                    app_local_data_directory.join(VAULT_ROOT_DIRECTORY),
                )
                .is_ok(),
                vault_layout_sha256,
            },
        ));
    };
    if manifest.directory_count != V031_VAULT_DIRECTORY_NAMES.len() as u64
        || manifest.file_count != 1
    {
        return Ok(V031VaultTargetNamespaceObservation::Incomplete(
            V031VaultTargetIncompleteGate {
                workspace_instance_id: authorization.workspace_instance_id.clone(),
                rollback_gate_binding_sha256: authorization.rollback_gate_binding_sha256.clone(),
                approved_target_components_evidence_sha256: authorization
                    .approved_target_components_evidence_sha256
                    .clone(),
                vault_namespace_present: true,
                vault_layout_sha256,
            },
        ));
    }
    Ok(V031VaultTargetNamespaceObservation::Complete(
        v031_gate_from_manifest(authorization, manifest)?,
    ))
}

fn verify_v031_vault_target_component_with_authorization_read_only(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
    expected_gate: &V031VaultTargetComponentGate,
) -> Result<(), V031VaultTargetComponentError> {
    let observed = load_v031_vault_target_component_with_authorization_read_only(
        app_local_data_directory,
        authorization,
    )?;
    if &observed != expected_gate {
        return Err(v031_vault_invalid());
    }
    Ok(())
}

fn load_v031_vault_target_component_with_authorization_read_only(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    let _operation = V031_VAULT_TARGET_OPERATION
        .lock()
        .map_err(|_| v031_vault_invalid())?;
    load_v031_vault_target_component_with_authorization_locked_read_only(
        app_local_data_directory,
        authorization,
    )
}

fn load_v031_vault_target_component_with_authorization_locked_read_only(
    app_local_data_directory: &Path,
    authorization: &V031VaultWriteAuthorization,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    authorization.validate()?;
    let manifest = v031_validate_vault_component(
        app_local_data_directory,
        &authorization.workspace_instance_id,
        V031VaultValidationMode::RequireComplete,
    )?
    .ok_or_else(v031_vault_invalid)?;
    v031_gate_from_manifest(authorization, manifest)
}

fn v031_gate_from_manifest(
    authorization: &V031VaultWriteAuthorization,
    manifest: V031VaultComponentManifest,
) -> Result<V031VaultTargetComponentGate, V031VaultTargetComponentError> {
    if manifest.schema_version != VAULT_STORE_SCHEMA_VERSION
        || manifest.schema_sha256 != V031_VAULT_SCHEMA_SHA256
        || manifest.metadata_rows != 2
        || manifest.directory_count != V031_VAULT_DIRECTORY_NAMES.len() as u64
        || manifest.file_count != 1
    {
        return Err(v031_vault_invalid());
    }
    if manifest.business_rows != 0
        || manifest.key_record_count != 0
        || manifest.object_root_entry_count != 0
    {
        return Err(v031_vault_nonempty());
    }
    let vault_component_manifest_sha256 = v031_canonical_sha256(&manifest)?;
    let evidence_sha256 = v031_canonical_sha256(&V031VaultTargetEvidence {
        evidence_schema: V031_VAULT_TARGET_EVIDENCE_SCHEMA,
        lineage_id: &authorization.rollback.lineage_id,
        envelope_binding_id: &authorization.rollback.envelope_binding_id,
        source_profile_proof_sha256: &authorization.rollback.source_profile_proof_sha256,
        original_identity_sha256: &authorization.rollback.original_identity_sha256,
        original_bundle_sha256: &authorization.rollback.original_bundle_sha256,
        original_rollback_receipt_sha256: &authorization.rollback.original_rollback_receipt_sha256,
        rollback_gate_binding_sha256: &authorization.rollback_gate_binding_sha256,
        approved_workspace_instance_id: authorization.workspace_instance_id.as_str(),
        approved_target_components_evidence_sha256: &authorization
            .approved_target_components_evidence_sha256,
        approved_credential_manifest_sha256: &authorization.approved_credential_manifest_sha256,
        approved_workspace_manifest_sha256: &authorization.approved_workspace_manifest_sha256,
        approved_work_products_manifest_sha256: &authorization
            .approved_work_products_manifest_sha256,
        vault_component_manifest_sha256: &vault_component_manifest_sha256,
        vault_schema_sha256: &manifest.schema_sha256,
        vault_database_sha256: &manifest.database_sha256,
        vault_layout_sha256: &manifest.layout_sha256,
        vault_schema_version: manifest.schema_version,
        vault_metadata_rows: manifest.metadata_rows,
        vault_business_rows: manifest.business_rows,
        vault_key_record_count: manifest.key_record_count,
        vault_object_root_entry_count: manifest.object_root_entry_count,
    })?;
    Ok(V031VaultTargetComponentGate {
        workspace_instance_id: authorization.workspace_instance_id.clone(),
        rollback_gate_binding_sha256: authorization.rollback_gate_binding_sha256.clone(),
        approved_target_components_evidence_sha256: authorization
            .approved_target_components_evidence_sha256
            .clone(),
        vault_schema_sha256: manifest.schema_sha256,
        vault_database_sha256: manifest.database_sha256,
        vault_layout_sha256: manifest.layout_sha256,
        vault_component_manifest_sha256,
        evidence_sha256,
        schema_version: manifest.schema_version,
        schema_objects: manifest.schema_objects,
        metadata_rows: manifest.metadata_rows,
        business_rows: manifest.business_rows,
        key_record_count: manifest.key_record_count,
        object_root_entry_count: manifest.object_root_entry_count,
        directory_count: manifest.directory_count,
        file_count: manifest.file_count,
    })
}

fn v031_incomplete_vault_layout_sha256(
    app_local_data_directory: &Path,
) -> Result<String, V031VaultTargetComponentError> {
    let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
    let mut layout: Vec<(String, &'static str, Option<u64>, Option<String>)> = Vec::new();
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            layout.push((".".to_owned(), "absent", None, None));
            return v031_canonical_sha256(&layout);
        }
        Err(_) => return Err(v031_vault_invalid()),
        Ok(_) => validate_fixed_local_directory(&root).map_err(|_| v031_vault_invalid())?,
    }
    layout.push((".".to_owned(), "directory", None, None));
    let basenames_before = v031_vault_basenames(&root)?;
    for basename in &basenames_before {
        let path = root.join(basename);
        let metadata = fs::symlink_metadata(&path).map_err(|_| v031_vault_invalid())?;
        if metadata.is_dir() {
            validate_fixed_local_directory(&path).map_err(|_| v031_vault_invalid())?;
            if !v031_vault_directory_is_empty(&path)? {
                return Err(v031_vault_nonempty());
            }
            layout.push((basename.clone(), "directory", None, None));
        } else if metadata.is_file() {
            validate_fixed_local_regular_file(&path).map_err(|_| v031_vault_invalid())?;
            let mut bytes = crate::v031_upgrade_r2::read_bounded_file(
                &path,
                MAX_V031_EMPTY_VAULT_DATABASE_BYTES,
            )
            .map_err(|_| v031_vault_invalid())?;
            let length = bytes.len() as u64;
            let digest = sha256_hex(&bytes);
            bytes.fill(0);
            compiler_fence(Ordering::SeqCst);
            layout.push((basename.clone(), "file", Some(length), Some(digest)));
        } else {
            return Err(v031_vault_invalid());
        }
    }
    if v031_vault_basenames(&root)? != basenames_before {
        return Err(v031_vault_invalid());
    }
    v031_canonical_sha256(&layout)
}

fn v031_validate_app_root(
    app_local_data_directory: &Path,
) -> Result<(), V031VaultTargetComponentError> {
    validate_fixed_local_directory(app_local_data_directory).map_err(|_| v031_vault_invalid())
}

fn v031_validate_current_vault_component(
    app_local_data_directory: &Path,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    database_manifest: &VaultDatabaseReadOnlyManifestV1,
) -> Result<V031VaultComponentManifest, V031VaultTargetComponentError> {
    v031_validate_app_root(app_local_data_directory)?;
    if database_manifest.schema_version != VAULT_STORE_SCHEMA_VERSION
        || database_manifest.schema_sha256 != V031_VAULT_SCHEMA_SHA256
        || !v031_is_lower_sha256(&database_manifest.database_sha256)
        || database_manifest
            .wal_sha256
            .as_deref()
            .is_some_and(|hash| !v031_is_lower_sha256(hash))
        || database_manifest.schema_object_count == 0
        || database_manifest.metadata_rows != 2
        || database_manifest.business_rows < database_manifest.journal_row_count
        || database_manifest.committed_object_count > database_manifest.journal_row_count
        || !v031_is_workspace_id(expected_workspace_instance_id.as_str())
    {
        return Err(v031_vault_invalid());
    }

    let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
    validate_fixed_local_directory(&root).map_err(|_| v031_vault_invalid())?;
    let basenames_before = v031_vault_basenames(&root)?;
    let allowed = V031_VAULT_DIRECTORY_NAMES
        .into_iter()
        .chain([
            V031_VAULT_DATABASE_NAME,
            V031_VAULT_WAL_NAME,
            V031_VAULT_SHM_NAME,
        ])
        .collect::<BTreeSet<_>>();
    if basenames_before
        .iter()
        .any(|name| !allowed.contains(name.as_str()))
    {
        return Err(v031_vault_invalid());
    }

    let mut layout = Vec::new();
    for name in V031_VAULT_DIRECTORY_NAMES {
        let path = root.join(name);
        validate_fixed_local_directory(&path).map_err(|_| v031_vault_invalid())?;
        layout.push(V031VaultLayoutEntry {
            kind: "directory",
            basename: name.to_owned(),
            bytes: None,
            sha256: None,
        });
    }

    let database = root.join(V031_VAULT_DATABASE_NAME);
    let database_file =
        v031_pin_current_vault_physical_file(&database, &database_manifest.database_sha256)?;
    layout.push(V031VaultLayoutEntry {
        kind: "file",
        basename: V031_VAULT_DATABASE_NAME.to_owned(),
        bytes: Some(database_file.length),
        sha256: Some(database_manifest.database_sha256.clone()),
    });

    let wal_path = root.join(V031_VAULT_WAL_NAME);
    let wal_file = match &database_manifest.wal_sha256 {
        Some(expected_sha256) => {
            let pinned = v031_pin_current_vault_physical_file(&wal_path, expected_sha256)?;
            v031_validate_current_sqlite_wal(database_file.bytes.deref(), pinned.bytes.deref())?;
            layout.push(V031VaultLayoutEntry {
                kind: "file",
                basename: V031_VAULT_WAL_NAME.to_owned(),
                bytes: Some(pinned.length),
                sha256: Some(expected_sha256.clone()),
            });
            Some(pinned)
        }
        None => {
            match fs::symlink_metadata(&wal_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) | Err(_) => return Err(v031_vault_invalid()),
            }
            None
        }
    };
    let shm_path = root.join(V031_VAULT_SHM_NAME);
    let shm_file = match fs::symlink_metadata(&shm_path) {
        Ok(_) => {
            // SHM carries only volatile lock/read-mark state. Its path and file
            // identity are controlled, but its bytes never enter durable proof.
            Some(v031_pin_current_vault_volatile_file_identity(&shm_path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(v031_vault_invalid()),
    };
    layout.sort_by(|left, right| left.basename.cmp(&right.basename));

    if v031_vault_basenames(&root)? != basenames_before {
        return Err(v031_vault_invalid());
    }
    v031_verify_pinned_current_vault_physical_file(&database, &database_file)?;
    if let Some(pinned) = wal_file.as_ref() {
        v031_verify_pinned_current_vault_physical_file(&wal_path, pinned)?;
    }
    if let Some(pinned) = shm_file.as_ref() {
        v031_verify_pinned_current_vault_volatile_file_identity(&shm_path, pinned)?;
    }

    Ok(V031VaultComponentManifest {
        schema_version: database_manifest.schema_version,
        schema_sha256: database_manifest.schema_sha256.clone(),
        database_sha256: database_manifest.database_sha256.clone(),
        layout_sha256: v031_canonical_sha256(&layout)?,
        schema_objects: database_manifest.schema_object_count,
        metadata_rows: database_manifest.metadata_rows,
        business_rows: database_manifest.business_rows,
        directory_count: V031_VAULT_DIRECTORY_NAMES.len() as u64,
        file_count: if database_manifest.wal_sha256.is_some() {
            2
        } else {
            1
        },
        key_record_count: 0,
        object_root_entry_count: 0,
    })
}

struct V031PinnedCurrentVaultPhysicalFile {
    _file: File,
    identity: Vec<u8>,
    length: u64,
    last_write_time: u64,
    sha256: String,
    bytes: ZeroizingBytes,
}

struct V031PinnedCurrentVaultVolatileFileIdentity {
    _file: File,
    identity: Vec<u8>,
}

#[cfg(windows)]
fn v031_pin_current_vault_physical_file(
    path: &Path,
    expected_sha256: &str,
) -> Result<V031PinnedCurrentVaultPhysicalFile, V031VaultTargetComponentError> {
    // This is deliberately not `validate_fixed_local_regular_file`: that
    // immutable-file helper opens with FILE_SHARE_READ only, which is
    // incompatible with a live SQLite writer. The already-validated parent
    // plus OPEN_REPARSE_POINT and `fixed_local_file_identity` preserve the
    // fixed-local, no-reparse, single-link guarantees on this pinned handle.
    let parent = path.parent().ok_or_else(v031_vault_invalid)?;
    validate_fixed_local_directory(parent).map_err(|_| v031_vault_invalid())?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| v031_vault_invalid())?;
    let identity = fixed_local_file_identity(&file).map_err(|_| v031_vault_invalid())?;
    let metadata_before = file.metadata().map_err(|_| v031_vault_invalid())?;
    let length = metadata_before.file_size();
    if length == 0 || length > MAX_V031_EMPTY_VAULT_DATABASE_BYTES as u64 {
        return Err(v031_vault_invalid());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| v031_vault_invalid())?);
    (&mut file)
        .take(MAX_V031_EMPTY_VAULT_DATABASE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| v031_vault_invalid())?;
    if bytes.len() as u64 != length || bytes.len() > MAX_V031_EMPTY_VAULT_DATABASE_BYTES {
        bytes.fill(0);
        return Err(v031_vault_invalid());
    }
    let bytes = ZeroizingBytes::new(bytes);
    let sha256 = sha256_hex(&bytes);
    let metadata_after = file.metadata().map_err(|_| v031_vault_invalid())?;
    if sha256 != expected_sha256
        || fixed_local_file_identity(&file).map_err(|_| v031_vault_invalid())? != identity
        || metadata_after.file_size() != length
        || metadata_after.last_write_time() != metadata_before.last_write_time()
    {
        return Err(v031_vault_invalid());
    }
    Ok(V031PinnedCurrentVaultPhysicalFile {
        _file: file,
        identity,
        length,
        last_write_time: metadata_before.last_write_time(),
        sha256,
        bytes,
    })
}

#[cfg(not(windows))]
fn v031_pin_current_vault_physical_file(
    _path: &Path,
    _expected_sha256: &str,
) -> Result<V031PinnedCurrentVaultPhysicalFile, V031VaultTargetComponentError> {
    Err(v031_vault_invalid())
}

fn v031_verify_pinned_current_vault_physical_file(
    path: &Path,
    expected: &V031PinnedCurrentVaultPhysicalFile,
) -> Result<(), V031VaultTargetComponentError> {
    let observed = v031_pin_current_vault_physical_file(path, &expected.sha256)?;
    if observed.identity != expected.identity
        || observed.length != expected.length
        || observed.last_write_time != expected.last_write_time
        || observed.bytes.deref() != expected.bytes.deref()
    {
        return Err(v031_vault_invalid());
    }
    Ok(())
}

#[cfg(windows)]
fn v031_pin_current_vault_volatile_file_identity(
    path: &Path,
) -> Result<V031PinnedCurrentVaultVolatileFileIdentity, V031VaultTargetComponentError> {
    let parent = path.parent().ok_or_else(v031_vault_invalid)?;
    validate_fixed_local_directory(parent).map_err(|_| v031_vault_invalid())?;
    let path_metadata = fs::symlink_metadata(path).map_err(|_| v031_vault_invalid())?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(v031_vault_invalid());
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| v031_vault_invalid())?;
    if !file.metadata().map_err(|_| v031_vault_invalid())?.is_file() {
        return Err(v031_vault_invalid());
    }
    let identity = fixed_local_file_identity(&file).map_err(|_| v031_vault_invalid())?;
    Ok(V031PinnedCurrentVaultVolatileFileIdentity {
        _file: file,
        identity,
    })
}

#[cfg(not(windows))]
fn v031_pin_current_vault_volatile_file_identity(
    _path: &Path,
) -> Result<V031PinnedCurrentVaultVolatileFileIdentity, V031VaultTargetComponentError> {
    Err(v031_vault_invalid())
}

fn v031_verify_pinned_current_vault_volatile_file_identity(
    path: &Path,
    expected: &V031PinnedCurrentVaultVolatileFileIdentity,
) -> Result<(), V031VaultTargetComponentError> {
    let observed = v031_pin_current_vault_volatile_file_identity(path)?;
    if observed.identity != expected.identity {
        return Err(v031_vault_invalid());
    }
    Ok(())
}

fn v031_validate_current_sqlite_wal(
    database: &[u8],
    wal: &[u8],
) -> Result<(), V031VaultTargetComponentError> {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
    const WAL_HEADER_BYTES: usize = 32;
    const WAL_FRAME_HEADER_BYTES: usize = 24;
    const WAL_MAGIC: u32 = 0x377f_0682;
    const WAL_FORMAT_VERSION: u32 = 3_007_000;

    if database.len() < 100 || &database[..SQLITE_HEADER.len()] != SQLITE_HEADER {
        return Err(v031_vault_invalid());
    }
    let encoded_database_page_size = u16::from_be_bytes([database[16], database[17]]);
    let database_page_size = if encoded_database_page_size == 1 {
        65_536_usize
    } else {
        usize::from(encoded_database_page_size)
    };
    if !(512..=65_536).contains(&database_page_size) || !database_page_size.is_power_of_two() {
        return Err(v031_vault_invalid());
    }
    if wal.len() < WAL_HEADER_BYTES {
        return Err(v031_vault_invalid());
    }
    let magic = v031_sqlite_u32_be(&wal[0..4])?;
    let wal_page_size =
        usize::try_from(v031_sqlite_u32_be(&wal[8..12])?).map_err(|_| v031_vault_invalid())?;
    let frame_bytes = WAL_FRAME_HEADER_BYTES
        .checked_add(wal_page_size)
        .ok_or_else(v031_vault_invalid)?;
    if magic & !1 != WAL_MAGIC
        || v031_sqlite_u32_be(&wal[4..8])? != WAL_FORMAT_VERSION
        || wal_page_size != database_page_size
        || frame_bytes == 0
        || wal.len() == WAL_HEADER_BYTES
        || !(wal.len() - WAL_HEADER_BYTES).is_multiple_of(frame_bytes)
    {
        return Err(v031_vault_invalid());
    }

    // SQLite stores all WAL header/frame fields in big-endian form, while
    // the magic LSB selects how the checksum input words are interpreted.
    let checksum_words_are_big_endian = magic & 1 == 1;
    let mut checksum =
        v031_extend_sqlite_wal_checksum([0, 0], &wal[..24], checksum_words_are_big_endian)?;
    if checksum[0] != v031_sqlite_u32_be(&wal[24..28])?
        || checksum[1] != v031_sqlite_u32_be(&wal[28..32])?
    {
        return Err(v031_vault_invalid());
    }

    let salt = &wal[16..24];
    let mut final_frame_commits = false;
    for frame in wal[WAL_HEADER_BYTES..].chunks_exact(frame_bytes) {
        if v031_sqlite_u32_be(&frame[0..4])? == 0 || &frame[8..16] != salt {
            return Err(v031_vault_invalid());
        }
        checksum =
            v031_extend_sqlite_wal_checksum(checksum, &frame[..8], checksum_words_are_big_endian)?;
        checksum = v031_extend_sqlite_wal_checksum(
            checksum,
            &frame[WAL_FRAME_HEADER_BYTES..],
            checksum_words_are_big_endian,
        )?;
        if checksum[0] != v031_sqlite_u32_be(&frame[16..20])?
            || checksum[1] != v031_sqlite_u32_be(&frame[20..24])?
        {
            return Err(v031_vault_invalid());
        }
        final_frame_commits = v031_sqlite_u32_be(&frame[4..8])? != 0;
    }
    if !final_frame_commits {
        return Err(v031_vault_invalid());
    }
    Ok(())
}

fn v031_extend_sqlite_wal_checksum(
    mut checksum: [u32; 2],
    bytes: &[u8],
    words_are_big_endian: bool,
) -> Result<[u32; 2], V031VaultTargetComponentError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(v031_vault_invalid());
    }
    for pair in bytes.chunks_exact(8) {
        let first = v031_sqlite_checksum_word(&pair[..4], words_are_big_endian)?;
        let second = v031_sqlite_checksum_word(&pair[4..], words_are_big_endian)?;
        checksum[0] = checksum[0].wrapping_add(first).wrapping_add(checksum[1]);
        checksum[1] = checksum[1].wrapping_add(second).wrapping_add(checksum[0]);
    }
    Ok(checksum)
}

fn v031_sqlite_checksum_word(
    bytes: &[u8],
    big_endian: bool,
) -> Result<u32, V031VaultTargetComponentError> {
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| v031_vault_invalid())?;
    Ok(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

fn v031_sqlite_u32_be(bytes: &[u8]) -> Result<u32, V031VaultTargetComponentError> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| v031_vault_invalid())?,
    ))
}

fn v031_validate_vault_component(
    app_local_data_directory: &Path,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    mode: V031VaultValidationMode,
) -> Result<Option<V031VaultComponentManifest>, V031VaultTargetComponentError> {
    v031_validate_app_root(app_local_data_directory)?;
    let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if mode == V031VaultValidationMode::AllowIncomplete {
                Ok(None)
            } else {
                Err(v031_vault_invalid())
            };
        }
        Err(_) => return Err(v031_vault_invalid()),
        Ok(_) => validate_fixed_local_directory(&root).map_err(|_| v031_vault_invalid())?,
    }

    let basenames_before = v031_vault_basenames(&root)?;
    let allowed = V031_VAULT_DIRECTORY_NAMES
        .into_iter()
        .chain([V031_VAULT_DATABASE_NAME])
        .collect::<BTreeSet<_>>();
    if basenames_before
        .iter()
        .any(|name| !allowed.contains(name.as_str()))
    {
        return Err(v031_vault_invalid());
    }

    let mut layout = Vec::new();
    let mut directory_count = 0_u64;
    for name in V031_VAULT_DIRECTORY_NAMES {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_fixed_local_directory(&path).map_err(|_| v031_vault_invalid())?;
                // Every directory reachable while the Step-3 initializer is
                // incomplete is empty.  Reject residue during the read-only
                // observation, before the initializer can repair around it.
                if !v031_vault_directory_is_empty(&path)? {
                    return Err(v031_vault_nonempty());
                }
                directory_count = directory_count
                    .checked_add(1)
                    .ok_or_else(v031_vault_invalid)?;
                layout.push(V031VaultLayoutEntry {
                    kind: "directory",
                    basename: name.to_owned(),
                    bytes: None,
                    sha256: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if mode == V031VaultValidationMode::RequireComplete {
                    return Err(v031_vault_invalid());
                }
            }
            Err(_) => return Err(v031_vault_invalid()),
        }
    }

    let database = root.join(V031_VAULT_DATABASE_NAME);
    let database_manifest = match fs::symlink_metadata(&database) {
        Ok(_) => {
            validate_fixed_local_regular_file(&database).map_err(|_| v031_vault_invalid())?;
            Some(v031_validate_vault_database(
                &database,
                expected_workspace_instance_id,
            )?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(v031_vault_invalid()),
    };

    if mode != V031VaultValidationMode::AllowIncomplete
        && (directory_count != V031_VAULT_DIRECTORY_NAMES.len() as u64
            || database_manifest.is_none())
    {
        return Err(v031_vault_invalid());
    }
    let Some((schema_sha256, database_sha256, schema_objects, metadata_rows, business_rows)) =
        database_manifest
    else {
        return Ok(None);
    };
    let database_bytes = fs::metadata(&database)
        .map_err(|_| v031_vault_invalid())?
        .len();
    layout.push(V031VaultLayoutEntry {
        kind: "file",
        basename: V031_VAULT_DATABASE_NAME.to_owned(),
        bytes: Some(database_bytes),
        sha256: Some(database_sha256.clone()),
    });
    layout.sort_by(|left, right| left.basename.cmp(&right.basename));

    if v031_vault_basenames(&root)? != basenames_before {
        return Err(v031_vault_invalid());
    }
    for name in V031_VAULT_DIRECTORY_NAMES {
        let path = root.join(name);
        if path.exists() && !v031_vault_directory_is_empty(&path)? {
            return Err(v031_vault_nonempty());
        }
    }
    validate_fixed_local_regular_file(&database).map_err(|_| v031_vault_invalid())?;
    if business_rows != 0 {
        return Err(v031_vault_nonempty());
    }
    Ok(Some(V031VaultComponentManifest {
        schema_version: VAULT_STORE_SCHEMA_VERSION,
        schema_sha256,
        database_sha256,
        layout_sha256: v031_canonical_sha256(&layout)?,
        schema_objects,
        metadata_rows,
        business_rows,
        directory_count,
        file_count: 1,
        key_record_count: 0,
        object_root_entry_count: 0,
    }))
}

fn v031_validate_vault_database(
    path: &Path,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(String, String, u64, u64, u64), V031VaultTargetComponentError> {
    let mut bytes_before =
        crate::v031_upgrade_r2::read_bounded_file(path, MAX_V031_EMPTY_VAULT_DATABASE_BYTES)
            .map_err(|_| v031_vault_invalid())?;
    let database_sha256 = sha256_hex(&bytes_before);
    let uri = v031_immutable_sqlite_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| v031_vault_invalid())?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| v031_vault_invalid())?;
    if quick_check != "ok" {
        return Err(v031_vault_invalid());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| v031_vault_invalid())?;
    if foreign_keys
        .query([])
        .map_err(|_| v031_vault_invalid())?
        .next()
        .map_err(|_| v031_vault_invalid())?
        .is_some()
    {
        return Err(v031_vault_invalid());
    }
    drop(foreign_keys);

    let schema = v031_vault_schema_objects(&connection)?;
    let schema_sha256 = v031_canonical_sha256(&schema)?;
    if schema_sha256 != V031_VAULT_SCHEMA_SHA256 {
        return Err(v031_vault_invalid());
    }
    let (vault_meta_rows, schema_version, workspace): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*),MIN(schema_version),MIN(workspace_instance_id) FROM vault_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| v031_vault_invalid())?;
    let (lifecycle_meta_rows, lifecycle_schema_version): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),MIN(schema_version) FROM vault_lifecycle_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| v031_vault_invalid())?;
    if vault_meta_rows != 1
        || schema_version != i64::from(VAULT_STORE_SCHEMA_VERSION)
        || workspace != expected_workspace_instance_id.as_str()
        || lifecycle_meta_rows != 1
        || lifecycle_schema_version != i64::from(privacy::VAULT_LIFECYCLE_SCHEMA_VERSION)
    {
        return Err(v031_vault_invalid());
    }

    let mut business_rows = 0_u64;
    for table in [
        "object_journal",
        "nonce_reservations",
        "vault_object_retention",
        "vault_cleanup_journal",
        "vault_cleanup_candidates",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(|_| v031_vault_invalid())?;
        business_rows = business_rows
            .checked_add(u64::try_from(count).map_err(|_| v031_vault_invalid())?)
            .ok_or_else(v031_vault_invalid)?;
    }
    drop(connection);
    let mut bytes_after =
        crate::v031_upgrade_r2::read_bounded_file(path, MAX_V031_EMPTY_VAULT_DATABASE_BYTES)
            .map_err(|_| v031_vault_invalid())?;
    let unchanged = bytes_before == bytes_after && sha256_hex(&bytes_after) == database_sha256;
    bytes_before.fill(0);
    bytes_after.fill(0);
    compiler_fence(Ordering::SeqCst);
    if !unchanged {
        return Err(v031_vault_invalid());
    }
    Ok((
        schema_sha256,
        database_sha256,
        u64::try_from(schema.len()).map_err(|_| v031_vault_invalid())?,
        2,
        business_rows,
    ))
}

fn v031_vault_schema_objects(
    connection: &Connection,
) -> Result<Vec<V031VaultSchemaObject>, V031VaultTargetComponentError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name",
        )
        .map_err(|_| v031_vault_invalid())?;
    let rows = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok(V031VaultSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql_sha256: sha256_hex(sql.as_bytes()),
            })
        })
        .map_err(|_| v031_vault_invalid())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| v031_vault_invalid())
}

fn v031_sync_vault_database(path: &Path) -> Result<(), V031VaultTargetComponentError> {
    validate_fixed_local_regular_file(path).map_err(|_| v031_vault_invalid())?;
    let mut verified =
        crate::v031_upgrade_r2::read_bounded_file(path, MAX_V031_EMPTY_VAULT_DATABASE_BYTES)
            .map_err(|_| v031_vault_invalid())?;
    verified.fill(0);
    compiler_fence(Ordering::SeqCst);
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| v031_vault_invalid())
}

fn v031_vault_basenames(root: &Path) -> Result<Vec<String>, V031VaultTargetComponentError> {
    let mut names = fs::read_dir(root)
        .map_err(|_| v031_vault_invalid())?
        .map(|entry| {
            entry
                .map_err(|_| v031_vault_invalid())?
                .file_name()
                .into_string()
                .map_err(|_| v031_vault_invalid())
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

fn v031_vault_directory_is_empty(path: &Path) -> Result<bool, V031VaultTargetComponentError> {
    validate_fixed_local_directory(path).map_err(|_| v031_vault_invalid())?;
    Ok(fs::read_dir(path)
        .map_err(|_| v031_vault_invalid())?
        .next()
        .is_none())
}

fn v031_immutable_sqlite_uri(path: &Path) -> Result<String, V031VaultTargetComponentError> {
    let canonical = fs::canonicalize(path).map_err(|_| v031_vault_invalid())?;
    let raw = canonical.to_str().ok_or_else(v031_vault_invalid)?;
    let raw = raw.strip_prefix(r"\\?\").unwrap_or(raw).replace('\\', "/");
    let bytes = raw.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'/'
        || bytes[3..].contains(&b':')
    {
        return Err(v031_vault_invalid());
    }
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(format!("file:///{encoded}?mode=ro&immutable=1"))
}

fn v031_canonical_sha256(value: &impl Serialize) -> Result<String, V031VaultTargetComponentError> {
    let bytes = canonical_json_v1(value).map_err(|_| v031_vault_invalid())?;
    Ok(sha256_hex(&bytes))
}

fn v031_is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn v031_is_workspace_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("ws_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn v031_vault_invalid() -> V031VaultTargetComponentError {
    V031VaultTargetComponentError::new(
        "v031_vault_target_component_invalid",
        "The v0.3.1 Vault target component is unavailable or inconsistent.",
    )
}

fn v031_vault_nonempty() -> V031VaultTargetComponentError {
    V031VaultTargetComponentError::new(
        "v031_vault_target_component_nonempty",
        "The v0.3.1 Vault target component contains unexpected application state.",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VaultImportBinding {
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub object_id: ObjectId,
    pub object_version: u64,
    pub source_sha256: Sha256Hex,
    pub envelope_sha256: Sha256Hex,
    pub content_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VaultAuxBinding {
    pub case_id: CaseId,
    pub object_id: ObjectId,
    pub object_version: u64,
    pub content_sha256: Sha256Hex,
    pub envelope_sha256: Sha256Hex,
    pub content_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SealedPrivateValueBatch {
    pub references: Vec<PrivateValueRefV1>,
    pub binding: VaultAuxBinding,
}

pub(super) struct VaultAuxLease {
    decrypted: DecryptedVaultObjectV1,
}

impl VaultAuxLease {
    pub fn content(&self) -> &[u8] {
        &self.decrypted.content
    }
}

impl fmt::Debug for VaultAuxLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultAuxLease")
            .field("case_id", &self.decrypted.case_id)
            .field("object_id", &self.decrypted.object_id)
            .field("object_version", &self.decrypted.version)
            .field(
                "content",
                &format_args!("[DECRYPTED PRIVATE {} BYTES]", self.decrypted.content.len()),
            )
            .finish()
    }
}
pub(super) fn initialize_vault_link_schema(connection: &Connection) -> Result<(), VaultStoreError> {
    privacy::initialize_privacy_vault_link_schema(connection)
        .map_err(|_| VaultStoreError::DatabaseFailed)
}

pub(super) fn persist_vault_import(
    transaction: &Transaction<'_>,
    binding: &VaultImportBinding,
    retention_expires_at_unix: u64,
    retention_policy_revision: u64,
    bound_at_unix: u64,
) -> Result<(), VaultStoreError> {
    if retention_expires_at_unix <= bound_at_unix || retention_policy_revision == 0 {
        return Err(VaultStoreError::InvalidInput);
    }
    transaction
        .execute(
            "INSERT INTO privacy_vault_material_refs(
                 material_id,case_id,object_id,object_version,source_sha256,envelope_sha256,
                 content_bytes,retention_expires_at_unix,retention_policy_revision,bound_at_unix,
                 import_state
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'vault_committed')",
            params![
                binding.material_id.as_str(),
                binding.case_id.as_str(),
                binding.object_id.as_str(),
                sql_i64(binding.object_version)?,
                binding.source_sha256.as_str(),
                binding.envelope_sha256.as_str(),
                sql_i64(binding.content_bytes)?,
                sql_i64(retention_expires_at_unix)?,
                sql_i64(retention_policy_revision)?,
                sql_i64(bound_at_unix)?,
            ],
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    Ok(())
}

pub(super) fn complete_vault_material_processing(
    transaction: &Transaction<'_>,
    binding: &VaultImportBinding,
    media_type: &str,
    page_count: u32,
) -> Result<(), VaultStoreError> {
    if media_type.is_empty()
        || media_type.len() > 255
        || media_type.chars().any(char::is_control)
        || page_count == 0
        || page_count > 10_000
    {
        return Err(VaultStoreError::InvalidInput);
    }
    let changed = transaction
        .execute(
            "UPDATE privacy_materials
             SET media_type=?2,page_count=?3,updated_at=CURRENT_TIMESTAMP,
                 row_version=row_version+1
             WHERE material_id=?1 AND source_sha256=?4 AND state IN('registered','failed')",
            params![
                binding.material_id.as_str(),
                media_type,
                page_count,
                binding.source_sha256.as_str(),
            ],
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if changed != 1 {
        return Err(VaultStoreError::ContentCorrupt);
    }
    mark_vault_review_ready(transaction, &binding.material_id)
}
pub(super) fn mark_vault_review_ready(
    transaction: &Transaction<'_>,
    material_id: &MaterialId,
) -> Result<(), VaultStoreError> {
    let changed = transaction
        .execute(
            "UPDATE privacy_vault_material_refs
             SET import_state='review_ready',failure_code=NULL,updated_at=CURRENT_TIMESTAMP
             WHERE material_id=?1 AND import_state IN('vault_committed','processing_failed')",
            [material_id.as_str()],
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(VaultStoreError::ContentCorrupt)
    }
}

pub(super) fn mark_vault_processing_failed(
    connection: &Connection,
    material_id: &MaterialId,
    failure_code: &str,
) -> Result<(), VaultStoreError> {
    if failure_code.is_empty()
        || failure_code.len() > 128
        || failure_code.chars().any(char::is_control)
    {
        return Err(VaultStoreError::InvalidInput);
    }
    let changed = connection
        .execute(
            "UPDATE privacy_vault_material_refs
             SET import_state='processing_failed',failure_code=?2,updated_at=CURRENT_TIMESTAMP
             WHERE material_id=?1 AND import_state='vault_committed'",
            params![material_id.as_str(), failure_code],
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    connection
        .execute(
            "UPDATE privacy_materials
             SET state='failed',updated_at=CURRENT_TIMESTAMP,row_version=row_version+1
             WHERE material_id=?1 AND state='registered'",
            [material_id.as_str()],
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(VaultStoreError::ContentCorrupt)
    }
}

pub(super) fn load_vault_binding_for_material(
    connection: &Connection,
    material_id: &str,
) -> Result<Option<VaultImportBinding>, VaultStoreError> {
    let row = connection
        .query_row(
            "SELECT case_id,object_id,object_version,source_sha256,envelope_sha256,content_bytes
             FROM privacy_vault_material_refs
             WHERE material_id=?1 AND import_state IN('vault_committed','review_ready','processing_failed')",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    row.map(|row| {
        Ok(VaultImportBinding {
            case_id: CaseId::parse(row.0).map_err(|_| VaultStoreError::ContentCorrupt)?,
            material_id: MaterialId::parse(material_id.to_owned())
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            object_id: ObjectId::parse(row.1).map_err(|_| VaultStoreError::ContentCorrupt)?,
            object_version: u64::try_from(row.2).map_err(|_| VaultStoreError::ContentCorrupt)?,
            source_sha256: Sha256Hex::parse(row.3).map_err(|_| VaultStoreError::ContentCorrupt)?,
            envelope_sha256: Sha256Hex::parse(row.4)
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            content_bytes: u64::try_from(row.5).map_err(|_| VaultStoreError::ContentCorrupt)?,
        })
    })
    .transpose()
}

pub(super) fn load_vault_binding_for_redaction(
    connection: &Connection,
    redaction_id: &str,
) -> Result<Option<VaultImportBinding>, VaultStoreError> {
    let material_id = connection
        .query_row(
            "SELECT material_id FROM privacy_redactions WHERE redaction_id=?1",
            [redaction_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    material_id
        .as_deref()
        .map(|material_id| load_vault_binding_for_material(connection, material_id))
        .transpose()
        .map(Option::flatten)
}

fn sql_i64(value: u64) -> Result<i64, VaultStoreError> {
    i64::try_from(value).map_err(|_| VaultStoreError::InvalidInput)
}

pub(super) struct ImportSourceRequest<'a> {
    pub case_id: &'a CaseId,
    pub material_id: &'a MaterialId,
    pub original_file_name: &'a str,
    pub original_source_path: &'a Path,
    pub original_media_type: &'a str,
    pub content: &'a [u8],
    pub imported_at_unix: u64,
}

impl fmt::Debug for ImportSourceRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportSourceRequest")
            .field("case_id", self.case_id)
            .field("material_id", self.material_id)
            .field("original_file_name", &"[ENCRYPTED_PRIVATE_METADATA]")
            .field("original_source_path", &"[ENCRYPTED_PRIVATE_METADATA]")
            .field("original_media_type", &self.original_media_type)
            .field(
                "content",
                &format_args!("[PRIVATE {} BYTES]", self.content.len()),
            )
            .field("imported_at_unix", &self.imported_at_unix)
            .finish()
    }
}

pub(super) struct PrivateValueToSeal<'a> {
    pub value_locator_hash: Sha256Hex,
    pub private_value: &'a str,
}

impl fmt::Debug for PrivateValueToSeal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateValueToSeal")
            .field("value_locator_hash", &self.value_locator_hash)
            .field("private_value", &"[ENCRYPTED_PRIVATE_VALUE]")
            .finish()
    }
}

pub(super) struct VaultSourceLease {
    decrypted: DecryptedVaultObjectV1,
}

impl VaultSourceLease {
    pub fn content(&self) -> &[u8] {
        &self.decrypted.content
    }
}

impl fmt::Debug for VaultSourceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSourceLease")
            .field("case_id", &self.decrypted.case_id)
            .field("object_id", &self.decrypted.object_id)
            .field("object_version", &self.decrypted.version)
            .field(
                "content",
                &format_args!("[DECRYPTED PRIVATE {} BYTES]", self.decrypted.content.len()),
            )
            .finish()
    }
}

pub(super) trait VaultBroker: Send + Sync {
    fn export_encrypted_backup(
        &self,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError>;

    fn export_encrypted_backup_read_only(
        &self,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError>;

    fn import_source(
        &self,
        request: ImportSourceRequest<'_>,
    ) -> Result<VaultImportBinding, VaultStoreError>;

    fn read_source(
        &self,
        binding: &VaultImportBinding,
    ) -> Result<VaultSourceLease, VaultStoreError>;

    fn seal_private_values(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        values: &[PrivateValueToSeal<'_>],
        created_at_unix: u64,
    ) -> Result<SealedPrivateValueBatch, VaultStoreError>;

    fn seal_aux_payload(
        &self,
        case_id: &CaseId,
        payload_kind: &str,
        content: &[u8],
        created_at_unix: u64,
    ) -> Result<VaultAuxBinding, VaultStoreError>;

    fn read_aux_payload(&self, binding: &VaultAuxBinding)
        -> Result<VaultAuxLease, VaultStoreError>;

    fn bind_aux_retention(
        &self,
        binding: &VaultAuxBinding,
        expires_at_unix: u64,
        legal_hold: bool,
        policy_revision: u64,
        bound_at_unix: u64,
    ) -> Result<(), VaultStoreError>;

    fn bind_retention(
        &self,
        binding: &VaultImportBinding,
        expires_at_unix: u64,
        legal_hold: bool,
        policy_revision: u64,
        bound_at_unix: u64,
    ) -> Result<(), VaultStoreError>;

    fn set_legal_hold(
        &self,
        binding: &VaultImportBinding,
        enabled: bool,
        changed_at_unix: u64,
    ) -> Result<(), VaultStoreError>;

    fn run_or_resume_expired_cleanup(
        &self,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<VaultCleanupReportV1, VaultStoreError>;

    fn run_or_resume_expired_cleanup_with_failure_injector(
        &self,
        cleanup_id: &str,
        now_unix: u64,
        failure_injector: &dyn V031Step8MaintenanceFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError>;

    fn recover_cleanups(&self, now_unix: u64)
        -> Result<Vec<VaultCleanupReportV1>, VaultStoreError>;

    fn inspect_cleanup_status_read_only(
        &self,
    ) -> Result<VaultCleanupPendingStatusV1, VaultStoreError>;

    fn inspect_inventory_read_only(&self) -> Result<VaultReadOnlyInventoryV1, VaultStoreError>;

    fn isolation_status(&self) -> Result<VaultIsolationStatusV1, VaultStoreError>;

    fn startup_vault_present(&self) -> bool;

    fn startup_write_required(&self) -> bool;

    fn prepare_for_migration_backup_after_preflight(&self) -> Result<(), VaultStoreError>;

    fn upgrade_schema_after_backup(&self) -> Result<(), VaultStoreError>;
}

pub(super) struct LocalEncryptedVaultBroker {
    root: PathBuf,
    workspace_instance_id: WorkspaceInstanceId,
    store: Mutex<Option<VaultStore>>,
    initialization_required: AtomicBool,
    schema_upgrade_required: AtomicBool,
}

impl fmt::Debug for LocalEncryptedVaultBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalEncryptedVaultBroker")
            .field("store", &"<fixed-private-vault>")
            .finish()
    }
}

impl LocalEncryptedVaultBroker {
    pub fn initialize(
        app_local_data_directory: &Path,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, VaultStoreError> {
        if !app_local_data_directory.is_absolute() {
            return Err(VaultStoreError::InvalidRoot);
        }
        let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
        let store = VaultStore::initialize(&root, workspace_instance_id.clone())?;
        Ok(Self {
            root,
            workspace_instance_id,
            store: Mutex::new(Some(store)),
            initialization_required: AtomicBool::new(false),
            schema_upgrade_required: AtomicBool::new(false),
        })
    }

    /// Opens existing Vault state without creating or upgrading anything. A
    /// missing Vault remains deferred until the complete read-only migration
    /// preflight has succeeded.
    pub fn open_for_application_startup(
        app_local_data_directory: &Path,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, VaultStoreError> {
        if !app_local_data_directory.is_absolute() {
            return Err(VaultStoreError::InvalidRoot);
        }
        let root = app_local_data_directory.join(VAULT_ROOT_DIRECTORY);
        let (store, initialization_required, schema_upgrade_required) =
            match std::fs::symlink_metadata(&root) {
                Ok(_) => {
                    let (store, upgrade_required) = VaultStore::open_for_application_startup(
                        &root,
                        workspace_instance_id.clone(),
                    )?;
                    (Some(store), false, upgrade_required)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, true, false),
                Err(_) => return Err(VaultStoreError::IoFailed),
            };
        Ok(Self {
            root,
            workspace_instance_id,
            store: Mutex::new(store),
            initialization_required: AtomicBool::new(initialization_required),
            schema_upgrade_required: AtomicBool::new(schema_upgrade_required),
        })
    }

    fn with_store<T>(
        &self,
        operation: impl FnOnce(&VaultStore) -> Result<T, VaultStoreError>,
    ) -> Result<T, VaultStoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        operation(store.as_ref().ok_or(VaultStoreError::ObjectNotAvailable)?)
    }
}

struct Step8VaultCleanupFailureAdapter<'a> {
    failure_injector: &'a dyn V031Step8MaintenanceFailureInjector,
}

impl VaultCleanupFailureInjector for Step8VaultCleanupFailureAdapter<'_> {
    fn inject(&self, point: VaultCleanupFailurePoint) -> Result<(), VaultStoreError> {
        let point = match point {
            VaultCleanupFailurePoint::AfterPreparedTransactionCommit => {
                V031Step8MaintenanceFailurePoint::AfterVaultPreparedBeforeCommit
            }
            VaultCleanupFailurePoint::AfterCommittedTransactionCommit => {
                V031Step8MaintenanceFailurePoint::AfterVaultCommittedBeforeFinalize
            }
            VaultCleanupFailurePoint::AfterPhysicalPurgeBeforeJournalCommit => {
                V031Step8MaintenanceFailurePoint::AfterVaultPhysicalPurgeBeforeJournalCommit
            }
        };
        if self.failure_injector.should_fail(point) {
            Err(VaultStoreError::IoFailed)
        } else {
            Ok(())
        }
    }
}

impl VaultBroker for LocalEncryptedVaultBroker {
    fn export_encrypted_backup(
        &self,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError> {
        let store = self
            .store
            .lock()
            .map_err(|_| privacy::VaultBackupError::Store(VaultStoreError::DatabaseFailed))?;
        privacy::export_encrypted_vault_backup(store.as_ref().ok_or(
            privacy::VaultBackupError::Store(VaultStoreError::ObjectNotAvailable),
        )?)
    }

    fn export_encrypted_backup_read_only(
        &self,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError> {
        let store = self
            .store
            .lock()
            .map_err(|_| privacy::VaultBackupError::Store(VaultStoreError::DatabaseFailed))?;
        privacy::export_encrypted_vault_backup_read_only(store.as_ref().ok_or(
            privacy::VaultBackupError::Store(VaultStoreError::ObjectNotAvailable),
        )?)
    }

    fn import_source(
        &self,
        request: ImportSourceRequest<'_>,
    ) -> Result<VaultImportBinding, VaultStoreError> {
        if request.content.is_empty() {
            return Err(VaultStoreError::InvalidInput);
        }
        let source_sha256 = Sha256Hex::parse(sha256_hex(request.content))
            .map_err(|_| VaultStoreError::InvalidInput)?;
        let summary = self.with_store(|store| {
            store.create_source_object(
                request.case_id,
                VaultPrivateMetadataInputV1 {
                    original_file_name: request.original_file_name.to_owned(),
                    original_source_path: Some(
                        request
                            .original_source_path
                            .as_os_str()
                            .to_string_lossy()
                            .into_owned(),
                    ),
                    original_media_type: request.original_media_type.to_owned(),
                    imported_at_unix: request.imported_at_unix,
                },
                request.content,
                request.imported_at_unix,
            )
        })?;
        if summary.object_kind != VaultObjectKind::SourceMaterial
            || summary.case_id != *request.case_id
            || summary.content_bytes
                != u64::try_from(request.content.len())
                    .map_err(|_| VaultStoreError::ObjectTooLarge)?
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        Ok(VaultImportBinding {
            case_id: request.case_id.clone(),
            material_id: request.material_id.clone(),
            object_id: summary.object_id,
            object_version: summary.version,
            source_sha256,
            envelope_sha256: summary.envelope_sha256,
            content_bytes: summary.content_bytes,
        })
    }

    fn read_source(
        &self,
        binding: &VaultImportBinding,
    ) -> Result<VaultSourceLease, VaultStoreError> {
        let decrypted = self.with_store(|store| {
            store.read_object(&binding.case_id, &binding.object_id, binding.object_version)
        })?;
        if decrypted.object_kind != VaultObjectKind::SourceMaterial
            || decrypted.private_metadata.source_sha256 != binding.source_sha256
            || decrypted.private_metadata.source_bytes != binding.content_bytes
            || sha256_hex(&decrypted.content) != binding.source_sha256.as_str()
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        Ok(VaultSourceLease { decrypted })
    }

    fn seal_private_values(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        values: &[PrivateValueToSeal<'_>],
        created_at_unix: u64,
    ) -> Result<SealedPrivateValueBatch, VaultStoreError> {
        if values.is_empty()
            || values.len() > MAX_PRIVATE_VALUE_COUNT
            || created_at_unix == 0
            || values.iter().any(|value| value.private_value.is_empty())
        {
            return Err(VaultStoreError::InvalidInput);
        }
        let payload = PrivateValueBatchPayload {
            schema_version: PRIVATE_VALUE_PAYLOAD_VERSION,
            case_id,
            material_id,
            entries: values
                .iter()
                .map(|value| PrivateValueEntry {
                    value_locator_hash: &value.value_locator_hash,
                    private_value: value.private_value,
                })
                .collect(),
        };
        let plaintext = ZeroizingBytes::new(
            serde_json::to_vec(&payload).map_err(|_| VaultStoreError::InvalidInput)?,
        );
        let summary = self.with_store(|store| {
            store.create_object(
                case_id,
                VaultObjectKind::ReviewDraft,
                VaultPrivateMetadataInputV1 {
                    original_file_name: PRIVATE_VALUE_OBJECT_NAME.to_owned(),
                    original_source_path: None,
                    original_media_type: PRIVATE_VALUE_MEDIA_TYPE.to_owned(),
                    imported_at_unix: created_at_unix,
                },
                &plaintext,
                created_at_unix,
            )
        })?;
        let content_sha256 =
            Sha256Hex::parse(sha256_hex(&plaintext)).map_err(|_| VaultStoreError::InvalidInput)?;
        let references = values
            .iter()
            .map(|value| PrivateValueRefV1 {
                object_id: summary.object_id.clone(),
                object_version: summary.version,
                value_locator_hash: value.value_locator_hash.clone(),
            })
            .collect();
        Ok(SealedPrivateValueBatch {
            references,
            binding: VaultAuxBinding {
                case_id: case_id.clone(),
                object_id: summary.object_id,
                object_version: summary.version,
                content_sha256,
                envelope_sha256: summary.envelope_sha256,
                content_bytes: summary.content_bytes,
            },
        })
    }

    fn seal_aux_payload(
        &self,
        case_id: &CaseId,
        payload_kind: &str,
        content: &[u8],
        created_at_unix: u64,
    ) -> Result<VaultAuxBinding, VaultStoreError> {
        if payload_kind.is_empty()
            || payload_kind.len() > 96
            || !payload_kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || content.is_empty()
            || created_at_unix == 0
        {
            return Err(VaultStoreError::InvalidInput);
        }
        let summary = self.with_store(|store| {
            store.create_object(
                case_id,
                VaultObjectKind::ReviewDraft,
                VaultPrivateMetadataInputV1 {
                    original_file_name: format!("encrypted-{payload_kind}"),
                    original_source_path: None,
                    original_media_type: format!("{AUX_PAYLOAD_MEDIA_PREFIX}{payload_kind}+json"),
                    imported_at_unix: created_at_unix,
                },
                content,
                created_at_unix,
            )
        })?;
        Ok(VaultAuxBinding {
            case_id: case_id.clone(),
            object_id: summary.object_id,
            object_version: summary.version,
            content_sha256: Sha256Hex::parse(sha256_hex(content))
                .map_err(|_| VaultStoreError::InvalidInput)?,
            envelope_sha256: summary.envelope_sha256,
            content_bytes: summary.content_bytes,
        })
    }

    fn read_aux_payload(
        &self,
        binding: &VaultAuxBinding,
    ) -> Result<VaultAuxLease, VaultStoreError> {
        let decrypted = self.with_store(|store| {
            store.read_object(&binding.case_id, &binding.object_id, binding.object_version)
        })?;
        if decrypted.object_kind != VaultObjectKind::ReviewDraft
            || decrypted.private_metadata.source_sha256 != binding.content_sha256
            || decrypted.private_metadata.source_bytes != binding.content_bytes
            || sha256_hex(&decrypted.content) != binding.content_sha256.as_str()
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        Ok(VaultAuxLease { decrypted })
    }

    fn bind_aux_retention(
        &self,
        binding: &VaultAuxBinding,
        expires_at_unix: u64,
        legal_hold: bool,
        policy_revision: u64,
        bound_at_unix: u64,
    ) -> Result<(), VaultStoreError> {
        self.with_store(|store| {
            store.set_object_retention(&VaultRetentionBindingV1 {
                case_id: binding.case_id.clone(),
                object_id: binding.object_id.clone(),
                version: binding.object_version,
                expires_at_unix,
                legal_hold,
                policy_revision,
                bound_at_unix,
            })
        })
    }

    fn bind_retention(
        &self,
        binding: &VaultImportBinding,
        expires_at_unix: u64,
        legal_hold: bool,
        policy_revision: u64,
        bound_at_unix: u64,
    ) -> Result<(), VaultStoreError> {
        self.with_store(|store| {
            store.set_object_retention(&VaultRetentionBindingV1 {
                case_id: binding.case_id.clone(),
                object_id: binding.object_id.clone(),
                version: binding.object_version,
                expires_at_unix,
                legal_hold,
                policy_revision,
                bound_at_unix,
            })
        })
    }

    fn set_legal_hold(
        &self,
        binding: &VaultImportBinding,
        enabled: bool,
        changed_at_unix: u64,
    ) -> Result<(), VaultStoreError> {
        self.with_store(|store| {
            store.set_object_legal_hold(
                &binding.case_id,
                &binding.object_id,
                binding.object_version,
                enabled,
                changed_at_unix,
            )
        })
    }

    fn run_or_resume_expired_cleanup(
        &self,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        self.with_store(|store| store.run_or_resume_expired_object_cleanup(cleanup_id, now_unix))
    }

    fn run_or_resume_expired_cleanup_with_failure_injector(
        &self,
        cleanup_id: &str,
        now_unix: u64,
        failure_injector: &dyn V031Step8MaintenanceFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        let adapter = Step8VaultCleanupFailureAdapter { failure_injector };
        self.with_store(|store| {
            store.run_or_resume_expired_object_cleanup_with_failure_injector(
                cleanup_id, now_unix, &adapter,
            )
        })
    }

    fn recover_cleanups(
        &self,
        now_unix: u64,
    ) -> Result<Vec<VaultCleanupReportV1>, VaultStoreError> {
        self.with_store(|store| store.recover_object_cleanups(now_unix))
    }

    fn inspect_cleanup_status_read_only(
        &self,
    ) -> Result<VaultCleanupPendingStatusV1, VaultStoreError> {
        if self.initialization_required.load(Ordering::Acquire) {
            return Ok(VaultCleanupPendingStatusV1 {
                prepared_count: 0,
                committed_count: 0,
                purged_count: 0,
            });
        }
        self.with_store(VaultStore::inspect_cleanup_status_read_only)
    }

    fn inspect_inventory_read_only(&self) -> Result<VaultReadOnlyInventoryV1, VaultStoreError> {
        if self.initialization_required.load(Ordering::Acquire) {
            return Ok(VaultReadOnlyInventoryV1 {
                journal_row_count: 0,
                committed_object_count: 0,
                key_record_count: 0,
                object_root_entry_count: 0,
            });
        }
        self.with_store(VaultStore::inspect_inventory_read_only)
    }

    fn isolation_status(&self) -> Result<VaultIsolationStatusV1, VaultStoreError> {
        self.with_store(VaultStore::isolation_status)
    }

    fn startup_write_required(&self) -> bool {
        self.initialization_required.load(Ordering::Acquire)
            || self.schema_upgrade_required.load(Ordering::Acquire)
    }

    fn startup_vault_present(&self) -> bool {
        !self.initialization_required.load(Ordering::Acquire)
    }

    fn prepare_for_migration_backup_after_preflight(&self) -> Result<(), VaultStoreError> {
        if !self.initialization_required.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if store.is_none() {
            *store = Some(VaultStore::initialize(
                &self.root,
                self.workspace_instance_id.clone(),
            )?);
        }
        self.initialization_required.store(false, Ordering::Release);
        Ok(())
    }

    fn upgrade_schema_after_backup(&self) -> Result<(), VaultStoreError> {
        if !self.schema_upgrade_required.load(Ordering::Acquire) {
            return Ok(());
        }
        self.with_store(VaultStore::upgrade_schema_after_backup)?;
        self.schema_upgrade_required.store(false, Ordering::Release);
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateValueBatchPayload<'a> {
    schema_version: &'static str,
    case_id: &'a CaseId,
    material_id: &'a MaterialId,
    entries: Vec<PrivateValueEntry<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateValueEntry<'a> {
    value_locator_hash: &'a Sha256Hex,
    private_value: &'a str,
}

pub(super) struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for ZeroizingBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, path::PathBuf, time::SystemTime};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_98989898989898989898989898989898").expect("workspace")
    }

    fn case() -> CaseId {
        CaseId::parse("case_78787878787878787878787878787878").expect("case")
    }

    fn material() -> MaterialId {
        MaterialId::parse("mat_67676767676767676767676767676767").expect("material")
    }

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("la-vault-broker-test-{}", Uuid::new_v4().simple()))
    }

    fn v031_authorization() -> V031VaultWriteAuthorization {
        let rollback = V031VaultRollbackEvidence {
            lineage_id: "a".repeat(64),
            envelope_binding_id: format!("ws_{}", "b".repeat(32)),
            source_profile_proof_sha256: "c".repeat(64),
            original_identity_sha256: "d".repeat(64),
            original_bundle_sha256: "e".repeat(64),
            original_rollback_receipt_sha256: "f".repeat(64),
        };
        let rollback_gate_binding_sha256 =
            v031_canonical_sha256(&rollback).expect("rollback binding");
        V031VaultWriteAuthorization {
            rollback,
            rollback_gate_binding_sha256,
            workspace_instance_id: workspace(),
            approved_target_components_evidence_sha256: "1".repeat(64),
            approved_credential_manifest_sha256: "2".repeat(64),
            approved_workspace_manifest_sha256: "3".repeat(64),
            approved_work_products_manifest_sha256: "4".repeat(64),
            approved_credential_count: 4,
            approved_business_rows: 0,
            approved_work_product_business_rows: 0,
        }
    }

    fn v031_fixture() -> (TempDir, PathBuf, V031VaultWriteAuthorization) {
        let directory = tempfile::tempdir().expect("v031 Vault app root");
        let app_root = directory.path().to_path_buf();
        (directory, app_root, v031_authorization())
    }

    fn v031_database(app_root: &Path) -> PathBuf {
        app_root
            .join(VAULT_ROOT_DIRECTORY)
            .join(V031_VAULT_DATABASE_NAME)
    }

    #[allow(clippy::type_complexity)]
    fn snapshot_vault_tree(
        root: &Path,
    ) -> BTreeMap<PathBuf, (bool, u64, SystemTime, Option<Vec<u8>>)> {
        let mut snapshot = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = fs::symlink_metadata(&path).expect("Vault snapshot metadata");
            let relative = path
                .strip_prefix(root)
                .expect("Vault snapshot relative path")
                .to_path_buf();
            let is_directory = metadata.is_dir();
            let bytes = if metadata.is_file() {
                Some(fs::read(&path).expect("Vault snapshot bytes"))
            } else {
                None
            };
            snapshot.insert(
                relative,
                (
                    is_directory,
                    metadata.len(),
                    metadata.modified().expect("Vault snapshot mtime"),
                    bytes,
                ),
            );
            if is_directory {
                for entry in fs::read_dir(&path).expect("Vault snapshot directory") {
                    pending.push(entry.expect("Vault snapshot entry").path());
                }
            }
        }
        snapshot
    }

    #[test]
    fn v031_vault_schema_fingerprint_matches_frozen_production_schema() {
        let (_directory, app_root, authorization) = v031_fixture();
        let vault_root = app_root.join(VAULT_ROOT_DIRECTORY);
        drop(
            VaultStore::initialize(&vault_root, authorization.workspace_instance_id.clone())
                .expect("initialize production Vault schema"),
        );
        let uri = v031_immutable_sqlite_uri(&v031_database(&app_root)).expect("immutable URI");
        let connection = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("read production Vault schema");
        let actual = v031_canonical_sha256(
            &v031_vault_schema_objects(&connection).expect("Vault schema objects"),
        )
        .expect("Vault schema hash");
        assert_eq!(actual, V031_VAULT_SCHEMA_SHA256);
    }

    #[test]
    fn v031_vault_target_fresh_resume_and_read_only_verification_are_idempotent() {
        let (_directory, app_root, authorization) = v031_fixture();
        let first =
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect("fresh Vault target");
        assert_eq!(
            first.workspace_instance_id(),
            &authorization.workspace_instance_id
        );
        assert_eq!(
            first.rollback_gate_binding_sha256(),
            authorization.rollback_gate_binding_sha256
        );
        assert_eq!(
            first.approved_target_components_evidence_sha256(),
            authorization.approved_target_components_evidence_sha256
        );
        assert_eq!(first.vault_schema_sha256(), V031_VAULT_SCHEMA_SHA256);
        assert_eq!(first.metadata_rows(), 2);
        assert_eq!(first.business_rows(), 0);
        assert_eq!(first.key_record_count(), 0);
        assert_eq!(first.object_root_entry_count(), 0);
        for hash in [
            first.vault_database_sha256(),
            first.vault_layout_sha256(),
            first.vault_component_manifest_sha256(),
            first.evidence_sha256(),
        ] {
            assert!(v031_is_lower_sha256(hash));
        }
        let vault_root = app_root.join(VAULT_ROOT_DIRECTORY);
        assert_eq!(
            v031_vault_basenames(&vault_root).expect("Vault layout"),
            vec![
                ".quarantine".to_owned(),
                ".staging".to_owned(),
                "keys".to_owned(),
                "objects".to_owned(),
                V031_VAULT_DATABASE_NAME.to_owned(),
            ]
        );

        let database_before = fs::read(v031_database(&app_root)).expect("Vault database before");
        let layout_before = v031_vault_basenames(&vault_root).expect("layout before verifier");
        verify_v031_vault_target_component_with_authorization_read_only(
            &app_root,
            &authorization,
            &first,
        )
        .expect("read-only Vault verification");
        assert_eq!(
            fs::read(v031_database(&app_root)).expect("Vault database after"),
            database_before
        );
        assert_eq!(
            v031_vault_basenames(&vault_root).expect("layout after verifier"),
            layout_before
        );

        let second =
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect("resumed Vault target");
        assert_eq!(second, first);
    }

    #[test]
    fn v031_vault_target_recovers_only_an_empty_partial_layout() {
        let (_directory, app_root, authorization) = v031_fixture();
        fs::create_dir(app_root.join(VAULT_ROOT_DIRECTORY)).expect("partial Vault root");
        fs::create_dir(app_root.join(VAULT_ROOT_DIRECTORY).join("objects"))
            .expect("partial objects root");

        let gate =
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect("resume empty partial Vault target");
        assert_eq!(gate.business_rows(), 0);
        assert_eq!(gate.key_record_count(), 0);
        assert_eq!(gate.object_root_entry_count(), 0);
        assert_eq!(
            v031_vault_basenames(&app_root.join(VAULT_ROOT_DIRECTORY)).expect("completed layout"),
            vec![
                ".quarantine".to_owned(),
                ".staging".to_owned(),
                "keys".to_owned(),
                "objects".to_owned(),
                V031_VAULT_DATABASE_NAME.to_owned(),
            ]
        );
    }

    #[test]
    fn v031_vault_startup_observer_is_read_only_for_absent_partial_and_complete_states() {
        let (_absent_directory, absent_root, _) = v031_fixture();
        let entries_before = fs::read_dir(&absent_root)
            .expect("absent root before")
            .count();
        observe_v031_vault_target_absent_read_only(&absent_root).expect("Vault absent predecessor");
        assert_eq!(
            fs::read_dir(&absent_root)
                .expect("absent root after")
                .count(),
            entries_before
        );

        let (_partial_directory, partial_root, authorization) = v031_fixture();
        fs::create_dir(partial_root.join(VAULT_ROOT_DIRECTORY)).expect("partial Vault root");
        fs::create_dir(partial_root.join(VAULT_ROOT_DIRECTORY).join("objects"))
            .expect("partial objects root");
        let before = snapshot_vault_tree(&partial_root.join(VAULT_ROOT_DIRECTORY));
        let observed = observe_v031_vault_target_namespace_with_authorization_read_only(
            &partial_root,
            &authorization,
        )
        .expect("partial Vault startup observation");
        assert!(matches!(
            observed,
            V031VaultTargetNamespaceObservation::Incomplete(_)
        ));
        assert_eq!(
            snapshot_vault_tree(&partial_root.join(VAULT_ROOT_DIRECTORY)),
            before
        );

        let (_complete_directory, complete_root, authorization) = v031_fixture();
        let expected =
            prepare_v031_vault_target_component_with_authorization(&complete_root, &authorization)
                .expect("complete Vault target");
        let before = snapshot_vault_tree(&complete_root.join(VAULT_ROOT_DIRECTORY));
        assert_eq!(
            observe_v031_vault_target_namespace_with_authorization_read_only(
                &complete_root,
                &authorization,
            )
            .expect("complete Vault startup observation"),
            V031VaultTargetNamespaceObservation::Complete(expected)
        );
        assert_eq!(
            snapshot_vault_tree(&complete_root.join(VAULT_ROOT_DIRECTORY)),
            before
        );
    }

    #[test]
    fn v031_vault_startup_observer_rejects_unknown_partial_residue_without_writes() {
        let (_directory, app_root, authorization) = v031_fixture();
        let vault_root = app_root.join(VAULT_ROOT_DIRECTORY);
        fs::create_dir(&vault_root).expect("partial Vault root");
        fs::write(vault_root.join("unknown-residue"), b"unchanged").expect("unknown residue");
        let before = snapshot_vault_tree(&vault_root);
        assert_eq!(
            observe_v031_vault_target_namespace_with_authorization_read_only(
                &app_root,
                &authorization,
            )
            .expect_err("unknown partial residue must fail")
            .code(),
            "v031_vault_target_component_invalid"
        );
        assert_eq!(snapshot_vault_tree(&vault_root), before);
    }

    #[test]
    fn v031_vault_target_rejects_nonempty_inventory_and_extra_sidecars() {
        let (_directory, app_root, authorization) = v031_fixture();
        prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
            .expect("fresh Vault target");
        let objects = app_root.join(VAULT_ROOT_DIRECTORY).join("objects");
        fs::write(objects.join("unexpected-object"), b"not empty").expect("inject object");
        assert_eq!(
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect_err("nonempty object inventory must fail")
                .code(),
            "v031_vault_target_component_nonempty"
        );
        fs::remove_file(objects.join("unexpected-object")).expect("remove injected object");
        fs::write(
            app_root
                .join(VAULT_ROOT_DIRECTORY)
                .join("vault-state.sqlite-wal"),
            b"unexpected sidecar",
        )
        .expect("inject sidecar");
        assert_eq!(
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect_err("extra sidecar must fail")
                .code(),
            "v031_vault_target_component_invalid"
        );
    }

    #[test]
    fn v031_vault_target_rejects_schema_identity_and_version_tamper() {
        let (_directory, app_root, authorization) = v031_fixture();
        prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
            .expect("fresh Vault target");
        let database = v031_database(&app_root);
        Connection::open(&database)
            .expect("schema tamper connection")
            .execute_batch("DROP TRIGGER trg_vault_cleanup_no_delete")
            .expect("tamper Vault schema");
        assert_eq!(
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect_err("schema tamper must fail")
                .code(),
            "v031_vault_target_component_invalid"
        );

        let (_directory, app_root, authorization) = v031_fixture();
        prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
            .expect("fresh Vault target");
        let database = v031_database(&app_root);
        Connection::open(&database)
            .expect("identity tamper connection")
            .execute(
                "UPDATE vault_meta SET workspace_instance_id=?1",
                [format!("ws_{}", "7".repeat(32))],
            )
            .expect("tamper Vault identity");
        assert_eq!(
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect_err("workspace identity tamper must fail")
                .code(),
            "v031_vault_target_component_invalid"
        );

        for unsupported_version in [1_u32, VAULT_STORE_SCHEMA_VERSION + 1] {
            let (_directory, app_root, authorization) = v031_fixture();
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect("fresh Vault target");
            Connection::open(v031_database(&app_root))
                .expect("version tamper connection")
                .execute(
                    "UPDATE vault_meta SET schema_version=?1",
                    [unsupported_version],
                )
                .expect("tamper Vault schema version");
            assert_eq!(
                prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                    .expect_err("unsupported Vault schema must fail")
                    .code(),
                "v031_vault_target_component_invalid"
            );
        }
    }

    #[test]
    fn v031_vault_target_rejects_database_hardlinks_and_gate_mismatch() {
        let (_directory, app_root, authorization) = v031_fixture();
        let gate =
            prepare_v031_vault_target_component_with_authorization(&app_root, &authorization)
                .expect("fresh Vault target");
        let mut mismatched = gate.clone();
        mismatched.evidence_sha256 = "9".repeat(64);
        assert_eq!(
            verify_v031_vault_target_component_with_authorization_read_only(
                &app_root,
                &authorization,
                &mismatched,
            )
            .expect_err("gate mismatch must fail")
            .code(),
            "v031_vault_target_component_invalid"
        );

        let external_link = app_root.join("vault-database-hardlink");
        fs::hard_link(v031_database(&app_root), &external_link).expect("database hardlink");
        assert_eq!(
            verify_v031_vault_target_component_with_authorization_read_only(
                &app_root,
                &authorization,
                &gate,
            )
            .expect_err("hardlinked database must fail")
            .code(),
            "v031_vault_target_component_invalid"
        );
    }

    #[test]
    fn broker_imports_reads_and_cryptographically_cleans_synthetic_source() {
        let app_root = root();
        std::fs::create_dir_all(&app_root).expect("app root");
        let broker = LocalEncryptedVaultBroker::initialize(&app_root, workspace()).expect("broker");
        let source = b"SYNTHETIC_VAULT_SOURCE_CANARY";
        let source_path = app_root.join("SYNTHETIC_PRIVATE_NAME.pdf");
        let binding = broker
            .import_source(ImportSourceRequest {
                case_id: &case(),
                material_id: &material(),
                original_file_name: "SYNTHETIC_PRIVATE_NAME.pdf",
                original_source_path: &source_path,
                original_media_type: "application/pdf",
                content: source,
                imported_at_unix: 100,
            })
            .expect("import");
        broker
            .bind_retention(&binding, 200, false, 1, 100)
            .expect("retention");
        let lease = broker.read_source(&binding).expect("read");
        assert_eq!(lease.content(), source);
        assert!(!format!("{lease:?}").contains("SYNTHETIC_VAULT_SOURCE_CANARY"));
        drop(lease);

        let vault_root = app_root.join(VAULT_ROOT_DIRECTORY);
        for entry in walk_files(&vault_root) {
            let bytes = std::fs::read(&entry).expect("vault file");
            assert!(!bytes.windows(source.len()).any(|window| window == source));
            assert!(!bytes
                .windows(b"SYNTHETIC_PRIVATE_NAME.pdf".len())
                .any(|window| window == b"SYNTHETIC_PRIVATE_NAME.pdf"));
        }
        let status = broker.isolation_status().expect("isolation");
        assert!(status.private_acl_enforced);
        assert!(status.content_indexing_disabled);
        assert!(!status.strong_service_identity_boundary);
        broker
            .run_or_resume_expired_cleanup("cln_11111111111111111111111111111111", 200)
            .expect("cleanup");
        assert!(matches!(
            broker.read_source(&binding),
            Err(VaultStoreError::ObjectNotAvailable)
        ));
        std::fs::remove_dir_all(app_root).expect("cleanup root");
    }

    #[test]
    fn application_startup_defers_missing_vault_until_read_only_preflight_succeeds() {
        let app_root = root();
        std::fs::create_dir_all(&app_root).expect("app root");
        let vault_root = app_root.join(VAULT_ROOT_DIRECTORY);
        let broker =
            LocalEncryptedVaultBroker::open_for_application_startup(&app_root, workspace())
                .expect("deferred startup broker");

        assert!(broker.startup_write_required());
        assert!(!vault_root.exists());
        assert!(matches!(
            broker.isolation_status(),
            Err(VaultStoreError::ObjectNotAvailable)
        ));
        assert!(!vault_root.exists());

        broker
            .prepare_for_migration_backup_after_preflight()
            .expect("initialize empty backup baseline");
        assert!(!broker.startup_write_required());
        assert!(vault_root.is_dir());
        broker.isolation_status().expect("initialized isolation");
        std::fs::remove_dir_all(app_root).expect("cleanup root");
    }

    #[test]
    fn current_vault_observer_is_exact_path_free_and_source_read_only() {
        let absent = tempfile::tempdir().expect("absent Vault app root");
        assert_eq!(
            observe_current_vault_read_only(absent.path(), &workspace())
                .expect("absent Vault observation"),
            CurrentVaultObservation::Absent
        );

        let partial = tempfile::tempdir().expect("partial Vault app root");
        fs::create_dir(partial.path().join(VAULT_ROOT_DIRECTORY)).expect("partial Vault namespace");
        assert!(
            observe_current_vault_read_only(partial.path(), &workspace()).is_err(),
            "a present partial Vault must fail closed"
        );

        let directory = tempfile::tempdir().expect("current Vault app root");
        let workspace_instance_id = workspace();
        let vault_root = directory.path().join(VAULT_ROOT_DIRECTORY);
        let store = VaultStore::initialize(&vault_root, workspace_instance_id.clone())
            .expect("initialize current Vault");
        let live_wal = Connection::open(vault_root.join(V031_VAULT_DATABASE_NAME))
            .expect("open live current Vault WAL fixture");
        live_wal
            .pragma_update(None, "journal_mode", "WAL")
            .expect("retain WAL mode");
        live_wal
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("disable fixture auto-checkpoint");
        store
            .create_source_object(
                &case(),
                VaultPrivateMetadataInputV1 {
                    original_file_name: "observer-canary.pdf".to_owned(),
                    original_source_path: None,
                    original_media_type: "application/pdf".to_owned(),
                    imported_at_unix: 100,
                },
                b"CURRENT_VAULT_OBSERVER_CANARY",
                100,
            )
            .expect("commit a valid current object to the retained WAL");
        drop(store);
        assert!(vault_root
            .join(format!("{V031_VAULT_DATABASE_NAME}-wal"))
            .is_file());
        let before = snapshot_vault_tree(&vault_root);
        let (diagnostic_store, diagnostic_upgrade_required) =
            VaultStore::open_for_application_startup(&vault_root, workspace_instance_id.clone())
                .expect("live WAL current Vault opens read-only");
        assert!(!diagnostic_upgrade_required);
        diagnostic_store
            .inspect_inventory_read_only()
            .expect("live WAL current Vault inventory authenticates");
        let diagnostic_database_manifest = diagnostic_store
            .inspect_database_manifest_read_only()
            .expect("live WAL current Vault semantic manifest authenticates");
        assert_eq!(
            diagnostic_database_manifest.schema_sha256,
            V031_VAULT_SCHEMA_SHA256
        );
        assert!(
            diagnostic_database_manifest.business_rows
                >= diagnostic_database_manifest.journal_row_count
        );
        assert_eq!(
            sha256_hex(&fs::read(vault_root.join(V031_VAULT_DATABASE_NAME)).unwrap()),
            diagnostic_database_manifest.database_sha256
        );
        let live_wal_sha256 = sha256_hex(&fs::read(vault_root.join(V031_VAULT_WAL_NAME)).unwrap());
        assert_eq!(
            diagnostic_database_manifest.wal_sha256.as_deref(),
            Some(live_wal_sha256.as_str())
        );
        let diagnostic_shm =
            v031_pin_current_vault_volatile_file_identity(&vault_root.join(V031_VAULT_SHM_NAME))
                .expect("live SQLite SHM remains a controlled single-link local file");
        v031_verify_pinned_current_vault_volatile_file_identity(
            &vault_root.join(V031_VAULT_SHM_NAME),
            &diagnostic_shm,
        )
        .expect("live SQLite SHM path still names the pinned file");
        diagnostic_store
            .isolation_status()
            .expect("live WAL current Vault isolation authenticates");
        v031_validate_current_vault_component(
            directory.path(),
            &workspace_instance_id,
            &diagnostic_database_manifest,
        )
        .expect("live WAL current Vault physical component validates");

        let CurrentVaultObservation::Exact(proof) =
            observe_current_vault_read_only(directory.path(), &workspace_instance_id)
                .expect("exact current Vault observation")
        else {
            panic!("current Vault must be exact");
        };
        assert_eq!(proof.workspace_instance_id(), &workspace_instance_id);
        assert_eq!(proof.schema_version(), VAULT_STORE_SCHEMA_VERSION);
        assert_eq!(proof.inventory().journal_row_count, 1);
        assert_eq!(proof.inventory().committed_object_count, 1);
        for hash in [
            proof.schema_sha256(),
            proof.database_sha256(),
            proof.layout_sha256(),
            proof.component_manifest_sha256(),
        ] {
            assert!(v031_is_lower_sha256(hash));
        }
        assert!(proof.isolation().private_acl_enforced);
        assert!(proof.isolation().content_indexing_disabled);
        assert!(!format!("{proof:?}").contains(workspace_instance_id.as_str()));
        assert_eq!(
            observe_current_vault_read_only(directory.path(), &workspace_instance_id)
                .expect("repeated live WAL current Vault observation"),
            CurrentVaultObservation::Exact(proof.clone()),
            "the same durable main/WAL state must reconstruct the same opaque proof"
        );
        assert_eq!(
            snapshot_vault_tree(&vault_root),
            before,
            "current Vault observation must preserve bytes, mtimes, and entries"
        );
        drop(live_wal);
    }

    #[test]
    fn current_vault_observer_rejects_wal_tamper_and_sqlite_corruption() {
        use std::io::{Seek, SeekFrom, Write};

        let wal_tamper = tempfile::tempdir().expect("current Vault WAL tamper root");
        let workspace_instance_id = workspace();
        let vault_root = wal_tamper.path().join(VAULT_ROOT_DIRECTORY);
        let store = VaultStore::initialize(&vault_root, workspace_instance_id.clone())
            .expect("initialize WAL tamper Vault");
        let live_wal = Connection::open(vault_root.join(V031_VAULT_DATABASE_NAME))
            .expect("open valid WAL tamper source");
        live_wal
            .pragma_update(None, "journal_mode", "WAL")
            .expect("retain WAL mode for tamper");
        live_wal
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("disable WAL tamper auto-checkpoint");
        store
            .create_source_object(
                &case(),
                VaultPrivateMetadataInputV1 {
                    original_file_name: "wal-tamper-canary.pdf".to_owned(),
                    original_source_path: None,
                    original_media_type: "application/pdf".to_owned(),
                    imported_at_unix: 200,
                },
                b"CURRENT_VAULT_WAL_TAMPER_CANARY",
                200,
            )
            .expect("write a valid current object before tampering");
        drop(store);
        let wal_path = vault_root.join(V031_VAULT_WAL_NAME);
        let wal_bytes = fs::read(&wal_path).expect("read valid WAL bytes");
        assert!(wal_bytes.len() > 32);
        let mut wal_file = std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .expect("open retained WAL for adversarial mutation");
        wal_file
            .seek(SeekFrom::Start((wal_bytes.len() - 1) as u64))
            .expect("seek final WAL byte");
        wal_file
            .write_all(&[wal_bytes[wal_bytes.len() - 1] ^ 0x01])
            .expect("tamper a valid WAL frame");
        wal_file.sync_all().expect("durably tamper WAL frame");
        drop(wal_file);
        assert!(
            observe_current_vault_read_only(wal_tamper.path(), &workspace_instance_id).is_err(),
            "tampering a genuine WAL frame must fail closed"
        );
        drop(live_wal);

        let database_tamper = tempfile::tempdir().expect("current Vault database tamper root");
        let vault_root = database_tamper.path().join(VAULT_ROOT_DIRECTORY);
        drop(
            VaultStore::initialize(&vault_root, workspace_instance_id.clone())
                .expect("initialize database tamper Vault"),
        );
        let database = vault_root.join(V031_VAULT_DATABASE_NAME);
        let mut bytes = fs::read(&database).expect("read current Vault database");
        bytes[0] ^= 0x01;
        fs::write(&database, bytes).expect("corrupt current Vault database header");
        assert!(
            observe_current_vault_read_only(database_tamper.path(), &workspace_instance_id)
                .is_err(),
            "corrupt current SQLite must fail closed"
        );
    }

    fn walk_files(root: &Path) -> Vec<PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory).expect("read dir") {
                let entry = entry.expect("entry");
                let metadata = entry.file_type().expect("type");
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() {
                    files.push(entry.path());
                }
            }
        }
        files
    }
}
