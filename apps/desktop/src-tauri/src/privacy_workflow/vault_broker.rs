use privacy::{
    sha256_hex,
    vault_store::{
        DecryptedVaultObjectV1, VaultIsolationStatusV1, VaultObjectKind,
        VaultPrivateMetadataInputV1, VaultRetentionBindingV1, VaultStore, VaultStoreError,
    },
    vnext::{CaseId, MaterialId, ObjectId, PrivateValueRefV1, Sha256Hex, WorkspaceInstanceId},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;
use std::{
    fmt,
    ops::Deref,
    path::Path,
    sync::atomic::{compiler_fence, Ordering},
};

pub(super) const VAULT_ROOT_DIRECTORY: &str = "case-vault-v2";
const PRIVATE_VALUE_MEDIA_TYPE: &str = "application/vnd.lawyer-assistance.private-values+json";
const PRIVATE_VALUE_OBJECT_NAME: &str = "encrypted-private-values";
const PRIVATE_VALUE_PAYLOAD_VERSION: &str = "private-value-batch-v1";
const MAX_PRIVATE_VALUE_COUNT: usize = 100_000;
const AUX_PAYLOAD_MEDIA_PREFIX: &str = "application/vnd.lawyer-assistance.";

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
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS privacy_vault_material_refs (
                material_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_version INTEGER NOT NULL CHECK(object_version > 0),
                source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
                envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64),
                content_bytes INTEGER NOT NULL CHECK(content_bytes > 0),
                retention_expires_at_unix INTEGER NOT NULL,
                retention_policy_revision INTEGER NOT NULL CHECK(retention_policy_revision > 0),
                bound_at_unix INTEGER NOT NULL,
                import_state TEXT NOT NULL CHECK(import_state IN (
                    'vault_committed','review_ready','processing_failed','revoked'
                )),
                failure_code TEXT CHECK(failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(object_id, object_version),
                FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_privacy_vault_case
                ON privacy_vault_material_refs(case_id, material_id);
            ",
        )
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
             SET media_type=?2,page_count=?3,updated_at=CURRENT_TIMESTAMP
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
            "UPDATE privacy_materials SET state='failed',updated_at=CURRENT_TIMESTAMP
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

    fn run_expired_cleanup(&self, cleanup_id: &str, now_unix: u64) -> Result<(), VaultStoreError>;

    fn recover_cleanups(&self, now_unix: u64) -> Result<(), VaultStoreError>;

    fn isolation_status(&self) -> Result<VaultIsolationStatusV1, VaultStoreError>;
}

pub(super) struct LocalEncryptedVaultBroker {
    store: VaultStore,
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
        let store = VaultStore::initialize(root, workspace_instance_id)?;
        Ok(Self { store })
    }
}

impl VaultBroker for LocalEncryptedVaultBroker {
    fn export_encrypted_backup(
        &self,
    ) -> Result<(Vec<u8>, privacy::VaultBackupSummaryV1), privacy::VaultBackupError> {
        privacy::export_encrypted_vault_backup(&self.store)
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
        let summary = self.store.create_source_object(
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
        )?;
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
        let decrypted =
            self.store
                .read_object(&binding.case_id, &binding.object_id, binding.object_version)?;
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
        let summary = self.store.create_object(
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
        )?;
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
        let summary = self.store.create_object(
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
        )?;
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
        let decrypted =
            self.store
                .read_object(&binding.case_id, &binding.object_id, binding.object_version)?;
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
        self.store.set_object_retention(&VaultRetentionBindingV1 {
            case_id: binding.case_id.clone(),
            object_id: binding.object_id.clone(),
            version: binding.object_version,
            expires_at_unix,
            legal_hold,
            policy_revision,
            bound_at_unix,
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
        self.store.set_object_retention(&VaultRetentionBindingV1 {
            case_id: binding.case_id.clone(),
            object_id: binding.object_id.clone(),
            version: binding.object_version,
            expires_at_unix,
            legal_hold,
            policy_revision,
            bound_at_unix,
        })
    }

    fn set_legal_hold(
        &self,
        binding: &VaultImportBinding,
        enabled: bool,
        changed_at_unix: u64,
    ) -> Result<(), VaultStoreError> {
        self.store.set_object_legal_hold(
            &binding.case_id,
            &binding.object_id,
            binding.object_version,
            enabled,
            changed_at_unix,
        )
    }

    fn run_expired_cleanup(&self, cleanup_id: &str, now_unix: u64) -> Result<(), VaultStoreError> {
        self.store
            .run_expired_object_cleanup(cleanup_id, now_unix)
            .map(|_| ())
    }

    fn recover_cleanups(&self, now_unix: u64) -> Result<(), VaultStoreError> {
        self.store.recover_object_cleanups(now_unix).map(|_| ())
    }

    fn isolation_status(&self) -> Result<VaultIsolationStatusV1, VaultStoreError> {
        self.store.isolation_status()
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
    use std::path::PathBuf;
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
            .run_expired_cleanup("cln_11111111111111111111111111111111", 200)
            .expect("cleanup");
        assert!(matches!(
            broker.read_source(&binding),
            Err(VaultStoreError::ObjectNotAvailable)
        ));
        std::fs::remove_dir_all(app_root).expect("cleanup root");
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
