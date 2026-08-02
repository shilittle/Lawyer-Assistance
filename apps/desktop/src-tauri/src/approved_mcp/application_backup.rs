use super::{
    now_seconds, workspace_error, workspace_instance_id, zeroize, ApprovedMcpError,
    ApprovedMcpWorkspace, KeyRole, V031ApprovedMcpTargetComponentsGate, V031RollbackGateBinding,
    KEY_VERSION,
};
use crate::commands::original_migration_backup::OriginalRollbackVerifiedGate;
use crate::privacy_manager;
#[cfg(test)]
use crate::privacy_workflow::approved_workspace::ApprovedGenerationSource;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
#[cfg(test)]
use legal_mcp::approved_backend::{
    ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError,
    ApprovedWorkspaceQualificationProvider,
};
use privacy::{
    sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, PublicationId, WorkProductId,
        WorkspaceInstanceId,
    },
    work_products::{WorkProductPublisher, WorkProductService},
    workspace::{ApprovedWorkspaceService, ManifestSigningKey, WorkspacePublisher},
    MAX_APPROVED_WORKSPACE_BACKUP_BYTES, MAX_WORK_PRODUCTS_BACKUP_BYTES,
};
#[cfg(test)]
use privacy::{
    vnext::{ApprovedMaterialRefV1, Sha256Hex},
    work_products::WorkProductWriteV1,
};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    },
};

const ARCHIVE_SCHEMA_VERSION: &str = "approved-mcp-application-backup-archive-v1";
const ARCHIVE_MANIFEST_SCHEMA_VERSION: &str = "approved-mcp-application-backup-archive-manifest-v1";
const APPROVED_STORE_KIND: &str = "approved_workspace";
const WORK_PRODUCTS_STORE_KIND: &str = "work_products";
const APPROVED_DATABASE_FILE: &str = "workspace-state.sqlite";
const WORK_PRODUCTS_DATABASE_FILE: &str = "work-products.sqlite";
const MAX_ARCHIVE_FILES: usize = 100_000;
const MAX_ARCHIVE_PATH_BYTES: usize = 512;
const MAX_ARCHIVE_DATABASE_BYTES: usize = 128 * 1024 * 1024;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
struct ApplicationBackupTestKeys {
    approved_manifest: Mutex<Option<[u8; 32]>>,
    work_product_manifest: Mutex<Option<[u8; 32]>>,
    ticket: Mutex<Option<[u8; 32]>>,
    qualification_epoch: Mutex<Option<[u8; 32]>>,
    panic_on_load_or_create: AtomicBool,
}

#[cfg(test)]
impl ApplicationBackupTestKeys {
    fn new() -> Self {
        Self {
            approved_manifest: Mutex::new(None),
            work_product_manifest: Mutex::new(None),
            ticket: Mutex::new(None),
            qualification_epoch: Mutex::new(None),
            panic_on_load_or_create: AtomicBool::new(false),
        }
    }

    fn epochs(&self) -> Result<(u8, u8), ApprovedMcpError> {
        let mut ticket =
            <Self as super::ApprovedMcpKeyProvider>::load_or_create(self, KeyRole::McpTicket)?;
        let mut qualification = <Self as super::ApprovedMcpKeyProvider>::load_or_create(
            self,
            KeyRole::QualificationRevocationEpoch,
        )?;
        let epochs = (ticket[0], qualification[0]);
        zeroize(&mut ticket);
        zeroize(&mut qualification);
        Ok(epochs)
    }

    fn slot(&self, role: KeyRole) -> &Mutex<Option<[u8; 32]>> {
        match role {
            KeyRole::ApprovedManifest => &self.approved_manifest,
            KeyRole::WorkProductManifest => &self.work_product_manifest,
            KeyRole::McpTicket => &self.ticket,
            KeyRole::QualificationRevocationEpoch => &self.qualification_epoch,
        }
    }

    fn random_key() -> Result<[u8; 32], ApprovedMcpError> {
        let mut key = [0_u8; 32];
        super::fill_random(&mut key)?;
        if key.iter().all(|byte| *byte == 0) {
            zeroize(&mut key);
            return Err(workspace_error());
        }
        Ok(key)
    }

    fn rotate_to_distinct_key(current: Option<&[u8; 32]>) -> Result<[u8; 32], ApprovedMcpError> {
        for _ in 0..16 {
            let candidate = Self::random_key()?;
            if current.is_none_or(|value| value != &candidate && value[0] != candidate[0]) {
                return Ok(candidate);
            }
        }
        Err(workspace_error())
    }
}

#[cfg(test)]
impl Drop for ApplicationBackupTestKeys {
    fn drop(&mut self) {
        for slot in [
            &mut self.approved_manifest,
            &mut self.work_product_manifest,
            &mut self.ticket,
            &mut self.qualification_epoch,
        ] {
            if let Ok(value) = slot.get_mut() {
                if let Some(key) = value.as_mut() {
                    zeroize(key);
                }
            }
        }
    }
}

#[cfg(test)]
impl super::ApprovedMcpKeyProvider for ApplicationBackupTestKeys {
    fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        self.slot(role)
            .lock()
            .map(|value| *value)
            .map_err(|_| workspace_error())
    }

    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        assert!(
            !self.panic_on_load_or_create.load(Ordering::SeqCst),
            "read-only application restore observation invoked load_or_create"
        );
        let mut slot = self.slot(role).lock().map_err(|_| workspace_error())?;
        if let Some(key) = *slot {
            return Ok(key);
        }
        let key = Self::random_key()?;
        *slot = Some(key);
        Ok(key)
    }

    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        if !matches!(
            role,
            KeyRole::McpTicket | KeyRole::QualificationRevocationEpoch
        ) {
            return Err(workspace_error());
        }
        let mut slot = self.slot(role).lock().map_err(|_| workspace_error())?;
        let key = Self::rotate_to_distinct_key(slot.as_ref())?;
        if let Some(previous) = slot.as_mut() {
            zeroize(previous);
        }
        *slot = Some(key);
        Ok(key)
    }
}

#[cfg(test)]
#[derive(Debug)]
struct ApplicationBackupAlwaysQualified;

#[cfg(test)]
impl ApprovedWorkspaceQualificationProvider for ApplicationBackupAlwaysQualified {
    fn current_qualification(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError> {
        Ok(ApprovedMcpQualificationSnapshotV1 {
            evidence_id: format!("mcpq_{}", "a".repeat(32)),
            evidence_sha256: Sha256Hex::parse("b".repeat(64)).expect("test evidence hash"),
            stdio_canary_passed: true,
            streamable_http_canary_passed: true,
            exact_app_policy_binding: true,
            exact_server_key_binding: true,
            mcp_binary_path_identity_sha256: Sha256Hex::parse("c".repeat(64))
                .expect("test path hash"),
            mcp_binary_file_identity_sha256: Sha256Hex::parse("d".repeat(64))
                .expect("test identity hash"),
            mcp_binary_sha256: Sha256Hex::parse("e".repeat(64)).expect("test binary hash"),
            mcp_binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: legal_mcp::approved_backend::APPROVED_MCP_POLICY_ID.to_owned(),
            policy_version: legal_mcp::approved_backend::APPROVED_MCP_POLICY_VERSION,
            server_key_id: "application-backup-test-key".to_owned(),
            server_key_version: 1,
            revocation_epoch: 1,
            issued_at_unix: now_unix.saturating_sub(1).max(1),
            expires_at_unix: now_unix.saturating_add(3600),
            revoked: false,
        })
    }
}

/// Migration checkpoints do not need an MCP qualification and must not gain a
/// passing qualification merely because their test workspace is ephemeral.
/// Returning `Unavailable` makes any accidental qualification dependency fail
/// closed while the real Step-3/4/6 storage and credential paths remain usable.
#[cfg(test)]
#[derive(Debug)]
struct ApplicationBackupMigrationQualificationUnavailable;

#[cfg(test)]
impl ApprovedWorkspaceQualificationProvider for ApplicationBackupMigrationQualificationUnavailable {
    fn current_qualification(
        &self,
        _now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError> {
        Err(ApprovedWorkspaceQualificationError::Unavailable)
    }
}

#[cfg(test)]
pub(crate) struct ApplicationBackupTestHarness {
    pub(crate) workspace: ApprovedMcpWorkspace,
    keys: Arc<ApplicationBackupTestKeys>,
}

#[cfg(test)]
impl ApplicationBackupTestHarness {
    pub(crate) fn new(app_local_data_directory: PathBuf) -> Self {
        Self::with_qualification(
            app_local_data_directory,
            Arc::new(ApplicationBackupAlwaysQualified),
            true,
        )
    }

    /// Creates the real migration storage/key fixture without installing a
    /// synthetic passing MCP qualification. Fixed production Credential
    /// Manager names remain untouched; the four migration target keys are
    /// generated lazily by the Windows CSPRNG-backed in-memory provider.
    pub(crate) fn new_for_v031_migration(app_local_data_directory: PathBuf) -> Self {
        Self::with_qualification(
            app_local_data_directory,
            Arc::new(ApplicationBackupMigrationQualificationUnavailable),
            false,
        )
    }

    fn with_qualification(
        app_local_data_directory: PathBuf,
        qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
        install_qualification_control: bool,
    ) -> Self {
        let keys = Arc::new(ApplicationBackupTestKeys::new());
        let key_provider: Arc<dyn super::ApprovedMcpKeyProvider> = keys.clone();
        let qualification_control = Arc::new(
            super::qualification::DesktopApprovedMcpQualificationProvider::new(
                app_local_data_directory
                    .join("privacy")
                    .join("approved-mcp")
                    .join("qualification"),
                key_provider.clone(),
                app_local_data_directory.join("missing-test-mcp.exe"),
            ),
        );
        let workspace = ApprovedMcpWorkspace::from_parts(
            app_local_data_directory,
            qualification,
            key_provider,
            install_qualification_control.then_some(qualification_control),
        );
        Self { workspace, keys }
    }

    /// Returns a one-test CSPRNG key for secondary test-only signers. It is
    /// deliberately unrelated to the four lazily created Approved workspace
    /// keys and never enters Windows Credential Manager.
    pub(crate) fn ephemeral_secret_key(&self) -> Result<[u8; 32], ApprovedMcpError> {
        ApplicationBackupTestKeys::random_key()
    }

    pub(crate) fn panic_if_load_or_create_is_called(&self) {
        self.keys
            .panic_on_load_or_create
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn drift_application_restore_ticket_credential(
        &self,
    ) -> Result<(), ApprovedMcpError> {
        let mut replacement = <ApplicationBackupTestKeys as super::ApprovedMcpKeyProvider>::rotate(
            self.keys.as_ref(),
            KeyRole::McpTicket,
        )?;
        zeroize(&mut replacement);
        Ok(())
    }

    pub(crate) fn epochs(&self) -> Result<(u8, u8), ApprovedMcpError> {
        self.keys.epochs()
    }

    pub(crate) fn publish_generation(
        &self,
        case_id: &str,
        nonce: char,
    ) -> Result<super::PublishedApprovedGeneration, ApprovedMcpError> {
        let now_unix = now_seconds()?;
        let approved_payload = format!(
            "{{\"schemaVersion\":1,\"pages\":[{{\"pageNumber\":1,\"text\":\"[PERSON_001] approved {nonce}\"}}]}}"
        )
        .into_bytes();
        let source_sha256 = sha256_hex(format!("source-{nonce}").as_bytes());
        let extraction_sha256 = sha256_hex(format!("extraction-{nonce}").as_bytes());
        let redacted_content_sha256 = sha256_hex(format!("redacted-{nonce}").as_bytes());
        let approved_payload_sha256 = sha256_hex(&approved_payload);
        let receipt = privacy::ReceiptSigner::new([0x55; 32])
            .map_err(|_| workspace_error())?
            .issue(privacy::RedactionReceiptClaims {
                receipt_id: format!("rct_{}", nonce.to_string().repeat(32)),
                source_sha256: vec![source_sha256.clone()],
                extraction_sha256: extraction_sha256.clone(),
                redacted_content_sha256: redacted_content_sha256.clone(),
                approved_payload_sha256: approved_payload_sha256.clone(),
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: privacy::REDACTION_VERSION.to_owned(),
                destination: privacy::DestinationScope {
                    kind: privacy::DestinationKind::ExternalMcpHost,
                    identifier: privacy::workspace::APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
                },
                purpose: privacy::workspace::APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
                unresolved_high_risk_count: 0,
                review_state: privacy::ReviewState::Approved,
                issued_at_unix: now_unix,
                expires_at_unix: Some(now_unix.saturating_add(3600)),
                key_version: 1,
            })
            .map_err(|_| workspace_error())?;
        self.workspace.publish(
            case_id,
            ApprovedGenerationSource {
                redaction_id: format!("red_{}", nonce.to_string().repeat(32)),
                case_id: Some(case_id.to_owned()),
                material_id: format!("mat_{}", "1".repeat(32)),
                source_sha256,
                source_name_sha256: Sha256Hex::parse(sha256_hex(
                    format!("synthetic-{nonce}.pdf").as_bytes(),
                ))
                .map_err(|_| workspace_error())?,
                source_revision_hash: Sha256Hex::parse(sha256_hex(
                    format!("source-revision-{nonce}").as_bytes(),
                ))
                .map_err(|_| workspace_error())?,
                extraction_sha256,
                redacted_content_sha256,
                approved_payload_sha256,
                content_media_type: "application/vnd.lawyer-assistance.approved+json".to_owned(),
                approved_payload,
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: privacy::REDACTION_VERSION.to_owned(),
                processing_version: "application-backup-test-v1".to_owned(),
                backend_trace: Vec::new(),
                summary: privacy::RedactionSummary::default(),
                dictionary_revision_hash: Sha256Hex::parse(sha256_hex(
                    format!("dictionary-{nonce}").as_bytes(),
                ))
                .map_err(|_| workspace_error())?,
                mapping_revision_hash: Sha256Hex::parse(sha256_hex(
                    format!("mapping-{nonce}").as_bytes(),
                ))
                .map_err(|_| workspace_error())?,
                case_dictionary_terms: zeroize::Zeroizing::new(vec![format!(
                    "Synthetic Raw Name {nonce}"
                )]),
                source_terms: zeroize::Zeroizing::new(vec![format!("synthetic-{nonce}.pdf")]),
                raw_canary_terms: zeroize::Zeroizing::new(vec![format!(
                    "Sensitive Canary {nonce}447700900123"
                )]),
                receipt,
            },
        )
    }

    pub(crate) fn create_work_product(
        &self,
        published: &super::PublishedApprovedGeneration,
        content: &[u8],
    ) -> Result<String, ApprovedMcpError> {
        let _manager_operation = self.workspace.operation()?;
        let manifest_key = self
            .workspace
            .inner
            .keys
            .load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_id = workspace_instance_id(&manifest_key)?;
        let approved_signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let approved_verifier = approved_signer.verification_key();
        WorkspacePublisher::initialize(&self.workspace.inner.approved_root, approved_signer)
            .map_err(|_| workspace_error())?;
        let approved =
            ApprovedWorkspaceService::open(&self.workspace.inner.approved_root, approved_verifier)
                .map_err(|_| workspace_error())?;
        let work_key = self
            .workspace
            .inner
            .keys
            .load_or_create(KeyRole::WorkProductManifest)?;
        let work_signer =
            ManifestSigningKey::from_bytes(work_key, KEY_VERSION).map_err(|_| workspace_error())?;
        let publisher = WorkProductPublisher::initialize(
            &self.workspace.inner.work_product_root,
            workspace_id,
            work_signer,
        )
        .map_err(|_| workspace_error())?;
        let case_id = CaseId::parse(published.case_id.clone()).map_err(|_| workspace_error())?;
        let created = publisher
            .create(
                &case_id,
                WorkProductWriteV1 {
                    task_type: "case_analysis".to_owned(),
                    status: "draft".to_owned(),
                    source_approved_refs: vec![ApprovedMaterialRefV1 {
                        material_id: privacy::vnext::MaterialId::parse(
                            published.material_id.clone(),
                        )
                        .map_err(|_| workspace_error())?,
                        document_version: published.document_version,
                        publication_id: PublicationId::parse(published.publication_id.clone())
                            .map_err(|_| workspace_error())?,
                        manifest_sha256: Sha256Hex::parse(published.manifest_sha256.clone())
                            .map_err(|_| workspace_error())?,
                    }],
                    content_media_type: "text/markdown".to_owned(),
                    diagram_spec_sha256: None,
                    placeholder_policy_version: "placeholder-v1".to_owned(),
                    author_tool: "application-backup-test".to_owned(),
                    author_tool_version: env!("CARGO_PKG_VERSION").to_owned(),
                    idempotency_key: format!("backup-test-{}", Uuid::new_v4().simple()),
                },
                content,
                &approved,
                now_seconds()?,
            )
            .map_err(|_| workspace_error())?;
        Ok(created.work_product_id.as_str().to_owned())
    }

    pub(crate) fn work_product_count(&self, case_id: &str) -> Result<usize, ApprovedMcpError> {
        let _manager_operation = self.workspace.operation()?;
        let (_, approved, work_products) = self.workspace.open_backup_services()?;
        let case_id = CaseId::parse(case_id.to_owned()).map_err(|_| workspace_error())?;
        work_products
            .list_case(&case_id, &approved, now_seconds()?)
            .map(|rows| rows.len())
            .map_err(|_| workspace_error())
    }

    pub(crate) fn committed_work_product_row_count(
        &self,
        case_id: &str,
    ) -> Result<usize, ApprovedMcpError> {
        let _manager_operation = self.workspace.operation()?;
        let case_id = CaseId::parse(case_id.to_owned()).map_err(|_| workspace_error())?;
        let connection = open_read_only_database(
            &self
                .workspace
                .inner
                .work_product_root
                .join(WORK_PRODUCTS_DATABASE_FILE),
        )?;
        validate_sqlite(&connection)?;
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM work_product_versions
                 WHERE case_id=?1 AND state='committed' AND revoked_at_unix IS NULL",
                [case_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| workspace_error())?;
        usize::try_from(count).map_err(|_| workspace_error())
    }
}

pub(crate) struct ApprovedApplicationBackupSnapshot {
    pub approved_workspace_bundle: Vec<u8>,
    pub approved_workspace_manifest_sha256: String,
    pub work_products_bundle: Vec<u8>,
    pub work_products_manifest_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurrentApprovedComponentsLifecycle {
    /// The workspace identity exists, while neither lazily-created store has
    /// ever been initialized.
    IdentityOnly,
    /// Approved generations exist, while work products have not yet been used.
    ApprovedOnly,
    /// Both current stores exist and were authenticated independently.
    ApprovedAndWorkProducts,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CurrentApprovedComponentsProof {
    workspace_instance_id: WorkspaceInstanceId,
    lifecycle: CurrentApprovedComponentsLifecycle,
    approved_archive_sha256: Option<String>,
    approved_manifest_sha256: Option<String>,
    work_products_archive_sha256: Option<String>,
    work_products_manifest_sha256: Option<String>,
    approved_publication_rows: u64,
    active_work_product_rows: u64,
    mcp_ticket_credential_present: bool,
    qualification_credential_present: bool,
}

impl std::fmt::Debug for CurrentApprovedComponentsProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CurrentApprovedComponentsProof")
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field("lifecycle", &self.lifecycle)
            .field("approved_archive_sha256", &self.approved_archive_sha256)
            .field("approved_manifest_sha256", &self.approved_manifest_sha256)
            .field(
                "work_products_archive_sha256",
                &self.work_products_archive_sha256,
            )
            .field(
                "work_products_manifest_sha256",
                &self.work_products_manifest_sha256,
            )
            .field("approved_publication_rows", &self.approved_publication_rows)
            .field("active_work_product_rows", &self.active_work_product_rows)
            .field(
                "mcp_ticket_credential_present",
                &self.mcp_ticket_credential_present,
            )
            .field(
                "qualification_credential_present",
                &self.qualification_credential_present,
            )
            .finish()
    }
}

impl CurrentApprovedComponentsProof {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub(crate) fn lifecycle(&self) -> CurrentApprovedComponentsLifecycle {
        self.lifecycle
    }

    pub(crate) fn approved_archive_sha256(&self) -> Option<&str> {
        self.approved_archive_sha256.as_deref()
    }

    pub(crate) fn approved_manifest_sha256(&self) -> Option<&str> {
        self.approved_manifest_sha256.as_deref()
    }

    pub(crate) fn work_products_archive_sha256(&self) -> Option<&str> {
        self.work_products_archive_sha256.as_deref()
    }

    pub(crate) fn work_products_manifest_sha256(&self) -> Option<&str> {
        self.work_products_manifest_sha256.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentApprovedComponentsObservation {
    /// No Approved-MCP identity, component root, or auxiliary credential exists.
    Absent,
    Exact(CurrentApprovedComponentsProof),
}

impl std::fmt::Debug for ApprovedApplicationBackupSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovedApplicationBackupSnapshot")
            .field(
                "approved_workspace_bundle",
                &format_args!("[PROTECTED {} BYTES]", self.approved_workspace_bundle.len()),
            )
            .field(
                "work_products_bundle",
                &format_args!("[PROTECTED {} BYTES]", self.work_products_bundle.len()),
            )
            .field(
                "approved_workspace_manifest_sha256",
                &self.approved_workspace_manifest_sha256,
            )
            .field(
                "work_products_manifest_sha256",
                &self.work_products_manifest_sha256,
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreArchiveEnvelopeV1 {
    schema_version: String,
    manifest: StoreArchiveManifestV1,
    manifest_sha256: String,
    files: Vec<StoreArchivePayloadV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreArchiveManifestV1 {
    schema_version: String,
    store_kind: String,
    workspace_instance_id: WorkspaceInstanceId,
    files: Vec<StoreArchiveFileV1>,
    file_count: u64,
    plaintext_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreArchiveFileV1 {
    relative_path: String,
    plaintext_bytes: u64,
    plaintext_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreArchivePayloadV1 {
    relative_path: String,
    plaintext_base64: String,
}

struct DatabaseSnapshot {
    bytes: Vec<u8>,
    active_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V031SqlitePhysicalFileEvidence {
    identity_sha256: String,
    length: u64,
    modified: SystemTime,
    sha256: String,
    prefix: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V031SqlitePhysicalEvidence {
    database: V031SqlitePhysicalFileEvidence,
    wal: Option<V031SqlitePhysicalFileEvidence>,
    shm: Option<V031SqlitePhysicalFileEvidence>,
    journal: Option<V031SqlitePhysicalFileEvidence>,
}

/// Retains read-only, deny-write, deny-delete handles for every component that
/// existed at preflight. The process-wide migration operation gate excludes
/// application writers; these handles additionally prevent SQLite's read-only
/// recovery view from persisting volatile SHM read-mark changes.
struct V031PinnedSqlitePhysicalState {
    evidence: V031SqlitePhysicalEvidence,
    database_bytes: Vec<u8>,
    _guards: Vec<File>,
}

impl ApprovedMcpWorkspace {
    /// Authenticates the finite, lazy lifecycle of the two ordinary current
    /// stores before any manager is initialized.
    ///
    /// The only accepted states are identity-only, approved-only, and
    /// approved-plus-work-products.  A work-product root without an approved
    /// root, a root without its Credential Manager key, or a key whose root was
    /// never committed is a partial state and fails closed.  No key, directory,
    /// SQLite object, checkpoint, journal mode, or recovery file is created.
    pub(crate) fn observe_current_components_read_only(
        &self,
    ) -> Result<CurrentApprovedComponentsObservation, ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        validate_directory_identity(&self.inner.app_local_data_directory)?;

        let (approved_present, work_products_present, ticket_present, qualification_present) =
            observe_current_component_directories(self)?;
        let credential_digests_before = current_credential_digests(self.inner.keys.as_ref())?;
        let approved_credential_present = credential_digests_before[0].is_some();
        let work_products_credential_present = credential_digests_before[1].is_some();
        let ticket_credential_present = credential_digests_before[2].is_some();
        let qualification_credential_present = credential_digests_before[3].is_some();

        if !approved_credential_present {
            if approved_present
                || work_products_present
                || ticket_present
                || qualification_present
                || credential_digests_before.iter().any(Option::is_some)
            {
                return Err(workspace_error());
            }
            return Ok(CurrentApprovedComponentsObservation::Absent);
        }

        // Ticket and qualification state are optional ordinary runtime state,
        // but a persisted root and its authenticating credential must appear as
        // a pair.  They do not otherwise decide the five-component lifecycle.
        if ticket_present && !ticket_credential_present
            || qualification_present && !qualification_credential_present
        {
            return Err(workspace_error());
        }
        if work_products_present && !approved_present
            || work_products_present != work_products_credential_present
        {
            return Err(workspace_error());
        }

        let mut approved_key = self
            .inner
            .keys
            .load_existing(KeyRole::ApprovedManifest)?
            .ok_or_else(workspace_error)?;
        let workspace_instance_id = workspace_instance_id(&approved_key)?;
        let approved_signer = ManifestSigningKey::from_bytes(approved_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        zeroize(&mut approved_key);

        let mut approved_archive_sha256 = None;
        let mut approved_manifest_sha256 = None;
        let mut work_products_archive_sha256 = None;
        let mut work_products_manifest_sha256 = None;
        let mut approved_publication_rows = 0_u64;
        let mut active_work_product_rows = 0_u64;

        let lifecycle = if !approved_present {
            if work_products_credential_present {
                return Err(workspace_error());
            }
            CurrentApprovedComponentsLifecycle::IdentityOnly
        } else {
            let approved_physical_guard = capture_current_sqlite_physical_state(
                &self.inner.approved_root.join(APPROVED_DATABASE_FILE),
            )?;
            let approved_before = capture_current_store_archive(
                &self.inner.app_local_data_directory,
                &self.inner.approved_root,
                APPROVED_STORE_KIND,
                APPROVED_DATABASE_FILE,
                &workspace_instance_id,
                MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
            )?;
            let approved = ApprovedWorkspaceService::open_read_only(
                &self.inner.approved_root,
                approved_signer.verification_key(),
            )
            .map_err(|_| workspace_error())?;
            let operation = approved
                .acquire_operation_guard()
                .map_err(|_| workspace_error())?;
            approved_publication_rows = validate_current_approved_store_locked(
                &approved,
                &operation,
                &self.inner.approved_root.join(APPROVED_DATABASE_FILE),
                now_seconds()?,
            )?;

            if work_products_present {
                let work_physical_guard = capture_current_sqlite_physical_state(
                    &self
                        .inner
                        .work_product_root
                        .join(WORK_PRODUCTS_DATABASE_FILE),
                )?;
                let mut work_key = self
                    .inner
                    .keys
                    .load_existing(KeyRole::WorkProductManifest)?
                    .ok_or_else(workspace_error)?;
                let work_signer = ManifestSigningKey::from_bytes(work_key, KEY_VERSION)
                    .map_err(|_| workspace_error())?;
                zeroize(&mut work_key);
                let work_before = capture_current_store_archive(
                    &self.inner.app_local_data_directory,
                    &self.inner.work_product_root,
                    WORK_PRODUCTS_STORE_KIND,
                    WORK_PRODUCTS_DATABASE_FILE,
                    &workspace_instance_id,
                    MAX_WORK_PRODUCTS_BACKUP_BYTES,
                )?;
                let work_products = WorkProductService::open_read_only(
                    &self.inner.work_product_root,
                    workspace_instance_id.clone(),
                    work_signer.verification_key(),
                )
                .map_err(|_| workspace_error())?;
                active_work_product_rows = validate_current_work_products_locked(
                    &approved,
                    &work_products,
                    &operation,
                    &self
                        .inner
                        .work_product_root
                        .join(WORK_PRODUCTS_DATABASE_FILE),
                    now_seconds()?,
                )?;
                let work_after = capture_current_store_archive(
                    &self.inner.app_local_data_directory,
                    &self.inner.work_product_root,
                    WORK_PRODUCTS_STORE_KIND,
                    WORK_PRODUCTS_DATABASE_FILE,
                    &workspace_instance_id,
                    MAX_WORK_PRODUCTS_BACKUP_BYTES,
                )?;
                if work_after != work_before {
                    return Err(workspace_error());
                }
                work_products_archive_sha256 = Some(work_before.archive_sha256);
                work_products_manifest_sha256 = Some(work_before.manifest_sha256);
                drop(work_physical_guard);
            }
            drop(operation);
            let approved_after = capture_current_store_archive(
                &self.inner.app_local_data_directory,
                &self.inner.approved_root,
                APPROVED_STORE_KIND,
                APPROVED_DATABASE_FILE,
                &workspace_instance_id,
                MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
            )?;
            if approved_after != approved_before {
                return Err(workspace_error());
            }
            approved_archive_sha256 = Some(approved_before.archive_sha256);
            approved_manifest_sha256 = Some(approved_before.manifest_sha256);
            drop(approved_physical_guard);
            if work_products_present {
                CurrentApprovedComponentsLifecycle::ApprovedAndWorkProducts
            } else {
                CurrentApprovedComponentsLifecycle::ApprovedOnly
            }
        };

        if current_credential_digests(self.inner.keys.as_ref())? != credential_digests_before
            || observe_current_component_directories(self)?
                != (
                    approved_present,
                    work_products_present,
                    ticket_present,
                    qualification_present,
                )
        {
            return Err(workspace_error());
        }

        Ok(CurrentApprovedComponentsObservation::Exact(
            CurrentApprovedComponentsProof {
                workspace_instance_id,
                lifecycle,
                approved_archive_sha256,
                approved_manifest_sha256,
                work_products_archive_sha256,
                work_products_manifest_sha256,
                approved_publication_rows,
                active_work_product_rows,
                mcp_ticket_credential_present: ticket_credential_present,
                qualification_credential_present,
            },
        ))
    }

    /// Captures the already-authenticated, empty Step-3 target without opening
    /// either service through its writable initializer. The caller verifies the
    /// opaque Approved/Vault gates immediately before this call; this method
    /// keeps the target database files and sidecars byte-for-byte unchanged.
    pub(crate) fn snapshot_for_v031_migration_checkpoint(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        approved_gate: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<ApprovedApplicationBackupSnapshot, ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        let root_basenames_before = direct_child_basenames(&self.inner.app_local_data_directory)?;
        reject_application_backup_temporaries(&root_basenames_before)?;
        let rollback_binding = V031RollbackGateBinding::from_verified_gate(rollback_gate);
        self.verify_v031_target_components_with_binding_locked_read_only(
            &rollback_binding,
            approved_gate,
        )?;
        let mut manifest_key = self
            .inner
            .keys
            .load_existing(KeyRole::ApprovedManifest)?
            .ok_or_else(workspace_error)?;
        let workspace_id = workspace_instance_id(&manifest_key);
        zeroize(&mut manifest_key);
        let workspace_id = workspace_id?;
        if &workspace_id != approved_gate.workspace_instance_id() {
            return Err(workspace_error());
        }
        let approved_database = snapshot_database_for_v031_migration(
            &self.inner.app_local_data_directory,
            &self.inner.approved_root.join(APPROVED_DATABASE_FILE),
            APPROVED_STORE_KIND,
        )?;
        let work_products_database = snapshot_database_for_v031_migration(
            &self.inner.app_local_data_directory,
            &self
                .inner
                .work_product_root
                .join(WORK_PRODUCTS_DATABASE_FILE),
            WORK_PRODUCTS_STORE_KIND,
        )?;
        let (approved_workspace_bundle, approved_workspace_manifest_sha256) = build_archive(
            &self.inner.approved_root,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            approved_database.bytes,
            approved_database.active_paths,
            &workspace_id,
            MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
        )?;
        let (work_products_bundle, work_products_manifest_sha256) = build_archive(
            &self.inner.work_product_root,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            work_products_database.bytes,
            work_products_database.active_paths,
            &workspace_id,
            MAX_WORK_PRODUCTS_BACKUP_BYTES,
        )?;
        let snapshot = ApprovedApplicationBackupSnapshot {
            approved_workspace_bundle,
            approved_workspace_manifest_sha256,
            work_products_bundle,
            work_products_manifest_sha256,
        };
        self.verify_v031_target_components_with_binding_locked_read_only(
            &rollback_binding,
            approved_gate,
        )?;
        let root_basenames_after = direct_child_basenames(&self.inner.app_local_data_directory)?;
        reject_application_backup_temporaries(&root_basenames_after)?;
        if root_basenames_after != root_basenames_before {
            return Err(workspace_error());
        }
        Ok(snapshot)
    }

    pub(crate) fn snapshot_for_application_backup(
        &self,
    ) -> Result<ApprovedApplicationBackupSnapshot, ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        let now_unix = now_seconds()?;
        let (workspace_id, approved, work_products) = self.open_backup_services()?;
        let operation = approved
            .acquire_operation_guard()
            .map_err(|_| workspace_error())?;
        validate_active_store_locked(
            &approved,
            &work_products,
            &operation,
            &self
                .inner
                .work_product_root
                .join(WORK_PRODUCTS_DATABASE_FILE),
            now_unix,
        )?;

        let approved_database = snapshot_database(
            &self.inner.app_local_data_directory,
            &self.inner.approved_root.join(APPROVED_DATABASE_FILE),
            APPROVED_STORE_KIND,
        )?;
        let work_products_database = snapshot_database(
            &self.inner.app_local_data_directory,
            &self
                .inner
                .work_product_root
                .join(WORK_PRODUCTS_DATABASE_FILE),
            WORK_PRODUCTS_STORE_KIND,
        )?;
        let (approved_workspace_bundle, approved_workspace_manifest_sha256) = build_archive(
            &self.inner.approved_root,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            approved_database.bytes,
            approved_database.active_paths,
            &workspace_id,
            MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
        )?;
        let (work_products_bundle, work_products_manifest_sha256) = build_archive(
            &self.inner.work_product_root,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            work_products_database.bytes,
            work_products_database.active_paths,
            &workspace_id,
            MAX_WORK_PRODUCTS_BACKUP_BYTES,
        )?;
        Ok(ApprovedApplicationBackupSnapshot {
            approved_workspace_bundle,
            approved_workspace_manifest_sha256,
            work_products_bundle,
            work_products_manifest_sha256,
        })
    }

    /// Strict, allocation-only readback for checkpoint archives.  It verifies
    /// canonical outer JSON, every payload hash, the embedded SQLite image and
    /// the exact active-file projection without creating a restore directory.
    pub(crate) fn verify_application_backup_snapshot_bytes(
        &self,
        approved_bundle: &[u8],
        expected_approved_manifest_sha256: &str,
        work_products_bundle: &[u8],
        expected_work_products_manifest_sha256: &str,
    ) -> Result<(), ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        let workspace_id = self.existing_workspace_instance_id_locked()?;
        verify_archive_bytes(
            approved_bundle,
            expected_approved_manifest_sha256,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            &workspace_id,
            MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
        )?;
        verify_archive_bytes(
            work_products_bundle,
            expected_work_products_manifest_sha256,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            &workspace_id,
            MAX_WORK_PRODUCTS_BACKUP_BYTES,
        )
    }

    pub(crate) fn stage_application_backup_components(
        &self,
        approved_bundle: &[u8],
        expected_approved_manifest_sha256: &str,
        work_products_bundle: &[u8],
        expected_work_products_manifest_sha256: &str,
        approved_incoming: &Path,
        work_products_incoming: &Path,
    ) -> Result<(), ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        let workspace_id = self.workspace_instance_id_locked()?;
        unpack_archive(
            approved_bundle,
            expected_approved_manifest_sha256,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            &workspace_id,
            approved_incoming,
            MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
        )?;
        if let Err(error) = unpack_archive(
            work_products_bundle,
            expected_work_products_manifest_sha256,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            &workspace_id,
            work_products_incoming,
            MAX_WORK_PRODUCTS_BACKUP_BYTES,
        ) {
            let _ = remove_validated_restore_tree(approved_incoming);
            return Err(error);
        }
        if let Err(error) = self.validate_application_backup_roots(
            approved_incoming,
            work_products_incoming,
            now_seconds()?,
        ) {
            let _ = remove_validated_restore_tree(work_products_incoming);
            let _ = remove_validated_restore_tree(approved_incoming);
            return Err(error);
        }
        // Service validation may switch SQLite journal mode while checking every signature,
        // source dependency and DPAPI content envelope. Recreate the two incoming roots from the
        // already authenticated archives so the crash-recovery transaction starts from the exact
        // outer-manifest bytes, with no service-generated sidecars or metadata drift.
        remove_validated_restore_tree(work_products_incoming)?;
        remove_validated_restore_tree(approved_incoming)?;
        unpack_archive(
            approved_bundle,
            expected_approved_manifest_sha256,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            &workspace_id,
            approved_incoming,
            MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
        )?;
        if let Err(error) = unpack_archive(
            work_products_bundle,
            expected_work_products_manifest_sha256,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            &workspace_id,
            work_products_incoming,
            MAX_WORK_PRODUCTS_BACKUP_BYTES,
        ) {
            let _ = remove_validated_restore_tree(approved_incoming);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn validate_staged_application_backup_manifests(
        &self,
        approved_root: &Path,
        expected_approved_manifest_sha256: &str,
        work_products_root: &Path,
        expected_work_products_manifest_sha256: &str,
    ) -> Result<(), ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        // Startup restore observation is a strict read boundary.  Missing
        // credentials must fail closed here and must never fall through to the
        // ordinary lazy identity creator.
        let approved_key = super::ApplicationRestoreSecretKey::new(
            self.inner
                .keys
                .load_existing(KeyRole::ApprovedManifest)?
                .ok_or_else(workspace_error)?,
        );
        let _work_products_key = super::ApplicationRestoreSecretKey::new(
            self.inner
                .keys
                .load_existing(KeyRole::WorkProductManifest)?
                .ok_or_else(workspace_error)?,
        );
        let workspace_id = workspace_instance_id(approved_key.as_bytes())?;
        validate_exact_archive_root(
            approved_root,
            APPROVED_STORE_KIND,
            APPROVED_DATABASE_FILE,
            &workspace_id,
            expected_approved_manifest_sha256,
        )?;
        validate_exact_archive_root(
            work_products_root,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
            &workspace_id,
            expected_work_products_manifest_sha256,
        )
    }

    pub(crate) fn validate_application_backup_roots(
        &self,
        approved_root: &Path,
        work_products_root: &Path,
        now_unix: u64,
    ) -> Result<(), ApprovedMcpError> {
        validate_directory_identity(approved_root)?;
        validate_directory_identity(work_products_root)?;
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_id = workspace_instance_id(&manifest_key)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(approved_root, signer).map_err(|_| workspace_error())?;
        let approved = ApprovedWorkspaceService::open(approved_root, verifier)
            .map_err(|_| workspace_error())?;
        let work_key = self
            .inner
            .keys
            .load_or_create(KeyRole::WorkProductManifest)?;
        let work_signer =
            ManifestSigningKey::from_bytes(work_key, KEY_VERSION).map_err(|_| workspace_error())?;
        let work_verifier = work_signer.verification_key();
        WorkProductPublisher::initialize(work_products_root, workspace_id.clone(), work_signer)
            .map_err(|_| workspace_error())?;
        let work_products =
            WorkProductService::open(work_products_root, workspace_id, work_verifier)
                .map_err(|_| workspace_error())?;
        let operation = approved
            .acquire_operation_guard()
            .map_err(|_| workspace_error())?;
        validate_active_store_locked(
            &approved,
            &work_products,
            &operation,
            &work_products_root.join(WORK_PRODUCTS_DATABASE_FILE),
            now_unix,
        )?;
        drop(operation);
        checkpoint_restore_database(&approved_root.join(APPROVED_DATABASE_FILE))?;
        checkpoint_restore_database(&work_products_root.join(WORK_PRODUCTS_DATABASE_FILE))?;
        validate_staged_tree(approved_root, APPROVED_STORE_KIND, APPROVED_DATABASE_FILE)?;
        validate_staged_tree(
            work_products_root,
            WORK_PRODUCTS_STORE_KIND,
            WORK_PRODUCTS_DATABASE_FILE,
        )
    }

    pub(crate) fn invalidate_after_application_restore(&self) -> Result<(), ApprovedMcpError> {
        let _manager_operation = self.operation()?;
        let mut replacement = self.inner.keys.rotate(KeyRole::McpTicket)?;
        replacement.fill(0);
        if let Some(control) = &self.inner.qualification_control {
            control.revoke()?;
        }
        revoke_standalone_sessions_with(
            || {
                legal_mcp::standalone_approved::inspect_standalone_sessions(
                    &self.inner.app_local_data_directory,
                )
                .map(|sessions| {
                    sessions
                        .into_iter()
                        .map(|session| session.server_instance_id)
                        .collect()
                })
                .map_err(super::standalone_error)
            },
            |server_instance_id| {
                legal_mcp::standalone_approved::revoke_standalone_session(
                    &self.inner.app_local_data_directory,
                    server_instance_id,
                )
                .map_err(super::standalone_error)
            },
        )?;
        Ok(())
    }

    fn open_backup_services(
        &self,
    ) -> Result<
        (
            WorkspaceInstanceId,
            ApprovedWorkspaceService,
            WorkProductService,
        ),
        ApprovedMcpError,
    > {
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_id = workspace_instance_id(&manifest_key)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        let approved = ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?;
        let work_key = self
            .inner
            .keys
            .load_or_create(KeyRole::WorkProductManifest)?;
        let work_signer =
            ManifestSigningKey::from_bytes(work_key, KEY_VERSION).map_err(|_| workspace_error())?;
        let work_verifier = work_signer.verification_key();
        WorkProductPublisher::initialize(
            &self.inner.work_product_root,
            workspace_id.clone(),
            work_signer,
        )
        .map_err(|_| workspace_error())?;
        let work_products = WorkProductService::open(
            &self.inner.work_product_root,
            workspace_id.clone(),
            work_verifier,
        )
        .map_err(|_| workspace_error())?;
        Ok((workspace_id, approved, work_products))
    }

    fn workspace_instance_id_locked(&self) -> Result<WorkspaceInstanceId, ApprovedMcpError> {
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        workspace_instance_id(&manifest_key)
    }

    fn existing_workspace_instance_id_locked(
        &self,
    ) -> Result<WorkspaceInstanceId, ApprovedMcpError> {
        let mut manifest_key = self
            .inner
            .keys
            .load_existing(KeyRole::ApprovedManifest)?
            .ok_or_else(workspace_error)?;
        let workspace_id = workspace_instance_id(&manifest_key);
        zeroize(&mut manifest_key);
        workspace_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentStoreArchiveEvidence {
    archive_sha256: String,
    manifest_sha256: String,
}

fn observe_current_component_directories(
    workspace: &ApprovedMcpWorkspace,
) -> Result<(bool, bool, bool, bool), ApprovedMcpError> {
    let parent = workspace
        .inner
        .app_local_data_directory
        .join("privacy")
        .join("approved-mcp");
    let parent_present = optional_current_directory(&parent)?;
    if !parent_present {
        return Ok((false, false, false, false));
    }
    let allowed = BTreeSet::from([
        super::APPROVED_ROOT_NAME,
        super::WORK_PRODUCT_ROOT_NAME,
        super::TICKET_ROOT_NAME,
        "qualification",
    ]);
    if direct_child_basenames(&parent)?
        .iter()
        .any(|name| !allowed.contains(name.as_str()))
    {
        return Err(workspace_error());
    }
    Ok((
        optional_current_directory(&workspace.inner.approved_root)?,
        optional_current_directory(&workspace.inner.work_product_root)?,
        optional_current_directory(&workspace.inner.ticket_root)?,
        optional_current_directory(&parent.join("qualification"))?,
    ))
}

fn optional_current_directory(path: &Path) -> Result<bool, ApprovedMcpError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_directory_identity(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(workspace_error()),
    }
}

fn current_credential_digests(
    provider: &dyn super::ApprovedMcpKeyProvider,
) -> Result<[Option<String>; 4], ApprovedMcpError> {
    let mut output: [Option<String>; 4] = std::array::from_fn(|_| None);
    for (index, role) in [
        KeyRole::ApprovedManifest,
        KeyRole::WorkProductManifest,
        KeyRole::McpTicket,
        KeyRole::QualificationRevocationEpoch,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(mut key) = provider.load_existing(role)? {
            if key.iter().all(|byte| *byte == 0) {
                zeroize(&mut key);
                return Err(workspace_error());
            }
            output[index] = Some(sha256_hex(&key));
            zeroize(&mut key);
        }
    }
    Ok(output)
}

fn capture_current_store_archive(
    app_local_data_directory: &Path,
    root: &Path,
    store_kind: &str,
    database_name: &str,
    workspace_instance_id: &WorkspaceInstanceId,
    maximum_bytes: usize,
) -> Result<CurrentStoreArchiveEvidence, ApprovedMcpError> {
    validate_staged_tree(root, store_kind, database_name)?;
    validate_directory_identity(app_local_data_directory)?;
    let snapshot =
        snapshot_database_for_current_observation(&root.join(database_name), store_kind)?;
    let (mut archive, manifest_sha256) = build_archive(
        root,
        store_kind,
        database_name,
        snapshot.bytes,
        snapshot.active_paths,
        workspace_instance_id,
        maximum_bytes,
    )?;
    let archive_sha256 = sha256_hex(&archive);
    zeroize(&mut archive);
    Ok(CurrentStoreArchiveEvidence {
        archive_sha256,
        manifest_sha256,
    })
}

fn validate_current_approved_store_locked(
    approved: &ApprovedWorkspaceService,
    operation: &privacy::workspace::ApprovedWorkspaceOperationGuard,
    database: &Path,
    now_unix: u64,
) -> Result<u64, ApprovedMcpError> {
    let connection = open_read_only_database(database)?;
    validate_sqlite(&connection)?;
    let cases = approved
        .list_cases_locked(operation, now_unix)
        .map_err(|_| workspace_error())?;
    for case in cases {
        approved
            .list_case_materials_locked(operation, &case.case_id, now_unix)
            .map_err(|_| workspace_error())?;
    }
    let history = approved
        .list_publication_history(None)
        .map_err(|_| workspace_error())?;
    u64::try_from(history.len()).map_err(|_| workspace_error())
}

fn validate_current_work_products_locked(
    approved: &ApprovedWorkspaceService,
    work_products: &WorkProductService,
    operation: &privacy::workspace::ApprovedWorkspaceOperationGuard,
    database: &Path,
    now_unix: u64,
) -> Result<u64, ApprovedMcpError> {
    let connection = open_read_only_database(database)?;
    validate_sqlite(&connection)?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT case_id FROM work_product_versions
             WHERE state='committed' AND revoked_at_unix IS NULL ORDER BY case_id",
        )
        .map_err(|_| workspace_error())?;
    let case_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| workspace_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| workspace_error())?;
    let mut count = 0_u64;
    for value in case_ids {
        let case_id = CaseId::parse(value).map_err(|_| workspace_error())?;
        let rows = work_products
            .list_case_locked(operation, &case_id, approved, now_unix)
            .map_err(|_| workspace_error())?;
        count = count
            .checked_add(u64::try_from(rows.len()).map_err(|_| workspace_error())?)
            .ok_or_else(workspace_error)?;
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
fn verify_archive_bytes(
    bytes: &[u8],
    expected_manifest_sha256: &str,
    expected_store_kind: &str,
    database_name: &str,
    workspace_id: &WorkspaceInstanceId,
    maximum_bytes: usize,
) -> Result<(), ApprovedMcpError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes || !is_hash(expected_manifest_sha256) {
        return Err(workspace_error());
    }
    let envelope: StoreArchiveEnvelopeV1 =
        strict_json_v1_from_slice(bytes).map_err(|_| workspace_error())?;
    if canonical_json_v1(&envelope).map_err(|_| workspace_error())? != bytes
        || envelope.schema_version != ARCHIVE_SCHEMA_VERSION
        || envelope.manifest.schema_version != ARCHIVE_MANIFEST_SCHEMA_VERSION
        || envelope.manifest.store_kind != expected_store_kind
        || envelope.manifest.workspace_instance_id != *workspace_id
        || envelope.manifest.file_count
            != u64::try_from(envelope.manifest.files.len()).map_err(|_| workspace_error())?
        || envelope.manifest.files.is_empty()
        || envelope.manifest.files.len() > MAX_ARCHIVE_FILES
        || envelope.files.len() != envelope.manifest.files.len()
    {
        return Err(workspace_error());
    }
    let actual_manifest_sha256 =
        sha256_hex(&canonical_json_v1(&envelope.manifest).map_err(|_| workspace_error())?);
    if envelope.manifest_sha256 != actual_manifest_sha256
        || actual_manifest_sha256 != expected_manifest_sha256
    {
        return Err(workspace_error());
    }

    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    let mut database_bytes = None;
    for (metadata, payload) in envelope.manifest.files.iter().zip(&envelope.files) {
        if metadata.relative_path != payload.relative_path
            || !seen.insert(metadata.relative_path.clone())
            || !is_hash(&metadata.plaintext_sha256)
            || payload.plaintext_base64.len() > maximum_bytes.saturating_mul(2)
        {
            return Err(workspace_error());
        }
        let is_database = metadata.relative_path == database_name;
        validate_archive_path(expected_store_kind, &metadata.relative_path, is_database)?;
        if (is_database && metadata.plaintext_bytes > MAX_ARCHIVE_DATABASE_BYTES as u64)
            || (!is_database && metadata.plaintext_bytes > MAX_ARCHIVE_ENTRY_BYTES as u64)
        {
            return Err(workspace_error());
        }
        total = total
            .checked_add(metadata.plaintext_bytes)
            .ok_or_else(workspace_error)?;
        if total > maximum_bytes as u64 {
            return Err(workspace_error());
        }
        let value = BASE64_STANDARD
            .decode(payload.plaintext_base64.as_bytes())
            .map_err(|_| workspace_error())?;
        if value.len() as u64 != metadata.plaintext_bytes
            || sha256_hex(&value) != metadata.plaintext_sha256
        {
            return Err(workspace_error());
        }
        if is_database && database_bytes.replace(value).is_some() {
            return Err(workspace_error());
        }
    }
    if total != envelope.manifest.plaintext_bytes {
        return Err(workspace_error());
    }
    let database_bytes = database_bytes.ok_or_else(workspace_error)?;
    let image_len = u64::try_from(database_bytes.len()).map_err(|_| workspace_error())?;
    let mut connection = Connection::open_in_memory().map_err(|_| workspace_error())?;
    connection
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            Cursor::new(&database_bytes),
            database_bytes.len(),
            true,
        )
        .map_err(|_| workspace_error())?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| workspace_error())?;
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .map_err(|_| workspace_error())?;
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .map_err(|_| workspace_error())?;
    if u64::try_from(page_size).ok().and_then(|size| {
        u64::try_from(page_count)
            .ok()
            .and_then(|count| size.checked_mul(count))
    }) != Some(image_len)
    {
        return Err(workspace_error());
    }
    validate_sqlite(&connection)?;
    let active_paths = if expected_store_kind == APPROVED_STORE_KIND {
        approved_active_paths(&connection)?
    } else if expected_store_kind == WORK_PRODUCTS_STORE_KIND {
        work_product_active_paths(&connection)?
    } else {
        return Err(workspace_error());
    };
    let archived_paths = seen
        .into_iter()
        .filter(|path| path != database_name)
        .collect::<BTreeSet<_>>();
    if archived_paths != active_paths {
        return Err(workspace_error());
    }
    Ok(())
}

fn revoke_standalone_sessions_with<Inspect, Revoke>(
    mut inspect: Inspect,
    mut revoke: Revoke,
) -> Result<(), ApprovedMcpError>
where
    Inspect: FnMut() -> Result<Vec<String>, ApprovedMcpError>,
    Revoke: FnMut(&str) -> Result<(), ApprovedMcpError>,
{
    for server_instance_id in inspect()? {
        revoke(&server_instance_id)?;
    }
    Ok(())
}

fn validate_active_store_locked(
    approved: &ApprovedWorkspaceService,
    work_products: &WorkProductService,
    operation: &privacy::workspace::ApprovedWorkspaceOperationGuard,
    work_database: &Path,
    now_unix: u64,
) -> Result<(), ApprovedMcpError> {
    let cases = approved
        .list_cases_locked(operation, now_unix)
        .map_err(|_| workspace_error())?;
    for case in cases {
        approved
            .list_case_materials_locked(operation, &case.case_id, now_unix)
            .map_err(|_| workspace_error())?;
    }
    let connection = open_read_only_database(work_database)?;
    validate_sqlite(&connection)?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT case_id FROM work_product_versions
             WHERE state='committed' AND revoked_at_unix IS NULL ORDER BY case_id",
        )
        .map_err(|_| workspace_error())?;
    let case_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| workspace_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| workspace_error())?;
    for value in case_ids {
        let case_id = CaseId::parse(value).map_err(|_| workspace_error())?;
        work_products
            .list_case_locked(operation, &case_id, approved, now_unix)
            .map_err(|_| workspace_error())?;
    }
    Ok(())
}

fn snapshot_database(
    temporary_root: &Path,
    source_path: &Path,
    store_kind: &str,
) -> Result<DatabaseSnapshot, ApprovedMcpError> {
    snapshot_database_inner(temporary_root, source_path, store_kind)
}

fn snapshot_database_for_v031_migration(
    temporary_root: &Path,
    source_path: &Path,
    store_kind: &str,
) -> Result<DatabaseSnapshot, ApprovedMcpError> {
    // Migration checkpoints are recoverable evidence.  They may not create an
    // untracked UUID file in the application root even transiently: a process
    // crash there would leave an unknown sensitive marker that the frozen
    // recovery state machine cannot authenticate.  Copy committed pages from
    // a pinned read-only transaction directly into an in-memory database.
    // `immutable=1` is deliberately forbidden for a WAL-backed source because
    // it can ignore committed frames. A cold database whose WAL, SHM, and
    // rollback journal are all absent is instead parsed directly from its
    // pinned main-file bytes, so opening SQLite cannot create new sidecars.
    validate_directory_identity(temporary_root)?;
    let before = capture_v031_sqlite_physical_state(source_path)?;
    let header_mode = before
        .database_bytes
        .get(18..20)
        .ok_or_else(workspace_error)?;
    let has_no_sidecars = before.evidence.wal.is_none()
        && before.evidence.shm.is_none()
        && before.evidence.journal.is_none();
    if has_no_sidecars {
        if header_mode != [1_u8, 1_u8] && header_mode != [2_u8, 2_u8] {
            return Err(workspace_error());
        }
        let bytes = normalize_self_contained_sqlite_image(before.database_bytes.clone())?;
        let active_paths = active_paths_from_serialized_database(&bytes, store_kind)?;
        validate_serialized_database_image(&bytes, store_kind, &active_paths)?;
        let after = capture_v031_sqlite_physical_state(source_path)?;
        if before.evidence != after.evidence {
            return Err(workspace_error());
        }
        return Ok(DatabaseSnapshot {
            bytes,
            active_paths,
        });
    }

    validate_v031_wal_physical_state(&before)?;
    let mut source = open_v031_wal_database_read_only_no_create(source_path)?;
    source
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| workspace_error())?;
    if !source
        .is_readonly(rusqlite::MAIN_DB)
        .map_err(|_| workspace_error())?
    {
        return Err(workspace_error());
    }
    let opened = capture_v031_sqlite_physical_state(source_path)?;
    if before.evidence != opened.evidence {
        return Err(workspace_error());
    }
    let transaction = source
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(|_| workspace_error())?;
    let result = (|| {
        validate_sqlite(&transaction)?;
        let mut destination = Connection::open_in_memory().map_err(|_| workspace_error())?;
        {
            let backup =
                Backup::new(&transaction, &mut destination).map_err(|_| workspace_error())?;
            backup
                .run_to_completion(64, Duration::from_millis(1), None)
                .map_err(|_| workspace_error())?;
        }
        validate_sqlite(&destination)?;
        let active_paths = active_paths_from_connection(&destination, store_kind)?;
        let bytes = serialize_backup_as_self_contained_sqlite(&destination)?;
        validate_serialized_database_image(&bytes, store_kind, &active_paths)?;
        Ok(DatabaseSnapshot {
            bytes,
            active_paths,
        })
    })();
    let transaction_close = transaction.commit().map_err(|_| workspace_error());
    let result = match (result, transaction_close) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    };
    drop(source);
    let snapshot = result?;
    let after = capture_v031_sqlite_physical_state(source_path)?;
    if before.evidence != after.evidence {
        return Err(workspace_error());
    }
    Ok(snapshot)
}

/// Current SQLite stores can legitimately retain a zero-length WAL and a stale
/// SHM after the last writer checkpointed all committed frames.  That state is
/// not an admissible migration checkpoint source (whose physical contract is
/// intentionally narrower), but it is a valid read-only current-store state.
/// A non-empty WAL still goes through the stricter crash-WAL implementation.
fn snapshot_database_for_current_observation(
    source_path: &Path,
    store_kind: &str,
) -> Result<DatabaseSnapshot, ApprovedMcpError> {
    let before = capture_current_sqlite_physical_state(source_path)?;
    if before.evidence.journal.is_some() {
        return Err(workspace_error());
    }
    if before
        .evidence
        .wal
        .as_ref()
        .is_some_and(|wal| wal.length > 0)
    {
        return snapshot_database_for_v031_migration(
            source_path.parent().ok_or_else(workspace_error)?,
            source_path,
            store_kind,
        );
    }
    if before.database_bytes.get(18..20) != Some([1_u8, 1_u8].as_slice())
        && before.database_bytes.get(18..20) != Some([2_u8, 2_u8].as_slice())
    {
        return Err(workspace_error());
    }
    let bytes = normalize_self_contained_sqlite_image(before.database_bytes.clone())?;
    let active_paths = active_paths_from_serialized_database(&bytes, store_kind)?;
    validate_serialized_database_image(&bytes, store_kind, &active_paths)?;
    let after = capture_current_sqlite_physical_state(source_path)?;
    if before.evidence != after.evidence {
        return Err(workspace_error());
    }
    Ok(DatabaseSnapshot {
        bytes,
        active_paths,
    })
}

fn capture_current_sqlite_physical_state(
    source_path: &Path,
) -> Result<V031PinnedSqlitePhysicalState, ApprovedMcpError> {
    let root = source_path.parent().ok_or_else(workspace_error)?;
    validate_directory_identity(root)?;
    let (database_guard, database, database_bytes) =
        capture_v031_sqlite_component(root, source_path, true, false)?
            .ok_or_else(workspace_error)?;
    let mut guards = vec![database_guard];
    let mut capture_optional = |suffix: &str| {
        let path = v031_sqlite_sidecar_path(source_path, suffix);
        capture_v031_sqlite_component(root, &path, false, true).map(|captured| {
            captured.map(|(guard, evidence, _)| {
                guards.push(guard);
                evidence
            })
        })
    };
    let wal = capture_optional("-wal")?;
    let shm = capture_optional("-shm")?;
    let journal = capture_optional("-journal")?;
    Ok(V031PinnedSqlitePhysicalState {
        evidence: V031SqlitePhysicalEvidence {
            database,
            wal,
            shm,
            journal,
        },
        database_bytes,
        _guards: guards,
    })
}

fn open_v031_wal_database_read_only_no_create(path: &Path) -> Result<Connection, ApprovedMcpError> {
    let canonical = fs::canonicalize(path).map_err(|_| workspace_error())?;
    let raw = canonical
        .to_str()
        .ok_or_else(workspace_error)?
        .strip_prefix(r"\\?\")
        .unwrap_or_else(|| canonical.to_str().expect("Unicode path checked"))
        .replace('\\', "/");
    let bytes = raw.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'/'
        || bytes[3..].contains(&b':')
    {
        return Err(workspace_error());
    }
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Connection::open_with_flags(
        format!("file:///{encoded}?mode=ro"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| workspace_error())
}

fn capture_v031_sqlite_physical_state(
    source_path: &Path,
) -> Result<V031PinnedSqlitePhysicalState, ApprovedMcpError> {
    let root = source_path.parent().ok_or_else(workspace_error)?;
    validate_directory_identity(root)?;
    let (database_guard, database, database_bytes) =
        capture_v031_sqlite_component(root, source_path, true, false)?
            .ok_or_else(workspace_error)?;
    let mut guards = vec![database_guard];
    let (wal, shm, journal) = (
        v031_sqlite_sidecar_path(source_path, "-wal"),
        v031_sqlite_sidecar_path(source_path, "-shm"),
        v031_sqlite_sidecar_path(source_path, "-journal"),
    );
    let wal = capture_v031_sqlite_component(root, &wal, false, false)?;
    let shm = capture_v031_sqlite_component(root, &shm, false, false)?;
    let journal = capture_v031_sqlite_component(root, &journal, false, false)?;
    let wal_evidence = wal.map(|(guard, evidence, _)| {
        guards.push(guard);
        evidence
    });
    let shm_evidence = shm.map(|(guard, evidence, _)| {
        guards.push(guard);
        evidence
    });
    let journal_evidence = journal.map(|(guard, evidence, _)| {
        guards.push(guard);
        evidence
    });
    Ok(V031PinnedSqlitePhysicalState {
        evidence: V031SqlitePhysicalEvidence {
            database,
            wal: wal_evidence,
            shm: shm_evidence,
            journal: journal_evidence,
        },
        database_bytes,
        _guards: guards,
    })
}

fn capture_v031_sqlite_component(
    root: &Path,
    path: &Path,
    required: bool,
    allow_empty: bool,
) -> Result<Option<(File, V031SqlitePhysicalFileEvidence, Vec<u8>)>, ApprovedMcpError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(workspace_error()),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| workspace_error())?;
    let canonical_root = fs::canonicalize(root).map_err(|_| workspace_error())?;
    let canonical_path = fs::canonicalize(path).map_err(|_| workspace_error())?;
    if !path.is_absolute()
        || !path.starts_with(root)
        || !canonical_path.starts_with(&canonical_root)
        || !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(workspace_error());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| workspace_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    let pinned_metadata = file.metadata().map_err(|_| workspace_error())?;
    let length = pinned_metadata.len();
    let modified = pinned_metadata.modified().map_err(|_| workspace_error())?;
    let maximum = u64::try_from(MAX_ARCHIVE_DATABASE_BYTES).map_err(|_| workspace_error())?;
    if (!allow_empty && length == 0) || length > maximum {
        return Err(workspace_error());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| workspace_error())?);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| (&mut file).take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|_| workspace_error())?;
    if u64::try_from(bytes.len()).map_err(|_| workspace_error())? != length
        || !ordinary_single_link_handle(&file)
    {
        return Err(workspace_error());
    }
    let mut prefix = [0_u8; 32];
    let prefix_length = bytes.len().min(prefix.len());
    prefix[..prefix_length].copy_from_slice(&bytes[..prefix_length]);
    let identity_sha256 = v031_live_file_identity_sha256(&file)?;
    Ok(Some((
        file,
        V031SqlitePhysicalFileEvidence {
            identity_sha256,
            length,
            modified,
            sha256: sha256_hex(&bytes),
            prefix,
        },
        bytes,
    )))
}

fn v031_live_file_identity_sha256(file: &File) -> Result<String, ApprovedMcpError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if handle.is_null()
        || unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
        || information.nNumberOfLinks != 1
    {
        return Err(workspace_error());
    }
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(b"lawyer-assistance-v031-approved-sqlite-file-identity-v1\0");
    identity.extend_from_slice(&information.dwVolumeSerialNumber.to_be_bytes());
    identity.extend_from_slice(&information.nFileIndexHigh.to_be_bytes());
    identity.extend_from_slice(&information.nFileIndexLow.to_be_bytes());
    Ok(sha256_hex(&identity))
}

fn v031_sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn validate_v031_wal_physical_state(
    state: &V031PinnedSqlitePhysicalState,
) -> Result<(), ApprovedMcpError> {
    if state.database_bytes.get(18..20) != Some([2_u8, 2_u8].as_slice())
        || state.evidence.journal.is_some()
    {
        return Err(workspace_error());
    }
    let (wal, shm) = state
        .evidence
        .wal
        .as_ref()
        .zip(state.evidence.shm.as_ref())
        .ok_or_else(workspace_error)?;
    let page_size = sqlite_page_size(&state.evidence.database.prefix)?;
    let wal_page_size = u32::from_be_bytes(
        wal.prefix[8..12]
            .try_into()
            .map_err(|_| workspace_error())?,
    );
    let frame_size = 24_u64
        .checked_add(u64::from(wal_page_size))
        .ok_or_else(workspace_error)?;
    let wal_magic = u32::from_be_bytes(wal.prefix[..4].try_into().map_err(|_| workspace_error())?);
    let wal_version =
        u32::from_be_bytes(wal.prefix[4..8].try_into().map_err(|_| workspace_error())?);
    if wal.length < 32 + frame_size
        || !matches!(wal_magic, 0x377f_0682 | 0x377f_0683)
        || wal_version != 3_007_000
        || u64::from(wal_page_size) != page_size
        || (wal.length - 32) % frame_size != 0
        || shm.length < 32 * 1024
        || shm.length % (32 * 1024) != 0
    {
        return Err(workspace_error());
    }
    Ok(())
}

fn sqlite_page_size(prefix: &[u8; 32]) -> Result<u64, ApprovedMcpError> {
    if !prefix.starts_with(b"SQLite format 3\0") {
        return Err(workspace_error());
    }
    let encoded = u16::from_be_bytes(prefix[16..18].try_into().map_err(|_| workspace_error())?);
    let page_size = if encoded == 1 {
        65_536
    } else {
        u64::from(encoded)
    };
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(workspace_error());
    }
    Ok(page_size)
}

fn snapshot_database_inner(
    temporary_root: &Path,
    source_path: &Path,
    store_kind: &str,
) -> Result<DatabaseSnapshot, ApprovedMcpError> {
    validate_directory_identity(temporary_root)?;
    validate_regular_file(
        source_path,
        source_path.parent().ok_or_else(workspace_error)?,
    )?;
    let source = open_read_only_database(source_path)?;
    validate_sqlite(&source)?;
    let temporary_name = format!(
        ".application-backup-{}-{}.sqlite",
        store_kind.replace('_', "-"),
        Uuid::new_v4().simple()
    );
    let temporary_path = temporary_root.join(temporary_name);
    if temporary_path.exists() {
        return Err(workspace_error());
    }
    let result = (|| {
        let mut destination = Connection::open(&temporary_path).map_err(|_| workspace_error())?;
        {
            let backup = Backup::new(&source, &mut destination).map_err(|_| workspace_error())?;
            backup
                .run_to_completion(64, Duration::from_millis(1), None)
                .map_err(|_| workspace_error())?;
        }
        destination
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .map_err(|_| workspace_error())?;
        validate_sqlite(&destination)?;
        destination.close().map_err(|_| workspace_error())?;
        let active_paths = active_paths_from_database(&temporary_path, store_kind)?;
        let bytes = read_pinned_file(temporary_root, &temporary_path, MAX_ARCHIVE_DATABASE_BYTES)?;
        Ok(DatabaseSnapshot {
            bytes,
            active_paths,
        })
    })();
    let cleanup = remove_validated_file(&temporary_path, temporary_root);
    match (result, cleanup) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

fn serialize_backup_as_self_contained_sqlite(
    destination: &Connection,
) -> Result<Vec<u8>, ApprovedMcpError> {
    let image = destination
        .serialize(rusqlite::MAIN_DB)
        .map_err(|_| workspace_error())?
        .to_vec();
    normalize_self_contained_sqlite_image(image)
}

fn normalize_self_contained_sqlite_image(mut image: Vec<u8>) -> Result<Vec<u8>, ApprovedMcpError> {
    if image.len() < 100 || !image.starts_with(b"SQLite format 3\0") {
        return Err(workspace_error());
    }
    match (image[18], image[19]) {
        (1, 1) => {}
        (2, 2) => {
            image[18] = 1;
            image[19] = 1;
        }
        _ => return Err(workspace_error()),
    }
    Ok(image)
}

fn active_paths_from_serialized_database(
    image: &[u8],
    store_kind: &str,
) -> Result<BTreeSet<String>, ApprovedMcpError> {
    let mut connection = Connection::open_in_memory().map_err(|_| workspace_error())?;
    connection
        .deserialize_read_exact(rusqlite::MAIN_DB, Cursor::new(image), image.len(), true)
        .map_err(|_| workspace_error())?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| workspace_error())?;
    validate_sqlite(&connection)?;
    active_paths_from_connection(&connection, store_kind)
}

fn validate_serialized_database_image(
    image: &[u8],
    store_kind: &str,
    expected_active_paths: &BTreeSet<String>,
) -> Result<(), ApprovedMcpError> {
    if image.len() < 100
        || image.len() > MAX_ARCHIVE_DATABASE_BYTES
        || !image.starts_with(b"SQLite format 3\0")
        || image.get(18..20) != Some([1_u8, 1_u8].as_slice())
    {
        return Err(workspace_error());
    }
    let mut readback = Connection::open_in_memory().map_err(|_| workspace_error())?;
    readback
        .deserialize_read_exact(rusqlite::MAIN_DB, Cursor::new(image), image.len(), true)
        .map_err(|_| workspace_error())?;
    readback
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| workspace_error())?;
    validate_sqlite(&readback)?;
    if &active_paths_from_connection(&readback, store_kind)? != expected_active_paths {
        return Err(workspace_error());
    }
    Ok(())
}

fn approved_active_paths(connection: &Connection) -> Result<BTreeSet<String>, ApprovedMcpError> {
    let mut statement = connection
        .prepare(
            "SELECT case_id,publication_id FROM publication_journal
                 WHERE state='committed' AND revoked_at_unix IS NULL
                 ORDER BY case_id,publication_id",
        )
        .map_err(|_| workspace_error())?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| workspace_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| workspace_error())?;
    let mut paths = BTreeSet::new();
    for (case, publication) in rows {
        let case = CaseId::parse(case).map_err(|_| workspace_error())?;
        let publication = PublicationId::parse(publication).map_err(|_| workspace_error())?;
        for file in [
            "content.bin",
            "manifest.json",
            "egress-guard.json",
            "commit.json",
        ] {
            paths.insert(format!(
                "cases/{}/approved/{}/{}",
                case.as_str(),
                publication.as_str(),
                file
            ));
        }
    }
    Ok(paths)
}

fn work_product_active_paths(
    connection: &Connection,
) -> Result<BTreeSet<String>, ApprovedMcpError> {
    let mut statement = connection
        .prepare(
            "SELECT case_id,work_product_id,version FROM work_product_versions
                 WHERE state='committed' AND revoked_at_unix IS NULL
                 ORDER BY case_id,work_product_id,version",
        )
        .map_err(|_| workspace_error())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| workspace_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| workspace_error())?;
    let mut paths = BTreeSet::new();
    for (case, work_product, version) in rows {
        let case = CaseId::parse(case).map_err(|_| workspace_error())?;
        let work_product = WorkProductId::parse(work_product).map_err(|_| workspace_error())?;
        let version = u64::try_from(version)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(workspace_error)?;
        for file in ["content.envelope.json", "manifest.json", "commit.json"] {
            paths.insert(format!(
                "work-products/{}/{}/v{:020}/{}",
                case.as_str(),
                work_product.as_str(),
                version,
                file
            ));
        }
    }
    Ok(paths)
}

fn active_paths_from_database(
    database: &Path,
    store_kind: &str,
) -> Result<BTreeSet<String>, ApprovedMcpError> {
    let connection = open_read_only_database(database)?;
    validate_sqlite(&connection)?;
    active_paths_from_connection(&connection, store_kind)
}

fn active_paths_from_connection(
    connection: &Connection,
    store_kind: &str,
) -> Result<BTreeSet<String>, ApprovedMcpError> {
    if store_kind == APPROVED_STORE_KIND {
        approved_active_paths(connection)
    } else if store_kind == WORK_PRODUCTS_STORE_KIND {
        work_product_active_paths(connection)
    } else {
        Err(workspace_error())
    }
}

fn direct_child_basenames(root: &Path) -> Result<BTreeSet<String>, ApprovedMcpError> {
    validate_directory_identity(root)?;
    fs::read_dir(root)
        .map_err(|_| workspace_error())?
        .map(|entry| {
            entry
                .map_err(|_| workspace_error())?
                .file_name()
                .into_string()
                .map_err(|_| workspace_error())
        })
        .collect()
}

fn reject_application_backup_temporaries(
    basenames: &BTreeSet<String>,
) -> Result<(), ApprovedMcpError> {
    if basenames
        .iter()
        .any(|basename| basename.starts_with(".application-backup-"))
    {
        return Err(workspace_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_archive(
    root: &Path,
    store_kind: &str,
    database_name: &str,
    database: Vec<u8>,
    relative_paths: BTreeSet<String>,
    workspace_id: &WorkspaceInstanceId,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, String), ApprovedMcpError> {
    validate_directory_identity(root)?;
    if relative_paths.len().saturating_add(1) > MAX_ARCHIVE_FILES {
        return Err(workspace_error());
    }
    let mut values = BTreeMap::new();
    values.insert(database_name.to_owned(), database);
    for relative in relative_paths {
        validate_archive_path(store_kind, &relative, false)?;
        let path = archive_path(root, &relative)?;
        let value = read_pinned_file(root, &path, MAX_ARCHIVE_ENTRY_BYTES)?;
        values.insert(relative, value);
    }
    let mut files = Vec::with_capacity(values.len());
    let mut payloads = Vec::with_capacity(values.len());
    let mut total = 0_u64;
    for (relative_path, value) in values {
        let bytes = u64::try_from(value.len()).map_err(|_| workspace_error())?;
        total = total.checked_add(bytes).ok_or_else(workspace_error)?;
        files.push(StoreArchiveFileV1 {
            relative_path: relative_path.clone(),
            plaintext_bytes: bytes,
            plaintext_sha256: sha256_hex(&value),
        });
        payloads.push(StoreArchivePayloadV1 {
            relative_path,
            plaintext_base64: BASE64_STANDARD.encode(value),
        });
    }
    let manifest = StoreArchiveManifestV1 {
        schema_version: ARCHIVE_MANIFEST_SCHEMA_VERSION.to_owned(),
        store_kind: store_kind.to_owned(),
        workspace_instance_id: workspace_id.clone(),
        file_count: u64::try_from(files.len()).map_err(|_| workspace_error())?,
        plaintext_bytes: total,
        files,
    };
    let manifest_sha256 = sha256_hex(&canonical_json_v1(&manifest).map_err(|_| workspace_error())?);
    let envelope = StoreArchiveEnvelopeV1 {
        schema_version: ARCHIVE_SCHEMA_VERSION.to_owned(),
        manifest,
        manifest_sha256: manifest_sha256.clone(),
        files: payloads,
    };
    let bytes = canonical_json_v1(&envelope).map_err(|_| workspace_error())?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(workspace_error());
    }
    Ok((bytes, manifest_sha256))
}

fn validate_exact_archive_root(
    root: &Path,
    store_kind: &str,
    database_name: &str,
    workspace_id: &WorkspaceInstanceId,
    expected_manifest_sha256: &str,
) -> Result<(), ApprovedMcpError> {
    if !is_hash(expected_manifest_sha256) {
        return Err(workspace_error());
    }
    validate_directory_identity(root)?;
    let active_paths = active_paths_from_database(&root.join(database_name), store_kind)?;
    let mut expected_files = active_paths;
    expected_files.insert(database_name.to_owned());
    let (actual_files, actual_directories) = collect_tree_layout(root)?;
    if actual_files != expected_files {
        return Err(workspace_error());
    }
    let mut expected_directories = BTreeSet::from([String::new()]);
    for relative in &expected_files {
        let mut current = PathBuf::new();
        let path = Path::new(relative);
        if let Some(parent) = path.parent() {
            for component in parent.components() {
                let Component::Normal(value) = component else {
                    return Err(workspace_error());
                };
                current.push(value);
                expected_directories.insert(path_to_archive_string(&current)?);
            }
        }
    }
    if actual_directories != expected_directories {
        return Err(workspace_error());
    }
    let mut files = Vec::with_capacity(expected_files.len());
    let mut total = 0_u64;
    for relative in expected_files {
        let database = relative == database_name;
        validate_archive_path(store_kind, &relative, database)?;
        let maximum = if database {
            MAX_ARCHIVE_DATABASE_BYTES
        } else {
            MAX_ARCHIVE_ENTRY_BYTES
        };
        let value = read_pinned_file(root, &archive_path(root, &relative)?, maximum)?;
        let bytes = u64::try_from(value.len()).map_err(|_| workspace_error())?;
        total = total.checked_add(bytes).ok_or_else(workspace_error)?;
        files.push(StoreArchiveFileV1 {
            relative_path: relative,
            plaintext_bytes: bytes,
            plaintext_sha256: sha256_hex(&value),
        });
    }
    let manifest = StoreArchiveManifestV1 {
        schema_version: ARCHIVE_MANIFEST_SCHEMA_VERSION.to_owned(),
        store_kind: store_kind.to_owned(),
        workspace_instance_id: workspace_id.clone(),
        file_count: u64::try_from(files.len()).map_err(|_| workspace_error())?,
        plaintext_bytes: total,
        files,
    };
    let actual_manifest_sha256 =
        sha256_hex(&canonical_json_v1(&manifest).map_err(|_| workspace_error())?);
    if actual_manifest_sha256 != expected_manifest_sha256 {
        return Err(workspace_error());
    }
    Ok(())
}

fn collect_tree_layout(
    root: &Path,
) -> Result<(BTreeSet<String>, BTreeSet<String>), ApprovedMcpError> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::from([String::new()]);
    collect_tree_layout_at(root, root, &mut files, &mut directories)?;
    Ok((files, directories))
}

fn collect_tree_layout_at(
    root: &Path,
    current: &Path,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), ApprovedMcpError> {
    validate_directory_identity(current)?;
    for entry in fs::read_dir(current).map_err(|_| workspace_error())? {
        let entry = entry.map_err(|_| workspace_error())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| workspace_error())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(workspace_error());
        }
        let relative = path.strip_prefix(root).map_err(|_| workspace_error())?;
        let relative = path_to_archive_string(relative)?;
        if metadata.is_dir() {
            if !directories.insert(relative) {
                return Err(workspace_error());
            }
            collect_tree_layout_at(root, &path, files, directories)?;
        } else if metadata.is_file() {
            validate_regular_file(&path, root)?;
            if !files.insert(relative) {
                return Err(workspace_error());
            }
        } else {
            return Err(workspace_error());
        }
    }
    Ok(())
}

fn path_to_archive_string(path: &Path) -> Result<String, ApprovedMcpError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(workspace_error());
        };
        let value = value.to_str().ok_or_else(workspace_error)?;
        if !value.is_ascii() || value.is_empty() {
            return Err(workspace_error());
        }
        parts.push(value);
    }
    Ok(parts.join("/"))
}

#[allow(clippy::too_many_arguments)]
fn unpack_archive(
    bytes: &[u8],
    expected_manifest_sha256: &str,
    expected_store_kind: &str,
    database_name: &str,
    workspace_id: &WorkspaceInstanceId,
    destination: &Path,
    maximum_bytes: usize,
) -> Result<(), ApprovedMcpError> {
    if bytes.is_empty()
        || bytes.len() > maximum_bytes
        || !is_hash(expected_manifest_sha256)
        || destination.exists()
    {
        return Err(workspace_error());
    }
    let envelope: StoreArchiveEnvelopeV1 =
        strict_json_v1_from_slice(bytes).map_err(|_| workspace_error())?;
    if canonical_json_v1(&envelope).map_err(|_| workspace_error())? != bytes
        || envelope.schema_version != ARCHIVE_SCHEMA_VERSION
        || envelope.manifest.schema_version != ARCHIVE_MANIFEST_SCHEMA_VERSION
        || envelope.manifest.store_kind != expected_store_kind
        || envelope.manifest.workspace_instance_id != *workspace_id
        || envelope.manifest.file_count
            != u64::try_from(envelope.manifest.files.len()).map_err(|_| workspace_error())?
        || envelope.manifest.files.is_empty()
        || envelope.manifest.files.len() > MAX_ARCHIVE_FILES
        || envelope.files.len() != envelope.manifest.files.len()
    {
        return Err(workspace_error());
    }
    let actual_manifest_sha256 =
        sha256_hex(&canonical_json_v1(&envelope.manifest).map_err(|_| workspace_error())?);
    if envelope.manifest_sha256 != actual_manifest_sha256
        || actual_manifest_sha256 != expected_manifest_sha256
    {
        return Err(workspace_error());
    }
    let parent = destination.parent().ok_or_else(workspace_error)?;
    validate_directory_identity(parent)?;
    fs::create_dir(destination).map_err(|_| workspace_error())?;
    validate_directory_identity(destination)?;
    let result = (|| {
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        let mut database_seen = false;
        for (metadata, payload) in envelope.manifest.files.iter().zip(&envelope.files) {
            if metadata.relative_path != payload.relative_path
                || !seen.insert(metadata.relative_path.clone())
                || !is_hash(&metadata.plaintext_sha256)
                || payload.plaintext_base64.len() > maximum_bytes.saturating_mul(2)
            {
                return Err(workspace_error());
            }
            let is_database = metadata.relative_path == database_name;
            validate_archive_path(expected_store_kind, &metadata.relative_path, is_database)?;
            if is_database {
                if database_seen || metadata.plaintext_bytes > MAX_ARCHIVE_DATABASE_BYTES as u64 {
                    return Err(workspace_error());
                }
                database_seen = true;
            } else if metadata.plaintext_bytes > MAX_ARCHIVE_ENTRY_BYTES as u64 {
                return Err(workspace_error());
            }
            total = total
                .checked_add(metadata.plaintext_bytes)
                .ok_or_else(workspace_error)?;
            if total > maximum_bytes as u64 {
                return Err(workspace_error());
            }
            let value = BASE64_STANDARD
                .decode(payload.plaintext_base64.as_bytes())
                .map_err(|_| workspace_error())?;
            if value.len() as u64 != metadata.plaintext_bytes
                || sha256_hex(&value) != metadata.plaintext_sha256
            {
                return Err(workspace_error());
            }
            let target = archive_path(destination, &metadata.relative_path)?;
            create_archive_parent_directories(destination, &target)?;
            write_new_pinned_file(destination, &target, &value)?;
        }
        if !database_seen || total != envelope.manifest.plaintext_bytes {
            return Err(workspace_error());
        }
        let database = destination.join(database_name);
        let active_paths = active_paths_from_database(&database, expected_store_kind)?;
        let archived_paths = seen
            .into_iter()
            .filter(|path| path != database_name)
            .collect::<BTreeSet<_>>();
        if archived_paths != active_paths {
            return Err(workspace_error());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_validated_restore_tree(destination);
    }
    result
}

fn validate_archive_path(
    store_kind: &str,
    relative: &str,
    database: bool,
) -> Result<(), ApprovedMcpError> {
    if relative.is_empty()
        || relative.len() > MAX_ARCHIVE_PATH_BYTES
        || !relative.is_ascii()
        || relative.contains('\\')
        || relative.starts_with('/')
        || relative.ends_with('/')
    {
        return Err(workspace_error());
    }
    if database {
        let expected = if store_kind == APPROVED_STORE_KIND {
            APPROVED_DATABASE_FILE
        } else if store_kind == WORK_PRODUCTS_STORE_KIND {
            WORK_PRODUCTS_DATABASE_FILE
        } else {
            return Err(workspace_error());
        };
        return (relative == expected)
            .then_some(())
            .ok_or_else(workspace_error);
    }
    let parts = relative.split('/').collect::<Vec<_>>();
    if store_kind == APPROVED_STORE_KIND {
        if parts.len() != 5
            || parts[0] != "cases"
            || parts[2] != "approved"
            || CaseId::parse(parts[1].to_owned()).is_err()
            || PublicationId::parse(parts[3].to_owned()).is_err()
            || !matches!(
                parts[4],
                "content.bin" | "manifest.json" | "egress-guard.json" | "commit.json"
            )
        {
            return Err(workspace_error());
        }
    } else if store_kind == WORK_PRODUCTS_STORE_KIND {
        if parts.len() != 5
            || parts[0] != "work-products"
            || CaseId::parse(parts[1].to_owned()).is_err()
            || WorkProductId::parse(parts[2].to_owned()).is_err()
            || !valid_version_directory(parts[3])
            || !matches!(
                parts[4],
                "content.envelope.json" | "manifest.json" | "commit.json"
            )
        {
            return Err(workspace_error());
        }
    } else {
        return Err(workspace_error());
    }
    Ok(())
}

fn valid_version_directory(value: &str) -> bool {
    value.len() == 21
        && value.starts_with('v')
        && value[1..].bytes().all(|byte| byte.is_ascii_digit())
        && value[1..].parse::<u64>().is_ok_and(|version| version > 0)
}

fn archive_path(root: &Path, relative: &str) -> Result<PathBuf, ApprovedMcpError> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(value) => path.push(value),
            _ => return Err(workspace_error()),
        }
    }
    if path.parent().is_none() || !path.starts_with(root) {
        return Err(workspace_error());
    }
    Ok(path)
}

fn create_archive_parent_directories(root: &Path, target: &Path) -> Result<(), ApprovedMcpError> {
    let parent = target.parent().ok_or_else(workspace_error)?;
    let relative = parent.strip_prefix(root).map_err(|_| workspace_error())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(workspace_error());
        };
        current.push(value);
        if !current.exists() {
            fs::create_dir(&current).map_err(|_| workspace_error())?;
        }
        validate_directory_identity(&current)?;
    }
    Ok(())
}

fn validate_staged_tree(
    root: &Path,
    store_kind: &str,
    database_name: &str,
) -> Result<(), ApprovedMcpError> {
    validate_directory_identity(root)?;
    validate_regular_file(&root.join(database_name), root)?;
    let expected = active_paths_from_database(&root.join(database_name), store_kind)?;
    for relative in expected {
        validate_archive_path(store_kind, &relative, false)?;
        validate_regular_file(&archive_path(root, &relative)?, root)?;
    }
    Ok(())
}

fn checkpoint_restore_database(path: &Path) -> Result<(), ApprovedMcpError> {
    let connection = Connection::open(path).map_err(|_| workspace_error())?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
        .map_err(|_| workspace_error())?;
    validate_sqlite(&connection)
}

fn open_read_only_database(path: &Path) -> Result<Connection, ApprovedMcpError> {
    privacy::workspace::open_existing_sqlite_read_only(path).map_err(|_| workspace_error())
}

fn validate_sqlite(connection: &Connection) -> Result<(), ApprovedMcpError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| workspace_error())?;
    let foreign_keys: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| workspace_error())?;
    if integrity != "ok" || foreign_keys != 0 {
        return Err(workspace_error());
    }
    Ok(())
}

fn read_pinned_file(root: &Path, path: &Path, maximum: usize) -> Result<Vec<u8>, ApprovedMcpError> {
    validate_regular_file(path, root)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| workspace_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    let length = usize::try_from(file.metadata().map_err(|_| workspace_error())?.len())
        .map_err(|_| workspace_error())?;
    if length == 0 || length > maximum {
        return Err(workspace_error());
    }
    let mut bytes = Vec::with_capacity(length);
    (&mut file)
        .take(u64::try_from(maximum).map_err(|_| workspace_error())? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| workspace_error())?;
    if bytes.len() != length || !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    Ok(bytes)
}

fn write_new_pinned_file(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), ApprovedMcpError> {
    if bytes.is_empty() || !path.starts_with(root) {
        return Err(workspace_error());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| workspace_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| workspace_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    Ok(())
}

fn validate_directory_identity(path: &Path) -> Result<(), ApprovedMcpError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| workspace_error())?;
    if !path.is_absolute()
        || !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(workspace_error());
    }
    Ok(())
}

fn validate_regular_file(path: &Path, root: &Path) -> Result<(), ApprovedMcpError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| workspace_error())?;
    let canonical_root = fs::canonicalize(root).map_err(|_| workspace_error())?;
    let canonical_path = fs::canonicalize(path).map_err(|_| workspace_error())?;
    if !path.is_absolute()
        || !path.starts_with(root)
        || !canonical_path.starts_with(&canonical_root)
        || !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(workspace_error());
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| workspace_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(workspace_error());
    }
    Ok(())
}

fn ordinary_single_link_handle(file: &File) -> bool {
    if !privacy_manager::opened_file_resolves_to_ordinary_local(file) {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || privacy_manager::has_cloud_recall_attributes(&metadata)
    {
        return false;
    }
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    !handle.is_null()
        && unsafe { GetFileInformationByHandle(handle, &mut information) } != 0
        && information.nNumberOfLinks == 1
}

fn remove_validated_file(path: &Path, root: &Path) -> Result<(), ApprovedMcpError> {
    validate_regular_file(path, root)?;
    fs::remove_file(path).map_err(|_| workspace_error())
}

pub(crate) fn remove_validated_restore_tree(path: &Path) -> Result<(), ApprovedMcpError> {
    if !path.exists() {
        return Ok(());
    }
    validate_directory_identity(path)?;
    validate_tree(path, path)?;
    fs::remove_dir_all(path).map_err(|_| workspace_error())?;
    if path.exists() {
        return Err(workspace_error());
    }
    Ok(())
}

fn validate_tree(root: &Path, current: &Path) -> Result<(), ApprovedMcpError> {
    let metadata = fs::symlink_metadata(current).map_err(|_| workspace_error())?;
    if !current.starts_with(root) || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(workspace_error());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(current).map_err(|_| workspace_error())? {
            validate_tree(root, &entry.map_err(|_| workspace_error())?.path())?;
        }
        Ok(())
    } else if metadata.is_file() {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(current)
            .map_err(|_| workspace_error())?;
        ordinary_single_link_handle(&file)
            .then_some(())
            .ok_or_else(workspace_error)
    } else {
        Err(workspace_error())
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approved_mcp::ApprovedMcpKeyProvider;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestTreeEntry {
        relative: String,
        kind: &'static str,
        bytes: u64,
        modified_unix_nanos: u128,
        sha256: Option<String>,
    }

    fn capture_test_tree(root: &Path) -> Vec<TestTreeEntry> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<TestTreeEntry>) {
            let mut entries = fs::read_dir(current)
                .expect("test tree enumerates")
                .collect::<Result<Vec<_>, _>>()
                .expect("test tree entries read");
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("test tree metadata");
                let relative = path
                    .strip_prefix(root)
                    .expect("test tree remains beneath root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let modified_unix_nanos = metadata
                    .modified()
                    .expect("test tree mtime")
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("test tree mtime is after epoch")
                    .as_nanos();
                if metadata.is_dir() {
                    output.push(TestTreeEntry {
                        relative,
                        kind: "directory",
                        bytes: 0,
                        modified_unix_nanos,
                        sha256: None,
                    });
                    visit(root, &path, output);
                } else {
                    let bytes = fs::read(&path).expect("test tree file reads");
                    output.push(TestTreeEntry {
                        relative,
                        kind: "file",
                        bytes: bytes.len() as u64,
                        modified_unix_nanos,
                        sha256: Some(sha256_hex(&bytes)),
                    });
                }
            }
        }

        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    fn assert_current_observation_is_read_only(
        root: &Path,
        workspace: &ApprovedMcpWorkspace,
        expected_lifecycle: CurrentApprovedComponentsLifecycle,
        expected_workspace_instance_id: &WorkspaceInstanceId,
    ) {
        let before = capture_test_tree(root);
        let observation = workspace
            .observe_current_components_read_only()
            .expect("current components observe");
        let CurrentApprovedComponentsObservation::Exact(proof) = observation else {
            panic!("current identity must be present");
        };
        assert_eq!(proof.lifecycle(), expected_lifecycle);
        assert_eq!(
            proof.workspace_instance_id(),
            expected_workspace_instance_id
        );
        assert_eq!(capture_test_tree(root), before);
    }

    #[test]
    fn current_approved_components_observer_authenticates_lazy_lifecycle_without_writes() {
        let root = tempfile::tempdir().expect("current components fixture");
        let harness = ApplicationBackupTestHarness::new(root.path().to_path_buf());
        assert_eq!(
            harness
                .workspace
                .observe_current_components_read_only()
                .expect("genuine absence observes"),
            CurrentApprovedComponentsObservation::Absent
        );

        let workspace_instance_id = harness
            .workspace
            .workspace_instance_id()
            .expect("workspace identity creates outside observation");
        assert_current_observation_is_read_only(
            root.path(),
            &harness.workspace,
            CurrentApprovedComponentsLifecycle::IdentityOnly,
            &workspace_instance_id,
        );

        let case_id = format!("case_{}", "a".repeat(32));
        let generation = harness
            .publish_generation(&case_id, 'a')
            .expect("approved generation publishes outside observation");
        assert_current_observation_is_read_only(
            root.path(),
            &harness.workspace,
            CurrentApprovedComponentsLifecycle::ApprovedOnly,
            &workspace_instance_id,
        );

        harness
            .create_work_product(
                &generation,
                b"[PERSON_001] authenticated current work product",
            )
            .expect("work product publishes outside observation");
        assert_current_observation_is_read_only(
            root.path(),
            &harness.workspace,
            CurrentApprovedComponentsLifecycle::ApprovedAndWorkProducts,
            &workspace_instance_id,
        );
    }

    #[test]
    fn current_approved_components_observer_rejects_partial_lifecycle_states() {
        let root = tempfile::tempdir().expect("current partial credential fixture");
        let harness = ApplicationBackupTestHarness::new(root.path().to_path_buf());
        harness
            .workspace
            .workspace_instance_id()
            .expect("workspace identity creates");
        let mut orphan_work_key = harness
            .keys
            .load_or_create(KeyRole::WorkProductManifest)
            .expect("orphan work credential creates outside observation");
        zeroize(&mut orphan_work_key);
        assert!(harness
            .workspace
            .observe_current_components_read_only()
            .is_err());

        let root = tempfile::tempdir().expect("current reverse lifecycle fixture");
        let moved = tempfile::tempdir().expect("approved root holding fixture");
        let harness = ApplicationBackupTestHarness::new(root.path().to_path_buf());
        let case_id = format!("case_{}", "b".repeat(32));
        let generation = harness
            .publish_generation(&case_id, 'b')
            .expect("approved generation publishes");
        harness
            .create_work_product(&generation, b"[PERSON_001] reverse lifecycle")
            .expect("work product publishes");
        fs::rename(
            &harness.workspace.inner.approved_root,
            moved.path().join("approved-generations"),
        )
        .expect("approved root moves outside observed app root");
        let before = capture_test_tree(root.path());
        assert!(harness
            .workspace
            .observe_current_components_read_only()
            .is_err());
        assert_eq!(capture_test_tree(root.path()), before);

        let root = tempfile::tempdir().expect("current unknown child fixture");
        let harness = ApplicationBackupTestHarness::new(root.path().to_path_buf());
        harness
            .workspace
            .workspace_instance_id()
            .expect("workspace identity creates");
        let unknown = root.path().join("privacy/approved-mcp/unknown-state");
        fs::create_dir_all(&unknown).expect("unknown state creates outside observation");
        let before = capture_test_tree(root.path());
        assert!(harness
            .workspace
            .observe_current_components_read_only()
            .is_err());
        assert_eq!(capture_test_tree(root.path()), before);
    }

    #[cfg(windows)]
    const V031_APPROVED_WAL_FIXTURE_CHILD_PATH: &str =
        "LAWYER_ASSISTANCE_V031_APPROVED_WAL_FIXTURE_CHILD_PATH";

    #[cfg(windows)]
    fn create_v031_persistent_wal_source(source_path: &Path) -> Connection {
        let source = Connection::open(source_path).expect("source opens");
        source
            .execute_batch(
                "CREATE TABLE publication_journal(
                   case_id TEXT NOT NULL,
                   publication_id TEXT NOT NULL,
                   state TEXT NOT NULL,
                   revoked_at_unix INTEGER
                 );",
            )
            .expect("source schema creates");
        let mode: String = source
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("WAL mode enables");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        source
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpoint disables");
        source
            .execute(
                "INSERT INTO publication_journal(case_id,publication_id,state,revoked_at_unix)
                 VALUES(?1,?2,'pending',NULL)",
                [
                    format!("case_{}", "a".repeat(32)),
                    format!("pub_{}", "b".repeat(32)),
                ],
            )
            .expect("committed WAL row inserts");
        source
    }

    #[cfg(windows)]
    fn exit_after_creating_v031_approved_crash_wal_if_requested() {
        let Some(source_path) = std::env::var_os(V031_APPROVED_WAL_FIXTURE_CHILD_PATH) else {
            return;
        };
        let source_path = PathBuf::from(source_path);
        let _source = create_v031_persistent_wal_source(&source_path);
        assert!(v031_sqlite_sidecar_path(&source_path, "-wal").is_file());
        assert!(v031_sqlite_sidecar_path(&source_path, "-shm").is_file());
        // Deliberately bypass Connection::drop. A graceful final close may
        // checkpoint or remove the WAL and would not model crash recovery.
        std::process::exit(0);
    }

    #[cfg(windows)]
    fn create_v031_approved_crash_wal_fixture(source_path: &Path) {
        let status = std::process::Command::new(
            std::env::current_exe().expect("current test executable resolves"),
        )
        .arg("--exact")
        .arg(
            "approved_mcp::application_backup::tests::v031_read_only_snapshot_is_memory_only_and_normalizes_persistent_wal",
        )
        .env(V031_APPROVED_WAL_FIXTURE_CHILD_PATH, source_path)
        .status()
        .expect("WAL fixture child launches");
        assert!(status.success(), "WAL fixture child must succeed");
    }

    #[cfg(windows)]
    #[test]
    fn v031_read_only_snapshot_is_memory_only_and_normalizes_persistent_wal() {
        exit_after_creating_v031_approved_crash_wal_if_requested();
        let directory = tempfile::tempdir().expect("read-only snapshot fixture");
        let root = directory.path();
        let source_path = root.join(APPROVED_DATABASE_FILE);
        create_v031_approved_crash_wal_fixture(&source_path);

        let basenames_before = direct_child_basenames(root).expect("root enumerates before");
        reject_application_backup_temporaries(&basenames_before)
            .expect("no migration temporary exists before");
        let physical_before = capture_v031_sqlite_physical_state(&source_path)
            .expect("physical evidence captures before");
        let physical_evidence_before = physical_before.evidence.clone();
        let cold_main =
            normalize_self_contained_sqlite_image(physical_before.database_bytes.clone())
                .expect("cold main normalizes");
        drop(physical_before);
        let mut cold_readback = Connection::open_in_memory().expect("cold readback opens");
        cold_readback
            .deserialize_read_exact(
                rusqlite::MAIN_DB,
                Cursor::new(&cold_main),
                cold_main.len(),
                true,
            )
            .expect("cold main reads without WAL");
        let cold_rows: i64 = cold_readback
            .query_row("SELECT COUNT(*) FROM publication_journal", [], |row| {
                row.get(0)
            })
            .expect("cold main row count reads");
        assert_eq!(cold_rows, 0, "the committed row must exist only in WAL");
        drop(cold_readback);

        let snapshot =
            snapshot_database_for_v031_migration(root, &source_path, APPROVED_STORE_KIND)
                .expect("ordinary read-only in-memory snapshot succeeds");
        let basenames_after = direct_child_basenames(root).expect("root enumerates after");
        assert_eq!(basenames_after, basenames_before);
        reject_application_backup_temporaries(&basenames_after)
            .expect("no migration temporary exists after");
        let physical_evidence_after = capture_v031_sqlite_physical_state(&source_path)
            .expect("physical evidence captures after")
            .evidence;
        assert_eq!(physical_evidence_after, physical_evidence_before);
        assert_eq!(snapshot.bytes.get(18..20), Some([1_u8, 1_u8].as_slice()));
        assert!(snapshot.active_paths.is_empty());

        let mut readback = Connection::open_in_memory().expect("readback opens");
        readback
            .deserialize_read_exact(
                rusqlite::MAIN_DB,
                Cursor::new(&snapshot.bytes),
                snapshot.bytes.len(),
                true,
            )
            .expect("detached image reads without sidecars");
        let rows: i64 = readback
            .query_row("SELECT COUNT(*) FROM publication_journal", [], |row| {
                row.get(0)
            })
            .expect("committed WAL row reads");
        assert_eq!(rows, 1);
    }

    #[cfg(windows)]
    #[test]
    fn v031_read_only_snapshot_fails_closed_when_live_writer_changes_shm() {
        let directory = tempfile::tempdir().expect("live-writer snapshot fixture");
        let root = directory.path();
        let source_path = root.join(APPROVED_DATABASE_FILE);
        let _source = create_v031_persistent_wal_source(&source_path);
        let basenames_before = direct_child_basenames(root).expect("root enumerates before");
        assert!(
            snapshot_database_for_v031_migration(root, &source_path, APPROVED_STORE_KIND).is_err()
        );
        assert_eq!(
            direct_child_basenames(root).expect("root enumerates after"),
            basenames_before
        );
        reject_application_backup_temporaries(&basenames_before)
            .expect("failed snapshot installs no temporary checkpoint input");
    }

    #[test]
    fn snapshot_excludes_ticket_qualification_log_and_temporary_state() {
        let root = tempfile::tempdir().expect("application backup harness");
        let harness = ApplicationBackupTestHarness::new(root.path().to_path_buf());
        let case_id = format!("case_{}", "a".repeat(32));
        let generation = harness
            .publish_generation(&case_id, 'a')
            .expect("approved generation");
        harness
            .create_work_product(
                &generation,
                b"[PERSON_001] approved encrypted work product SNAPSHOT_CONTENT_CANARY",
            )
            .expect("encrypted work product");

        let decoys = [
            harness
                .workspace
                .inner
                .approved_root
                .join("sensitive-debug.log"),
            harness
                .workspace
                .inner
                .work_product_root
                .join(".uncommitted-sensitive.tmp"),
            harness
                .workspace
                .inner
                .ticket_root
                .join("srv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .join("session.raw"),
            harness
                .workspace
                .inner
                .app_local_data_directory
                .join("privacy/approved-mcp/qualification/qualification.raw"),
        ];
        for path in &decoys {
            fs::create_dir_all(path.parent().expect("decoy parent")).expect("decoy parent");
            fs::write(path, b"RAW_UNAPPROVED_BACKUP_DECOY_CANARY").expect("decoy");
        }

        let snapshot = harness
            .workspace
            .snapshot_for_application_backup()
            .expect("strict snapshot");
        harness
            .workspace
            .verify_application_backup_snapshot_bytes(
                &snapshot.approved_workspace_bundle,
                &snapshot.approved_workspace_manifest_sha256,
                &snapshot.work_products_bundle,
                &snapshot.work_products_manifest_sha256,
            )
            .expect("allocation-only strict readback accepts both exact archives");
        for bytes in [
            snapshot.approved_workspace_bundle.as_slice(),
            snapshot.work_products_bundle.as_slice(),
        ] {
            assert!(!bytes
                .windows(b"RAW_UNAPPROVED_BACKUP_DECOY_CANARY".len())
                .any(|window| window == b"RAW_UNAPPROVED_BACKUP_DECOY_CANARY"));
            assert!(!bytes
                .windows(b"SNAPSHOT_CONTENT_CANARY".len())
                .any(|window| window == b"SNAPSHOT_CONTENT_CANARY"));
        }
        let approved: StoreArchiveEnvelopeV1 =
            strict_json_v1_from_slice(&snapshot.approved_workspace_bundle)
                .expect("approved archive");
        let work_products: StoreArchiveEnvelopeV1 =
            strict_json_v1_from_slice(&snapshot.work_products_bundle).expect("work archive");
        let mut tampered_approved = approved.clone();
        let mut tampered_payload = BASE64_STANDARD
            .decode(tampered_approved.files[0].plaintext_base64.as_bytes())
            .expect("payload decodes");
        tampered_payload[0] ^= 1;
        tampered_approved.files[0].plaintext_base64 = BASE64_STANDARD.encode(tampered_payload);
        let tampered_approved =
            canonical_json_v1(&tampered_approved).expect("tampered archive encodes canonically");
        assert!(harness
            .workspace
            .verify_application_backup_snapshot_bytes(
                &tampered_approved,
                &snapshot.approved_workspace_manifest_sha256,
                &snapshot.work_products_bundle,
                &snapshot.work_products_manifest_sha256,
            )
            .is_err());
        assert_eq!(approved.manifest.files.len(), 5);
        assert_eq!(work_products.manifest.files.len(), 4);
        for file in approved
            .manifest
            .files
            .iter()
            .chain(&work_products.manifest.files)
        {
            assert!(!file.relative_path.contains("ticket"));
            assert!(!file.relative_path.contains("qualification"));
            assert!(!file.relative_path.ends_with(".log"));
            assert!(!file.relative_path.ends_with(".tmp"));
        }
    }

    #[test]
    fn standalone_session_revocation_visits_every_authenticated_session_and_fails_closed() {
        let sessions = vec![
            format!("srv_{}", "1".repeat(32)),
            format!("srv_{}", "2".repeat(32)),
        ];
        let visited = Mutex::new(Vec::new());
        revoke_standalone_sessions_with(
            || Ok(sessions.clone()),
            |server_instance_id| {
                visited
                    .lock()
                    .map_err(|_| workspace_error())?
                    .push(server_instance_id.to_owned());
                Ok(())
            },
        )
        .expect("revoke all sessions");
        assert_eq!(*visited.lock().unwrap(), sessions);

        let attempted = Mutex::new(Vec::new());
        let error = revoke_standalone_sessions_with(
            || Ok(sessions.clone()),
            |server_instance_id| {
                attempted
                    .lock()
                    .unwrap()
                    .push(server_instance_id.to_owned());
                Err(workspace_error())
            },
        )
        .expect_err("a session revocation failure must fail the restore closed");
        assert_eq!(error.code(), "approved_workspace_unavailable");
        assert_eq!(attempted.lock().unwrap().len(), 1);
    }

    #[test]
    fn standalone_session_revocation_replay_keeps_every_prior_session_revoked() {
        let sessions = vec![
            format!("srv_{}", "3".repeat(32)),
            format!("srv_{}", "4".repeat(32)),
        ];
        let revoked = Mutex::new(BTreeSet::new());
        let visits = Mutex::new(Vec::new());

        for _ in 0..2 {
            revoke_standalone_sessions_with(
                || Ok(sessions.clone()),
                |server_instance_id| {
                    visits
                        .lock()
                        .map_err(|_| workspace_error())?
                        .push(server_instance_id.to_owned());
                    revoked
                        .lock()
                        .map_err(|_| workspace_error())?
                        .insert(server_instance_id.to_owned());
                    Ok(())
                },
            )
            .expect("standalone revocation replay remains idempotent");
            assert_eq!(
                *revoked.lock().unwrap(),
                sessions.iter().cloned().collect::<BTreeSet<_>>(),
                "every session revoked by an earlier pass remains revoked"
            );
        }

        assert_eq!(
            *visits.lock().unwrap(),
            sessions
                .iter()
                .chain(sessions.iter())
                .cloned()
                .collect::<Vec<_>>(),
            "a crash replay must revisit every authenticated descriptor"
        );
    }
}
