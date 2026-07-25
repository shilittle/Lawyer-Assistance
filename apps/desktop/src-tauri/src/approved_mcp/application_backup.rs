use super::{
    now_seconds, workspace_error, workspace_instance_id, ApprovedMcpError, ApprovedMcpWorkspace,
    KeyRole, KEY_VERSION,
};
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
use std::sync::{Arc, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf},
    time::Duration,
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
    ticket: Mutex<[u8; 32]>,
    qualification_epoch: Mutex<[u8; 32]>,
}

#[cfg(test)]
impl ApplicationBackupTestKeys {
    fn new() -> Self {
        Self {
            ticket: Mutex::new([0x33; 32]),
            qualification_epoch: Mutex::new([0x44; 32]),
        }
    }

    fn epochs(&self) -> Result<(u8, u8), ApprovedMcpError> {
        Ok((
            self.ticket.lock().map_err(|_| workspace_error())?[0],
            self.qualification_epoch
                .lock()
                .map_err(|_| workspace_error())?[0],
        ))
    }
}

#[cfg(test)]
impl super::ApprovedMcpKeyProvider for ApplicationBackupTestKeys {
    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        match role {
            KeyRole::ApprovedManifest => Ok([0x11; 32]),
            KeyRole::WorkProductManifest => Ok([0x22; 32]),
            KeyRole::McpTicket => self
                .ticket
                .lock()
                .map(|value| *value)
                .map_err(|_| workspace_error()),
            KeyRole::QualificationRevocationEpoch => self
                .qualification_epoch
                .lock()
                .map(|value| *value)
                .map_err(|_| workspace_error()),
        }
    }

    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        let slot = match role {
            KeyRole::McpTicket => &self.ticket,
            KeyRole::QualificationRevocationEpoch => &self.qualification_epoch,
            _ => return Err(workspace_error()),
        };
        let mut value = slot.lock().map_err(|_| workspace_error())?;
        value[0] = value[0].wrapping_add(1);
        Ok(*value)
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

#[cfg(test)]
pub(crate) struct ApplicationBackupTestHarness {
    pub(crate) workspace: ApprovedMcpWorkspace,
    keys: Arc<ApplicationBackupTestKeys>,
}

#[cfg(test)]
impl ApplicationBackupTestHarness {
    pub(crate) fn new(app_local_data_directory: PathBuf) -> Self {
        let keys = Arc::new(ApplicationBackupTestKeys::new());
        let key_provider: Arc<dyn super::ApprovedMcpKeyProvider> = keys.clone();
        let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> =
            Arc::new(ApplicationBackupAlwaysQualified);
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
            Some(qualification_control),
        );
        Self { workspace, keys }
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

impl ApprovedMcpWorkspace {
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
        let workspace_id = self.workspace_instance_id_locked()?;
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
    if store_kind == APPROVED_STORE_KIND {
        approved_active_paths(&connection)
    } else if store_kind == WORK_PRODUCTS_STORE_KIND {
        work_product_active_paths(&connection)
    } else {
        Err(workspace_error())
    }
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
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| workspace_error())
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
}
