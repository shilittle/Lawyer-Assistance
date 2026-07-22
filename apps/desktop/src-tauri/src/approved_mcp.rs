mod application_backup;
mod ocr_invalidation;
mod qualification;
mod qualification_canary;
#[cfg(test)]
pub(crate) use application_backup::ApplicationBackupTestHarness;
#[cfg(test)]
mod qualification_tests;
#[cfg(all(test, target_os = "windows", feature = "standalone-mcp-e2e"))]
mod standalone_binary_tests;

pub(crate) use qualification::ApprovedMcpQualificationStatus;

use crate::privacy_workflow::{
    approved_workspace::ApprovedGenerationSource, ApprovedPublicationInvalidator,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use legal_mcp::approved_backend::{
    ApprovedBackendInitError, ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceBackend,
    ApprovedWorkspaceQualificationProvider,
};
use legal_mcp::standalone_approved::{
    ApprovedMcpGrantGroupV1, ProvisionedStandaloneSessionV1, StandaloneSessionMetadataV1,
    StandaloneSessionProvisioningV1,
};
#[cfg(test)]
use privacy::mcp_ticket::MAX_MCP_ACCESS_TICKET_TTL_SECONDS;
use privacy::{
    mcp_ticket::{McpAccessTicketStore, McpTicketSigningKey, McpTransportBindingV1},
    sha256_hex,
    vnext::{
        ApprovalMode, ApprovedMaterialManifestV1, CaseId, MaterialId, PublicationId, ReceiptId,
        Sha256Hex, WorkspaceInstanceId, WorkspaceIsolationLevel, APPROVED_CLASSIFICATION,
        APPROVED_MATERIAL_MANIFEST_VERSION,
    },
    work_products::{WorkProductPublisher, WorkProductService},
    workspace::{
        ApprovedEgressGuardInputV1, ApprovedPublicationHistoryV1, ApprovedWorkspaceService,
        ManifestSigningKey, PublishedMaterialSummaryV1, WorkspaceError, WorkspacePublisher,
        APPROVED_MATERIAL_READ_PURPOSE, APPROVED_WORKSPACE_DESTINATION_SCOPE,
    },
};
use providers::{
    windows_credentials::WindowsCredentialStore, ApiSecret, CredentialStore, ProviderCredentialKey,
    ProviderStoreLock,
};
use serde::Serialize;
#[cfg(test)]
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    ptr,
    sync::{
        atomic::{compiler_fence, AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

const KEY_FORMAT_PREFIX: &str = "approved-mcp-key-v1.";
const KEY_SERVICE_PREFIX: &str = "LawyerAssistanceApprovedMcp";
const KEY_VERSION: u64 = 1;
const APPROVED_ROOT_NAME: &str = "approved-generations";
const WORK_PRODUCT_ROOT_NAME: &str = "work-products";
const TICKET_ROOT_NAME: &str = "ticket-sessions";
#[cfg(test)]
const MAX_PREPARED_ARGUMENT_BYTES: usize = 256 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApprovedMcpError {
    code: &'static str,
    message: &'static str,
}

impl ApprovedMcpError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Debug for ApprovedMcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedMcpError")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for ApprovedMcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ApprovedMcpError {}

#[derive(Clone, Copy)]
enum KeyRole {
    ApprovedManifest,
    WorkProductManifest,
    McpTicket,
    QualificationRevocationEpoch,
}

impl KeyRole {
    const fn provider_id(self) -> &'static str {
        match self {
            Self::ApprovedManifest => "approved-manifest",
            Self::WorkProductManifest => "work-product-manifest",
            Self::McpTicket => "mcp-access-ticket",
            Self::QualificationRevocationEpoch => "mcp-qualification-revocation-epoch",
        }
    }
}

trait ApprovedMcpKeyProvider: Send + Sync {
    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError>;
    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError>;
}

#[derive(Debug)]
struct WindowsApprovedMcpKeyProvider {
    store: WindowsCredentialStore,
}

impl WindowsApprovedMcpKeyProvider {
    fn new() -> Self {
        Self {
            store: WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX),
        }
    }

    fn write_random_locked(
        &self,
        credential_key: &ProviderCredentialKey,
    ) -> Result<[u8; 32], ApprovedMcpError> {
        let mut key = [0_u8; 32];
        fill_random(&mut key)?;
        if key.iter().all(|byte| *byte == 0) {
            zeroize(&mut key);
            return Err(key_store_error());
        }
        let encoded = format!("{KEY_FORMAT_PREFIX}{}", URL_SAFE_NO_PAD.encode(key));
        if self
            .store
            .write_api_key(credential_key, ApiSecret::new(encoded))
            .is_err()
        {
            zeroize(&mut key);
            return Err(key_store_error());
        }
        Ok(key)
    }
}

impl ApprovedMcpKeyProvider for WindowsApprovedMcpKeyProvider {
    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        if let Some(secret) = self
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
        {
            return decode_key(secret.expose_secret());
        }

        self.write_random_locked(&credential_key)
    }

    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        self.write_random_locked(&credential_key)
    }
}

fn decode_key(value: &str) -> Result<[u8; 32], ApprovedMcpError> {
    let encoded = value
        .strip_prefix(KEY_FORMAT_PREFIX)
        .ok_or_else(key_store_error)?;
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| key_store_error())?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        zeroize(&mut decoded);
        return Err(key_store_error());
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    zeroize(&mut decoded);
    Ok(key)
}

fn fill_random(output: &mut [u8]) -> Result<(), ApprovedMcpError> {
    let length = u32::try_from(output.len()).map_err(|_| key_store_error())?;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            output.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(key_store_error());
    }
    Ok(())
}

fn zeroize(bytes: &mut [u8]) {
    bytes.fill(0);
    compiler_fence(Ordering::SeqCst);
}

fn key_store_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_key_unavailable",
        "The local approved MCP signing identity is unavailable.",
    )
}

#[derive(Debug, Clone)]
pub(crate) struct StandaloneMcpHostBinding {
    pub legal_database_path: PathBuf,
    pub user_database_path: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub http_bind: Option<std::net::SocketAddr>,
    pub allowed_origins: Vec<String>,
}

struct ApprovedMcpWorkspaceInner {
    app_local_data_directory: PathBuf,
    approved_root: PathBuf,
    work_product_root: PathBuf,
    ticket_root: PathBuf,
    qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
    qualification_control: Option<Arc<qualification::DesktopApprovedMcpQualificationProvider>>,
    keys: Arc<dyn ApprovedMcpKeyProvider>,
    operation: Mutex<()>,
}

#[derive(Clone)]
pub(crate) struct ApprovedMcpWorkspace {
    inner: Arc<ApprovedMcpWorkspaceInner>,
}

impl fmt::Debug for ApprovedMcpWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedMcpWorkspace")
            .field("approved_root", &"[FIXED_LOCAL_STATE]")
            .field("work_product_root", &"[FIXED_LOCAL_STATE]")
            .field("ticket_root", &"[FIXED_LOCAL_STATE]")
            .finish()
    }
}

impl ApprovedMcpWorkspace {
    pub(crate) fn new(app_local_data_directory: PathBuf) -> Self {
        Self::new_with_binary(app_local_data_directory, installed_mcp_binary_path())
    }

    fn new_with_binary(app_local_data_directory: PathBuf, binary_path: PathBuf) -> Self {
        let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(WindowsApprovedMcpKeyProvider::new());
        let qualification_control =
            Arc::new(qualification::DesktopApprovedMcpQualificationProvider::new(
                app_local_data_directory
                    .join("privacy")
                    .join("approved-mcp")
                    .join("qualification"),
                Arc::clone(&keys),
                binary_path,
            ));
        Self::from_parts(
            app_local_data_directory,
            qualification_control.clone(),
            keys,
            Some(qualification_control),
        )
    }

    #[cfg(all(test, feature = "standalone-mcp-e2e"))]
    pub(crate) fn new_with_mcp_binary_for_test(
        app_local_data_directory: PathBuf,
        binary_path: PathBuf,
    ) -> Self {
        Self::new_with_binary(app_local_data_directory, binary_path)
    }

    fn from_parts(
        app_local_data_directory: PathBuf,
        qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
        keys: Arc<dyn ApprovedMcpKeyProvider>,
        qualification_control: Option<Arc<qualification::DesktopApprovedMcpQualificationProvider>>,
    ) -> Self {
        let root = app_local_data_directory
            .join("privacy")
            .join("approved-mcp");
        Self {
            inner: Arc::new(ApprovedMcpWorkspaceInner {
                app_local_data_directory,
                approved_root: root.join(APPROVED_ROOT_NAME),
                work_product_root: root.join(WORK_PRODUCT_ROOT_NAME),
                ticket_root: root.join(TICKET_ROOT_NAME),
                qualification,
                qualification_control,
                keys,
                operation: Mutex::new(()),
            }),
        }
    }

    pub(crate) fn publish(
        &self,
        case_id: &str,
        source: ApprovedGenerationSource,
    ) -> Result<PublishedApprovedGeneration, ApprovedMcpError> {
        let _operation = self.operation()?;
        let now_unix = now_seconds()?;
        let qualification = self.qualification(now_unix)?;
        let case_id = CaseId::parse(case_id.to_owned()).map_err(|_| invalid_request())?;
        let source_case_id = source.case_id.as_deref().ok_or_else(invalid_source)?;
        if source_case_id != case_id.as_str() {
            return Err(invalid_source());
        }
        validate_generation_source_binding(&source, now_unix)?;
        let material_id =
            MaterialId::parse(source.material_id.clone()).map_err(|_| invalid_source())?;
        let publication_id = PublicationId::parse(format!("pub_{}", Uuid::new_v4().simple()))
            .map_err(|_| invalid_source())?;
        let receipt_id = ReceiptId::parse(source.receipt.claims.receipt_id.clone())
            .map_err(|_| invalid_source())?;
        let expires_at_unix = source
            .receipt
            .claims
            .expires_at_unix
            .filter(|expires| *expires > now_unix)
            .ok_or_else(receipt_expired)?;

        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_instance_id = workspace_instance_id(&manifest_key)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let publisher = WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        let document_version = publisher
            .next_document_version(&case_id, &material_id)
            .map_err(|_| workspace_error())?;

        let (worker_sha256, model_manifest_sha256, model_versions, ocr_output_sha256) =
            trace_provenance(&source)?;
        let detector_versions = BTreeMap::from([(
            "deterministic_redactor".to_owned(),
            source.detector_version.clone(),
        )]);
        let content_sha256 = parse_sha(&source.approved_payload_sha256)?;
        let finding_summary_hash = hash_json(&source.summary)?;
        let hard_gate_evaluation_hash = hash_bytes(
            format!(
                "human-approved-v1\0{}\0{}",
                source.receipt.claims.receipt_id, source.approved_payload_sha256
            )
            .as_bytes(),
        )?;
        let policy_sha256 = hash_bytes(
            format!(
                "{}\0{}\0{}",
                source.policy_id, source.policy_version, source.detector_version
            )
            .as_bytes(),
        )?;
        let dictionary_revision_hash = source.dictionary_revision_hash.clone();
        let mapping_revision_hash = source.mapping_revision_hash.clone();
        let receipt_nonce = sha256_hex(
            format!(
                "{}\0{}\0{}",
                source.receipt.claims.receipt_id,
                source.receipt.mac_hex,
                source.approved_payload_sha256
            )
            .as_bytes(),
        );
        let claims = ApprovedMaterialManifestV1 {
            schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
            classification: APPROVED_CLASSIFICATION.to_owned(),
            workspace_instance_id,
            case_id,
            material_id,
            document_version,
            publication_id,
            content_media_type: source.content_media_type,
            content_sha256,
            content_bytes: u64::try_from(source.approved_payload.len())
                .map_err(|_| invalid_source())?,
            source_sha256: parse_sha(&source.source_sha256)?,
            source_name_sha256: source.source_name_sha256,
            source_revision_hash: source.source_revision_hash,
            extraction_sha256: parse_sha(&source.extraction_sha256)?,
            ocr_output_sha256,
            finding_summary_hash,
            hard_gate_evaluation_hash,
            policy_id: source.policy_id,
            policy_version: u64::from(source.policy_version),
            policy_sha256,
            detector_versions,
            model_versions,
            worker_sha256,
            model_manifest_sha256,
            qualification_report_id: Some(qualification.evidence_id),
            calibration_evidence_version: None,
            dictionary_revision_hash,
            mapping_revision_hash,
            approval_mode: ApprovalMode::Human,
            readiness_score: 100,
            unresolved_p0: 0,
            unresolved_p1: 0,
            unresolved_p2: 0,
            destination_scope: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
            purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
            workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
            issued_at_unix: now_unix,
            expires_at_unix,
            receipt_id,
            receipt_nonce,
            revocation_epoch: 0,
        };
        let case_dictionary_term_refs = source
            .case_dictionary_terms
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let source_term_refs = source
            .source_terms
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let raw_canary_term_refs = source
            .raw_canary_terms
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let published = publisher
            .publish_with_egress_guard_and_lifecycle_binding(
                claims,
                &source.approved_payload,
                ApprovedEgressGuardInputV1 {
                    case_dictionary_terms: &case_dictionary_term_refs,
                    source_terms: &source_term_refs,
                    raw_canary_terms: &raw_canary_term_refs,
                },
                Some(&source.redaction_id),
            )
            .map_err(workspace_operation_error)?;
        Ok(PublishedApprovedGeneration::from(published))
    }

    pub(crate) fn list(
        &self,
        case_id: Option<&str>,
    ) -> Result<Vec<ApprovedGenerationHistory>, ApprovedMcpError> {
        let _operation = self.operation()?;
        let case_id = case_id
            .map(|value| CaseId::parse(value.to_owned()).map_err(|_| invalid_request()))
            .transpose()?;
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        let service = ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?;
        service
            .list_publication_history(case_id.as_ref())
            .map_err(|_| workspace_error())
            .map(|rows| {
                rows.into_iter()
                    .map(ApprovedGenerationHistory::from)
                    .collect()
            })
    }

    pub(crate) fn revoke(
        &self,
        case_id: &str,
        material_id: &str,
        document_version: u64,
        publication_id: &str,
    ) -> Result<(), ApprovedMcpError> {
        if document_version == 0 {
            return Err(invalid_request());
        }
        let _operation = self.operation()?;
        let now_unix = now_seconds()?;
        let case_id = CaseId::parse(case_id.to_owned()).map_err(|_| invalid_request())?;
        let material_id =
            MaterialId::parse(material_id.to_owned()).map_err(|_| invalid_request())?;
        let publication_id =
            PublicationId::parse(publication_id.to_owned()).map_err(|_| invalid_request())?;
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?
            .revoke(
                &case_id,
                &material_id,
                document_version,
                &publication_id,
                now_unix,
            )
            .map_err(|_| workspace_error())
    }

    fn invalidate_case_publications_locked(
        &self,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<u64, ApprovedMcpError> {
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?
            .revoke_case_publications(case_id, now_unix)
            .map_err(workspace_operation_error)
    }

    fn invalidate_material_publications_locked(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        now_unix: u64,
    ) -> Result<u64, ApprovedMcpError> {
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?
            .revoke_material_publications(case_id, material_id, now_unix)
            .map_err(workspace_operation_error)
    }

    fn invalidate_lifecycle_bindings_locked(
        &self,
        lifecycle_binding_ids: &BTreeSet<String>,
        reason_code: &'static str,
        now_unix: u64,
    ) -> Result<u64, ApprovedMcpError> {
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_instance_id = workspace_instance_id(&manifest_key)?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| workspace_error())?;
        let approved = ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| workspace_error())?;
        let revoked = approved
            .prepare_lifecycle_retention_revocation(lifecycle_binding_ids, now_unix, reason_code)
            .map_err(workspace_operation_error)?;

        let work_key = self
            .inner
            .keys
            .load_or_create(KeyRole::WorkProductManifest)?;
        let work_signer =
            ManifestSigningKey::from_bytes(work_key, KEY_VERSION).map_err(|_| workspace_error())?;
        let work_verifier = work_signer.verification_key();
        WorkProductPublisher::initialize(
            &self.inner.work_product_root,
            workspace_instance_id.clone(),
            work_signer,
        )
        .map_err(|_| workspace_error())?;
        let work_products = WorkProductService::open(
            &self.inner.work_product_root,
            workspace_instance_id,
            work_verifier,
        )
        .map_err(|_| workspace_error())?;
        let work_product_count = work_products
            .prepare_retention_revocation_by_sources(
                &approved,
                &revoked.publication_ids,
                now_unix,
                reason_code,
            )
            .map_err(|_| workspace_error())?;

        // Derived work products are removed before their source bundles. Both stores journal the
        // revoke before touching the filesystem, so a crash remains fail-closed and recoverable.
        work_products
            .recover_retention_cleanup(&approved, now_unix)
            .map_err(|_| workspace_error())?;
        approved
            .recover_lifecycle_retention_cleanup(now_unix)
            .map_err(workspace_operation_error)?;
        revoked
            .newly_revoked
            .checked_add(work_product_count)
            .ok_or_else(workspace_error)
    }

    pub(crate) fn provision_standalone_session(
        &self,
        connector_id: String,
        transport: McpTransportBindingV1,
        grant_groups: Vec<ApprovedMcpGrantGroupV1>,
        ttl_seconds: u64,
        host: StandaloneMcpHostBinding,
    ) -> Result<ProvisionedStandaloneSessionV1, ApprovedMcpError> {
        if ttl_seconds == 0 {
            return Err(invalid_request());
        }
        let now_unix = now_seconds()?;
        let qualification = self.qualification(now_unix)?;
        let expires_at_unix = now_unix
            .checked_add(ttl_seconds)
            .filter(|expires| *expires <= qualification.expires_at_unix)
            .ok_or_else(invalid_request)?;
        let session = self.prepare_required_session_at(transport, now_unix)?;
        let result = legal_mcp::standalone_approved::provision_standalone_session(
            StandaloneSessionProvisioningV1 {
                app_local_data_directory: self.inner.app_local_data_directory.clone(),
                approved_root: self.inner.approved_root.clone(),
                work_product_root: self.inner.work_product_root.clone(),
                ticket_root: self
                    .inner
                    .ticket_root
                    .join(session.backend.server_instance_id()),
                legal_database_path: host.legal_database_path,
                user_database_path: host.user_database_path,
                allowed_roots: host.allowed_roots,
                output_root: host.output_root,
                workspace_instance_id: session.backend.workspace_instance_id().clone(),
                server_instance_id: session.backend.server_instance_id().to_owned(),
                session_id: session.backend.session_id().to_owned(),
                connector_id,
                transport,
                grant_groups,
                qualification,
                ticket_revocation_epoch: session
                    .tickets
                    .current_revocation_epoch()
                    .map_err(|_| ticket_error())?,
                issued_at_unix: now_unix,
                expires_at_unix,
                http_bind: host.http_bind,
                allowed_origins: host.allowed_origins,
            },
        )
        .map_err(standalone_error);
        if result.is_err() {
            let _ = session.revoke_all();
        }
        result
    }

    pub(crate) fn list_standalone_sessions(
        &self,
    ) -> Result<Vec<StandaloneSessionMetadataV1>, ApprovedMcpError> {
        legal_mcp::standalone_approved::inspect_standalone_sessions(
            &self.inner.app_local_data_directory,
        )
        .map_err(standalone_error)
    }

    pub(crate) fn revoke_standalone_session(
        &self,
        server_instance_id: &str,
    ) -> Result<(), ApprovedMcpError> {
        legal_mcp::standalone_approved::revoke_standalone_session(
            &self.inner.app_local_data_directory,
            server_instance_id,
        )
        .map_err(standalone_error)
    }

    pub(crate) fn prepare_session(
        &self,
        transport: McpTransportBindingV1,
    ) -> Result<Option<ApprovedMcpServerSession>, ApprovedMcpError> {
        let now_unix = now_seconds()?;
        let qualified = self
            .inner
            .qualification
            .current_qualification(now_unix)
            .is_ok_and(|snapshot| snapshot.approved_workspace_qualified_at(now_unix));
        if !qualified {
            return Ok(None);
        }
        self.prepare_required_session_at(transport, now_unix)
            .map(Some)
    }

    fn prepare_required_session_at(
        &self,
        transport: McpTransportBindingV1,
        now_unix: u64,
    ) -> Result<ApprovedMcpServerSession, ApprovedMcpError> {
        let _operation = self.operation()?;
        self.qualification(now_unix)?;
        let manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let workspace_instance_id = workspace_instance_id(&manifest_key)?;
        let manifest_signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| workspace_error())?;
        let manifest_verifier = manifest_signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, manifest_signer)
            .map_err(|_| workspace_error())?;
        let approved = ApprovedWorkspaceService::open(&self.inner.approved_root, manifest_verifier)
            .map_err(|_| workspace_error())?;

        let work_key = self
            .inner
            .keys
            .load_or_create(KeyRole::WorkProductManifest)?;
        let work_signer =
            ManifestSigningKey::from_bytes(work_key, KEY_VERSION).map_err(|_| workspace_error())?;
        let work_verifier = work_signer.verification_key();
        let work_product_publisher = WorkProductPublisher::initialize(
            &self.inner.work_product_root,
            workspace_instance_id.clone(),
            work_signer,
        )
        .map_err(|_| workspace_error())?;
        let work_products = WorkProductService::open(
            &self.inner.work_product_root,
            workspace_instance_id.clone(),
            work_verifier,
        )
        .map_err(|_| workspace_error())?;
        work_products
            .recover_retention_cleanup(&approved, now_unix)
            .map_err(|_| workspace_error())?;
        approved
            .recover_lifecycle_retention_cleanup(now_unix)
            .map_err(workspace_operation_error)?;

        let server_instance_id = format!("srv_{}", Uuid::new_v4().simple());
        let session_id = match transport {
            McpTransportBindingV1::Stdio => format!("session_stdio_{}", Uuid::new_v4().simple()),
            McpTransportBindingV1::StreamableHttp => {
                format!("session_http_{}", Uuid::new_v4().simple())
            }
        };
        let ticket_key = self.inner.keys.load_or_create(KeyRole::McpTicket)?;
        let ticket_key_id = format!("mcpkey_{}", &sha256_hex(&ticket_key)[..24]);
        let ticket_signer = McpTicketSigningKey::from_bytes(ticket_key, ticket_key_id, KEY_VERSION)
            .map_err(|_| ticket_error())?;
        let ticket_directory = self.inner.ticket_root.join(&server_instance_id);
        let tickets = McpAccessTicketStore::initialize(
            ticket_directory,
            ticket_signer,
            workspace_instance_id,
            server_instance_id,
        )
        .map_err(|_| ticket_error())?;
        let backend = ApprovedWorkspaceBackend::initialize(
            Arc::clone(&self.inner.qualification),
            approved,
            work_product_publisher,
            work_products,
            tickets.clone(),
            transport,
            session_id,
            now_unix,
        )
        .map_err(map_backend_error)?;
        Ok(ApprovedMcpServerSession {
            backend,
            tickets,
            revoked: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            qualification: Arc::clone(&self.inner.qualification),
        })
    }

    fn operation(&self) -> Result<std::sync::MutexGuard<'_, ()>, ApprovedMcpError> {
        self.inner.operation.lock().map_err(|_| workspace_error())
    }

    fn qualification(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedMcpError> {
        let snapshot = self
            .inner
            .qualification
            .current_qualification(now_unix)
            .map_err(|_| qualification_error())?;
        if !snapshot.approved_workspace_qualified_at(now_unix) {
            return Err(qualification_error());
        }
        Ok(snapshot)
    }
}

fn installed_mcp_binary_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_default()
        .join(legal_mcp::release_binary::binary_file_name())
}

impl ApprovedPublicationInvalidator for ApprovedMcpWorkspace {
    fn invalidate_case(
        &self,
        case_id: &CaseId,
        _reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        let _operation = self.operation().map_err(|error| error.code())?;
        self.invalidate_case_publications_locked(
            case_id,
            now_seconds().map_err(|error| error.code())?,
        )
        .map_err(|error| error.code())
    }

    fn invalidate_material(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        _reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        let _operation = self.operation().map_err(|error| error.code())?;
        self.invalidate_material_publications_locked(
            case_id,
            material_id,
            now_seconds().map_err(|error| error.code())?,
        )
        .map_err(|error| error.code())
    }

    fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
        let _operation = self.operation().map_err(|error| error.code())?;
        let now_unix = now_seconds().map_err(|error| error.code())?;
        let manifest_key = self
            .inner
            .keys
            .load_or_create(KeyRole::ApprovedManifest)
            .map_err(|error| error.code())?;
        let signer = ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION)
            .map_err(|_| "approved_workspace_unavailable")?;
        let verifier = signer.verification_key();
        WorkspacePublisher::initialize(&self.inner.approved_root, signer)
            .map_err(|_| "approved_workspace_unavailable")?;
        let service = ApprovedWorkspaceService::open(&self.inner.approved_root, verifier)
            .map_err(|_| "approved_workspace_unavailable")?;
        let cases = service
            .list_publication_history(None)
            .map_err(|error| error.code())?
            .into_iter()
            .filter(|row| row.revoked_at_unix.is_none())
            .map(|row| row.case_id)
            .collect::<std::collections::BTreeSet<_>>();
        cases.into_iter().try_fold(0_u64, |total, case_id| {
            let count = service
                .revoke_case_publications(&case_id, now_unix)
                .map_err(|error| error.code())?;
            total
                .checked_add(count)
                .ok_or("approved_workspace_unavailable")
        })
    }

    fn invalidate_lifecycle_bindings(
        &self,
        lifecycle_binding_ids: &BTreeSet<String>,
        reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        let _operation = self.operation().map_err(|error| error.code())?;
        self.invalidate_lifecycle_bindings_locked(
            lifecycle_binding_ids,
            reason_code,
            now_seconds().map_err(|error| error.code())?,
        )
        .map_err(|error| error.code())
    }
}

#[derive(Clone)]
pub(crate) struct ApprovedMcpServerSession {
    backend: ApprovedWorkspaceBackend,
    tickets: McpAccessTicketStore,
    revoked: Arc<AtomicBool>,
    #[cfg(test)]
    qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
}

impl fmt::Debug for ApprovedMcpServerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedMcpServerSession")
            .field("server_instance_id", &self.backend.server_instance_id())
            .field("transport", &self.backend.transport())
            .field("session_id", &"[BOUND]")
            .field("revoked", &self.revoked.load(Ordering::Acquire))
            .finish()
    }
}

impl ApprovedMcpServerSession {
    pub(crate) fn backend(&self) -> &ApprovedWorkspaceBackend {
        &self.backend
    }

    #[cfg(test)]
    pub(crate) fn prepare_call(
        &self,
        tool_name: &str,
        mut business_arguments: Map<String, Value>,
        ttl_seconds: u64,
    ) -> Result<PreparedApprovedMcpCall, ApprovedMcpError> {
        if self.revoked.load(Ordering::Acquire)
            || ttl_seconds == 0
            || ttl_seconds > MAX_MCP_ACCESS_TICKET_TTL_SECONDS
            || business_arguments.contains_key("access_ticket")
            || serde_json::to_vec(&business_arguments)
                .map_or(true, |bytes| bytes.len() > MAX_PREPARED_ARGUMENT_BYTES)
        {
            return Err(invalid_request());
        }
        let issued_at_unix = now_seconds()?;
        let qualification = self
            .qualification
            .current_qualification(issued_at_unix)
            .map_err(|_| qualification_error())?;
        if !qualification.approved_workspace_qualified_at(issued_at_unix) {
            return Err(qualification_error());
        }
        let expires_at_unix = issued_at_unix
            .checked_add(ttl_seconds)
            .ok_or_else(invalid_request)?;
        let request = self
            .backend
            .ticket_request(
                tool_name,
                &business_arguments,
                issued_at_unix,
                expires_at_unix,
            )
            .map_err(map_backend_error)?;
        let purpose = request.purpose.clone();
        let canonical_request_sha256 = request.canonical_request_sha256.as_str().to_owned();
        let ticket = self.tickets.issue(request).map_err(|_| ticket_error())?;
        business_arguments.insert("access_ticket".to_owned(), Value::String(ticket));
        Ok(PreparedApprovedMcpCall {
            server_instance_id: self.backend.server_instance_id().to_owned(),
            transport: self.backend.transport(),
            session_id: self.backend.session_id().to_owned(),
            tool_name: tool_name.to_owned(),
            purpose,
            canonical_request_sha256,
            issued_at_unix,
            expires_at_unix,
            arguments: Value::Object(business_arguments),
        })
    }

    pub(crate) fn revoke_all(&self) -> Result<(), ApprovedMcpError> {
        if self
            .revoked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.tickets
                .bump_revocation_epoch()
                .map_err(|_| ticket_error())?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(test)]
pub(crate) struct PreparedApprovedMcpCall {
    pub server_instance_id: String,
    pub transport: McpTransportBindingV1,
    pub session_id: String,
    pub tool_name: String,
    pub purpose: String,
    pub canonical_request_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub arguments: Value,
}

#[cfg(test)]
impl fmt::Debug for PreparedApprovedMcpCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedApprovedMcpCall")
            .field("server_instance_id", &self.server_instance_id)
            .field("transport", &self.transport)
            .field("session_id", &"[BOUND]")
            .field("tool_name", &self.tool_name)
            .field("purpose", &self.purpose)
            .field("canonical_request_sha256", &self.canonical_request_sha256)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("arguments", &"[REDACTED_BOUND_ARGUMENTS]")
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublishedApprovedGeneration {
    pub case_id: String,
    pub material_id: String,
    pub document_version: u64,
    pub publication_id: String,
    pub content_sha256: String,
    pub manifest_sha256: String,
}

impl From<PublishedMaterialSummaryV1> for PublishedApprovedGeneration {
    fn from(value: PublishedMaterialSummaryV1) -> Self {
        Self {
            case_id: value.case_id.as_str().to_owned(),
            material_id: value.material_id.as_str().to_owned(),
            document_version: value.document_version,
            publication_id: value.publication_id.as_str().to_owned(),
            content_sha256: value.content_sha256.as_str().to_owned(),
            manifest_sha256: value.manifest_sha256.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovedGenerationHistory {
    pub case_id: String,
    pub material_id: String,
    pub document_version: u64,
    pub publication_id: String,
    pub manifest_sha256: String,
    pub content_sha256: String,
    pub created_at_unix: u64,
    pub committed_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    pub revocation_epoch: u64,
}

impl From<ApprovedPublicationHistoryV1> for ApprovedGenerationHistory {
    fn from(value: ApprovedPublicationHistoryV1) -> Self {
        Self {
            case_id: value.case_id.as_str().to_owned(),
            material_id: value.material_id.as_str().to_owned(),
            document_version: value.document_version,
            publication_id: value.publication_id.as_str().to_owned(),
            manifest_sha256: value.manifest_sha256.as_str().to_owned(),
            content_sha256: value.content_sha256.as_str().to_owned(),
            created_at_unix: value.created_at_unix,
            committed_at_unix: value.committed_at_unix,
            revoked_at_unix: value.revoked_at_unix,
            revocation_epoch: value.revocation_epoch,
        }
    }
}

type TraceProvenance = (
    Option<Sha256Hex>,
    Option<Sha256Hex>,
    BTreeMap<String, String>,
    Option<Sha256Hex>,
);

fn trace_provenance(
    source: &ApprovedGenerationSource,
) -> Result<TraceProvenance, ApprovedMcpError> {
    let mineru = source
        .backend_trace
        .iter()
        .filter(|trace| {
            matches!(
                trace.backend,
                material_processing::ExtractionBackend::MineruLocal
            )
        })
        .collect::<Vec<_>>();
    let mut model_versions = BTreeMap::from([(
        "processing_chain".to_owned(),
        source.processing_version.clone(),
    )]);
    if mineru.is_empty() {
        return Ok((None, None, model_versions, None));
    }
    if mineru.iter().any(|trace| {
        !trace.isolation_verified
            || trace.worker_sha256.is_none()
            || trace.model_manifest_sha256.is_none()
    }) {
        return Err(invalid_source());
    }
    let worker = mineru[0]
        .worker_sha256
        .as_deref()
        .ok_or_else(invalid_source)?;
    let model = mineru[0]
        .model_manifest_sha256
        .as_deref()
        .ok_or_else(invalid_source)?;
    if mineru.iter().any(|trace| {
        trace.worker_sha256.as_deref() != Some(worker)
            || trace.model_manifest_sha256.as_deref() != Some(model)
    }) {
        return Err(invalid_source());
    }
    let worker = parse_sha(worker)?;
    let model = parse_sha(model)?;
    model_versions.insert(
        "mineru_model_manifest".to_owned(),
        model.as_str().to_owned(),
    );
    Ok((
        Some(worker),
        Some(model),
        model_versions,
        Some(parse_sha(&source.extraction_sha256)?),
    ))
}

fn validate_generation_source_binding(
    source: &ApprovedGenerationSource,
    now_unix: u64,
) -> Result<(), ApprovedMcpError> {
    let receipt = &source.receipt.claims;
    if source.content_media_type != "application/vnd.lawyer-assistance.approved+json"
        || source.approved_payload.is_empty()
        || source.source_terms.is_empty()
        || sha256_hex(&source.approved_payload) != source.approved_payload_sha256
        || receipt.source_sha256.len() != 1
        || receipt.source_sha256.first() != Some(&source.source_sha256)
        || receipt.extraction_sha256 != source.extraction_sha256
        || receipt.redacted_content_sha256 != source.redacted_content_sha256
        || receipt.approved_payload_sha256 != source.approved_payload_sha256
        || receipt.policy_id != source.policy_id
        || receipt.policy_version != source.policy_version
        || receipt.detector_version != source.detector_version
        || receipt.destination.kind != privacy::DestinationKind::ExternalMcpHost
        || receipt.destination.identifier != APPROVED_WORKSPACE_DESTINATION_SCOPE
        || receipt.purpose != APPROVED_MATERIAL_READ_PURPOSE
        || receipt.review_state != privacy::ReviewState::Approved
        || receipt.unresolved_high_risk_count != 0
        || receipt.issued_at_unix > now_unix
        || receipt
            .expires_at_unix
            .is_none_or(|expires| expires <= now_unix)
    {
        return Err(invalid_source());
    }
    Ok(())
}

fn workspace_instance_id(key: &[u8; 32]) -> Result<WorkspaceInstanceId, ApprovedMcpError> {
    WorkspaceInstanceId::parse(format!("ws_{}", &sha256_hex(key)[..32]))
        .map_err(|_| workspace_error())
}

fn parse_sha(value: &str) -> Result<Sha256Hex, ApprovedMcpError> {
    Sha256Hex::parse(value.to_owned()).map_err(|_| invalid_source())
}

fn hash_json<T: Serialize>(value: &T) -> Result<Sha256Hex, ApprovedMcpError> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid_source())?;
    hash_bytes(&bytes)
}

fn hash_bytes(bytes: &[u8]) -> Result<Sha256Hex, ApprovedMcpError> {
    Sha256Hex::parse(sha256_hex(bytes)).map_err(|_| invalid_source())
}

fn now_seconds() -> Result<u64, ApprovedMcpError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ApprovedMcpError::new(
                "approved_mcp_clock_unavailable",
                "The system clock is unavailable for approved MCP work.",
            )
        })
}

fn map_backend_error(_: ApprovedBackendInitError) -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_binding_invalid",
        "The approved MCP call binding is invalid.",
    )
}

fn invalid_request() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_request_invalid",
        "The approved MCP request is invalid.",
    )
}

fn invalid_source() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_generation_invalid",
        "The locally approved generation is invalid.",
    )
}

fn receipt_expired() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_generation_receipt_expired",
        "The human approval receipt is expired or has no expiry.",
    )
}

fn workspace_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_workspace_unavailable",
        "The local approved workspace is unavailable.",
    )
}

fn workspace_operation_error(error: WorkspaceError) -> ApprovedMcpError {
    ApprovedMcpError::new(
        error.code(),
        "The approved workspace rejected the operation at a local privacy boundary.",
    )
}

fn ticket_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_ticket_unavailable",
        "The one-time approved MCP ticket could not be issued or revoked.",
    )
}

fn qualification_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_not_qualified",
        "The approved MCP profile is not currently qualified.",
    )
}

fn standalone_error(
    error: legal_mcp::standalone_approved::StandaloneApprovedError,
) -> ApprovedMcpError {
    ApprovedMcpError::new(
        error.code(),
        "The standalone approved MCP session is unavailable or invalid.",
    )
}
