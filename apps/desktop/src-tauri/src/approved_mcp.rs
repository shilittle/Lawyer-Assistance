mod application_backup;
mod ocr_invalidation;
mod qualification;
mod qualification_canary;
#[cfg(test)]
pub(crate) use application_backup::ApplicationBackupTestHarness;
pub(crate) use application_backup::{
    verify_v031_recovery_safety_archive_pair_allocation_only, CurrentApprovedComponentsLifecycle,
    CurrentApprovedComponentsObservation, CurrentApprovedComponentsProof,
};
#[cfg(test)]
mod qualification_tests;
#[cfg(all(test, target_os = "windows", feature = "standalone-mcp-e2e"))]
mod standalone_binary_tests;

pub(crate) use qualification::ApprovedMcpQualificationStatus;

use crate::commands::original_migration_backup::OriginalRollbackVerifiedGate;
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
        canonical_json_v1, ApprovalMode, ApprovedMaterialManifestV1, CaseId, MaterialId,
        PublicationId, ReceiptId, Sha256Hex, WorkspaceInstanceId, WorkspaceIsolationLevel,
        APPROVED_CLASSIFICATION, APPROVED_MATERIAL_MANIFEST_VERSION,
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
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    ptr,
    sync::{
        atomic::{compiler_fence, AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
    Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
};

const KEY_FORMAT_PREFIX: &str = "approved-mcp-key-v1.";
const KEY_SERVICE_PREFIX: &str = "LawyerAssistanceApprovedMcp";
const KEY_VERSION: u64 = 1;
const APPROVED_ROOT_NAME: &str = "approved-generations";
const WORK_PRODUCT_ROOT_NAME: &str = "work-products";
const TICKET_ROOT_NAME: &str = "ticket-sessions";
const V031_TARGET_COMPONENTS_EVIDENCE_SCHEMA: &str =
    "lawyer-assistance-v031-approved-mcp-target-components-v1";
const V031_RECOVERY_CREDENTIAL_ARCHIVE_SCHEMA: &str =
    "lawyer-assistance-v031-recovery-credential-archive-v1";
const V031_RECOVERY_CREDENTIAL_ARCHIVE_FORMAT_VERSION: u64 = 1;
const MAX_V031_RECOVERY_CREDENTIAL_ARCHIVE_PLAINTEXT_BYTES: usize = 8 * 1024;
pub(crate) const V031_APPROVED_WORKSPACE_SCHEMA_SHA256: &str =
    "cbd44ec67a2a0bc709fa26e71137103ed76082a7f6c87ee54d1fb2657a90127b";
pub(crate) const V031_WORK_PRODUCTS_SCHEMA_SHA256: &str =
    "27903c10e473943f7c2aa4b23cac92001c68bab095047c8dd7cf58660b85231b";
const MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const STARTUP_IDENTITY_PRIMARY_HISTORY_PATHS: [&str; 5] = [
    "user.sqlite",
    "privacy/privacy-workflow.sqlite",
    "case-vault-v2",
    "privacy/approved-mcp/approved-generations",
    "privacy/approved-mcp/work-products",
];
const STARTUP_IDENTITY_RECOVERY_HISTORY_PATHS: [&str; 24] = [
    "application-restore-pending.dpapi",
    "user.sqlite-wal",
    "user.sqlite-shm",
    "user.sqlite-journal",
    "user.sqlite.application-restore-incoming",
    "user.sqlite.application-restore-rollback",
    "user.sqlite.restore-incoming",
    "user.sqlite.restore-pending.json",
    "user.sqlite.restore-rollback",
    "privacy/privacy-workflow.sqlite.application-restore-incoming",
    "privacy/privacy-workflow.sqlite.application-restore-rollback",
    "case-vault-v2.application-restore-incoming",
    "case-vault-v2.application-restore-rollback",
    "privacy/approved-mcp/approved-generations.application-restore-incoming",
    "privacy/approved-mcp/approved-generations.application-restore-rollback",
    "privacy/approved-mcp/work-products.application-restore-incoming",
    "privacy/approved-mcp/work-products.application-restore-rollback",
    "migration-backups",
    "privacy/privacy-workflow.sqlite-wal",
    "privacy/privacy-workflow.sqlite-shm",
    "privacy/privacy-workflow.sqlite-journal",
    "privacy/privacy-workflow.sqlite.restore-incoming",
    "privacy/privacy-workflow.sqlite.restore-pending.dpapi",
    "privacy/privacy-workflow.sqlite.restore-rollback",
];
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

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ApprovedMcpTargetComponentsGate {
    workspace_instance_id: WorkspaceInstanceId,
    rollback_gate_binding_sha256: String,
    credential_manifest_sha256: String,
    approved_workspace_schema_sha256: String,
    work_products_schema_sha256: String,
    approved_workspace_manifest_sha256: String,
    work_products_manifest_sha256: String,
    evidence_sha256: String,
    credential_count: u64,
    approved_business_rows: u64,
    work_product_business_rows: u64,
}

/// Complete non-secret Approved portion of the historical receipt-2 gate as
/// persisted inside a DPAPI-authenticated migration-checkpoint identity.
/// The record is never accepted on its own: reconstruction re-reads all four
/// existing credentials, derives the workspace identity again, and recomputes
/// the exact Approved target evidence before the aggregate receipt-2 evidence
/// is authenticated by the target-components boundary.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ApprovedMcpHistoricalTargetRecord {
    pub(crate) workspace_instance_id: WorkspaceInstanceId,
    pub(crate) credential_manifest_sha256: String,
    pub(crate) approved_workspace_schema_sha256: String,
    pub(crate) work_products_schema_sha256: String,
    pub(crate) approved_workspace_manifest_sha256: String,
    pub(crate) work_products_manifest_sha256: String,
    pub(crate) evidence_sha256: String,
    pub(crate) credential_count: u64,
    pub(crate) approved_business_rows: u64,
    pub(crate) work_product_business_rows: u64,
}

impl fmt::Debug for V031ApprovedMcpTargetComponentsGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ApprovedMcpTargetComponentsGate")
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field(
                "rollback_gate_binding_sha256",
                &self.rollback_gate_binding_sha256,
            )
            .field(
                "credential_manifest_sha256",
                &self.credential_manifest_sha256,
            )
            .field(
                "approved_workspace_schema_sha256",
                &self.approved_workspace_schema_sha256,
            )
            .field(
                "work_products_schema_sha256",
                &self.work_products_schema_sha256,
            )
            .field(
                "approved_workspace_manifest_sha256",
                &self.approved_workspace_manifest_sha256,
            )
            .field(
                "work_products_manifest_sha256",
                &self.work_products_manifest_sha256,
            )
            .field("evidence_sha256", &self.evidence_sha256)
            .field("credential_count", &self.credential_count)
            .field("approved_business_rows", &self.approved_business_rows)
            .field(
                "work_product_business_rows",
                &self.work_product_business_rows,
            )
            .finish()
    }
}

impl V031ApprovedMcpTargetComponentsGate {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub(crate) fn rollback_gate_binding_sha256(&self) -> &str {
        &self.rollback_gate_binding_sha256
    }

    pub(crate) fn credential_manifest_sha256(&self) -> &str {
        &self.credential_manifest_sha256
    }

    pub(crate) fn approved_workspace_schema_sha256(&self) -> &str {
        &self.approved_workspace_schema_sha256
    }

    pub(crate) fn work_products_schema_sha256(&self) -> &str {
        &self.work_products_schema_sha256
    }

    pub(crate) fn approved_workspace_manifest_sha256(&self) -> &str {
        &self.approved_workspace_manifest_sha256
    }

    pub(crate) fn work_products_manifest_sha256(&self) -> &str {
        &self.work_products_manifest_sha256
    }

    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) const fn credential_count(&self) -> u64 {
        self.credential_count
    }

    pub(crate) const fn approved_business_rows(&self) -> u64 {
        self.approved_business_rows
    }

    pub(crate) const fn work_product_business_rows(&self) -> u64 {
        self.work_product_business_rows
    }

    #[cfg(test)]
    pub(crate) fn for_v031_target_components_orchestrator_test(
        workspace_instance_id: WorkspaceInstanceId,
        rollback_gate_binding_sha256: String,
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
            credential_manifest_sha256: digest("credential-manifest"),
            approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256.to_owned(),
            work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256.to_owned(),
            approved_workspace_manifest_sha256: digest("approved-workspace-manifest"),
            work_products_manifest_sha256: digest("work-products-manifest"),
            evidence_sha256: digest("approved-target-evidence"),
            credential_count: 4,
            approved_business_rows: 0,
            work_product_business_rows: 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031RollbackGateBinding {
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
    original_identity_sha256: String,
    original_bundle_sha256: String,
    original_rollback_receipt_sha256: String,
}

impl V031RollbackGateBinding {
    fn from_verified_gate(gate: &OriginalRollbackVerifiedGate) -> Self {
        Self {
            lineage_id: gate.lineage_id().to_owned(),
            envelope_binding_id: gate.envelope_binding_id().to_owned(),
            source_profile_proof_sha256: gate.source_profile_proof_sha256().to_owned(),
            original_identity_sha256: gate.original_identity_sha256().to_owned(),
            original_bundle_sha256: gate.original_bundle_sha256().to_owned(),
            original_rollback_receipt_sha256: gate.original_rollback_receipt_sha256().to_owned(),
        }
    }

    fn validate(&self) -> Result<(), ApprovedMcpError> {
        if !is_lower_sha256(&self.lineage_id)
            || !is_workspace_id(&self.envelope_binding_id)
            || !is_lower_sha256(&self.source_profile_proof_sha256)
            || !is_lower_sha256(&self.original_identity_sha256)
            || !is_lower_sha256(&self.original_bundle_sha256)
            || !is_lower_sha256(&self.original_rollback_receipt_sha256)
        {
            return Err(v031_target_components_error());
        }
        Ok(())
    }

    fn sha256(&self) -> Result<String, ApprovedMcpError> {
        canonical_sha256(self)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031CredentialEvidence {
    role: &'static str,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031TargetComponentsEvidence<'a> {
    schema_version: &'static str,
    rollback_gate_binding_sha256: &'a str,
    workspace_instance_id: &'a str,
    credential_manifest_sha256: &'a str,
    approved_workspace_schema_sha256: &'a str,
    work_products_schema_sha256: &'a str,
    approved_workspace_manifest_sha256: &'a str,
    work_products_manifest_sha256: &'a str,
    credential_count: u64,
    approved_business_rows: u64,
    work_product_business_rows: u64,
    ticket_session_count: u64,
    qualification_record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct V031ComponentManifest {
    component: &'static str,
    schema_sha256: String,
    database_sha256: String,
    layout_sha256: String,
    schema_objects: u64,
    metadata_rows: u64,
    business_rows: u64,
    directory_count: u64,
    file_count: u64,
}

struct V031PreparedCredentialKeys {
    approved_manifest: [u8; 32],
    work_product_manifest: [u8; 32],
    mcp_ticket: [u8; 32],
    qualification_revocation_epoch: [u8; 32],
}

impl V031PreparedCredentialKeys {
    fn zeroed() -> Self {
        Self {
            approved_manifest: [0_u8; 32],
            work_product_manifest: [0_u8; 32],
            mcp_ticket: [0_u8; 32],
            qualification_revocation_epoch: [0_u8; 32],
        }
    }
}

impl Drop for V031PreparedCredentialKeys {
    fn drop(&mut self) {
        zeroize(&mut self.approved_manifest);
        zeroize(&mut self.work_product_manifest);
        zeroize(&mut self.mcp_ticket);
        zeroize(&mut self.qualification_revocation_epoch);
    }
}

/// A no-op in production and an exact crash boundary in tests. The hook is
/// deliberately inside the real writer: tests cannot substitute credential,
/// SQLite, or filesystem operations.
trait V031ApprovedTargetWriterFailureInjector {
    fn after_credential_prefix(&self, _prefix_len: usize) -> Result<(), ApprovedMcpError> {
        Ok(())
    }

    fn after_approved_workspace_closed(&self) -> Result<(), ApprovedMcpError> {
        Ok(())
    }

    fn after_work_products_closed_before_sync(&self) -> Result<(), ApprovedMcpError> {
        Ok(())
    }
}

struct NoV031ApprovedTargetWriterFailure;

impl V031ApprovedTargetWriterFailureInjector for NoV031ApprovedTargetWriterFailure {}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031ApprovedTargetWriterFailurePoint {
    AfterCredentialPrefix1,
    AfterCredentialPrefix2,
    AfterCredentialPrefix3,
    AfterCredentialPrefix4,
    AfterApprovedWorkspaceClosed,
    AfterWorkProductsClosedBeforeSync,
}

#[cfg(test)]
impl V031ApprovedTargetWriterFailureInjector for V031ApprovedTargetWriterFailurePoint {
    fn after_credential_prefix(&self, prefix_len: usize) -> Result<(), ApprovedMcpError> {
        let selected_prefix = match self {
            Self::AfterCredentialPrefix1 => Some(1),
            Self::AfterCredentialPrefix2 => Some(2),
            Self::AfterCredentialPrefix3 => Some(3),
            Self::AfterCredentialPrefix4 => Some(4),
            Self::AfterApprovedWorkspaceClosed | Self::AfterWorkProductsClosedBeforeSync => None,
        };
        if selected_prefix == Some(prefix_len) {
            return Err(v031_target_components_error());
        }
        Ok(())
    }

    fn after_approved_workspace_closed(&self) -> Result<(), ApprovedMcpError> {
        if *self == Self::AfterApprovedWorkspaceClosed {
            return Err(v031_target_components_error());
        }
        Ok(())
    }

    fn after_work_products_closed_before_sync(&self) -> Result<(), ApprovedMcpError> {
        if *self == Self::AfterWorkProductsClosedBeforeSync {
            return Err(v031_target_components_error());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

const V031_TARGET_CREDENTIAL_ROLES: [KeyRole; 4] = [
    KeyRole::ApprovedManifest,
    KeyRole::WorkProductManifest,
    KeyRole::McpTicket,
    KeyRole::QualificationRevocationEpoch,
];

const V031_RECOVERY_CREDENTIAL_DELETE_ROLES: [KeyRole; 4] = [
    KeyRole::QualificationRevocationEpoch,
    KeyRole::McpTicket,
    KeyRole::WorkProductManifest,
    KeyRole::ApprovedManifest,
];

trait ApprovedMcpKeyProvider: Send + Sync {
    /// Reads an existing key without creating, rotating, or otherwise mutating the provider.
    ///
    /// Providers that cannot offer this guarantee must fail closed. Startup identity preflight
    /// deliberately never falls back to `load_or_create`.
    fn load_existing(&self, _role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        Err(key_store_error())
    }

    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError>;
    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError>;

    /// Installs one already-authenticated key without generating or rotating it.
    ///
    /// This is intentionally unavailable unless a provider can hold its store
    /// lock across conflict detection, write, and byte-exact readback.
    fn write_exact(&self, _role: KeyRole, _expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
        Err(key_store_error())
    }

    /// Deletes one already-authenticated key and proves the exact entry absent.
    ///
    /// Providers must treat an already-absent entry as an idempotent success,
    /// but must not delete a present value that differs from `expected`.
    fn delete_exact(&self, _role: KeyRole, _expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
        Err(key_store_error())
    }
}

#[cfg(test)]
std::thread_local! {
    static V031_RECOVERY_TEST_KEY_PROVIDER: std::cell::RefCell<Option<Arc<dyn ApprovedMcpKeyProvider>>> =
        const { std::cell::RefCell::new(None) };
}

fn with_v031_recovery_key_provider<T>(
    operation: impl FnOnce(&dyn ApprovedMcpKeyProvider) -> Result<T, ApprovedMcpError>,
) -> Result<T, ApprovedMcpError> {
    #[cfg(test)]
    {
        let test_provider = V031_RECOVERY_TEST_KEY_PROVIDER.with(|slot| slot.borrow().clone());
        if let Some(provider) = test_provider {
            return operation(provider.as_ref());
        }
    }

    let production = WindowsApprovedMcpKeyProvider::new();
    operation(&production)
}

/// The four post-invalidation approved-MCP credentials retained by an R3
/// safety archive. Values stay private to this module, are always stored in
/// the frozen creation order, and are cleared when the owner is dropped.
pub(crate) struct V031ApprovedMcpCredentialSnapshot {
    values: [[u8; 32]; 4],
}

impl V031ApprovedMcpCredentialSnapshot {
    fn zeroed() -> Self {
        Self {
            values: [[0_u8; 32]; 4],
        }
    }

    fn value(&self, role: KeyRole) -> &[u8; 32] {
        &self.values[v031_recovery_credential_role_index(role)]
    }

    fn validate(&self) -> Result<(), ApprovedMcpError> {
        if self
            .values
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(key_store_error());
        }
        let distinct = self
            .values
            .iter()
            .map(|value| sha256_hex(value))
            .collect::<BTreeSet<_>>();
        if distinct.len() != V031_TARGET_CREDENTIAL_ROLES.len() {
            return Err(key_store_error());
        }
        Ok(())
    }

    fn matches(&self, other: &Self) -> bool {
        self.values == other.values
    }

    fn binding_sha256(&self) -> Result<String, ApprovedMcpError> {
        let evidence = V031RecoveryCredentialSnapshotEvidence {
            schema: V031_RECOVERY_CREDENTIAL_ARCHIVE_SCHEMA,
            credential_sha256: self.values.each_ref().map(|value| sha256_hex(value)),
        };
        canonical_sha256(&evidence).map_err(|_| key_store_error())
    }

    /// Produces the only plaintext representation accepted by the R3 DPAPI
    /// credential archive. The returned buffer owns and zeroizes its bytes.
    pub(crate) fn to_canonical_archive_plaintext(
        &self,
    ) -> Result<V031ApprovedMcpCredentialArchivePlaintext, ApprovedMcpError> {
        self.validate()?;
        let wire = V031RecoveryCredentialArchiveWire {
            schema: V031_RECOVERY_CREDENTIAL_ARCHIVE_SCHEMA.to_owned(),
            format_version: V031_RECOVERY_CREDENTIAL_ARCHIVE_FORMAT_VERSION,
            credentials: std::array::from_fn(|index| V031RecoveryCredentialArchiveEntry {
                role: V031_TARGET_CREDENTIAL_ROLES[index].provider_id().to_owned(),
                value: self.values[index],
            }),
        };
        let bytes = canonical_json_v1(&wire).map_err(|_| key_store_error())?;
        if bytes.len() > MAX_V031_RECOVERY_CREDENTIAL_ARCHIVE_PLAINTEXT_BYTES {
            return Err(key_store_error());
        }
        Ok(V031ApprovedMcpCredentialArchivePlaintext(bytes))
    }

    /// Reconstructs an opaque snapshot only from byte-for-byte canonical R3
    /// archive plaintext with exactly the four frozen roles in order.
    pub(crate) fn from_canonical_archive_plaintext(
        plaintext: &[u8],
    ) -> Result<Self, ApprovedMcpError> {
        if plaintext.is_empty()
            || plaintext.len() > MAX_V031_RECOVERY_CREDENTIAL_ARCHIVE_PLAINTEXT_BYTES
        {
            return Err(key_store_error());
        }
        let wire: V031RecoveryCredentialArchiveWire =
            serde_json::from_slice(plaintext).map_err(|_| key_store_error())?;
        let mut canonical = canonical_json_v1(&wire).map_err(|_| key_store_error())?;
        let canonical_matches = canonical.as_slice() == plaintext;
        zeroize(&mut canonical);
        if !canonical_matches
            || wire.schema != V031_RECOVERY_CREDENTIAL_ARCHIVE_SCHEMA
            || wire.format_version != V031_RECOVERY_CREDENTIAL_ARCHIVE_FORMAT_VERSION
        {
            return Err(key_store_error());
        }

        let mut snapshot = Self::zeroed();
        for (index, entry) in wire.credentials.iter().enumerate() {
            if entry.role != V031_TARGET_CREDENTIAL_ROLES[index].provider_id() {
                return Err(key_store_error());
            }
            snapshot.values[index].copy_from_slice(&entry.value);
        }
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn clear(&mut self) {
        for value in &mut self.values {
            zeroize(value);
        }
    }

    #[cfg(test)]
    fn clear_for_test(&mut self) {
        self.clear();
    }

    #[cfg(test)]
    fn is_cleared_for_test(&self) -> bool {
        self.values
            .iter()
            .all(|value| value.iter().all(|byte| *byte == 0))
    }
}

impl fmt::Debug for V031ApprovedMcpCredentialSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ApprovedMcpCredentialSnapshot")
            .field("credential_count", &self.values.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Drop for V031ApprovedMcpCredentialSnapshot {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Zeroizing canonical JSON bytes ready to be protected by DPAPI CurrentUser.
pub(crate) struct V031ApprovedMcpCredentialArchivePlaintext(Vec<u8>);

impl V031ApprovedMcpCredentialArchivePlaintext {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn clear(&mut self) {
        zeroize(&mut self.0);
    }

    #[cfg(test)]
    fn clear_for_test(&mut self) {
        self.clear();
    }

    #[cfg(test)]
    fn is_cleared_for_test(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for V031ApprovedMcpCredentialArchivePlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ApprovedMcpCredentialArchivePlaintext")
            .field("bytes", &self.0.len())
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl Drop for V031ApprovedMcpCredentialArchivePlaintext {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031RecoveryCredentialSnapshotEvidence {
    schema: &'static str,
    credential_sha256: [String; 4],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031RecoveryCredentialArchiveWire {
    schema: String,
    format_version: u64,
    credentials: [V031RecoveryCredentialArchiveEntry; 4],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031RecoveryCredentialArchiveEntry {
    role: String,
    value: [u8; 32],
}

impl Drop for V031RecoveryCredentialArchiveEntry {
    fn drop(&mut self) {
        zeroize(&mut self.value);
    }
}

/// Read-only proof that Credential Manager is in exactly one legal deletion
/// prefix relative to an authenticated snapshot.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ApprovedMcpCredentialDeletePrefixGate {
    prefix_len: u8,
    snapshot_binding_sha256: String,
}

impl V031ApprovedMcpCredentialDeletePrefixGate {
    pub(crate) const fn prefix_len(&self) -> usize {
        self.prefix_len as usize
    }
}

impl fmt::Debug for V031ApprovedMcpCredentialDeletePrefixGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ApprovedMcpCredentialDeletePrefixGate")
            .field("prefix_len", &self.prefix_len)
            .field("snapshot_binding_sha256", &self.snapshot_binding_sha256)
            .finish()
    }
}

/// Captures and immediately re-reads the four production entries without
/// constructing any approved-MCP manager or creating credentials.
pub(crate) fn capture_v031_recovery_approved_mcp_credentials_read_only(
) -> Result<V031ApprovedMcpCredentialSnapshot, ApprovedMcpError> {
    with_v031_recovery_key_provider(capture_v031_recovery_approved_mcp_credentials_with)
}

/// Re-observes all four production entries twice and compares them byte for
/// byte with the opaque safety snapshot.
pub(crate) fn authenticate_v031_recovery_approved_mcp_credentials_read_only(
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), ApprovedMcpError> {
    with_v031_recovery_key_provider(|provider| {
        authenticate_v031_recovery_approved_mcp_credentials_with(provider, expected)
    })
}

/// Observes the exact ADR deletion prefix without creating, deleting, or
/// repairing any Credential Manager entry.
pub(crate) fn observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<V031ApprovedMcpCredentialDeletePrefixGate, ApprovedMcpError> {
    with_v031_recovery_key_provider(|provider| {
        observe_v031_recovery_approved_mcp_credential_delete_prefix_with(provider, expected)
    })
}

/// Advances exactly one frozen deletion step. A stale, skipped, conflicted,
/// or already-complete gate is rejected before mutation.
pub(crate) fn advance_v031_recovery_approved_mcp_credential_delete_prefix(
    expected: &V031ApprovedMcpCredentialSnapshot,
    current: &V031ApprovedMcpCredentialDeletePrefixGate,
) -> Result<V031ApprovedMcpCredentialDeletePrefixGate, ApprovedMcpError> {
    with_v031_recovery_key_provider(|provider| {
        advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
            provider, expected, current,
        )
    })
}

/// Restores only absent entries whose remaining peers still exactly match the
/// snapshot, then re-reads all four values twice. No new random key is made.
pub(crate) fn restore_v031_recovery_approved_mcp_credentials_exact(
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), ApprovedMcpError> {
    with_v031_recovery_key_provider(|provider| {
        restore_v031_recovery_approved_mcp_credentials_exact_with(provider, expected)
    })
}

fn v031_recovery_credential_role_index(role: KeyRole) -> usize {
    match role {
        KeyRole::ApprovedManifest => 0,
        KeyRole::WorkProductManifest => 1,
        KeyRole::McpTicket => 2,
        KeyRole::QualificationRevocationEpoch => 3,
    }
}

fn read_v031_recovery_approved_mcp_credentials_once(
    provider: &dyn ApprovedMcpKeyProvider,
) -> Result<V031ApprovedMcpCredentialSnapshot, ApprovedMcpError> {
    let mut snapshot = V031ApprovedMcpCredentialSnapshot::zeroed();
    for role in V031_TARGET_CREDENTIAL_ROLES {
        snapshot.values[v031_recovery_credential_role_index(role)] =
            provider.load_existing(role)?.ok_or_else(key_store_error)?;
    }
    snapshot.validate()?;
    Ok(snapshot)
}

fn capture_v031_recovery_approved_mcp_credentials_with(
    provider: &dyn ApprovedMcpKeyProvider,
) -> Result<V031ApprovedMcpCredentialSnapshot, ApprovedMcpError> {
    let first = read_v031_recovery_approved_mcp_credentials_once(provider)?;
    let second = read_v031_recovery_approved_mcp_credentials_once(provider)?;
    if !first.matches(&second) {
        return Err(key_store_error());
    }
    Ok(first)
}

fn authenticate_v031_recovery_approved_mcp_credentials_with(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), ApprovedMcpError> {
    expected.validate()?;
    let first = read_v031_recovery_approved_mcp_credentials_once(provider)?;
    let second = read_v031_recovery_approved_mcp_credentials_once(provider)?;
    if !expected.matches(&first) || !first.matches(&second) {
        return Err(key_store_error());
    }
    Ok(())
}

fn observe_v031_recovery_approved_mcp_credential_delete_prefix_once(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<V031ApprovedMcpCredentialDeletePrefixGate, ApprovedMcpError> {
    expected.validate()?;
    let mut prefix_len = 0_u8;
    let mut saw_present = false;
    for role in V031_RECOVERY_CREDENTIAL_DELETE_ROLES {
        match provider.load_existing(role)? {
            None if !saw_present => prefix_len += 1,
            None => return Err(key_store_error()),
            Some(mut actual) => {
                saw_present = true;
                let matches = &actual == expected.value(role);
                zeroize(&mut actual);
                if !matches {
                    return Err(key_store_error());
                }
            }
        }
    }
    Ok(V031ApprovedMcpCredentialDeletePrefixGate {
        prefix_len,
        snapshot_binding_sha256: expected.binding_sha256()?,
    })
}

fn observe_v031_recovery_approved_mcp_credential_delete_prefix_with(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<V031ApprovedMcpCredentialDeletePrefixGate, ApprovedMcpError> {
    let first =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_once(provider, expected)?;
    let second =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_once(provider, expected)?;
    if first != second {
        return Err(key_store_error());
    }
    Ok(first)
}

fn advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
    current: &V031ApprovedMcpCredentialDeletePrefixGate,
) -> Result<V031ApprovedMcpCredentialDeletePrefixGate, ApprovedMcpError> {
    let observed =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_with(provider, expected)?;
    if &observed != current || current.prefix_len() >= V031_RECOVERY_CREDENTIAL_DELETE_ROLES.len() {
        return Err(key_store_error());
    }
    let role = V031_RECOVERY_CREDENTIAL_DELETE_ROLES[current.prefix_len()];
    provider.delete_exact(role, expected.value(role))?;
    let advanced =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_with(provider, expected)?;
    if advanced.prefix_len() != current.prefix_len() + 1 {
        return Err(key_store_error());
    }
    Ok(advanced)
}

fn observe_v031_recovery_restore_compatible_once(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<[bool; 4], ApprovedMcpError> {
    expected.validate()?;
    let mut missing = [false; 4];
    for role in V031_TARGET_CREDENTIAL_ROLES {
        let index = v031_recovery_credential_role_index(role);
        match provider.load_existing(role)? {
            None => missing[index] = true,
            Some(mut actual) => {
                let matches = &actual == expected.value(role);
                zeroize(&mut actual);
                if !matches {
                    return Err(key_store_error());
                }
            }
        }
    }
    Ok(missing)
}

fn restore_v031_recovery_approved_mcp_credentials_exact_with(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), ApprovedMcpError> {
    let first = observe_v031_recovery_restore_compatible_once(provider, expected)?;
    let second = observe_v031_recovery_restore_compatible_once(provider, expected)?;
    if first != second {
        return Err(key_store_error());
    }
    for role in V031_TARGET_CREDENTIAL_ROLES {
        if first[v031_recovery_credential_role_index(role)] {
            provider.write_exact(role, expected.value(role))?;
        }
    }
    authenticate_v031_recovery_approved_mcp_credentials_with(provider, expected)
}

#[cfg(test)]
fn verify_v031_target_credentials_absent_with(
    provider: &dyn ApprovedMcpKeyProvider,
) -> Result<u64, ApprovedMcpError> {
    for role in V031_TARGET_CREDENTIAL_ROLES {
        if let Some(mut existing) = provider.load_existing(role)? {
            zeroize(&mut existing);
            return Err(ApprovedMcpError::new(
                "v031_upgrade_target_credential_present",
                "A target-only approved MCP credential already exists.",
            ));
        }
    }
    Ok(V031_TARGET_CREDENTIAL_ROLES.len() as u64)
}

pub(crate) struct V031ApprovedMcpCredentialProbe {
    provider: Arc<dyn ApprovedMcpKeyProvider>,
}

impl V031ApprovedMcpCredentialProbe {
    pub(crate) fn new() -> Self {
        #[cfg(test)]
        if let Some(provider) = V031_RECOVERY_TEST_KEY_PROVIDER.with(|slot| slot.borrow().clone()) {
            return Self { provider };
        }
        Self {
            provider: Arc::new(WindowsApprovedMcpKeyProvider::new()),
        }
    }

    #[cfg(test)]
    fn from_provider(provider: Arc<dyn ApprovedMcpKeyProvider>) -> Self {
        Self { provider }
    }
}

impl crate::v031_upgrade_r2::CredentialPresenceProbe for V031ApprovedMcpCredentialProbe {
    type Error = ApprovedMcpError;

    fn credential_exists_read_only(
        &self,
        query: crate::v031_upgrade_r2::CredentialAbsenceQuery,
    ) -> Result<bool, Self::Error> {
        if query.target != query.role.target()
            || query.account != crate::v031_upgrade_r2::APPROVED_MCP_CREDENTIAL_ACCOUNT
        {
            return Err(key_store_error());
        }
        let role = match query.role {
            crate::v031_upgrade_r2::ApprovedMcpCredentialRole::ApprovedManifest => {
                KeyRole::ApprovedManifest
            }
            crate::v031_upgrade_r2::ApprovedMcpCredentialRole::WorkProductManifest => {
                KeyRole::WorkProductManifest
            }
            crate::v031_upgrade_r2::ApprovedMcpCredentialRole::McpAccessTicket => {
                KeyRole::McpTicket
            }
            crate::v031_upgrade_r2::ApprovedMcpCredentialRole::QualificationRevocationEpoch => {
                KeyRole::QualificationRevocationEpoch
            }
        };
        let mut existing = self.provider.load_existing(role)?;
        let present = existing.is_some();
        if let Some(key) = existing.as_mut() {
            zeroize(key);
        }
        Ok(present)
    }
}

/// Prepares only the approved-MCP portion of frozen migration Step 3.
///
/// Possession of the opaque rollback gate is the sole write authorization.
/// This entry point creates no qualification record, ticket store, standalone
/// session, publication, work product, or case-specific state.
pub(crate) fn prepare_v031_approved_mcp_target_components(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
    let workspace = ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf());
    workspace.prepare_v031_target_components_with_binding(
        &V031RollbackGateBinding::from_verified_gate(rollback_gate),
    )
}

/// Re-authenticates the completed approved-MCP target with credential reads and
/// immutable SQLite reads only. It never creates, rotates, repairs, or syncs
/// credentials, files, databases, tickets, or qualification state.
pub(crate) fn verify_v031_approved_mcp_target_components_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    expected_gate: &V031ApprovedMcpTargetComponentsGate,
) -> Result<(), ApprovedMcpError> {
    let workspace = ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf());
    workspace.verify_v031_target_components_with_binding_read_only(
        &V031RollbackGateBinding::from_verified_gate(rollback_gate),
        expected_gate,
    )
}

/// Rebuilds the opaque approved-MCP target gate from existing credentials and
/// immutable component storage. This is the crash-resume counterpart to the
/// write-authorized prepare entry point.
pub(crate) fn load_v031_approved_mcp_target_components_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
    let workspace = ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf());
    workspace.load_v031_target_components_with_binding_read_only(
        &V031RollbackGateBinding::from_verified_gate(rollback_gate),
    )
}

/// Rebuilds the historical empty Approved Gate2 without consulting the
/// evolved live Approved/work-products databases. The checkpoint record is
/// useful only when its hashes agree with a fresh, read-only Credential
/// Manager snapshot and the exact rollback binding.
pub(crate) fn load_v031_approved_mcp_historical_target_from_checkpoint_read_only(
    workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    record: &V031ApprovedMcpHistoricalTargetRecord,
) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
    let rollback_binding = V031RollbackGateBinding::from_verified_gate(rollback_gate);
    load_v031_approved_mcp_historical_target_with_binding_read_only(
        workspace,
        &rollback_binding,
        record,
    )
}

fn load_v031_approved_mcp_historical_target_with_binding_read_only(
    workspace: &ApprovedMcpWorkspace,
    rollback_binding: &V031RollbackGateBinding,
    record: &V031ApprovedMcpHistoricalTargetRecord,
) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
    let _operation = workspace.operation()?;
    rollback_binding.validate()?;
    let keys = load_v031_existing_credentials_read_only(workspace.inner.keys.as_ref())?;
    let workspace_instance_id = workspace_instance_id(&keys.approved_manifest)?;
    let credential_manifest_sha256 = v031_credential_manifest_sha256(&keys)?;
    if workspace_instance_id != record.workspace_instance_id
        || credential_manifest_sha256 != record.credential_manifest_sha256
        || record.approved_workspace_schema_sha256 != V031_APPROVED_WORKSPACE_SCHEMA_SHA256
        || record.work_products_schema_sha256 != V031_WORK_PRODUCTS_SCHEMA_SHA256
        || !is_lower_sha256(&record.approved_workspace_manifest_sha256)
        || !is_lower_sha256(&record.work_products_manifest_sha256)
        || !is_lower_sha256(&record.evidence_sha256)
        || record.credential_count != V031_TARGET_CREDENTIAL_ROLES.len() as u64
        || record.approved_business_rows != 0
        || record.work_product_business_rows != 0
    {
        return Err(v031_target_components_error());
    }
    let rollback_gate_binding_sha256 = rollback_binding.sha256()?;
    let evidence_sha256 = canonical_sha256(&V031TargetComponentsEvidence {
        schema_version: V031_TARGET_COMPONENTS_EVIDENCE_SCHEMA,
        rollback_gate_binding_sha256: &rollback_gate_binding_sha256,
        workspace_instance_id: workspace_instance_id.as_str(),
        credential_manifest_sha256: &credential_manifest_sha256,
        approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256,
        work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256,
        approved_workspace_manifest_sha256: &record.approved_workspace_manifest_sha256,
        work_products_manifest_sha256: &record.work_products_manifest_sha256,
        credential_count: record.credential_count,
        approved_business_rows: record.approved_business_rows,
        work_product_business_rows: record.work_product_business_rows,
        ticket_session_count: 0,
        qualification_record_count: 0,
    })?;
    if evidence_sha256 != record.evidence_sha256 {
        return Err(v031_target_components_error());
    }
    Ok(V031ApprovedMcpTargetComponentsGate {
        workspace_instance_id,
        rollback_gate_binding_sha256,
        credential_manifest_sha256,
        approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256.to_owned(),
        work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256.to_owned(),
        approved_workspace_manifest_sha256: record.approved_workspace_manifest_sha256.clone(),
        work_products_manifest_sha256: record.work_products_manifest_sha256.clone(),
        evidence_sha256,
        credential_count: record.credential_count,
        approved_business_rows: record.approved_business_rows,
        work_product_business_rows: record.work_product_business_rows,
    })
}

/// Revalidates only the stable Credential/rollback portion of a historical
/// Approved Gate2. It is safe after the live Approved stores have evolved.
pub(crate) fn verify_v031_approved_mcp_historical_target_credentials_read_only(
    workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    expected: &V031ApprovedMcpTargetComponentsGate,
) -> Result<(), ApprovedMcpError> {
    let observed = load_v031_approved_mcp_historical_target_from_checkpoint_read_only(
        workspace,
        rollback_gate,
        &V031ApprovedMcpHistoricalTargetRecord {
            workspace_instance_id: expected.workspace_instance_id().clone(),
            credential_manifest_sha256: expected.credential_manifest_sha256().to_owned(),
            approved_workspace_schema_sha256: expected
                .approved_workspace_schema_sha256()
                .to_owned(),
            work_products_schema_sha256: expected.work_products_schema_sha256().to_owned(),
            approved_workspace_manifest_sha256: expected
                .approved_workspace_manifest_sha256()
                .to_owned(),
            work_products_manifest_sha256: expected.work_products_manifest_sha256().to_owned(),
            evidence_sha256: expected.evidence_sha256().to_owned(),
            credential_count: expected.credential_count(),
            approved_business_rows: expected.approved_business_rows(),
            work_product_business_rows: expected.work_product_business_rows(),
        },
    )?;
    if &observed != expected {
        return Err(v031_target_components_error());
    }
    Ok(())
}

/// Path-free evidence that the two directories selected by the full-application
/// restore state machine are an exact, authenticated Approved/work-products pair.
/// The two manifest credentials are part of the proof; ticket and qualification
/// credentials are observed only to prove that validation did not mutate them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApplicationRestoreApprovedComponentsProof {
    workspace_instance_id: WorkspaceInstanceId,
    approved_manifest_sha256: String,
    work_products_manifest_sha256: String,
    credential_sha256: [Option<String>; 4],
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ApplicationRestoreWorkspaceIdentityProof {
    workspace_instance_id: WorkspaceInstanceId,
    credential_sha256: [Option<String>; 4],
}

impl fmt::Debug for ApplicationRestoreWorkspaceIdentityProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationRestoreWorkspaceIdentityProof")
            .field("workspace_instance_id", &"[AUTHENTICATED_WORKSPACE]")
            .field(
                "credential_presence",
                &self.credential_sha256.each_ref().map(Option::is_some),
            )
            .finish()
    }
}

impl ApplicationRestoreWorkspaceIdentityProof {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }
}

impl fmt::Debug for ApplicationRestoreApprovedComponentsProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationRestoreApprovedComponentsProof")
            .field("workspace_instance_id", &"[AUTHENTICATED_WORKSPACE]")
            .field("approved_manifest_sha256", &self.approved_manifest_sha256)
            .field(
                "work_products_manifest_sha256",
                &self.work_products_manifest_sha256,
            )
            .field(
                "credential_presence",
                &self.credential_sha256.each_ref().map(Option::is_some),
            )
            .finish()
    }
}

impl ApplicationRestoreApprovedComponentsProof {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }
}

/// Loads the already-existing Approved-MCP identity without consulting any
/// component directory and without invoking a lazy credential creator.  This
/// is the root/workspace binding used by legacy V2 full restores.
pub(crate) fn observe_application_restore_workspace_identity_read_only(
    app_local_data_directory: &Path,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<ApplicationRestoreWorkspaceIdentityProof, ApprovedMcpError> {
    let workspace = ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf());
    workspace
        .observe_application_restore_workspace_identity_read_only(expected_workspace_instance_id)
}

impl ApprovedMcpWorkspace {
    pub(crate) fn observe_application_restore_workspace_identity_read_only(
        &self,
        expected_workspace_instance_id: &WorkspaceInstanceId,
    ) -> Result<ApplicationRestoreWorkspaceIdentityProof, ApprovedMcpError> {
        let credentials = application_restore_credential_digests(self.inner.keys.as_ref())?;
        credentials[0].as_ref().ok_or_else(workspace_error)?;
        let approved_key = ApplicationRestoreSecretKey::new(
            self.inner
                .keys
                .load_existing(KeyRole::ApprovedManifest)?
                .ok_or_else(workspace_error)?,
        );
        let workspace_instance_id = workspace_instance_id(approved_key.as_bytes())?;
        if &workspace_instance_id != expected_workspace_instance_id
            || application_restore_credential_digests(self.inner.keys.as_ref())? != credentials
        {
            return Err(workspace_error());
        }
        Ok(ApplicationRestoreWorkspaceIdentityProof {
            workspace_instance_id,
            credential_sha256: credentials,
        })
    }
}

/// Authenticates an arbitrary pair of fixed full-restore slots without creating
/// an Approved-MCP identity or opening either writable service.  Both this
/// boundary and the exact manifest validator use only `load_existing`; all four
/// credential values must also remain byte-identical across validation.
pub(crate) fn validate_application_restore_components_read_only(
    app_local_data_directory: &Path,
    approved_root: &Path,
    work_products_root: &Path,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    expected_approved_manifest_sha256: &str,
    expected_work_products_manifest_sha256: &str,
) -> Result<ApplicationRestoreApprovedComponentsProof, ApprovedMcpError> {
    let workspace = ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf());
    workspace.validate_application_restore_components_read_only(
        approved_root,
        work_products_root,
        expected_workspace_instance_id,
        expected_approved_manifest_sha256,
        expected_work_products_manifest_sha256,
    )
}

impl ApprovedMcpWorkspace {
    pub(crate) fn validate_application_restore_components_read_only(
        &self,
        approved_root: &Path,
        work_products_root: &Path,
        expected_workspace_instance_id: &WorkspaceInstanceId,
        expected_approved_manifest_sha256: &str,
        expected_work_products_manifest_sha256: &str,
    ) -> Result<ApplicationRestoreApprovedComponentsProof, ApprovedMcpError> {
        let before = application_restore_credential_digests(self.inner.keys.as_ref())?;
        before[0].as_ref().ok_or_else(workspace_error)?;
        before[1].as_ref().ok_or_else(workspace_error)?;

        let raw_approved_key = ApplicationRestoreSecretKey::new(
            self.inner
                .keys
                .load_existing(KeyRole::ApprovedManifest)?
                .ok_or_else(workspace_error)?,
        );
        let observed_workspace_instance_id = workspace_instance_id(raw_approved_key.as_bytes())?;
        if &observed_workspace_instance_id != expected_workspace_instance_id {
            return Err(workspace_error());
        }

        self.validate_staged_application_backup_manifests(
            approved_root,
            expected_approved_manifest_sha256,
            work_products_root,
            expected_work_products_manifest_sha256,
        )?;
        let after = application_restore_credential_digests(self.inner.keys.as_ref())?;
        if after != before {
            return Err(workspace_error());
        }

        Ok(ApplicationRestoreApprovedComponentsProof {
            workspace_instance_id: observed_workspace_instance_id,
            approved_manifest_sha256: expected_approved_manifest_sha256.to_owned(),
            work_products_manifest_sha256: expected_work_products_manifest_sha256.to_owned(),
            credential_sha256: before,
        })
    }
}

pub(super) struct ApplicationRestoreSecretKey([u8; 32]);

impl ApplicationRestoreSecretKey {
    pub(super) fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for ApplicationRestoreSecretKey {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

fn application_restore_credential_digests(
    provider: &dyn ApprovedMcpKeyProvider,
) -> Result<[Option<String>; 4], ApprovedMcpError> {
    let mut digests: [Option<String>; 4] = std::array::from_fn(|_| None);
    for (index, role) in V031_TARGET_CREDENTIAL_ROLES.into_iter().enumerate() {
        if let Some(mut key) = provider.load_existing(role)? {
            digests[index] = Some(sha256_hex(&key));
            zeroize(&mut key);
        }
    }
    Ok(digests)
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

    #[cfg(test)]
    fn with_service_prefix(service_prefix: impl Into<String>) -> Self {
        Self {
            store: WindowsCredentialStore::with_service_prefix(service_prefix),
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
    fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        self.store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
            .map(|secret| decode_key(secret.expose_secret()))
            .transpose()
    }

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

    fn write_exact(&self, role: KeyRole, expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
        if expected.iter().all(|byte| *byte == 0) {
            return Err(key_store_error());
        }
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        if let Some(secret) = self
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
        {
            let mut existing = decode_key(secret.expose_secret())?;
            let matches = &existing == expected;
            zeroize(&mut existing);
            return if matches {
                Ok(())
            } else {
                Err(key_store_error())
            };
        }

        let encoded = format!("{KEY_FORMAT_PREFIX}{}", URL_SAFE_NO_PAD.encode(expected));
        self.store
            .write_api_key(&credential_key, ApiSecret::new(encoded))
            .map_err(|_| key_store_error())?;
        let mut readback = self
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
            .ok_or_else(key_store_error)
            .and_then(|secret| decode_key(secret.expose_secret()))?;
        let matches = &readback == expected;
        zeroize(&mut readback);
        if !matches {
            return Err(key_store_error());
        }
        Ok(())
    }

    fn delete_exact(&self, role: KeyRole, expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
        if expected.iter().all(|byte| *byte == 0) {
            return Err(key_store_error());
        }
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        let Some(secret) = self
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
        else {
            return Ok(());
        };
        let mut existing = decode_key(secret.expose_secret())?;
        let matches = &existing == expected;
        zeroize(&mut existing);
        if !matches {
            return Err(key_store_error());
        }
        self.store
            .delete_api_key(&credential_key)
            .map_err(|_| key_store_error())?;
        if self
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
            .is_some()
        {
            return Err(key_store_error());
        }
        Ok(())
    }
}

/// Feature-only provider used by the R3 current desktop executable. Every
/// mutating trait operation fails closed; the real process can only reopen the
/// UUID-scoped keys already installed by the parent acceptance harness.
#[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
#[derive(Debug)]
struct R3CurrentReadOnlyApprovedMcpKeyProvider {
    store: WindowsCredentialStore,
}

#[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
impl R3CurrentReadOnlyApprovedMcpKeyProvider {
    fn new(service_prefix: &str) -> Self {
        let suffix = service_prefix
            .strip_prefix(V031_CROSS_PROCESS_CREDENTIAL_PREFIX)
            .expect("authenticated R3 current credential prefix");
        let parsed = Uuid::parse_str(suffix).expect("authenticated R3 current credential UUID");
        assert_eq!(parsed.hyphenated().to_string(), suffix);
        Self {
            store: WindowsCredentialStore::with_service_prefix(service_prefix),
        }
    }
}

#[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
impl ApprovedMcpKeyProvider for R3CurrentReadOnlyApprovedMcpKeyProvider {
    fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        self.store
            .read_api_key(&ProviderCredentialKey::new(
                role.provider_id(),
                "user-boundary-v1",
            ))
            .map_err(|_| key_store_error())?
            .map(|secret| decode_key(secret.expose_secret()))
            .transpose()
    }

    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        self.load_existing(role)?.ok_or_else(key_store_error)
    }

    fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        Err(key_store_error())
    }
}

#[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
pub(crate) fn load_r3_current_receipt_signer_key_read_only() -> Result<[u8; 32], ApprovedMcpError> {
    let store = WindowsCredentialStore::with_service_prefix(
        crate::r3_current_binary_harness::credential_prefix(),
    );
    let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
    store
        .read_api_key(&ProviderCredentialKey::new(
            V031_CROSS_PROCESS_RECEIPT_SIGNER_PROVIDER,
            V031_CROSS_PROCESS_RECEIPT_SIGNER_ACCOUNT,
        ))
        .map_err(|_| key_store_error())?
        .ok_or_else(key_store_error)
        .and_then(|secret| decode_key(secret.expose_secret()))
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

#[cfg(test)]
impl ApprovedMcpWorkspace {
    pub(crate) fn prepare_v031_target_components_for_checkpoint_test(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        self.prepare_v031_target_components_with_binding(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
        )
    }

    pub(crate) fn prepare_v031_target_components_with_writer_failure_for_test(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        failure_point: V031ApprovedTargetWriterFailurePoint,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        self.prepare_v031_target_components_with_binding_and_failure_injector(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
            &failure_point,
        )
    }

    pub(crate) fn verify_v031_target_components_for_checkpoint_test(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        expected_gate: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), ApprovedMcpError> {
        self.verify_v031_target_components_with_binding_read_only(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
            expected_gate,
        )
    }

    pub(crate) fn load_v031_target_components_for_checkpoint_test(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        self.load_v031_target_components_with_binding_read_only(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
        )
    }

    pub(crate) fn observe_v031_target_namespace_for_checkpoint_test(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetNamespaceObservation, ApprovedMcpError> {
        self.observe_v031_target_namespace_with_binding_read_only(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
        )
    }

    pub(crate) fn v031_credential_probe_for_test(&self) -> V031ApprovedMcpCredentialProbe {
        V031ApprovedMcpCredentialProbe::from_provider(Arc::clone(&self.inner.keys))
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031TargetWriterProviderAudit {
    credential_sha256: [Option<String>; 4],
    load_existing_calls: usize,
    load_or_create_calls: usize,
    creation_writes: usize,
    rotate_calls: usize,
}

#[cfg(test)]
impl V031TargetWriterProviderAudit {
    pub(crate) fn credential_sha256(&self) -> &[Option<String>; 4] {
        &self.credential_sha256
    }

    pub(crate) const fn load_existing_calls(&self) -> usize {
        self.load_existing_calls
    }

    pub(crate) const fn load_or_create_calls(&self) -> usize {
        self.load_or_create_calls
    }

    pub(crate) const fn creation_writes(&self) -> usize {
        self.creation_writes
    }

    pub(crate) const fn rotate_calls(&self) -> usize {
        self.rotate_calls
    }
}

#[cfg(test)]
struct V031TargetWriterAuditedKeyProvider {
    keys: Mutex<[Option<[u8; 32]>; 4]>,
    load_existing_calls: std::sync::atomic::AtomicUsize,
    load_or_create_calls: std::sync::atomic::AtomicUsize,
    creation_writes: std::sync::atomic::AtomicUsize,
    rotate_calls: std::sync::atomic::AtomicUsize,
    mutating_calls_forbidden: AtomicBool,
}

#[cfg(test)]
impl V031TargetWriterAuditedKeyProvider {
    fn new() -> Self {
        Self {
            keys: Mutex::new(std::array::from_fn(|_| None)),
            load_existing_calls: std::sync::atomic::AtomicUsize::new(0),
            load_or_create_calls: std::sync::atomic::AtomicUsize::new(0),
            creation_writes: std::sync::atomic::AtomicUsize::new(0),
            rotate_calls: std::sync::atomic::AtomicUsize::new(0),
            mutating_calls_forbidden: AtomicBool::new(false),
        }
    }

    fn role_index(role: KeyRole) -> usize {
        match role {
            KeyRole::ApprovedManifest => 0,
            KeyRole::WorkProductManifest => 1,
            KeyRole::McpTicket => 2,
            KeyRole::QualificationRevocationEpoch => 3,
        }
    }

    fn audit(&self) -> Result<V031TargetWriterProviderAudit, ApprovedMcpError> {
        Ok(V031TargetWriterProviderAudit {
            credential_sha256: application_restore_credential_digests(self)?,
            load_existing_calls: self.load_existing_calls.load(Ordering::SeqCst),
            load_or_create_calls: self.load_or_create_calls.load(Ordering::SeqCst),
            creation_writes: self.creation_writes.load(Ordering::SeqCst),
            rotate_calls: self.rotate_calls.load(Ordering::SeqCst),
        })
    }
}

#[cfg(test)]
impl Drop for V031TargetWriterAuditedKeyProvider {
    fn drop(&mut self) {
        if let Ok(keys) = self.keys.get_mut() {
            for key in keys.iter_mut().flatten() {
                zeroize(key);
            }
        }
    }
}

#[cfg(test)]
impl ApprovedMcpKeyProvider for V031TargetWriterAuditedKeyProvider {
    fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        self.load_existing_calls.fetch_add(1, Ordering::SeqCst);
        self.keys
            .lock()
            .map(|keys| keys[Self::role_index(role)])
            .map_err(|_| key_store_error())
    }

    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        self.load_or_create_calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.mutating_calls_forbidden.load(Ordering::SeqCst),
            "a committed target-component retry invoked load_or_create"
        );
        let mut keys = self.keys.lock().map_err(|_| key_store_error())?;
        let slot = &mut keys[Self::role_index(role)];
        if let Some(key) = *slot {
            return Ok(key);
        }
        let mut key = [0_u8; 32];
        if let Err(error) = fill_random(&mut key) {
            zeroize(&mut key);
            return Err(error);
        }
        if key.iter().all(|byte| *byte == 0) {
            zeroize(&mut key);
            return Err(key_store_error());
        }
        *slot = Some(key);
        self.creation_writes.fetch_add(1, Ordering::SeqCst);
        Ok(key)
    }

    fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        self.rotate_calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.mutating_calls_forbidden.load(Ordering::SeqCst),
            "a committed target-component retry invoked rotate"
        );
        Err(key_store_error())
    }
}

#[cfg(test)]
struct V031TargetWriterUnavailableQualification;

#[cfg(test)]
impl ApprovedWorkspaceQualificationProvider for V031TargetWriterUnavailableQualification {
    fn current_qualification(
        &self,
        _now_unix: u64,
    ) -> Result<
        ApprovedMcpQualificationSnapshotV1,
        legal_mcp::approved_backend::ApprovedWorkspaceQualificationError,
    > {
        Err(legal_mcp::approved_backend::ApprovedWorkspaceQualificationError::Unavailable)
    }
}

/// Real Approved/work-products writers backed by an isolated CSPRNG provider
/// whose reads, creation writes, rotations, and non-secret digests are audited.
#[cfg(test)]
pub(crate) struct V031TargetWriterTestHarness {
    pub(crate) workspace: ApprovedMcpWorkspace,
    provider: Arc<V031TargetWriterAuditedKeyProvider>,
}

#[cfg(test)]
impl V031TargetWriterTestHarness {
    pub(crate) fn new(app_local_data_directory: PathBuf) -> Self {
        let provider = Arc::new(V031TargetWriterAuditedKeyProvider::new());
        let key_provider: Arc<dyn ApprovedMcpKeyProvider> = provider.clone();
        let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> =
            Arc::new(V031TargetWriterUnavailableQualification);
        let workspace = ApprovedMcpWorkspace::from_parts(
            app_local_data_directory,
            qualification,
            key_provider,
            None,
        );
        Self {
            workspace,
            provider,
        }
    }

    pub(crate) fn credential_probe(&self) -> V031ApprovedMcpCredentialProbe {
        V031ApprovedMcpCredentialProbe::from_provider(self.provider.clone())
    }

    pub(crate) fn provider_audit(&self) -> Result<V031TargetWriterProviderAudit, ApprovedMcpError> {
        self.provider.audit()
    }

    pub(crate) fn forbid_provider_mutation(&self) {
        self.provider
            .mutating_calls_forbidden
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn remove_credential_for_test(&self, index: usize) -> Result<(), ApprovedMcpError> {
        let mut keys = self.provider.keys.lock().map_err(|_| key_store_error())?;
        let slot = keys.get_mut(index).ok_or_else(key_store_error)?;
        let mut removed = slot.take().ok_or_else(key_store_error)?;
        zeroize(&mut removed);
        Ok(())
    }
}

#[cfg(any(test, feature = "r3-real-current-binary-harness"))]
const V031_CROSS_PROCESS_CREDENTIAL_PREFIX: &str = "LawyerAssistanceV031RestartTest-";
#[cfg(any(test, feature = "r3-real-current-binary-harness"))]
const V031_CROSS_PROCESS_RECEIPT_SIGNER_PROVIDER: &str =
    "v031-process-restart-privacy-receipt-signer";
#[cfg(any(test, feature = "r3-real-current-binary-harness"))]
const V031_CROSS_PROCESS_RECEIPT_SIGNER_ACCOUNT: &str = "test-boundary-v1";

/// Test-only credential boundary for a real Windows child-process restart.
///
/// The service prefix is a fresh UUID namespace, so the fixture never reads,
/// writes, rotates, or deletes the fixed production Approved-MCP credentials.
/// Only the non-secret prefix crosses the process boundary. The four real
/// Approved keys and the separate Privacy receipt-signer key remain in Windows
/// Credential Manager and are reopened by the child through the production
/// credential codec.
#[cfg(test)]
pub(crate) struct V031CrossProcessCredentialHarness {
    pub(crate) workspace: ApprovedMcpWorkspace,
    provider: Arc<WindowsApprovedMcpKeyProvider>,
    service_prefix: String,
    cleanup_on_drop: bool,
}

/// A same-thread test seam for driving the production R3 credential state
/// machine against one UUID-scoped Windows Credential Manager namespace.
/// The `Rc` marker deliberately prevents moving the override across threads.
#[cfg(test)]
pub(crate) struct V031RecoveryCredentialOverrideGuard {
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Sendable factory for installing the UUID-scoped R3 credential provider on
/// the exact blocking worker that executes one production staging boundary.
/// The installed guard remains thread-local and deliberately cannot leave that
/// worker.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct V031RecoveryCredentialOverrideFactory {
    provider: Arc<dyn ApprovedMcpKeyProvider>,
}

#[cfg(test)]
impl V031RecoveryCredentialOverrideFactory {
    pub(crate) fn install_on_current_thread(
        &self,
    ) -> Result<V031RecoveryCredentialOverrideGuard, ApprovedMcpError> {
        let installed = V031_RECOVERY_TEST_KEY_PROVIDER.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                false
            } else {
                *slot = Some(Arc::clone(&self.provider));
                true
            }
        });
        if !installed {
            return Err(key_store_error());
        }
        Ok(V031RecoveryCredentialOverrideGuard {
            _same_thread: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
impl Drop for V031RecoveryCredentialOverrideGuard {
    fn drop(&mut self) {
        V031_RECOVERY_TEST_KEY_PROVIDER.with(|slot| {
            let removed = slot.borrow_mut().take();
            debug_assert!(removed.is_some());
        });
    }
}

#[cfg(test)]
impl V031CrossProcessCredentialHarness {
    pub(crate) fn create_parent(
        app_local_data_directory: PathBuf,
    ) -> Result<Self, ApprovedMcpError> {
        let service_prefix = format!("{V031_CROSS_PROCESS_CREDENTIAL_PREFIX}{}", Uuid::new_v4());
        let harness = Self::from_prefix(app_local_data_directory, service_prefix, true)?;
        harness.verify_all_credentials_absent()?;
        Ok(harness)
    }

    pub(crate) fn reopen_child(
        app_local_data_directory: PathBuf,
        service_prefix: &str,
    ) -> Result<Self, ApprovedMcpError> {
        let harness =
            Self::from_prefix(app_local_data_directory, service_prefix.to_owned(), false)?;
        harness.verify_all_credentials_present()?;
        Ok(harness)
    }

    fn from_prefix(
        app_local_data_directory: PathBuf,
        service_prefix: String,
        cleanup_on_drop: bool,
    ) -> Result<Self, ApprovedMcpError> {
        validate_v031_cross_process_service_prefix(&service_prefix)?;
        let provider = Arc::new(WindowsApprovedMcpKeyProvider::with_service_prefix(
            service_prefix.clone(),
        ));
        let key_provider: Arc<dyn ApprovedMcpKeyProvider> = provider.clone();
        let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> =
            Arc::new(V031TargetWriterUnavailableQualification);
        let workspace = ApprovedMcpWorkspace::from_parts(
            app_local_data_directory,
            qualification,
            key_provider,
            None,
        );
        Ok(Self {
            workspace,
            provider,
            service_prefix,
            cleanup_on_drop,
        })
    }

    pub(crate) fn service_prefix(&self) -> &str {
        &self.service_prefix
    }

    pub(crate) fn credential_probe(&self) -> V031ApprovedMcpCredentialProbe {
        V031ApprovedMcpCredentialProbe::from_provider(self.provider.clone())
    }

    pub(crate) fn seed_v031_target_credentials_for_test(&self) -> Result<(), ApprovedMcpError> {
        for role in V031_TARGET_CREDENTIAL_ROLES {
            let mut key = self.provider.load_or_create(role)?;
            zeroize(&mut key);
        }
        Ok(())
    }

    pub(crate) fn recovery_credential_override_factory_for_test(
        &self,
    ) -> V031RecoveryCredentialOverrideFactory {
        let provider: Arc<dyn ApprovedMcpKeyProvider> = self.provider.clone();
        V031RecoveryCredentialOverrideFactory { provider }
    }

    pub(crate) fn install_recovery_credential_override_for_test(
        &self,
    ) -> Result<V031RecoveryCredentialOverrideGuard, ApprovedMcpError> {
        self.recovery_credential_override_factory_for_test()
            .install_on_current_thread()
    }

    pub(crate) fn load_or_create_privacy_receipt_signer_key(
        &self,
    ) -> Result<[u8; 32], ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        let credential_key = v031_cross_process_receipt_signer_credential_key();
        if let Some(secret) = self
            .provider
            .store
            .read_api_key(&credential_key)
            .map_err(|_| key_store_error())?
        {
            return decode_key(secret.expose_secret());
        }

        let mut key = [0_u8; 32];
        if let Err(error) = fill_random(&mut key) {
            zeroize(&mut key);
            return Err(error);
        }
        if key.iter().all(|byte| *byte == 0) {
            zeroize(&mut key);
            return Err(key_store_error());
        }
        let encoded = format!("{KEY_FORMAT_PREFIX}{}", URL_SAFE_NO_PAD.encode(key));
        if self
            .provider
            .store
            .write_api_key(&credential_key, ApiSecret::new(encoded))
            .is_err()
        {
            zeroize(&mut key);
            return Err(key_store_error());
        }
        Ok(key)
    }

    pub(crate) fn load_privacy_receipt_signer_key_read_only(
        &self,
    ) -> Result<[u8; 32], ApprovedMcpError> {
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        self.provider
            .store
            .read_api_key(&v031_cross_process_receipt_signer_credential_key())
            .map_err(|_| key_store_error())?
            .ok_or_else(key_store_error)
            .and_then(|secret| decode_key(secret.expose_secret()))
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ApprovedMcpError> {
        self.cleanup_exact_credentials()?;
        self.verify_all_credentials_absent()?;
        self.cleanup_on_drop = false;
        Ok(())
    }

    pub(crate) fn verify_all_credentials_absent_read_only_for_test(
        &self,
    ) -> Result<(), ApprovedMcpError> {
        self.verify_all_credentials_absent()
    }

    fn verify_all_credentials_absent(&self) -> Result<(), ApprovedMcpError> {
        for role in V031_TARGET_CREDENTIAL_ROLES {
            if let Some(mut key) = self.provider.load_existing(role)? {
                zeroize(&mut key);
                return Err(key_store_error());
            }
        }
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        if self
            .provider
            .store
            .read_api_key(&v031_cross_process_receipt_signer_credential_key())
            .map_err(|_| key_store_error())?
            .is_some()
        {
            return Err(key_store_error());
        }
        Ok(())
    }

    fn verify_all_credentials_present(&self) -> Result<(), ApprovedMcpError> {
        for role in V031_TARGET_CREDENTIAL_ROLES {
            let mut key = self
                .provider
                .load_existing(role)?
                .ok_or_else(key_store_error)?;
            zeroize(&mut key);
        }
        let mut receipt_signer = self.load_privacy_receipt_signer_key_read_only()?;
        zeroize(&mut receipt_signer);
        Ok(())
    }

    fn cleanup_exact_credentials(&self) -> Result<(), ApprovedMcpError> {
        validate_v031_cross_process_service_prefix(&self.service_prefix)?;
        let _store_lock = ProviderStoreLock::acquire().map_err(|_| key_store_error())?;
        for role in V031_TARGET_CREDENTIAL_ROLES {
            self.provider
                .store
                .delete_api_key(&ProviderCredentialKey::new(
                    role.provider_id(),
                    "user-boundary-v1",
                ))
                .map_err(|_| key_store_error())?;
        }
        self.provider
            .store
            .delete_api_key(&v031_cross_process_receipt_signer_credential_key())
            .map_err(|_| key_store_error())?;
        Ok(())
    }
}

#[cfg(test)]
impl Drop for V031CrossProcessCredentialHarness {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = self.cleanup_exact_credentials();
        }
    }
}

#[cfg(test)]
fn validate_v031_cross_process_service_prefix(
    service_prefix: &str,
) -> Result<(), ApprovedMcpError> {
    let suffix = service_prefix
        .strip_prefix(V031_CROSS_PROCESS_CREDENTIAL_PREFIX)
        .ok_or_else(key_store_error)?;
    let parsed = Uuid::parse_str(suffix).map_err(|_| key_store_error())?;
    if parsed.hyphenated().to_string() != suffix || service_prefix == KEY_SERVICE_PREFIX {
        return Err(key_store_error());
    }
    Ok(())
}

#[cfg(test)]
fn v031_cross_process_receipt_signer_credential_key() -> ProviderCredentialKey {
    ProviderCredentialKey::new(
        V031_CROSS_PROCESS_RECEIPT_SIGNER_PROVIDER,
        V031_CROSS_PROCESS_RECEIPT_SIGNER_ACCOUNT,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V031ComponentValidationMode {
    AllowIncomplete,
    RequireComplete,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031LayoutEntry {
    kind: &'static str,
    basename: String,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031SqliteSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql_sha256: String,
}

fn prepare_v031_credentials(
    provider: &dyn ApprovedMcpKeyProvider,
    failure_injector: &dyn V031ApprovedTargetWriterFailureInjector,
) -> Result<V031PreparedCredentialKeys, ApprovedMcpError> {
    // Construct the Drop-zeroized owner before the first provider call. Every
    // successful prefix, including an injected crash return, is therefore
    // cleared from process memory by the same owner rather than by best-effort
    // cleanup after the fact.
    let mut keys = V031PreparedCredentialKeys::zeroed();
    for (index, (role, destination)) in [
        (KeyRole::ApprovedManifest, &mut keys.approved_manifest),
        (
            KeyRole::WorkProductManifest,
            &mut keys.work_product_manifest,
        ),
        (KeyRole::McpTicket, &mut keys.mcp_ticket),
        (
            KeyRole::QualificationRevocationEpoch,
            &mut keys.qualification_revocation_epoch,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut prepared = load_or_create_v031_key(provider, role)?;
        destination.copy_from_slice(&prepared);
        zeroize(&mut prepared);
        failure_injector.after_credential_prefix(index + 1)?;
    }
    let distinct = [
        sha256_hex(&keys.approved_manifest),
        sha256_hex(&keys.work_product_manifest),
        sha256_hex(&keys.mcp_ticket),
        sha256_hex(&keys.qualification_revocation_epoch),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if distinct.len() != V031_TARGET_CREDENTIAL_ROLES.len() {
        return Err(v031_target_components_error());
    }
    Ok(keys)
}

fn load_v031_existing_credentials_read_only(
    provider: &dyn ApprovedMcpKeyProvider,
) -> Result<V031PreparedCredentialKeys, ApprovedMcpError> {
    let mut keys = V031PreparedCredentialKeys::zeroed();
    for (role, destination) in [
        (KeyRole::ApprovedManifest, &mut keys.approved_manifest),
        (
            KeyRole::WorkProductManifest,
            &mut keys.work_product_manifest,
        ),
        (KeyRole::McpTicket, &mut keys.mcp_ticket),
        (
            KeyRole::QualificationRevocationEpoch,
            &mut keys.qualification_revocation_epoch,
        ),
    ] {
        let mut existing = provider
            .load_existing(role)?
            .ok_or_else(v031_target_components_error)?;
        if existing.iter().all(|byte| *byte == 0) {
            zeroize(&mut existing);
            return Err(v031_target_components_error());
        }
        destination.copy_from_slice(&existing);
        zeroize(&mut existing);
    }
    let distinct = [
        sha256_hex(&keys.approved_manifest),
        sha256_hex(&keys.work_product_manifest),
        sha256_hex(&keys.mcp_ticket),
        sha256_hex(&keys.qualification_revocation_epoch),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if distinct.len() != V031_TARGET_CREDENTIAL_ROLES.len() {
        return Err(v031_target_components_error());
    }
    Ok(keys)
}

fn load_or_create_v031_key(
    provider: &dyn ApprovedMcpKeyProvider,
    role: KeyRole,
) -> Result<[u8; 32], ApprovedMcpError> {
    let mut prepared = provider.load_or_create(role)?;
    let readback = match provider.load_existing(role) {
        Ok(Some(readback)) => readback,
        Ok(None) => {
            zeroize(&mut prepared);
            return Err(v031_target_components_error());
        }
        Err(error) => {
            zeroize(&mut prepared);
            return Err(error);
        }
    };
    if prepared != readback || prepared.iter().all(|byte| *byte == 0) {
        zeroize(&mut prepared);
        let mut readback = readback;
        zeroize(&mut readback);
        return Err(v031_target_components_error());
    }
    let mut readback = readback;
    zeroize(&mut readback);
    Ok(prepared)
}

fn validate_v031_prepared_credentials(
    provider: &dyn ApprovedMcpKeyProvider,
    expected: &V031PreparedCredentialKeys,
) -> Result<(), ApprovedMcpError> {
    for (role, expected_key) in [
        (KeyRole::ApprovedManifest, &expected.approved_manifest),
        (
            KeyRole::WorkProductManifest,
            &expected.work_product_manifest,
        ),
        (KeyRole::McpTicket, &expected.mcp_ticket),
        (
            KeyRole::QualificationRevocationEpoch,
            &expected.qualification_revocation_epoch,
        ),
    ] {
        let mut actual = provider
            .load_existing(role)?
            .ok_or_else(v031_target_components_error)?;
        let matches = &actual == expected_key;
        zeroize(&mut actual);
        if !matches {
            return Err(v031_target_components_error());
        }
    }
    Ok(())
}

fn v031_credential_manifest_sha256(
    keys: &V031PreparedCredentialKeys,
) -> Result<String, ApprovedMcpError> {
    canonical_sha256(&[
        V031CredentialEvidence {
            role: KeyRole::ApprovedManifest.provider_id(),
            sha256: sha256_hex(&keys.approved_manifest),
        },
        V031CredentialEvidence {
            role: KeyRole::WorkProductManifest.provider_id(),
            sha256: sha256_hex(&keys.work_product_manifest),
        },
        V031CredentialEvidence {
            role: KeyRole::McpTicket.provider_id(),
            sha256: sha256_hex(&keys.mcp_ticket),
        },
        V031CredentialEvidence {
            role: KeyRole::QualificationRevocationEpoch.provider_id(),
            sha256: sha256_hex(&keys.qualification_revocation_epoch),
        },
    ])
}

fn validate_v031_app_root(app_local_data_directory: &Path) -> Result<(), ApprovedMcpError> {
    if !app_local_data_directory.is_absolute() {
        return Err(v031_target_components_error());
    }
    ensure_v031_plain_directory(app_local_data_directory)?;
    ensure_v031_plain_directory(&app_local_data_directory.join("privacy"))
}

fn validate_v031_approved_mcp_namespace(
    app_local_data_directory: &Path,
    mode: V031ComponentValidationMode,
    expected_workspace_instance_id: Option<&WorkspaceInstanceId>,
) -> Result<Option<(V031ComponentManifest, V031ComponentManifest)>, ApprovedMcpError> {
    validate_v031_app_root(app_local_data_directory)?;
    let root = app_local_data_directory
        .join("privacy")
        .join("approved-mcp");
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if mode == V031ComponentValidationMode::AllowIncomplete {
                Ok(None)
            } else {
                Err(v031_target_components_error())
            };
        }
        Err(_) => return Err(v031_target_components_error()),
        Ok(_) => ensure_v031_plain_directory(&root)?,
    }
    let allowed = BTreeSet::from([APPROVED_ROOT_NAME, WORK_PRODUCT_ROOT_NAME]);
    let present = enumerate_v031_basenames(&root)?;
    if present.iter().any(|name| !allowed.contains(name.as_str())) {
        return Err(v031_target_components_error());
    }

    let approved_root = root.join(APPROVED_ROOT_NAME);
    let work_products_root = root.join(WORK_PRODUCT_ROOT_NAME);
    let approved = validate_v031_approved_workspace(&approved_root, mode)?;
    let work_products =
        validate_v031_work_products(&work_products_root, mode, expected_workspace_instance_id)?;
    if enumerate_v031_basenames(&root)? != present {
        return Err(v031_target_components_error());
    }
    ensure_v031_plain_directory(&root)?;
    match (approved, work_products, mode) {
        (Some(approved), Some(work_products), _) => Ok(Some((approved, work_products))),
        (_, _, V031ComponentValidationMode::AllowIncomplete) => Ok(None),
        _ => Err(v031_target_components_error()),
    }
}

fn validate_v031_approved_workspace(
    root: &Path,
    mode: V031ComponentValidationMode,
) -> Result<Option<V031ComponentManifest>, ApprovedMcpError> {
    validate_v031_component_root(
        root,
        mode,
        &[".quarantine", ".staging", "cases"],
        &[
            ".approved-workspace-operation.lock",
            "workspace-state.sqlite",
            "workspace-state.sqlite-wal",
            "workspace-state.sqlite-shm",
            "workspace-state.sqlite-journal",
        ],
        &[
            ".approved-workspace-operation.lock",
            "workspace-state.sqlite",
        ],
        validate_v031_approved_database,
        "approved_workspace",
    )
}

fn validate_v031_work_products(
    root: &Path,
    mode: V031ComponentValidationMode,
    expected_workspace_instance_id: Option<&WorkspaceInstanceId>,
) -> Result<Option<V031ComponentManifest>, ApprovedMcpError> {
    validate_v031_component_root(
        root,
        mode,
        &[
            ".work-product-quarantine",
            ".work-product-staging",
            "work-products",
        ],
        &[
            "work-products.sqlite",
            "work-products.sqlite-wal",
            "work-products.sqlite-shm",
            "work-products.sqlite-journal",
        ],
        &["work-products.sqlite"],
        |database| validate_v031_work_products_database(database, expected_workspace_instance_id),
        "work_products",
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_v031_component_root(
    root: &Path,
    mode: V031ComponentValidationMode,
    directory_names: &[&str],
    file_names: &[&str],
    required_file_names: &[&str],
    validate_database: impl Fn(&Path) -> Result<(String, u64, u64, u64, String), ApprovedMcpError>,
    component: &'static str,
) -> Result<Option<V031ComponentManifest>, ApprovedMcpError> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if mode == V031ComponentValidationMode::AllowIncomplete {
                Ok(None)
            } else {
                Err(v031_target_components_error())
            };
        }
        Err(_) => return Err(v031_target_components_error()),
        Ok(_) => ensure_v031_plain_directory(root)?,
    }

    let allowed_directories = directory_names.iter().copied().collect::<BTreeSet<_>>();
    let allowed_files = file_names.iter().copied().collect::<BTreeSet<_>>();
    let basenames = enumerate_v031_basenames(root)?;
    if basenames.iter().any(|name| {
        !allowed_directories.contains(name.as_str()) && !allowed_files.contains(name.as_str())
    }) {
        return Err(v031_target_components_error());
    }
    let mut layout = Vec::new();
    for name in directory_names {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                ensure_v031_plain_directory(&path)?;
                if fs::read_dir(&path)
                    .map_err(|_| v031_target_components_error())?
                    .next()
                    .is_some()
                {
                    return Err(v031_target_components_nonempty_error());
                }
                layout.push(V031LayoutEntry {
                    kind: "directory",
                    basename: (*name).to_owned(),
                    bytes: None,
                    sha256: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if mode == V031ComponentValidationMode::RequireComplete {
                    return Err(v031_target_components_error());
                }
            }
            Err(_) => return Err(v031_target_components_error()),
        }
    }

    let mut database_path = None;
    let mut database_sha256 = None;
    for name in file_names {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let mut bytes = crate::v031_upgrade_r2::read_bounded_file(
                    &path,
                    MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES,
                )
                .map_err(|_| v031_target_components_error())?;
                if *name == ".approved-workspace-operation.lock" && !bytes.is_empty() {
                    zeroize(&mut bytes);
                    return Err(v031_target_components_error());
                }
                let digest = sha256_hex(&bytes);
                let length = bytes.len() as u64;
                zeroize(&mut bytes);
                if name.ends_with(".sqlite") {
                    database_path = Some(path);
                    database_sha256 = Some(digest.clone());
                }
                layout.push(V031LayoutEntry {
                    kind: "file",
                    basename: (*name).to_owned(),
                    bytes: Some(length),
                    sha256: Some(digest),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if mode == V031ComponentValidationMode::RequireComplete
                    && required_file_names.contains(name)
                {
                    return Err(v031_target_components_error());
                }
            }
            Err(_) => return Err(v031_target_components_error()),
        }
    }
    layout.sort_by(|left, right| left.basename.cmp(&right.basename));
    let Some(database_path) = database_path else {
        return if mode == V031ComponentValidationMode::AllowIncomplete {
            Ok(None)
        } else {
            Err(v031_target_components_error())
        };
    };
    let (schema_sha256, schema_objects, metadata_rows, business_rows, verified_database_sha256) =
        validate_database(&database_path)?;
    if database_sha256.as_deref() != Some(verified_database_sha256.as_str()) {
        return Err(v031_target_components_error());
    }
    if enumerate_v031_basenames(root)? != basenames {
        return Err(v031_target_components_error());
    }
    ensure_v031_plain_directory(root)?;
    for name in directory_names {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            ensure_v031_plain_directory(&path)?;
            if fs::read_dir(&path)
                .map_err(|_| v031_target_components_error())?
                .next()
                .is_some()
            {
                return Err(v031_target_components_nonempty_error());
            }
        }
    }
    for name in file_names {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            let mut bytes = crate::v031_upgrade_r2::read_bounded_file(
                &path,
                MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES,
            )
            .map_err(|_| v031_target_components_error())?;
            let expected = layout
                .iter()
                .find(|entry| entry.kind == "file" && entry.basename == *name)
                .ok_or_else(v031_target_components_error)?;
            let digest = sha256_hex(&bytes);
            let matches = expected.bytes == Some(bytes.len() as u64)
                && expected.sha256.as_deref() == Some(digest.as_str());
            zeroize(&mut bytes);
            if !matches {
                return Err(v031_target_components_error());
            }
        }
    }
    let directory_count = u64::try_from(
        layout
            .iter()
            .filter(|entry| entry.kind == "directory")
            .count(),
    )
    .map_err(|_| v031_target_components_error())?;
    let file_count = u64::try_from(layout.iter().filter(|entry| entry.kind == "file").count())
        .map_err(|_| v031_target_components_error())?;
    Ok(Some(V031ComponentManifest {
        component,
        schema_sha256,
        database_sha256: verified_database_sha256,
        layout_sha256: canonical_sha256(&layout)?,
        schema_objects,
        metadata_rows,
        business_rows,
        directory_count,
        file_count,
    }))
}

fn validate_v031_approved_database(
    path: &Path,
) -> Result<(String, u64, u64, u64, String), ApprovedMcpError> {
    validate_v031_component_database(
        path,
        V031_APPROVED_WORKSPACE_SCHEMA_SHA256,
        &["publication_journal", "publication_retention_cleanup"],
        "SELECT schema_version FROM workspace_meta WHERE singleton=1",
        None,
        None,
    )
}

fn validate_v031_work_products_database(
    path: &Path,
    expected_workspace_instance_id: Option<&WorkspaceInstanceId>,
) -> Result<(String, u64, u64, u64, String), ApprovedMcpError> {
    validate_v031_component_database(
        path,
        V031_WORK_PRODUCTS_SCHEMA_SHA256,
        &["work_product_versions", "work_product_retention_cleanup"],
        "SELECT schema_version FROM work_product_meta WHERE singleton=1",
        Some("SELECT workspace_instance_id FROM work_product_meta WHERE singleton=1"),
        expected_workspace_instance_id,
    )
}

fn validate_v031_component_database(
    path: &Path,
    expected_schema_sha256: &str,
    business_tables: &[&str],
    metadata_version_query: &str,
    workspace_query: Option<&str>,
    expected_workspace_instance_id: Option<&WorkspaceInstanceId>,
) -> Result<(String, u64, u64, u64, String), ApprovedMcpError> {
    let mut bytes_before =
        crate::v031_upgrade_r2::read_bounded_file(path, MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES)
            .map_err(|_| v031_target_components_error())?;
    let database_sha256 = sha256_hex(&bytes_before);
    let connection = Connection::open_with_flags(
        v031_immutable_sqlite_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| v031_target_components_error())?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| v031_target_components_error())?;
    if quick_check != "ok" {
        return Err(v031_target_components_error());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| v031_target_components_error())?;
    if foreign_keys
        .query([])
        .map_err(|_| v031_target_components_error())?
        .next()
        .map_err(|_| v031_target_components_error())?
        .is_some()
    {
        return Err(v031_target_components_error());
    }
    drop(foreign_keys);

    let schema = v031_sqlite_schema_objects(&connection)?;
    let schema_sha256 = canonical_sha256(&schema)?;
    if schema_sha256 != expected_schema_sha256 {
        return Err(v031_target_components_error());
    }
    let metadata_rows: i64 = connection
        .query_row(
            &format!("SELECT COUNT(*) FROM ({metadata_version_query}) WHERE schema_version=1"),
            [],
            |row| row.get(0),
        )
        .map_err(|_| v031_target_components_error())?;
    if metadata_rows != 1 {
        return Err(v031_target_components_error());
    }
    if let Some(query) = workspace_query {
        let workspace: String = connection
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| v031_target_components_error())?;
        if !is_workspace_id(&workspace)
            || expected_workspace_instance_id.is_some_and(|expected| workspace != expected.as_str())
        {
            return Err(v031_target_components_error());
        }
    }
    let mut business_rows = 0_u64;
    for table in business_tables {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(|_| v031_target_components_error())?;
        let count = u64::try_from(count).map_err(|_| v031_target_components_error())?;
        business_rows = business_rows
            .checked_add(count)
            .ok_or_else(v031_target_components_error)?;
    }
    drop(connection);
    let mut bytes_after =
        crate::v031_upgrade_r2::read_bounded_file(path, MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES)
            .map_err(|_| v031_target_components_error())?;
    let unchanged = bytes_before == bytes_after && sha256_hex(&bytes_after) == database_sha256;
    zeroize(&mut bytes_before);
    zeroize(&mut bytes_after);
    if !unchanged {
        return Err(v031_target_components_error());
    }
    Ok((
        schema_sha256,
        u64::try_from(schema.len()).map_err(|_| v031_target_components_error())?,
        u64::try_from(metadata_rows).map_err(|_| v031_target_components_error())?,
        business_rows,
        database_sha256,
    ))
}

fn v031_sqlite_schema_objects(
    connection: &Connection,
) -> Result<Vec<V031SqliteSchemaObject>, ApprovedMcpError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name",
        )
        .map_err(|_| v031_target_components_error())?;
    let rows = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok(V031SqliteSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql_sha256: sha256_hex(sql.as_bytes()),
            })
        })
        .map_err(|_| v031_target_components_error())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| v031_target_components_error())
}

fn v031_immutable_sqlite_uri(path: &Path) -> Result<String, ApprovedMcpError> {
    let canonical = fs::canonicalize(path).map_err(|_| v031_target_components_error())?;
    let raw = canonical
        .to_str()
        .ok_or_else(v031_target_components_error)?;
    let raw = raw.strip_prefix(r"\\?\").unwrap_or(raw).replace('\\', "/");
    let bytes = raw.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'/'
        || bytes[3..].contains(&b':')
    {
        return Err(v031_target_components_error());
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

fn enumerate_v031_basenames(root: &Path) -> Result<Vec<String>, ApprovedMcpError> {
    let mut output = fs::read_dir(root)
        .map_err(|_| v031_target_components_error())?
        .map(|entry| {
            entry
                .map_err(|_| v031_target_components_error())?
                .file_name()
                .into_string()
                .map_err(|_| v031_target_components_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    output.sort();
    Ok(output)
}

fn ensure_v031_plain_directory(path: &Path) -> Result<(), ApprovedMcpError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| v031_target_components_error())?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_dir()
    {
        return Err(v031_target_components_error());
    }
    Ok(())
}

fn sync_v031_component_storage(
    app_local_data_directory: &Path,
    approved_root: &Path,
    work_products_root: &Path,
) -> Result<(), ApprovedMcpError> {
    for path in [
        approved_root.join(".approved-workspace-operation.lock"),
        approved_root.join("workspace-state.sqlite"),
        work_products_root.join("work-products.sqlite"),
    ] {
        let mut verified = crate::v031_upgrade_r2::read_bounded_file(
            &path,
            MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES,
        )
        .map_err(|_| v031_target_components_error())?;
        zeroize(&mut verified);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|_| v031_target_components_error())?;
    }
    for directory in [
        approved_root.join("cases"),
        approved_root.join(".staging"),
        approved_root.join(".quarantine"),
        approved_root.to_path_buf(),
        work_products_root.join("work-products"),
        work_products_root.join(".work-product-staging"),
        work_products_root.join(".work-product-quarantine"),
        work_products_root.to_path_buf(),
        app_local_data_directory
            .join("privacy")
            .join("approved-mcp"),
        app_local_data_directory.join("privacy"),
        app_local_data_directory.to_path_buf(),
    ] {
        ensure_v031_plain_directory(&directory)?;
    }
    Ok(())
}

fn v031_target_components_gate(
    rollback_binding: &V031RollbackGateBinding,
    workspace_instance_id: WorkspaceInstanceId,
    keys: &V031PreparedCredentialKeys,
    approved_manifest: V031ComponentManifest,
    work_products_manifest: V031ComponentManifest,
) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
    rollback_binding.validate()?;
    if !is_workspace_id(workspace_instance_id.as_str())
        || workspace_instance_id.as_str() == rollback_binding.envelope_binding_id
    {
        return Err(v031_target_components_error());
    }
    if approved_manifest.business_rows != 0 || work_products_manifest.business_rows != 0 {
        return Err(v031_target_components_nonempty_error());
    }
    if approved_manifest.component != "approved_workspace"
        || approved_manifest.schema_sha256 != V031_APPROVED_WORKSPACE_SCHEMA_SHA256
        || approved_manifest.metadata_rows != 1
        || approved_manifest.directory_count != 3
        || approved_manifest.file_count != 2
        || work_products_manifest.component != "work_products"
        || work_products_manifest.schema_sha256 != V031_WORK_PRODUCTS_SCHEMA_SHA256
        || work_products_manifest.metadata_rows != 1
        || work_products_manifest.directory_count != 3
        || work_products_manifest.file_count != 1
    {
        return Err(v031_target_components_error());
    }

    let rollback_gate_binding_sha256 = rollback_binding.sha256()?;
    let credential_manifest_sha256 = v031_credential_manifest_sha256(keys)?;
    let approved_workspace_manifest_sha256 = canonical_sha256(&approved_manifest)?;
    let work_products_manifest_sha256 = canonical_sha256(&work_products_manifest)?;
    let credential_count = V031_TARGET_CREDENTIAL_ROLES.len() as u64;
    let evidence_sha256 = canonical_sha256(&V031TargetComponentsEvidence {
        schema_version: V031_TARGET_COMPONENTS_EVIDENCE_SCHEMA,
        rollback_gate_binding_sha256: &rollback_gate_binding_sha256,
        workspace_instance_id: workspace_instance_id.as_str(),
        credential_manifest_sha256: &credential_manifest_sha256,
        approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256,
        work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256,
        approved_workspace_manifest_sha256: &approved_workspace_manifest_sha256,
        work_products_manifest_sha256: &work_products_manifest_sha256,
        credential_count,
        approved_business_rows: approved_manifest.business_rows,
        work_product_business_rows: work_products_manifest.business_rows,
        ticket_session_count: 0,
        qualification_record_count: 0,
    })?;
    Ok(V031ApprovedMcpTargetComponentsGate {
        workspace_instance_id,
        rollback_gate_binding_sha256,
        credential_manifest_sha256,
        approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256.to_owned(),
        work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256.to_owned(),
        approved_workspace_manifest_sha256,
        work_products_manifest_sha256,
        evidence_sha256,
        credential_count,
        approved_business_rows: approved_manifest.business_rows,
        work_product_business_rows: work_products_manifest.business_rows,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, ApprovedMcpError> {
    let bytes = canonical_json_v1(value).map_err(|_| v031_target_components_error())?;
    Ok(sha256_hex(&bytes))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_workspace_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("ws_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn v031_target_components_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "v031_target_components_invalid",
        "The v0.3.1 target components are unavailable or inconsistent.",
    )
}

fn v031_target_components_nonempty_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "v031_target_components_nonempty",
        "The v0.3.1 target components contain unexpected application state.",
    )
}

fn startup_identity_missing_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_identity_missing_for_existing_state",
        "The local approved MCP identity is missing while application data already exists.",
    )
}

fn startup_identity_preflight_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_identity_preflight_failed",
        "The local application history could not be verified before approved MCP identity startup.",
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

pub(crate) enum StartupWorkspaceIdentityPreflight {
    Existing(WorkspaceInstanceId),
    Fresh { app_local_data_directory: PathBuf },
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
        #[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
        if let Some(credential_prefix) =
            crate::r3_current_binary_harness::credential_prefix_if_initialized()
        {
            return Self::new_with_r3_current_read_only_credentials(
                app_local_data_directory,
                credential_prefix,
            );
        }
        Self::new_with_binary(app_local_data_directory, installed_mcp_binary_path())
    }

    #[cfg(all(feature = "r3-real-current-binary-harness", not(test)))]
    fn new_with_r3_current_read_only_credentials(
        app_local_data_directory: PathBuf,
        credential_prefix: &str,
    ) -> Self {
        let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(
            R3CurrentReadOnlyApprovedMcpKeyProvider::new(credential_prefix),
        );
        let qualification_control =
            Arc::new(qualification::DesktopApprovedMcpQualificationProvider::new(
                app_local_data_directory
                    .join("privacy")
                    .join("approved-mcp")
                    .join("qualification"),
                Arc::clone(&keys),
                installed_mcp_binary_path(),
            ));
        Self::from_parts(
            app_local_data_directory,
            qualification_control.clone(),
            keys,
            Some(qualification_control),
        )
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
    ) -> Result<Self, ApprovedMcpError> {
        let service_prefix =
            legal_mcp::standalone_approved::standalone_mcp_e2e_credential_service_prefix()
                .map_err(|_| key_store_error())?;
        let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(
            WindowsApprovedMcpKeyProvider::with_service_prefix(service_prefix),
        );
        let qualification_control =
            Arc::new(qualification::DesktopApprovedMcpQualificationProvider::new(
                app_local_data_directory
                    .join("privacy")
                    .join("approved-mcp")
                    .join("qualification"),
                Arc::clone(&keys),
                binary_path,
            ));
        Ok(Self::from_parts(
            app_local_data_directory,
            qualification_control.clone(),
            keys,
            Some(qualification_control),
        ))
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

    fn startup_history_present_read_only(&self) -> Result<bool, ApprovedMcpError> {
        STARTUP_IDENTITY_PRIMARY_HISTORY_PATHS
            .iter()
            .chain(STARTUP_IDENTITY_RECOVERY_HISTORY_PATHS.iter())
            .try_fold(false, |history_present, relative| {
                let path = self.inner.app_local_data_directory.join(relative);
                match fs::symlink_metadata(path) {
                    Ok(metadata) => {
                        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            return Err(startup_identity_preflight_error());
                        }
                        Ok(true)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Ok(history_present)
                    }
                    Err(_) => Err(startup_identity_preflight_error()),
                }
            })
    }

    fn prepare_v031_target_components_with_binding(
        &self,
        rollback_binding: &V031RollbackGateBinding,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        self.prepare_v031_target_components_with_binding_and_failure_injector(
            rollback_binding,
            &NoV031ApprovedTargetWriterFailure,
        )
    }

    fn prepare_v031_target_components_with_binding_and_failure_injector(
        &self,
        rollback_binding: &V031RollbackGateBinding,
        failure_injector: &dyn V031ApprovedTargetWriterFailureInjector,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        // Classification is deliberately read-only.  The opaque observation is
        // then re-authenticated while holding the writer mutex before either a
        // durability-only sync or the resumable initializer becomes reachable.
        let observed =
            self.observe_v031_target_namespace_with_binding_read_only(rollback_binding)?;
        let _operation = self.operation()?;
        let reobserved =
            self.observe_v031_target_namespace_with_binding_locked_read_only(rollback_binding)?;
        if reobserved != observed {
            return Err(v031_target_components_error());
        }
        match reobserved {
            V031ApprovedMcpTargetNamespaceObservation::Complete(expected) => {
                sync_v031_component_storage(
                    &self.inner.app_local_data_directory,
                    &self.inner.approved_root,
                    &self.inner.work_product_root,
                )?;
                let loaded = self
                    .load_v031_target_components_with_binding_locked_read_only(rollback_binding)?;
                if loaded != expected {
                    return Err(v031_target_components_error());
                }
                Ok(loaded)
            }
            V031ApprovedMcpTargetNamespaceObservation::Incomplete(_) => self
                .write_v031_target_components_with_binding_locked(
                    rollback_binding,
                    failure_injector,
                ),
        }
    }

    fn write_v031_target_components_with_binding_locked(
        &self,
        rollback_binding: &V031RollbackGateBinding,
        failure_injector: &dyn V031ApprovedTargetWriterFailureInjector,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        rollback_binding.validate()?;
        validate_v031_app_root(&self.inner.app_local_data_directory)?;
        validate_v031_approved_mcp_namespace(
            &self.inner.app_local_data_directory,
            V031ComponentValidationMode::AllowIncomplete,
            None,
        )?;

        let keys = prepare_v031_credentials(self.inner.keys.as_ref(), failure_injector)?;
        let workspace_instance_id = workspace_instance_id(&keys.approved_manifest)?;
        if workspace_instance_id.as_str() == rollback_binding.envelope_binding_id {
            return Err(v031_target_components_error());
        }
        let credential_manifest_sha256 = v031_credential_manifest_sha256(&keys)?;

        let approved_signer = ManifestSigningKey::from_bytes(keys.approved_manifest, KEY_VERSION)
            .map_err(|_| v031_target_components_error())?;
        let approved_verifier = approved_signer.verification_key();
        let approved_publisher =
            WorkspacePublisher::initialize(&self.inner.approved_root, approved_signer)
                .map_err(|_| v031_target_components_error())?;
        drop(approved_publisher);
        let approved_service =
            ApprovedWorkspaceService::open(&self.inner.approved_root, approved_verifier)
                .map_err(|_| v031_target_components_error())?;
        if !approved_service
            .list_publication_history(None)
            .map_err(|_| v031_target_components_error())?
            .is_empty()
        {
            return Err(v031_target_components_nonempty_error());
        }
        drop(approved_service);
        failure_injector.after_approved_workspace_closed()?;

        let work_product_signer =
            ManifestSigningKey::from_bytes(keys.work_product_manifest, KEY_VERSION)
                .map_err(|_| v031_target_components_error())?;
        let work_product_verifier = work_product_signer.verification_key();
        let work_product_publisher = WorkProductPublisher::initialize(
            &self.inner.work_product_root,
            workspace_instance_id.clone(),
            work_product_signer,
        )
        .map_err(|_| v031_target_components_error())?;
        if work_product_publisher.workspace_instance_id() != &workspace_instance_id {
            return Err(v031_target_components_error());
        }
        drop(work_product_publisher);
        let work_product_service = WorkProductService::open(
            &self.inner.work_product_root,
            workspace_instance_id.clone(),
            work_product_verifier,
        )
        .map_err(|_| v031_target_components_error())?;
        if work_product_service.workspace_instance_id() != &workspace_instance_id {
            return Err(v031_target_components_error());
        }
        drop(work_product_service);
        failure_injector.after_work_products_closed_before_sync()?;

        sync_v031_component_storage(
            &self.inner.app_local_data_directory,
            &self.inner.approved_root,
            &self.inner.work_product_root,
        )?;
        validate_v031_prepared_credentials(self.inner.keys.as_ref(), &keys)?;
        let verified_credential_manifest_sha256 = v031_credential_manifest_sha256(&keys)?;
        if verified_credential_manifest_sha256 != credential_manifest_sha256 {
            return Err(v031_target_components_error());
        }

        let (approved_manifest, work_products_manifest) = validate_v031_approved_mcp_namespace(
            &self.inner.app_local_data_directory,
            V031ComponentValidationMode::RequireComplete,
            Some(&workspace_instance_id),
        )?
        .ok_or_else(v031_target_components_error)?;
        v031_target_components_gate(
            rollback_binding,
            workspace_instance_id,
            &keys,
            approved_manifest,
            work_products_manifest,
        )
    }

    fn load_v031_target_components_with_binding_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        let _operation = self.operation()?;
        self.load_v031_target_components_with_binding_locked_read_only(rollback_binding)
    }

    fn load_v031_target_components_with_binding_locked_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
        rollback_binding.validate()?;
        validate_v031_app_root(&self.inner.app_local_data_directory)?;

        let keys = load_v031_existing_credentials_read_only(self.inner.keys.as_ref())?;
        let workspace_instance_id = workspace_instance_id(&keys.approved_manifest)?;
        let (approved_manifest, work_products_manifest) = validate_v031_approved_mcp_namespace(
            &self.inner.app_local_data_directory,
            V031ComponentValidationMode::RequireComplete,
            Some(&workspace_instance_id),
        )?
        .ok_or_else(v031_target_components_error)?;
        validate_v031_prepared_credentials(self.inner.keys.as_ref(), &keys)?;
        v031_target_components_gate(
            rollback_binding,
            workspace_instance_id,
            &keys,
            approved_manifest,
            work_products_manifest,
        )
    }

    fn verify_v031_target_components_with_binding_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
        expected_gate: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), ApprovedMcpError> {
        let _operation = self.operation()?;
        self.verify_v031_target_components_with_binding_locked_read_only(
            rollback_binding,
            expected_gate,
        )
    }

    fn verify_v031_target_components_with_binding_locked_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
        expected_gate: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), ApprovedMcpError> {
        let observed =
            self.load_v031_target_components_with_binding_locked_read_only(rollback_binding)?;
        if &observed != expected_gate {
            return Err(v031_target_components_error());
        }
        Ok(())
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

/// Opaque proof for a legal, resumable prefix of the Step-3 Approved target
/// writer.  Credential values never escape; only their protected-store
/// digests and the fixed prefix length are retained for exact re-observation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ApprovedMcpTargetIncompleteGate {
    rollback_gate_binding_sha256: String,
    credential_sha256: [Option<String>; 4],
    approved_namespace_present: bool,
    workspace_instance_id: Option<WorkspaceInstanceId>,
    namespace_layout_sha256: String,
}

impl fmt::Debug for V031ApprovedMcpTargetIncompleteGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ApprovedMcpTargetIncompleteGate")
            .field(
                "credential_presence",
                &self.credential_sha256.each_ref().map(Option::is_some),
            )
            .field(
                "approved_namespace_present",
                &self.approved_namespace_present,
            )
            .field(
                "workspace_instance_id_present",
                &self.workspace_instance_id.is_some(),
            )
            .field("namespace_layout_sha256", &self.namespace_layout_sha256)
            .field(
                "rollback_gate_binding_sha256",
                &self.rollback_gate_binding_sha256,
            )
            .finish()
    }
}

impl V031ApprovedMcpTargetIncompleteGate {
    #[cfg(test)]
    pub(crate) fn credential_prefix_len(&self) -> usize {
        self.credential_sha256.iter().flatten().count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum V031ApprovedMcpTargetNamespaceObservation {
    Incomplete(V031ApprovedMcpTargetIncompleteGate),
    Complete(V031ApprovedMcpTargetComponentsGate),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031ApprovedMcpIncompleteLayoutEntry {
    relative_path: &'static str,
    kind: &'static str,
    bytes: Option<u64>,
    sha256: Option<String>,
}

/// Authenticates every state reachable before the Approved/work-products
/// writer returns.  The four Credential Manager entries must be a strict
/// production-order prefix.  No component path is legal until all four exist;
/// afterwards only the fixed `AllowIncomplete` layout is accepted.
pub(crate) fn observe_v031_approved_mcp_target_namespace_read_only(
    app_local_data_directory: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
) -> Result<V031ApprovedMcpTargetNamespaceObservation, ApprovedMcpError> {
    ApprovedMcpWorkspace::new(app_local_data_directory.to_path_buf())
        .observe_v031_target_namespace_with_binding_read_only(
            &V031RollbackGateBinding::from_verified_gate(rollback_gate),
        )
}

impl ApprovedMcpWorkspace {
    fn observe_v031_target_namespace_with_binding_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
    ) -> Result<V031ApprovedMcpTargetNamespaceObservation, ApprovedMcpError> {
        let _operation = self.operation()?;
        self.observe_v031_target_namespace_with_binding_locked_read_only(rollback_binding)
    }

    fn observe_v031_target_namespace_with_binding_locked_read_only(
        &self,
        rollback_binding: &V031RollbackGateBinding,
    ) -> Result<V031ApprovedMcpTargetNamespaceObservation, ApprovedMcpError> {
        rollback_binding.validate()?;
        validate_v031_app_root(&self.inner.app_local_data_directory)?;

        let before = application_restore_credential_digests(self.inner.keys.as_ref())?;
        let credential_prefix_len = validate_v031_credential_digest_prefix(&before)?;
        let rollback_gate_binding_sha256 = rollback_binding.sha256()?;
        let approved_namespace = self
            .inner
            .app_local_data_directory
            .join("privacy")
            .join("approved-mcp");
        let namespace_layout_before =
            v031_approved_mcp_incomplete_layout_sha256(&self.inner.app_local_data_directory)?;

        if credential_prefix_len < V031_TARGET_CREDENTIAL_ROLES.len() {
            match fs::symlink_metadata(&approved_namespace) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) | Ok(_) => return Err(v031_target_components_error()),
            }
            if application_restore_credential_digests(self.inner.keys.as_ref())? != before {
                return Err(v031_target_components_error());
            }
            let namespace_layout_after =
                v031_approved_mcp_incomplete_layout_sha256(&self.inner.app_local_data_directory)?;
            if namespace_layout_after != namespace_layout_before {
                return Err(v031_target_components_error());
            }
            return Ok(V031ApprovedMcpTargetNamespaceObservation::Incomplete(
                V031ApprovedMcpTargetIncompleteGate {
                    rollback_gate_binding_sha256,
                    credential_sha256: before,
                    approved_namespace_present: false,
                    workspace_instance_id: None,
                    namespace_layout_sha256: namespace_layout_after,
                },
            ));
        }

        let keys = load_v031_existing_credentials_read_only(self.inner.keys.as_ref())?;
        let workspace_instance_id = workspace_instance_id(&keys.approved_manifest)?;
        if workspace_instance_id.as_str() == rollback_binding.envelope_binding_id {
            return Err(v031_target_components_error());
        }
        let observed = validate_v031_approved_mcp_namespace(
            &self.inner.app_local_data_directory,
            V031ComponentValidationMode::AllowIncomplete,
            Some(&workspace_instance_id),
        )?;
        validate_v031_prepared_credentials(self.inner.keys.as_ref(), &keys)?;
        if application_restore_credential_digests(self.inner.keys.as_ref())? != before {
            return Err(v031_target_components_error());
        }
        let namespace_layout_after =
            v031_approved_mcp_incomplete_layout_sha256(&self.inner.app_local_data_directory)?;
        if namespace_layout_after != namespace_layout_before {
            return Err(v031_target_components_error());
        }

        let Some((approved_manifest, work_products_manifest)) = observed else {
            return Ok(V031ApprovedMcpTargetNamespaceObservation::Incomplete(
                V031ApprovedMcpTargetIncompleteGate {
                    rollback_gate_binding_sha256,
                    credential_sha256: before,
                    approved_namespace_present: fs::symlink_metadata(&approved_namespace).is_ok(),
                    workspace_instance_id: Some(workspace_instance_id),
                    namespace_layout_sha256: namespace_layout_after,
                },
            ));
        };
        if approved_manifest.directory_count != 3
            || approved_manifest.file_count != 2
            || work_products_manifest.directory_count != 3
            || work_products_manifest.file_count != 1
        {
            return Ok(V031ApprovedMcpTargetNamespaceObservation::Incomplete(
                V031ApprovedMcpTargetIncompleteGate {
                    rollback_gate_binding_sha256,
                    credential_sha256: before,
                    approved_namespace_present: true,
                    workspace_instance_id: Some(workspace_instance_id),
                    namespace_layout_sha256: namespace_layout_after,
                },
            ));
        }
        Ok(V031ApprovedMcpTargetNamespaceObservation::Complete(
            v031_target_components_gate(
                rollback_binding,
                workspace_instance_id,
                &keys,
                approved_manifest,
                work_products_manifest,
            )?,
        ))
    }
}

fn v031_approved_mcp_incomplete_layout_sha256(
    app_local_data_directory: &Path,
) -> Result<String, ApprovedMcpError> {
    let approved_mcp_root = app_local_data_directory
        .join("privacy")
        .join("approved-mcp");
    let fixed_paths = [
        (".", approved_mcp_root.clone()),
        (
            "approved-generations",
            approved_mcp_root.join(APPROVED_ROOT_NAME),
        ),
        (
            "approved-generations/.quarantine",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join(".quarantine"),
        ),
        (
            "approved-generations/.staging",
            approved_mcp_root.join(APPROVED_ROOT_NAME).join(".staging"),
        ),
        (
            "approved-generations/cases",
            approved_mcp_root.join(APPROVED_ROOT_NAME).join("cases"),
        ),
        (
            "approved-generations/.approved-workspace-operation.lock",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join(".approved-workspace-operation.lock"),
        ),
        (
            "approved-generations/workspace-state.sqlite",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join("workspace-state.sqlite"),
        ),
        (
            "approved-generations/workspace-state.sqlite-wal",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join("workspace-state.sqlite-wal"),
        ),
        (
            "approved-generations/workspace-state.sqlite-shm",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join("workspace-state.sqlite-shm"),
        ),
        (
            "approved-generations/workspace-state.sqlite-journal",
            approved_mcp_root
                .join(APPROVED_ROOT_NAME)
                .join("workspace-state.sqlite-journal"),
        ),
        (
            "work-products",
            approved_mcp_root.join(WORK_PRODUCT_ROOT_NAME),
        ),
        (
            "work-products/.work-product-quarantine",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join(".work-product-quarantine"),
        ),
        (
            "work-products/.work-product-staging",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join(".work-product-staging"),
        ),
        (
            "work-products/work-products",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join("work-products"),
        ),
        (
            "work-products/work-products.sqlite",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join("work-products.sqlite"),
        ),
        (
            "work-products/work-products.sqlite-wal",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join("work-products.sqlite-wal"),
        ),
        (
            "work-products/work-products.sqlite-shm",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join("work-products.sqlite-shm"),
        ),
        (
            "work-products/work-products.sqlite-journal",
            approved_mcp_root
                .join(WORK_PRODUCT_ROOT_NAME)
                .join("work-products.sqlite-journal"),
        ),
    ];
    let mut entries = Vec::with_capacity(fixed_paths.len());
    for (relative_path, path) in fixed_paths {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                entries.push(V031ApprovedMcpIncompleteLayoutEntry {
                    relative_path,
                    kind: "absent",
                    bytes: None,
                    sha256: None,
                });
            }
            Err(_) => return Err(v031_target_components_error()),
            Ok(metadata) if metadata.is_dir() => {
                ensure_v031_plain_directory(&path)?;
                entries.push(V031ApprovedMcpIncompleteLayoutEntry {
                    relative_path,
                    kind: "directory",
                    bytes: None,
                    sha256: None,
                });
            }
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
            {
                let mut bytes = crate::v031_upgrade_r2::read_bounded_file(
                    &path,
                    MAX_V031_EMPTY_COMPONENT_DATABASE_BYTES,
                )
                .map_err(|_| v031_target_components_error())?;
                let length = bytes.len() as u64;
                let digest = sha256_hex(&bytes);
                zeroize(&mut bytes);
                entries.push(V031ApprovedMcpIncompleteLayoutEntry {
                    relative_path,
                    kind: "file",
                    bytes: Some(length),
                    sha256: Some(digest),
                });
            }
            Ok(_) => return Err(v031_target_components_error()),
        }
    }
    canonical_sha256(&entries)
}

fn validate_v031_credential_digest_prefix(
    digests: &[Option<String>; 4],
) -> Result<usize, ApprovedMcpError> {
    let mut saw_absent = false;
    let mut present = BTreeSet::new();
    let mut count = 0;
    for digest in digests {
        match digest {
            Some(digest) if !saw_absent && is_lower_sha256(digest) => {
                if !present.insert(digest) {
                    return Err(v031_target_components_error());
                }
                count += 1;
            }
            Some(_) => return Err(v031_target_components_error()),
            None => saw_absent = true,
        }
    }
    Ok(count)
}

#[cfg(test)]
mod v031_recovery_credential_boundary_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct RecoveryCredentialTestProvider {
        keys: Mutex<[Option<[u8; 32]>; 4]>,
        load_calls: AtomicUsize,
        write_order: Mutex<Vec<KeyRole>>,
        delete_order: Mutex<Vec<KeyRole>>,
    }

    impl RecoveryCredentialTestProvider {
        fn full() -> Self {
            Self {
                keys: Mutex::new(std::array::from_fn(|index| Some([(index + 1) as u8; 32]))),
                load_calls: AtomicUsize::new(0),
                write_order: Mutex::new(Vec::new()),
                delete_order: Mutex::new(Vec::new()),
            }
        }

        fn set(&self, role: KeyRole, value: Option<[u8; 32]>) {
            let mut keys = self.keys.lock().expect("recovery credential test keys");
            if let Some(mut old) =
                keys[v031_recovery_credential_role_index(role)].replace(value.unwrap_or([0_u8; 32]))
            {
                zeroize(&mut old);
            }
            if value.is_none() {
                keys[v031_recovery_credential_role_index(role)] = None;
            }
        }

        fn is_absent(&self, role: KeyRole) -> bool {
            self.keys.lock().expect("recovery credential test keys")
                [v031_recovery_credential_role_index(role)]
            .is_none()
        }
    }

    impl Drop for RecoveryCredentialTestProvider {
        fn drop(&mut self) {
            if let Ok(keys) = self.keys.get_mut() {
                for key in keys.iter_mut().flatten() {
                    zeroize(key);
                }
            }
        }
    }

    impl ApprovedMcpKeyProvider for RecoveryCredentialTestProvider {
        fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            self.keys
                .lock()
                .map(|keys| keys[v031_recovery_credential_role_index(role)])
                .map_err(|_| key_store_error())
        }

        fn load_or_create(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            panic!("R3 recovery boundary must not generate a credential")
        }

        fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            panic!("R3 recovery boundary must not rotate a credential")
        }

        fn write_exact(&self, role: KeyRole, expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
            if expected.iter().all(|byte| *byte == 0) {
                return Err(key_store_error());
            }
            let mut keys = self.keys.lock().map_err(|_| key_store_error())?;
            let slot = &mut keys[v031_recovery_credential_role_index(role)];
            match slot {
                Some(existing) if existing != expected => return Err(key_store_error()),
                Some(_) => return Ok(()),
                None => *slot = Some(*expected),
            }
            self.write_order
                .lock()
                .map_err(|_| key_store_error())?
                .push(role);
            if slot.as_ref() != Some(expected) {
                return Err(key_store_error());
            }
            Ok(())
        }

        fn delete_exact(&self, role: KeyRole, expected: &[u8; 32]) -> Result<(), ApprovedMcpError> {
            let mut keys = self.keys.lock().map_err(|_| key_store_error())?;
            let slot = &mut keys[v031_recovery_credential_role_index(role)];
            let Some(mut existing) = slot.take() else {
                return Ok(());
            };
            if &existing != expected {
                *slot = Some(existing);
                return Err(key_store_error());
            }
            zeroize(&mut existing);
            self.delete_order
                .lock()
                .map_err(|_| key_store_error())?
                .push(role);
            if slot.is_some() {
                return Err(key_store_error());
            }
            Ok(())
        }
    }

    #[test]
    fn recovery_snapshot_is_repeatable_canonical_opaque_and_zeroizing() {
        let provider = RecoveryCredentialTestProvider::full();
        let mut snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&provider).expect("capture");
        assert_eq!(provider.load_calls.load(Ordering::SeqCst), 8);
        authenticate_v031_recovery_approved_mcp_credentials_with(&provider, &snapshot)
            .expect("repeatable readback");
        assert_eq!(provider.load_calls.load(Ordering::SeqCst), 16);
        let mut plaintext = snapshot
            .to_canonical_archive_plaintext()
            .expect("canonical plaintext");
        let decoded = V031ApprovedMcpCredentialSnapshot::from_canonical_archive_plaintext(
            plaintext.as_bytes(),
        )
        .expect("canonical plaintext decodes");
        assert!(snapshot.matches(&decoded));
        let wire: Value = serde_json::from_slice(plaintext.as_bytes()).expect("archive JSON");
        assert_eq!(
            wire["credentials"]
                .as_array()
                .expect("credential array")
                .iter()
                .map(|entry| entry["role"].as_str().expect("role"))
                .collect::<Vec<_>>(),
            V031_TARGET_CREDENTIAL_ROLES
                .iter()
                .map(|role| role.provider_id())
                .collect::<Vec<_>>()
        );
        assert!(format!("{snapshot:?}").contains("<redacted>"));
        assert!(format!("{plaintext:?}").contains("<redacted>"));

        let mut noncanonical = Vec::with_capacity(plaintext.as_bytes().len() + 1);
        noncanonical.push(b' ');
        noncanonical.extend_from_slice(plaintext.as_bytes());
        assert!(
            V031ApprovedMcpCredentialSnapshot::from_canonical_archive_plaintext(&noncanonical)
                .is_err()
        );
        zeroize(&mut noncanonical);

        snapshot.clear_for_test();
        plaintext.clear_for_test();
        assert!(snapshot.is_cleared_for_test());
        assert!(plaintext.is_cleared_for_test());
    }

    #[test]
    fn recovery_delete_advances_only_the_frozen_exact_prefix() {
        let provider = RecoveryCredentialTestProvider::full();
        let snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&provider).expect("capture");
        let mut gate =
            observe_v031_recovery_approved_mcp_credential_delete_prefix_with(&provider, &snapshot)
                .expect("initial prefix");
        let stale = gate.clone();
        assert_eq!(gate.prefix_len(), 0);
        for expected_prefix in 1..=V031_RECOVERY_CREDENTIAL_DELETE_ROLES.len() {
            gate = advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
                &provider, &snapshot, &gate,
            )
            .expect("advance one exact prefix");
            assert_eq!(gate.prefix_len(), expected_prefix);
            assert_eq!(
                observe_v031_recovery_approved_mcp_credential_delete_prefix_with(
                    &provider, &snapshot
                )
                .expect("idempotent prefix read"),
                gate
            );
        }
        assert_eq!(
            *provider.delete_order.lock().expect("delete order"),
            V031_RECOVERY_CREDENTIAL_DELETE_ROLES
        );
        assert!(
            advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
                &provider, &snapshot, &stale
            )
            .is_err()
        );
        assert_eq!(provider.delete_order.lock().expect("delete order").len(), 4);
    }

    #[test]
    fn recovery_delete_rejects_holes_and_conflicts_before_mutation() {
        let partial = RecoveryCredentialTestProvider::full();
        let snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&partial).expect("capture");
        partial.set(KeyRole::QualificationRevocationEpoch, None);
        partial.set(KeyRole::McpTicket, None);
        assert_eq!(
            observe_v031_recovery_approved_mcp_credential_delete_prefix_with(&partial, &snapshot)
                .expect("legal partial delete")
                .prefix_len(),
            2
        );

        let hole = RecoveryCredentialTestProvider::full();
        let hole_snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&hole).expect("capture hole");
        hole.set(KeyRole::McpTicket, None);
        assert!(
            observe_v031_recovery_approved_mcp_credential_delete_prefix_with(&hole, &hole_snapshot)
                .is_err()
        );
        assert!(hole
            .delete_order
            .lock()
            .expect("hole delete order")
            .is_empty());

        let conflict = RecoveryCredentialTestProvider::full();
        let conflict_snapshot = capture_v031_recovery_approved_mcp_credentials_with(&conflict)
            .expect("capture conflict");
        conflict.set(KeyRole::WorkProductManifest, Some([9_u8; 32]));
        let forged_current = V031ApprovedMcpCredentialDeletePrefixGate {
            prefix_len: 0,
            snapshot_binding_sha256: conflict_snapshot
                .binding_sha256()
                .expect("snapshot binding"),
        };
        assert!(
            advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
                &conflict,
                &conflict_snapshot,
                &forged_current
            )
            .is_err()
        );
        assert!(conflict
            .delete_order
            .lock()
            .expect("conflict delete order")
            .is_empty());
    }

    #[test]
    fn recovery_restore_is_exact_idempotent_and_uses_creation_order() {
        let provider = RecoveryCredentialTestProvider::full();
        let snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&provider).expect("capture");
        let mut gate =
            observe_v031_recovery_approved_mcp_credential_delete_prefix_with(&provider, &snapshot)
                .expect("initial prefix");
        while gate.prefix_len() < V031_RECOVERY_CREDENTIAL_DELETE_ROLES.len() {
            gate = advance_v031_recovery_approved_mcp_credential_delete_prefix_with(
                &provider, &snapshot, &gate,
            )
            .expect("delete all");
        }
        restore_v031_recovery_approved_mcp_credentials_exact_with(&provider, &snapshot)
            .expect("restore all");
        assert_eq!(
            *provider.write_order.lock().expect("write order"),
            V031_TARGET_CREDENTIAL_ROLES
        );
        restore_v031_recovery_approved_mcp_credentials_exact_with(&provider, &snapshot)
            .expect("idempotent restore");
        assert_eq!(provider.write_order.lock().expect("write order").len(), 4);

        let partial = RecoveryCredentialTestProvider::full();
        let partial_snapshot =
            capture_v031_recovery_approved_mcp_credentials_with(&partial).expect("partial capture");
        partial.set(KeyRole::ApprovedManifest, None);
        partial.set(KeyRole::McpTicket, None);
        restore_v031_recovery_approved_mcp_credentials_exact_with(&partial, &partial_snapshot)
            .expect("arbitrary crash prefix restores");
        assert_eq!(
            *partial.write_order.lock().expect("partial write order"),
            [KeyRole::ApprovedManifest, KeyRole::McpTicket]
        );

        let conflict = RecoveryCredentialTestProvider::full();
        let conflict_snapshot = capture_v031_recovery_approved_mcp_credentials_with(&conflict)
            .expect("conflict capture");
        conflict.set(KeyRole::ApprovedManifest, None);
        conflict.set(KeyRole::WorkProductManifest, Some([9_u8; 32]));
        assert!(restore_v031_recovery_approved_mcp_credentials_exact_with(
            &conflict,
            &conflict_snapshot
        )
        .is_err());
        assert!(conflict
            .write_order
            .lock()
            .expect("conflict write order")
            .is_empty());
        assert!(conflict.is_absent(KeyRole::ApprovedManifest));
    }

    #[test]
    fn recovery_mutation_methods_fail_closed_by_default() {
        struct ReadOnlyDefaults;

        impl ApprovedMcpKeyProvider for ReadOnlyDefaults {
            fn load_existing(&self, _role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
                Ok(Some([1_u8; 32]))
            }

            fn load_or_create(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
                Err(key_store_error())
            }

            fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
                Err(key_store_error())
            }
        }

        let provider = ReadOnlyDefaults;
        assert!(provider
            .write_exact(KeyRole::ApprovedManifest, &[1_u8; 32])
            .is_err());
        assert!(provider
            .delete_exact(KeyRole::ApprovedManifest, &[1_u8; 32])
            .is_err());
    }
}

#[cfg(test)]
mod v031_target_credential_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct UnavailableQualification;

    impl ApprovedWorkspaceQualificationProvider for UnavailableQualification {
        fn current_qualification(
            &self,
            _now_unix: u64,
        ) -> Result<
            ApprovedMcpQualificationSnapshotV1,
            legal_mcp::approved_backend::ApprovedWorkspaceQualificationError,
        > {
            Err(legal_mcp::approved_backend::ApprovedWorkspaceQualificationError::Unavailable)
        }
    }

    #[derive(Default)]
    struct DeterministicKeyProvider {
        keys: Mutex<BTreeMap<&'static str, [u8; 32]>>,
        load_existing_calls: AtomicUsize,
        load_or_create_calls: AtomicUsize,
        creation_count: AtomicUsize,
        rotate_calls: AtomicUsize,
    }

    impl DeterministicKeyProvider {
        fn key_for(role: KeyRole) -> [u8; 32] {
            let byte = match role {
                KeyRole::ApprovedManifest => 1,
                KeyRole::WorkProductManifest => 2,
                KeyRole::McpTicket => 3,
                KeyRole::QualificationRevocationEpoch => 4,
            };
            [byte; 32]
        }

        fn key_count(&self) -> usize {
            self.keys.lock().expect("test key lock").len()
        }
    }

    impl ApprovedMcpKeyProvider for DeterministicKeyProvider {
        fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
            self.load_existing_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .keys
                .lock()
                .map_err(|_| key_store_error())?
                .get(role.provider_id())
                .copied())
        }

        fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            self.load_or_create_calls.fetch_add(1, Ordering::SeqCst);
            let mut keys = self.keys.lock().map_err(|_| key_store_error())?;
            if let Some(key) = keys.get(role.provider_id()) {
                return Ok(*key);
            }
            let key = Self::key_for(role);
            keys.insert(role.provider_id(), key);
            self.creation_count.fetch_add(1, Ordering::SeqCst);
            Ok(key)
        }

        fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            self.rotate_calls.fetch_add(1, Ordering::SeqCst);
            Err(key_store_error())
        }
    }

    struct TargetComponentFixture {
        _directory: tempfile::TempDir,
        app_root: PathBuf,
        workspace: ApprovedMcpWorkspace,
        keys: Arc<DeterministicKeyProvider>,
        rollback_binding: V031RollbackGateBinding,
    }

    impl TargetComponentFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("target component root");
            let app_root = directory.path().to_path_buf();
            fs::create_dir(app_root.join("privacy")).expect("privacy parent");
            let keys = Arc::new(DeterministicKeyProvider::default());
            let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> =
                Arc::new(UnavailableQualification);
            let key_provider: Arc<dyn ApprovedMcpKeyProvider> = keys.clone();
            let workspace = ApprovedMcpWorkspace::from_parts(
                app_root.clone(),
                qualification,
                key_provider,
                None,
            );
            Self {
                _directory: directory,
                app_root,
                workspace,
                keys,
                rollback_binding: V031RollbackGateBinding {
                    lineage_id: "a".repeat(64),
                    envelope_binding_id: format!("ws_{}", "b".repeat(32)),
                    source_profile_proof_sha256: "c".repeat(64),
                    original_identity_sha256: "d".repeat(64),
                    original_bundle_sha256: "e".repeat(64),
                    original_rollback_receipt_sha256: "f".repeat(64),
                },
            }
        }

        fn prepare(&self) -> Result<V031ApprovedMcpTargetComponentsGate, ApprovedMcpError> {
            self.workspace
                .prepare_v031_target_components_with_binding(&self.rollback_binding)
        }

        fn approved_mcp_root(&self) -> PathBuf {
            self.app_root.join("privacy").join("approved-mcp")
        }
    }

    struct ReadOnlyProbe {
        present_provider: Option<&'static str>,
        write_calls: AtomicUsize,
    }

    impl ApprovedMcpKeyProvider for ReadOnlyProbe {
        fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
            Ok((self.present_provider == Some(role.provider_id())).then_some([7_u8; 32]))
        }

        fn load_or_create(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            Err(key_store_error())
        }

        fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            Err(key_store_error())
        }
    }

    #[test]
    fn v031_credential_absence_uses_only_four_read_queries() {
        let probe = ReadOnlyProbe {
            present_provider: None,
            write_calls: AtomicUsize::new(0),
        };
        assert_eq!(
            verify_v031_target_credentials_absent_with(&probe).unwrap(),
            4
        );
        assert_eq!(probe.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_credential_presence_fails_without_repair_or_rotation() {
        let probe = ReadOnlyProbe {
            present_provider: Some("mcp-access-ticket"),
            write_calls: AtomicUsize::new(0),
        };
        assert_eq!(
            verify_v031_target_credentials_absent_with(&probe)
                .unwrap_err()
                .code(),
            "v031_upgrade_target_credential_present"
        );
        assert_eq!(probe.write_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(windows)]
    #[test]
    fn v031_cross_process_credentials_reopen_under_one_unique_prefix_and_cleanup_exactly() {
        let root = tempfile::tempdir().expect("cross-process credential fixture");
        let mut parent =
            V031CrossProcessCredentialHarness::create_parent(root.path().to_path_buf())
                .expect("unique parent credential namespace creates");
        let service_prefix = parent.service_prefix().to_owned();
        assert!(service_prefix.starts_with(V031_CROSS_PROCESS_CREDENTIAL_PREFIX));
        assert_ne!(service_prefix, KEY_SERVICE_PREFIX);

        for role in V031_TARGET_CREDENTIAL_ROLES {
            let mut key = parent
                .provider
                .load_or_create(role)
                .expect("parent Approved credential creates");
            zeroize(&mut key);
        }
        let mut parent_receipt_signer = parent
            .load_or_create_privacy_receipt_signer_key()
            .expect("parent receipt signer creates");
        let parent_digests = application_restore_credential_digests(parent.provider.as_ref())
            .expect("parent credential digests read");

        let child = V031CrossProcessCredentialHarness::reopen_child(
            root.path().to_path_buf(),
            &service_prefix,
        )
        .expect("a separately constructed child harness reopens every credential");
        assert_eq!(
            application_restore_credential_digests(child.provider.as_ref())
                .expect("child credential digests read"),
            parent_digests
        );
        let mut child_receipt_signer = child
            .load_privacy_receipt_signer_key_read_only()
            .expect("child receipt signer reopens read-only");
        assert_eq!(child_receipt_signer, parent_receipt_signer);
        zeroize(&mut child_receipt_signer);
        zeroize(&mut parent_receipt_signer);
        drop(child);

        parent
            .cleanup()
            .expect("the parent removes only its five unique credentials");
        parent
            .verify_all_credentials_absent_read_only_for_test()
            .expect("all four Approved keys and the Privacy signer are absent");
        assert!(V031CrossProcessCredentialHarness::reopen_child(
            root.path().to_path_buf(),
            &service_prefix,
        )
        .is_err());
    }

    #[test]
    fn v031_target_components_fresh_and_resume_are_empty_and_idempotent() {
        let fixture = TargetComponentFixture::new();
        let first = fixture.prepare().expect("fresh target components");

        assert!(is_workspace_id(first.workspace_instance_id().as_str()));
        assert_ne!(
            first.workspace_instance_id().as_str(),
            fixture.rollback_binding.envelope_binding_id
        );
        assert_eq!(first.credential_count(), 4);
        assert_eq!(first.approved_business_rows(), 0);
        assert_eq!(first.work_product_business_rows(), 0);
        for hash in [
            first.rollback_gate_binding_sha256(),
            first.credential_manifest_sha256(),
            first.approved_workspace_manifest_sha256(),
            first.work_products_manifest_sha256(),
            first.evidence_sha256(),
        ] {
            assert!(is_lower_sha256(hash));
        }
        assert_eq!(fixture.keys.key_count(), 4);
        assert_eq!(fixture.keys.creation_count.load(Ordering::SeqCst), 4);
        assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            enumerate_v031_basenames(&fixture.approved_mcp_root()).expect("target namespace"),
            vec![
                APPROVED_ROOT_NAME.to_owned(),
                WORK_PRODUCT_ROOT_NAME.to_owned()
            ]
        );
        assert!(!fixture.approved_mcp_root().join(TICKET_ROOT_NAME).exists());
        assert!(!fixture.approved_mcp_root().join("qualification").exists());

        let load_or_create_before_resume = fixture.keys.load_or_create_calls.load(Ordering::SeqCst);
        let second = fixture.prepare().expect("resumed target components");
        assert_eq!(second, first);
        assert_eq!(fixture.keys.key_count(), 4);
        assert_eq!(fixture.keys.creation_count.load(Ordering::SeqCst), 4);
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            load_or_create_before_resume,
            "a committed target retry must not invoke a credential-creating API"
        );
        assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn historical_gate2_recomputes_credentials_and_rejects_drift_without_writes() {
        let fixture = TargetComponentFixture::new();
        let gate = fixture.prepare().expect("fresh target components");
        let record = V031ApprovedMcpHistoricalTargetRecord {
            workspace_instance_id: gate.workspace_instance_id().clone(),
            credential_manifest_sha256: gate.credential_manifest_sha256().to_owned(),
            approved_workspace_schema_sha256: gate.approved_workspace_schema_sha256().to_owned(),
            work_products_schema_sha256: gate.work_products_schema_sha256().to_owned(),
            approved_workspace_manifest_sha256: gate
                .approved_workspace_manifest_sha256()
                .to_owned(),
            work_products_manifest_sha256: gate.work_products_manifest_sha256().to_owned(),
            evidence_sha256: gate.evidence_sha256().to_owned(),
            credential_count: gate.credential_count(),
            approved_business_rows: gate.approved_business_rows(),
            work_product_business_rows: gate.work_product_business_rows(),
        };
        let files_before = enumerate_v031_basenames(&fixture.approved_mcp_root())
            .expect("historical namespace before");
        let create_before = fixture.keys.load_or_create_calls.load(Ordering::SeqCst);
        let rotate_before = fixture.keys.rotate_calls.load(Ordering::SeqCst);
        assert_eq!(
            load_v031_approved_mcp_historical_target_with_binding_read_only(
                &fixture.workspace,
                &fixture.rollback_binding,
                &record,
            )
            .expect("historical Gate2 reconstructs"),
            gate
        );

        fixture
            .keys
            .keys
            .lock()
            .expect("test key lock")
            .insert(KeyRole::McpTicket.provider_id(), [9_u8; 32]);
        assert!(
            load_v031_approved_mcp_historical_target_with_binding_read_only(
                &fixture.workspace,
                &fixture.rollback_binding,
                &record,
            )
            .is_err()
        );
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            create_before
        );
        assert_eq!(
            fixture.keys.rotate_calls.load(Ordering::SeqCst),
            rotate_before
        );
        assert_eq!(
            enumerate_v031_basenames(&fixture.approved_mcp_root())
                .expect("historical namespace after"),
            files_before
        );
    }

    #[test]
    fn v031_target_components_live_verifier_is_read_only_and_binds_expected_gate() {
        let fixture = TargetComponentFixture::new();
        let gate = fixture.prepare().expect("fresh target components");
        let approved_database = fixture
            .approved_mcp_root()
            .join(APPROVED_ROOT_NAME)
            .join("workspace-state.sqlite");
        let work_products_database = fixture
            .approved_mcp_root()
            .join(WORK_PRODUCT_ROOT_NAME)
            .join("work-products.sqlite");
        let approved_before = fs::read(&approved_database).expect("approved database before");
        let work_products_before =
            fs::read(&work_products_database).expect("work products database before");
        let namespace_before =
            enumerate_v031_basenames(&fixture.approved_mcp_root()).expect("namespace before");
        let load_existing_before = fixture.keys.load_existing_calls.load(Ordering::SeqCst);
        let load_or_create_before = fixture.keys.load_or_create_calls.load(Ordering::SeqCst);
        let creation_before = fixture.keys.creation_count.load(Ordering::SeqCst);
        let rotate_before = fixture.keys.rotate_calls.load(Ordering::SeqCst);

        fixture
            .workspace
            .verify_v031_target_components_with_binding_read_only(&fixture.rollback_binding, &gate)
            .expect("read-only live verifier");
        assert_eq!(
            fixture.keys.load_existing_calls.load(Ordering::SeqCst),
            load_existing_before + 8
        );
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            load_or_create_before
        );
        assert_eq!(
            fixture.keys.creation_count.load(Ordering::SeqCst),
            creation_before
        );
        assert_eq!(
            fixture.keys.rotate_calls.load(Ordering::SeqCst),
            rotate_before
        );
        assert_eq!(
            fs::read(&approved_database).expect("approved database after"),
            approved_before
        );
        assert_eq!(
            fs::read(&work_products_database).expect("work products database after"),
            work_products_before
        );
        assert_eq!(
            enumerate_v031_basenames(&fixture.approved_mcp_root()).expect("namespace after"),
            namespace_before
        );
        assert!(!fixture.approved_mcp_root().join(TICKET_ROOT_NAME).exists());
        assert!(!fixture.approved_mcp_root().join("qualification").exists());

        let mut mismatched = gate.clone();
        mismatched.evidence_sha256 = "0".repeat(64);
        assert_eq!(
            fixture
                .workspace
                .verify_v031_target_components_with_binding_read_only(
                    &fixture.rollback_binding,
                    &mismatched,
                )
                .expect_err("expected gate mismatch must fail")
                .code(),
            "v031_target_components_invalid"
        );
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            load_or_create_before
        );
        assert_eq!(
            fixture.keys.creation_count.load(Ordering::SeqCst),
            creation_before
        );
        assert_eq!(
            fixture.keys.rotate_calls.load(Ordering::SeqCst),
            rotate_before
        );
    }

    #[test]
    fn v031_target_components_reject_nonempty_business_namespace_before_key_writes() {
        let fixture = TargetComponentFixture::new();
        fixture.prepare().expect("fresh target components");
        fs::write(
            fixture
                .approved_mcp_root()
                .join(APPROVED_ROOT_NAME)
                .join("cases")
                .join("unexpected.bin"),
            b"unexpected business state",
        )
        .expect("inject business state");
        let calls_before = fixture.keys.load_or_create_calls.load(Ordering::SeqCst);

        assert_eq!(
            fixture
                .prepare()
                .expect_err("nonempty state must fail")
                .code(),
            "v031_target_components_nonempty"
        );
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            calls_before
        );
        assert_eq!(fixture.keys.creation_count.load(Ordering::SeqCst), 4);
        assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_target_components_reject_schema_tamper_before_key_writes() {
        let fixture = TargetComponentFixture::new();
        fixture.prepare().expect("fresh target components");
        let database = fixture
            .approved_mcp_root()
            .join(APPROVED_ROOT_NAME)
            .join("workspace-state.sqlite");
        Connection::open(database)
            .expect("tamper connection")
            .execute_batch("DROP TRIGGER trg_publication_cleanup_no_delete")
            .expect("tamper schema");
        let calls_before = fixture.keys.load_or_create_calls.load(Ordering::SeqCst);

        assert_eq!(
            fixture.prepare().expect_err("tamper must fail").code(),
            "v031_target_components_invalid"
        );
        assert_eq!(
            fixture.keys.load_or_create_calls.load(Ordering::SeqCst),
            calls_before
        );
        assert_eq!(fixture.keys.creation_count.load(Ordering::SeqCst), 4);
        assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_credential_readback_mismatch_fails_closed() {
        struct ReadbackMismatch;

        impl ApprovedMcpKeyProvider for ReadbackMismatch {
            fn load_existing(&self, _role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
                Ok(Some([2_u8; 32]))
            }

            fn load_or_create(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
                Ok([1_u8; 32])
            }

            fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
                panic!("migration preparation must never rotate credentials")
            }
        }

        assert_eq!(
            load_or_create_v031_key(&ReadbackMismatch, KeyRole::ApprovedManifest)
                .expect_err("mismatched credential readback")
                .code(),
            "v031_target_components_invalid"
        );
    }

    #[test]
    fn v031_read_only_target_observer_accepts_only_strict_credential_prefixes() {
        for prefix_len in 0..=V031_TARGET_CREDENTIAL_ROLES.len() {
            let fixture = TargetComponentFixture::new();
            {
                let mut keys = fixture.keys.keys.lock().expect("test key lock");
                for role in V031_TARGET_CREDENTIAL_ROLES.into_iter().take(prefix_len) {
                    keys.insert(role.provider_id(), DeterministicKeyProvider::key_for(role));
                }
            }
            let namespace_before = fs::read_dir(&fixture.app_root)
                .expect("app root before")
                .count();
            let observed = fixture
                .workspace
                .observe_v031_target_namespace_with_binding_read_only(&fixture.rollback_binding)
                .expect("strict credential prefix is resumable");
            let V031ApprovedMcpTargetNamespaceObservation::Incomplete(gate) = observed else {
                panic!("a credential-only prefix cannot be complete")
            };
            assert_eq!(gate.credential_prefix_len(), prefix_len);
            assert_eq!(
                fs::read_dir(&fixture.app_root)
                    .expect("app root after")
                    .count(),
                namespace_before
            );
            assert_eq!(fixture.keys.load_or_create_calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.keys.creation_count.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
        }

        let fixture = TargetComponentFixture::new();
        fixture.keys.keys.lock().expect("test key lock").insert(
            KeyRole::WorkProductManifest.provider_id(),
            DeterministicKeyProvider::key_for(KeyRole::WorkProductManifest),
        );
        assert_eq!(
            fixture
                .workspace
                .observe_v031_target_namespace_with_binding_read_only(&fixture.rollback_binding,)
                .expect_err("a credential hole is not a production prefix")
                .code(),
            "v031_target_components_invalid"
        );
        assert_eq!(fixture.keys.load_or_create_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_read_only_target_observer_authenticates_partial_and_complete_fixed_layouts() {
        let partial = TargetComponentFixture::new();
        {
            let mut keys = partial.keys.keys.lock().expect("test key lock");
            for role in V031_TARGET_CREDENTIAL_ROLES {
                keys.insert(role.provider_id(), DeterministicKeyProvider::key_for(role));
            }
        }
        fs::create_dir(partial.approved_mcp_root()).expect("partial approved MCP root");
        fs::create_dir(partial.approved_mcp_root().join(APPROVED_ROOT_NAME))
            .expect("partial approved root");
        let observed = partial
            .workspace
            .observe_v031_target_namespace_with_binding_read_only(&partial.rollback_binding)
            .expect("fixed partial layout is resumable");
        assert!(matches!(
            observed,
            V031ApprovedMcpTargetNamespaceObservation::Incomplete(_)
        ));
        assert_eq!(partial.keys.load_or_create_calls.load(Ordering::SeqCst), 0);

        let complete = TargetComponentFixture::new();
        let expected = complete.prepare().expect("complete target fixture");
        let writes_before = complete.keys.load_or_create_calls.load(Ordering::SeqCst);
        assert_eq!(
            complete
                .workspace
                .observe_v031_target_namespace_with_binding_read_only(&complete.rollback_binding,)
                .expect("complete target observation"),
            V031ApprovedMcpTargetNamespaceObservation::Complete(expected)
        );
        assert_eq!(
            complete.keys.load_or_create_calls.load(Ordering::SeqCst),
            writes_before
        );
        assert_eq!(complete.keys.rotate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_read_only_target_observer_rejects_namespace_before_credentials() {
        let fixture = TargetComponentFixture::new();
        fs::create_dir(fixture.approved_mcp_root()).expect("out-of-order namespace");
        assert_eq!(
            fixture
                .workspace
                .observe_v031_target_namespace_with_binding_read_only(&fixture.rollback_binding,)
                .expect_err("namespace before credentials must fail")
                .code(),
            "v031_target_components_invalid"
        );
        assert_eq!(fixture.keys.load_or_create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.keys.rotate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn v031_schema_fingerprints_match_frozen_values() {
        let root = tempfile::tempdir().expect("schema fingerprint root");
        let approved_root = root.path().join(APPROVED_ROOT_NAME);
        let work_product_root = root.path().join(WORK_PRODUCT_ROOT_NAME);
        let workspace_instance_id =
            WorkspaceInstanceId::parse(format!("ws_{}", "1".repeat(32))).expect("workspace id");
        let approved_signer =
            ManifestSigningKey::from_bytes([1_u8; 32], KEY_VERSION).expect("approved signer");
        let work_product_signer =
            ManifestSigningKey::from_bytes([2_u8; 32], KEY_VERSION).expect("work signer");

        drop(
            WorkspacePublisher::initialize(&approved_root, approved_signer)
                .expect("approved workspace"),
        );
        drop(
            WorkProductPublisher::initialize(
                &work_product_root,
                workspace_instance_id,
                work_product_signer,
            )
            .expect("work products"),
        );

        let approved = Connection::open_with_flags(
            approved_root.join("workspace-state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("approved database");
        let work_products = Connection::open_with_flags(
            work_product_root.join("work-products.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("work products database");
        let approved_sha256 = canonical_sha256(
            &v031_sqlite_schema_objects(&approved).expect("approved schema objects"),
        )
        .expect("approved schema hash");
        let work_products_sha256 = canonical_sha256(
            &v031_sqlite_schema_objects(&work_products).expect("work product schema objects"),
        )
        .expect("work product schema hash");
        assert_eq!(approved_sha256, V031_APPROVED_WORKSPACE_SCHEMA_SHA256);
        assert_eq!(work_products_sha256, V031_WORK_PRODUCTS_SCHEMA_SHA256);
    }
}
