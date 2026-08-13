//! Frozen R2 infrastructure for the v0.3.1 -> v0.4.0 desktop upgrade.
//!
//! Filesystem enumeration, append-only receipt installation, Credential
//! Manager absence probing, Privacy receipt authentication, and startup
//! arbitration stay behind narrow interfaces so startup cannot accidentally
//! create target state during its read-only preflight.

use privacy::original_rollback_v2::{
    create_v031_original_rollback_identity_v2, open_v031_original_rollback_identity_v2,
    open_v031_original_rollback_v2, open_v031_original_rollback_v2_for_identity,
    protect_v031_original_rollback_identity_v2, seal_v031_original_rollback_v2,
    V031OriginalRollbackCreateRequest, V031OriginalRollbackIdentityV2,
    V031OriginalRollbackMetadataV2, V031OriginalRollbackOpenContext,
    MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES, MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
    V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME,
};
#[cfg(test)]
use privacy::vnext::canonical_json_v1;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(windows)]
use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

pub const V031_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
pub const V031_RECEIPT_SCHEMA: &str = "lawyer-assistance-v031-upgrade-receipt-v1";
pub const MIGRATION_BACKUPS_DIRECTORY: &str = "migration-backups";
pub const MAX_PROTECTED_RECEIPT_BYTES: usize = 1024 * 1024;
pub const APPROVED_MCP_CREDENTIAL_ACCOUNT: &str = "user-boundary-v1";
pub const STEP8_PREDECESSOR_EVIDENCE_FINAL: &str = "08-step8-predecessor.evidence.dpapi";
pub const STEP8_PREDECESSOR_EVIDENCE_INCOMING: &str =
    "08-step8-predecessor.evidence.dpapi.incoming";
pub const UPGRADE_COMPLETE_EVIDENCE_FINAL: &str = "09-upgrade_complete.evidence.dpapi";
pub const UPGRADE_COMPLETE_EVIDENCE_INCOMING: &str = "09-upgrade_complete.evidence.dpapi.incoming";

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_RECEIPT_AFTER_AUTHENTICATED_INCOMING: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_receipt_after_authenticated_incoming_for_test() {
    FAIL_NEXT_RECEIPT_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.set(true));
}

#[cfg(test)]
pub(crate) fn clear_receipt_install_failure_for_test() {
    FAIL_NEXT_RECEIPT_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.set(false));
}

#[derive(Debug)]
pub enum R2InfrastructureError {
    Io(std::io::Error),
    InvalidAppLocalDataRoot,
    InvalidLineageId,
    UnknownLineageDirectoryEntry,
    UnexpectedLineageEvidence,
    UnsafeLineageEntry,
    TargetPathPresent(TargetAbsencePath),
    CredentialPresent(ApprovedMcpCredentialRole),
    CredentialProbeFailed(ApprovedMcpCredentialRole),
    UnknownNearMarker(NearMarkerScope),
    MigrationBackupsAuthenticationRequired,
    ReceiptZeroBootstrapMismatch,
    ReceiptPrefixIsNotContiguous,
    MultipleOrOutOfOrderIncomingReceipts,
    ReceiptAuthenticationRejected {
        ordinal: u8,
        incoming: bool,
    },
    ReceiptMetadataMismatch {
        ordinal: u8,
        incoming: bool,
    },
    ReceiptTimestampRegression {
        ordinal: u8,
        incoming: bool,
    },
    ReceiptTooLarge,
    BoundedReadChanged,
    V2EvidenceOrderInvalid,
    LineageStateMismatch,
    OriginalRollbackAuthenticationFailed,
    OriginalRollbackContextMismatch,
    ReceiptIsNotNext,
    ExistingFinalRequiresStateVerification,
    ExistingIncomingDiffers,
    AtomicInstallRequiresSiblings,
    #[cfg(not(windows))]
    AtomicNoReplaceUnavailable,
    DirectorySyncFailed,
    #[cfg(test)]
    StartupEvidenceUnauthenticated,
    #[cfg(test)]
    StartupEvidenceMixed,
    #[cfg(test)]
    StartupEvidenceMissing,
}

impl fmt::Display for R2InfrastructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "R2 filesystem operation failed: {error}"),
            Self::InvalidAppLocalDataRoot => {
                formatter.write_str("R2 app-local-data root is not an absolute plain directory")
            }
            Self::InvalidLineageId => formatter.write_str("R2 lineage id is not canonical"),
            Self::UnknownLineageDirectoryEntry => {
                formatter.write_str("R2 lineage root contains an unknown entry")
            }
            Self::UnexpectedLineageEvidence => {
                formatter.write_str("R2 lineage directory contains unexpected evidence")
            }
            Self::UnsafeLineageEntry => {
                formatter.write_str("R2 lineage entry is not a plain single-link file")
            }
            Self::TargetPathPresent(slot) => {
                write!(
                    formatter,
                    "R2 target-only path is present: {}",
                    slot.label()
                )
            }
            Self::CredentialPresent(role) => {
                write!(
                    formatter,
                    "R2 target-only credential is present: {}",
                    role.label()
                )
            }
            Self::CredentialProbeFailed(role) => {
                write!(formatter, "R2 credential query failed: {}", role.label())
            }
            Self::UnknownNearMarker(scope) => {
                write!(
                    formatter,
                    "R2 unknown near-marker exists in {}",
                    scope.label()
                )
            }
            Self::MigrationBackupsAuthenticationRequired => formatter
                .write_str("R2 migration-backups state must be fully enumerated and authenticated"),
            Self::ReceiptZeroBootstrapMismatch => formatter.write_str(
                "R2 receipt-zero bootstrap namespace no longer matches its verified state",
            ),
            Self::ReceiptPrefixIsNotContiguous => {
                formatter.write_str("R2 final receipt prefix is not contiguous")
            }
            Self::MultipleOrOutOfOrderIncomingReceipts => {
                formatter.write_str("R2 receipt chain has multiple or out-of-order incoming files")
            }
            Self::ReceiptAuthenticationRejected { ordinal, incoming } => write!(
                formatter,
                "R2 receipt authentication rejected ordinal {ordinal} (incoming={incoming})"
            ),
            Self::ReceiptMetadataMismatch { ordinal, incoming } => write!(
                formatter,
                "R2 receipt metadata mismatched ordinal {ordinal} (incoming={incoming})"
            ),
            Self::ReceiptTimestampRegression { ordinal, incoming } => write!(
                formatter,
                "R2 receipt timestamp regressed at ordinal {ordinal} (incoming={incoming})"
            ),
            Self::ReceiptTooLarge => formatter.write_str("R2 receipt exceeds its read bound"),
            Self::BoundedReadChanged => {
                formatter.write_str("R2 bounded file changed while it was read")
            }
            Self::V2EvidenceOrderInvalid => {
                formatter.write_str("R2 V2 identity/bundle evidence order is invalid")
            }
            Self::LineageStateMismatch => {
                formatter.write_str("R2 receipt prefix and original rollback evidence disagree")
            }
            Self::OriginalRollbackAuthenticationFailed => {
                formatter.write_str("R2 original rollback identity or bundle authentication failed")
            }
            Self::OriginalRollbackContextMismatch => formatter
                .write_str("R2 original rollback evidence does not match its source context"),
            Self::ReceiptIsNotNext => {
                formatter.write_str("R2 receipt is not the unique next chain ordinal")
            }
            Self::ExistingFinalRequiresStateVerification => formatter
                .write_str("R2 final receipt already exists and requires component verification"),
            Self::ExistingIncomingDiffers => {
                formatter.write_str("R2 existing incoming receipt has different bytes")
            }
            Self::AtomicInstallRequiresSiblings => {
                formatter.write_str("R2 atomic install paths are not siblings")
            }
            #[cfg(not(windows))]
            Self::AtomicNoReplaceUnavailable => {
                formatter.write_str("R2 atomic no-replacement rename is unavailable")
            }
            Self::DirectorySyncFailed => {
                formatter.write_str("R2 parent-directory durability barrier failed")
            }
            #[cfg(test)]
            Self::StartupEvidenceUnauthenticated => {
                formatter.write_str("R2 startup evidence is unknown or unauthenticated")
            }
            #[cfg(test)]
            Self::StartupEvidenceMixed => {
                formatter.write_str("R2 startup evidence selects multiple incompatible flows")
            }
            #[cfg(test)]
            Self::StartupEvidenceMissing => {
                formatter.write_str("R2 startup evidence selects no recognized flow")
            }
        }
    }
}

impl std::error::Error for R2InfrastructureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for R2InfrastructureError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApprovedMcpCredentialRole {
    ApprovedManifest,
    WorkProductManifest,
    McpAccessTicket,
    QualificationRevocationEpoch,
}

impl ApprovedMcpCredentialRole {
    pub const ALL: [Self; 4] = [
        Self::ApprovedManifest,
        Self::WorkProductManifest,
        Self::McpAccessTicket,
        Self::QualificationRevocationEpoch,
    ];

    pub const fn target(self) -> &'static str {
        match self {
            Self::ApprovedManifest => {
                "LawyerAssistanceApprovedMcp/provider/approved-manifest/account/user-boundary-v1"
            }
            Self::WorkProductManifest => {
                "LawyerAssistanceApprovedMcp/provider/work-product-manifest/account/user-boundary-v1"
            }
            Self::McpAccessTicket => {
                "LawyerAssistanceApprovedMcp/provider/mcp-access-ticket/account/user-boundary-v1"
            }
            Self::QualificationRevocationEpoch => "LawyerAssistanceApprovedMcp/provider/mcp-qualification-revocation-epoch/account/user-boundary-v1",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ApprovedManifest => "approved_manifest",
            Self::WorkProductManifest => "work_product_manifest",
            Self::McpAccessTicket => "mcp_access_ticket",
            Self::QualificationRevocationEpoch => "qualification_revocation_epoch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialAbsenceQuery {
    pub role: ApprovedMcpCredentialRole,
    pub target: &'static str,
    pub account: &'static str,
}

/// Read-only Credential Manager bridge used by source preflight.
///
/// Deliberately no create, load-or-create, delete, or update operation exists on
/// this trait.  A production adapter must query exactly `query.target` and
/// `query.account` without materializing a credential on a miss.
pub trait CredentialPresenceProbe {
    type Error;

    fn credential_exists_read_only(
        &self,
        query: CredentialAbsenceQuery,
    ) -> Result<bool, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAbsencePath {
    VaultRoot,
    ApprovedMcpRoot,
    ApplicationRestorePending,
    MigrationRecoveryPending,
    UserApplicationRestoreIncoming,
    UserApplicationRestoreRollback,
    UserRestoreIncoming,
    UserRestorePending,
    UserRestoreRollback,
    PrivacyApplicationRestoreIncoming,
    PrivacyApplicationRestoreRollback,
    PrivacyRestoreIncoming,
    PrivacyRestorePending,
    PrivacyRestoreRollback,
    VaultApplicationRestoreIncoming,
    VaultApplicationRestoreRollback,
    ApprovedGenerationsApplicationRestoreIncoming,
    ApprovedGenerationsApplicationRestoreRollback,
    WorkProductsApplicationRestoreIncoming,
    WorkProductsApplicationRestoreRollback,
}

impl TargetAbsencePath {
    pub const ALL: [Self; 20] = [
        Self::VaultRoot,
        Self::ApprovedMcpRoot,
        Self::ApplicationRestorePending,
        Self::MigrationRecoveryPending,
        Self::UserApplicationRestoreIncoming,
        Self::UserApplicationRestoreRollback,
        Self::UserRestoreIncoming,
        Self::UserRestorePending,
        Self::UserRestoreRollback,
        Self::PrivacyApplicationRestoreIncoming,
        Self::PrivacyApplicationRestoreRollback,
        Self::PrivacyRestoreIncoming,
        Self::PrivacyRestorePending,
        Self::PrivacyRestoreRollback,
        Self::VaultApplicationRestoreIncoming,
        Self::VaultApplicationRestoreRollback,
        Self::ApprovedGenerationsApplicationRestoreIncoming,
        Self::ApprovedGenerationsApplicationRestoreRollback,
        Self::WorkProductsApplicationRestoreIncoming,
        Self::WorkProductsApplicationRestoreRollback,
    ];

    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::VaultRoot => "case-vault-v2",
            Self::ApprovedMcpRoot => "privacy/approved-mcp",
            Self::ApplicationRestorePending => "application-restore-pending.dpapi",
            Self::MigrationRecoveryPending => "v031-migration-recovery-pending.dpapi",
            Self::UserApplicationRestoreIncoming => "user.sqlite.application-restore-incoming",
            Self::UserApplicationRestoreRollback => "user.sqlite.application-restore-rollback",
            Self::UserRestoreIncoming => "user.sqlite.restore-incoming",
            Self::UserRestorePending => "user.sqlite.restore-pending.json",
            Self::UserRestoreRollback => "user.sqlite.restore-rollback",
            Self::PrivacyApplicationRestoreIncoming => {
                "privacy/privacy-workflow.sqlite.application-restore-incoming"
            }
            Self::PrivacyApplicationRestoreRollback => {
                "privacy/privacy-workflow.sqlite.application-restore-rollback"
            }
            Self::PrivacyRestoreIncoming => "privacy/privacy-workflow.sqlite.restore-incoming",
            Self::PrivacyRestorePending => "privacy/privacy-workflow.sqlite.restore-pending.dpapi",
            Self::PrivacyRestoreRollback => "privacy/privacy-workflow.sqlite.restore-rollback",
            Self::VaultApplicationRestoreIncoming => "case-vault-v2.application-restore-incoming",
            Self::VaultApplicationRestoreRollback => "case-vault-v2.application-restore-rollback",
            Self::ApprovedGenerationsApplicationRestoreIncoming => {
                "privacy/approved-mcp/approved-generations.application-restore-incoming"
            }
            Self::ApprovedGenerationsApplicationRestoreRollback => {
                "privacy/approved-mcp/approved-generations.application-restore-rollback"
            }
            Self::WorkProductsApplicationRestoreIncoming => {
                "privacy/approved-mcp/work-products.application-restore-incoming"
            }
            Self::WorkProductsApplicationRestoreRollback => {
                "privacy/approved-mcp/work-products.application-restore-rollback"
            }
        }
    }

    const fn label(self) -> &'static str {
        self.relative_path()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NearMarkerScope {
    AppRoot,
    PrivacyRoot,
}

impl NearMarkerScope {
    const fn label(self) -> &'static str {
        match self {
            Self::AppRoot => "app_root",
            Self::PrivacyRoot => "privacy_root",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TargetAbsenceProof {
    app_local_data_dir: PathBuf,
    migration_lineage_ids: Vec<String>,
    empty_receipt_zero_lineage_id: Option<String>,
    credential_roles_checked: usize,
    fixed_paths_checked: usize,
    sibling_directories_scanned: usize,
    _verified: (),
}

impl fmt::Debug for TargetAbsenceProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetAbsenceProof")
            .field("migration_lineage_ids", &self.migration_lineage_ids)
            .field(
                "empty_receipt_zero_lineage_id",
                &self.empty_receipt_zero_lineage_id,
            )
            .field("credential_roles_checked", &self.credential_roles_checked)
            .field("fixed_paths_checked", &self.fixed_paths_checked)
            .field(
                "sibling_directories_scanned",
                &self.sibling_directories_scanned,
            )
            .finish_non_exhaustive()
    }
}

impl TargetAbsenceProof {
    pub const fn credential_roles_checked(&self) -> usize {
        self.credential_roles_checked
    }

    pub const fn fixed_paths_checked(&self) -> usize {
        self.fixed_paths_checked
    }

    pub const fn sibling_directories_scanned(&self) -> usize {
        self.sibling_directories_scanned
    }
}

/// Proves target-only state is absent using only metadata enumeration and the
/// read-only Credential Manager callback.
pub fn verify_exact_target_absence<P: CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    credentials: &P,
) -> Result<TargetAbsenceProof, R2InfrastructureError> {
    verify_exact_target_absence_internal(
        app_local_data_dir,
        credentials,
        MigrationNamespaceAllowance::Absent,
    )
}

/// Re-proves target-only absence while allowing an existing
/// `migration-backups` root only when every lineage and receipt in that root
/// was authenticated against the same canonical app-local-data directory.
pub fn verify_exact_target_absence_with_authenticated_migration_backups<
    P: CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    credentials: &P,
    migration_backups: &AuthenticatedMigrationBackupsInventory,
) -> Result<TargetAbsenceProof, R2InfrastructureError> {
    verify_exact_target_absence_internal(
        app_local_data_dir,
        credentials,
        MigrationNamespaceAllowance::Authenticated(migration_backups),
    )
}

/// Re-proves target-only absence while allowing the exact namespace returned
/// by [`inspect_receipt_zero_namespace`]. This is the only absence proof that
/// may recognize the two pre-receipt crash residues: an empty
/// `migration-backups` root or one empty canonical lineage directory.
pub fn verify_exact_target_absence_with_receipt_zero_namespace<P: CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    credentials: &P,
    namespace: &ReceiptZeroNamespaceInventory,
) -> Result<TargetAbsenceProof, R2InfrastructureError> {
    verify_exact_target_absence_internal(
        app_local_data_dir,
        credentials,
        MigrationNamespaceAllowance::ReceiptZeroNamespace(namespace),
    )
}

/// Re-proves target-only absence during the narrow interval after a new empty
/// lineage directory has been durably created and before receipt zero exists.
/// Once an incoming or final receipt appears this verifier fails closed and
/// the caller must authenticate the complete migration-backups namespace.
pub fn verify_exact_target_absence_with_receipt_zero_bootstrap<P: CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    credentials: &P,
    bootstrap: &ReceiptZeroBootstrap,
) -> Result<TargetAbsenceProof, R2InfrastructureError> {
    verify_exact_target_absence_internal(
        app_local_data_dir,
        credentials,
        MigrationNamespaceAllowance::ReceiptZeroBootstrap(bootstrap),
    )
}

enum MigrationNamespaceAllowance<'a> {
    Absent,
    Authenticated(&'a AuthenticatedMigrationBackupsInventory),
    ReceiptZeroNamespace(&'a ReceiptZeroNamespaceInventory),
    ReceiptZeroBootstrap(&'a ReceiptZeroBootstrap),
}

fn verify_exact_target_absence_internal<P: CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    credentials: &P,
    migration_namespace: MigrationNamespaceAllowance<'_>,
) -> Result<TargetAbsenceProof, R2InfrastructureError> {
    validate_app_local_data_root(app_local_data_dir)?;

    let migration_root = app_local_data_dir.join(MIGRATION_BACKUPS_DIRECTORY);
    let namespace_mismatch_error = if matches!(
        &migration_namespace,
        MigrationNamespaceAllowance::ReceiptZeroNamespace(_)
            | MigrationNamespaceAllowance::ReceiptZeroBootstrap(_)
    ) {
        R2InfrastructureError::ReceiptZeroBootstrapMismatch
    } else {
        R2InfrastructureError::MigrationBackupsAuthenticationRequired
    };
    let (expected_lineage_ids, empty_receipt_zero_lineage_id, expects_root) =
        match migration_namespace {
            MigrationNamespaceAllowance::Absent => (Vec::new(), None, false),
            MigrationNamespaceAllowance::Authenticated(inventory) => {
                if inventory.app_local_data_dir != app_local_data_dir {
                    return Err(R2InfrastructureError::MigrationBackupsAuthenticationRequired);
                }
                (inventory.lineage_ids.clone(), None, true)
            }
            MigrationNamespaceAllowance::ReceiptZeroNamespace(namespace) => {
                if namespace.app_local_data_dir != app_local_data_dir {
                    return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
                }
                (
                    namespace.lineage_ids.clone(),
                    namespace.empty_lineage_id.clone(),
                    namespace.root_present,
                )
            }
            MigrationNamespaceAllowance::ReceiptZeroBootstrap(bootstrap) => {
                if bootstrap.app_local_data_dir != app_local_data_dir {
                    return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
                }
                (
                    bootstrap.lineage_ids.clone(),
                    Some(bootstrap.lineage_id.clone()),
                    true,
                )
            }
        };
    match fs::symlink_metadata(&migration_root) {
        Ok(metadata) => {
            ensure_plain_directory_metadata(&metadata)?;
            let current_lineages = enumerate_lineage_ids(app_local_data_dir)?;
            if !expects_root || current_lineages != expected_lineage_ids {
                return Err(namespace_mismatch_error);
            }
            if let Some(empty_lineage_id) = empty_receipt_zero_lineage_id.as_deref() {
                ensure_lineage_directory_is_empty(app_local_data_dir, empty_lineage_id)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if expects_root {
                return Err(namespace_mismatch_error);
            }
        }
        Err(error) => return Err(error.into()),
    }

    for role in ApprovedMcpCredentialRole::ALL {
        let query = CredentialAbsenceQuery {
            role,
            target: role.target(),
            account: APPROVED_MCP_CREDENTIAL_ACCOUNT,
        };
        let present = credentials
            .credential_exists_read_only(query)
            .map_err(|_| R2InfrastructureError::CredentialProbeFailed(role))?;
        if present {
            return Err(R2InfrastructureError::CredentialPresent(role));
        }
    }

    for target in TargetAbsencePath::ALL {
        match fs::symlink_metadata(app_local_data_dir.join(target.relative_path())) {
            Ok(_) => return Err(R2InfrastructureError::TargetPathPresent(target)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    scan_near_marker_siblings(app_local_data_dir, NearMarkerScope::AppRoot)?;
    let privacy = app_local_data_dir.join("privacy");
    let scanned_privacy = match fs::symlink_metadata(&privacy) {
        Ok(metadata) => {
            ensure_plain_directory_metadata(&metadata)?;
            scan_near_marker_siblings(&privacy, NearMarkerScope::PrivacyRoot)?;
            1
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };

    Ok(TargetAbsenceProof {
        app_local_data_dir: app_local_data_dir.to_path_buf(),
        migration_lineage_ids: expected_lineage_ids,
        empty_receipt_zero_lineage_id,
        credential_roles_checked: ApprovedMcpCredentialRole::ALL.len(),
        fixed_paths_checked: TargetAbsencePath::ALL.len(),
        sibling_directories_scanned: 1 + scanned_privacy,
        _verified: (),
    })
}

fn validate_app_local_data_root(path: &Path) -> Result<(), R2InfrastructureError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(R2InfrastructureError::InvalidAppLocalDataRoot);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| R2InfrastructureError::InvalidAppLocalDataRoot)?;
    ensure_plain_directory_metadata(&metadata)
        .map_err(|_| R2InfrastructureError::InvalidAppLocalDataRoot)
}

fn ensure_plain_directory_metadata(metadata: &fs::Metadata) -> Result<(), R2InfrastructureError> {
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(metadata)
        || !metadata.is_dir()
    {
        return Err(R2InfrastructureError::UnsafeLineageEntry);
    }
    Ok(())
}

fn scan_near_marker_siblings(
    directory: &Path,
    scope: NearMarkerScope,
) -> Result<(), R2InfrastructureError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| R2InfrastructureError::UnknownNearMarker(scope))?;
        let lowercase_name = name.to_ascii_lowercase();
        let unknown_near_marker = match scope {
            NearMarkerScope::AppRoot => {
                (lowercase_name.starts_with("user.sqlite")
                    && !matches!(
                        name.as_str(),
                        "user.sqlite"
                            | "user.sqlite-wal"
                            | "user.sqlite-shm"
                            | "user.sqlite-journal"
                    ))
                    || lowercase_name.starts_with("case-vault-v2")
                    || lowercase_name.starts_with("application-restore-")
                    || (lowercase_name.starts_with(MIGRATION_BACKUPS_DIRECTORY)
                        && name != MIGRATION_BACKUPS_DIRECTORY)
            }
            NearMarkerScope::PrivacyRoot => {
                (lowercase_name.starts_with("privacy-workflow.sqlite")
                    && !matches!(
                        name.as_str(),
                        "privacy-workflow.sqlite"
                            | "privacy-workflow.sqlite-wal"
                            | "privacy-workflow.sqlite-shm"
                            | "privacy-workflow.sqlite-journal"
                    ))
                    || lowercase_name.starts_with("approved-mcp")
            }
        };
        if unknown_near_marker {
            return Err(R2InfrastructureError::UnknownNearMarker(scope));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptDescriptor {
    pub ordinal: u8,
    pub stage: &'static str,
    pub final_basename: &'static str,
}

pub const V031_RECEIPTS: [ReceiptDescriptor; 10] = [
    ReceiptDescriptor {
        ordinal: 0,
        stage: "source_preflight_verified",
        final_basename: "00-source_preflight_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 1,
        stage: "original_rollback_verified",
        final_basename: "01-original_rollback_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 2,
        stage: "target_components_prepared",
        final_basename: "02-target_components_prepared.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 3,
        stage: "case_migration_backups_verified",
        final_basename: "03-case_migration_backups_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 4,
        stage: "privacy_v5_verified",
        final_basename: "04-privacy_v5_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 5,
        stage: "binding_materials_verified",
        final_basename: "05-binding_materials_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 6,
        stage: "projection_backup_verified",
        final_basename: "06-projection_backup_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 7,
        stage: "privacy_v6_verified",
        final_basename: "07-privacy_v6_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 8,
        stage: "user_v11_verified",
        final_basename: "08-user_v11_verified.receipt.dpapi",
    },
    ReceiptDescriptor {
        ordinal: 9,
        stage: "upgrade_complete",
        final_basename: "09-upgrade_complete.receipt.dpapi",
    },
];

pub const V2_IDENTITY_FINAL: &str = "v031-original-rollback-v2.identity.dpapi";
pub const V2_IDENTITY_INCOMING: &str = "v031-original-rollback-v2.identity.dpapi.incoming";
pub const V2_BUNDLE_FINAL: &str = "v031-original-rollback-v2.bundle";
pub const V2_BUNDLE_INCOMING: &str = "v031-original-rollback-v2.bundle.incoming";
pub const USER_SNAPSHOT_INCOMING: &str = "user_database.snapshot.sqlite.incoming";
pub const PRIVACY_SNAPSHOT_INCOMING: &str = "privacy_store.snapshot.sqlite.incoming";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum V031CheckpointKind {
    Binding,
    Materials,
    Projection,
}

impl V031CheckpointKind {
    pub const ALL: [Self; 3] = [Self::Binding, Self::Materials, Self::Projection];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Binding => "project_privacy_binding",
            Self::Materials => "case_materials",
            Self::Projection => "approved_case_projection",
        }
    }

    pub const fn identity_final_basename(self) -> &'static str {
        match self {
            Self::Binding => V031_BINDING_CHECKPOINT_IDENTITY_FINAL,
            Self::Materials => V031_MATERIALS_CHECKPOINT_IDENTITY_FINAL,
            Self::Projection => V031_PROJECTION_CHECKPOINT_IDENTITY_FINAL,
        }
    }

    pub const fn bundle_final_basename(self) -> &'static str {
        match self {
            Self::Binding => V031_BINDING_CHECKPOINT_BUNDLE_FINAL,
            Self::Materials => V031_MATERIALS_CHECKPOINT_BUNDLE_FINAL,
            Self::Projection => V031_PROJECTION_CHECKPOINT_BUNDLE_FINAL,
        }
    }

    pub fn identity_incoming_basename(self) -> String {
        format!("{}.incoming", self.identity_final_basename())
    }

    pub fn bundle_incoming_basename(self) -> String {
        format!("{}.incoming", self.bundle_final_basename())
    }
}

pub const V031_BINDING_CHECKPOINT_IDENTITY_FINAL: &str =
    "v031-project-privacy-binding-checkpoint-v1.identity.dpapi";
pub const V031_BINDING_CHECKPOINT_BUNDLE_FINAL: &str =
    "v031-project-privacy-binding-checkpoint-v1.bundle";
pub const V031_MATERIALS_CHECKPOINT_IDENTITY_FINAL: &str =
    "v031-case-materials-checkpoint-v1.identity.dpapi";
pub const V031_MATERIALS_CHECKPOINT_BUNDLE_FINAL: &str = "v031-case-materials-checkpoint-v1.bundle";
pub const V031_PROJECTION_CHECKPOINT_IDENTITY_FINAL: &str =
    "v031-approved-case-projection-checkpoint-v1.identity.dpapi";
pub const V031_PROJECTION_CHECKPOINT_BUNDLE_FINAL: &str =
    "v031-approved-case-projection-checkpoint-v1.bundle";

pub fn canonical_lineage_directory(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<PathBuf, R2InfrastructureError> {
    validate_app_local_data_root(app_local_data_dir)?;
    validate_lineage_id(lineage_id)?;
    Ok(app_local_data_dir
        .join(MIGRATION_BACKUPS_DIRECTORY)
        .join(lineage_id))
}

pub fn validate_lineage_id(lineage_id: &str) -> Result<(), R2InfrastructureError> {
    if lineage_id.len() != 64
        || !lineage_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(R2InfrastructureError::InvalidLineageId);
    }
    Ok(())
}

pub fn enumerate_lineage_ids(
    app_local_data_dir: &Path,
) -> Result<Vec<String>, R2InfrastructureError> {
    validate_app_local_data_root(app_local_data_dir)?;
    let root = app_local_data_dir.join(MIGRATION_BACKUPS_DIRECTORY);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    ensure_plain_directory_metadata(&metadata)?;

    let mut lineage_ids = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let lineage_id = entry
            .file_name()
            .into_string()
            .map_err(|_| R2InfrastructureError::UnknownLineageDirectoryEntry)?;
        validate_lineage_id(&lineage_id)
            .map_err(|_| R2InfrastructureError::UnknownLineageDirectoryEntry)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure_plain_directory_metadata(&metadata)
            .map_err(|_| R2InfrastructureError::UnknownLineageDirectoryEntry)?;
        lineage_ids.push(lineage_id);
    }
    lineage_ids.sort();
    Ok(lineage_ids)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptExpectation<'a> {
    pub descriptor: ReceiptDescriptor,
    pub lineage_id: &'a str,
    pub previous_receipt_sha256: Option<&'a str>,
    pub incoming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedReceiptMetadata {
    pub schema_version: String,
    pub migration_id: String,
    pub lineage_id: String,
    pub envelope_binding_id: String,
    pub ordinal: u8,
    pub stage: String,
    pub previous_receipt_sha256: Option<String>,
    pub source_profile_proof_sha256: String,
    pub evidence_schema_version: String,
    pub evidence_sha256: String,
    pub counts: BTreeMap<String, u64>,
    pub created_at_unix: i64,
    pub result_code: String,
}

/// Authentication-only bridge to the Privacy DPAPI/canonical receipt codec.
///
/// The adapter must reject unknown plaintext fields, non-canonical JSON,
/// disallowed stage-specific count keys, DPAPI/AAD failures, and secret-bearing
/// fields before returning metadata.  R2 filesystem code never receives the
/// decrypted receipt plaintext and cannot create Privacy or Credential state.
pub trait ReceiptAuthenticationBridge {
    type Error;

    fn authenticate_protected_receipt(
        &self,
        protected_file_bytes: &[u8],
        expectation: ReceiptExpectation<'_>,
    ) -> Result<AuthenticatedReceiptMetadata, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedReceiptFile {
    pub ordinal: u8,
    pub stage: &'static str,
    pub incoming: bool,
    pub protected_file_sha256: String,
    pub protected_byte_len: usize,
    pub metadata: AuthenticatedReceiptMetadata,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V2EvidenceInventory {
    pub identity_final: bool,
    pub identity_incoming: bool,
    pub bundle_final: bool,
    pub bundle_incoming: bool,
    pub user_snapshot_incoming: bool,
    pub privacy_snapshot_incoming: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckpointPairInventory {
    pub identity_final: bool,
    pub identity_incoming: bool,
    pub bundle_final: bool,
    pub bundle_incoming: bool,
}

impl CheckpointPairInventory {
    pub const fn is_absent(self) -> bool {
        !self.identity_final
            && !self.identity_incoming
            && !self.bundle_final
            && !self.bundle_incoming
    }

    pub const fn is_exact_final(self) -> bool {
        self.identity_final && !self.identity_incoming && self.bundle_final && !self.bundle_incoming
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V031CheckpointInventory {
    pub binding: CheckpointPairInventory,
    pub materials: CheckpointPairInventory,
    pub projection: CheckpointPairInventory,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Step8PredecessorEvidenceInventory {
    pub final_present: bool,
    pub incoming_present: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpgradeCompleteEvidenceInventory {
    pub final_present: bool,
    pub incoming_present: bool,
}

impl UpgradeCompleteEvidenceInventory {
    pub const fn is_absent(self) -> bool {
        !self.final_present && !self.incoming_present
    }

    pub const fn is_exact_final(self) -> bool {
        self.final_present && !self.incoming_present
    }
}

impl Step8PredecessorEvidenceInventory {
    pub const fn is_absent(self) -> bool {
        !self.final_present && !self.incoming_present
    }

    pub const fn is_exact_final(self) -> bool {
        self.final_present && !self.incoming_present
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedLineageInventory {
    app_local_data_dir: PathBuf,
    pub lineage_id: String,
    pub v2: V2EvidenceInventory,
    pub checkpoints: V031CheckpointInventory,
    pub step8_predecessor: Step8PredecessorEvidenceInventory,
    pub upgrade_complete_evidence: UpgradeCompleteEvidenceInventory,
    pub final_receipts: Vec<AuthenticatedReceiptFile>,
    pub next_incoming_receipt: Option<AuthenticatedReceiptFile>,
    _authenticated: (),
}

impl fmt::Debug for AuthenticatedLineageInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let final_receipt_ordinals = self
            .final_receipts
            .iter()
            .map(|receipt| receipt.ordinal)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("AuthenticatedLineageInventory")
            .field("lineage_id", &self.lineage_id)
            .field("v2", &self.v2)
            .field("checkpoints", &self.checkpoints)
            .field("step8_predecessor", &self.step8_predecessor)
            .field("upgrade_complete_evidence", &self.upgrade_complete_evidence)
            .field("final_receipt_ordinals", &final_receipt_ordinals)
            .field(
                "next_incoming_ordinal",
                &self
                    .next_incoming_receipt
                    .as_ref()
                    .map(|receipt| receipt.ordinal),
            )
            .finish_non_exhaustive()
    }
}

impl AuthenticatedLineageInventory {
    pub(crate) fn authenticates(&self, app_local_data_dir: &Path, lineage_id: &str) -> bool {
        self.app_local_data_dir == app_local_data_dir && self.lineage_id == lineage_id
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedMigrationBackupsInventory {
    app_local_data_dir: PathBuf,
    lineage_ids: Vec<String>,
    pub lineages: Vec<AuthenticatedLineageInventory>,
    _authenticated: (),
}

impl fmt::Debug for AuthenticatedMigrationBackupsInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMigrationBackupsInventory")
            .field("lineage_ids", &self.lineage_ids)
            .field("authenticated_lineage_count", &self.lineages.len())
            .finish_non_exhaustive()
    }
}

/// Fully classified migration namespace used only before receipt zero exists.
///
/// Every non-empty lineage is authenticated through its DPAPI receipt chain.
/// At most one canonical empty lineage is admitted as a recognized crash
/// residue. The type is opaque so target-absence callers cannot manufacture an
/// exception for arbitrary filesystem state.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptZeroNamespaceInventory {
    app_local_data_dir: PathBuf,
    root_present: bool,
    lineage_ids: Vec<String>,
    authenticated_lineages: Vec<AuthenticatedLineageInventory>,
    empty_lineage_id: Option<String>,
    _authenticated: (),
}

impl fmt::Debug for ReceiptZeroNamespaceInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptZeroNamespaceInventory")
            .field("root_present", &self.root_present)
            .field("lineage_ids", &self.lineage_ids)
            .field(
                "authenticated_lineage_count",
                &self.authenticated_lineages.len(),
            )
            .field("empty_lineage_id", &self.empty_lineage_id)
            .finish_non_exhaustive()
    }
}

impl ReceiptZeroNamespaceInventory {
    pub fn authenticated_lineages(&self) -> &[AuthenticatedLineageInventory] {
        &self.authenticated_lineages
    }

    pub fn empty_lineage_id(&self) -> Option<&str> {
        self.empty_lineage_id.as_deref()
    }

    pub fn lineage_ids(&self) -> &[String] {
        &self.lineage_ids
    }
}

/// Inspects the complete fixed namespace before a fresh receipt-zero install.
/// An absent root, an empty root, and one empty canonical lineage are the only
/// unauthenticated states admitted. Any non-empty lineage must authenticate in
/// full, and two empty lineages are always a conflict.
pub fn inspect_receipt_zero_namespace<B, F>(
    app_local_data_dir: &Path,
    mut bridge_for_lineage: F,
) -> Result<ReceiptZeroNamespaceInventory, R2InfrastructureError>
where
    B: ReceiptAuthenticationBridge,
    F: FnMut(&str) -> B,
{
    validate_app_local_data_root(app_local_data_dir)?;
    let root = app_local_data_dir.join(MIGRATION_BACKUPS_DIRECTORY);
    let root_present = match fs::symlink_metadata(&root) {
        Ok(metadata) => {
            ensure_plain_directory_metadata(&metadata)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let lineage_ids = enumerate_lineage_ids(app_local_data_dir)?;
    let mut authenticated_lineages = Vec::with_capacity(lineage_ids.len());
    let mut empty_lineage_id = None;
    for lineage_id in &lineage_ids {
        if lineage_directory_is_empty(app_local_data_dir, lineage_id)? {
            if empty_lineage_id.replace(lineage_id.clone()).is_some() {
                return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
            }
            continue;
        }
        let bridge = bridge_for_lineage(lineage_id);
        authenticated_lineages.push(enumerate_and_authenticate_lineage(
            app_local_data_dir,
            lineage_id,
            &bridge,
        )?);
    }
    Ok(ReceiptZeroNamespaceInventory {
        app_local_data_dir: app_local_data_dir.to_path_buf(),
        root_present,
        lineage_ids,
        authenticated_lineages,
        empty_lineage_id,
        _authenticated: (),
    })
}

/// Capability for the sole empty lineage that may exist between directory
/// creation and receipt-zero installation.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptZeroBootstrap {
    app_local_data_dir: PathBuf,
    lineage_id: String,
    lineage_ids: Vec<String>,
    _verified: (),
}

impl fmt::Debug for ReceiptZeroBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptZeroBootstrap")
            .field("lineage_id", &self.lineage_id)
            .field("lineage_ids", &self.lineage_ids)
            .finish_non_exhaustive()
    }
}

impl ReceiptZeroBootstrap {
    pub fn lineage_id(&self) -> &str {
        &self.lineage_id
    }
}

/// Durably prepares the unique receipt-zero lineage using a proof from the
/// same target-absence pass. A prior empty lineage has no receipt, protected
/// identity, bundle, or snapshot and therefore contains no evidence; because
/// its random envelope binding cannot be recovered after a crash, the exact
/// empty directory is atomically rebound to the newly generated lineage id
/// without deleting its inode. Authenticated terminal historical lineages are
/// preserved byte-for-byte.
pub fn prepare_receipt_zero_bootstrap<D: DirectorySync>(
    app_local_data_dir: &Path,
    lineage_id: &str,
    namespace: &ReceiptZeroNamespaceInventory,
    target_absence: &TargetAbsenceProof,
    verified_terminal_lineages: &[VerifiedOriginalRollbackV2],
    directory_sync: &D,
) -> Result<ReceiptZeroBootstrap, R2InfrastructureError> {
    validate_app_local_data_root(app_local_data_dir)?;
    validate_lineage_id(lineage_id)?;
    if namespace.app_local_data_dir != app_local_data_dir
        || target_absence.app_local_data_dir != app_local_data_dir
        || target_absence.migration_lineage_ids != namespace.lineage_ids
        || target_absence.empty_receipt_zero_lineage_id != namespace.empty_lineage_id
    {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    if verified_terminal_lineages.len() != namespace.authenticated_lineages.len() {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    let mut verified_lineage_ids = BTreeSet::new();
    for verified in verified_terminal_lineages {
        if !verified_lineage_ids.insert(verified.lineage_id.as_str()) {
            return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
        }
    }
    let mut terminal_lineage_pins = Vec::with_capacity(namespace.authenticated_lineages.len());
    for lineage in &namespace.authenticated_lineages {
        if !is_terminal_upgrade_lineage(lineage) {
            return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
        }
        let verified = verified_terminal_lineages
            .iter()
            .find(|verified| verified.lineage_id == lineage.lineage_id)
            .ok_or(R2InfrastructureError::ReceiptZeroBootstrapMismatch)?;
        terminal_lineage_pins.push(verify_terminal_lineage_bytes_unchanged(
            app_local_data_dir,
            lineage,
            verified,
        )?);
    }
    verify_receipt_zero_namespace_shape(app_local_data_dir, namespace)?;

    let root = app_local_data_dir.join(MIGRATION_BACKUPS_DIRECTORY);
    if namespace.root_present {
        ensure_plain_directory_metadata(&fs::symlink_metadata(&root)?)?;
    } else {
        fs::create_dir(&root)?;
        ensure_plain_directory_metadata(&fs::symlink_metadata(&root)?)?;
        directory_sync
            .sync_directory(app_local_data_dir)
            .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;
    }

    let mut preserved_lineage_ids = namespace
        .lineage_ids
        .iter()
        .filter(|candidate| Some(candidate.as_str()) != namespace.empty_lineage_id.as_deref())
        .cloned()
        .collect::<Vec<_>>();
    if preserved_lineage_ids
        .iter()
        .any(|candidate| candidate == lineage_id)
    {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }

    let rebound_empty_lineage =
        if let Some(empty_lineage_id) = namespace.empty_lineage_id.as_deref() {
            ensure_lineage_directory_is_empty(app_local_data_dir, empty_lineage_id)?;
            let existing_empty = canonical_lineage_directory(app_local_data_dir, empty_lineage_id)?;
            let rebound = root.join(lineage_id);
            rename_new_no_replace_write_through(&existing_empty, &rebound)?;
            ensure_lineage_directory_is_empty(app_local_data_dir, lineage_id)?;
            directory_sync
                .sync_directory(&root)
                .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;
            true
        } else {
            false
        };

    if !rebound_empty_lineage && enumerate_lineage_ids(app_local_data_dir)? != preserved_lineage_ids
    {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }

    let lineage_directory = root.join(lineage_id);
    if !rebound_empty_lineage {
        fs::create_dir(&lineage_directory)?;
    }
    ensure_plain_directory_metadata(&fs::symlink_metadata(&lineage_directory)?)?;
    ensure_lineage_directory_is_empty(app_local_data_dir, lineage_id)?;
    directory_sync
        .sync_directory(&root)
        .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;
    directory_sync
        .sync_directory(app_local_data_dir)
        .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;

    preserved_lineage_ids.push(lineage_id.to_owned());
    preserved_lineage_ids.sort();
    if enumerate_lineage_ids(app_local_data_dir)? != preserved_lineage_ids {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    // Keep every frozen historical evidence handle alive until all namespace
    // writes and final enumeration checks have completed. On Windows these
    // handles deny write/delete sharing, so a checkpoint or sidecar cannot be
    // swapped after the pre-write byte comparison.
    drop(terminal_lineage_pins);
    Ok(ReceiptZeroBootstrap {
        app_local_data_dir: app_local_data_dir.to_path_buf(),
        lineage_id: lineage_id.to_owned(),
        lineage_ids: preserved_lineage_ids,
        _verified: (),
    })
}

struct PinnedTerminalLineageFiles {
    _files: Vec<File>,
}

fn terminal_evidence_file_names() -> BTreeSet<String> {
    V031CheckpointKind::ALL
        .into_iter()
        .flat_map(|kind| {
            [
                kind.identity_final_basename().to_owned(),
                kind.bundle_final_basename().to_owned(),
            ]
        })
        .chain([
            STEP8_PREDECESSOR_EVIDENCE_FINAL.to_owned(),
            UPGRADE_COMPLETE_EVIDENCE_FINAL.to_owned(),
        ])
        .collect()
}

fn verify_terminal_lineage_bytes_unchanged(
    app_local_data_dir: &Path,
    lineage: &AuthenticatedLineageInventory,
    verified: &VerifiedOriginalRollbackV2,
) -> Result<PinnedTerminalLineageFiles, R2InfrastructureError> {
    if lineage.app_local_data_dir != app_local_data_dir
        || lineage.lineage_id != verified.lineage_id
        || !is_terminal_upgrade_lineage(lineage)
        || verified
            .terminal_evidence_files
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != terminal_evidence_file_names()
    {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    let directory = canonical_lineage_directory(app_local_data_dir, &lineage.lineage_id)?;
    let mut expected_files = BTreeMap::new();
    for receipt in &lineage.final_receipts {
        let descriptor = V031_RECEIPTS
            .get(usize::from(receipt.ordinal))
            .ok_or(R2InfrastructureError::ReceiptZeroBootstrapMismatch)?;
        expected_files.insert(
            descriptor.final_basename.to_owned(),
            FrozenTerminalEvidenceFile {
                file_bytes: u64::try_from(receipt.protected_byte_len)
                    .map_err(|_| R2InfrastructureError::ReceiptZeroBootstrapMismatch)?,
                sha256: receipt.protected_file_sha256.clone(),
            },
        );
    }
    expected_files.insert(
        V2_IDENTITY_FINAL.to_owned(),
        FrozenTerminalEvidenceFile {
            file_bytes: verified.identity_protected_bytes,
            sha256: verified.identity_protected_sha256.clone(),
        },
    );
    expected_files.insert(
        V2_BUNDLE_FINAL.to_owned(),
        FrozenTerminalEvidenceFile {
            file_bytes: verified.bundle_bytes,
            sha256: verified.bundle_sha256.clone(),
        },
    );
    expected_files.extend(verified.terminal_evidence_files.clone());
    let expected_names = expected_files.keys().cloned().collect::<BTreeSet<_>>();
    let mut actual_names = BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| R2InfrastructureError::UnexpectedLineageEvidence)?;
        verify_plain_single_link_file(&entry.path())?;
        if !actual_names.insert(name) {
            return Err(R2InfrastructureError::UnexpectedLineageEvidence);
        }
    }
    if actual_names != expected_names {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    let mut pinned_files = Vec::with_capacity(expected_files.len());
    for (basename, expected) in expected_files {
        if expected.file_bytes == 0 || !is_lower_hex_sha256(&expected.sha256) {
            return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
        }
        let (observed_bytes, observed_sha256, pinned) =
            hash_pinned_plain_file(&directory.join(basename), expected.file_bytes)?;
        if observed_bytes != expected.file_bytes || observed_sha256 != expected.sha256 {
            return Err(R2InfrastructureError::BoundedReadChanged);
        }
        pinned_files.push(pinned);
    }
    Ok(PinnedTerminalLineageFiles {
        _files: pinned_files,
    })
}

fn is_terminal_upgrade_lineage(lineage: &AuthenticatedLineageInventory) -> bool {
    lineage.final_receipts.len() == V031_RECEIPTS.len()
        && lineage
            .final_receipts
            .iter()
            .enumerate()
            .all(|(ordinal, receipt)| usize::from(receipt.ordinal) == ordinal)
        && lineage.next_incoming_receipt.is_none()
        && lineage.v2.identity_final
        && lineage.v2.bundle_final
        && !lineage.v2.identity_incoming
        && !lineage.v2.bundle_incoming
        && !lineage.v2.user_snapshot_incoming
        && !lineage.v2.privacy_snapshot_incoming
        && lineage.checkpoints.binding.is_exact_final()
        && lineage.checkpoints.materials.is_exact_final()
        && lineage.checkpoints.projection.is_exact_final()
        && lineage.step8_predecessor.is_exact_final()
        && lineage.upgrade_complete_evidence.is_exact_final()
}

fn verify_receipt_zero_namespace_shape(
    app_local_data_dir: &Path,
    namespace: &ReceiptZeroNamespaceInventory,
) -> Result<(), R2InfrastructureError> {
    let root = app_local_data_dir.join(MIGRATION_BACKUPS_DIRECTORY);
    match fs::symlink_metadata(&root) {
        Ok(metadata) => {
            if !namespace.root_present {
                return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
            }
            ensure_plain_directory_metadata(&metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if namespace.root_present {
                return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
            }
        }
        Err(error) => return Err(error.into()),
    }
    if enumerate_lineage_ids(app_local_data_dir)? != namespace.lineage_ids {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    if let Some(lineage_id) = namespace.empty_lineage_id.as_deref() {
        ensure_lineage_directory_is_empty(app_local_data_dir, lineage_id)?;
    }
    Ok(())
}

fn lineage_directory_is_empty(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<bool, R2InfrastructureError> {
    let directory = canonical_lineage_directory(app_local_data_dir, lineage_id)?;
    ensure_plain_directory_metadata(&fs::symlink_metadata(&directory)?)?;
    let mut entries = fs::read_dir(directory)?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(error.into()),
    }
}

fn ensure_lineage_directory_is_empty(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<(), R2InfrastructureError> {
    if lineage_directory_is_empty(app_local_data_dir, lineage_id)? {
        Ok(())
    } else {
        Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch)
    }
}

/// Authenticates the complete fixed migration-backups namespace. An empty
/// root or an empty lineage directory is not evidence and fails closed; an
/// in-progress lineage must contain at least an authenticated ordinal-zero
/// final or incoming receipt.
pub fn authenticate_migration_backups<B, F>(
    app_local_data_dir: &Path,
    mut bridge_for_lineage: F,
) -> Result<AuthenticatedMigrationBackupsInventory, R2InfrastructureError>
where
    B: ReceiptAuthenticationBridge,
    F: FnMut(&str) -> B,
{
    let lineage_ids = enumerate_lineage_ids(app_local_data_dir)?;
    if lineage_ids.is_empty() {
        return Err(R2InfrastructureError::MigrationBackupsAuthenticationRequired);
    }
    let mut lineages = Vec::with_capacity(lineage_ids.len());
    for lineage_id in &lineage_ids {
        let bridge = bridge_for_lineage(lineage_id);
        let inventory =
            enumerate_and_authenticate_lineage(app_local_data_dir, lineage_id, &bridge)?;
        let has_authenticated_zero = inventory
            .final_receipts
            .first()
            .is_some_and(|receipt| receipt.ordinal == 0)
            || inventory
                .next_incoming_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.ordinal == 0);
        if !has_authenticated_zero {
            return Err(R2InfrastructureError::MigrationBackupsAuthenticationRequired);
        }
        lineages.push(inventory);
    }
    Ok(AuthenticatedMigrationBackupsInventory {
        app_local_data_dir: app_local_data_dir.to_path_buf(),
        lineage_ids,
        lineages,
        _authenticated: (),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassifiedLineageEntry {
    V2IdentityFinal,
    V2IdentityIncoming,
    V2BundleFinal,
    V2BundleIncoming,
    UserSnapshotIncoming,
    PrivacySnapshotIncoming,
    CheckpointIdentityFinal(V031CheckpointKind),
    CheckpointIdentityIncoming(V031CheckpointKind),
    CheckpointBundleFinal(V031CheckpointKind),
    CheckpointBundleIncoming(V031CheckpointKind),
    Step8PredecessorFinal,
    Step8PredecessorIncoming,
    UpgradeCompleteEvidenceFinal,
    UpgradeCompleteEvidenceIncoming,
    ReceiptFinal(ReceiptDescriptor),
    ReceiptIncoming(ReceiptDescriptor),
}

fn classify_lineage_basename(name: &str) -> Option<ClassifiedLineageEntry> {
    let fixed = match name {
        V2_IDENTITY_FINAL => Some(ClassifiedLineageEntry::V2IdentityFinal),
        V2_IDENTITY_INCOMING => Some(ClassifiedLineageEntry::V2IdentityIncoming),
        V2_BUNDLE_FINAL => Some(ClassifiedLineageEntry::V2BundleFinal),
        V2_BUNDLE_INCOMING => Some(ClassifiedLineageEntry::V2BundleIncoming),
        USER_SNAPSHOT_INCOMING => Some(ClassifiedLineageEntry::UserSnapshotIncoming),
        PRIVACY_SNAPSHOT_INCOMING => Some(ClassifiedLineageEntry::PrivacySnapshotIncoming),
        STEP8_PREDECESSOR_EVIDENCE_FINAL => Some(ClassifiedLineageEntry::Step8PredecessorFinal),
        STEP8_PREDECESSOR_EVIDENCE_INCOMING => {
            Some(ClassifiedLineageEntry::Step8PredecessorIncoming)
        }
        UPGRADE_COMPLETE_EVIDENCE_FINAL => {
            Some(ClassifiedLineageEntry::UpgradeCompleteEvidenceFinal)
        }
        UPGRADE_COMPLETE_EVIDENCE_INCOMING => {
            Some(ClassifiedLineageEntry::UpgradeCompleteEvidenceIncoming)
        }
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    for kind in V031CheckpointKind::ALL {
        if name == kind.identity_final_basename() {
            return Some(ClassifiedLineageEntry::CheckpointIdentityFinal(kind));
        }
        if name == kind.identity_incoming_basename() {
            return Some(ClassifiedLineageEntry::CheckpointIdentityIncoming(kind));
        }
        if name == kind.bundle_final_basename() {
            return Some(ClassifiedLineageEntry::CheckpointBundleFinal(kind));
        }
        if name == kind.bundle_incoming_basename() {
            return Some(ClassifiedLineageEntry::CheckpointBundleIncoming(kind));
        }
    }
    for descriptor in V031_RECEIPTS {
        if name == descriptor.final_basename {
            return Some(ClassifiedLineageEntry::ReceiptFinal(descriptor));
        }
        if name
            .strip_suffix(".incoming")
            .is_some_and(|final_name| final_name == descriptor.final_basename)
        {
            return Some(ClassifiedLineageEntry::ReceiptIncoming(descriptor));
        }
    }
    None
}

pub fn enumerate_and_authenticate_lineage<B: ReceiptAuthenticationBridge>(
    app_local_data_dir: &Path,
    lineage_id: &str,
    bridge: &B,
) -> Result<AuthenticatedLineageInventory, R2InfrastructureError> {
    let directory = canonical_lineage_directory(app_local_data_dir, lineage_id)?;
    let metadata = fs::symlink_metadata(&directory)?;
    ensure_plain_directory_metadata(&metadata)?;

    let mut v2 = V2EvidenceInventory::default();
    let mut checkpoints = V031CheckpointInventory::default();
    let mut step8_predecessor = Step8PredecessorEvidenceInventory::default();
    let mut upgrade_complete_evidence = UpgradeCompleteEvidenceInventory::default();
    let mut final_receipts = BTreeMap::new();
    let mut incoming_receipts = BTreeMap::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let basename = entry
            .file_name()
            .into_string()
            .map_err(|_| R2InfrastructureError::UnexpectedLineageEvidence)?;
        let classified = classify_lineage_basename(&basename)
            .ok_or(R2InfrastructureError::UnexpectedLineageEvidence)?;
        verify_plain_single_link_file(&entry.path())?;
        match classified {
            ClassifiedLineageEntry::V2IdentityFinal => v2.identity_final = true,
            ClassifiedLineageEntry::V2IdentityIncoming => v2.identity_incoming = true,
            ClassifiedLineageEntry::V2BundleFinal => v2.bundle_final = true,
            ClassifiedLineageEntry::V2BundleIncoming => v2.bundle_incoming = true,
            ClassifiedLineageEntry::UserSnapshotIncoming => v2.user_snapshot_incoming = true,
            ClassifiedLineageEntry::PrivacySnapshotIncoming => {
                v2.privacy_snapshot_incoming = true;
            }
            ClassifiedLineageEntry::CheckpointIdentityFinal(kind) => {
                checkpoint_pair_mut(&mut checkpoints, kind).identity_final = true;
            }
            ClassifiedLineageEntry::CheckpointIdentityIncoming(kind) => {
                checkpoint_pair_mut(&mut checkpoints, kind).identity_incoming = true;
            }
            ClassifiedLineageEntry::CheckpointBundleFinal(kind) => {
                checkpoint_pair_mut(&mut checkpoints, kind).bundle_final = true;
            }
            ClassifiedLineageEntry::CheckpointBundleIncoming(kind) => {
                checkpoint_pair_mut(&mut checkpoints, kind).bundle_incoming = true;
            }
            ClassifiedLineageEntry::Step8PredecessorFinal => {
                step8_predecessor.final_present = true;
            }
            ClassifiedLineageEntry::Step8PredecessorIncoming => {
                step8_predecessor.incoming_present = true;
            }
            ClassifiedLineageEntry::UpgradeCompleteEvidenceFinal => {
                upgrade_complete_evidence.final_present = true;
            }
            ClassifiedLineageEntry::UpgradeCompleteEvidenceIncoming => {
                upgrade_complete_evidence.incoming_present = true;
            }
            ClassifiedLineageEntry::ReceiptFinal(descriptor) => {
                final_receipts.insert(descriptor.ordinal, (descriptor, entry.path()));
            }
            ClassifiedLineageEntry::ReceiptIncoming(descriptor) => {
                incoming_receipts.insert(descriptor.ordinal, (descriptor, entry.path()));
            }
        }
    }

    validate_v2_evidence_order(v2)?;
    for kind in V031CheckpointKind::ALL {
        validate_checkpoint_evidence_order(checkpoint_pair(&checkpoints, kind))?;
    }
    let expected_final_ordinals = (0..final_receipts.len() as u8).collect::<BTreeSet<_>>();
    if final_receipts.keys().copied().collect::<BTreeSet<_>>() != expected_final_ordinals {
        return Err(R2InfrastructureError::ReceiptPrefixIsNotContiguous);
    }
    if incoming_receipts.len() > 1
        || incoming_receipts
            .keys()
            .next()
            .is_some_and(|ordinal| usize::from(*ordinal) != final_receipts.len())
        || (!incoming_receipts.is_empty() && final_receipts.len() == V031_RECEIPTS.len())
    {
        return Err(R2InfrastructureError::MultipleOrOutOfOrderIncomingReceipts);
    }

    let mut authenticated_finals = Vec::with_capacity(final_receipts.len());
    let mut previous_sha256: Option<String> = None;
    let mut envelope_binding_id: Option<String> = None;
    let mut source_profile_proof_sha256: Option<String> = None;
    let mut previous_created_at_unix: Option<i64> = None;
    for ordinal in 0..final_receipts.len() as u8 {
        let (descriptor, path) = final_receipts
            .get(&ordinal)
            .expect("contiguous receipt prefix was proven");
        let authenticated = authenticate_receipt_file(
            path,
            *descriptor,
            lineage_id,
            previous_sha256.as_deref(),
            false,
            bridge,
        )?;
        validate_chain_constant_fields(
            &authenticated,
            envelope_binding_id.as_deref(),
            source_profile_proof_sha256.as_deref(),
        )?;
        if previous_created_at_unix
            .is_some_and(|previous| authenticated.metadata.created_at_unix < previous)
        {
            return Err(R2InfrastructureError::ReceiptTimestampRegression {
                ordinal,
                incoming: false,
            });
        }
        previous_created_at_unix = Some(authenticated.metadata.created_at_unix);
        envelope_binding_id
            .get_or_insert_with(|| authenticated.metadata.envelope_binding_id.clone());
        source_profile_proof_sha256
            .get_or_insert_with(|| authenticated.metadata.source_profile_proof_sha256.clone());
        previous_sha256 = Some(authenticated.protected_file_sha256.clone());
        authenticated_finals.push(authenticated);
    }

    let next_incoming_receipt = incoming_receipts
        .into_values()
        .next()
        .map(|(descriptor, path)| {
            authenticate_receipt_file(
                &path,
                descriptor,
                lineage_id,
                previous_sha256.as_deref(),
                true,
                bridge,
            )
        })
        .transpose()?;
    if let Some(incoming) = next_incoming_receipt.as_ref() {
        validate_chain_constant_fields(
            incoming,
            envelope_binding_id.as_deref(),
            source_profile_proof_sha256.as_deref(),
        )?;
        if previous_created_at_unix
            .is_some_and(|previous| incoming.metadata.created_at_unix < previous)
        {
            return Err(R2InfrastructureError::ReceiptTimestampRegression {
                ordinal: incoming.ordinal,
                incoming: true,
            });
        }
    }

    validate_lineage_cross_state(
        &v2,
        &checkpoints,
        step8_predecessor,
        upgrade_complete_evidence,
        &authenticated_finals,
        next_incoming_receipt.as_ref(),
    )?;

    Ok(AuthenticatedLineageInventory {
        app_local_data_dir: app_local_data_dir.to_path_buf(),
        lineage_id: lineage_id.to_owned(),
        v2,
        checkpoints,
        step8_predecessor,
        upgrade_complete_evidence,
        final_receipts: authenticated_finals,
        next_incoming_receipt,
        _authenticated: (),
    })
}

fn validate_lineage_cross_state(
    v2: &V2EvidenceInventory,
    checkpoints: &V031CheckpointInventory,
    step8_predecessor: Step8PredecessorEvidenceInventory,
    upgrade_complete_evidence: UpgradeCompleteEvidenceInventory,
    final_receipts: &[AuthenticatedReceiptFile],
    next_incoming_receipt: Option<&AuthenticatedReceiptFile>,
) -> Result<(), R2InfrastructureError> {
    if step8_predecessor.final_present && step8_predecessor.incoming_present {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    if upgrade_complete_evidence.final_present && upgrade_complete_evidence.incoming_present {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    if !step8_predecessor.is_absent() && final_receipts.len() < 9 {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    if (final_receipts.len() == 10
        || next_incoming_receipt.is_some_and(|receipt| receipt.ordinal == 9))
        && !step8_predecessor.is_exact_final()
    {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    if !upgrade_complete_evidence.is_absent()
        && (final_receipts.len() < 9 || !step8_predecessor.is_exact_final())
    {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    if (final_receipts.len() == 10
        || next_incoming_receipt.is_some_and(|receipt| receipt.ordinal == 9))
        && !upgrade_complete_evidence.is_exact_final()
    {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    let has_any_v2_evidence = v2.identity_final
        || v2.identity_incoming
        || v2.bundle_final
        || v2.bundle_incoming
        || v2.user_snapshot_incoming
        || v2.privacy_snapshot_incoming;
    let has_final_receipt_zero = final_receipts
        .first()
        .is_some_and(|receipt| receipt.ordinal == 0);
    if has_any_v2_evidence && !has_final_receipt_zero {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }

    let has_or_is_installing_receipt_one = final_receipts.len() >= 2
        || next_incoming_receipt.is_some_and(|receipt| receipt.ordinal >= 1);
    let has_exact_final_v2_pair = v2_evidence_is_exact_final(v2);
    if has_or_is_installing_receipt_one && !has_exact_final_v2_pair {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }

    // Receipt 02 proves that the target components used by the binding and
    // case-material checkpoints are fixed.  Both checkpoints must be durable
    // before receipt 03 may be installed.  At the exact 02 prefix they are
    // built in their fixed order and may therefore be in one of the audited
    // crash-resume states accepted by `validate_checkpoint_evidence_order`.
    let binding = checkpoints.binding;
    let materials = checkpoints.materials;
    if !materials.is_absent() && !binding.is_exact_final() {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    match final_receipts.len() {
        0..=2 => {
            if !binding.is_absent() || !materials.is_absent() {
                return Err(R2InfrastructureError::LineageStateMismatch);
            }
        }
        3 if next_incoming_receipt.is_none() => {}
        _ => {
            if !binding.is_exact_final() || !materials.is_exact_final() {
                return Err(R2InfrastructureError::LineageStateMismatch);
            }
        }
    }

    // Receipt 05 fixes the Privacy-v5 projection source.  Its checkpoint is
    // the prerequisite for installing receipt 06 and remains mandatory for
    // every later receipt in the lineage.
    let projection = checkpoints.projection;
    match final_receipts.len() {
        0..=5 => {
            if !projection.is_absent() {
                return Err(R2InfrastructureError::LineageStateMismatch);
            }
        }
        6 if next_incoming_receipt.is_none() => {}
        _ => {
            if !projection.is_exact_final() {
                return Err(R2InfrastructureError::LineageStateMismatch);
            }
        }
    }
    Ok(())
}

fn v2_evidence_is_exact_final(v2: &V2EvidenceInventory) -> bool {
    v2.identity_final
        && v2.bundle_final
        && !v2.identity_incoming
        && !v2.bundle_incoming
        && !v2.user_snapshot_incoming
        && !v2.privacy_snapshot_incoming
}

fn validate_next_receipt_prerequisites(
    inventory: &AuthenticatedLineageInventory,
    ordinal: u8,
) -> Result<(), R2InfrastructureError> {
    let valid = match ordinal {
        1 => v2_evidence_is_exact_final(&inventory.v2),
        3 => {
            inventory.checkpoints.binding.is_exact_final()
                && inventory.checkpoints.materials.is_exact_final()
        }
        6 => inventory.checkpoints.projection.is_exact_final(),
        9 => {
            inventory.step8_predecessor.is_exact_final()
                && inventory.upgrade_complete_evidence.is_exact_final()
        }
        _ => true,
    };
    if !valid {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    Ok(())
}

fn checkpoint_pair(
    checkpoints: &V031CheckpointInventory,
    kind: V031CheckpointKind,
) -> CheckpointPairInventory {
    match kind {
        V031CheckpointKind::Binding => checkpoints.binding,
        V031CheckpointKind::Materials => checkpoints.materials,
        V031CheckpointKind::Projection => checkpoints.projection,
    }
}

fn checkpoint_pair_mut(
    checkpoints: &mut V031CheckpointInventory,
    kind: V031CheckpointKind,
) -> &mut CheckpointPairInventory {
    match kind {
        V031CheckpointKind::Binding => &mut checkpoints.binding,
        V031CheckpointKind::Materials => &mut checkpoints.materials,
        V031CheckpointKind::Projection => &mut checkpoints.projection,
    }
}

fn validate_checkpoint_evidence_order(
    evidence: CheckpointPairInventory,
) -> Result<(), R2InfrastructureError> {
    let valid_crash_state = matches!(
        (
            evidence.identity_final,
            evidence.identity_incoming,
            evidence.bundle_final,
            evidence.bundle_incoming,
        ),
        // The bundle is staged first.  The identity is installed first so a
        // final identity can only coexist with its still-incoming bundle.
        (false, false, false, false)
            | (false, false, false, true)
            | (false, true, false, true)
            | (true, false, false, true)
            | (true, false, true, false)
    );
    if !valid_crash_state {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    Ok(())
}

fn validate_v2_evidence_order(evidence: V2EvidenceInventory) -> Result<(), R2InfrastructureError> {
    let valid_crash_state = matches!(
        (
            evidence.identity_final,
            evidence.identity_incoming,
            evidence.bundle_final,
            evidence.bundle_incoming,
        ),
        // No identity/bundle evidence yet. Either, both, or neither fixed
        // SQLite snapshot may still be present during the build window.
        (false, false, false, false)
            // Bundle is staged before either identity installation attempt.
            | (false, false, false, true)
            // Both staged files exist before identity is installed.
            | (false, true, false, true)
            // Identity is final; the matching staged bundle is the only legal
            // continuation and must be authenticated before installation.
            | (true, false, false, true)
            // Both no-replacement installations completed.
            | (true, false, true, false)
    );
    if !valid_crash_state {
        return Err(R2InfrastructureError::V2EvidenceOrderInvalid);
    }
    Ok(())
}

fn authenticate_receipt_file<B: ReceiptAuthenticationBridge>(
    path: &Path,
    descriptor: ReceiptDescriptor,
    lineage_id: &str,
    previous_receipt_sha256: Option<&str>,
    incoming: bool,
    bridge: &B,
) -> Result<AuthenticatedReceiptFile, R2InfrastructureError> {
    let protected_bytes = read_bounded_file(path, MAX_PROTECTED_RECEIPT_BYTES)?;
    let protected_file_sha256 = sha256_hex(&protected_bytes);
    let expectation = ReceiptExpectation {
        descriptor,
        lineage_id,
        previous_receipt_sha256,
        incoming,
    };
    let metadata = bridge
        .authenticate_protected_receipt(&protected_bytes, expectation)
        .map_err(|_| R2InfrastructureError::ReceiptAuthenticationRejected {
            ordinal: descriptor.ordinal,
            incoming,
        })?;
    validate_authenticated_receipt(&metadata, expectation)?;
    Ok(AuthenticatedReceiptFile {
        ordinal: descriptor.ordinal,
        stage: descriptor.stage,
        incoming,
        protected_file_sha256,
        protected_byte_len: protected_bytes.len(),
        metadata,
    })
}

fn validate_authenticated_receipt(
    receipt: &AuthenticatedReceiptMetadata,
    expectation: ReceiptExpectation<'_>,
) -> Result<(), R2InfrastructureError> {
    let metadata_matches = receipt.schema_version == V031_RECEIPT_SCHEMA
        && receipt.migration_id == V031_MIGRATION_ID
        && receipt.lineage_id == expectation.lineage_id
        && receipt.ordinal == expectation.descriptor.ordinal
        && receipt.stage == expectation.descriptor.stage
        && receipt.previous_receipt_sha256.as_deref() == expectation.previous_receipt_sha256
        && receipt.result_code == "ok"
        && receipt.created_at_unix >= 0
        && is_envelope_binding_id(&receipt.envelope_binding_id)
        && is_lower_hex_sha256(&receipt.source_profile_proof_sha256)
        && is_lower_hex_sha256(&receipt.evidence_sha256)
        && is_bounded_schema_token(&receipt.evidence_schema_version)
        && receipt.counts.len() <= 64
        && receipt.counts.keys().all(|key| is_bounded_count_key(key));
    if !metadata_matches {
        return Err(R2InfrastructureError::ReceiptMetadataMismatch {
            ordinal: expectation.descriptor.ordinal,
            incoming: expectation.incoming,
        });
    }
    Ok(())
}

fn validate_chain_constant_fields(
    receipt: &AuthenticatedReceiptFile,
    envelope_binding_id: Option<&str>,
    source_profile_proof_sha256: Option<&str>,
) -> Result<(), R2InfrastructureError> {
    if envelope_binding_id.is_some_and(|expected| receipt.metadata.envelope_binding_id != expected)
        || source_profile_proof_sha256
            .is_some_and(|expected| receipt.metadata.source_profile_proof_sha256 != expected)
    {
        return Err(R2InfrastructureError::ReceiptMetadataMismatch {
            ordinal: receipt.ordinal,
            incoming: receipt.incoming,
        });
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_envelope_binding_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("ws_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_bounded_schema_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_bounded_count_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn read_bounded_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, R2InfrastructureError> {
    let mut file = open_guarded_plain_single_link_file(path)?;
    let metadata_before = file.metadata()?;
    if metadata_before.len() > maximum_bytes as u64 {
        return Err(R2InfrastructureError::ReceiptTooLarge);
    }
    let modified_before = metadata_before.modified()?;
    let mut bytes = Vec::with_capacity(metadata_before.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(R2InfrastructureError::ReceiptTooLarge);
    }
    let metadata_after = file.metadata()?;
    if metadata_before.len() != metadata_after.len()
        || modified_before != metadata_after.modified()?
        || bytes.len() as u64 != metadata_after.len()
    {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    Ok(bytes)
}

fn terminal_evidence_maximum_bytes(basename: &str) -> Result<u64, R2InfrastructureError> {
    if basename == STEP8_PREDECESSOR_EVIDENCE_FINAL || basename == UPGRADE_COMPLETE_EVIDENCE_FINAL {
        return Ok(MAX_PROTECTED_RECEIPT_BYTES as u64);
    }
    if V031CheckpointKind::ALL.into_iter().any(|kind| {
        basename == kind.identity_final_basename() || basename == kind.bundle_final_basename()
    }) {
        return u64::try_from(privacy::MAX_APPLICATION_BACKUP_BYTES.saturating_add(64 * 1024))
            .map_err(|_| R2InfrastructureError::ReceiptTooLarge);
    }
    Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch)
}

fn hash_pinned_plain_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<(u64, String, File), R2InfrastructureError> {
    let mut file = open_guarded_plain_single_link_file(path)?;
    let metadata_before = file.metadata()?;
    let file_bytes = metadata_before.len();
    if file_bytes > maximum_bytes {
        return Err(R2InfrastructureError::ReceiptTooLarge);
    }
    let modified_before = metadata_before.modified()?;
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| R2InfrastructureError::ReceiptTooLarge)?;
        total = total
            .checked_add(read_u64)
            .ok_or(R2InfrastructureError::ReceiptTooLarge)?;
        if total > maximum_bytes {
            return Err(R2InfrastructureError::ReceiptTooLarge);
        }
        hasher.update(&buffer[..read]);
    }
    let metadata_after = file.metadata()?;
    if total != file_bytes
        || metadata_after.len() != file_bytes
        || metadata_after.modified()? != modified_before
    {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    let digest = hasher.finalize();
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((file_bytes, sha256, file))
}

pub(crate) fn verify_plain_single_link_file(path: &Path) -> Result<(), R2InfrastructureError> {
    open_guarded_plain_single_link_file(path).map(|_| ())
}

fn open_guarded_plain_single_link_file(path: &Path) -> Result<File, R2InfrastructureError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(R2InfrastructureError::UnsafeLineageEntry);
    }

    #[cfg(windows)]
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    #[cfg(not(windows))]
    let file = OpenOptions::new().read(true).open(path)?;

    #[cfg(windows)]
    {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns a valid handle and `information` is writable for
        // the duration of the Win32 call.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
        if succeeded == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
            != 0
            || information.nNumberOfLinks != 1
        {
            return Err(R2InfrastructureError::UnsafeLineageEntry);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(R2InfrastructureError::UnsafeLineageEntry);
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        return Err(R2InfrastructureError::UnsafeLineageEntry);
    }
    Ok(file)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub trait DirectorySync {
    type Error;

    fn sync_directory(&self, directory: &Path) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformDirectorySync;

impl DirectorySync for PlatformDirectorySync {
    type Error = std::io::Error;

    fn sync_directory(&self, directory: &Path) -> Result<(), Self::Error> {
        sync_directory_platform(directory)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledReceipt {
    pub receipt: AuthenticatedReceiptFile,
    pub resumed_existing_incoming: bool,
}

/// Installs the unique next receipt using the frozen append-only protocol.
///
/// The lineage directory must already exist.  This function never creates a
/// Credential, target component, or lineage directory.  It authenticates all
/// existing evidence before writing, writes only the exact next `.incoming`
/// basename with create-new semantics, flushes and syncs the file, authenticates
/// its readback, performs a no-replacement write-through rename, invokes the
/// directory durability barrier, and authenticates the final file again.
pub fn install_next_receipt<B: ReceiptAuthenticationBridge, D: DirectorySync>(
    app_local_data_dir: &Path,
    lineage_id: &str,
    ordinal: u8,
    protected_file_bytes: &[u8],
    bridge: &B,
    directory_sync: &D,
) -> Result<InstalledReceipt, R2InfrastructureError> {
    if protected_file_bytes.is_empty() || protected_file_bytes.len() > MAX_PROTECTED_RECEIPT_BYTES {
        return Err(R2InfrastructureError::ReceiptTooLarge);
    }
    let descriptor = V031_RECEIPTS
        .get(usize::from(ordinal))
        .copied()
        .ok_or(R2InfrastructureError::ReceiptIsNotNext)?;
    let before = enumerate_and_authenticate_lineage(app_local_data_dir, lineage_id, bridge)?;
    if usize::from(ordinal) < before.final_receipts.len() {
        return Err(R2InfrastructureError::ExistingFinalRequiresStateVerification);
    }
    if usize::from(ordinal) != before.final_receipts.len() {
        return Err(R2InfrastructureError::ReceiptIsNotNext);
    }
    // Fresh installs do not yet have an incoming receipt for cross-state
    // validation to observe.  Enforce every filesystem prerequisite for the
    // prospective 1/3/6/9 boundary before creating its incoming file.
    validate_next_receipt_prerequisites(&before, ordinal)?;

    let directory = canonical_lineage_directory(app_local_data_dir, lineage_id)?;
    let final_path = directory.join(descriptor.final_basename);
    let incoming_path = directory.join(format!("{}.incoming", descriptor.final_basename));
    let expected_sha256 = sha256_hex(protected_file_bytes);
    let resumed_existing_incoming = if let Some(incoming) = before.next_incoming_receipt.as_ref() {
        if incoming.ordinal != ordinal || incoming.protected_file_sha256 != expected_sha256 {
            return Err(R2InfrastructureError::ExistingIncomingDiffers);
        }
        let existing = read_bounded_file(&incoming_path, MAX_PROTECTED_RECEIPT_BYTES)?;
        if existing != protected_file_bytes {
            return Err(R2InfrastructureError::ExistingIncomingDiffers);
        }
        true
    } else {
        write_create_new_sync(
            &incoming_path,
            protected_file_bytes,
            MAX_PROTECTED_RECEIPT_BYTES,
        )?;
        false
    };

    let previous_sha256 = before
        .final_receipts
        .last()
        .map(|receipt| receipt.protected_file_sha256.as_str());
    let staged = authenticate_receipt_file(
        &incoming_path,
        descriptor,
        lineage_id,
        previous_sha256,
        true,
        bridge,
    )?;
    if staged.protected_file_sha256 != expected_sha256 {
        return Err(R2InfrastructureError::ExistingIncomingDiffers);
    }
    if let Some(anchor) = before.final_receipts.first() {
        validate_chain_constant_fields(
            &staged,
            Some(&anchor.metadata.envelope_binding_id),
            Some(&anchor.metadata.source_profile_proof_sha256),
        )?;
    }
    if let Some(existing) = before.next_incoming_receipt.as_ref() {
        if staged.metadata != existing.metadata {
            return Err(R2InfrastructureError::ExistingIncomingDiffers);
        }
    }

    #[cfg(test)]
    if FAIL_NEXT_RECEIPT_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.replace(false)) {
        // Model process loss after the create-new incoming file is durable and
        // authenticated, but before its no-replacement final rename.  The
        // production resume path must consume these exact bytes on restart.
        return Err(R2InfrastructureError::DirectorySyncFailed);
    }

    rename_new_no_replace_write_through(&incoming_path, &final_path)?;
    directory_sync
        .sync_directory(&directory)
        .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;

    let final_receipt = authenticate_receipt_file(
        &final_path,
        descriptor,
        lineage_id,
        previous_sha256,
        false,
        bridge,
    )?;
    if final_receipt.protected_file_sha256 != expected_sha256
        || final_receipt.metadata != staged.metadata
    {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    let after = enumerate_and_authenticate_lineage(app_local_data_dir, lineage_id, bridge)?;
    if after.final_receipts.len() != usize::from(ordinal) + 1
        || after.next_incoming_receipt.is_some()
        || after.final_receipts.last() != Some(&final_receipt)
    {
        return Err(R2InfrastructureError::ReceiptPrefixIsNotContiguous);
    }

    Ok(InstalledReceipt {
        receipt: final_receipt,
        resumed_existing_incoming,
    })
}

pub struct OriginalRollbackV2InstallRequest<'a> {
    pub source_profile_proof_sha256: &'a str,
    pub source_user_physical_file_set_sha256: &'a str,
    pub source_privacy_physical_file_set_sha256: &'a str,
    pub source_user_logical_manifest_sha256: &'a str,
    pub source_user_business_manifest_sha256: &'a str,
    pub source_privacy_logical_manifest_sha256: &'a str,
    pub source_privacy_business_manifest_sha256: &'a str,
    pub envelope_binding_id: &'a str,
    pub lineage_id: &'a str,
    pub user_database_snapshot: &'a [u8],
    pub privacy_store_snapshot: &'a [u8],
}

/// Read-only context for authenticating an already-installed Original V2
/// rollback point after its plaintext build snapshots have been removed.
pub struct OriginalRollbackV2VerificationRequest<'a> {
    pub source_profile_proof_sha256: &'a str,
    pub source_user_physical_file_set_sha256: &'a str,
    pub source_privacy_physical_file_set_sha256: &'a str,
    pub source_user_logical_manifest_sha256: &'a str,
    pub source_user_business_manifest_sha256: &'a str,
    pub source_privacy_logical_manifest_sha256: &'a str,
    pub source_privacy_business_manifest_sha256: &'a str,
    pub envelope_binding_id: &'a str,
    pub lineage_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOriginalRollbackV2 {
    lineage_id: String,
    identity_protected_sha256: String,
    identity_protected_bytes: u64,
    bundle_sha256: String,
    bundle_bytes: u64,
    encrypted_chunks: u64,
    user_database_snapshot_sha256: String,
    privacy_store_snapshot_sha256: String,
    #[cfg(test)]
    slot_identity_sha256: String,
    terminal_evidence_files: BTreeMap<String, FrozenTerminalEvidenceFile>,
    _verified: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenTerminalEvidenceFile {
    file_bytes: u64,
    sha256: String,
}

impl VerifiedOriginalRollbackV2 {
    pub fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    pub fn identity_protected_sha256(&self) -> &str {
        &self.identity_protected_sha256
    }

    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    pub const fn bundle_bytes(&self) -> u64 {
        self.bundle_bytes
    }

    pub const fn encrypted_chunks(&self) -> u64 {
        self.encrypted_chunks
    }

    pub fn user_database_snapshot_sha256(&self) -> &str {
        &self.user_database_snapshot_sha256
    }

    pub fn privacy_store_snapshot_sha256(&self) -> &str {
        &self.privacy_store_snapshot_sha256
    }

    #[cfg(test)]
    pub fn slot_identity_sha256(&self) -> &str {
        &self.slot_identity_sha256
    }
}

/// Extends an already authenticated Original-V2 capability with the exact six
/// checkpoint and two terminal-sidecar byte anchors obtained by the caller's
/// full DPAPI terminal-history authentication. The resulting token is the only
/// form accepted by fresh-lineage bootstrap when historical lineages exist.
pub(crate) fn bind_authenticated_terminal_evidence_files(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    mut verified: VerifiedOriginalRollbackV2,
    expected_sha256: &BTreeMap<String, String>,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    if inventory.app_local_data_dir != app_local_data_dir
        || inventory.lineage_id != verified.lineage_id
        || !is_terminal_upgrade_lineage(inventory)
        || expected_sha256.keys().cloned().collect::<BTreeSet<_>>()
            != terminal_evidence_file_names()
    {
        return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
    }
    let directory = canonical_lineage_directory(app_local_data_dir, &inventory.lineage_id)?;
    let mut frozen = BTreeMap::new();
    for (basename, expected_hash) in expected_sha256 {
        if !is_lower_hex_sha256(expected_hash) {
            return Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch);
        }
        let path = directory.join(basename);
        let maximum_bytes = terminal_evidence_maximum_bytes(basename)?;
        let (file_bytes, observed_hash, _pinned) = hash_pinned_plain_file(&path, maximum_bytes)?;
        if observed_hash != *expected_hash || file_bytes == 0 {
            return Err(R2InfrastructureError::BoundedReadChanged);
        }
        frozen.insert(
            basename.clone(),
            FrozenTerminalEvidenceFile {
                file_bytes,
                sha256: observed_hash,
            },
        );
    }
    verified.terminal_evidence_files = frozen;
    Ok(verified)
}

/// Creates or resumes the one frozen Original V2 installation protocol.
///
/// The bundle is staged first, but the protected identity is always the first
/// final artifact. The staged bundle can become final only after the final
/// identity has been re-opened and has authenticated its exact basename,
/// length and SHA-256. The final bundle is then decrypted into an isolated
/// in-memory validation area and compared byte-for-byte with both SQLite
/// snapshots before this function returns a verified token.
pub fn install_or_resume_original_rollback_v2<B: ReceiptAuthenticationBridge, D: DirectorySync>(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    request: &OriginalRollbackV2InstallRequest<'_>,
    bridge: &B,
    directory_sync: &D,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    if inventory.app_local_data_dir != app_local_data_dir
        || inventory.lineage_id != request.lineage_id
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    let receipt_zero = inventory
        .final_receipts
        .first()
        .filter(|receipt| receipt.ordinal == 0)
        .ok_or(R2InfrastructureError::LineageStateMismatch)?;
    let created_at_unix = u64::try_from(receipt_zero.metadata.created_at_unix)
        .map_err(|_| R2InfrastructureError::OriginalRollbackContextMismatch)?;
    if receipt_zero.metadata.envelope_binding_id != request.envelope_binding_id
        || receipt_zero.metadata.source_profile_proof_sha256 != request.source_profile_proof_sha256
        || receipt_zero.metadata.evidence_sha256 != request.source_profile_proof_sha256
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    let verification_request = OriginalRollbackV2VerificationRequest {
        source_profile_proof_sha256: request.source_profile_proof_sha256,
        source_user_physical_file_set_sha256: request.source_user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256: request.source_privacy_physical_file_set_sha256,
        source_user_logical_manifest_sha256: request.source_user_logical_manifest_sha256,
        source_user_business_manifest_sha256: request.source_user_business_manifest_sha256,
        source_privacy_logical_manifest_sha256: request.source_privacy_logical_manifest_sha256,
        source_privacy_business_manifest_sha256: request.source_privacy_business_manifest_sha256,
        envelope_binding_id: request.envelope_binding_id,
        lineage_id: request.lineage_id,
    };

    let directory = canonical_lineage_directory(app_local_data_dir, request.lineage_id)?;
    let bundle_incoming = directory.join(V2_BUNDLE_INCOMING);
    let bundle_final = directory.join(V2_BUNDLE_FINAL);
    let identity_incoming = directory.join(V2_IDENTITY_INCOMING);
    let identity_final = directory.join(V2_IDENTITY_FINAL);

    let bundle_bytes = if inventory.v2.bundle_final {
        read_bounded_file(&bundle_final, MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES)?
    } else if inventory.v2.bundle_incoming {
        read_bounded_file(&bundle_incoming, MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES)?
    } else {
        let (bytes, _) = seal_v031_original_rollback_v2(&V031OriginalRollbackCreateRequest {
            source_profile_proof_sha256: request.source_profile_proof_sha256,
            source_user_physical_file_set_sha256: request.source_user_physical_file_set_sha256,
            source_privacy_physical_file_set_sha256: request
                .source_privacy_physical_file_set_sha256,
            source_user_logical_manifest_sha256: request.source_user_logical_manifest_sha256,
            source_user_business_manifest_sha256: request.source_user_business_manifest_sha256,
            source_privacy_logical_manifest_sha256: request.source_privacy_logical_manifest_sha256,
            source_privacy_business_manifest_sha256: request
                .source_privacy_business_manifest_sha256,
            envelope_binding_id: request.envelope_binding_id,
            lineage_id: request.lineage_id,
            created_at_unix,
            user_database: request.user_database_snapshot,
            privacy_store: request.privacy_store_snapshot,
        })
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
        bytes
    };
    let bundle_sha256 = sha256_hex(&bundle_bytes);
    let opened_without_identity = open_v031_original_rollback_v2(
        &bundle_bytes,
        &V031OriginalRollbackOpenContext {
            expected_source_profile_proof_sha256: request.source_profile_proof_sha256,
            expected_source_user_physical_file_set_sha256: request
                .source_user_physical_file_set_sha256,
            expected_source_privacy_physical_file_set_sha256: request
                .source_privacy_physical_file_set_sha256,
            expected_source_user_logical_manifest_sha256: request
                .source_user_logical_manifest_sha256,
            expected_source_user_business_manifest_sha256: request
                .source_user_business_manifest_sha256,
            expected_source_privacy_logical_manifest_sha256: request
                .source_privacy_logical_manifest_sha256,
            expected_source_privacy_business_manifest_sha256: request
                .source_privacy_business_manifest_sha256,
            expected_envelope_binding_id: request.envelope_binding_id,
            expected_lineage_id: request.lineage_id,
            expected_created_at_unix: created_at_unix,
            expected_bundle_sha256: &bundle_sha256,
        },
    )
    .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    verify_opened_snapshots(&opened_without_identity, request)?;
    let metadata = opened_without_identity.metadata.clone();
    drop(opened_without_identity);

    let identity_protected = if inventory.v2.identity_final {
        read_bounded_file(&identity_final, MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES)?
    } else if inventory.v2.identity_incoming {
        read_bounded_file(
            &identity_incoming,
            MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
        )?
    } else {
        let identity = create_v031_original_rollback_identity_v2(&metadata)
            .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
        protect_v031_original_rollback_identity_v2(&identity)
            .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?
    };
    let identity = open_v031_original_rollback_identity_v2(&identity_protected)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    validate_original_rollback_identity(
        &identity,
        &verification_request,
        &metadata,
        created_at_unix,
    )?;

    if !inventory.v2.bundle_final {
        stage_new_evidence_file(
            &bundle_incoming,
            &bundle_bytes,
            MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES,
        )?;
    }
    if !inventory.v2.identity_final {
        stage_new_evidence_file(
            &identity_incoming,
            &identity_protected,
            MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
        )?;
        install_staged_evidence_file_no_replace(
            &identity_incoming,
            &identity_final,
            &identity_protected,
            MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
            directory_sync,
        )?;
    }

    let final_identity_protected =
        read_bounded_file(&identity_final, MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES)?;
    let final_identity = open_v031_original_rollback_identity_v2(&final_identity_protected)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    validate_original_rollback_identity(
        &final_identity,
        &verification_request,
        &metadata,
        created_at_unix,
    )?;
    if final_identity.bundle_file_name != V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME
        || final_identity.bundle_bytes
            != u64::try_from(bundle_bytes.len())
                .map_err(|_| R2InfrastructureError::OriginalRollbackContextMismatch)?
        || final_identity.bundle_sha256 != bundle_sha256
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }

    if !inventory.v2.bundle_final {
        install_staged_evidence_file_no_replace(
            &bundle_incoming,
            &bundle_final,
            &bundle_bytes,
            MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES,
            directory_sync,
        )?;
    }
    let final_bundle = read_bounded_file(&bundle_final, MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES)?;
    let opened = open_v031_original_rollback_v2_for_identity(&final_bundle, &final_identity)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    verify_opened_snapshots(&opened, request)?;
    let final_metadata = opened.metadata.clone();
    drop(opened);

    let after = enumerate_and_authenticate_lineage(app_local_data_dir, request.lineage_id, bridge)?;
    if !after.v2.identity_final
        || !after.v2.bundle_final
        || after.v2.identity_incoming
        || after.v2.bundle_incoming
    {
        return Err(R2InfrastructureError::LineageStateMismatch);
    }
    verified_original_rollback_v2(
        request.lineage_id,
        &final_identity_protected,
        &final_metadata,
    )
}

/// Authenticates an installed Original V2 rollback point without recreating or
/// retaining either plaintext SQLite build snapshot. The protected identity is
/// opened first, its exact fixed bundle is decrypted in memory, all five slot
/// hashes and authenticated-absent sentinels are checked by the Privacy codec,
/// and the complete receipt/filesystem inventory is authenticated again before
/// returning an opaque verified token.
pub fn verify_installed_original_rollback_v2<B: ReceiptAuthenticationBridge>(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    request: &OriginalRollbackV2VerificationRequest<'_>,
    bridge: &B,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    verify_installed_original_rollback_v2_internal(
        app_local_data_dir,
        inventory,
        request,
        bridge,
        true,
    )
}

/// Authenticates the final identity and bundle during recovery from a crash in
/// the narrow plaintext-snapshot cleanup window. This function never reads or
/// removes a snapshot. The caller may remove only a still-present exact fixed
/// snapshot after independently validating it against the pinned source, then
/// must call [`verify_installed_original_rollback_v2`] before receipt one.
pub fn verify_installed_original_rollback_v2_for_snapshot_cleanup<
    B: ReceiptAuthenticationBridge,
>(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    request: &OriginalRollbackV2VerificationRequest<'_>,
    bridge: &B,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    verify_installed_original_rollback_v2_internal(
        app_local_data_dir,
        inventory,
        request,
        bridge,
        false,
    )
}

fn verify_installed_original_rollback_v2_internal<B: ReceiptAuthenticationBridge>(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    request: &OriginalRollbackV2VerificationRequest<'_>,
    bridge: &B,
    require_snapshots_absent: bool,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    if inventory.app_local_data_dir != app_local_data_dir
        || inventory.lineage_id != request.lineage_id
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    let receipt_zero = inventory
        .final_receipts
        .first()
        .filter(|receipt| receipt.ordinal == 0)
        .ok_or(R2InfrastructureError::LineageStateMismatch)?;
    let created_at_unix = u64::try_from(receipt_zero.metadata.created_at_unix)
        .map_err(|_| R2InfrastructureError::OriginalRollbackContextMismatch)?;
    if receipt_zero.metadata.envelope_binding_id != request.envelope_binding_id
        || receipt_zero.metadata.source_profile_proof_sha256 != request.source_profile_proof_sha256
        || receipt_zero.metadata.evidence_sha256 != request.source_profile_proof_sha256
        || !inventory.v2.identity_final
        || !inventory.v2.bundle_final
        || inventory.v2.identity_incoming
        || inventory.v2.bundle_incoming
        || (require_snapshots_absent
            && (inventory.v2.user_snapshot_incoming || inventory.v2.privacy_snapshot_incoming))
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }

    let directory = canonical_lineage_directory(app_local_data_dir, request.lineage_id)?;
    let identity_protected = read_bounded_file(
        &directory.join(V2_IDENTITY_FINAL),
        MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
    )?;
    let identity = open_v031_original_rollback_identity_v2(&identity_protected)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    if identity.bundle_file_name != V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    let bundle = read_bounded_file(
        &directory.join(V2_BUNDLE_FINAL),
        MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES,
    )?;
    let opened = open_v031_original_rollback_v2_for_identity(&bundle, &identity)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    if opened.authenticated_absent_slots.len() != 3 {
        return Err(R2InfrastructureError::OriginalRollbackAuthenticationFailed);
    }
    validate_original_rollback_identity(&identity, request, &opened.metadata, created_at_unix)?;
    let metadata = opened.metadata.clone();
    drop(opened);

    let after = enumerate_and_authenticate_lineage(app_local_data_dir, request.lineage_id, bridge)?;
    if &after != inventory {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    verified_original_rollback_v2(request.lineage_id, &identity_protected, &metadata)
}

fn verified_original_rollback_v2(
    lineage_id: &str,
    identity_protected: &[u8],
    metadata: &V031OriginalRollbackMetadataV2,
) -> Result<VerifiedOriginalRollbackV2, R2InfrastructureError> {
    let user_database = metadata
        .slots
        .first()
        .ok_or(R2InfrastructureError::OriginalRollbackContextMismatch)?;
    let privacy_store = metadata
        .slots
        .get(1)
        .ok_or(R2InfrastructureError::OriginalRollbackContextMismatch)?;
    #[cfg(test)]
    let slot_identity = canonical_json_v1(&metadata.slots)
        .map_err(|_| R2InfrastructureError::OriginalRollbackAuthenticationFailed)?;
    Ok(VerifiedOriginalRollbackV2 {
        lineage_id: lineage_id.to_owned(),
        identity_protected_sha256: sha256_hex(identity_protected),
        identity_protected_bytes: u64::try_from(identity_protected.len())
            .map_err(|_| R2InfrastructureError::OriginalRollbackContextMismatch)?,
        bundle_sha256: metadata.bundle_sha256.clone(),
        bundle_bytes: metadata.bundle_bytes,
        encrypted_chunks: u64::from(metadata.total_chunk_count),
        user_database_snapshot_sha256: user_database.plaintext_sha256.clone(),
        privacy_store_snapshot_sha256: privacy_store.plaintext_sha256.clone(),
        #[cfg(test)]
        slot_identity_sha256: sha256_hex(&slot_identity),
        terminal_evidence_files: BTreeMap::new(),
        _verified: (),
    })
}

fn verify_opened_snapshots(
    opened: &privacy::original_rollback_v2::OpenedV031OriginalRollbackV2,
    request: &OriginalRollbackV2InstallRequest<'_>,
) -> Result<(), R2InfrastructureError> {
    if opened.user_database != request.user_database_snapshot
        || opened.privacy_store != request.privacy_store_snapshot
        || opened.authenticated_absent_slots.len() != 3
    {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    Ok(())
}

fn validate_original_rollback_identity(
    identity: &V031OriginalRollbackIdentityV2,
    request: &OriginalRollbackV2VerificationRequest<'_>,
    metadata: &V031OriginalRollbackMetadataV2,
    expected_created_at_unix: u64,
) -> Result<(), R2InfrastructureError> {
    let matches = identity.source_profile_proof_sha256 == request.source_profile_proof_sha256
        && identity.source_user_physical_file_set_sha256
            == request.source_user_physical_file_set_sha256
        && identity.source_privacy_physical_file_set_sha256
            == request.source_privacy_physical_file_set_sha256
        && identity.source_user_logical_manifest_sha256
            == request.source_user_logical_manifest_sha256
        && identity.source_user_business_manifest_sha256
            == request.source_user_business_manifest_sha256
        && identity.source_privacy_logical_manifest_sha256
            == request.source_privacy_logical_manifest_sha256
        && identity.source_privacy_business_manifest_sha256
            == request.source_privacy_business_manifest_sha256
        && identity.envelope_binding_id == request.envelope_binding_id
        && identity.lineage_id == request.lineage_id
        && identity.created_at_unix == expected_created_at_unix
        && metadata.created_at_unix == expected_created_at_unix
        && identity.bundle_file_name == V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME
        && identity.bundle_bytes == metadata.bundle_bytes
        && identity.bundle_sha256 == metadata.bundle_sha256
        && identity.wrapped_data_key_sha256 == metadata.wrapped_data_key_sha256
        && identity.total_chunk_count == metadata.total_chunk_count
        && identity.slots == metadata.slots;
    if !matches {
        return Err(R2InfrastructureError::OriginalRollbackContextMismatch);
    }
    Ok(())
}

/// Stages one fixed evidence artifact with create-new semantics. Existing
/// bytes are accepted only when they are exactly identical. The path is never
/// truncated, replaced, renamed, or removed by this helper.
fn stage_new_evidence_file(
    incoming: &Path,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<bool, R2InfrastructureError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(R2InfrastructureError::ReceiptTooLarge);
    }
    match fs::symlink_metadata(incoming) {
        Ok(_) => {
            verify_plain_single_link_file(incoming)?;
            if read_bounded_file(incoming, maximum_bytes)? != bytes {
                return Err(R2InfrastructureError::ExistingIncomingDiffers);
            }
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_create_new_sync(incoming, bytes, maximum_bytes)?;
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

/// Installs a previously staged fixed evidence artifact without replacement.
/// A pre-existing final is an idempotent no-op only when its bytes are exact
/// and the incoming sibling is absent.
fn install_staged_evidence_file_no_replace(
    incoming: &Path,
    destination: &Path,
    expected_bytes: &[u8],
    maximum_bytes: usize,
    directory_sync: &impl DirectorySync,
) -> Result<bool, R2InfrastructureError> {
    if expected_bytes.is_empty()
        || expected_bytes.len() > maximum_bytes
        || incoming.parent() != destination.parent()
    {
        return Err(R2InfrastructureError::AtomicInstallRequiresSiblings);
    }
    let directory = incoming
        .parent()
        .ok_or(R2InfrastructureError::AtomicInstallRequiresSiblings)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            verify_plain_single_link_file(destination)?;
            if fs::symlink_metadata(incoming).is_ok()
                || read_bounded_file(destination, maximum_bytes)? != expected_bytes
            {
                return Err(R2InfrastructureError::ExistingIncomingDiffers);
            }
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    verify_plain_single_link_file(incoming)?;
    if read_bounded_file(incoming, maximum_bytes)? != expected_bytes {
        return Err(R2InfrastructureError::ExistingIncomingDiffers);
    }
    rename_new_no_replace_write_through(incoming, destination)?;
    directory_sync
        .sync_directory(directory)
        .map_err(|_| R2InfrastructureError::DirectorySyncFailed)?;
    verify_plain_single_link_file(destination)?;
    if read_bounded_file(destination, maximum_bytes)? != expected_bytes {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    Ok(true)
}

pub(crate) fn write_create_new_sync(
    path: &Path,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<(), R2InfrastructureError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    options
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    let readback = read_bounded_file(path, maximum_bytes)?;
    if readback != bytes {
        return Err(R2InfrastructureError::BoundedReadChanged);
    }
    Ok(())
}

pub(crate) fn rename_new_no_replace_write_through(
    incoming: &Path,
    destination: &Path,
) -> Result<(), R2InfrastructureError> {
    let parent = incoming
        .parent()
        .filter(|parent| Some(*parent) == destination.parent())
        .ok_or(R2InfrastructureError::AtomicInstallRequiresSiblings)?;
    if incoming.file_name().is_none() || destination.file_name().is_none() {
        return Err(R2InfrastructureError::AtomicInstallRequiresSiblings);
    }
    #[cfg(windows)]
    {
        // Keep the exact, already-validated parent directory open without
        // FILE_SHARE_DELETE for the complete metadata move.  This prevents an
        // attacker from swapping the parent between pathname validation and
        // MoveFileExW, while the before/after path checks prove that the path
        // continues to resolve to the pinned plain directory.
        let pinned_parent = PinnedPlainDirectory::open(parent)?;
        pinned_parent.verify_path_binding()?;
        let incoming = wide_path(incoming);
        let destination = wide_path(destination);
        // SAFETY: both UTF-16 paths are NUL terminated and remain live through
        // the call.  MOVEFILE_REPLACE_EXISTING is deliberately absent.
        let succeeded = unsafe {
            MoveFileExW(
                incoming.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if succeeded == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        pinned_parent.verify_path_binding()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (incoming, destination, parent);
        Err(R2InfrastructureError::AtomicNoReplaceUnavailable)
    }
}

/// Replaces one already-authenticated sibling with its exact authenticated
/// successor. R3 uses this only for the phase-bearing DPAPI marker after both
/// files have been read back and compared as a direct state-machine successor.
pub(crate) fn replace_existing_sibling_write_through(
    incoming: &Path,
    destination: &Path,
) -> Result<(), R2InfrastructureError> {
    let parent = incoming
        .parent()
        .filter(|parent| Some(*parent) == destination.parent())
        .ok_or(R2InfrastructureError::AtomicInstallRequiresSiblings)?;
    if incoming.file_name().is_none() || destination.file_name().is_none() {
        return Err(R2InfrastructureError::AtomicInstallRequiresSiblings);
    }
    #[cfg(windows)]
    {
        let pinned_parent = PinnedPlainDirectory::open(parent)?;
        pinned_parent.verify_path_binding()?;
        let incoming = wide_path(incoming);
        let destination = wide_path(destination);
        // SAFETY: both sibling paths are NUL-terminated and remain alive for
        // the call. The caller authenticated the exact old/new marker pair.
        let succeeded = unsafe {
            MoveFileExW(
                incoming.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if succeeded == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        pinned_parent.verify_path_binding()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (incoming, destination, parent);
        Err(R2InfrastructureError::AtomicNoReplaceUnavailable)
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
#[derive(Debug)]
struct PinnedPlainDirectory {
    handle: File,
    path: PathBuf,
    identity: (u32, u64),
}

#[cfg(windows)]
impl PinnedPlainDirectory {
    fn open(path: &Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || metadata_is_reparse_point(&metadata)
            || !metadata.is_dir()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "R2 pinned parent is not a plain directory",
            ));
        }
        let handle = open_exact_windows_directory(path)?;
        let information = windows_file_information(&handle)?;
        validate_windows_plain_directory(&information)?;
        let pinned = Self {
            handle,
            path: path.to_path_buf(),
            identity: windows_file_identity(&information),
        };
        pinned.verify_path_binding()?;
        Ok(pinned)
    }

    fn verify_path_binding(&self) -> std::io::Result<()> {
        let information = windows_file_information(&self.handle)?;
        validate_windows_plain_directory(&information)?;
        if windows_file_identity(&information) != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "R2 pinned parent handle identity changed",
            ));
        }
        let path_handle = open_exact_windows_directory(&self.path)?;
        let path_information = windows_file_information(&path_handle)?;
        validate_windows_plain_directory(&path_information)?;
        if windows_file_identity(&path_information) != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "R2 pinned parent path identity changed",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn open_exact_windows_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        // Deliberately omit FILE_SHARE_DELETE. While this handle is live, the
        // exact checked directory cannot be renamed or replaced.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
fn windows_file_information(handle: &File) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` owns a valid handle and `information` remains writable
    // for the complete Win32 call.
    let succeeded =
        unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &raw mut information) };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(windows)]
fn windows_file_identity(information: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64) {
    (
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    )
}

#[cfg(windows)]
fn validate_windows_plain_directory(
    information: &BY_HANDLE_FILE_INFORMATION,
) -> std::io::Result<()> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "R2 directory handle is not a plain directory",
        ));
    }
    Ok(())
}

fn sync_directory_platform(directory: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "R2 directory durability target is not a plain directory",
        ));
    }
    #[cfg(windows)]
    {
        let pinned = PinnedPlainDirectory::open(directory)?;
        pinned.verify_path_binding()?;

        // Windows does not expose FlushFileBuffers for directory handles.  The
        // protocol's durable primitives are the already-flushed create-new file
        // and MoveFileExW(..., MOVEFILE_WRITE_THROUGH), which completes the
        // metadata move before returning.  This adapter therefore authenticates
        // and pins the exact parent instead of calling File::sync_all, whose
        // documented handle requirements make it deterministically AccessDenied
        // for a directory.  No other error is swallowed above.
        Ok(())
    }
    #[cfg(not(windows))]
    {
        File::open(directory)?.sync_all()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum AuthenticatedSignal {
    Absent,
    Authenticated,
    UnknownOrInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum V031UpgradeSignal {
    Absent,
    ExactSourceReady,
    AuthenticatedReceiptPrefix {
        final_count: u8,
        has_next_incoming: bool,
    },
    AuthenticatedTerminal,
    UnknownOrInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub struct StartupEvidence {
    pub current_profile: AuthenticatedSignal,
    pub pending_current_restore: AuthenticatedSignal,
    pub explicit_recovery: AuthenticatedSignal,
    pub v031_upgrade: V031UpgradeSignal,
    pub unknown_marker_or_sibling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum V031UpgradeEntry {
    StartExactSource,
    ResumeAuthenticated {
        next_ordinal: u8,
        resume_incoming: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub enum StartupDisposition {
    ContinueCurrent,
    ApplyPendingCurrentRestore,
    ResumeOrStartV031Upgrade(V031UpgradeEntry),
    ExplicitRecoveryPending,
}

/// Pure startup arbitration.  It performs no I/O and cannot initialize a
/// manager, migrate a schema, create a credential, or open the UI.
#[cfg(test)]
pub fn arbitrate_startup(
    evidence: StartupEvidence,
) -> Result<StartupDisposition, R2InfrastructureError> {
    if evidence.unknown_marker_or_sibling
        || matches!(
            evidence.pending_current_restore,
            AuthenticatedSignal::UnknownOrInvalid
        )
        || matches!(
            evidence.explicit_recovery,
            AuthenticatedSignal::UnknownOrInvalid
        )
        || matches!(evidence.v031_upgrade, V031UpgradeSignal::UnknownOrInvalid)
    {
        return Err(R2InfrastructureError::StartupEvidenceUnauthenticated);
    }

    let pending_restore = matches!(
        evidence.pending_current_restore,
        AuthenticatedSignal::Authenticated
    );
    let explicit_recovery = matches!(
        evidence.explicit_recovery,
        AuthenticatedSignal::Authenticated
    );
    let upgrade_flow = !matches!(evidence.v031_upgrade, V031UpgradeSignal::Absent);
    let selected_flows =
        usize::from(pending_restore) + usize::from(explicit_recovery) + usize::from(upgrade_flow);
    if selected_flows > 1 {
        return Err(R2InfrastructureError::StartupEvidenceMixed);
    }

    if explicit_recovery {
        return Ok(StartupDisposition::ExplicitRecoveryPending);
    }
    if pending_restore {
        return Ok(StartupDisposition::ApplyPendingCurrentRestore);
    }
    match evidence.v031_upgrade {
        V031UpgradeSignal::ExactSourceReady => {
            if matches!(evidence.current_profile, AuthenticatedSignal::Authenticated) {
                return Err(R2InfrastructureError::StartupEvidenceMixed);
            }
            return Ok(StartupDisposition::ResumeOrStartV031Upgrade(
                V031UpgradeEntry::StartExactSource,
            ));
        }
        V031UpgradeSignal::AuthenticatedReceiptPrefix {
            final_count,
            has_next_incoming,
        } => {
            if final_count >= V031_RECEIPTS.len() as u8 {
                return Err(R2InfrastructureError::StartupEvidenceUnauthenticated);
            }
            return Ok(StartupDisposition::ResumeOrStartV031Upgrade(
                V031UpgradeEntry::ResumeAuthenticated {
                    next_ordinal: final_count,
                    resume_incoming: has_next_incoming,
                },
            ));
        }
        V031UpgradeSignal::AuthenticatedTerminal => {
            return if matches!(evidence.current_profile, AuthenticatedSignal::Authenticated) {
                Ok(StartupDisposition::ContinueCurrent)
            } else {
                Err(R2InfrastructureError::StartupEvidenceMissing)
            };
        }
        V031UpgradeSignal::Absent => {}
        V031UpgradeSignal::UnknownOrInvalid => unreachable!("rejected above"),
    }

    match evidence.current_profile {
        AuthenticatedSignal::Authenticated => Ok(StartupDisposition::ContinueCurrent),
        AuthenticatedSignal::UnknownOrInvalid => {
            Err(R2InfrastructureError::StartupEvidenceUnauthenticated)
        }
        AuthenticatedSignal::Absent => Err(R2InfrastructureError::StartupEvidenceMissing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock follows Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "lawyer-assistance-v031-r2-{}-{timestamp}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory creates");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Default)]
    struct RecordingCredentialProbe {
        queries: RefCell<Vec<CredentialAbsenceQuery>>,
        present: Option<ApprovedMcpCredentialRole>,
        fail: Option<ApprovedMcpCredentialRole>,
    }

    impl CredentialPresenceProbe for RecordingCredentialProbe {
        type Error = ();

        fn credential_exists_read_only(
            &self,
            query: CredentialAbsenceQuery,
        ) -> Result<bool, Self::Error> {
            self.queries.borrow_mut().push(query);
            if self.fail == Some(query.role) {
                return Err(());
            }
            Ok(self.present == Some(query.role))
        }
    }

    fn setup_source_roots(root: &Path) {
        fs::create_dir(root.join("privacy")).expect("privacy parent creates");
        File::create(root.join("user.sqlite")).expect("user source fixture creates");
        File::create(root.join("privacy/privacy-workflow.sqlite"))
            .expect("Privacy source fixture creates");
    }

    fn lineage_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn setup_lineage(root: &Path, lineage: &str) -> PathBuf {
        let path = root.join(MIGRATION_BACKUPS_DIRECTORY).join(lineage);
        fs::create_dir_all(&path).expect("lineage directory creates");
        path
    }

    fn setup_mock_terminal_lineage(root: &Path, lineage: &str) -> PathBuf {
        let path = setup_lineage(root, lineage);
        fs::write(path.join(V2_IDENTITY_FINAL), b"protected-identity")
            .expect("terminal identity creates");
        fs::write(path.join(V2_BUNDLE_FINAL), b"encrypted-bundle")
            .expect("terminal bundle creates");
        for kind in V031CheckpointKind::ALL {
            setup_mock_checkpoint_pair(&path, kind);
        }
        for descriptor in V031_RECEIPTS {
            fs::write(
                path.join(descriptor.final_basename),
                format!("receipt-{}", descriptor.ordinal),
            )
            .expect("terminal receipt creates");
        }
        fs::write(
            path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL),
            b"protected-step8-predecessor",
        )
        .expect("terminal Step8 predecessor evidence creates");
        fs::write(
            path.join(UPGRADE_COMPLETE_EVIDENCE_FINAL),
            b"protected-upgrade-complete-evidence",
        )
        .expect("terminal upgrade-complete evidence creates");
        path
    }

    fn setup_mock_checkpoint_pair(path: &Path, kind: V031CheckpointKind) {
        fs::write(
            path.join(kind.identity_final_basename()),
            format!("{}-protected-identity", kind.label()),
        )
        .expect("checkpoint identity creates");
        fs::write(
            path.join(kind.bundle_final_basename()),
            format!("{}-encrypted-bundle", kind.label()),
        )
        .expect("checkpoint bundle creates");
    }

    fn assert_receipt_files_absent(path: &Path, ordinal: u8) {
        let descriptor = V031_RECEIPTS[usize::from(ordinal)];
        assert!(!path
            .join(format!("{}.incoming", descriptor.final_basename))
            .exists());
        assert!(!path.join(descriptor.final_basename).exists());
    }

    #[derive(Default)]
    struct MockReceiptBridge {
        reject: Cell<bool>,
        corrupt_ordinal: Cell<bool>,
        expectations: RefCell<Vec<(u8, bool, Option<String>)>>,
        created_at_overrides: RefCell<BTreeMap<(u8, bool), i64>>,
    }

    impl ReceiptAuthenticationBridge for MockReceiptBridge {
        type Error = ();

        fn authenticate_protected_receipt(
            &self,
            _protected_file_bytes: &[u8],
            expectation: ReceiptExpectation<'_>,
        ) -> Result<AuthenticatedReceiptMetadata, Self::Error> {
            self.expectations.borrow_mut().push((
                expectation.descriptor.ordinal,
                expectation.incoming,
                expectation.previous_receipt_sha256.map(str::to_owned),
            ));
            if self.reject.get() {
                return Err(());
            }
            Ok(AuthenticatedReceiptMetadata {
                schema_version: V031_RECEIPT_SCHEMA.to_owned(),
                migration_id: V031_MIGRATION_ID.to_owned(),
                lineage_id: expectation.lineage_id.to_owned(),
                envelope_binding_id: format!("ws_{}", "a".repeat(32)),
                ordinal: expectation
                    .descriptor
                    .ordinal
                    .saturating_add(u8::from(self.corrupt_ordinal.get())),
                stage: expectation.descriptor.stage.to_owned(),
                previous_receipt_sha256: expectation.previous_receipt_sha256.map(str::to_owned),
                source_profile_proof_sha256: "b".repeat(64),
                evidence_schema_version: "source-preflight-v1".to_owned(),
                evidence_sha256: "b".repeat(64),
                counts: BTreeMap::from([("items".to_owned(), 1)]),
                created_at_unix: self
                    .created_at_overrides
                    .borrow()
                    .get(&(expectation.descriptor.ordinal, expectation.incoming))
                    .copied()
                    .unwrap_or(1_784_475_689),
                result_code: "ok".to_owned(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingDirectorySync {
        calls: Cell<usize>,
        fail: Cell<bool>,
    }

    impl DirectorySync for RecordingDirectorySync {
        type Error = ();

        fn sync_directory(&self, _directory: &Path) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if self.fail.get() {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_barrier_pins_plain_parent_and_preserves_write_through_final() {
        use std::os::windows::fs::symlink_dir;

        let fixture = TestDirectory::new();
        let parent = fixture.path().join("plain-parent");
        fs::create_dir(&parent).expect("plain parent creates");
        let pinned = PinnedPlainDirectory::open(&parent).expect("plain parent pins");
        assert!(fs::rename(&parent, fixture.path().join("swapped-parent")).is_err());
        pinned
            .verify_path_binding()
            .expect("failed swap preserves pinned parent identity");
        drop(pinned);
        assert!(parent.is_dir());
        PlatformDirectorySync
            .sync_directory(&parent)
            .expect("plain exact parent is accepted");

        let file = fixture.path().join("not-a-directory");
        fs::write(&file, b"file").expect("file negative fixture creates");
        assert!(PlatformDirectorySync.sync_directory(&file).is_err());
        assert!(PlatformDirectorySync
            .sync_directory(&fixture.path().join("missing-parent"))
            .is_err());

        let link_target = fixture.path().join("link-target");
        let link = fixture.path().join("directory-link");
        fs::create_dir(&link_target).expect("link target creates");
        match symlink_dir(&link_target, &link) {
            Ok(()) => assert!(PlatformDirectorySync.sync_directory(&link).is_err()),
            Err(error) if error.raw_os_error() == Some(1314) => {
                // Creating a symlink requires Developer Mode or SeCreateSymbolicLinkPrivilege.
                // Standard Windows compatibility junctions provide a no-privilege reparse
                // fixture when that capability is deliberately unavailable to the test user.
                let junction = [
                    Path::new(r"C:\Documents and Settings"),
                    Path::new(r"C:\Users\All Users"),
                ]
                .into_iter()
                .find(|candidate| {
                    fs::symlink_metadata(candidate)
                        .map(|metadata| metadata_is_reparse_point(&metadata))
                        .unwrap_or(false)
                })
                .expect("Windows reparse-directory fixture exists");
                assert!(PlatformDirectorySync.sync_directory(junction).is_err());
            }
            Err(error) => panic!("directory symlink fixture failed unexpectedly: {error}"),
        }

        let incoming = parent.join("receipt.incoming");
        let final_path = parent.join("receipt.final");
        let final_bytes = b"write-through-final";
        let mut incoming_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incoming)
            .expect("incoming creates");
        incoming_file
            .write_all(final_bytes)
            .expect("incoming writes");
        incoming_file.flush().expect("incoming flushes");
        incoming_file.sync_all().expect("incoming syncs");
        drop(incoming_file);
        rename_new_no_replace_write_through(&incoming, &final_path)
            .expect("write-through rename succeeds");
        PlatformDirectorySync
            .sync_directory(&parent)
            .expect("exact final parent is accepted");
        assert_eq!(
            fs::read(&final_path).expect("final reads after barrier"),
            final_bytes
        );
    }

    #[test]
    fn no_replace_primitive_preserves_an_existing_destination() {
        let directory = TestDirectory::new();
        let destination = directory.path().join("receipt.dpapi");
        let incoming = directory.path().join("receipt.dpapi.incoming");
        fs::write(&destination, b"first").expect("existing receipt creates");
        fs::write(&incoming, b"second").expect("incoming receipt creates");

        rename_new_no_replace_write_through(&incoming, &destination)
            .expect_err("an append-only destination cannot be replaced");

        assert_eq!(fs::read(&destination).unwrap(), b"first");
        assert_eq!(fs::read(&incoming).unwrap(), b"second");
    }

    #[test]
    fn no_replace_primitive_requires_sibling_paths() {
        let first = TestDirectory::new();
        let second = TestDirectory::new();
        assert!(matches!(
            rename_new_no_replace_write_through(
                &first.path().join("receipt.dpapi.incoming"),
                &second.path().join("receipt.dpapi"),
            ),
            Err(R2InfrastructureError::AtomicInstallRequiresSiblings)
        ));
    }

    #[test]
    fn frozen_target_absence_is_read_only_and_queries_exact_credentials() {
        let directory = TestDirectory::new();
        setup_source_roots(directory.path());
        let before = fs::read_dir(directory.path())
            .expect("root enumerates")
            .count();
        let probe = RecordingCredentialProbe::default();

        let proof = verify_exact_target_absence(directory.path(), &probe)
            .expect("exact target-only state is absent");
        assert_eq!(proof.credential_roles_checked, 4);
        assert_eq!(proof.fixed_paths_checked, 20);
        assert_eq!(proof.sibling_directories_scanned, 2);
        assert_eq!(probe.queries.borrow().len(), 4);
        for (query, role) in probe
            .queries
            .borrow()
            .iter()
            .zip(ApprovedMcpCredentialRole::ALL)
        {
            assert_eq!(query.role, role);
            assert_eq!(query.target, role.target());
            assert_eq!(query.account, "user-boundary-v1");
        }
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("root re-enumerates")
                .count(),
            before,
            "absence proof must not create a target or evidence directory"
        );
    }

    #[test]
    fn target_absence_rejects_credentials_paths_and_unknown_near_markers() {
        let credential_directory = TestDirectory::new();
        setup_source_roots(credential_directory.path());
        let credential_probe = RecordingCredentialProbe {
            present: Some(ApprovedMcpCredentialRole::McpAccessTicket),
            ..Default::default()
        };
        assert!(matches!(
            verify_exact_target_absence(credential_directory.path(), &credential_probe),
            Err(R2InfrastructureError::CredentialPresent(
                ApprovedMcpCredentialRole::McpAccessTicket
            ))
        ));

        let path_directory = TestDirectory::new();
        setup_source_roots(path_directory.path());
        fs::create_dir(path_directory.path().join("case-vault-v2"))
            .expect("negative target path creates");
        assert!(matches!(
            verify_exact_target_absence(
                path_directory.path(),
                &RecordingCredentialProbe::default()
            ),
            Err(R2InfrastructureError::TargetPathPresent(
                TargetAbsencePath::VaultRoot
            ))
        ));

        let marker_directory = TestDirectory::new();
        setup_source_roots(marker_directory.path());
        File::create(marker_directory.path().join("user.sqlite.restore-surprise"))
            .expect("unknown marker creates");
        assert!(matches!(
            verify_exact_target_absence(
                marker_directory.path(),
                &RecordingCredentialProbe::default()
            ),
            Err(R2InfrastructureError::UnknownNearMarker(
                NearMarkerScope::AppRoot
            ))
        ));

        let case_directory = TestDirectory::new();
        setup_source_roots(case_directory.path());
        File::create(case_directory.path().join("CASE-VAULT-V2.staging"))
            .expect("case-variant near marker creates");
        assert!(matches!(
            verify_exact_target_absence(
                case_directory.path(),
                &RecordingCredentialProbe::default()
            ),
            Err(R2InfrastructureError::UnknownNearMarker(
                NearMarkerScope::AppRoot
            ))
        ));
    }

    #[test]
    fn target_absence_requires_complete_migration_root_authentication() {
        let directory = TestDirectory::new();
        setup_source_roots(directory.path());
        let lineage = lineage_id(0x12);
        let lineage_directory = setup_lineage(directory.path(), &lineage);
        fs::write(
            lineage_directory.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .expect("receipt zero creates");

        assert!(matches!(
            verify_exact_target_absence(directory.path(), &RecordingCredentialProbe::default()),
            Err(R2InfrastructureError::MigrationBackupsAuthenticationRequired)
        ));
        let authenticated =
            authenticate_migration_backups(directory.path(), |_| MockReceiptBridge::default())
                .expect("complete migration namespace authenticates");
        let proof = verify_exact_target_absence_with_authenticated_migration_backups(
            directory.path(),
            &RecordingCredentialProbe::default(),
            &authenticated,
        )
        .expect("authenticated audit evidence is excluded from target-only state");
        assert_eq!(proof.credential_roles_checked(), 4);
        assert_eq!(proof.fixed_paths_checked(), 20);
        assert_eq!(proof.sibling_directories_scanned(), 2);

        setup_lineage(directory.path(), &lineage_id(0x13));
        assert!(matches!(
            verify_exact_target_absence_with_authenticated_migration_backups(
                directory.path(),
                &RecordingCredentialProbe::default(),
                &authenticated,
            ),
            Err(R2InfrastructureError::MigrationBackupsAuthenticationRequired)
        ));
    }

    #[test]
    fn receipt_zero_bootstrap_recovers_empty_root_and_empty_lineage_only() {
        for residue in ["absent-root", "empty-root", "empty-lineage"] {
            let directory = TestDirectory::new();
            setup_source_roots(directory.path());
            let backups_root = directory.path().join(MIGRATION_BACKUPS_DIRECTORY);
            let abandoned_lineage = lineage_id(0x31);
            if residue != "absent-root" {
                fs::create_dir(&backups_root).expect("empty migration root creates");
            }
            if residue == "empty-lineage" {
                fs::create_dir(backups_root.join(&abandoned_lineage))
                    .expect("empty abandoned lineage creates");
            }

            let namespace =
                inspect_receipt_zero_namespace(directory.path(), |_| MockReceiptBridge::default())
                    .expect("pre-receipt crash residue classifies");
            assert_eq!(
                namespace.empty_lineage_id(),
                (residue == "empty-lineage").then_some(abandoned_lineage.as_str())
            );
            let absence = verify_exact_target_absence_with_receipt_zero_namespace(
                directory.path(),
                &RecordingCredentialProbe::default(),
                &namespace,
            )
            .expect("recognized crash residue remains target-absent");
            let new_lineage = lineage_id(0x41);
            let sync = RecordingDirectorySync::default();
            let bootstrap = prepare_receipt_zero_bootstrap(
                directory.path(),
                &new_lineage,
                &namespace,
                &absence,
                &[],
                &sync,
            )
            .expect("receipt-zero lineage prepares");
            assert_eq!(bootstrap.lineage_id(), new_lineage);
            assert!(backups_root.join(&new_lineage).is_dir());
            assert!(!backups_root.join(&abandoned_lineage).exists());
            verify_exact_target_absence_with_receipt_zero_bootstrap(
                directory.path(),
                &RecordingCredentialProbe::default(),
                &bootstrap,
            )
            .expect("the exact new empty lineage is the sole bootstrap exception");
        }
    }

    #[test]
    fn receipt_zero_bootstrap_switches_to_authenticated_resume_after_incoming() {
        let directory = TestDirectory::new();
        setup_source_roots(directory.path());
        let namespace =
            inspect_receipt_zero_namespace(directory.path(), |_| MockReceiptBridge::default())
                .expect("absent namespace classifies");
        let absence = verify_exact_target_absence_with_receipt_zero_namespace(
            directory.path(),
            &RecordingCredentialProbe::default(),
            &namespace,
        )
        .expect("target absence proves");
        let lineage = lineage_id(0x51);
        let bootstrap = prepare_receipt_zero_bootstrap(
            directory.path(),
            &lineage,
            &namespace,
            &absence,
            &[],
            &RecordingDirectorySync::default(),
        )
        .expect("bootstrap prepares");
        let receipt_zero_incoming = canonical_lineage_directory(directory.path(), &lineage)
            .expect("lineage path builds")
            .join(format!("{}.incoming", V031_RECEIPTS[0].final_basename));
        fs::write(receipt_zero_incoming, b"receipt-zero")
            .expect("receipt-zero incoming crash state creates");

        assert!(matches!(
            verify_exact_target_absence_with_receipt_zero_bootstrap(
                directory.path(),
                &RecordingCredentialProbe::default(),
                &bootstrap,
            ),
            Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch)
        ));
        let authenticated =
            authenticate_migration_backups(directory.path(), |_| MockReceiptBridge::default())
                .expect("incoming receipt zero authenticates as the resumable namespace");
        verify_exact_target_absence_with_authenticated_migration_backups(
            directory.path(),
            &RecordingCredentialProbe::default(),
            &authenticated,
        )
        .expect("authenticated incoming replaces the empty-lineage exception");
    }

    #[test]
    fn receipt_zero_bootstrap_requires_crypto_verified_history_and_rejects_ambiguous_residue() {
        let directory = TestDirectory::new();
        setup_source_roots(directory.path());
        let historical_lineage = lineage_id(0x61);
        let historical_directory =
            setup_mock_terminal_lineage(directory.path(), &historical_lineage);
        let abandoned_lineage = lineage_id(0x62);
        setup_lineage(directory.path(), &abandoned_lineage);

        let namespace =
            inspect_receipt_zero_namespace(directory.path(), |_| MockReceiptBridge::default())
                .expect("terminal history and one empty residue classify");
        assert_eq!(namespace.authenticated_lineages().len(), 1);
        let absence = verify_exact_target_absence_with_receipt_zero_namespace(
            directory.path(),
            &RecordingCredentialProbe::default(),
            &namespace,
        )
        .expect("terminal audit history is allowed");
        let new_lineage = lineage_id(0x63);
        assert!(matches!(
            prepare_receipt_zero_bootstrap(
                directory.path(),
                &new_lineage,
                &namespace,
                &absence,
                &[],
                &RecordingDirectorySync::default(),
            ),
            Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch)
        ));
        assert!(historical_directory.is_dir());
        assert!(historical_directory
            .join(V031_RECEIPTS[9].final_basename)
            .is_file());
        assert!(directory
            .path()
            .join(MIGRATION_BACKUPS_DIRECTORY)
            .join(abandoned_lineage)
            .exists());

        let ambiguous = TestDirectory::new();
        setup_source_roots(ambiguous.path());
        setup_lineage(ambiguous.path(), &lineage_id(0x71));
        setup_lineage(ambiguous.path(), &lineage_id(0x72));
        assert!(matches!(
            inspect_receipt_zero_namespace(ambiguous.path(), |_| { MockReceiptBridge::default() }),
            Err(R2InfrastructureError::ReceiptZeroBootstrapMismatch)
        ));
    }

    #[test]
    fn lineage_paths_and_root_enumeration_are_exact_allowlists() {
        let directory = TestDirectory::new();
        let first = lineage_id(0x11);
        let second = lineage_id(0x22);
        setup_lineage(directory.path(), &second);
        setup_lineage(directory.path(), &first);
        assert_eq!(
            enumerate_lineage_ids(directory.path()).expect("lineages enumerate"),
            vec![first.clone(), second]
        );
        assert_eq!(
            canonical_lineage_directory(directory.path(), &first)
                .expect("canonical lineage path builds"),
            directory
                .path()
                .join(MIGRATION_BACKUPS_DIRECTORY)
                .join(&first)
        );
        assert!(validate_lineage_id("../not-a-lineage").is_err());

        fs::create_dir(
            directory
                .path()
                .join(MIGRATION_BACKUPS_DIRECTORY)
                .join("unknown"),
        )
        .expect("unknown lineage entry creates");
        assert!(matches!(
            enumerate_lineage_ids(directory.path()),
            Err(R2InfrastructureError::UnknownLineageDirectoryEntry)
        ));
    }

    #[test]
    fn receipt_enumeration_authenticates_only_a_final_prefix_and_one_next_incoming() {
        let directory = TestDirectory::new();
        let lineage = lineage_id(0x33);
        let lineage_directory = setup_lineage(directory.path(), &lineage);
        File::create(lineage_directory.join(V2_IDENTITY_FINAL)).expect("identity creates");
        File::create(lineage_directory.join(V2_BUNDLE_FINAL)).expect("bundle creates");
        fs::write(
            lineage_directory.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .expect("receipt zero creates");
        fs::write(
            lineage_directory.join(V031_RECEIPTS[1].final_basename),
            b"receipt-one",
        )
        .expect("receipt one creates");
        fs::write(
            lineage_directory.join(format!("{}.incoming", V031_RECEIPTS[2].final_basename)),
            b"receipt-two-incoming",
        )
        .expect("receipt incoming creates");
        let bridge = MockReceiptBridge::default();

        let inventory = enumerate_and_authenticate_lineage(directory.path(), &lineage, &bridge)
            .expect("receipt prefix authenticates");
        assert_eq!(inventory.final_receipts.len(), 2);
        assert_eq!(
            inventory
                .next_incoming_receipt
                .as_ref()
                .map(|receipt| receipt.ordinal),
            Some(2)
        );
        assert!(inventory.v2.identity_final && inventory.v2.bundle_final);
        let expectations = bridge.expectations.borrow();
        assert_eq!(expectations.len(), 3);
        assert_eq!(expectations[0], (0, false, None));
        assert_eq!(expectations[1].0, 1);
        assert_eq!(expectations[1].2, Some(sha256_hex(b"receipt-zero")));
        assert_eq!(expectations[2].0, 2);
        assert!(expectations[2].1);
        assert_eq!(expectations[2].2, Some(sha256_hex(b"receipt-one")));
    }

    #[test]
    fn receipt_enumeration_rejects_gaps_multiple_incoming_unknown_and_bad_metadata() {
        let gap_directory = TestDirectory::new();
        let gap_lineage = lineage_id(0x44);
        let gap = setup_lineage(gap_directory.path(), &gap_lineage);
        fs::write(gap.join(V031_RECEIPTS[1].final_basename), b"gap")
            .expect("gapped receipt creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                gap_directory.path(),
                &gap_lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::ReceiptPrefixIsNotContiguous)
        ));

        let incoming_directory = TestDirectory::new();
        let incoming_lineage = lineage_id(0x55);
        let incoming = setup_lineage(incoming_directory.path(), &incoming_lineage);
        for descriptor in [&V031_RECEIPTS[0], &V031_RECEIPTS[1]] {
            fs::write(
                incoming.join(format!("{}.incoming", descriptor.final_basename)),
                descriptor.stage.as_bytes(),
            )
            .expect("incoming receipt creates");
        }
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                incoming_directory.path(),
                &incoming_lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::MultipleOrOutOfOrderIncomingReceipts)
        ));

        let unknown_directory = TestDirectory::new();
        let unknown_lineage = lineage_id(0x66);
        let unknown = setup_lineage(unknown_directory.path(), &unknown_lineage);
        fs::write(
            unknown.join("00-source_preflight_verified.receipt.dpapi.bak"),
            b"x",
        )
        .expect("unknown evidence creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                unknown_directory.path(),
                &unknown_lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::UnexpectedLineageEvidence)
        ));

        let metadata_directory = TestDirectory::new();
        let metadata_lineage = lineage_id(0x77);
        let metadata = setup_lineage(metadata_directory.path(), &metadata_lineage);
        fs::write(metadata.join(V031_RECEIPTS[0].final_basename), b"receipt")
            .expect("receipt creates");
        let bridge = MockReceiptBridge::default();
        bridge.corrupt_ordinal.set(true);
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                metadata_directory.path(),
                &metadata_lineage,
                &bridge
            ),
            Err(R2InfrastructureError::ReceiptMetadataMismatch {
                ordinal: 0,
                incoming: false
            })
        ));
    }

    #[test]
    fn receipt_enumeration_rejects_timestamp_regression_and_allows_equality() {
        let final_directory = TestDirectory::new();
        let final_lineage = lineage_id(0x5a);
        let final_path = setup_lineage(final_directory.path(), &final_lineage);
        fs::write(final_path.join(V2_IDENTITY_FINAL), b"identity").unwrap();
        fs::write(final_path.join(V2_BUNDLE_FINAL), b"bundle").unwrap();
        for descriptor in &V031_RECEIPTS[..3] {
            fs::write(
                final_path.join(descriptor.final_basename),
                format!("receipt-{}", descriptor.ordinal),
            )
            .unwrap();
        }
        let regressed = MockReceiptBridge::default();
        regressed
            .created_at_overrides
            .borrow_mut()
            .insert((0, false), 20);
        regressed
            .created_at_overrides
            .borrow_mut()
            .insert((1, false), 19);
        assert!(matches!(
            enumerate_and_authenticate_lineage(final_directory.path(), &final_lineage, &regressed,),
            Err(R2InfrastructureError::ReceiptTimestampRegression {
                ordinal: 1,
                incoming: false,
            })
        ));
        enumerate_and_authenticate_lineage(
            final_directory.path(),
            &final_lineage,
            &MockReceiptBridge::default(),
        )
        .expect("equal adjacent final timestamps are allowed");

        let incoming_directory = TestDirectory::new();
        let incoming_lineage = lineage_id(0x5b);
        let incoming_path = setup_lineage(incoming_directory.path(), &incoming_lineage);
        fs::write(incoming_path.join(V2_IDENTITY_FINAL), b"identity").unwrap();
        fs::write(incoming_path.join(V2_BUNDLE_FINAL), b"bundle").unwrap();
        fs::write(
            incoming_path.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .unwrap();
        fs::write(
            incoming_path.join(format!("{}.incoming", V031_RECEIPTS[1].final_basename)),
            b"receipt-one-incoming",
        )
        .unwrap();
        let incoming_regressed = MockReceiptBridge::default();
        incoming_regressed
            .created_at_overrides
            .borrow_mut()
            .insert((0, false), 20);
        incoming_regressed
            .created_at_overrides
            .borrow_mut()
            .insert((1, true), 19);
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                incoming_directory.path(),
                &incoming_lineage,
                &incoming_regressed,
            ),
            Err(R2InfrastructureError::ReceiptTimestampRegression {
                ordinal: 1,
                incoming: true,
            })
        ));
    }

    #[test]
    fn v2_bundle_without_final_identity_and_hardlinks_fail_closed() {
        let order_directory = TestDirectory::new();
        let order_lineage = lineage_id(0x88);
        let order = setup_lineage(order_directory.path(), &order_lineage);
        File::create(order.join(V2_BUNDLE_FINAL)).expect("orphan bundle creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                order_directory.path(),
                &order_lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::V2EvidenceOrderInvalid)
        ));

        let hardlink_directory = TestDirectory::new();
        let hardlink_lineage = lineage_id(0x99);
        let hardlink = setup_lineage(hardlink_directory.path(), &hardlink_lineage);
        let identity = hardlink.join(V2_IDENTITY_FINAL);
        File::create(&identity).expect("identity creates");
        fs::hard_link(&identity, hardlink_directory.path().join("identity-alias"))
            .expect("hardlink creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                hardlink_directory.path(),
                &hardlink_lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::UnsafeLineageEntry)
        ));
    }

    fn v2_evidence_from_masks(core: u8, snapshots: u8) -> V2EvidenceInventory {
        V2EvidenceInventory {
            identity_final: core & 0b0001 != 0,
            identity_incoming: core & 0b0010 != 0,
            bundle_final: core & 0b0100 != 0,
            bundle_incoming: core & 0b1000 != 0,
            user_snapshot_incoming: snapshots & 0b01 != 0,
            privacy_snapshot_incoming: snapshots & 0b10 != 0,
        }
    }

    #[test]
    fn v2_evidence_order_accepts_only_the_frozen_recoverable_crash_states() {
        // Core bits are identity.final, identity.incoming, bundle.final,
        // bundle.incoming. Snapshot files are orthogonal build-window
        // evidence and may be absent, singular, or both present.
        let allowed_core_states = [0b0000, 0b1000, 0b1010, 0b1001, 0b0101];
        for core in allowed_core_states {
            for snapshots in 0..=0b11 {
                validate_v2_evidence_order(v2_evidence_from_masks(core, snapshots))
                    .unwrap_or_else(|error| {
                        panic!(
                            "recoverable V2 state core={core:04b} snapshots={snapshots:02b} was rejected: {error}"
                        )
                    });
            }
        }
    }

    #[test]
    fn v2_evidence_order_rejects_every_other_identity_bundle_combination() {
        let allowed_core_states = [0b0000, 0b1000, 0b1010, 0b1001, 0b0101];
        for core in 0..=0b1111 {
            if allowed_core_states.contains(&core) {
                continue;
            }
            for snapshots in 0..=0b11 {
                assert!(
                    matches!(
                        validate_v2_evidence_order(v2_evidence_from_masks(core, snapshots)),
                        Err(R2InfrastructureError::V2EvidenceOrderInvalid)
                    ),
                    "invalid V2 state core={core:04b} snapshots={snapshots:02b} was accepted"
                );
            }
        }
    }

    fn setup_checkpoint_receipt_prefix(root: &Path, lineage: &str, final_count: usize) -> PathBuf {
        let path = setup_lineage(root, lineage);
        if final_count >= 2 {
            fs::write(path.join(V2_IDENTITY_FINAL), b"identity").expect("V2 identity creates");
            fs::write(path.join(V2_BUNDLE_FINAL), b"bundle").expect("V2 bundle creates");
        }
        for descriptor in V031_RECEIPTS.iter().take(final_count) {
            fs::write(
                path.join(descriptor.final_basename),
                format!("receipt-{}", descriptor.ordinal),
            )
            .expect("receipt prefix creates");
        }
        path
    }

    #[test]
    fn checkpoint_inventory_accepts_zero_one_and_two_ordered_step4_checkpoints() {
        for (index, checkpoint_count) in [0_usize, 1, 2].into_iter().enumerate() {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xa0 + index as u8);
            let path = setup_checkpoint_receipt_prefix(directory.path(), &lineage, 3);
            if checkpoint_count >= 1 {
                setup_mock_checkpoint_pair(&path, V031CheckpointKind::Binding);
            }
            if checkpoint_count >= 2 {
                setup_mock_checkpoint_pair(&path, V031CheckpointKind::Materials);
            }
            let inventory = enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            )
            .expect("ordered Step-4 checkpoint prefix authenticates");
            assert_eq!(
                inventory.checkpoints.binding.is_exact_final(),
                checkpoint_count >= 1
            );
            assert_eq!(
                inventory.checkpoints.materials.is_exact_final(),
                checkpoint_count >= 2
            );
        }

        let orphan = TestDirectory::new();
        let lineage = lineage_id(0xaf);
        let path = setup_checkpoint_receipt_prefix(orphan.path(), &lineage, 3);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Materials);
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                orphan.path(),
                &lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));
    }

    #[test]
    fn checkpoint_inventory_accepts_only_bundle_first_identity_first_crash_states() {
        let allowed = [
            (false, false, false, false),
            (false, false, false, true),
            (false, true, false, true),
            (true, false, false, true),
            (true, false, true, false),
        ];
        for (index, state) in allowed.into_iter().enumerate() {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xb0 + index as u8);
            let path = setup_checkpoint_receipt_prefix(directory.path(), &lineage, 3);
            let kind = V031CheckpointKind::Binding;
            for (present, basename) in [
                (state.0, kind.identity_final_basename().to_owned()),
                (state.1, kind.identity_incoming_basename()),
                (state.2, kind.bundle_final_basename().to_owned()),
                (state.3, kind.bundle_incoming_basename()),
            ] {
                if present {
                    fs::write(path.join(basename), b"checkpoint").expect("crash evidence creates");
                }
            }
            enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            )
            .expect("frozen checkpoint crash state authenticates");
        }

        for (index, state) in [(false, true, false, false), (false, false, true, false)]
            .into_iter()
            .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xc0 + index as u8);
            let path = setup_checkpoint_receipt_prefix(directory.path(), &lineage, 3);
            let kind = V031CheckpointKind::Binding;
            if state.1 {
                fs::write(path.join(kind.identity_incoming_basename()), b"identity")
                    .expect("orphan incoming identity creates");
            }
            if state.2 {
                fs::write(path.join(kind.bundle_final_basename()), b"bundle")
                    .expect("orphan final bundle creates");
            }
            assert!(matches!(
                enumerate_and_authenticate_lineage(
                    directory.path(),
                    &lineage,
                    &MockReceiptBridge::default()
                ),
                Err(R2InfrastructureError::LineageStateMismatch)
            ));
        }
    }

    #[test]
    fn checkpoint_receipt_prefix_projection_and_filesystem_guards_fail_closed() {
        let missing = TestDirectory::new();
        let lineage = lineage_id(0xd0);
        let path = setup_checkpoint_receipt_prefix(missing.path(), &lineage, 4);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Binding);
        assert!(enumerate_and_authenticate_lineage(
            missing.path(),
            &lineage,
            &MockReceiptBridge::default()
        )
        .is_err());

        let projection = TestDirectory::new();
        let lineage = lineage_id(0xd1);
        let path = setup_checkpoint_receipt_prefix(projection.path(), &lineage, 6);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Binding);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Materials);
        enumerate_and_authenticate_lineage(
            projection.path(),
            &lineage,
            &MockReceiptBridge::default(),
        )
        .expect("receipt-5 prefix permits projection build window");
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Projection);
        enumerate_and_authenticate_lineage(
            projection.path(),
            &lineage,
            &MockReceiptBridge::default(),
        )
        .expect("final projection permits receipt 6");

        let hardlink = TestDirectory::new();
        let lineage = lineage_id(0xd2);
        let path = setup_checkpoint_receipt_prefix(hardlink.path(), &lineage, 3);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Binding);
        fs::hard_link(
            path.join(V031_BINDING_CHECKPOINT_IDENTITY_FINAL),
            hardlink.path().join("checkpoint-hardlink-alias"),
        )
        .expect("checkpoint hardlink creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                hardlink.path(),
                &lineage,
                &MockReceiptBridge::default()
            ),
            Err(R2InfrastructureError::UnsafeLineageEntry)
        ));

        #[cfg(windows)]
        {
            let reparse = TestDirectory::new();
            let lineage = lineage_id(0xd3);
            let path = setup_checkpoint_receipt_prefix(reparse.path(), &lineage, 3);
            let target = reparse.path().join("reparse-target");
            fs::write(&target, b"target").expect("reparse target creates");
            if std::os::windows::fs::symlink_file(
                &target,
                path.join(V031_BINDING_CHECKPOINT_BUNDLE_FINAL),
            )
            .is_ok()
            {
                assert!(matches!(
                    enumerate_and_authenticate_lineage(
                        reparse.path(),
                        &lineage,
                        &MockReceiptBridge::default()
                    ),
                    Err(R2InfrastructureError::UnsafeLineageEntry)
                ));
            }
        }
    }

    fn setup_step8_receipt_prefix(root: &Path, lineage: &str, final_count: usize) -> PathBuf {
        let path = setup_checkpoint_receipt_prefix(root, lineage, final_count);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Binding);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Materials);
        setup_mock_checkpoint_pair(&path, V031CheckpointKind::Projection);
        path
    }

    #[test]
    fn step8_predecessor_sidecar_cross_state_matrix_is_exact() {
        let before = TestDirectory::new();
        let before_lineage = lineage_id(0xe1);
        let before_path = setup_step8_receipt_prefix(before.path(), &before_lineage, 8);
        fs::write(
            before_path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL),
            b"sidecar",
        )
        .unwrap();
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                before.path(),
                &before_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        for (index, basename) in [
            None,
            Some(STEP8_PREDECESSOR_EVIDENCE_INCOMING),
            Some(STEP8_PREDECESSOR_EVIDENCE_FINAL),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xe2 + index as u8);
            let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
            if let Some(basename) = basename {
                fs::write(path.join(basename), b"sidecar").unwrap();
            }
            enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            )
            .expect("receipt-8 prefix accepts absent, incoming, or exact-final sidecar");
        }

        let both = TestDirectory::new();
        let both_lineage = lineage_id(0xe5);
        let both_path = setup_step8_receipt_prefix(both.path(), &both_lineage, 9);
        fs::write(
            both_path.join(STEP8_PREDECESSOR_EVIDENCE_INCOMING),
            b"incoming",
        )
        .unwrap();
        fs::write(both_path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL), b"final").unwrap();
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                both.path(),
                &both_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        for (index, sidecar) in [
            None,
            Some(STEP8_PREDECESSOR_EVIDENCE_INCOMING),
            Some(STEP8_PREDECESSOR_EVIDENCE_FINAL),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xe6 + index as u8);
            let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
            fs::write(
                path.join(format!("{}.incoming", V031_RECEIPTS[9].final_basename)),
                b"receipt-nine-incoming",
            )
            .unwrap();
            fs::write(
                path.join(UPGRADE_COMPLETE_EVIDENCE_FINAL),
                b"upgrade-complete-evidence",
            )
            .unwrap();
            if let Some(sidecar) = sidecar {
                fs::write(path.join(sidecar), b"sidecar").unwrap();
            }
            let result = enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            );
            assert_eq!(
                result.is_ok(),
                sidecar == Some(STEP8_PREDECESSOR_EVIDENCE_FINAL)
            );
        }
    }

    #[test]
    fn step8_predecessor_namespace_rejects_the_unfrozen_legacy_basename_read_only() {
        const LEGACY_BASENAME: &str = "08-user_v11_verified.predecessor-evidence.dpapi";

        assert_eq!(
            STEP8_PREDECESSOR_EVIDENCE_FINAL,
            "08-step8-predecessor.evidence.dpapi"
        );
        assert_eq!(
            STEP8_PREDECESSOR_EVIDENCE_INCOMING,
            "08-step8-predecessor.evidence.dpapi.incoming"
        );
        assert_ne!(LEGACY_BASENAME, STEP8_PREDECESSOR_EVIDENCE_FINAL);

        let directory = TestDirectory::new();
        let lineage = lineage_id(0xef);
        let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
        fs::write(path.join(LEGACY_BASENAME), b"legacy-sidecar")
            .expect("legacy predecessor basename creates");
        let snapshot = |directory: &Path| {
            fs::read_dir(directory)
                .expect("lineage directory enumerates")
                .map(|entry| {
                    let entry = entry.expect("lineage entry enumerates");
                    let basename = entry.file_name().to_string_lossy().into_owned();
                    let bytes = fs::read(entry.path()).expect("plain lineage fixture file reads");
                    (basename, bytes)
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = snapshot(&path);

        assert!(matches!(
            enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::UnexpectedLineageEvidence)
        ));
        assert_eq!(
            snapshot(&path),
            before,
            "legacy namespace rejection must not rewrite any lineage file"
        );
    }

    #[test]
    fn upgrade_complete_evidence_sidecar_cross_state_matrix_is_exact() {
        let before = TestDirectory::new();
        let before_lineage = lineage_id(0xd1);
        let before_path = setup_step8_receipt_prefix(before.path(), &before_lineage, 8);
        fs::write(
            before_path.join(UPGRADE_COMPLETE_EVIDENCE_FINAL),
            b"sidecar",
        )
        .unwrap();
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                before.path(),
                &before_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        for (index, basename) in [
            None,
            Some(UPGRADE_COMPLETE_EVIDENCE_INCOMING),
            Some(UPGRADE_COMPLETE_EVIDENCE_FINAL),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xd2 + index as u8);
            let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
            fs::write(path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL), b"predecessor").unwrap();
            if let Some(basename) = basename {
                fs::write(path.join(basename), b"sidecar").unwrap();
            }
            enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            )
            .expect("receipt-8 prefix accepts absent, incoming, or exact-final terminal evidence");
        }

        let both = TestDirectory::new();
        let both_lineage = lineage_id(0xd5);
        let both_path = setup_step8_receipt_prefix(both.path(), &both_lineage, 9);
        fs::write(
            both_path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL),
            b"predecessor",
        )
        .unwrap();
        fs::write(
            both_path.join(UPGRADE_COMPLETE_EVIDENCE_INCOMING),
            b"incoming",
        )
        .unwrap();
        fs::write(both_path.join(UPGRADE_COMPLETE_EVIDENCE_FINAL), b"final").unwrap();
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                both.path(),
                &both_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        for (index, terminal_evidence) in [
            None,
            Some(UPGRADE_COMPLETE_EVIDENCE_INCOMING),
            Some(UPGRADE_COMPLETE_EVIDENCE_FINAL),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xd6 + index as u8);
            let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
            fs::write(path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL), b"predecessor").unwrap();
            fs::write(
                path.join(format!("{}.incoming", V031_RECEIPTS[9].final_basename)),
                b"receipt-nine-incoming",
            )
            .unwrap();
            if let Some(basename) = terminal_evidence {
                fs::write(path.join(basename), b"terminal evidence").unwrap();
            }
            let result = enumerate_and_authenticate_lineage(
                directory.path(),
                &lineage,
                &MockReceiptBridge::default(),
            );
            assert_eq!(
                result.is_ok(),
                terminal_evidence == Some(UPGRADE_COMPLETE_EVIDENCE_FINAL)
            );
        }
    }

    #[test]
    fn receipt_boundary_prerequisites_fail_before_any_write() {
        let missing_v2 = TestDirectory::new();
        let missing_v2_lineage = lineage_id(0xc5);
        let missing_v2_path =
            setup_checkpoint_receipt_prefix(missing_v2.path(), &missing_v2_lineage, 1);
        assert!(matches!(
            install_next_receipt(
                missing_v2.path(),
                &missing_v2_lineage,
                1,
                b"protected-receipt-one",
                &MockReceiptBridge::default(),
                &RecordingDirectorySync::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));
        assert_receipt_files_absent(&missing_v2_path, 1);

        let missing_step4_checkpoints = TestDirectory::new();
        let missing_step4_lineage = lineage_id(0xc6);
        let missing_step4_path = setup_checkpoint_receipt_prefix(
            missing_step4_checkpoints.path(),
            &missing_step4_lineage,
            3,
        );
        assert!(matches!(
            install_next_receipt(
                missing_step4_checkpoints.path(),
                &missing_step4_lineage,
                3,
                b"protected-receipt-three",
                &MockReceiptBridge::default(),
                &RecordingDirectorySync::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));
        assert_receipt_files_absent(&missing_step4_path, 3);

        let missing_projection = TestDirectory::new();
        let missing_projection_lineage = lineage_id(0xc7);
        let missing_projection_path = setup_checkpoint_receipt_prefix(
            missing_projection.path(),
            &missing_projection_lineage,
            6,
        );
        setup_mock_checkpoint_pair(&missing_projection_path, V031CheckpointKind::Binding);
        setup_mock_checkpoint_pair(&missing_projection_path, V031CheckpointKind::Materials);
        assert!(matches!(
            install_next_receipt(
                missing_projection.path(),
                &missing_projection_lineage,
                6,
                b"protected-receipt-six",
                &MockReceiptBridge::default(),
                &RecordingDirectorySync::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));
        assert_receipt_files_absent(&missing_projection_path, 6);
    }

    #[test]
    fn receipt_nine_requires_both_exact_final_sidecars_before_any_write() {
        for (index, (predecessor_present, completion_present)) in
            [(false, false), (true, false), (false, true)]
                .into_iter()
                .enumerate()
        {
            let directory = TestDirectory::new();
            let lineage = lineage_id(0xc8 + index as u8);
            let path = setup_step8_receipt_prefix(directory.path(), &lineage, 9);
            if predecessor_present {
                fs::write(
                    path.join(STEP8_PREDECESSOR_EVIDENCE_FINAL),
                    b"protected-step8-predecessor",
                )
                .expect("Step8 predecessor fixture creates");
            }
            if completion_present {
                fs::write(
                    path.join(UPGRADE_COMPLETE_EVIDENCE_FINAL),
                    b"protected-upgrade-complete-evidence",
                )
                .expect("upgrade-complete fixture creates");
            }

            assert!(matches!(
                install_next_receipt(
                    directory.path(),
                    &lineage,
                    9,
                    b"protected-receipt-nine",
                    &MockReceiptBridge::default(),
                    &RecordingDirectorySync::default(),
                ),
                Err(R2InfrastructureError::LineageStateMismatch)
            ));
            assert_receipt_files_absent(&path, 9);
        }
    }

    #[test]
    fn receipt_prefix_and_v2_evidence_must_describe_the_same_transition() {
        let missing_zero_directory = TestDirectory::new();
        let missing_zero_lineage = lineage_id(0x9a);
        let missing_zero = setup_lineage(missing_zero_directory.path(), &missing_zero_lineage);
        fs::write(missing_zero.join(V2_BUNDLE_INCOMING), b"bundle").expect("staged bundle creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                missing_zero_directory.path(),
                &missing_zero_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        let missing_v2_directory = TestDirectory::new();
        let missing_v2_lineage = lineage_id(0x9b);
        let missing_v2 = setup_lineage(missing_v2_directory.path(), &missing_v2_lineage);
        fs::write(
            missing_v2.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .expect("receipt zero creates");
        fs::write(
            missing_v2.join(V031_RECEIPTS[1].final_basename),
            b"receipt-one",
        )
        .expect("receipt one creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                missing_v2_directory.path(),
                &missing_v2_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));

        let plaintext_residue_directory = TestDirectory::new();
        let plaintext_residue_lineage = lineage_id(0x9c);
        let plaintext_residue = setup_lineage(
            plaintext_residue_directory.path(),
            &plaintext_residue_lineage,
        );
        fs::write(
            plaintext_residue.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .expect("receipt zero creates");
        fs::write(plaintext_residue.join(V2_IDENTITY_FINAL), b"identity")
            .expect("identity creates");
        fs::write(plaintext_residue.join(V2_BUNDLE_FINAL), b"bundle").expect("bundle creates");
        fs::write(
            plaintext_residue.join(USER_SNAPSHOT_INCOMING),
            b"plaintext sqlite image",
        )
        .expect("plaintext snapshot residue creates");
        fs::write(
            plaintext_residue.join(V031_RECEIPTS[1].final_basename),
            b"receipt-one",
        )
        .expect("receipt one creates");
        assert!(matches!(
            enumerate_and_authenticate_lineage(
                plaintext_residue_directory.path(),
                &plaintext_residue_lineage,
                &MockReceiptBridge::default(),
            ),
            Err(R2InfrastructureError::LineageStateMismatch)
        ));
    }

    #[test]
    fn bounded_read_and_atomic_receipt_install_are_append_only() {
        let directory = TestDirectory::new();
        let lineage = lineage_id(0xaa);
        let lineage_directory = setup_lineage(directory.path(), &lineage);
        let bridge = MockReceiptBridge::default();
        let sync = RecordingDirectorySync::default();
        let protected = b"protected-receipt-zero";

        let installed =
            install_next_receipt(directory.path(), &lineage, 0, protected, &bridge, &sync)
                .expect("next receipt installs");
        assert_eq!(installed.receipt.ordinal, 0);
        assert!(!installed.resumed_existing_incoming);
        assert_eq!(sync.calls.get(), 1);
        assert_eq!(
            fs::read(lineage_directory.join(V031_RECEIPTS[0].final_basename))
                .expect("final receipt reads"),
            protected
        );
        assert!(!lineage_directory
            .join(format!("{}.incoming", V031_RECEIPTS[0].final_basename))
            .exists());

        let error = install_next_receipt(
            directory.path(),
            &lineage,
            0,
            b"replacement",
            &bridge,
            &sync,
        )
        .expect_err("existing final cannot be replaced");
        assert!(matches!(
            error,
            R2InfrastructureError::ExistingFinalRequiresStateVerification
        ));
        assert_eq!(
            fs::read(lineage_directory.join(V031_RECEIPTS[0].final_basename))
                .expect("original final remains"),
            protected
        );

        let oversized = lineage_directory.join(USER_SNAPSHOT_INCOMING);
        fs::write(&oversized, vec![0u8; 17]).expect("bounded fixture creates");
        assert!(matches!(
            read_bounded_file(&oversized, 16),
            Err(R2InfrastructureError::ReceiptTooLarge)
        ));
    }

    #[test]
    fn matching_authenticated_incoming_resumes_but_different_bytes_are_preserved() {
        let resume_directory = TestDirectory::new();
        let resume_lineage = lineage_id(0xbb);
        let resume = setup_lineage(resume_directory.path(), &resume_lineage);
        let incoming_path = resume.join(format!("{}.incoming", V031_RECEIPTS[0].final_basename));
        fs::write(&incoming_path, b"matching-incoming").expect("incoming creates");
        let sync = RecordingDirectorySync::default();
        let installed = install_next_receipt(
            resume_directory.path(),
            &resume_lineage,
            0,
            b"matching-incoming",
            &MockReceiptBridge::default(),
            &sync,
        )
        .expect("matching incoming resumes");
        assert!(installed.resumed_existing_incoming);

        let mismatch_directory = TestDirectory::new();
        let mismatch_lineage = lineage_id(0xcc);
        let mismatch = setup_lineage(mismatch_directory.path(), &mismatch_lineage);
        let mismatch_path = mismatch.join(format!("{}.incoming", V031_RECEIPTS[0].final_basename));
        fs::write(&mismatch_path, b"first").expect("mismatched incoming creates");
        assert!(matches!(
            install_next_receipt(
                mismatch_directory.path(),
                &mismatch_lineage,
                0,
                b"second",
                &MockReceiptBridge::default(),
                &RecordingDirectorySync::default(),
            ),
            Err(R2InfrastructureError::ExistingIncomingDiffers)
        ));
        assert_eq!(fs::read(mismatch_path).expect("incoming remains"), b"first");
    }

    #[test]
    fn v2_evidence_staging_survives_each_identity_before_bundle_install_boundary() {
        let directory = TestDirectory::new();
        let lineage = lineage_id(0xdd);
        let lineage_directory = setup_lineage(directory.path(), &lineage);
        let bundle_incoming = lineage_directory.join(V2_BUNDLE_INCOMING);
        let bundle_final = lineage_directory.join(V2_BUNDLE_FINAL);
        let identity_incoming = lineage_directory.join(V2_IDENTITY_INCOMING);
        let identity_final = lineage_directory.join(V2_IDENTITY_FINAL);
        let bundle = vec![0x5a; MAX_PROTECTED_RECEIPT_BYTES + 1];
        let identity = b"dpapi-protected-identity";
        let sync = RecordingDirectorySync::default();

        assert!(
            stage_new_evidence_file(&bundle_incoming, &bundle, bundle.len())
                .expect("bundle stages")
        );
        validate_v2_evidence_order(V2EvidenceInventory {
            bundle_incoming: true,
            ..Default::default()
        })
        .expect("bundle-only staging state is recoverable");

        assert!(
            stage_new_evidence_file(&identity_incoming, identity, MAX_PROTECTED_RECEIPT_BYTES)
                .expect("identity stages")
        );
        validate_v2_evidence_order(V2EvidenceInventory {
            identity_incoming: true,
            bundle_incoming: true,
            ..Default::default()
        })
        .expect("both incoming files are recoverable");

        assert!(install_staged_evidence_file_no_replace(
            &identity_incoming,
            &identity_final,
            identity,
            MAX_PROTECTED_RECEIPT_BYTES,
            &sync,
        )
        .expect("identity installs first"));
        validate_v2_evidence_order(V2EvidenceInventory {
            identity_final: true,
            bundle_incoming: true,
            ..Default::default()
        })
        .expect("installed identity plus staged bundle is recoverable");

        assert!(install_staged_evidence_file_no_replace(
            &bundle_incoming,
            &bundle_final,
            &bundle,
            bundle.len(),
            &sync,
        )
        .expect("bundle installs second"));
        validate_v2_evidence_order(V2EvidenceInventory {
            identity_final: true,
            bundle_final: true,
            ..Default::default()
        })
        .expect("final V2 pair is valid");
        assert_eq!(sync.calls.get(), 2);
        assert_eq!(fs::read(bundle_final).expect("bundle reads"), bundle);

        assert!(!install_staged_evidence_file_no_replace(
            &identity_incoming,
            &identity_final,
            identity,
            MAX_PROTECTED_RECEIPT_BYTES,
            &sync,
        )
        .expect("exact final is idempotent"));
        assert_eq!(sync.calls.get(), 2);
    }

    #[cfg(windows)]
    struct TypedOriginalV2CrashFixture {
        directory: TestDirectory,
        lineage: String,
        source_profile_proof_sha256: String,
        source_user_physical_file_set_sha256: String,
        source_privacy_physical_file_set_sha256: String,
        source_user_logical_manifest_sha256: String,
        source_user_business_manifest_sha256: String,
        source_privacy_logical_manifest_sha256: String,
        source_privacy_business_manifest_sha256: String,
        envelope_binding_id: String,
        user_snapshot_path: PathBuf,
        privacy_snapshot_path: PathBuf,
        user_snapshot: Vec<u8>,
        privacy_snapshot: Vec<u8>,
    }

    #[cfg(windows)]
    impl TypedOriginalV2CrashFixture {
        fn new(lineage_byte: u8) -> Self {
            let directory = TestDirectory::new();
            let lineage = lineage_id(lineage_byte);
            let lineage_directory = setup_lineage(directory.path(), &lineage);
            fs::write(
                lineage_directory.join(V031_RECEIPTS[0].final_basename),
                b"receipt-zero",
            )
            .expect("receipt zero creates");

            let user_snapshot_path = directory.path().join("typed-user-source.sqlite");
            let privacy_snapshot_path = directory.path().join("typed-privacy-source.sqlite");
            for path in [&user_snapshot_path, &privacy_snapshot_path] {
                let connection =
                    rusqlite::Connection::open(path).expect("typed crash source SQLite creates");
                connection
                    .execute_batch("CREATE TABLE fixture(id INTEGER PRIMARY KEY, value TEXT);")
                    .expect("typed crash source schema creates");
            }
            let user_snapshot =
                fs::read(&user_snapshot_path).expect("typed user source snapshot reads");
            let privacy_snapshot =
                fs::read(&privacy_snapshot_path).expect("typed Privacy source snapshot reads");
            Self {
                directory,
                lineage,
                source_profile_proof_sha256: "b".repeat(64),
                source_user_physical_file_set_sha256: "1".repeat(64),
                source_privacy_physical_file_set_sha256: "2".repeat(64),
                source_user_logical_manifest_sha256: "c".repeat(64),
                source_user_business_manifest_sha256: "d".repeat(64),
                source_privacy_logical_manifest_sha256: "e".repeat(64),
                source_privacy_business_manifest_sha256: "f".repeat(64),
                envelope_binding_id: format!("ws_{}", "a".repeat(32)),
                user_snapshot_path,
                privacy_snapshot_path,
                user_snapshot,
                privacy_snapshot,
            }
        }

        fn root(&self) -> &Path {
            self.directory.path()
        }

        fn lineage_directory(&self) -> PathBuf {
            canonical_lineage_directory(self.root(), &self.lineage)
                .expect("typed crash lineage resolves")
        }

        fn request(&self) -> OriginalRollbackV2InstallRequest<'_> {
            OriginalRollbackV2InstallRequest {
                source_profile_proof_sha256: &self.source_profile_proof_sha256,
                source_user_physical_file_set_sha256: &self.source_user_physical_file_set_sha256,
                source_privacy_physical_file_set_sha256: &self
                    .source_privacy_physical_file_set_sha256,
                source_user_logical_manifest_sha256: &self.source_user_logical_manifest_sha256,
                source_user_business_manifest_sha256: &self.source_user_business_manifest_sha256,
                source_privacy_logical_manifest_sha256: &self
                    .source_privacy_logical_manifest_sha256,
                source_privacy_business_manifest_sha256: &self
                    .source_privacy_business_manifest_sha256,
                envelope_binding_id: &self.envelope_binding_id,
                lineage_id: &self.lineage,
                user_database_snapshot: &self.user_snapshot,
                privacy_store_snapshot: &self.privacy_snapshot,
            }
        }

        fn verification_request(&self) -> OriginalRollbackV2VerificationRequest<'_> {
            OriginalRollbackV2VerificationRequest {
                source_profile_proof_sha256: &self.source_profile_proof_sha256,
                source_user_physical_file_set_sha256: &self.source_user_physical_file_set_sha256,
                source_privacy_physical_file_set_sha256: &self
                    .source_privacy_physical_file_set_sha256,
                source_user_logical_manifest_sha256: &self.source_user_logical_manifest_sha256,
                source_user_business_manifest_sha256: &self.source_user_business_manifest_sha256,
                source_privacy_logical_manifest_sha256: &self
                    .source_privacy_logical_manifest_sha256,
                source_privacy_business_manifest_sha256: &self
                    .source_privacy_business_manifest_sha256,
                envelope_binding_id: &self.envelope_binding_id,
                lineage_id: &self.lineage,
            }
        }

        fn seal_typed_pair(&self) -> (Vec<u8>, Vec<u8>) {
            let request = self.request();
            let (bundle, metadata) =
                seal_v031_original_rollback_v2(&V031OriginalRollbackCreateRequest {
                    source_profile_proof_sha256: request.source_profile_proof_sha256,
                    source_user_physical_file_set_sha256: request
                        .source_user_physical_file_set_sha256,
                    source_privacy_physical_file_set_sha256: request
                        .source_privacy_physical_file_set_sha256,
                    source_user_logical_manifest_sha256: request
                        .source_user_logical_manifest_sha256,
                    source_user_business_manifest_sha256: request
                        .source_user_business_manifest_sha256,
                    source_privacy_logical_manifest_sha256: request
                        .source_privacy_logical_manifest_sha256,
                    source_privacy_business_manifest_sha256: request
                        .source_privacy_business_manifest_sha256,
                    envelope_binding_id: request.envelope_binding_id,
                    lineage_id: request.lineage_id,
                    created_at_unix: 1_784_475_689,
                    user_database: request.user_database_snapshot,
                    privacy_store: request.privacy_store_snapshot,
                })
                .expect("typed V2 crash bundle seals");
            let identity = create_v031_original_rollback_identity_v2(&metadata)
                .expect("typed V2 crash identity builds");
            let protected = protect_v031_original_rollback_identity_v2(&identity)
                .expect("typed V2 crash identity protects with DPAPI");
            (bundle, protected)
        }

        fn source_observation(&self) -> [(Vec<u8>, SystemTime); 2] {
            [
                (
                    fs::read(&self.user_snapshot_path).expect("user source reads"),
                    fs::metadata(&self.user_snapshot_path)
                        .and_then(|metadata| metadata.modified())
                        .expect("user source modified time reads"),
                ),
                (
                    fs::read(&self.privacy_snapshot_path).expect("Privacy source reads"),
                    fs::metadata(&self.privacy_snapshot_path)
                        .and_then(|metadata| metadata.modified())
                        .expect("Privacy source modified time reads"),
                ),
            ]
        }

        fn inventory(&self, bridge: &MockReceiptBridge) -> AuthenticatedLineageInventory {
            enumerate_and_authenticate_lineage(self.root(), &self.lineage, bridge)
                .expect("typed V2 crash lineage authenticates")
        }
    }

    #[cfg(windows)]
    #[derive(Clone, Copy, Debug)]
    #[allow(clippy::enum_variant_names)]
    enum TypedOriginalV2CrashState {
        BundleIncoming,
        IdentityAndBundleIncoming,
        IdentityFinalAndBundleIncoming,
    }

    #[cfg(windows)]
    #[test]
    fn typed_original_v2_resumes_all_legal_incoming_states_with_exact_readback_and_no_source_writes(
    ) {
        for (index, state) in [
            TypedOriginalV2CrashState::BundleIncoming,
            TypedOriginalV2CrashState::IdentityAndBundleIncoming,
            TypedOriginalV2CrashState::IdentityFinalAndBundleIncoming,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = TypedOriginalV2CrashFixture::new(0xe0 + index as u8);
            let (bundle, protected_identity) = fixture.seal_typed_pair();
            let lineage = fixture.lineage_directory();
            fs::write(lineage.join(V2_BUNDLE_INCOMING), &bundle)
                .expect("typed bundle incoming stages");
            match state {
                TypedOriginalV2CrashState::BundleIncoming => {}
                TypedOriginalV2CrashState::IdentityAndBundleIncoming => {
                    fs::write(lineage.join(V2_IDENTITY_INCOMING), &protected_identity)
                        .expect("typed identity incoming stages");
                }
                TypedOriginalV2CrashState::IdentityFinalAndBundleIncoming => {
                    fs::write(lineage.join(V2_IDENTITY_FINAL), &protected_identity)
                        .expect("typed identity final stages before bundle final");
                }
            }
            assert!(
                !lineage.join(V2_BUNDLE_FINAL).exists(),
                "a bundle may be staged first but may never be final before identity: {state:?}"
            );

            let source_before = fixture.source_observation();
            let bridge = MockReceiptBridge::default();
            let inventory = fixture.inventory(&bridge);
            let sync = RecordingDirectorySync::default();
            let verified = install_or_resume_original_rollback_v2(
                fixture.root(),
                &inventory,
                &fixture.request(),
                &bridge,
                &sync,
            )
            .expect("typed V2 legal crash state resumes");
            assert_eq!(fixture.source_observation(), source_before);
            assert_eq!(
                fs::read(lineage.join(V2_BUNDLE_FINAL)).expect("final typed bundle reads"),
                bundle
            );
            let final_identity =
                fs::read(lineage.join(V2_IDENTITY_FINAL)).expect("final typed identity reads");
            if !matches!(state, TypedOriginalV2CrashState::BundleIncoming) {
                assert_eq!(
                    final_identity, protected_identity,
                    "an already staged protected identity is installed byte-for-byte"
                );
            }
            assert!(!lineage.join(V2_BUNDLE_INCOMING).exists());
            assert!(!lineage.join(V2_IDENTITY_INCOMING).exists());
            assert_eq!(verified.bundle_sha256(), sha256_hex(&bundle));
            assert_eq!(
                verified.identity_protected_sha256(),
                sha256_hex(&final_identity)
            );

            let final_inventory = fixture.inventory(&bridge);
            let readback = verify_installed_original_rollback_v2(
                fixture.root(),
                &final_inventory,
                &fixture.verification_request(),
                &bridge,
            )
            .expect("typed V2 final files decrypt and verify from disk");
            assert_eq!(readback, verified);
            assert_eq!(fixture.source_observation(), source_before);
            assert_eq!(
                sync.calls.get(),
                match state {
                    TypedOriginalV2CrashState::IdentityFinalAndBundleIncoming => 1,
                    _ => 2,
                }
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn typed_original_v2_rejects_unknown_or_mismatched_staged_payload_without_cleanup() {
        let unknown = TypedOriginalV2CrashFixture::new(0xe8);
        let (mut unknown_bundle, _) = unknown.seal_typed_pair();
        let last = unknown_bundle.len() - 1;
        unknown_bundle[last] ^= 0x01;
        let unknown_lineage = unknown.lineage_directory();
        fs::write(unknown_lineage.join(V2_BUNDLE_INCOMING), &unknown_bundle)
            .expect("unknown bundle incoming stages");
        let source_before = unknown.source_observation();
        let bridge = MockReceiptBridge::default();
        let inventory = unknown.inventory(&bridge);
        assert!(install_or_resume_original_rollback_v2(
            unknown.root(),
            &inventory,
            &unknown.request(),
            &bridge,
            &RecordingDirectorySync::default(),
        )
        .is_err());
        assert_eq!(unknown.source_observation(), source_before);
        assert_eq!(
            fs::read(unknown_lineage.join(V2_BUNDLE_INCOMING))
                .expect("unknown staged bundle is preserved"),
            unknown_bundle
        );
        assert!(!unknown_lineage.join(V2_IDENTITY_FINAL).exists());
        assert!(!unknown_lineage.join(V2_BUNDLE_FINAL).exists());

        let mismatch = TypedOriginalV2CrashFixture::new(0xe9);
        let (first_bundle, _) = mismatch.seal_typed_pair();
        let (_, second_identity) = mismatch.seal_typed_pair();
        let mismatch_lineage = mismatch.lineage_directory();
        fs::write(mismatch_lineage.join(V2_BUNDLE_INCOMING), &first_bundle)
            .expect("first typed bundle incoming stages");
        fs::write(mismatch_lineage.join(V2_IDENTITY_FINAL), &second_identity)
            .expect("different typed identity final stages");
        let source_before = mismatch.source_observation();
        let bridge = MockReceiptBridge::default();
        let inventory = mismatch.inventory(&bridge);
        assert!(install_or_resume_original_rollback_v2(
            mismatch.root(),
            &inventory,
            &mismatch.request(),
            &bridge,
            &RecordingDirectorySync::default(),
        )
        .is_err());
        assert_eq!(mismatch.source_observation(), source_before);
        assert_eq!(
            fs::read(mismatch_lineage.join(V2_BUNDLE_INCOMING))
                .expect("valid staged bundle is preserved after mismatch"),
            first_bundle
        );
        assert_eq!(
            fs::read(mismatch_lineage.join(V2_IDENTITY_FINAL))
                .expect("installed identity is preserved after mismatch"),
            second_identity
        );
        assert!(!mismatch_lineage.join(V2_BUNDLE_FINAL).exists());
    }

    #[test]
    fn typed_original_v2_installer_authenticates_receipt_identity_bundle_and_five_slots() {
        let directory = TestDirectory::new();
        let lineage = lineage_id(0xde);
        let lineage_directory = setup_lineage(directory.path(), &lineage);
        fs::write(
            lineage_directory.join(V031_RECEIPTS[0].final_basename),
            b"receipt-zero",
        )
        .expect("receipt zero creates");
        let bridge = MockReceiptBridge::default();
        let inventory = enumerate_and_authenticate_lineage(directory.path(), &lineage, &bridge)
            .expect("receipt-zero lineage authenticates");
        let user_snapshot_path = directory.path().join("typed-user-snapshot.sqlite");
        let privacy_snapshot_path = directory.path().join("typed-privacy-snapshot.sqlite");
        for path in [&user_snapshot_path, &privacy_snapshot_path] {
            let connection = rusqlite::Connection::open(path).expect("snapshot SQLite creates");
            connection
                .execute_batch("CREATE TABLE fixture(id INTEGER PRIMARY KEY, value TEXT);")
                .expect("snapshot schema creates");
        }
        let user_snapshot = fs::read(&user_snapshot_path).expect("user snapshot reads");
        let privacy_snapshot = fs::read(&privacy_snapshot_path).expect("Privacy snapshot reads");
        let request = OriginalRollbackV2InstallRequest {
            source_profile_proof_sha256: &"b".repeat(64),
            source_user_physical_file_set_sha256: &"1".repeat(64),
            source_privacy_physical_file_set_sha256: &"2".repeat(64),
            source_user_logical_manifest_sha256: &"c".repeat(64),
            source_user_business_manifest_sha256: &"d".repeat(64),
            source_privacy_logical_manifest_sha256: &"e".repeat(64),
            source_privacy_business_manifest_sha256: &"f".repeat(64),
            envelope_binding_id: &format!("ws_{}", "a".repeat(32)),
            lineage_id: &lineage,
            user_database_snapshot: &user_snapshot,
            privacy_store_snapshot: &privacy_snapshot,
        };
        let sync = RecordingDirectorySync::default();
        let verified = install_or_resume_original_rollback_v2(
            directory.path(),
            &inventory,
            &request,
            &bridge,
            &sync,
        )
        .expect("typed V2 install verifies all five slots");
        assert_eq!(verified.lineage_id(), lineage);
        assert_eq!(verified.identity_protected_sha256().len(), 64);
        assert_eq!(verified.bundle_sha256().len(), 64);
        assert!(verified.bundle_bytes() > 0);
        assert!(verified.encrypted_chunks() >= 5);
        assert_eq!(
            verified.user_database_snapshot_sha256(),
            sha256_hex(&user_snapshot)
        );
        assert_eq!(
            verified.privacy_store_snapshot_sha256(),
            sha256_hex(&privacy_snapshot)
        );
        assert_eq!(verified.slot_identity_sha256().len(), 64);
        assert!(lineage_directory.join(V2_IDENTITY_FINAL).is_file());
        assert!(lineage_directory.join(V2_BUNDLE_FINAL).is_file());
        assert!(!lineage_directory.join(V2_IDENTITY_INCOMING).exists());
        assert!(!lineage_directory.join(V2_BUNDLE_INCOMING).exists());
        assert_eq!(sync.calls.get(), 2);

        fs::write(
            lineage_directory.join(USER_SNAPSHOT_INCOMING),
            &user_snapshot,
        )
        .expect("user cleanup-crash snapshot creates");
        fs::write(
            lineage_directory.join(PRIVACY_SNAPSHOT_INCOMING),
            &privacy_snapshot,
        )
        .expect("Privacy cleanup-crash snapshot creates");
        let cleanup_inventory =
            enumerate_and_authenticate_lineage(directory.path(), &lineage, &bridge)
                .expect("cleanup crash inventory authenticates");
        let verification_request = OriginalRollbackV2VerificationRequest {
            source_profile_proof_sha256: request.source_profile_proof_sha256,
            source_user_physical_file_set_sha256: request.source_user_physical_file_set_sha256,
            source_privacy_physical_file_set_sha256: request
                .source_privacy_physical_file_set_sha256,
            source_user_logical_manifest_sha256: request.source_user_logical_manifest_sha256,
            source_user_business_manifest_sha256: request.source_user_business_manifest_sha256,
            source_privacy_logical_manifest_sha256: request.source_privacy_logical_manifest_sha256,
            source_privacy_business_manifest_sha256: request
                .source_privacy_business_manifest_sha256,
            envelope_binding_id: request.envelope_binding_id,
            lineage_id: request.lineage_id,
        };
        assert!(verify_installed_original_rollback_v2(
            directory.path(),
            &cleanup_inventory,
            &verification_request,
            &bridge,
        )
        .is_err());
        let cleanup_verified = verify_installed_original_rollback_v2_for_snapshot_cleanup(
            directory.path(),
            &cleanup_inventory,
            &verification_request,
            &bridge,
        )
        .expect("final V2 authenticates before exact snapshot cleanup");
        assert_eq!(cleanup_verified, verified);
        fs::remove_file(lineage_directory.join(USER_SNAPSHOT_INCOMING))
            .expect("user cleanup-crash snapshot removes");
        fs::remove_file(lineage_directory.join(PRIVACY_SNAPSHOT_INCOMING))
            .expect("Privacy cleanup-crash snapshot removes");

        let resumed_inventory =
            enumerate_and_authenticate_lineage(directory.path(), &lineage, &bridge)
                .expect("final V2 lineage reauthenticates");
        let read_only_verified = verify_installed_original_rollback_v2(
            directory.path(),
            &resumed_inventory,
            &verification_request,
            &bridge,
        )
        .expect("installed V2 authenticates without plaintext staging snapshots");
        assert_eq!(read_only_verified, verified);
        let resumed = install_or_resume_original_rollback_v2(
            directory.path(),
            &resumed_inventory,
            &request,
            &bridge,
            &sync,
        )
        .expect("exact final V2 is an authenticated no-op");
        assert_eq!(resumed, verified);
        assert_eq!(sync.calls.get(), 2);

        let receipt_zero_before = fs::read(lineage_directory.join(V031_RECEIPTS[0].final_basename))
            .expect("historical receipt zero reads");
        for ordinal in 1_u8..10 {
            if ordinal == 3 {
                setup_mock_checkpoint_pair(&lineage_directory, V031CheckpointKind::Binding);
                setup_mock_checkpoint_pair(&lineage_directory, V031CheckpointKind::Materials);
            }
            if ordinal == 6 {
                setup_mock_checkpoint_pair(&lineage_directory, V031CheckpointKind::Projection);
            }
            if ordinal == 9 {
                fs::write(
                    lineage_directory.join(STEP8_PREDECESSOR_EVIDENCE_FINAL),
                    b"protected-step8-predecessor",
                )
                .expect("terminal Step8 predecessor evidence creates");
                fs::write(
                    lineage_directory.join(UPGRADE_COMPLETE_EVIDENCE_FINAL),
                    b"protected-upgrade-complete-evidence",
                )
                .expect("terminal upgrade-complete evidence creates");
            }
            install_next_receipt(
                directory.path(),
                &lineage,
                ordinal,
                format!("protected-receipt-{ordinal}").as_bytes(),
                &bridge,
                &sync,
            )
            .expect("remaining terminal receipt installs");
        }
        let terminal_inventory =
            enumerate_and_authenticate_lineage(directory.path(), &lineage, &bridge)
                .expect("terminal lineage authenticates");
        let terminal_verified = verify_installed_original_rollback_v2(
            directory.path(),
            &terminal_inventory,
            &verification_request,
            &bridge,
        )
        .expect("terminal history V2 authenticates cryptographically");
        let terminal_evidence_sha256 = terminal_evidence_file_names()
            .into_iter()
            .map(|basename| {
                let bytes = fs::read(lineage_directory.join(&basename))
                    .expect("terminal evidence reads for authenticated fixture");
                (basename, sha256_hex(&bytes))
            })
            .collect::<BTreeMap<_, _>>();
        let terminal_verified = bind_authenticated_terminal_evidence_files(
            directory.path(),
            &terminal_inventory,
            terminal_verified,
            &terminal_evidence_sha256,
        )
        .expect("terminal checkpoint and sidecar bytes bind");
        let receipt_zero_namespace =
            inspect_receipt_zero_namespace(directory.path(), |_| MockReceiptBridge::default())
                .expect("terminal history namespace authenticates");
        let terminal_absence = verify_exact_target_absence_with_receipt_zero_namespace(
            directory.path(),
            &RecordingCredentialProbe::default(),
            &receipt_zero_namespace,
        )
        .expect("terminal history remains outside target-only state");
        let second_lineage = lineage_id(0xdf);
        for tampered_basename in [
            V031CheckpointKind::Binding.identity_final_basename(),
            STEP8_PREDECESSOR_EVIDENCE_FINAL,
            UPGRADE_COMPLETE_EVIDENCE_FINAL,
        ] {
            let tampered_path = lineage_directory.join(tampered_basename);
            let original = fs::read(&tampered_path).expect("frozen terminal evidence reads");
            let mut changed = original.clone();
            changed[0] ^= 0x01;
            fs::write(&tampered_path, &changed).expect("terminal evidence tamper writes");
            assert!(matches!(
                prepare_receipt_zero_bootstrap(
                    directory.path(),
                    &second_lineage,
                    &receipt_zero_namespace,
                    &terminal_absence,
                    std::slice::from_ref(&terminal_verified),
                    &sync,
                ),
                Err(R2InfrastructureError::BoundedReadChanged)
            ));
            assert!(
                !canonical_lineage_directory(directory.path(), &second_lineage)
                    .expect("second lineage path builds")
                    .exists()
            );
            fs::write(&tampered_path, original).expect("frozen terminal evidence restores");
        }
        prepare_receipt_zero_bootstrap(
            directory.path(),
            &second_lineage,
            &receipt_zero_namespace,
            &terminal_absence,
            &[terminal_verified],
            &sync,
        )
        .expect("crypto-verified terminal history permits a new re-upgrade lineage");
        assert!(
            canonical_lineage_directory(directory.path(), &second_lineage)
                .expect("second lineage path builds")
                .is_dir()
        );
        assert_eq!(
            fs::read(lineage_directory.join(V031_RECEIPTS[0].final_basename))
                .expect("historical receipt zero re-reads"),
            receipt_zero_before
        );
    }

    fn empty_startup_evidence() -> StartupEvidence {
        StartupEvidence {
            current_profile: AuthenticatedSignal::Absent,
            pending_current_restore: AuthenticatedSignal::Absent,
            explicit_recovery: AuthenticatedSignal::Absent,
            v031_upgrade: V031UpgradeSignal::Absent,
            unknown_marker_or_sibling: false,
        }
    }

    #[test]
    fn startup_arbitration_covers_all_frozen_dispositions() {
        let mut current = empty_startup_evidence();
        current.current_profile = AuthenticatedSignal::Authenticated;
        assert_eq!(
            arbitrate_startup(current).expect("current continues"),
            StartupDisposition::ContinueCurrent
        );

        let mut restore = current;
        restore.pending_current_restore = AuthenticatedSignal::Authenticated;
        assert_eq!(
            arbitrate_startup(restore).expect("pending restore applies first"),
            StartupDisposition::ApplyPendingCurrentRestore
        );
        restore.current_profile = AuthenticatedSignal::UnknownOrInvalid;
        assert_eq!(
            arbitrate_startup(restore).expect("authenticated restore precedes mixed active state"),
            StartupDisposition::ApplyPendingCurrentRestore
        );

        let mut explicit = current;
        explicit.explicit_recovery = AuthenticatedSignal::Authenticated;
        assert_eq!(
            arbitrate_startup(explicit).expect("explicit recovery arbitrates first"),
            StartupDisposition::ExplicitRecoveryPending
        );

        let mut start = empty_startup_evidence();
        start.v031_upgrade = V031UpgradeSignal::ExactSourceReady;
        assert_eq!(
            arbitrate_startup(start).expect("exact source starts"),
            StartupDisposition::ResumeOrStartV031Upgrade(V031UpgradeEntry::StartExactSource)
        );

        let mut resume = empty_startup_evidence();
        resume.v031_upgrade = V031UpgradeSignal::AuthenticatedReceiptPrefix {
            final_count: 4,
            has_next_incoming: true,
        };
        assert_eq!(
            arbitrate_startup(resume).expect("authenticated prefix resumes"),
            StartupDisposition::ResumeOrStartV031Upgrade(V031UpgradeEntry::ResumeAuthenticated {
                next_ordinal: 4,
                resume_incoming: true,
            })
        );
        resume.current_profile = AuthenticatedSignal::UnknownOrInvalid;
        assert_eq!(
            arbitrate_startup(resume)
                .expect("authenticated upgrade prefix precedes mixed active state"),
            StartupDisposition::ResumeOrStartV031Upgrade(V031UpgradeEntry::ResumeAuthenticated {
                next_ordinal: 4,
                resume_incoming: true,
            })
        );

        let mut terminal = current;
        terminal.v031_upgrade = V031UpgradeSignal::AuthenticatedTerminal;
        assert_eq!(
            arbitrate_startup(terminal).expect("authenticated terminal continues current startup"),
            StartupDisposition::ContinueCurrent
        );
    }

    #[test]
    fn startup_arbitration_rejects_unknown_missing_and_mixed_evidence() {
        let mut unknown = empty_startup_evidence();
        unknown.unknown_marker_or_sibling = true;
        assert!(matches!(
            arbitrate_startup(unknown),
            Err(R2InfrastructureError::StartupEvidenceUnauthenticated)
        ));

        let mut unauthenticated_upgrade = empty_startup_evidence();
        unauthenticated_upgrade.v031_upgrade = V031UpgradeSignal::UnknownOrInvalid;
        assert!(matches!(
            arbitrate_startup(unauthenticated_upgrade),
            Err(R2InfrastructureError::StartupEvidenceUnauthenticated)
        ));

        assert!(matches!(
            arbitrate_startup(empty_startup_evidence()),
            Err(R2InfrastructureError::StartupEvidenceMissing)
        ));

        let mut mixed = empty_startup_evidence();
        mixed.pending_current_restore = AuthenticatedSignal::Authenticated;
        mixed.explicit_recovery = AuthenticatedSignal::Authenticated;
        assert!(matches!(
            arbitrate_startup(mixed),
            Err(R2InfrastructureError::StartupEvidenceMixed)
        ));

        let mut current_and_old = empty_startup_evidence();
        current_and_old.current_profile = AuthenticatedSignal::Authenticated;
        current_and_old.v031_upgrade = V031UpgradeSignal::ExactSourceReady;
        assert!(matches!(
            arbitrate_startup(current_and_old),
            Err(R2InfrastructureError::StartupEvidenceMixed)
        ));
    }
}
