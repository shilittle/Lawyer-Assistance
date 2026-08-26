//! Path-free startup arbitration for the v0.3.1 -> v0.4.0 transition.
//!
//! Filesystem and DPAPI observers must finish before constructing this value.
//! The router itself is deliberately pure: it cannot create a Credential,
//! initialize a manager, install a receipt, run maintenance, or reveal a UI.

use crate::{
    approved_mcp::{
        observe_v031_approved_mcp_target_namespace_read_only, ApprovedMcpWorkspace,
        CurrentApprovedComponentsLifecycle, CurrentApprovedComponentsObservation,
        CurrentApprovedComponentsProof, V031ApprovedMcpCredentialProbe,
        V031ApprovedMcpTargetComponentsGate, V031ApprovedMcpTargetIncompleteGate,
        V031ApprovedMcpTargetNamespaceObservation,
    },
    commands::{
        application_backup::{
            observe_pending_application_restore_read_only, PendingApplicationRestoreGate,
            PendingApplicationRestoreObservation,
        },
        original_migration_backup::{
            establish_original_migration_backup, load_original_migration_backup_gate,
            verify_one_v031_terminal_history_lineage_read_only, OriginalRollbackVerifiedGate,
        },
        release::{
            observe_pending_database_restore_read_only, PendingDatabaseRestoreGate,
            PendingDatabaseRestoreObservation,
        },
        v031_checkpoint_receipts::{
            ensure_v031_case_migration_backups_verified_gate,
            ensure_v031_projection_backup_verified_gate,
            load_v031_case_migration_backups_verified_gate_read_only,
            load_v031_projection_backup_verified_gate_read_only,
            verify_v031_case_migration_backups_historical_profile_read_only,
        },
        v031_migration_checkpoint::load_v031_historical_target_components_from_checkpoint_read_only,
        v031_migration_recovery::{
            observe_v031_migration_recovery_read_only, V031MigrationRecoveryGate,
            V031MigrationRecoveryObservation,
        },
        v031_privacy_migration::{
            ensure_v031_binding_materials_verified, ensure_v031_privacy_v5_verified,
            ensure_v031_privacy_v6_verified, load_v031_binding_materials_verified_gate_read_only,
            load_v031_privacy_v5_verified_gate_read_only,
            load_v031_privacy_v6_verified_gate_read_only,
        },
        v031_target_components::{
            load_v031_target_components_prepared_gate_read_only, prepare_v031_target_components,
            V031TargetComponentsPreparedGate,
        },
        v031_upgrade_complete::{
            authenticate_v031_terminal_history_offline, ensure_v031_upgrade_complete,
            load_v031_upgrade_complete_gate_read_only,
            observe_v031_upgrade_at_process_start_read_only, V031ProcessStartUpgradeObservation,
            V031UpgradeCompleteGate,
        },
        v031_user_upgrade::ensure_v031_user_v11_verified,
    },
    privacy_workflow::{
        observe_current_privacy_profile_read_only, observe_current_vault_read_only,
        observe_pending_privacy_restore_read_only, observe_v031_vault_target_absent_read_only,
        observe_v031_vault_target_namespace_read_only, CurrentPrivacyProfileObservation,
        CurrentPrivacyProfileProof, CurrentVaultObservation, CurrentVaultProof,
        PendingPrivacyRestoreGate, PendingPrivacyRestoreObservation, PrivacyWorkflowManager,
        V031VaultTargetAbsentGate, V031VaultTargetComponentGate, V031VaultTargetIncompleteGate,
        V031VaultTargetNamespaceObservation,
    },
    v031_upgrade_receipts::{load_authenticated_v031_lineage, PrivacyReceiptAuthenticationBridge},
};
use std::{fmt, fs, path::Path, sync::Arc};

const RECEIPT_EIGHT_FINAL_COUNT: u8 =
    privacy::upgrade_receipt_v1::V031UpgradeReceiptStage::UpgradeComplete.ordinal();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatedPresence {
    Absent,
    Authenticated,
    UnknownOrInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurrentRestoreKind {
    FullApplication,
    LegacyUserDatabase,
    StandalonePrivacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestoreObservation {
    pub(crate) explicit_recovery: AuthenticatedPresence,
    pub(crate) full_application: AuthenticatedPresence,
    pub(crate) legacy_user_database: AuthenticatedPresence,
    pub(crate) standalone_privacy: AuthenticatedPresence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstalledProfile {
    /// All five active slots and every target/restore/receipt namespace are
    /// absent. This is stronger than merely observing a missing user DB.
    GenuineFresh,
    ExactV031Source,
    ExactCurrent,
    /// A DPAPI-authenticated recovery or the exact read-only candidate for the
    /// empty-v10/missing-Privacy development-era bootstrap.
    EmptyLegacyBootstrap,
    /// A nonterminal, receipt-bound schema combination. The next opaque gate
    /// must re-authenticate its exact live shape before any stage write.
    AuthenticatedUpgradeState,
    PartialOrUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentOptionalSlotShape {
    Absent,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentFiveSlotShape {
    user_exact_v11: bool,
    privacy_exact_v6: bool,
    approved_lifecycle: Option<CurrentApprovedComponentsLifecycle>,
    vault: CurrentOptionalSlotShape,
    approved_workspace_matches: bool,
    vault_workspace_matches: bool,
}

fn is_exact_current_five_slot_shape(shape: CurrentFiveSlotShape) -> bool {
    shape.user_exact_v11
        && shape.privacy_exact_v6
        && matches!(
            shape.approved_lifecycle,
            Some(
                CurrentApprovedComponentsLifecycle::IdentityOnly
                    | CurrentApprovedComponentsLifecycle::ApprovedOnly
                    | CurrentApprovedComponentsLifecycle::ApprovedAndWorkProducts
            )
        )
        && shape.approved_workspace_matches
        && match shape.vault {
            CurrentOptionalSlotShape::Absent => true,
            CurrentOptionalSlotShape::Exact => shape.vault_workspace_matches,
        }
}

/// Opaque, path-free proof for the finite set of legal current five-slot
/// lifecycles. The last three physical slots remain lazy, but absence is
/// accepted only through their dedicated authenticated observers.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExactCurrentProfileGate {
    user: database::UserMigrationSourceProof,
    privacy: CurrentPrivacyProfileProof,
    vault: Option<CurrentVaultProof>,
    approved: CurrentApprovedComponentsProof,
}

impl fmt::Debug for ExactCurrentProfileGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactCurrentProfileGate")
            .field("user", &self.user)
            .field("privacy", &self.privacy)
            .field("vault", &self.vault)
            .field("approved", &self.approved)
            .finish()
    }
}

impl ExactCurrentProfileGate {
    pub(crate) fn workspace_instance_id(&self) -> &privacy::vnext::WorkspaceInstanceId {
        self.privacy.workspace_instance_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Exact observations own their authenticated proof rather than a detachable
// heap handle, preserving capability equality across the startup recheck.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ExactCurrentProfileObservation {
    NotCurrent,
    Exact(ExactCurrentProfileGate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactCurrentProfileError {
    User,
    Privacy,
    Approved,
    Vault,
    WorkspaceMismatch,
}

impl fmt::Display for ExactCurrentProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::User => "the current user database profile is invalid",
            Self::Privacy => "the current Privacy profile is invalid",
            Self::Approved => "the current approved/work-product profile is invalid",
            Self::Vault => "the current Vault profile is invalid",
            Self::WorkspaceMismatch => "the current component workspace identities do not match",
        })
    }
}

impl std::error::Error for ExactCurrentProfileError {}

/// Path-free proof that all five active slots, all fixed target/restore/receipt
/// namespaces and all four target credentials were absent. The app root itself
/// may be absent on a first launch and is never created by this observer.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GenuineFreshProfileGate {
    app_root_was_absent: bool,
    filesystem_absence_checks: u64,
    credential_absence_checks: u64,
}

impl fmt::Debug for GenuineFreshProfileGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenuineFreshProfileGate")
            .field("app_root_was_absent", &self.app_root_was_absent)
            .field("filesystem_absence_checks", &self.filesystem_absence_checks)
            .field("credential_absence_checks", &self.credential_absence_checks)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GenuineFreshProfileObservation {
    NotFresh,
    Exact(GenuineFreshProfileGate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenuineFreshProfileError {
    Credentials,
    Namespace,
    CountMismatch,
}

impl fmt::Display for GenuineFreshProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Credentials => "the fresh profile credential namespace is not absent",
            Self::Namespace => "the fresh profile filesystem namespace is not exact",
            Self::CountMismatch => "the fresh profile absence proof count is not frozen",
        })
    }
}

impl std::error::Error for GenuineFreshProfileError {}

pub(crate) fn observe_genuine_fresh_profile_read_only(
    app_local_data_dir: &Path,
) -> Result<GenuineFreshProfileObservation, GenuineFreshProfileError> {
    observe_genuine_fresh_profile_with_credentials_read_only(
        app_local_data_dir,
        &V031ApprovedMcpCredentialProbe::new(),
    )
}

fn observe_genuine_fresh_profile_with_credentials_read_only<
    P: crate::v031_upgrade_r2::CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    credentials: &P,
) -> Result<GenuineFreshProfileObservation, GenuineFreshProfileError> {
    match fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let credential_absence_checks = verify_fresh_credentials_absent_read_only(credentials)?;
            if credential_absence_checks != 4 {
                return Err(GenuineFreshProfileError::CountMismatch);
            }
            return Ok(GenuineFreshProfileObservation::Exact(
                GenuineFreshProfileGate {
                    app_root_was_absent: true,
                    // Twenty fixed paths plus the app-root and Privacy-root
                    // sibling scopes; a missing root proves both scopes absent.
                    filesystem_absence_checks: 22,
                    credential_absence_checks,
                },
            ));
        }
        Err(_) => return Err(GenuineFreshProfileError::Namespace),
        Ok(_) => {}
    }

    // Either active source database means this is an installed profile. Any
    // Privacy root, even an empty one, is a partial namespace rather than fresh.
    for path in [
        database::user_database_path(app_local_data_dir),
        app_local_data_dir.join("privacy"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(GenuineFreshProfileObservation::NotFresh),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(GenuineFreshProfileError::Namespace),
        }
    }

    let proof =
        crate::v031_upgrade_r2::verify_exact_target_absence(app_local_data_dir, credentials)
            .map_err(|_| GenuineFreshProfileError::Namespace)?;
    let credential_absence_checks = u64::try_from(proof.credential_roles_checked())
        .map_err(|_| GenuineFreshProfileError::CountMismatch)?;
    let filesystem_absence_checks = u64::try_from(
        proof
            .fixed_paths_checked()
            .checked_add(proof.sibling_directories_scanned())
            // The absent Privacy root is the second frozen sibling scope.
            .and_then(|count| count.checked_add(1))
            .ok_or(GenuineFreshProfileError::CountMismatch)?,
    )
    .map_err(|_| GenuineFreshProfileError::CountMismatch)?;
    if credential_absence_checks != 4 || filesystem_absence_checks != 22 {
        return Err(GenuineFreshProfileError::CountMismatch);
    }
    Ok(GenuineFreshProfileObservation::Exact(
        GenuineFreshProfileGate {
            app_root_was_absent: false,
            filesystem_absence_checks,
            credential_absence_checks,
        },
    ))
}

fn verify_fresh_credentials_absent_read_only<P: crate::v031_upgrade_r2::CredentialPresenceProbe>(
    credentials: &P,
) -> Result<u64, GenuineFreshProfileError> {
    let mut checked = 0_u64;
    for role in crate::v031_upgrade_r2::ApprovedMcpCredentialRole::ALL {
        let present = credentials
            .credential_exists_read_only(crate::v031_upgrade_r2::CredentialAbsenceQuery {
                role,
                target: role.target(),
                account: crate::v031_upgrade_r2::APPROVED_MCP_CREDENTIAL_ACCOUNT,
            })
            .map_err(|_| GenuineFreshProfileError::Credentials)?;
        if present {
            return Err(GenuineFreshProfileError::Credentials);
        }
        checked = checked
            .checked_add(1)
            .ok_or(GenuineFreshProfileError::CountMismatch)?;
    }
    Ok(checked)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExactV031SourceProfileGate {
    user: database::UserMigrationSourceProof,
    privacy: privacy::ValidatedPrivacyV1Source,
    filesystem_absence_checks: u64,
    credential_absence_checks: u64,
}

impl fmt::Debug for ExactV031SourceProfileGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactV031SourceProfileGate")
            .field(
                "user_logical_manifest_sha256",
                &self.user.logical_database_manifest_sha256,
            )
            .field(
                "privacy_logical_manifest_sha256",
                &self.privacy.logical_manifest.sha256,
            )
            .field("filesystem_absence_checks", &self.filesystem_absence_checks)
            .field("credential_absence_checks", &self.credential_absence_checks)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The exact v0.3.1 source proof remains inline for deterministic re-observation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ExactV031SourceProfileObservation {
    NotSource,
    Exact(ExactV031SourceProfileGate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactV031SourceProfileError {
    User,
    Privacy,
    Namespace,
    CountMismatch,
}

impl fmt::Display for ExactV031SourceProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::User => "the v0.3.1 user source is invalid",
            Self::Privacy => "the v0.3.1 Privacy source is invalid",
            Self::Namespace => "the v0.3.1 target namespace is not authenticated-absent",
            Self::CountMismatch => "the v0.3.1 target absence count is not frozen",
        })
    }
}

impl std::error::Error for ExactV031SourceProfileError {}

/// Classifies an exact v0.3.1 live source without creating the receipt-zero
/// lineage. Existing terminal histories and the narrow receipt-zero crash
/// residue are admitted only through the authenticated namespace inventory.
pub(crate) fn observe_exact_v031_source_profile_read_only(
    app_local_data_dir: &Path,
) -> Result<ExactV031SourceProfileObservation, ExactV031SourceProfileError> {
    observe_exact_v031_source_profile_with_credentials_read_only(
        app_local_data_dir,
        &V031ApprovedMcpCredentialProbe::new(),
    )
}

fn observe_exact_v031_source_profile_with_credentials_read_only<
    P: crate::v031_upgrade_r2::CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    credentials: &P,
) -> Result<ExactV031SourceProfileObservation, ExactV031SourceProfileError> {
    let user_path = database::user_database_path(app_local_data_dir);
    match fs::symlink_metadata(&user_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExactV031SourceProfileObservation::NotSource)
        }
        Err(_) => return Err(ExactV031SourceProfileError::User),
        Ok(_) => {}
    }
    let (user, ()) =
        database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .map_err(|_| ExactV031SourceProfileError::User)?;
    if user.schema != database::ValidatedUserSourceSchema::V031V10 {
        return Ok(ExactV031SourceProfileObservation::NotSource);
    }

    let privacy_path = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    match fs::symlink_metadata(&privacy_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExactV031SourceProfileObservation::NotSource)
        }
        Err(_) => return Err(ExactV031SourceProfileError::Privacy),
        Ok(_) => {}
    }
    let (privacy, ()) =
        privacy::with_validated_privacy_v1_migration_source_read_only(&privacy_path, |_| ())
            .map_err(|_| ExactV031SourceProfileError::Privacy)?;

    let namespace =
        crate::v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
            PrivacyReceiptAuthenticationBridge::discovering()
        })
        .map_err(|_| ExactV031SourceProfileError::Namespace)?;
    let absence =
        match crate::v031_upgrade_r2::verify_exact_target_absence_with_receipt_zero_namespace(
            app_local_data_dir,
            credentials,
            &namespace,
        ) {
            Ok(proof) => proof,
            // A receipt-2 target transition is the only legitimate reason an
            // otherwise exact v0.3.1 source can have target state. The aggregate
            // observer must authenticate that state separately before classifying
            // it as an upgrade profile; every other caller gets NotSource.
            Err(_) => return Ok(ExactV031SourceProfileObservation::NotSource),
        };
    let credential_absence_checks = u64::try_from(absence.credential_roles_checked())
        .map_err(|_| ExactV031SourceProfileError::CountMismatch)?;
    let filesystem_absence_checks = u64::try_from(
        absence
            .fixed_paths_checked()
            .checked_add(absence.sibling_directories_scanned())
            .ok_or(ExactV031SourceProfileError::CountMismatch)?,
    )
    .map_err(|_| ExactV031SourceProfileError::CountMismatch)?;
    if credential_absence_checks != 4 || filesystem_absence_checks != 22 {
        return Err(ExactV031SourceProfileError::CountMismatch);
    }
    Ok(ExactV031SourceProfileObservation::Exact(
        ExactV031SourceProfileGate {
            user,
            privacy,
            filesystem_absence_checks,
            credential_absence_checks,
        },
    ))
}

// Every variant is an opaque authenticated target capability with a different
// frozen crash-window shape; keep the proofs inline.
#[allow(clippy::large_enum_variant)]
enum AuthenticatedUpgradeTargetProof {
    /// A strict Credential prefix or fixed Approved/work-products partial
    /// layout. Vault must still be authenticated-absent in this state.
    ApprovedInFlight {
        approved: V031ApprovedMcpTargetIncompleteGate,
        vault: V031VaultTargetAbsentGate,
    },
    /// Approved/work-products are complete and Vault is a legal fixed partial
    /// layout, but the target-components receipt is not yet final.
    VaultInFlight {
        approved: V031ApprovedMcpTargetComponentsGate,
        vault: V031VaultTargetIncompleteGate,
    },
    /// Target components are complete but receipt 2 has not necessarily
    /// reached its final basename yet.
    PreparedInFlight {
        approved: V031ApprovedMcpTargetComponentsGate,
        vault: V031VaultTargetComponentGate,
    },
    ReceiptBound(V031TargetComponentsPreparedGate),
}

impl fmt::Debug for AuthenticatedUpgradeTargetProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApprovedInFlight { approved, vault } => formatter
                .debug_struct("ApprovedInFlight")
                .field("approved", approved)
                .field("vault", vault)
                .finish(),
            Self::VaultInFlight { approved, vault } => formatter
                .debug_struct("VaultInFlight")
                .field("approved", approved)
                .field("vault", vault)
                .finish(),
            Self::PreparedInFlight { approved, vault } => formatter
                .debug_struct("PreparedInFlight")
                .field("approved", approved)
                .field("vault", vault)
                .finish(),
            Self::ReceiptBound(gate) => formatter.debug_tuple("ReceiptBound").field(gate).finish(),
        }
    }
}

pub(crate) struct AuthenticatedUpgradeProfileGate {
    rollback: OriginalRollbackVerifiedGate,
    target: AuthenticatedUpgradeTargetProof,
}

impl fmt::Debug for AuthenticatedUpgradeProfileGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedUpgradeProfileGate")
            .field("rollback", &self.rollback)
            .field("target", &self.target)
            .finish()
    }
}

fn observe_authenticated_upgrade_profile_read_only(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
) -> Result<AuthenticatedUpgradeProfileGate, V031StartupTransitionError> {
    let final_count = process_start
        .active_final_receipt_count()
        .ok_or(V031StartupTransitionError::Observation)?;
    if !(2..=usize::from(RECEIPT_EIGHT_FINAL_COUNT)).contains(&final_count) {
        return Err(V031StartupTransitionError::Observation);
    }
    let lineage_id = process_start
        .active_lineage_id()
        .ok_or(V031StartupTransitionError::Observation)?;
    let rollback = load_original_migration_backup_gate(app_local_data_dir, lineage_id)
        .map_err(|_| V031StartupTransitionError::OriginalRollback)?;
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    let target = if final_count == 2 {
        match observe_v031_approved_mcp_target_namespace_read_only(app_local_data_dir, &rollback)
            .map_err(|_| V031StartupTransitionError::TargetComponents)?
        {
            V031ApprovedMcpTargetNamespaceObservation::Incomplete(approved) => {
                let vault = observe_v031_vault_target_absent_read_only(app_local_data_dir)
                    .map_err(|_| V031StartupTransitionError::TargetComponents)?;
                AuthenticatedUpgradeTargetProof::ApprovedInFlight { approved, vault }
            }
            V031ApprovedMcpTargetNamespaceObservation::Complete(approved) => {
                match observe_v031_vault_target_namespace_read_only(
                    app_local_data_dir,
                    &rollback,
                    &approved,
                )
                .map_err(|_| V031StartupTransitionError::TargetComponents)?
                {
                    V031VaultTargetNamespaceObservation::Incomplete(vault) => {
                        AuthenticatedUpgradeTargetProof::VaultInFlight { approved, vault }
                    }
                    V031VaultTargetNamespaceObservation::Complete(vault) => {
                        AuthenticatedUpgradeTargetProof::PreparedInFlight { approved, vault }
                    }
                }
            }
        }
    } else if final_count == 3 {
        AuthenticatedUpgradeTargetProof::ReceiptBound(
            load_v031_target_components_prepared_gate_read_only(
                app_local_data_dir,
                &rollback,
                &approved_workspace,
            )
            .map_err(|_| V031StartupTransitionError::TargetComponents)?,
        )
    } else {
        let target = load_v031_historical_target_components_from_checkpoint_read_only(
            app_local_data_dir,
            &rollback,
            &approved_workspace,
        )
        .map_err(|_| V031StartupTransitionError::TargetComponents)?;
        verify_v031_case_migration_backups_historical_profile_read_only(
            app_local_data_dir,
            &approved_workspace,
            &target,
        )
        .map_err(|_| V031StartupTransitionError::CaseMigrationBackups)?;
        AuthenticatedUpgradeTargetProof::ReceiptBound(target)
    };
    Ok(AuthenticatedUpgradeProfileGate { rollback, target })
}

/// Reconstructs the exact-current capability without creating a Credential,
/// manager, SQLite sidecar, component root, recovery artifact, or receipt.
///
/// Legal lazy states are deliberately finite: Vault is absent or exact; the
/// approved/work-product lifecycle is identity-only, approved-only, or both
/// exact. Work-products without approved state and every root/key mismatch are
/// rejected by the component observer before this gate can be built.
pub(crate) fn observe_exact_current_profile_read_only(
    app_local_data_dir: &Path,
) -> Result<ExactCurrentProfileObservation, ExactCurrentProfileError> {
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    observe_exact_current_profile_with_approved_workspace_read_only(
        app_local_data_dir,
        &approved_workspace,
    )
}

fn observe_exact_current_profile_with_approved_workspace_read_only(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<ExactCurrentProfileObservation, ExactCurrentProfileError> {
    let user_path = database::user_database_path(app_local_data_dir);
    match fs::symlink_metadata(&user_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExactCurrentProfileObservation::NotCurrent)
        }
        Err(_) => return Err(ExactCurrentProfileError::User),
        Ok(_) => {}
    }
    let (user, ()) =
        database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .map_err(|_| ExactCurrentProfileError::User)?;
    if user.schema != database::ValidatedUserSourceSchema::CurrentV11 {
        return Ok(ExactCurrentProfileObservation::NotCurrent);
    }

    let privacy = match observe_current_privacy_profile_read_only(app_local_data_dir)
        .map_err(|_| ExactCurrentProfileError::Privacy)?
    {
        CurrentPrivacyProfileObservation::Absent => {
            return Ok(ExactCurrentProfileObservation::NotCurrent)
        }
        CurrentPrivacyProfileObservation::ExactCurrent(proof) => proof,
    };
    let approved = match approved_workspace
        .observe_current_components_read_only()
        .map_err(|_| ExactCurrentProfileError::Approved)?
    {
        CurrentApprovedComponentsObservation::Absent => {
            return Ok(ExactCurrentProfileObservation::NotCurrent)
        }
        CurrentApprovedComponentsObservation::Exact(proof) => proof,
    };
    let approved_workspace_matches =
        approved.workspace_instance_id() == privacy.workspace_instance_id();
    if !approved_workspace_matches {
        return Err(ExactCurrentProfileError::WorkspaceMismatch);
    }

    let vault =
        match observe_current_vault_read_only(app_local_data_dir, privacy.workspace_instance_id())
            .map_err(|_| ExactCurrentProfileError::Vault)?
        {
            CurrentVaultObservation::Absent => None,
            CurrentVaultObservation::Exact(proof) => Some(proof),
        };
    let vault_workspace_matches = vault
        .as_ref()
        .is_none_or(|proof| proof.workspace_instance_id() == privacy.workspace_instance_id());
    let shape = CurrentFiveSlotShape {
        user_exact_v11: true,
        privacy_exact_v6: true,
        approved_lifecycle: Some(approved.lifecycle()),
        vault: if vault.is_some() {
            CurrentOptionalSlotShape::Exact
        } else {
            CurrentOptionalSlotShape::Absent
        },
        approved_workspace_matches,
        vault_workspace_matches,
    };
    if !is_exact_current_five_slot_shape(shape) {
        return Err(ExactCurrentProfileError::WorkspaceMismatch);
    }
    Ok(ExactCurrentProfileObservation::Exact(
        ExactCurrentProfileGate {
            user,
            privacy,
            vault,
            approved,
        },
    ))
}

#[cfg(test)]
pub(crate) fn observe_exact_current_profile_with_approved_workspace_for_test(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<ExactCurrentProfileObservation, ExactCurrentProfileError> {
    observe_exact_current_profile_with_approved_workspace_read_only(
        app_local_data_dir,
        approved_workspace,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveUpgradeObservation {
    /// Number of contiguous final receipts. The next legal ordinal is exactly
    /// this value.
    pub(crate) final_receipt_count: u8,
    pub(crate) next_incoming_ordinal: Option<u8>,
    /// This capability bit is true only when receipt 8 was authenticated by the
    /// frozen process-start observer, never when this process just installed it.
    pub(crate) receipt_eight_observed_at_process_start: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpgradeObservation {
    pub(crate) terminal_lineage_count: usize,
    pub(crate) active: Option<ActiveUpgradeObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartupObservation {
    pub(crate) restores: RestoreObservation,
    pub(crate) upgrade: UpgradeObservation,
    pub(crate) profile: InstalledProfile,
    pub(crate) unknown_marker_or_sibling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRoute {
    ApplyExplicitRecoveryAndExit,
    ApplyCurrentRestoreAndReclassify(CurrentRestoreKind),
    RepairEmptyLegacyBootstrapAndRestart,
    AdvanceUpgradeThroughReceiptEight { next_ordinal: u8 },
    RunStepEightAndInstallReceiptNine,
    InitializeCurrent,
    InitializeFresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupClassificationError {
    UnknownOrUnauthenticated,
    MixedRecoveryFlows,
    InvalidReceiptPrefix,
    ProfileDoesNotMatchReceipts,
    PartialProfile,
}

impl fmt::Display for StartupClassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownOrUnauthenticated => "startup evidence is unknown or unauthenticated",
            Self::MixedRecoveryFlows => "startup evidence selects mixed recovery flows",
            Self::InvalidReceiptPrefix => "startup receipt prefix is not the unique next state",
            Self::ProfileDoesNotMatchReceipts => {
                "startup profile does not match the authenticated receipt state"
            }
            Self::PartialProfile => "startup profile is partial or unsupported",
        })
    }
}

impl std::error::Error for StartupClassificationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031StartupTransitionError {
    Observation,
    OriginalRollback,
    TargetComponents,
    WorkflowManager,
    CaseMigrationBackups,
    PrivacyV5,
    BindingMaterials,
    ProjectionBackup,
    PrivacyV6,
    UserV11,
    UpgradeComplete,
}

impl fmt::Display for V031StartupTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Observation => "v031 startup observation does not authorize this transition",
            Self::OriginalRollback => "v031 original rollback gate failed",
            Self::TargetComponents => "v031 target component gate failed",
            Self::WorkflowManager => "v031 migration workflow manager failed",
            Self::CaseMigrationBackups => "v031 case migration checkpoint gate failed",
            Self::PrivacyV5 => "v031 Privacy-v5 gate failed",
            Self::BindingMaterials => "v031 binding/material gate failed",
            Self::ProjectionBackup => "v031 projection checkpoint gate failed",
            Self::PrivacyV6 => "v031 Privacy-v6 gate failed",
            Self::UserV11 => "v031 user-v11 gate failed",
            Self::UpgradeComplete => "v031 upgrade-complete gate failed",
        })
    }
}

impl std::error::Error for V031StartupTransitionError {}

/// Complete path-free result of the single manager-free startup pass.  The
/// summary is intentionally insufficient for mutation: every route that can
/// write also retains the exact opaque capability returned by its observer.
pub(crate) struct ProductionStartupObservation {
    summary: StartupObservation,
    explicit_recovery: Option<V031MigrationRecoveryGate>,
    full_application_restore: Option<PendingApplicationRestoreGate>,
    legacy_user_database_restore: Option<PendingDatabaseRestoreGate>,
    standalone_privacy_restore: Option<PendingPrivacyRestoreGate>,
    process_start_upgrade: Option<V031ProcessStartUpgradeObservation>,
    genuine_fresh: Option<GenuineFreshProfileGate>,
    exact_v031_source: Option<ExactV031SourceProfileGate>,
    exact_current: Option<ExactCurrentProfileGate>,
    authenticated_upgrade: Option<AuthenticatedUpgradeProfileGate>,
    empty_legacy_bootstrap: Option<crate::empty_legacy_bootstrap::EmptyLegacyBootstrapGate>,
}

impl fmt::Debug for ProductionStartupObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionStartupObservation")
            .field("summary", &self.summary)
            .field("explicit_recovery", &self.explicit_recovery.is_some())
            .field(
                "full_application_restore",
                &self.full_application_restore.is_some(),
            )
            .field(
                "legacy_user_database_restore",
                &self.legacy_user_database_restore.is_some(),
            )
            .field(
                "standalone_privacy_restore",
                &self.standalone_privacy_restore.is_some(),
            )
            .field("process_start_upgrade", &self.process_start_upgrade)
            .field("genuine_fresh", &self.genuine_fresh.is_some())
            .field("exact_v031_source", &self.exact_v031_source.is_some())
            .field("exact_current", &self.exact_current.is_some())
            .field(
                "authenticated_upgrade",
                &self.authenticated_upgrade.is_some(),
            )
            .field(
                "empty_legacy_bootstrap",
                &self.empty_legacy_bootstrap.is_some(),
            )
            .finish()
    }
}

impl ProductionStartupObservation {
    pub(crate) const fn summary(&self) -> StartupObservation {
        self.summary
    }

    pub(crate) fn take_explicit_recovery_gate(&mut self) -> Option<V031MigrationRecoveryGate> {
        self.explicit_recovery.take()
    }

    pub(crate) fn take_empty_legacy_bootstrap_gate(
        &mut self,
    ) -> Option<crate::empty_legacy_bootstrap::EmptyLegacyBootstrapGate> {
        self.empty_legacy_bootstrap.take()
    }

    pub(crate) fn full_application_restore_gate(&self) -> Option<&PendingApplicationRestoreGate> {
        self.full_application_restore.as_ref()
    }

    pub(crate) fn legacy_user_database_restore_gate(&self) -> Option<&PendingDatabaseRestoreGate> {
        self.legacy_user_database_restore.as_ref()
    }

    pub(crate) fn standalone_privacy_restore_gate(&self) -> Option<&PendingPrivacyRestoreGate> {
        self.standalone_privacy_restore.as_ref()
    }

    pub(crate) fn process_start_upgrade_gate(&self) -> Option<&V031ProcessStartUpgradeObservation> {
        self.process_start_upgrade.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn process_start_upgrade(&self) -> &V031ProcessStartUpgradeObservation {
        self.process_start_upgrade_gate()
            .expect("ordinary startup test fixture retains a process-start upgrade observation")
    }

    pub(crate) fn genuine_fresh_gate(&self) -> Option<&GenuineFreshProfileGate> {
        self.genuine_fresh.as_ref()
    }

    pub(crate) fn exact_v031_source_gate(&self) -> Option<&ExactV031SourceProfileGate> {
        self.exact_v031_source.as_ref()
    }

    pub(crate) fn exact_current_gate(&self) -> Option<&ExactCurrentProfileGate> {
        self.exact_current.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProductionStartupObservationError {
    Root,
    ExplicitRecovery,
    FullApplicationRestore,
    LegacyUserDatabaseRestore,
    StandalonePrivacyRestore,
    UpgradeHistory,
    FreshProfile,
    V031SourceProfile,
    CurrentProfile,
    ActiveUpgradeProfile,
    EmptyLegacyBootstrap,
}

impl fmt::Display for ProductionStartupObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Root => "the fixed application root could not be observed",
            Self::ExplicitRecovery => "the explicit v0.3.1 recovery namespace is invalid",
            Self::FullApplicationRestore => {
                "the pending full-application restore namespace is invalid"
            }
            Self::LegacyUserDatabaseRestore => {
                "the pending legacy-user restore namespace is invalid"
            }
            Self::StandalonePrivacyRestore => {
                "the pending standalone-Privacy restore namespace is invalid"
            }
            Self::UpgradeHistory => "the v0.3.1 upgrade history is invalid",
            Self::FreshProfile => "the genuine-fresh profile proof failed",
            Self::V031SourceProfile => "the exact v0.3.1 source profile proof failed",
            Self::CurrentProfile => "the exact current profile proof failed",
            Self::ActiveUpgradeProfile => "the active upgrade profile proof failed",
            Self::EmptyLegacyBootstrap => "the interrupted empty legacy bootstrap proof failed",
        })
    }
}

impl std::error::Error for ProductionStartupObservationError {}

pub(crate) fn observe_production_startup_read_only(
    app_local_data_dir: &Path,
) -> Result<ProductionStartupObservation, ProductionStartupObservationError> {
    observe_production_startup_with_credentials_read_only(
        app_local_data_dir,
        &V031ApprovedMcpCredentialProbe::new(),
        true,
    )
}

/// Runs the production startup observer with a test-owned credential namespace.
/// The filesystem, restore, receipt, profile, and arbitration paths are exactly
/// the production common inner; only the four read-only Credential Manager
/// queries are redirected away from the fixed application namespace.
#[cfg(test)]
pub(crate) fn observe_production_startup_with_credential_probe_for_test<
    P: crate::v031_upgrade_r2::CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    credentials: &P,
) -> Result<ProductionStartupObservation, ProductionStartupObservationError> {
    observe_production_startup_with_credentials_read_only(app_local_data_dir, credentials, false)
}

fn observe_production_startup_with_credentials_read_only<
    P: crate::v031_upgrade_r2::CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    fresh_credentials: &P,
    observe_empty_legacy_bootstrap: bool,
) -> Result<ProductionStartupObservation, ProductionStartupObservationError> {
    if !crate::privacy_manager::is_normal_local_absolute(app_local_data_dir)
        || !crate::privacy_manager::local_path_chain_is_ordinary(app_local_data_dir)
    {
        return Err(ProductionStartupObservationError::Root);
    }
    let root_absent = match fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => return Err(ProductionStartupObservationError::Root),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => false,
        Ok(_) => return Err(ProductionStartupObservationError::Root),
    };

    // R3 recovery owns the shared restore slots and authenticates every
    // conflicting marker itself.  Observe it before the ordinary upgrade and
    // restore observers because a legal recovery crash phase may have moved
    // one or more current slots away from their ordinary locations.
    let explicit_recovery = if root_absent {
        None
    } else {
        match observe_v031_migration_recovery_read_only(app_local_data_dir)
            .map_err(|_| ProductionStartupObservationError::ExplicitRecovery)?
        {
            V031MigrationRecoveryObservation::Absent => None,
            V031MigrationRecoveryObservation::Authenticated(gate) => Some(*gate),
        }
    };
    if explicit_recovery.is_some() {
        return Ok(ProductionStartupObservation {
            summary: StartupObservation {
                restores: RestoreObservation {
                    explicit_recovery: AuthenticatedPresence::Authenticated,
                    full_application: AuthenticatedPresence::Absent,
                    legacy_user_database: AuthenticatedPresence::Absent,
                    standalone_privacy: AuthenticatedPresence::Absent,
                },
                // Explicit recovery is classified before the ordinary upgrade
                // summary, so no synthetic receipt capability is retained.
                upgrade: UpgradeObservation {
                    terminal_lineage_count: 0,
                    active: None,
                },
                profile: InstalledProfile::PartialOrUnknown,
                unknown_marker_or_sibling: false,
            },
            explicit_recovery,
            full_application_restore: None,
            legacy_user_database_restore: None,
            standalone_privacy_restore: None,
            process_start_upgrade: None,
            genuine_fresh: None,
            exact_v031_source: None,
            exact_current: None,
            authenticated_upgrade: None,
            empty_legacy_bootstrap: None,
        });
    }

    // The process observer is part of the same immutable ordinary pass even
    // when a current restore has precedence. This rejects an invalid or mixed
    // historical lineage before any ordinary restore swap is authorized.
    let process_start_upgrade = observe_v031_upgrade_at_process_start_read_only(app_local_data_dir)
        .map_err(|_| ProductionStartupObservationError::UpgradeHistory)?;

    let (full_application, full_application_restore) = if root_absent {
        (AuthenticatedPresence::Absent, None)
    } else {
        match observe_pending_application_restore_read_only(app_local_data_dir)
            .map_err(|_| ProductionStartupObservationError::FullApplicationRestore)?
        {
            PendingApplicationRestoreObservation::Absent => (AuthenticatedPresence::Absent, None),
            PendingApplicationRestoreObservation::Authenticated(gate) => {
                (AuthenticatedPresence::Authenticated, Some(gate))
            }
        }
    };
    let (legacy_user_database, legacy_user_database_restore) = if root_absent {
        (AuthenticatedPresence::Absent, None)
    } else {
        match observe_pending_database_restore_read_only(app_local_data_dir)
            .map_err(|_| ProductionStartupObservationError::LegacyUserDatabaseRestore)?
        {
            PendingDatabaseRestoreObservation::Absent => (AuthenticatedPresence::Absent, None),
            PendingDatabaseRestoreObservation::Authenticated(gate) => {
                (AuthenticatedPresence::Authenticated, Some(gate))
            }
        }
    };
    let (standalone_privacy, standalone_privacy_restore) = if root_absent {
        (AuthenticatedPresence::Absent, None)
    } else {
        match observe_pending_privacy_restore_read_only(app_local_data_dir)
            .map_err(|_| ProductionStartupObservationError::StandalonePrivacyRestore)?
        {
            PendingPrivacyRestoreObservation::Absent => (AuthenticatedPresence::Absent, None),
            PendingPrivacyRestoreObservation::Authenticated(gate) => {
                (AuthenticatedPresence::Authenticated, Some(gate))
            }
        }
    };
    let restores = RestoreObservation {
        explicit_recovery: AuthenticatedPresence::Absent,
        full_application,
        legacy_user_database,
        standalone_privacy,
    };
    let upgrade = upgrade_summary(&process_start_upgrade)?;

    // Recovery routes are selected before an installed profile.  Their exact
    // gates above are retained, while ordinary profile observers are skipped
    // because a legal crash phase can temporarily move an active slot away.
    if [full_application, legacy_user_database, standalone_privacy]
        .into_iter()
        .any(|presence| presence != AuthenticatedPresence::Absent)
    {
        return Ok(ProductionStartupObservation {
            summary: StartupObservation {
                restores,
                upgrade,
                profile: InstalledProfile::PartialOrUnknown,
                unknown_marker_or_sibling: false,
            },
            explicit_recovery: None,
            full_application_restore,
            legacy_user_database_restore,
            standalone_privacy_restore,
            process_start_upgrade: Some(process_start_upgrade),
            genuine_fresh: None,
            exact_v031_source: None,
            exact_current: None,
            authenticated_upgrade: None,
            empty_legacy_bootstrap: None,
        });
    }

    if observe_empty_legacy_bootstrap {
        let empty_legacy_bootstrap =
            match crate::empty_legacy_bootstrap::observe_interrupted_empty_legacy_profile_read_only(
                app_local_data_dir,
            )
            .map_err(|_| ProductionStartupObservationError::EmptyLegacyBootstrap)?
            {
                crate::empty_legacy_bootstrap::EmptyLegacyBootstrapObservation::Absent => None,
                crate::empty_legacy_bootstrap::EmptyLegacyBootstrapObservation::Authenticated(
                    gate,
                ) => Some(gate),
            };
        if let Some(gate) = empty_legacy_bootstrap {
            if upgrade.active.is_some() || upgrade.terminal_lineage_count != 0 {
                return Err(ProductionStartupObservationError::EmptyLegacyBootstrap);
            }
            return Ok(ProductionStartupObservation {
                summary: StartupObservation {
                    restores,
                    upgrade,
                    profile: InstalledProfile::EmptyLegacyBootstrap,
                    unknown_marker_or_sibling: false,
                },
                explicit_recovery: None,
                full_application_restore: None,
                legacy_user_database_restore: None,
                standalone_privacy_restore: None,
                process_start_upgrade: Some(process_start_upgrade),
                genuine_fresh: None,
                exact_v031_source: None,
                exact_current: None,
                authenticated_upgrade: None,
                empty_legacy_bootstrap: Some(gate),
            });
        }
    }

    let mut genuine_fresh = None;
    let mut exact_v031_source = None;
    let mut exact_current = None;
    let mut authenticated_upgrade = None;
    let profile = if let Some(active) = upgrade.active {
        match active.final_receipt_count {
            0..=1 => match observe_exact_v031_source_profile_with_credentials_read_only(
                app_local_data_dir,
                fresh_credentials,
            )
            .map_err(|_| ProductionStartupObservationError::V031SourceProfile)?
            {
                ExactV031SourceProfileObservation::Exact(gate) => {
                    exact_v031_source = Some(gate);
                    InstalledProfile::ExactV031Source
                }
                ExactV031SourceProfileObservation::NotSource => InstalledProfile::PartialOrUnknown,
            },
            2 => match observe_exact_v031_source_profile_with_credentials_read_only(
                app_local_data_dir,
                fresh_credentials,
            )
            .map_err(|_| ProductionStartupObservationError::V031SourceProfile)?
            {
                ExactV031SourceProfileObservation::Exact(gate) => {
                    exact_v031_source = Some(gate);
                    InstalledProfile::ExactV031Source
                }
                ExactV031SourceProfileObservation::NotSource => {
                    authenticated_upgrade = Some(
                        observe_authenticated_upgrade_profile_read_only(
                            app_local_data_dir,
                            &process_start_upgrade,
                        )
                        .map_err(|_| ProductionStartupObservationError::ActiveUpgradeProfile)?,
                    );
                    InstalledProfile::AuthenticatedUpgradeState
                }
            },
            3..=7 => {
                authenticated_upgrade = Some(
                    observe_authenticated_upgrade_profile_read_only(
                        app_local_data_dir,
                        &process_start_upgrade,
                    )
                    .map_err(|_| ProductionStartupObservationError::ActiveUpgradeProfile)?,
                );
                InstalledProfile::AuthenticatedUpgradeState
            }
            8 => match observe_exact_current_profile_read_only(app_local_data_dir)
                .map_err(|_| ProductionStartupObservationError::CurrentProfile)?
            {
                ExactCurrentProfileObservation::Exact(gate) => {
                    exact_current = Some(gate);
                    InstalledProfile::ExactCurrent
                }
                ExactCurrentProfileObservation::NotCurrent => {
                    authenticated_upgrade = Some(
                        observe_authenticated_upgrade_profile_read_only(
                            app_local_data_dir,
                            &process_start_upgrade,
                        )
                        .map_err(|_| ProductionStartupObservationError::ActiveUpgradeProfile)?,
                    );
                    InstalledProfile::AuthenticatedUpgradeState
                }
            },
            RECEIPT_EIGHT_FINAL_COUNT => {
                match observe_exact_current_profile_read_only(app_local_data_dir)
                    .map_err(|_| ProductionStartupObservationError::CurrentProfile)?
                {
                    ExactCurrentProfileObservation::Exact(gate) => {
                        exact_current = Some(gate);
                        InstalledProfile::ExactCurrent
                    }
                    ExactCurrentProfileObservation::NotCurrent => {
                        InstalledProfile::PartialOrUnknown
                    }
                }
            }
            _ => InstalledProfile::PartialOrUnknown,
        }
    } else {
        match observe_exact_current_profile_read_only(app_local_data_dir)
            .map_err(|_| ProductionStartupObservationError::CurrentProfile)?
        {
            ExactCurrentProfileObservation::Exact(gate) => {
                exact_current = Some(gate);
                InstalledProfile::ExactCurrent
            }
            ExactCurrentProfileObservation::NotCurrent => {
                match observe_exact_v031_source_profile_with_credentials_read_only(
                    app_local_data_dir,
                    fresh_credentials,
                )
                .map_err(|_| ProductionStartupObservationError::V031SourceProfile)?
                {
                    ExactV031SourceProfileObservation::Exact(gate) => {
                        exact_v031_source = Some(gate);
                        InstalledProfile::ExactV031Source
                    }
                    ExactV031SourceProfileObservation::NotSource => {
                        match observe_genuine_fresh_profile_with_credentials_read_only(
                            app_local_data_dir,
                            fresh_credentials,
                        )
                        .map_err(|_| ProductionStartupObservationError::FreshProfile)?
                        {
                            GenuineFreshProfileObservation::Exact(gate) => {
                                genuine_fresh = Some(gate);
                                InstalledProfile::GenuineFresh
                            }
                            GenuineFreshProfileObservation::NotFresh => {
                                InstalledProfile::PartialOrUnknown
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(ProductionStartupObservation {
        summary: StartupObservation {
            restores,
            upgrade,
            profile,
            unknown_marker_or_sibling: false,
        },
        explicit_recovery: None,
        full_application_restore,
        legacy_user_database_restore,
        standalone_privacy_restore,
        process_start_upgrade: Some(process_start_upgrade),
        genuine_fresh,
        exact_v031_source,
        exact_current,
        authenticated_upgrade,
        empty_legacy_bootstrap: None,
    })
}

fn upgrade_summary(
    process_start: &V031ProcessStartUpgradeObservation,
) -> Result<UpgradeObservation, ProductionStartupObservationError> {
    let active = process_start
        .active_final_receipt_count()
        .map(|final_receipt_count| {
            Ok(ActiveUpgradeObservation {
                final_receipt_count: u8::try_from(final_receipt_count)
                    .map_err(|_| ProductionStartupObservationError::UpgradeHistory)?,
                next_incoming_ordinal: process_start.active_next_incoming_ordinal(),
                receipt_eight_observed_at_process_start: process_start
                    .receipt_eight_observed_at_process_start()
                    .is_some(),
            })
        })
        .transpose()?;
    Ok(UpgradeObservation {
        terminal_lineage_count: process_start.terminal_lineage_count(),
        active,
    })
}

/// Managers created solely to authenticate either Step 8 or an already-
/// terminal lineage. They are not installed in Tauri state until receipt 9
/// has committed and the live terminal gate has been reconstructed.
pub(crate) struct V031StepEightReady {
    pub(crate) approved_workspace: ApprovedMcpWorkspace,
    pub(crate) privacy_workflow: PrivacyWorkflowManager,
    _complete_gate: V031UpgradeCompleteGate,
}

impl V031StepEightReady {
    pub(crate) fn into_managers(self) -> (ApprovedMcpWorkspace, PrivacyWorkflowManager) {
        (self.approved_workspace, self.privacy_workflow)
    }
}

fn select_unique_live_current_terminal_lineage<'a>(
    candidates: &'a [(String, String)],
    current_workspace_instance_id: &str,
) -> Result<&'a str, V031StartupTransitionError> {
    let mut matching = candidates.iter().filter(|(_, workspace_instance_id)| {
        workspace_instance_id == current_workspace_instance_id
    });
    let selected = matching
        .next()
        .ok_or(V031StartupTransitionError::Observation)?;
    if matching.next().is_some() {
        return Err(V031StartupTransitionError::Observation);
    }
    Ok(selected.0.as_str())
}

fn authenticate_completed_v031_terminal_lineage_for_current(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_current: &ExactCurrentProfileGate,
    reobserve_exact_current: impl FnOnce() -> Result<
        ExactCurrentProfileObservation,
        ExactCurrentProfileError,
    >,
) -> Result<String, V031StartupTransitionError> {
    if !process_start.has_terminal_lineage_only()
        || process_start.terminal_lineage_count() == 0
        || process_start.active_lineage_id().is_some()
        || process_start.active_final_receipt_count().is_some()
        || process_start.active_next_incoming_ordinal().is_some()
        || process_start
            .receipt_eight_observed_at_process_start()
            .is_some()
    {
        return Err(V031StartupTransitionError::Observation);
    }
    if reobserve_exact_current().map_err(|_| V031StartupTransitionError::Observation)?
        != ExactCurrentProfileObservation::Exact(exact_current.clone())
    {
        return Err(V031StartupTransitionError::Observation);
    }

    let namespace =
        crate::v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
            PrivacyReceiptAuthenticationBridge::discovering()
        })
        .map_err(|_| V031StartupTransitionError::UpgradeComplete)?;
    if namespace.empty_lineage_id().is_some()
        || namespace.lineage_ids().len() != namespace.authenticated_lineages().len()
        || namespace.authenticated_lineages().len() != process_start.terminal_lineage_count()
        || namespace.authenticated_lineages().iter().any(|inventory| {
            inventory.final_receipts.len()
                != privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_STAGE_COUNT
                || inventory.next_incoming_receipt.is_some()
        })
    {
        return Err(V031StartupTransitionError::Observation);
    }

    let mut terminal_candidates = Vec::with_capacity(namespace.authenticated_lineages().len());
    for expected_inventory in namespace.authenticated_lineages() {
        verify_one_v031_terminal_history_lineage_read_only(app_local_data_dir, expected_inventory)
            .map_err(|_| V031StartupTransitionError::UpgradeComplete)?;
        let bridge = PrivacyReceiptAuthenticationBridge::discovering();
        let inventory = load_authenticated_v031_lineage(
            app_local_data_dir,
            &expected_inventory.lineage_id,
            &bridge,
        )
        .map_err(|_| V031StartupTransitionError::UpgradeComplete)?;
        if &inventory != expected_inventory {
            return Err(V031StartupTransitionError::Observation);
        }
        let receipt_context = bridge
            .context()
            .map_err(|_| V031StartupTransitionError::UpgradeComplete)?;
        let predecessor = authenticate_v031_terminal_history_offline(
            app_local_data_dir,
            &inventory,
            &receipt_context,
        )
        .map_err(|_| V031StartupTransitionError::UpgradeComplete)?;
        terminal_candidates.push((
            inventory.lineage_id.clone(),
            predecessor
                .predecessor_manifest()
                .workspace_instance_id()
                .to_owned(),
        ));
    }
    select_unique_live_current_terminal_lineage(
        &terminal_candidates,
        exact_current.workspace_instance_id().as_str(),
    )
    .map(str::to_owned)
}

fn load_completed_v031_gate_for_selected_lineage(
    app_local_data_dir: &Path,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    selected_lineage_id: &str,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    load_v031_upgrade_complete_gate_read_only(
        app_local_data_dir,
        privacy_workflow,
        approved_workspace,
        selected_lineage_id,
    )
    .map_err(|_| V031StartupTransitionError::UpgradeComplete)
}

/// Rebuilds the completed-upgrade gate before ordinary startup is allowed to
/// write a crash log, run updater cleanup, or construct business services.
///
/// Every terminal history is re-authenticated after the frozen process-start
/// pass. Exactly one terminal predecessor must bind the currently observed
/// five-slot workspace; zero or multiple live-current matches fail closed.
/// This path calls only the terminal loader and never the Step-8 maintenance
/// coordinator.
pub(crate) fn load_completed_v031_for_ordinary_startup(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_current: &ExactCurrentProfileGate,
) -> Result<V031StepEightReady, V031StartupTransitionError> {
    let selected_lineage_id = authenticate_completed_v031_terminal_lineage_for_current(
        app_local_data_dir,
        process_start,
        exact_current,
        || observe_exact_current_profile_read_only(app_local_data_dir),
    )?;
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    let privacy_workflow =
        PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            app_local_data_dir.to_path_buf(),
            exact_current.workspace_instance_id().clone(),
            Arc::new(approved_workspace.clone()),
        )
        .map_err(|_| V031StartupTransitionError::WorkflowManager)?;
    let complete_gate = load_completed_v031_gate_for_selected_lineage(
        app_local_data_dir,
        &privacy_workflow,
        &approved_workspace,
        &selected_lineage_id,
    )?;
    Ok(V031StepEightReady {
        approved_workspace,
        privacy_workflow,
        _complete_gate: complete_gate,
    })
}

fn load_completed_v031_with_existing_managers(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_current: &ExactCurrentProfileGate,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    let selected_lineage_id = authenticate_completed_v031_terminal_lineage_for_current(
        app_local_data_dir,
        process_start,
        exact_current,
        || {
            observe_exact_current_profile_with_approved_workspace_read_only(
                app_local_data_dir,
                approved_workspace,
            )
        },
    )?;
    load_completed_v031_gate_for_selected_lineage(
        app_local_data_dir,
        privacy_workflow,
        approved_workspace,
        &selected_lineage_id,
    )
}

/// Re-authenticates the unique completed lineage for an explicit R3 staging
/// request made by the already initialized current v0.4 application.
pub(crate) fn authenticate_completed_v031_for_recovery_stage(
    app_local_data_dir: &Path,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    let process_start = observe_v031_upgrade_at_process_start_read_only(app_local_data_dir)
        .map_err(|_| V031StartupTransitionError::Observation)?;
    let ExactCurrentProfileObservation::Exact(exact_current) =
        observe_exact_current_profile_with_approved_workspace_read_only(
            app_local_data_dir,
            approved_workspace,
        )
        .map_err(|_| V031StartupTransitionError::Observation)?
    else {
        return Err(V031StartupTransitionError::Observation);
    };
    load_completed_v031_with_existing_managers(
        app_local_data_dir,
        &process_start,
        &exact_current,
        privacy_workflow,
        approved_workspace,
    )
}

#[cfg(test)]
pub(crate) fn load_completed_v031_with_existing_managers_for_test(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_current: &ExactCurrentProfileGate,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    load_completed_v031_with_existing_managers(
        app_local_data_dir,
        process_start,
        exact_current,
        privacy_workflow,
        approved_workspace,
    )
}

/// Advances only the unique authenticated active lineage through receipt 8.
/// Every predecessor is rebuilt through the existing opaque gate API. The
/// function deliberately returns no manager: its caller must drop the
/// migration mutex and request a controlled restart with zero ordinary
/// initialization in this process.
pub(crate) fn advance_v031_upgrade_through_receipt_eight(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_source: Option<&ExactV031SourceProfileGate>,
) -> Result<(), V031StartupTransitionError> {
    let final_count = if let Some(final_count) = process_start.active_final_receipt_count() {
        final_count
    } else {
        let expected_source = exact_source.ok_or(V031StartupTransitionError::Observation)?;
        if process_start.active_lineage_id().is_some()
            || process_start.active_next_incoming_ordinal().is_some()
            || process_start
                .receipt_eight_observed_at_process_start()
                .is_some()
            || observe_exact_v031_source_profile_read_only(app_local_data_dir)
                .map_err(|_| V031StartupTransitionError::Observation)?
                != ExactV031SourceProfileObservation::Exact(expected_source.clone())
        {
            return Err(V031StartupTransitionError::Observation);
        }
        0
    };
    if final_count > 8
        || process_start
            .receipt_eight_observed_at_process_start()
            .is_some()
    {
        return Err(V031StartupTransitionError::Observation);
    }
    let final_count =
        u8::try_from(final_count).map_err(|_| V031StartupTransitionError::Observation)?;
    if process_start
        .active_next_incoming_ordinal()
        .is_some_and(|ordinal| ordinal != final_count)
    {
        return Err(V031StartupTransitionError::Observation);
    }

    let user_database_path = database::user_database_path(app_local_data_dir);
    let privacy_database_path = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    let rollback = if final_count < 2 {
        establish_original_migration_backup(
            app_local_data_dir,
            &user_database_path,
            &privacy_database_path,
        )
        .map_err(|_| V031StartupTransitionError::OriginalRollback)?
    } else {
        let lineage_id = process_start
            .active_lineage_id()
            .ok_or(V031StartupTransitionError::Observation)?;
        load_original_migration_backup_gate(app_local_data_dir, lineage_id)
            .map_err(|_| V031StartupTransitionError::OriginalRollback)?
    };

    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    let target = if final_count < 3 {
        prepare_v031_target_components(app_local_data_dir, &rollback)
            .map_err(|_| V031StartupTransitionError::TargetComponents)?
    } else if final_count == 3 {
        load_v031_target_components_prepared_gate_read_only(
            app_local_data_dir,
            &rollback,
            &approved_workspace,
        )
        .map_err(|_| V031StartupTransitionError::TargetComponents)?
    } else {
        load_v031_historical_target_components_from_checkpoint_read_only(
            app_local_data_dir,
            &rollback,
            &approved_workspace,
        )
        .map_err(|_| V031StartupTransitionError::TargetComponents)?
    };
    let privacy_workflow =
        PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            app_local_data_dir.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(approved_workspace.clone()),
        )
        .map_err(|_| V031StartupTransitionError::WorkflowManager)?;

    // A crash after the user-v11 transaction but before receipt 8 is handled
    // entirely inside this gate. Its historical predecessor loaders are the
    // only APIs allowed to cross that schema boundary.
    if final_count == 8 {
        ensure_v031_user_v11_verified(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            rollback.lineage_id(),
        )
        .map_err(|_| V031StartupTransitionError::UserV11)?;
        return Ok(());
    }

    let case_backups = if final_count < 4 {
        ensure_v031_case_migration_backups_verified_gate(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &target,
        )
        .map_err(|_| V031StartupTransitionError::CaseMigrationBackups)?
    } else {
        load_v031_case_migration_backups_verified_gate_read_only(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &target,
        )
        .map_err(|_| V031StartupTransitionError::CaseMigrationBackups)?
    };
    let privacy_v5 = if final_count < 5 {
        ensure_v031_privacy_v5_verified(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &case_backups,
        )
        .map_err(|_| V031StartupTransitionError::PrivacyV5)?
    } else {
        load_v031_privacy_v5_verified_gate_read_only(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &case_backups,
        )
        .map_err(|_| V031StartupTransitionError::PrivacyV5)?
    };
    let binding_materials = if final_count < 6 {
        ensure_v031_binding_materials_verified(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &privacy_v5,
        )
        .map_err(|_| V031StartupTransitionError::BindingMaterials)?
    } else {
        load_v031_binding_materials_verified_gate_read_only(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &privacy_v5,
        )
        .map_err(|_| V031StartupTransitionError::BindingMaterials)?
    };
    let projection_backup = if final_count < 7 {
        ensure_v031_projection_backup_verified_gate(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &binding_materials,
        )
        .map_err(|_| V031StartupTransitionError::ProjectionBackup)?
    } else {
        load_v031_projection_backup_verified_gate_read_only(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &target,
        )
        .map_err(|_| V031StartupTransitionError::ProjectionBackup)?
    };
    let _privacy_v6 = if final_count < 8 {
        ensure_v031_privacy_v6_verified(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &projection_backup,
        )
        .map_err(|_| V031StartupTransitionError::PrivacyV6)?
    } else {
        load_v031_privacy_v6_verified_gate_read_only(
            app_local_data_dir,
            &privacy_workflow,
            &approved_workspace,
            &projection_backup,
        )
        .map_err(|_| V031StartupTransitionError::PrivacyV6)?
    };
    ensure_v031_user_v11_verified(
        app_local_data_dir,
        &privacy_workflow,
        &approved_workspace,
        rollback.lineage_id(),
    )
    .map_err(|_| V031StartupTransitionError::UserV11)?;
    Ok(())
}

/// Executes Step 8 only with the non-forgeable receipt-8 capability captured
/// during the initial read-only process-start pass. Receipt 9 is committed
/// before these managers can be handed to ordinary startup.
fn run_step_eight_with_existing_managers(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    let observed_receipt_eight = process_start
        .receipt_eight_observed_at_process_start()
        .ok_or(V031StartupTransitionError::Observation)?;
    if process_start.active_final_receipt_count()
        != Some(usize::from(
            privacy::upgrade_receipt_v1::V031UpgradeReceiptStage::UpgradeComplete.ordinal(),
        ))
        || process_start.has_terminal_lineage_only()
    {
        return Err(V031StartupTransitionError::Observation);
    }
    ensure_v031_upgrade_complete(
        app_local_data_dir,
        privacy_workflow,
        approved_workspace,
        observed_receipt_eight,
    )
    .map_err(|_| V031StartupTransitionError::UpgradeComplete)
}

/// Uses the same Gate-8 authorization step as production while allowing the
/// Windows subprocess fixture to supply its isolated Credential-Manager-backed
/// workspace and Privacy signer.
#[cfg(test)]
pub(crate) fn run_step_eight_with_existing_managers_for_test(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    privacy_workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031UpgradeCompleteGate, V031StartupTransitionError> {
    run_step_eight_with_existing_managers(
        app_local_data_dir,
        process_start,
        privacy_workflow,
        approved_workspace,
    )
}

pub(crate) fn run_step_eight_and_install_receipt_nine(
    app_local_data_dir: &Path,
    process_start: &V031ProcessStartUpgradeObservation,
    exact_current: &ExactCurrentProfileGate,
) -> Result<V031StepEightReady, V031StartupTransitionError> {
    if process_start.active_final_receipt_count()
        != Some(usize::from(
            privacy::upgrade_receipt_v1::V031UpgradeReceiptStage::UpgradeComplete.ordinal(),
        ))
    {
        return Err(V031StartupTransitionError::Observation);
    }
    if observe_exact_current_profile_read_only(app_local_data_dir)
        .map_err(|_| V031StartupTransitionError::Observation)?
        != ExactCurrentProfileObservation::Exact(exact_current.clone())
    {
        return Err(V031StartupTransitionError::Observation);
    }
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    let privacy_workflow =
        PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            app_local_data_dir.to_path_buf(),
            exact_current.workspace_instance_id().clone(),
            Arc::new(approved_workspace.clone()),
        )
        .map_err(|_| V031StartupTransitionError::WorkflowManager)?;
    let complete_gate = run_step_eight_with_existing_managers(
        app_local_data_dir,
        process_start,
        &privacy_workflow,
        &approved_workspace,
    )?;
    Ok(V031StepEightReady {
        approved_workspace,
        privacy_workflow,
        _complete_gate: complete_gate,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupExecutionOutcome {
    ExplicitRecoveryAppliedAndExited,
    RestoreAppliedAndRestartRequested,
    EmptyLegacyBootstrapRepairedAndRestartRequested,
    ReceiptEightInstalledAndRestartRequested,
    Ready,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartupExecutionError<E> {
    Classification(StartupClassificationError),
    Action(E),
}

/// Narrow behavior seam used by the production router and call-count tests.
/// `observe_read_only` is unconditionally the first call. Receipt advancement
/// is one authenticated operation because the concrete transition consumes a
/// process-start observation only once; the implementation above still walks
/// every frozen predecessor gate in ordinal order before installing receipt 8.
pub(crate) trait StartupActions {
    type Error;

    fn observe_read_only(&mut self) -> Result<StartupObservation, Self::Error>;
    fn apply_explicit_recovery_and_exit(&mut self) -> Result<(), Self::Error>;
    fn apply_current_restore(&mut self, kind: CurrentRestoreKind) -> Result<(), Self::Error>;
    fn repair_empty_legacy_bootstrap(&mut self) -> Result<(), Self::Error>;
    fn advance_upgrade_through_receipt_eight(
        &mut self,
        next_ordinal: u8,
    ) -> Result<(), Self::Error>;
    fn run_step_eight_and_install_receipt_nine(&mut self) -> Result<(), Self::Error>;
    fn request_controlled_restart(&mut self) -> Result<(), Self::Error>;
    fn initialize_ordinary_application(&mut self, fresh: bool) -> Result<(), Self::Error>;
}

pub(crate) fn execute_startup<A: StartupActions>(
    actions: &mut A,
) -> Result<StartupExecutionOutcome, StartupExecutionError<A::Error>> {
    let observed = actions
        .observe_read_only()
        .map_err(StartupExecutionError::Action)?;
    let route = classify_startup(observed).map_err(StartupExecutionError::Classification)?;
    match route {
        StartupRoute::ApplyExplicitRecoveryAndExit => {
            actions
                .apply_explicit_recovery_and_exit()
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::ExplicitRecoveryAppliedAndExited)
        }
        StartupRoute::ApplyCurrentRestoreAndReclassify(kind) => {
            actions
                .apply_current_restore(kind)
                .map_err(StartupExecutionError::Action)?;
            actions
                .request_controlled_restart()
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::RestoreAppliedAndRestartRequested)
        }
        StartupRoute::RepairEmptyLegacyBootstrapAndRestart => {
            actions
                .repair_empty_legacy_bootstrap()
                .map_err(StartupExecutionError::Action)?;
            actions
                .request_controlled_restart()
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::EmptyLegacyBootstrapRepairedAndRestartRequested)
        }
        StartupRoute::AdvanceUpgradeThroughReceiptEight { next_ordinal } => {
            actions
                .advance_upgrade_through_receipt_eight(next_ordinal)
                .map_err(StartupExecutionError::Action)?;
            actions
                .request_controlled_restart()
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::ReceiptEightInstalledAndRestartRequested)
        }
        StartupRoute::RunStepEightAndInstallReceiptNine => {
            actions
                .run_step_eight_and_install_receipt_nine()
                .map_err(StartupExecutionError::Action)?;
            actions
                .initialize_ordinary_application(false)
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::Ready)
        }
        StartupRoute::InitializeCurrent => {
            actions
                .initialize_ordinary_application(false)
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::Ready)
        }
        StartupRoute::InitializeFresh => {
            actions
                .initialize_ordinary_application(true)
                .map_err(StartupExecutionError::Action)?;
            Ok(StartupExecutionOutcome::Ready)
        }
    }
}

/// Applies the frozen precedence without performing any I/O:
/// explicit recovery -> one pending current restore -> active v0.3.1 upgrade
/// -> exact v0.3.1 source -> receipt-9/current -> genuine fresh.
pub(crate) fn classify_startup(
    observed: StartupObservation,
) -> Result<StartupRoute, StartupClassificationError> {
    let restore_signals = [
        observed.restores.explicit_recovery,
        observed.restores.full_application,
        observed.restores.legacy_user_database,
        observed.restores.standalone_privacy,
    ];
    if observed.unknown_marker_or_sibling
        || restore_signals.contains(&AuthenticatedPresence::UnknownOrInvalid)
    {
        return Err(StartupClassificationError::UnknownOrUnauthenticated);
    }

    let explicit_recovery =
        observed.restores.explicit_recovery == AuthenticatedPresence::Authenticated;
    let current_restores = [
        (
            observed.restores.full_application,
            CurrentRestoreKind::FullApplication,
        ),
        (
            observed.restores.legacy_user_database,
            CurrentRestoreKind::LegacyUserDatabase,
        ),
        (
            observed.restores.standalone_privacy,
            CurrentRestoreKind::StandalonePrivacy,
        ),
    ]
    .into_iter()
    .filter_map(|(signal, kind)| (signal == AuthenticatedPresence::Authenticated).then_some(kind))
    .collect::<Vec<_>>();

    if usize::from(explicit_recovery) + current_restores.len() > 1 {
        return Err(StartupClassificationError::MixedRecoveryFlows);
    }
    if explicit_recovery {
        return Ok(StartupRoute::ApplyExplicitRecoveryAndExit);
    }
    if let Some(kind) = current_restores.first().copied() {
        return Ok(StartupRoute::ApplyCurrentRestoreAndReclassify(kind));
    }

    if let Some(active) = observed.upgrade.active {
        if active.final_receipt_count > RECEIPT_EIGHT_FINAL_COUNT
            || active
                .next_incoming_ordinal
                .is_some_and(|ordinal| ordinal != active.final_receipt_count)
            || (active.receipt_eight_observed_at_process_start
                != (active.final_receipt_count == RECEIPT_EIGHT_FINAL_COUNT))
        {
            return Err(StartupClassificationError::InvalidReceiptPrefix);
        }
        if !active_receipt_prefix_matches_profile(active.final_receipt_count, observed.profile) {
            return Err(StartupClassificationError::ProfileDoesNotMatchReceipts);
        }
        if active.final_receipt_count == RECEIPT_EIGHT_FINAL_COUNT {
            return Ok(StartupRoute::RunStepEightAndInstallReceiptNine);
        }
        return Ok(StartupRoute::AdvanceUpgradeThroughReceiptEight {
            next_ordinal: active.final_receipt_count,
        });
    }

    match observed.profile {
        InstalledProfile::EmptyLegacyBootstrap if observed.upgrade.terminal_lineage_count == 0 => {
            Ok(StartupRoute::RepairEmptyLegacyBootstrapAndRestart)
        }
        InstalledProfile::EmptyLegacyBootstrap => {
            Err(StartupClassificationError::ProfileDoesNotMatchReceipts)
        }
        InstalledProfile::ExactV031Source => {
            Ok(StartupRoute::AdvanceUpgradeThroughReceiptEight { next_ordinal: 0 })
        }
        InstalledProfile::ExactCurrent => Ok(StartupRoute::InitializeCurrent),
        InstalledProfile::AuthenticatedUpgradeState => {
            Err(StartupClassificationError::ProfileDoesNotMatchReceipts)
        }
        InstalledProfile::GenuineFresh if observed.upgrade.terminal_lineage_count == 0 => {
            Ok(StartupRoute::InitializeFresh)
        }
        InstalledProfile::GenuineFresh => {
            Err(StartupClassificationError::ProfileDoesNotMatchReceipts)
        }
        InstalledProfile::PartialOrUnknown => Err(StartupClassificationError::PartialProfile),
    }
}

/// Frozen schema/profile matrix for the active receipt prefix. The two
/// boundary counts accept both sides of the corresponding atomic component
/// transition so an authenticated incoming receipt can resume after a crash;
/// no other cross-stage profile is writable.
fn active_receipt_prefix_matches_profile(
    final_receipt_count: u8,
    profile: InstalledProfile,
) -> bool {
    match final_receipt_count {
        0..=1 => profile == InstalledProfile::ExactV031Source,
        2 => matches!(
            profile,
            InstalledProfile::ExactV031Source | InstalledProfile::AuthenticatedUpgradeState
        ),
        3..=7 => profile == InstalledProfile::AuthenticatedUpgradeState,
        8 => matches!(
            profile,
            InstalledProfile::AuthenticatedUpgradeState | InstalledProfile::ExactCurrent
        ),
        9 => profile == InstalledProfile::ExactCurrent,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::{collections::BTreeMap, time::SystemTime};

    #[cfg(windows)]
    type ExactWindowsTreeObservation = BTreeMap<String, (u32, u64, SystemTime, Option<Vec<u8>>)>;

    #[cfg(windows)]
    fn exact_windows_tree_observation(root: &Path) -> ExactWindowsTreeObservation {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;

        fn visit(root: &Path, directory: &Path, entries: &mut ExactWindowsTreeObservation) {
            use std::os::windows::fs::MetadataExt as _;

            let mut children = fs::read_dir(directory)
                .expect("Windows fixture tree enumerates")
                .collect::<Result<Vec<_>, _>>()
                .expect("Windows fixture entries enumerate");
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let path = child.path();
                let metadata = fs::symlink_metadata(&path).expect("Windows fixture metadata reads");
                let attributes = metadata.file_attributes();
                let is_reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0;
                let relative = path
                    .strip_prefix(root)
                    .expect("Windows fixture entry remains below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = if metadata.is_file() && !is_reparse {
                    Some(fs::read(&path).expect("Windows fixture file bytes read"))
                } else {
                    None
                };
                assert!(
                    entries
                        .insert(
                            relative,
                            (
                                attributes,
                                metadata.len(),
                                metadata
                                    .modified()
                                    .expect("Windows fixture modified time reads"),
                                bytes,
                            ),
                        )
                        .is_none(),
                    "Windows fixture paths are unique"
                );
                if metadata.is_dir() && !is_reparse {
                    visit(root, &path, entries);
                }
            }
        }

        let metadata = fs::symlink_metadata(root).expect("Windows fixture root metadata reads");
        let mut entries = BTreeMap::from([(
            ".".to_owned(),
            (
                metadata.file_attributes(),
                metadata.len(),
                metadata
                    .modified()
                    .expect("Windows fixture root modified time reads"),
                None,
            ),
        )]);
        if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE == 0
        {
            visit(root, root, &mut entries);
        }
        entries
    }

    #[cfg(windows)]
    fn create_directory_junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .arg("/D")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .expect("junction command starts without elevation");
        assert!(
            output.status.success(),
            "junction fixture creation failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        use std::os::windows::fs::MetadataExt as _;
        assert_ne!(
            fs::symlink_metadata(link)
                .expect("junction metadata reads")
                .file_attributes()
                & 0x0000_0400,
            0,
            "fixture must be a real Windows reparse point"
        );
    }

    #[cfg(windows)]
    fn assert_production_reparse_rejected_without_writes(root: &Path, target_root: &Path) {
        let root_before = exact_windows_tree_observation(root);
        let target_before = exact_windows_tree_observation(target_root);
        let probe = FreshCredentialProbe::default();
        assert!(matches!(
            observe_production_startup_with_credentials_read_only(root, &probe, false),
            Err(ProductionStartupObservationError::UpgradeHistory)
        ));
        assert!(
            probe.calls.lock().unwrap().is_empty(),
            "process-start lineage rejection precedes profile Credential probes"
        );
        assert_eq!(exact_windows_tree_observation(root), root_before);
        assert_eq!(exact_windows_tree_observation(target_root), target_before);
    }

    #[derive(serde::Deserialize)]
    struct FrozenV031UserSchemaObject {
        object_type: String,
        sql: String,
    }

    fn create_exact_v031_source_fixture(root: &Path) {
        let user_database_path = database::user_database_path(root);
        let connection = rusqlite::Connection::open(&user_database_path).unwrap();
        let objects =
            include_str!("../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| serde_json::from_str::<FrozenV031UserSchemaObject>(line).unwrap())
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object.object_type == object_type)
            {
                connection.execute_batch(&object.sql).unwrap();
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_SCHEMA_VERSION.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .unwrap();
        drop(connection);

        let privacy_root = root.join("privacy");
        fs::create_dir(&privacy_root).unwrap();
        let privacy_database_path = privacy_root.join("privacy-workflow.sqlite");
        let connection = rusqlite::Connection::open(privacy_database_path).unwrap();
        connection
            .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .unwrap();
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                 VALUES('schema_version','1','2026-07-19 15:41:29')",
                [],
            )
            .unwrap();
    }

    #[test]
    fn exact_current_matrix_accepts_only_the_six_frozen_lazy_lifecycles() {
        for approved_lifecycle in [
            CurrentApprovedComponentsLifecycle::IdentityOnly,
            CurrentApprovedComponentsLifecycle::ApprovedOnly,
            CurrentApprovedComponentsLifecycle::ApprovedAndWorkProducts,
        ] {
            for vault in [
                CurrentOptionalSlotShape::Absent,
                CurrentOptionalSlotShape::Exact,
            ] {
                assert!(is_exact_current_five_slot_shape(CurrentFiveSlotShape {
                    user_exact_v11: true,
                    privacy_exact_v6: true,
                    approved_lifecycle: Some(approved_lifecycle),
                    vault,
                    approved_workspace_matches: true,
                    vault_workspace_matches: true,
                }));
            }
        }
    }

    #[test]
    fn exact_current_matrix_rejects_missing_required_slots_and_workspace_mismatch() {
        let exact = CurrentFiveSlotShape {
            user_exact_v11: true,
            privacy_exact_v6: true,
            approved_lifecycle: Some(CurrentApprovedComponentsLifecycle::IdentityOnly),
            vault: CurrentOptionalSlotShape::Absent,
            approved_workspace_matches: true,
            vault_workspace_matches: true,
        };
        for invalid in [
            CurrentFiveSlotShape {
                user_exact_v11: false,
                ..exact
            },
            CurrentFiveSlotShape {
                privacy_exact_v6: false,
                ..exact
            },
            CurrentFiveSlotShape {
                approved_lifecycle: None,
                ..exact
            },
            CurrentFiveSlotShape {
                approved_workspace_matches: false,
                ..exact
            },
            CurrentFiveSlotShape {
                vault: CurrentOptionalSlotShape::Exact,
                vault_workspace_matches: false,
                ..exact
            },
        ] {
            assert!(!is_exact_current_five_slot_shape(invalid));
        }
        assert!(is_exact_current_five_slot_shape(CurrentFiveSlotShape {
            vault: CurrentOptionalSlotShape::Absent,
            // A nonexistent Vault has no workspace identity to compare.
            vault_workspace_matches: false,
            ..exact
        }));
    }

    #[test]
    fn exact_current_observer_treats_absence_as_not_current_without_creating_state() {
        let directory = tempfile::tempdir().unwrap();
        let entries_before = fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(
            observe_exact_current_profile_read_only(directory.path()).unwrap(),
            ExactCurrentProfileObservation::NotCurrent
        );
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            entries_before
        );
    }

    #[derive(Default)]
    struct FreshCredentialProbe {
        present: Option<crate::v031_upgrade_r2::ApprovedMcpCredentialRole>,
        calls: std::sync::Mutex<Vec<crate::v031_upgrade_r2::ApprovedMcpCredentialRole>>,
    }

    impl crate::v031_upgrade_r2::CredentialPresenceProbe for FreshCredentialProbe {
        type Error = ();

        fn credential_exists_read_only(
            &self,
            query: crate::v031_upgrade_r2::CredentialAbsenceQuery,
        ) -> Result<bool, Self::Error> {
            self.calls.lock().unwrap().push(query.role);
            Ok(self.present == Some(query.role))
        }
    }

    #[test]
    fn genuine_fresh_observer_proves_all_twenty_six_absences_without_creating_root() {
        let directory = tempfile::tempdir().unwrap();
        let missing_root = directory.path().join("never-created-app-root");
        let probe = FreshCredentialProbe::default();
        let observed =
            observe_genuine_fresh_profile_with_credentials_read_only(&missing_root, &probe)
                .unwrap();
        let GenuineFreshProfileObservation::Exact(gate) = observed else {
            panic!("missing root must be genuinely fresh")
        };
        assert!(gate.app_root_was_absent);
        assert_eq!(gate.filesystem_absence_checks, 22);
        assert_eq!(gate.credential_absence_checks, 4);
        assert_eq!(probe.calls.lock().unwrap().len(), 4);
        assert!(!missing_root.exists());
    }

    #[test]
    fn production_observer_routes_a_missing_root_from_one_read_only_pass() {
        let directory = tempfile::tempdir().unwrap();
        let missing_root = directory.path().join("never-created-production-root");
        let probe = FreshCredentialProbe::default();
        let observed =
            observe_production_startup_with_credentials_read_only(&missing_root, &probe, false)
                .expect("missing root production observation");

        assert_eq!(observed.summary().profile, InstalledProfile::GenuineFresh);
        assert_eq!(
            classify_startup(observed.summary()),
            Ok(StartupRoute::InitializeFresh)
        );
        assert_eq!(observed.summary().upgrade.terminal_lineage_count, 0);
        assert!(observed.summary().upgrade.active.is_none());
        assert!(observed.genuine_fresh_gate().is_some());
        assert_eq!(probe.calls.lock().unwrap().len(), 4);
        assert!(!missing_root.exists());
    }

    #[test]
    fn no_lineage_exact_v031_source_routes_to_the_real_bootstrap_ordinal() {
        let directory = tempfile::tempdir().unwrap();
        create_exact_v031_source_fixture(directory.path());
        let probe = FreshCredentialProbe::default();
        let observed =
            observe_production_startup_with_credentials_read_only(directory.path(), &probe, false)
                .expect("exact v0.3.1 production observation");

        assert_eq!(
            observed.summary().profile,
            InstalledProfile::ExactV031Source
        );
        assert!(observed.summary().upgrade.active.is_none());
        assert_eq!(observed.summary().upgrade.terminal_lineage_count, 0);
        assert!(observed.exact_v031_source_gate().is_some());
        assert_eq!(
            classify_startup(observed.summary()),
            Ok(StartupRoute::AdvanceUpgradeThroughReceiptEight { next_ordinal: 0 })
        );
    }

    #[test]
    fn production_observer_rejects_a_junction_root_before_any_profile_probe() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("junction-target");
        let junction = directory.path().join("junction-app-root");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"unchanged").unwrap();
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                junction.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .status()
            .expect("junction command starts");
        assert!(status.success(), "junction fixture creation failed");

        let probe = FreshCredentialProbe::default();
        assert!(matches!(
            observe_production_startup_with_credentials_read_only(&junction, &probe, false),
            Err(ProductionStartupObservationError::Root)
        ));
        assert!(probe.calls.lock().unwrap().is_empty());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"unchanged");
        fs::remove_dir(&junction).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn production_process_start_rejects_migration_root_junction_without_writes() {
        let directory = tempfile::tempdir().expect("migration-root reparse fixture");
        let app_root = directory.path().join("ordinary-app-root");
        let target = directory.path().join("migration-root-junction-target");
        fs::create_dir(&app_root).expect("ordinary app root creates");
        fs::create_dir(&target).expect("migration-root junction target creates");
        fs::write(
            target.join("sentinel.bin"),
            b"migration-root-target-unchanged",
        )
        .expect("migration-root target sentinel creates");
        let junction = app_root.join(crate::v031_upgrade_r2::MIGRATION_BACKUPS_DIRECTORY);
        create_directory_junction(&junction, &target);

        assert_production_reparse_rejected_without_writes(&app_root, &target);
        fs::remove_dir(&junction).expect("migration-root junction removes without following");
    }

    #[cfg(windows)]
    #[test]
    fn production_process_start_rejects_lineage_directory_junction_without_writes() {
        let directory = tempfile::tempdir().expect("lineage reparse fixture");
        let app_root = directory.path().join("ordinary-app-root");
        let migration_root = app_root.join(crate::v031_upgrade_r2::MIGRATION_BACKUPS_DIRECTORY);
        let target = directory.path().join("lineage-junction-target");
        fs::create_dir(&app_root).expect("ordinary app root creates");
        fs::create_dir(&migration_root).expect("ordinary migration root creates");
        fs::create_dir(&target).expect("lineage junction target creates");
        fs::write(target.join("sentinel.bin"), b"lineage-target-unchanged")
            .expect("lineage target sentinel creates");
        let junction = migration_root.join("a".repeat(64));
        create_directory_junction(&junction, &target);

        assert_production_reparse_rejected_without_writes(&app_root, &target);
        fs::remove_dir(&junction).expect("lineage junction removes without following");
    }

    #[cfg(windows)]
    #[test]
    fn production_process_start_rejects_evidence_reparse_without_writes() {
        enum EvidenceReparseFixture {
            FileSymbolicLink,
            DirectoryJunction,
        }

        let directory = tempfile::tempdir().expect("evidence reparse fixture");
        let app_root = directory.path().join("ordinary-app-root");
        let migration_root = app_root.join(crate::v031_upgrade_r2::MIGRATION_BACKUPS_DIRECTORY);
        let lineage = migration_root.join("b".repeat(64));
        let target_root = directory.path().join("evidence-reparse-target");
        fs::create_dir(&app_root).expect("ordinary app root creates");
        fs::create_dir(&migration_root).expect("ordinary migration root creates");
        fs::create_dir(&lineage).expect("ordinary lineage creates");
        fs::create_dir(&target_root).expect("evidence target root creates");
        let evidence = lineage.join(crate::v031_upgrade_r2::V2_BUNDLE_INCOMING);
        let target_file = target_root.join("target.bundle");
        fs::write(&target_file, b"evidence-target-unchanged")
            .expect("evidence target file creates");

        let fixture = match std::os::windows::fs::symlink_file(&target_file, &evidence) {
            Ok(()) => EvidenceReparseFixture::FileSymbolicLink,
            Err(error) => {
                eprintln!(
                    "R2 Windows platform limitation: an unprivileged file symbolic-link reparse fixture is unavailable ({error}); exercising the same evidence basename as a real directory junction instead"
                );
                let target_directory = target_root.join("target-directory");
                fs::create_dir(&target_directory)
                    .expect("evidence junction fallback target creates");
                fs::write(
                    target_directory.join("sentinel.bin"),
                    b"junction-target-unchanged",
                )
                .expect("evidence junction fallback sentinel creates");
                create_directory_junction(&evidence, &target_directory);
                EvidenceReparseFixture::DirectoryJunction
            }
        };

        assert_production_reparse_rejected_without_writes(&app_root, &target_root);
        match fixture {
            EvidenceReparseFixture::FileSymbolicLink => {
                fs::remove_file(&evidence).expect("evidence file symbolic link removes")
            }
            EvidenceReparseFixture::DirectoryJunction => {
                fs::remove_dir(&evidence).expect("evidence junction removes without following")
            }
        }
    }

    #[test]
    fn genuine_fresh_existing_empty_root_is_read_only_and_credential_bound() {
        let directory = tempfile::tempdir().unwrap();
        let probe = FreshCredentialProbe::default();
        let entries_before = fs::read_dir(directory.path()).unwrap().count();
        let observed =
            observe_genuine_fresh_profile_with_credentials_read_only(directory.path(), &probe)
                .unwrap();
        let GenuineFreshProfileObservation::Exact(gate) = observed else {
            panic!("empty root must be genuinely fresh")
        };
        assert!(!gate.app_root_was_absent);
        assert_eq!(gate.filesystem_absence_checks, 22);
        assert_eq!(gate.credential_absence_checks, 4);
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            entries_before
        );
    }

    #[test]
    fn genuine_fresh_rejects_a_target_credential_and_installed_slot() {
        let directory = tempfile::tempdir().unwrap();
        let credential_probe = FreshCredentialProbe {
            present: Some(crate::v031_upgrade_r2::ApprovedMcpCredentialRole::ApprovedManifest),
            ..FreshCredentialProbe::default()
        };
        assert_eq!(
            observe_genuine_fresh_profile_with_credentials_read_only(
                directory.path(),
                &credential_probe,
            ),
            Err(GenuineFreshProfileError::Namespace)
        );

        fs::write(
            database::user_database_path(directory.path()),
            b"installed-slot",
        )
        .unwrap();
        assert_eq!(
            observe_genuine_fresh_profile_with_credentials_read_only(
                directory.path(),
                &FreshCredentialProbe::default(),
            )
            .unwrap(),
            GenuineFreshProfileObservation::NotFresh
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockError {
        UnexpectedPreclassificationSideEffect,
    }

    struct CountingActions {
        observed: StartupObservation,
        events: Vec<String>,
        writes: usize,
        credential_calls: usize,
        ordinary_manager_initializations: usize,
    }

    impl CountingActions {
        fn new(observed: StartupObservation) -> Self {
            Self {
                observed,
                events: Vec::new(),
                writes: 0,
                credential_calls: 0,
                ordinary_manager_initializations: 0,
            }
        }
    }

    impl StartupActions for CountingActions {
        type Error = MockError;

        fn observe_read_only(&mut self) -> Result<StartupObservation, Self::Error> {
            if self.writes != 0
                || self.credential_calls != 0
                || self.ordinary_manager_initializations != 0
                || !self.events.is_empty()
            {
                return Err(MockError::UnexpectedPreclassificationSideEffect);
            }
            self.events.push("classify".to_owned());
            Ok(self.observed)
        }

        fn apply_explicit_recovery_and_exit(&mut self) -> Result<(), Self::Error> {
            self.writes += 1;
            self.events.push("explicit-recovery".to_owned());
            Ok(())
        }

        fn apply_current_restore(&mut self, kind: CurrentRestoreKind) -> Result<(), Self::Error> {
            self.writes += 1;
            self.events.push(format!("restore-{kind:?}"));
            Ok(())
        }

        fn repair_empty_legacy_bootstrap(&mut self) -> Result<(), Self::Error> {
            self.writes += 1;
            self.credential_calls += 1;
            self.events.push("empty-legacy-bootstrap".to_owned());
            Ok(())
        }

        fn advance_upgrade_through_receipt_eight(
            &mut self,
            next_ordinal: u8,
        ) -> Result<(), Self::Error> {
            self.writes += usize::from(9 - next_ordinal);
            if next_ordinal <= 2 {
                self.credential_calls += 1;
            }
            self.events
                .push(format!("receipts-{next_ordinal}-through-8"));
            Ok(())
        }

        fn run_step_eight_and_install_receipt_nine(&mut self) -> Result<(), Self::Error> {
            self.writes += 1;
            self.events.push("step-8-receipt-9".to_owned());
            Ok(())
        }

        fn request_controlled_restart(&mut self) -> Result<(), Self::Error> {
            self.events.push("controlled-restart".to_owned());
            Ok(())
        }

        fn initialize_ordinary_application(&mut self, fresh: bool) -> Result<(), Self::Error> {
            self.ordinary_manager_initializations += 1;
            self.events.push(if fresh {
                "initialize-fresh".to_owned()
            } else {
                "initialize-current".to_owned()
            });
            Ok(())
        }
    }

    fn absent_restores() -> RestoreObservation {
        RestoreObservation {
            explicit_recovery: AuthenticatedPresence::Absent,
            full_application: AuthenticatedPresence::Absent,
            legacy_user_database: AuthenticatedPresence::Absent,
            standalone_privacy: AuthenticatedPresence::Absent,
        }
    }

    fn observation(profile: InstalledProfile) -> StartupObservation {
        StartupObservation {
            restores: absent_restores(),
            upgrade: UpgradeObservation {
                terminal_lineage_count: 0,
                active: None,
            },
            profile,
            unknown_marker_or_sibling: false,
        }
    }

    #[test]
    fn strict_precedence_selects_only_one_authenticated_recovery() {
        let mut explicit = observation(InstalledProfile::ExactCurrent);
        explicit.restores.explicit_recovery = AuthenticatedPresence::Authenticated;
        assert_eq!(
            classify_startup(explicit),
            Ok(StartupRoute::ApplyExplicitRecoveryAndExit)
        );

        let mut restore = observation(InstalledProfile::ExactCurrent);
        restore.restores.standalone_privacy = AuthenticatedPresence::Authenticated;
        assert_eq!(
            classify_startup(restore),
            Ok(StartupRoute::ApplyCurrentRestoreAndReclassify(
                CurrentRestoreKind::StandalonePrivacy
            ))
        );

        restore.restores.full_application = AuthenticatedPresence::Authenticated;
        assert_eq!(
            classify_startup(restore),
            Err(StartupClassificationError::MixedRecoveryFlows)
        );

        let mut interrupted = observation(InstalledProfile::EmptyLegacyBootstrap);
        interrupted.restores.standalone_privacy = AuthenticatedPresence::Authenticated;
        assert_eq!(
            classify_startup(interrupted),
            Ok(StartupRoute::ApplyCurrentRestoreAndReclassify(
                CurrentRestoreKind::StandalonePrivacy
            ))
        );
    }

    #[test]
    fn receipt_eight_requires_the_process_start_capability() {
        let mut observed = observation(InstalledProfile::ExactCurrent);
        observed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 9,
            next_incoming_ordinal: None,
            receipt_eight_observed_at_process_start: false,
        });
        assert_eq!(
            classify_startup(observed),
            Err(StartupClassificationError::InvalidReceiptPrefix)
        );

        observed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 9,
            next_incoming_ordinal: Some(9),
            receipt_eight_observed_at_process_start: true,
        });
        assert_eq!(
            classify_startup(observed),
            Ok(StartupRoute::RunStepEightAndInstallReceiptNine)
        );
    }

    #[test]
    fn terminal_live_current_selection_requires_exactly_one_workspace_match() {
        let current = format!("ws_{}", "a".repeat(32));
        let historical = format!("ws_{}", "b".repeat(32));
        let first_lineage = "1".repeat(64);
        let second_lineage = "2".repeat(64);

        assert_eq!(
            select_unique_live_current_terminal_lineage(
                &[(first_lineage.clone(), historical.clone())],
                &current,
            ),
            Err(V031StartupTransitionError::Observation)
        );
        assert_eq!(
            select_unique_live_current_terminal_lineage(
                &[
                    (first_lineage.clone(), current.clone()),
                    (second_lineage, current.clone()),
                ],
                &current,
            ),
            Err(V031StartupTransitionError::Observation)
        );
        assert_eq!(
            select_unique_live_current_terminal_lineage(
                &[
                    (first_lineage.clone(), current.clone()),
                    ("3".repeat(64), historical),
                ],
                &current,
            ),
            Ok(first_lineage.as_str())
        );
    }

    #[test]
    fn exact_source_starts_or_resumes_the_unique_receipt_prefix() {
        let exact = observation(InstalledProfile::ExactV031Source);
        assert_eq!(
            classify_startup(exact),
            Ok(StartupRoute::AdvanceUpgradeThroughReceiptEight { next_ordinal: 0 })
        );

        let mut resumed = observation(InstalledProfile::AuthenticatedUpgradeState);
        resumed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 4,
            next_incoming_ordinal: Some(4),
            receipt_eight_observed_at_process_start: false,
        });
        assert_eq!(
            classify_startup(resumed),
            Ok(StartupRoute::AdvanceUpgradeThroughReceiptEight { next_ordinal: 4 })
        );
    }

    #[test]
    fn every_active_receipt_count_rejects_profiles_outside_the_frozen_crash_matrix() {
        let profiles = [
            InstalledProfile::GenuineFresh,
            InstalledProfile::EmptyLegacyBootstrap,
            InstalledProfile::ExactV031Source,
            InstalledProfile::ExactCurrent,
            InstalledProfile::AuthenticatedUpgradeState,
            InstalledProfile::PartialOrUnknown,
        ];
        for final_receipt_count in 0..=9 {
            for profile in profiles {
                let expected_match = match final_receipt_count {
                    0..=1 => profile == InstalledProfile::ExactV031Source,
                    2 => matches!(
                        profile,
                        InstalledProfile::ExactV031Source
                            | InstalledProfile::AuthenticatedUpgradeState
                    ),
                    3..=7 => profile == InstalledProfile::AuthenticatedUpgradeState,
                    8 => matches!(
                        profile,
                        InstalledProfile::AuthenticatedUpgradeState
                            | InstalledProfile::ExactCurrent
                    ),
                    9 => profile == InstalledProfile::ExactCurrent,
                    _ => unreachable!(),
                };
                assert_eq!(
                    active_receipt_prefix_matches_profile(final_receipt_count, profile),
                    expected_match,
                    "count={final_receipt_count}, profile={profile:?}"
                );

                let mut observed = observation(profile);
                observed.upgrade.active = Some(ActiveUpgradeObservation {
                    final_receipt_count,
                    next_incoming_ordinal: None,
                    receipt_eight_observed_at_process_start: final_receipt_count == 9,
                });
                let classified = classify_startup(observed);
                if expected_match {
                    assert!(classified.is_ok(), "{final_receipt_count}/{profile:?}");
                } else {
                    assert_eq!(
                        classified,
                        Err(StartupClassificationError::ProfileDoesNotMatchReceipts),
                        "count={final_receipt_count}, profile={profile:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn genuine_fresh_is_distinct_from_every_partial_or_residual_state() {
        assert_eq!(
            classify_startup(observation(InstalledProfile::GenuineFresh)),
            Ok(StartupRoute::InitializeFresh)
        );
        assert_eq!(
            classify_startup(observation(InstalledProfile::PartialOrUnknown)),
            Err(StartupClassificationError::PartialProfile)
        );

        let mut residue = observation(InstalledProfile::GenuineFresh);
        residue.upgrade.terminal_lineage_count = 1;
        assert_eq!(
            classify_startup(residue),
            Err(StartupClassificationError::ProfileDoesNotMatchReceipts)
        );

        assert_eq!(
            classify_startup(observation(InstalledProfile::EmptyLegacyBootstrap)),
            Ok(StartupRoute::RepairEmptyLegacyBootstrapAndRestart)
        );
        let mut legacy_with_terminal = observation(InstalledProfile::EmptyLegacyBootstrap);
        legacy_with_terminal.upgrade.terminal_lineage_count = 1;
        assert_eq!(
            classify_startup(legacy_with_terminal),
            Err(StartupClassificationError::ProfileDoesNotMatchReceipts)
        );
    }

    #[test]
    fn unknown_marker_and_malformed_incoming_fail_closed() {
        let mut unknown = observation(InstalledProfile::ExactCurrent);
        unknown.unknown_marker_or_sibling = true;
        assert_eq!(
            classify_startup(unknown),
            Err(StartupClassificationError::UnknownOrUnauthenticated)
        );

        let mut malformed = observation(InstalledProfile::ExactCurrent);
        malformed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 6,
            next_incoming_ordinal: Some(7),
            receipt_eight_observed_at_process_start: false,
        });
        assert_eq!(
            classify_startup(malformed),
            Err(StartupClassificationError::InvalidReceiptPrefix)
        );
    }

    #[test]
    fn production_observer_authenticates_r3_before_every_ordinary_observer() {
        let source = include_str!("v031_startup.rs");
        let observer = source
            .split("fn observe_production_startup_with_credentials_read_only")
            .nth(1)
            .and_then(|value| value.split("fn upgrade_summary").next())
            .expect("production startup observer source");
        let r3 = observer
            .find("observe_v031_migration_recovery_read_only")
            .expect("authenticated R3 observer");
        let exclusive_return = observer
            .find("if explicit_recovery.is_some()")
            .expect("exclusive recovery return");
        let upgrade = observer
            .find("observe_v031_upgrade_at_process_start_read_only")
            .expect("ordinary upgrade observer");
        let full_restore = observer
            .find("observe_pending_application_restore_read_only")
            .expect("ordinary full restore observer");
        let legacy_restore = observer
            .find("observe_pending_database_restore_read_only")
            .expect("ordinary legacy restore observer");
        let privacy_restore = observer
            .find("observe_pending_privacy_restore_read_only")
            .expect("ordinary Privacy restore observer");
        assert!(
            r3 < exclusive_return
                && exclusive_return < upgrade
                && upgrade < full_restore
                && full_restore < legacy_restore
                && legacy_restore < privacy_restore
        );
        let recovery_only = &observer[exclusive_return..upgrade];
        for retained_absence in [
            "full_application_restore: None",
            "legacy_user_database_restore: None",
            "standalone_privacy_restore: None",
            "process_start_upgrade: None",
        ] {
            assert!(recovery_only.contains(retained_absence));
        }
    }

    #[test]
    fn classification_is_the_first_call_before_write_credential_or_manager_paths() {
        let mut actions = CountingActions::new(observation(InstalledProfile::ExactV031Source));
        let outcome = execute_startup(&mut actions).expect("exact upgrade executes");

        assert_eq!(
            outcome,
            StartupExecutionOutcome::ReceiptEightInstalledAndRestartRequested
        );
        assert_eq!(actions.events.first().map(String::as_str), Some("classify"));
        assert_eq!(
            actions.events,
            ["classify", "receipts-0-through-8", "controlled-restart"]
        );
        assert_eq!(actions.writes, 9);

        let mut repair = CountingActions::new(observation(InstalledProfile::EmptyLegacyBootstrap));
        assert_eq!(
            execute_startup(&mut repair),
            Ok(StartupExecutionOutcome::EmptyLegacyBootstrapRepairedAndRestartRequested)
        );
        assert_eq!(
            repair.events,
            ["classify", "empty-legacy-bootstrap", "controlled-restart"]
        );
        assert_eq!(repair.writes, 1);
        assert_eq!(repair.credential_calls, 1);
        assert_eq!(repair.ordinary_manager_initializations, 0);
    }

    #[test]
    fn recovery_and_every_current_restore_route_initialize_zero_ordinary_managers() {
        let mut explicit_observation = observation(InstalledProfile::ExactCurrent);
        explicit_observation.restores.explicit_recovery = AuthenticatedPresence::Authenticated;
        let mut explicit = CountingActions::new(explicit_observation);
        assert_eq!(
            execute_startup(&mut explicit),
            Ok(StartupExecutionOutcome::ExplicitRecoveryAppliedAndExited)
        );
        assert_eq!(explicit.events, ["classify", "explicit-recovery"]);
        assert_eq!(explicit.ordinary_manager_initializations, 0);

        for (signal, expected) in [
            (
                CurrentRestoreKind::FullApplication,
                "restore-FullApplication",
            ),
            (
                CurrentRestoreKind::LegacyUserDatabase,
                "restore-LegacyUserDatabase",
            ),
            (
                CurrentRestoreKind::StandalonePrivacy,
                "restore-StandalonePrivacy",
            ),
        ] {
            let mut restore_observation = observation(InstalledProfile::PartialOrUnknown);
            match signal {
                CurrentRestoreKind::FullApplication => {
                    restore_observation.restores.full_application =
                        AuthenticatedPresence::Authenticated;
                }
                CurrentRestoreKind::LegacyUserDatabase => {
                    restore_observation.restores.legacy_user_database =
                        AuthenticatedPresence::Authenticated;
                }
                CurrentRestoreKind::StandalonePrivacy => {
                    restore_observation.restores.standalone_privacy =
                        AuthenticatedPresence::Authenticated;
                }
            }
            let mut restore = CountingActions::new(restore_observation);
            assert_eq!(
                execute_startup(&mut restore),
                Ok(StartupExecutionOutcome::RestoreAppliedAndRestartRequested)
            );
            assert_eq!(restore.events, ["classify", expected, "controlled-restart"]);
            assert_eq!(restore.ordinary_manager_initializations, 0);
        }
    }

    #[test]
    fn newly_installed_receipt_eight_restarts_with_zero_ordinary_initialization() {
        let mut observed = observation(InstalledProfile::ExactCurrent);
        observed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 8,
            next_incoming_ordinal: None,
            receipt_eight_observed_at_process_start: false,
        });
        let mut actions = CountingActions::new(observed);

        assert_eq!(
            execute_startup(&mut actions),
            Ok(StartupExecutionOutcome::ReceiptEightInstalledAndRestartRequested)
        );
        assert_eq!(actions.ordinary_manager_initializations, 0);
        assert_eq!(
            actions.events,
            ["classify", "receipts-8-through-8", "controlled-restart"]
        );
        assert_eq!(actions.writes, 1);
    }

    #[test]
    fn only_process_start_receipt_eight_runs_step_eight_then_initializes_current() {
        let mut observed = observation(InstalledProfile::ExactCurrent);
        observed.upgrade.active = Some(ActiveUpgradeObservation {
            final_receipt_count: 9,
            next_incoming_ordinal: None,
            receipt_eight_observed_at_process_start: true,
        });
        let mut actions = CountingActions::new(observed);

        assert_eq!(
            execute_startup(&mut actions),
            Ok(StartupExecutionOutcome::Ready)
        );
        assert_eq!(actions.ordinary_manager_initializations, 1);
        assert_eq!(
            actions.events,
            ["classify", "step-8-receipt-9", "initialize-current"]
        );
    }

    #[test]
    fn fresh_initializes_once_but_partial_state_performs_no_actions() {
        let mut fresh = CountingActions::new(observation(InstalledProfile::GenuineFresh));
        assert_eq!(
            execute_startup(&mut fresh),
            Ok(StartupExecutionOutcome::Ready)
        );
        assert_eq!(fresh.ordinary_manager_initializations, 1);

        let mut partial = CountingActions::new(observation(InstalledProfile::PartialOrUnknown));
        assert_eq!(
            execute_startup(&mut partial),
            Err(StartupExecutionError::Classification(
                StartupClassificationError::PartialProfile
            ))
        );
        assert_eq!(partial.events, ["classify"]);
        assert_eq!(partial.writes, 0);
        assert_eq!(partial.credential_calls, 0);
        assert_eq!(partial.ordinary_manager_initializations, 0);
    }
}
