#![cfg(windows)]

//! R3 recovery protocol matrix tests.
//!
//! This file is intentionally a child of `v031_migration_recovery`: it tests
//! the private protocol state and validators without widening the production
//! API.  The production module declaration is added separately by the owner of
//! that file so concurrent R3 implementation work does not conflict here.

use super::*;
use std::{collections::BTreeMap, time::SystemTime};

fn protocol_hash(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn component_wire(component: V031RecoveryComponent) -> &'static str {
    match component {
        V031RecoveryComponent::UserDatabase => "user_database",
        V031RecoveryComponent::PrivacyDatabase => "privacy_database",
        V031RecoveryComponent::VaultStore => "vault_store",
        V031RecoveryComponent::ApprovedWorkspace => "approved_workspace",
        V031RecoveryComponent::WorkProducts => "work_products",
    }
}

fn fingerprint(component: V031RecoveryComponent, label: &str) -> V031RecoverySlotFingerprint {
    serde_json::from_value(serde_json::json!({
        "component": component_wire(component),
        "directory": matches!(
            component,
            V031RecoveryComponent::VaultStore
                | V031RecoveryComponent::ApprovedWorkspace
                | V031RecoveryComponent::WorkProducts
        ),
        "proofSha256": protocol_hash(label),
        "totalBytes": 1,
        "entryCount": 1,
    }))
    .expect("deterministic R3 slot fingerprint")
}

fn fingerprints(prefix: &str) -> [V031RecoverySlotFingerprint; 5] {
    std::array::from_fn(|index| {
        fingerprint(
            RECOVERY_COMPONENTS[index],
            &format!("{prefix}-{}", component_wire(RECOVERY_COMPONENTS[index])),
        )
    })
}

fn safety_proof(
    workspace_instance_id: &str,
    current_slots: &[V031RecoverySlotFingerprint; 5],
) -> V031RecoverySafetyBackupProof {
    let inventory = canonical_json_v1(current_slots).expect("canonical slot inventory");
    serde_json::from_value(serde_json::json!({
        "backupId": "appbkp_11111111111111111111111111111111",
        "privacyBackupId": "bkp_22222222222222222222222222222222",
        "workspaceInstanceId": workspace_instance_id,
        "appVersion": CREATOR_APP_VERSION,
        "userSchemaVersion": database::USER_SCHEMA_VERSION,
        "createdAtUnix": 1_754_000_000_u64,
        "expiresAtUnix": 1_754_086_400_u64,
        "bundleSha256": protocol_hash("safety-bundle"),
        "bundleBytes": 4096_u64,
        "componentIdentitySha256": protocol_hash("five-component-identity"),
        "stageSlotInventorySha256": sha256_hex(&inventory),
    }))
    .expect("deterministic R3 safety proof")
}

fn requested_marker_with_slots(
    current_slots: [V031RecoverySlotFingerprint; 5],
) -> V031MigrationRecoveryPendingV1 {
    let workspace_instance_id = format!("ws_{}", "a".repeat(32));
    let marker = V031MigrationRecoveryPendingV1 {
        schema: MARKER_SCHEMA.to_owned(),
        format_version: MARKER_FORMAT_VERSION,
        migration_id: V031_MIGRATION_ID.to_owned(),
        recovery_id: format!("rcv_{}", "1".repeat(32)),
        lineage_id: protocol_hash("lineage"),
        envelope_binding_id: format!("ws_{}", "b".repeat(32)),
        source_profile_proof_sha256: protocol_hash("source-profile"),
        creator_app_version: CREATOR_APP_VERSION.to_owned(),
        target_app_version: TARGET_APP_VERSION.to_owned(),
        created_at_unix: 1_754_000_000,
        receipt_nine_protected_sha256: protocol_hash("receipt-nine-protected"),
        receipt_nine_evidence_sha256: protocol_hash("receipt-nine-evidence"),
        step8_predecessor_protected_sha256: protocol_hash("step-eight-predecessor"),
        upgrade_complete_sidecar_protected_sha256: protocol_hash("upgrade-complete-sidecar"),
        original_identity_protected_sha256: protocol_hash("original-identity"),
        original_identity_protected_bytes: 1024,
        original_bundle_sha256: protocol_hash("original-bundle"),
        original_bundle_bytes: 8192,
        original_user_sha256: protocol_hash("original-user"),
        original_user_bytes: 4096,
        original_privacy_sha256: protocol_hash("original-privacy"),
        original_privacy_bytes: 4096,
        workspace_instance_id: workspace_instance_id.clone(),
        current_five_slot_manifest_sha256: protocol_hash("current-five-slot-manifest"),
        safety_backup: safety_proof(&workspace_instance_id, &current_slots),
        credential_archive: CredentialArchiveProof {
            basename: CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
            protected_sha256: protocol_hash("credential-archive"),
            protected_bytes: 2048,
        },
        current_slots,
        slot_count: 5,
        phase: RecoveryPhase::Requested,
        commit_evidence_protected_sha256: None,
        report_protected_sha256: None,
    };
    validate_marker_static(&marker).expect("deterministic requested marker is valid");
    marker
}

fn requested_marker() -> V031MigrationRecoveryPendingV1 {
    requested_marker_with_slots(fingerprints("current"))
}

const PHASE_WIRE: [(RecoveryPhase, &str); 25] = [
    (RecoveryPhase::Requested, "requested"),
    (RecoveryPhase::UserV10Staged, "user_v10_staged"),
    (RecoveryPhase::SourcesStaged, "sources_staged"),
    (RecoveryPhase::CommitReady, "commit_ready"),
    (RecoveryPhase::UserMovedToRollback, "user_moved_to_rollback"),
    (RecoveryPhase::UserInstalled, "user_installed"),
    (
        RecoveryPhase::PrivacyMovedToRollback,
        "privacy_moved_to_rollback",
    ),
    (RecoveryPhase::PrivacyInstalled, "privacy_installed"),
    (
        RecoveryPhase::VaultMovedToRollback,
        "vault_moved_to_rollback",
    ),
    (
        RecoveryPhase::ApprovedMovedToRollback,
        "approved_moved_to_rollback",
    ),
    (
        RecoveryPhase::WorkProductsMovedToRollback,
        "work_products_moved_to_rollback",
    ),
    (RecoveryPhase::FiveSlotCommitted, "five_slot_committed"),
    (
        RecoveryPhase::WorkProductsRollbackCleaned,
        "work_products_rollback_cleaned",
    ),
    (
        RecoveryPhase::ApprovedRollbackCleaned,
        "approved_rollback_cleaned",
    ),
    (
        RecoveryPhase::VaultRollbackCleaned,
        "vault_rollback_cleaned",
    ),
    (
        RecoveryPhase::PrivacyRollbackCleaned,
        "privacy_rollback_cleaned",
    ),
    (RecoveryPhase::UserRollbackCleaned, "user_rollback_cleaned"),
    (
        RecoveryPhase::TicketSessionsCleaned,
        "ticket_sessions_cleaned",
    ),
    (RecoveryPhase::QualificationCleaned, "qualification_cleaned"),
    (
        RecoveryPhase::CredentialQualificationDeleted,
        "credential_qualification_deleted",
    ),
    (
        RecoveryPhase::CredentialTicketDeleted,
        "credential_ticket_deleted",
    ),
    (
        RecoveryPhase::CredentialWorkProductDeleted,
        "credential_work_product_deleted",
    ),
    (
        RecoveryPhase::CredentialApprovedDeleted,
        "credential_approved_deleted",
    ),
    (RecoveryPhase::TargetVerified, "target_verified"),
    (RecoveryPhase::ReportInstalled, "report_installed"),
];

fn marker_at_phase(
    requested: &V031MigrationRecoveryPendingV1,
    phase: RecoveryPhase,
) -> V031MigrationRecoveryPendingV1 {
    let mut marker = requested.clone();
    marker.phase = phase;
    if phase.ordinal() >= RecoveryPhase::FiveSlotCommitted.ordinal() {
        marker.commit_evidence_protected_sha256 = Some(protocol_hash("commit-evidence"));
    }
    if phase == RecoveryPhase::ReportInstalled {
        marker.report_protected_sha256 = Some(protocol_hash("applied-report"));
    }
    validate_marker_static(&marker).expect("phase fixture satisfies the production wire");
    marker
}

#[test]
fn r3_recovery_phase_successor_chain_and_wire_are_exact() {
    let requested = requested_marker();
    for (index, (phase, wire)) in PHASE_WIRE.iter().copied().enumerate() {
        assert_eq!(phase.ordinal(), index as u8, "ordinal for {wire}");
        assert_eq!(
            serde_json::to_string(&phase).expect("serialize phase"),
            format!("\"{wire}\"")
        );
        assert_eq!(
            serde_json::from_str::<RecoveryPhase>(&format!("\"{wire}\""))
                .expect("deserialize exact phase"),
            phase
        );
        assert_eq!(
            phase.successor(),
            PHASE_WIRE.get(index + 1).map(|entry| entry.0),
            "unique successor for {wire}"
        );
    }
    for rejected in [
        "Requested",
        "user-v10-staged",
        "five_slot_commit",
        "report_installed_extra",
        "",
    ] {
        assert!(
            serde_json::from_str::<RecoveryPhase>(&format!("\"{rejected}\"")).is_err(),
            "non-frozen phase {rejected:?} must be rejected"
        );
    }

    for (current_index, (current_phase, _)) in PHASE_WIRE.iter().copied().enumerate() {
        let current = marker_at_phase(&requested, current_phase);
        for (candidate_index, (candidate_phase, _)) in PHASE_WIRE.iter().copied().enumerate() {
            let candidate = marker_at_phase(&requested, candidate_phase);
            assert_eq!(
                direct_marker_successor(&current, &candidate),
                candidate_index == current_index + 1,
                "only the immediate successor may advance {current_phase:?} to {candidate_phase:?}"
            );
        }
    }

    let before_commit = marker_at_phase(&requested, RecoveryPhase::WorkProductsMovedToRollback);
    let mut missing_commit_hash = marker_at_phase(&requested, RecoveryPhase::FiveSlotCommitted);
    missing_commit_hash.commit_evidence_protected_sha256 = None;
    assert!(!direct_marker_successor(
        &before_commit,
        &missing_commit_hash
    ));

    let target_verified = marker_at_phase(&requested, RecoveryPhase::TargetVerified);
    let mut missing_report_hash = marker_at_phase(&requested, RecoveryPhase::ReportInstalled);
    missing_report_hash.report_protected_sha256 = None;
    assert!(!direct_marker_successor(
        &target_verified,
        &missing_report_hash
    ));

    let mut payload_drift = marker_at_phase(&requested, RecoveryPhase::UserV10Staged);
    payload_drift.lineage_id = protocol_hash("substituted-lineage");
    assert!(!direct_marker_successor(&requested, &payload_drift));
}

#[test]
fn r3_marker_wire_is_canonical_exact_and_rejects_unknown_fields() {
    let requested = requested_marker();
    let requested_value = serde_json::to_value(&requested).expect("marker JSON value");
    let requested_object = requested_value.as_object().expect("marker object");
    let expected_keys = std::collections::BTreeSet::from([
        "schema",
        "formatVersion",
        "migrationId",
        "recoveryId",
        "lineageId",
        "envelopeBindingId",
        "sourceProfileProofSha256",
        "creatorAppVersion",
        "targetAppVersion",
        "createdAtUnix",
        "receiptNineProtectedSha256",
        "receiptNineEvidenceSha256",
        "step8PredecessorProtectedSha256",
        "upgradeCompleteSidecarProtectedSha256",
        "originalIdentityProtectedSha256",
        "originalIdentityProtectedBytes",
        "originalBundleSha256",
        "originalBundleBytes",
        "originalUserSha256",
        "originalUserBytes",
        "originalPrivacySha256",
        "originalPrivacyBytes",
        "workspaceInstanceId",
        "currentFiveSlotManifestSha256",
        "currentSlots",
        "safetyBackup",
        "credentialArchive",
        "slotCount",
        "phase",
    ]);
    assert_eq!(
        requested_object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_keys
    );
    assert!(!requested_object.contains_key("commitEvidenceProtectedSha256"));
    assert!(!requested_object.contains_key("reportProtectedSha256"));

    let safety = requested_object["safetyBackup"]
        .as_object()
        .expect("safety proof object");
    assert_eq!(
        safety
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "backupId",
            "privacyBackupId",
            "workspaceInstanceId",
            "appVersion",
            "userSchemaVersion",
            "createdAtUnix",
            "expiresAtUnix",
            "bundleSha256",
            "bundleBytes",
            "componentIdentitySha256",
            "stageSlotInventorySha256",
        ])
    );
    let credential = requested_object["credentialArchive"]
        .as_object()
        .expect("credential proof object");
    assert_eq!(
        credential
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["basename", "protectedSha256", "protectedBytes"])
    );
    for slot in requested_object["currentSlots"]
        .as_array()
        .expect("five slot inventory")
    {
        assert_eq!(
            slot.as_object()
                .expect("slot object")
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "component",
                "directory",
                "proofSha256",
                "totalBytes",
                "entryCount",
            ])
        );
    }

    let canonical = canonical_json_v1(&requested).expect("canonical marker");
    let decoded: V031MigrationRecoveryPendingV1 =
        strict_json_v1_from_slice(&canonical).expect("strict canonical marker");
    assert_eq!(decoded, requested);

    let mut unknown = requested_value;
    unknown
        .as_object_mut()
        .expect("marker object")
        .insert("privacyCaseId".to_owned(), serde_json::json!("forbidden"));
    let unknown = canonical_json_v1(&unknown).expect("canonical unknown-field fixture");
    assert!(strict_json_v1_from_slice::<V031MigrationRecoveryPendingV1>(&unknown).is_err());

    let report = marker_at_phase(&requested, RecoveryPhase::ReportInstalled);
    let report_value = serde_json::to_value(report).expect("terminal marker JSON");
    assert!(report_value.get("commitEvidenceProtectedSha256").is_some());
    assert!(report_value.get("reportProtectedSha256").is_some());
}

fn assert_static_marker_tamper_rejected(
    baseline: &V031MigrationRecoveryPendingV1,
    label: &str,
    mutate: impl FnOnce(&mut V031MigrationRecoveryPendingV1),
) {
    let mut candidate = baseline.clone();
    mutate(&mut candidate);
    assert!(
        validate_marker_static(&candidate).is_err(),
        "static marker tamper {label} must fail closed"
    );
}

#[test]
fn r3_marker_static_tamper_matrix_fails_closed() {
    let requested = requested_marker();
    assert_static_marker_tamper_rejected(&requested, "schema", |marker| {
        marker.schema.push_str("-substituted");
    });
    assert_static_marker_tamper_rejected(&requested, "format", |marker| {
        marker.format_version += 1;
    });
    assert_static_marker_tamper_rejected(&requested, "migration", |marker| {
        marker.migration_id.push_str("-other");
    });
    assert_static_marker_tamper_rejected(&requested, "recovery uppercase", |marker| {
        marker.recovery_id = format!("rcv_{}", "A".repeat(32));
    });
    assert_static_marker_tamper_rejected(&requested, "recovery traversal", |marker| {
        marker.recovery_id = "rcv_../../outside".to_owned();
    });
    assert_static_marker_tamper_rejected(&requested, "lineage", |marker| {
        marker.lineage_id = "f".repeat(63);
    });
    assert_static_marker_tamper_rejected(&requested, "creator", |marker| {
        marker.creator_app_version = "0.4.1".to_owned();
    });
    assert_static_marker_tamper_rejected(&requested, "target", |marker| {
        marker.target_app_version = "0.3.0".to_owned();
    });
    assert_static_marker_tamper_rejected(&requested, "timestamp", |marker| {
        marker.created_at_unix = 0;
    });
    assert_static_marker_tamper_rejected(&requested, "slot count", |marker| {
        marker.slot_count = 4;
    });
    assert_static_marker_tamper_rejected(&requested, "zero original bytes", |marker| {
        marker.original_user_bytes = 0;
    });
    assert_static_marker_tamper_rejected(&requested, "credential basename", |marker| {
        marker.credential_archive.basename = "credentials.dpapi".to_owned();
    });
    assert_static_marker_tamper_rejected(&requested, "hash shape", |marker| {
        marker.receipt_nine_evidence_sha256 = "A".repeat(64);
    });
    assert_static_marker_tamper_rejected(&requested, "component order", |marker| {
        marker.current_slots.swap(0, 1);
    });
    assert_static_marker_tamper_rejected(&requested, "component substitution", |marker| {
        marker.current_slots[0] = fingerprint(V031RecoveryComponent::UserDatabase, "foreign");
        marker.current_slots[0] = serde_json::from_value(serde_json::json!({
            "component": "privacy_database",
            "directory": false,
            "proofSha256": protocol_hash("foreign"),
            "totalBytes": 1,
            "entryCount": 1,
        }))
        .expect("wrong-component fingerprint parses");
    });
    assert_static_marker_tamper_rejected(&requested, "safety slot inventory", |marker| {
        let mut proof = serde_json::to_value(&marker.safety_backup).expect("safety JSON");
        proof["stageSlotInventorySha256"] = serde_json::json!(protocol_hash("other-inventory"));
        marker.safety_backup =
            serde_json::from_value(proof).expect("valid-shaped substituted safety proof");
    });

    let mut premature_commit = requested.clone();
    premature_commit.commit_evidence_protected_sha256 = Some(protocol_hash("premature-commit"));
    assert!(validate_marker_static(&premature_commit).is_err());

    let mut missing_commit = marker_at_phase(&requested, RecoveryPhase::FiveSlotCommitted);
    missing_commit.commit_evidence_protected_sha256 = None;
    assert!(validate_marker_static(&missing_commit).is_err());

    let mut premature_report = marker_at_phase(&requested, RecoveryPhase::TargetVerified);
    premature_report.report_protected_sha256 = Some(protocol_hash("premature-report"));
    assert!(validate_marker_static(&premature_report).is_err());

    let mut missing_report = marker_at_phase(&requested, RecoveryPhase::ReportInstalled);
    missing_report.report_protected_sha256 = None;
    assert!(validate_marker_static(&missing_report).is_err());
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeEntrySnapshot {
    directory: bool,
    bytes: Vec<u8>,
    modified: SystemTime,
}

fn snapshot_tree(root: &Path) -> BTreeMap<String, TreeEntrySnapshot> {
    fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<String, TreeEntrySnapshot>) {
        let metadata = std::fs::symlink_metadata(path).expect("snapshot metadata");
        let relative = if path == root {
            ".".to_owned()
        } else {
            path.strip_prefix(root)
                .expect("snapshot path remains below root")
                .to_string_lossy()
                .replace('\\', "/")
        };
        let directory = metadata.is_dir();
        let bytes = if directory {
            Vec::new()
        } else {
            std::fs::read(path).expect("snapshot file bytes")
        };
        assert!(
            snapshot
                .insert(
                    relative,
                    TreeEntrySnapshot {
                        directory,
                        bytes,
                        modified: metadata.modified().expect("snapshot modification time"),
                    },
                )
                .is_none(),
            "snapshot paths are unique"
        );
        if directory {
            let mut entries = std::fs::read_dir(path)
                .expect("snapshot directory")
                .collect::<Result<Vec<_>, _>>()
                .expect("snapshot entries");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                visit(root, &entry.path(), snapshot);
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

fn write_residue(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("residue parent")).expect("create residue parent");
    std::fs::write(path, bytes).expect("write deterministic residue");
}

type RecoveryResidueEntry<'a> = (&'a str, &'a [u8]);
type RecoveryResidueCase<'a> = (&'a str, &'a [RecoveryResidueEntry<'a>]);

#[test]
fn r3_formal_absent_ignores_malformed_residue_without_parsing_or_writes() {
    let cases: [RecoveryResidueCase<'_>; 5] = [
        (
            "incoming only",
            &[(V031_MIGRATION_RECOVERY_MARKER_INCOMING, b"not-dpapi")],
        ),
        (
            "inner staging only",
            &[(V031_MIGRATION_RECOVERY_MARKER_STAGING, b"partial")],
        ),
        (
            "both marker residues",
            &[
                (V031_MIGRATION_RECOVERY_MARKER_INCOMING, b"corrupt-incoming"),
                (V031_MIGRATION_RECOVERY_MARKER_STAGING, b"corrupt-staging"),
            ],
        ),
        (
            "audit final without marker",
            &[(
                "v031-migration-recovery-audit/rcv_11111111111111111111111111111111/applied-downgrade.report.dpapi",
                b"orphaned-audit-final",
            )],
        ),
        (
            "all unauthorized residue",
            &[
                (V031_MIGRATION_RECOVERY_MARKER_INCOMING, b"incoming"),
                (V031_MIGRATION_RECOVERY_MARKER_STAGING, b"staging"),
                (
                    "v031-migration-recovery-audit/rcv_11111111111111111111111111111111/five-slot-commit.evidence.dpapi",
                    b"commit-shaped-residue",
                ),
                (
                    "v031-migration-recovery-audit/rcv_11111111111111111111111111111111/current-v040-safety-v3.lavbackup.incoming",
                    b"safety-residue",
                ),
            ],
        ),
    ];

    for (label, entries) in cases {
        let directory = tempfile::tempdir().expect("R3 formal-absent fixture");
        for (relative, bytes) in entries {
            write_residue(directory.path(), relative, bytes);
        }
        let before = snapshot_tree(directory.path());
        match observe_v031_migration_recovery_read_only(directory.path())
            .unwrap_or_else(|error| panic!("{label} must remain absent: {}", error.error_type))
        {
            V031MigrationRecoveryObservation::Absent => {}
            V031MigrationRecoveryObservation::Authenticated(_) => {
                panic!("{label} acquired recovery authority without a formal marker")
            }
        }
        assert_eq!(
            snapshot_tree(directory.path()),
            before,
            "{label} must not be parsed, promoted, deleted, or rewritten"
        );
    }
}

#[test]
fn r3_formal_marker_present_is_authoritative_and_malformed_final_fails_read_only() {
    let directory = tempfile::tempdir().expect("R3 malformed formal marker fixture");
    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER,
        b"not-a-dpapi-marker",
    );
    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER_INCOMING,
        b"also-malformed",
    );
    let before = snapshot_tree(directory.path());
    let error = match observe_v031_migration_recovery_read_only(directory.path()) {
        Ok(_) => panic!("a present malformed formal marker must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.error_type, "v031_migration_recovery_invalid");
    assert_eq!(snapshot_tree(directory.path()), before);
}

#[test]
fn r3_explicit_restaging_cleanup_removes_only_unauthorized_marker_residue() {
    let directory = tempfile::tempdir().expect("R3 residue cleanup fixture");
    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER_INCOMING,
        b"stale-incoming",
    );
    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER_STAGING,
        b"stale-staging",
    );
    write_residue(
        directory.path(),
        "v031-migration-recovery-audit/rcv_11111111111111111111111111111111/audit-retained.bin",
        b"retained-audit",
    );
    cleanup_unauthorized_initial_marker_residue(directory.path())
        .expect("explicit restaging may remove marker-only residue");
    assert!(!directory
        .path()
        .join(V031_MIGRATION_RECOVERY_MARKER_INCOMING)
        .exists());
    assert!(!directory
        .path()
        .join(V031_MIGRATION_RECOVERY_MARKER_STAGING)
        .exists());
    assert_eq!(
        std::fs::read(directory.path().join(
            "v031-migration-recovery-audit/rcv_11111111111111111111111111111111/audit-retained.bin"
        ))
        .expect("audit material remains"),
        b"retained-audit"
    );

    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER,
        b"formal-authority",
    );
    write_residue(
        directory.path(),
        V031_MIGRATION_RECOVERY_MARKER_INCOMING,
        b"successor-residue",
    );
    let before = snapshot_tree(directory.path());
    assert!(cleanup_unauthorized_initial_marker_residue(directory.path()).is_err());
    assert_eq!(snapshot_tree(directory.path()), before);
}

#[test]
fn r3_initial_marker_and_every_successor_use_the_authenticated_fixed_install_chain() {
    let directory = tempfile::tempdir().expect("R3 marker install fixture");
    let mut installed = requested_marker();
    install_initial_marker_incoming(directory.path(), &installed)
        .expect("initial marker reaches fixed incoming");
    let (final_path, incoming_path) = marker_paths(directory.path());
    let staging_path = marker_staging_path(directory.path());
    assert!(!final_path.exists());
    assert!(!staging_path.exists());
    assert_eq!(
        read_marker(&incoming_path)
            .expect("authenticate initial incoming")
            .0,
        installed
    );

    finalize_initial_marker(directory.path()).expect("formal marker installs after quiescence");
    assert!(!incoming_path.exists());
    assert!(!staging_path.exists());
    assert_eq!(
        read_marker(&final_path)
            .expect("authenticate formal marker")
            .0,
        installed
    );

    for (phase, wire) in PHASE_WIRE.iter().copied().skip(1) {
        let next = marker_at_phase(&requested_marker(), phase);
        installed = install_marker_successor(directory.path(), &installed, next.clone())
            .unwrap_or_else(|error| {
                panic!(
                    "install exact marker successor {wire}: {}",
                    error.error_type
                )
            });
        assert_eq!(installed, next);
        assert_eq!(
            read_marker(&final_path)
                .expect("authenticate installed successor")
                .0,
            next,
            "formal marker at {wire}"
        );
        assert!(!incoming_path.exists(), "incoming absent after {wire}");
        assert!(!staging_path.exists(), "inner staging absent after {wire}");
    }

    assert_eq!(installed.phase, RecoveryPhase::ReportInstalled);
    assert!(installed.commit_evidence_protected_sha256.is_some());
    assert!(installed.report_protected_sha256.is_some());
}

#[test]
fn r3_protected_marker_rejects_noncanonical_unknown_and_ciphertext_tamper() {
    let directory = tempfile::tempdir().expect("R3 protected marker fixture");
    let path = directory.path().join("marker-under-test.dpapi");
    let marker = requested_marker();

    let protected = canonical_protected_marker(&marker).expect("protect canonical marker");
    std::fs::write(&path, &protected).expect("write protected marker");
    assert_eq!(read_marker(&path).expect("read canonical marker").0, marker);

    let canonical = canonical_json_v1(&marker).expect("canonical plaintext");
    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&canonical);
    let protected_noncanonical = protect_local(&noncanonical).expect("protect noncanonical JSON");
    std::fs::write(&path, protected_noncanonical).expect("write noncanonical marker");
    assert!(read_marker(&path).is_err());

    let mut unknown = serde_json::to_value(&marker).expect("marker value");
    unknown.as_object_mut().expect("marker object").insert(
        "absolutePath".to_owned(),
        serde_json::json!("C:\\forbidden"),
    );
    let unknown_plaintext = canonical_json_v1(&unknown).expect("canonical unknown marker");
    let protected_unknown = protect_local(&unknown_plaintext).expect("protect unknown marker");
    std::fs::write(&path, protected_unknown).expect("write unknown marker");
    assert!(read_marker(&path).is_err());

    let mut ciphertext_tamper = protected;
    let middle = ciphertext_tamper.len() / 2;
    ciphertext_tamper[middle] ^= 0x5a;
    std::fs::write(&path, ciphertext_tamper).expect("write ciphertext tamper");
    assert!(read_marker(&path).is_err());
}

fn empty_audit_slots() -> [RecoveryAuditSlotV1; 5] {
    std::array::from_fn(|index| RecoveryAuditSlotV1 {
        component: RECOVERY_COMPONENTS[index],
        active: None,
        incoming: None,
        rollback: None,
        cleanup: None,
    })
}

fn committed_audit_slots(
    current: &[V031RecoverySlotFingerprint; 5],
    target: &[V031RecoverySlotFingerprint; 5],
) -> [RecoveryAuditSlotV1; 5] {
    let mut slots = empty_audit_slots();
    for index in 0..2 {
        slots[index].active = Some(target[index].clone());
        slots[index].rollback = Some(current[index].clone());
    }
    for slot in slots.iter_mut().skip(2) {
        let index = component_index(slot.component);
        slot.rollback = Some(current[index].clone());
    }
    slots
}

fn applied_audit_slots(target: &[V031RecoverySlotFingerprint; 5]) -> [RecoveryAuditSlotV1; 5] {
    let mut slots = empty_audit_slots();
    for index in 0..2 {
        slots[index].active = Some(target[index].clone());
    }
    slots
}

fn restored_audit_slots(current: &[V031RecoverySlotFingerprint; 5]) -> [RecoveryAuditSlotV1; 5] {
    std::array::from_fn(|index| RecoveryAuditSlotV1 {
        component: RECOVERY_COMPONENTS[index],
        active: Some(current[index].clone()),
        incoming: None,
        rollback: None,
        cleanup: None,
    })
}

fn audit_evidence(
    marker: &V031MigrationRecoveryPendingV1,
    kind: AuditEvidenceKind,
    marker_phase: RecoveryPhase,
    physical_slots: [RecoveryAuditSlotV1; 5],
    credential_delete_prefix: u64,
    commit_evidence_authenticated_absent: bool,
) -> RecoveryAuditEvidenceV1 {
    RecoveryAuditEvidenceV1 {
        schema: AUDIT_EVIDENCE_SCHEMA.to_owned(),
        format_version: 1,
        kind,
        recovery_id: marker.recovery_id.clone(),
        migration_id: marker.migration_id.clone(),
        lineage_id: marker.lineage_id.clone(),
        source_profile_proof_sha256: marker.source_profile_proof_sha256.clone(),
        safety_backup_sha256: marker.safety_backup.bundle_sha256().to_owned(),
        credential_archive_sha256: marker.credential_archive.protected_sha256.clone(),
        current_five_slot_manifest_sha256: marker.current_five_slot_manifest_sha256.clone(),
        target_app_version: marker.target_app_version.clone(),
        marker_phase,
        stage_slot_inventory_sha256: stage_slot_inventory_sha256(marker)
            .expect("stage inventory binding"),
        physical_slots,
        credential_delete_prefix,
        commit_evidence_authenticated_absent,
    }
}

fn assert_audit_tamper_rejected(
    marker: &V031MigrationRecoveryPendingV1,
    kind: AuditEvidenceKind,
    baseline: &RecoveryAuditEvidenceV1,
    label: &str,
    mutate: impl FnOnce(&mut RecoveryAuditEvidenceV1),
) {
    let mut candidate = baseline.clone();
    mutate(&mut candidate);
    assert!(
        validate_audit_evidence(marker, kind, &candidate).is_err(),
        "audit tamper {label} must fail closed"
    );
}

#[test]
fn r3_commit_abort_reports_and_terminal_target_binding_are_exact() {
    let requested = requested_marker();
    let current = requested.current_slots.clone();
    let target = fingerprints("v031-target");

    let precommit = marker_at_phase(&requested, RecoveryPhase::WorkProductsMovedToRollback);
    let commit_slots = committed_audit_slots(&current, &target);
    let commit = audit_evidence(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        RecoveryPhase::WorkProductsMovedToRollback,
        commit_slots.clone(),
        0,
        false,
    );
    validate_audit_evidence(&precommit, AuditEvidenceKind::FiveSlotCommit, &commit)
        .expect("exact five-slot commit evidence");
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit kind",
        |evidence| evidence.kind = AuditEvidenceKind::AbortToCurrent,
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit recovery binding",
        |evidence| evidence.recovery_id = format!("rcv_{}", "2".repeat(32)),
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit inventory binding",
        |evidence| evidence.stage_slot_inventory_sha256 = protocol_hash("foreign-inventory"),
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit phase",
        |evidence| evidence.marker_phase = RecoveryPhase::ApprovedMovedToRollback,
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit credential prefix",
        |evidence| evidence.credential_delete_prefix = 1,
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit authenticated-absent flag",
        |evidence| evidence.commit_evidence_authenticated_absent = true,
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit current rollback substitution",
        |evidence| {
            evidence.physical_slots[component_index(V031RecoveryComponent::VaultStore)].rollback =
                Some(fingerprint(V031RecoveryComponent::VaultStore, "foreign"));
        },
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::FiveSlotCommit,
        &commit,
        "commit component order",
        |evidence| evidence.physical_slots.swap(0, 1),
    );

    let abort = audit_evidence(
        &precommit,
        AuditEvidenceKind::AbortToCurrent,
        precommit.phase,
        commit_slots,
        0,
        true,
    );
    validate_audit_evidence(&precommit, AuditEvidenceKind::AbortToCurrent, &abort)
        .expect("exact precommit abort intent");
    assert!(
        validate_audit_evidence(&precommit, AuditEvidenceKind::FiveSlotCommit, &abort).is_err(),
        "one final evidence payload cannot authorize both abort and commit"
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::AbortToCurrent,
        &abort,
        "abort commit absence",
        |evidence| evidence.commit_evidence_authenticated_absent = false,
    );
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::AbortToCurrent,
        &abort,
        "abort credential prefix",
        |evidence| evidence.credential_delete_prefix = 1,
    );

    let aborted = audit_evidence(
        &precommit,
        AuditEvidenceKind::AbortedCurrentRestored,
        precommit.phase,
        restored_audit_slots(&current),
        0,
        true,
    );
    validate_audit_evidence(
        &precommit,
        AuditEvidenceKind::AbortedCurrentRestored,
        &aborted,
    )
    .expect("exact current-restored report");
    assert_audit_tamper_rejected(
        &precommit,
        AuditEvidenceKind::AbortedCurrentRestored,
        &aborted,
        "aborted report residue",
        |evidence| {
            evidence.physical_slots[component_index(V031RecoveryComponent::PrivacyDatabase)]
                .incoming = Some(fingerprint(
                V031RecoveryComponent::PrivacyDatabase,
                "residue",
            ));
        },
    );

    let target_verified = marker_at_phase(&requested, RecoveryPhase::TargetVerified);
    let applied = audit_evidence(
        &target_verified,
        AuditEvidenceKind::AppliedDowngrade,
        RecoveryPhase::TargetVerified,
        applied_audit_slots(&target),
        4,
        false,
    );
    validate_audit_evidence(
        &target_verified,
        AuditEvidenceKind::AppliedDowngrade,
        &applied,
    )
    .expect("exact applied report");
    validate_applied_report_commit_binding(&target_verified, &commit, &applied)
        .expect("applied targets bind to commit targets");

    let mut substituted_applied = applied.clone();
    substituted_applied.physical_slots[component_index(V031RecoveryComponent::PrivacyDatabase)]
        .active = Some(fingerprint(
        V031RecoveryComponent::PrivacyDatabase,
        "shape-valid-substitution",
    ));
    validate_audit_evidence(
        &target_verified,
        AuditEvidenceKind::AppliedDowngrade,
        &substituted_applied,
    )
    .expect("the substituted report remains shape-valid");
    assert!(
        validate_applied_report_commit_binding(&target_verified, &commit, &substituted_applied)
            .is_err(),
        "terminal proof must bind exact committed database targets"
    );

    let report_installed = marker_at_phase(&requested, RecoveryPhase::ReportInstalled);
    assert!(direct_marker_successor(&target_verified, &report_installed));
    let mut report_hash_drift = report_installed;
    report_hash_drift.report_protected_sha256 = Some(protocol_hash("other-report"));
    assert!(direct_marker_successor(
        &target_verified,
        &report_hash_drift
    ));
    assert_ne!(
        report_hash_drift.report_protected_sha256,
        Some(protocol_hash("applied-report")),
        "the file-level report readback must supply the actual protected hash"
    );
}

fn protect_audit_evidence(evidence: &RecoveryAuditEvidenceV1) -> Vec<u8> {
    let plaintext = canonical_json_v1(evidence).expect("canonical audit evidence");
    protect_local(&plaintext).expect("DPAPI-protect audit evidence")
}

fn install_formal_marker_fixture(root: &Path, marker: &V031MigrationRecoveryPendingV1) {
    let (final_path, _) = marker_paths(root);
    std::fs::write(
        final_path,
        canonical_protected_marker(marker).expect("protect formal marker fixture"),
    )
    .expect("install formal marker fixture");
}

fn rewrap_marker_with_distinct_ciphertext(
    path: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    previous_hash: &str,
) {
    let protected = (0..8)
        .find_map(|_| {
            let candidate = canonical_protected_marker(marker).expect("rewrap marker fixture");
            (sha256_hex(&candidate) != previous_hash).then_some(candidate)
        })
        .expect("DPAPI rewrap produces distinct authenticated ciphertext");
    std::fs::write(path, protected).expect("replace marker fixture with readable hash drift");
}

#[test]
fn r3_observed_abort_authority_rejects_final_replace_and_discard_ciphertext_hash_drift() {
    {
        let directory = tempfile::tempdir().expect("R3 final marker hash fixture");
        let formal = requested_marker();
        install_formal_marker_fixture(directory.path(), &formal);
        let (final_path, _) = marker_paths(directory.path());
        let (_, formal_hash) = read_marker(&final_path).expect("read frozen final marker");
        let proof = ObservedMarkerInstallProof {
            marker: &formal,
            marker_protected_sha256: &formal_hash,
            predecessor_marker_protected_sha256: None,
            successor_marker_protected_sha256: None,
            marker_install_state: MarkerInstallState::Final,
        };
        authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .expect("unchanged Final observation authenticates");
        rewrap_marker_with_distinct_ciphertext(&final_path, &formal, &formal_hash);
        assert!(authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .is_err());
    }

    {
        let directory = tempfile::tempdir().expect("R3 replace marker hash fixture");
        let formal = requested_marker();
        let successor = marker_at_phase(&formal, RecoveryPhase::UserV10Staged);
        install_formal_marker_fixture(directory.path(), &formal);
        let (final_path, incoming_path) = marker_paths(directory.path());
        std::fs::write(
            &incoming_path,
            canonical_protected_marker(&successor).expect("protect replacement successor"),
        )
        .expect("install replacement successor");
        let (_, formal_hash) = read_marker(&final_path).expect("read replacement predecessor");
        let (_, successor_hash) = read_marker(&incoming_path).expect("read replacement successor");
        let proof = ObservedMarkerInstallProof {
            marker: &successor,
            marker_protected_sha256: &successor_hash,
            predecessor_marker_protected_sha256: Some(&formal_hash),
            successor_marker_protected_sha256: None,
            marker_install_state: MarkerInstallState::ReplaceFinalWithIncoming,
        };
        authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .expect("unchanged Replace observation authenticates");
        rewrap_marker_with_distinct_ciphertext(&final_path, &formal, &formal_hash);
        assert!(authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .is_err());
    }

    {
        let directory = tempfile::tempdir().expect("R3 discard marker hash fixture");
        let formal = requested_marker();
        let successor = marker_at_phase(&formal, RecoveryPhase::UserV10Staged);
        install_formal_marker_fixture(directory.path(), &formal);
        let (final_path, incoming_path) = marker_paths(directory.path());
        std::fs::write(
            &incoming_path,
            canonical_protected_marker(&successor).expect("protect discard successor"),
        )
        .expect("install discard successor");
        let (_, formal_hash) = read_marker(&final_path).expect("read discard formal");
        let (_, successor_hash) = read_marker(&incoming_path).expect("read discard successor");
        let proof = ObservedMarkerInstallProof {
            marker: &formal,
            marker_protected_sha256: &formal_hash,
            predecessor_marker_protected_sha256: None,
            successor_marker_protected_sha256: Some(&successor_hash),
            marker_install_state: MarkerInstallState::DiscardIncomingForAbort,
        };
        authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .expect("unchanged Discard observation authenticates");
        rewrap_marker_with_distinct_ciphertext(&incoming_path, &successor, &successor_hash);
        assert!(authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::Observed(proof),
        )
        .is_err());
    }
}

#[test]
fn r3_forward_error_abort_authority_accepts_only_three_durable_marker_boundaries() {
    let expected = requested_marker();
    let successor = marker_at_phase(&expected, RecoveryPhase::UserV10Staged);

    {
        let directory = tempfile::tempdir().expect("R3 forward boundary one");
        install_formal_marker_fixture(directory.path(), &expected);
        let authority = authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::ForwardError(&expected),
        )
        .expect("formal local marker without incoming is legal");
        assert_eq!(authority.formal_marker, expected);
        assert!(authority.successor.is_none());
    }

    {
        let directory = tempfile::tempdir().expect("R3 forward boundary two");
        install_formal_marker_fixture(directory.path(), &expected);
        let (_, incoming_path) = marker_paths(directory.path());
        std::fs::write(
            incoming_path,
            canonical_protected_marker(&successor).expect("protect direct incoming"),
        )
        .expect("install direct incoming");
        let authority = authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::ForwardError(&expected),
        )
        .expect("formal local marker plus direct incoming is legal");
        assert_eq!(authority.formal_marker, expected);
        assert_eq!(
            authority
                .successor
                .expect("direct incoming is frozen")
                .marker,
            successor
        );
    }

    {
        let directory = tempfile::tempdir().expect("R3 forward boundary three");
        install_formal_marker_fixture(directory.path(), &successor);
        let authority = authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::ForwardError(&expected),
        )
        .expect("completed direct-successor replacement is legal");
        assert_eq!(authority.formal_marker, successor);
        assert!(authority.successor.is_none());
    }

    {
        let directory = tempfile::tempdir().expect("R3 illegal forward boundary");
        let two_phases_ahead = marker_at_phase(&expected, RecoveryPhase::SourcesStaged);
        install_formal_marker_fixture(directory.path(), &two_phases_ahead);
        assert!(authenticate_authoritative_marker_for_abort(
            directory.path(),
            AbortMarkerExpectation::ForwardError(&expected),
        )
        .is_err());
    }
}

#[test]
fn r3_real_commit_and_abort_finals_are_unconditionally_rejected() {
    let directory = tempfile::tempdir().expect("R3 dual-final fixture");
    let marker = marker_at_phase(
        &requested_marker(),
        RecoveryPhase::WorkProductsMovedToRollback,
    );
    let audit_directory = create_audit_directory(directory.path(), &marker.recovery_id)
        .expect("create dual-final audit directory");
    let slots = committed_audit_slots(&marker.current_slots, &fingerprints("dual-final-target"));
    let commit = audit_evidence(
        &marker,
        AuditEvidenceKind::FiveSlotCommit,
        marker.phase,
        slots.clone(),
        0,
        false,
    );
    let abort = audit_evidence(
        &marker,
        AuditEvidenceKind::AbortToCurrent,
        marker.phase,
        slots,
        0,
        true,
    );
    let commit_path = audit_directory.join(COMMIT_EVIDENCE_BASENAME);
    let abort_path = audit_directory.join(ABORT_INTENT_BASENAME);
    std::fs::write(&commit_path, protect_audit_evidence(&commit))
        .expect("install real authenticated commit final");
    std::fs::write(&abort_path, protect_audit_evidence(&abort))
        .expect("install real authenticated abort final");

    assert!(
        validate_evidence_state(directory.path(), &marker).is_err(),
        "two authenticated physical finals are contradictory before target cross-binding"
    );
    assert!(commit_path.exists());
    assert!(abort_path.exists());
}

#[test]
fn r3_abort_evidence_install_crash_matrix_preserves_first_authenticated_final() {
    let directory = tempfile::tempdir().expect("R3 abort evidence fixture");
    let marker = marker_at_phase(&requested_marker(), RecoveryPhase::PrivacyInstalled);
    let audit_directory = create_audit_directory(directory.path(), &marker.recovery_id)
        .expect("create fixed audit directory");
    let exact = audit_evidence(
        &marker,
        AuditEvidenceKind::AbortToCurrent,
        marker.phase,
        restored_audit_slots(&marker.current_slots),
        0,
        true,
    );
    let installed_hash = install_or_verify_audit_evidence(
        directory.path(),
        &marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &exact,
    )
    .expect("install durable abort intent");
    let final_path = audit_directory.join(ABORT_INTENT_BASENAME);
    let (incoming, staging) = audit_evidence_transaction_paths(&final_path);
    assert!(!incoming.exists());
    assert!(!staging.exists());
    let (readback, readback_hash) =
        read_audit_evidence_file(&final_path, &marker, AuditEvidenceKind::AbortToCurrent)
            .expect("authenticate installed abort intent");
    assert_eq!(readback, exact);
    assert_eq!(readback_hash, installed_hash);

    std::fs::write(&incoming, b"non-authoritative incoming residue")
        .expect("write incoming residue");
    std::fs::write(&staging, b"non-authoritative staging residue").expect("write staging residue");
    let mut later_observation = exact.clone();
    later_observation.physical_slots[component_index(V031RecoveryComponent::PrivacyDatabase)]
        .incoming = Some(fingerprint(
        V031RecoveryComponent::PrivacyDatabase,
        "later-observation",
    ));
    let resumed_hash = install_or_verify_audit_evidence(
        directory.path(),
        &marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &later_observation,
    )
    .expect("authenticated abort final wins and residue is cleaned");
    assert_eq!(resumed_hash, installed_hash);
    assert!(!incoming.exists());
    assert!(!staging.exists());
    assert_eq!(
        read_audit_evidence_file(&final_path, &marker, AuditEvidenceKind::AbortToCurrent,)
            .expect("first abort intent remains authoritative")
            .0,
        exact
    );

    let mut incoming_marker = marker.clone();
    incoming_marker.recovery_id = format!("rcv_{}", "3".repeat(32));
    validate_marker_static(&incoming_marker).expect("second recovery marker");
    let incoming_directory = create_audit_directory(directory.path(), &incoming_marker.recovery_id)
        .expect("second audit directory");
    let incoming_candidate = audit_evidence(
        &incoming_marker,
        AuditEvidenceKind::AbortToCurrent,
        incoming_marker.phase,
        restored_audit_slots(&incoming_marker.current_slots),
        0,
        true,
    );
    let incoming_final = incoming_directory.join(ABORT_INTENT_BASENAME);
    let (incoming_path, incoming_staging) = audit_evidence_transaction_paths(&incoming_final);
    std::fs::write(&incoming_path, protect_audit_evidence(&incoming_candidate))
        .expect("write exact interrupted incoming");
    let promoted_hash = install_or_verify_audit_evidence(
        directory.path(),
        &incoming_marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &incoming_candidate,
    )
    .expect("resume exact incoming to final");
    assert!(incoming_final.exists());
    assert!(!incoming_path.exists());
    assert!(!incoming_staging.exists());
    assert_eq!(
        read_audit_evidence_file(
            &incoming_final,
            &incoming_marker,
            AuditEvidenceKind::AbortToCurrent,
        )
        .expect("authenticate promoted abort intent")
        .1,
        promoted_hash
    );

    let mut staging_marker = incoming_marker.clone();
    staging_marker.recovery_id = format!("rcv_{}", "5".repeat(32));
    validate_marker_static(&staging_marker).expect("staging recovery marker");
    let staging_directory = create_audit_directory(directory.path(), &staging_marker.recovery_id)
        .expect("staging audit directory");
    let staging_candidate = audit_evidence(
        &staging_marker,
        AuditEvidenceKind::AbortToCurrent,
        staging_marker.phase,
        restored_audit_slots(&staging_marker.current_slots),
        0,
        true,
    );
    let staging_final = staging_directory.join(ABORT_INTENT_BASENAME);
    let (staging_incoming, staging_path) = audit_evidence_transaction_paths(&staging_final);
    std::fs::write(&staging_path, protect_audit_evidence(&staging_candidate))
        .expect("write exact interrupted staging");
    install_or_verify_audit_evidence(
        directory.path(),
        &staging_marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &staging_candidate,
    )
    .expect("resume exact staging through incoming to final");
    assert!(staging_final.exists());
    assert!(!staging_incoming.exists());
    assert!(!staging_path.exists());
    assert_eq!(
        read_audit_evidence_file(
            &staging_final,
            &staging_marker,
            AuditEvidenceKind::AbortToCurrent,
        )
        .expect("authenticate staging-resumed abort intent")
        .0,
        staging_candidate
    );

    let mut dual_residue_marker = incoming_marker.clone();
    dual_residue_marker.recovery_id = format!("rcv_{}", "6".repeat(32));
    validate_marker_static(&dual_residue_marker).expect("dual-residue recovery marker");
    let dual_residue_directory =
        create_audit_directory(directory.path(), &dual_residue_marker.recovery_id)
            .expect("dual-residue audit directory");
    let dual_residue_candidate = audit_evidence(
        &dual_residue_marker,
        AuditEvidenceKind::AbortToCurrent,
        dual_residue_marker.phase,
        restored_audit_slots(&dual_residue_marker.current_slots),
        0,
        true,
    );
    let dual_residue_final = dual_residue_directory.join(ABORT_INTENT_BASENAME);
    let (dual_residue_incoming, dual_residue_staging) =
        audit_evidence_transaction_paths(&dual_residue_final);
    std::fs::write(
        &dual_residue_incoming,
        protect_audit_evidence(&dual_residue_candidate),
    )
    .expect("write exact interrupted incoming");
    std::fs::write(
        &dual_residue_staging,
        protect_audit_evidence(&dual_residue_candidate),
    )
    .expect("write exact interrupted inner staging");
    assert!(install_or_verify_audit_evidence(
        directory.path(),
        &dual_residue_marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &dual_residue_candidate,
    )
    .is_err());
    assert!(!dual_residue_final.exists());
    assert!(dual_residue_incoming.exists());
    assert!(dual_residue_staging.exists());

    let mut malformed_marker = marker;
    malformed_marker.recovery_id = format!("rcv_{}", "4".repeat(32));
    validate_marker_static(&malformed_marker).expect("third recovery marker");
    let malformed_directory =
        create_audit_directory(directory.path(), &malformed_marker.recovery_id)
            .expect("third audit directory");
    let malformed_final = malformed_directory.join(ABORT_INTENT_BASENAME);
    let (malformed_incoming, _) = audit_evidence_transaction_paths(&malformed_final);
    std::fs::write(&malformed_incoming, b"malformed incoming").expect("write malformed incoming");
    let malformed_candidate = audit_evidence(
        &malformed_marker,
        AuditEvidenceKind::AbortToCurrent,
        malformed_marker.phase,
        restored_audit_slots(&malformed_marker.current_slots),
        0,
        true,
    );
    assert!(install_or_verify_audit_evidence(
        directory.path(),
        &malformed_marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &malformed_candidate,
    )
    .is_err());
    assert!(!malformed_final.exists());
    assert!(malformed_incoming.exists());
}

#[test]
fn r3_abort_final_precedes_requested_marker_database_and_commit_residue_cleanup() {
    let fixture = PhysicalRecoveryFixture::new();
    let marker = fixture.marker.clone();
    install_formal_marker_fixture(&fixture.root_path, &marker);
    let audit_directory = create_audit_directory(&fixture.root_path, &marker.recovery_id)
        .expect("create abort audit directory");

    let marker_staging = marker_staging_path(&fixture.root_path);
    std::fs::write(&marker_staging, b"interrupted-marker-staging")
        .expect("write marker staging residue");
    let database_staging = fixture
        .paths
        .staging(V031RecoveryComponent::UserDatabase)
        .expect("user database staging path")
        .to_path_buf();
    std::fs::write(&database_staging, b"interrupted-database-staging")
        .expect("write database staging residue");
    let commit_final = audit_directory.join(COMMIT_EVIDENCE_BASENAME);
    let (commit_incoming, commit_staging) = audit_evidence_transaction_paths(&commit_final);
    std::fs::write(&commit_incoming, b"interrupted-commit-incoming")
        .expect("write commit incoming residue");
    std::fs::write(&commit_staging, b"interrupted-commit-staging")
        .expect("write commit staging residue");

    let physical_before =
        capture_recovery_layout(&fixture.paths, 0).expect("capture pre-abort layout");
    let abort = audit_evidence(
        &marker,
        AuditEvidenceKind::AbortToCurrent,
        RecoveryPhase::Requested,
        restored_audit_slots(&marker.current_slots),
        0,
        true,
    );
    install_or_verify_audit_evidence(
        &fixture.root_path,
        &marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &abort,
    )
    .expect("install abort final before residue cleanup");

    let abort_final = audit_directory.join(ABORT_INTENT_BASENAME);
    assert_eq!(
        read_audit_evidence_file(&abort_final, &marker, AuditEvidenceKind::AbortToCurrent)
            .expect("abort final is authenticated at the crash boundary")
            .0,
        abort
    );
    assert!(marker_staging.exists());
    assert!(database_staging.exists());
    assert!(commit_incoming.exists());
    assert!(commit_staging.exists());
    let authority = authenticate_authoritative_marker_for_abort(
        &fixture.root_path,
        AbortMarkerExpectation::ForwardError(&marker),
    )
    .expect("restart authenticates and freezes the same formal marker");
    assert_eq!(authority.formal_marker, marker);
    assert!(audit_evidence_present_and_valid(
        &fixture.root_path,
        &marker,
        COMMIT_EVIDENCE_BASENAME,
        AuditEvidenceKind::FiveSlotCommit,
    )
    .expect("commit final absence is read independently of residue")
    .is_none());

    cleanup_precommit_residue_after_authenticated_abort(&fixture.root_path, &authority, &abort)
        .expect("authenticated abort final authorizes residue cleanup");
    assert!(!marker_staging.exists());
    assert!(!database_staging.exists());
    assert!(!commit_incoming.exists());
    assert!(!commit_staging.exists());
    assert!(abort_final.exists());
    assert_eq!(
        capture_recovery_layout(&fixture.paths, 0).expect("capture post-cleanup layout"),
        physical_before,
        "residue cleanup must precede and must not perform the first reverse slot mutation"
    );
}

#[test]
fn r3_authenticated_abort_final_keeps_formal_marker_and_discards_direct_successor() {
    let directory = tempfile::tempdir().expect("R3 abort successor fixture");
    let formal = requested_marker();
    let successor = marker_at_phase(&formal, RecoveryPhase::UserV10Staged);
    install_formal_marker_fixture(directory.path(), &formal);
    let (_, incoming_path) = marker_paths(directory.path());
    std::fs::write(
        &incoming_path,
        canonical_protected_marker(&successor).expect("protect direct successor"),
    )
    .expect("install interrupted direct successor incoming");
    let marker_staging = marker_staging_path(directory.path());
    std::fs::write(&marker_staging, b"non-authoritative inner staging")
        .expect("install marker inner staging residue");
    let authority = authenticate_authoritative_marker_for_abort(
        directory.path(),
        AbortMarkerExpectation::ForwardError(&formal),
    )
    .expect("freeze formal and direct-successor authority");
    create_audit_directory(directory.path(), &formal.recovery_id)
        .expect("create successor abort audit directory");
    let abort = audit_evidence(
        &formal,
        AuditEvidenceKind::AbortToCurrent,
        RecoveryPhase::Requested,
        restored_audit_slots(&formal.current_slots),
        0,
        true,
    );
    install_or_verify_audit_evidence(
        directory.path(),
        &formal,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &abort,
    )
    .expect("install abort final while successor remains staged");
    assert!(incoming_path.exists());
    assert!(marker_staging.exists());

    cleanup_precommit_residue_after_authenticated_abort(directory.path(), &authority, &abort)
        .expect("abort final authorizes discarding the direct successor");
    let (final_path, incoming_path) = marker_paths(directory.path());
    assert_eq!(
        read_marker(&final_path)
            .expect("formal marker remains authoritative")
            .0,
        formal
    );
    assert!(!incoming_path.exists());
    assert!(!marker_staging.exists());
    assert!(
        audit_evidence_path(directory.path(), &formal, ABORT_INTENT_BASENAME)
            .expect("fixed abort final path")
            .exists()
    );
}

#[test]
fn r3_abort_cleanup_proves_inner_staging_absent_before_successor_hash_failure() {
    let directory = tempfile::tempdir().expect("R3 ordered marker cleanup fixture");
    let formal = requested_marker();
    let successor = marker_at_phase(&formal, RecoveryPhase::UserV10Staged);
    install_formal_marker_fixture(directory.path(), &formal);
    let (_, incoming_path) = marker_paths(directory.path());
    std::fs::write(
        &incoming_path,
        canonical_protected_marker(&successor).expect("protect direct successor"),
    )
    .expect("install interrupted direct successor incoming");
    let marker_staging = marker_staging_path(directory.path());
    std::fs::write(&marker_staging, b"non-authoritative inner staging")
        .expect("install marker inner staging residue");
    let authority = authenticate_authoritative_marker_for_abort(
        directory.path(),
        AbortMarkerExpectation::ForwardError(&formal),
    )
    .expect("freeze direct-successor hash before cleanup");
    create_audit_directory(directory.path(), &formal.recovery_id)
        .expect("create ordered-cleanup audit directory");
    let abort = audit_evidence(
        &formal,
        AuditEvidenceKind::AbortToCurrent,
        formal.phase,
        restored_audit_slots(&formal.current_slots),
        0,
        true,
    );
    install_or_verify_audit_evidence(
        directory.path(),
        &formal,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &abort,
    )
    .expect("install durable abort final before cleanup");
    let frozen_successor_hash = authority
        .successor
        .as_ref()
        .expect("frozen direct successor")
        .protected_sha256
        .clone();
    rewrap_marker_with_distinct_ciphertext(&incoming_path, &successor, &frozen_successor_hash);

    assert!(cleanup_precommit_residue_after_authenticated_abort(
        directory.path(),
        &authority,
        &abort,
    )
    .is_err());
    assert!(
        !marker_staging.exists(),
        "inner staging is removed and proved absent before successor authentication"
    );
    assert!(
        incoming_path.exists(),
        "hash-drifted successor is never discarded after authentication fails"
    );
    assert!(
        audit_evidence_path(directory.path(), &formal, ABORT_INTENT_BASENAME)
            .expect("fixed abort final path")
            .exists(),
        "abort final remains durable across ordered cleanup failure"
    );
}

fn create_exact_v031_user_database(path: &Path) {
    let connection = rusqlite::Connection::open(path).expect("exact user-v10 fixture opens");
    let objects =
        include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .expect("frozen user-v10 schema object parses")
            })
            .collect::<Vec<_>>();
    for object_type in ["table", "index", "trigger", "view"] {
        for object in objects
            .iter()
            .filter(|object| object["object_type"] == object_type)
        {
            connection
                .execute_batch(object["sql"].as_str().expect("frozen schema SQL"))
                .expect("frozen user-v10 schema object executes");
        }
    }
    connection
        .execute(
            "INSERT INTO user_database_metadata(key,value,updated_at)
             VALUES('schema_version',?1,'2026-07-19 15:41:29')",
            [database::V031_USER_SCHEMA_VERSION.to_string()],
        )
        .expect("user-v10 schema version inserts");
    connection
        .execute(
            "INSERT INTO user_database_metadata(key,value,updated_at)
             VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
            [database::V031_USER_CANONICAL_SCHEMA_MARKER],
        )
        .expect("user-v10 canonical marker inserts");
}

fn create_exact_privacy_v1_database(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("Privacy-v1 fixture parent"))
        .expect("Privacy-v1 fixture parent creates");
    let connection = rusqlite::Connection::open(path).expect("Privacy-v1 fixture opens");
    connection
        .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
        .expect("frozen Privacy-v1 schema executes");
    connection
        .execute(
            "INSERT INTO privacy_schema_metadata(key,value,updated_at)
             VALUES('schema_version','1','2026-07-19 15:41:29')",
            [],
        )
        .expect("Privacy-v1 schema version inserts");
}

fn restored_observed_layout(current: &[V031RecoverySlotFingerprint; 5]) -> ObservedRecoveryLayout {
    ObservedRecoveryLayout {
        slots: std::array::from_fn(|index| ObservedRecoverySlot {
            active: Some(current[index].clone()),
            incoming: None,
            rollback: None,
            cleanup: None,
        }),
        credential_delete_prefix: 0,
    }
}

fn layout_to_audit_slots(layout: &ObservedRecoveryLayout) -> [RecoveryAuditSlotV1; 5] {
    std::array::from_fn(|index| RecoveryAuditSlotV1 {
        component: RECOVERY_COMPONENTS[index],
        active: layout.slots[index].active.clone(),
        incoming: layout.slots[index].incoming.clone(),
        rollback: layout.slots[index].rollback.clone(),
        cleanup: layout.slots[index].cleanup.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhysicalMutation {
    StageUser,
    StagePrivacy,
    MoveUser,
    InstallUser,
    MovePrivacy,
    InstallPrivacy,
    MoveVault,
    MoveApproved,
    MoveWorkProducts,
    StageWorkProductsCleanup,
    FinishWorkProductsCleanup,
    StageApprovedCleanup,
    FinishApprovedCleanup,
    StageVaultCleanup,
    FinishVaultCleanup,
    RemovePrivacyRollback,
    RemoveUserRollback,
    RemoveTicketSessions,
    RemoveQualificationAndParent,
}

impl PhysicalMutation {
    const ALL: [Self; 19] = [
        Self::StageUser,
        Self::StagePrivacy,
        Self::MoveUser,
        Self::InstallUser,
        Self::MovePrivacy,
        Self::InstallPrivacy,
        Self::MoveVault,
        Self::MoveApproved,
        Self::MoveWorkProducts,
        Self::StageWorkProductsCleanup,
        Self::FinishWorkProductsCleanup,
        Self::StageApprovedCleanup,
        Self::FinishApprovedCleanup,
        Self::StageVaultCleanup,
        Self::FinishVaultCleanup,
        Self::RemovePrivacyRollback,
        Self::RemoveUserRollback,
        Self::RemoveTicketSessions,
        Self::RemoveQualificationAndParent,
    ];
}

struct PhysicalRecoveryFixture {
    _root: tempfile::TempDir,
    _sources: tempfile::TempDir,
    root_path: PathBuf,
    paths: V031RecoverySwapPaths,
    marker: V031MigrationRecoveryPendingV1,
    user_target_bytes: Vec<u8>,
    privacy_target_bytes: Vec<u8>,
    target_slots: [Option<V031RecoverySlotFingerprint>; 5],
    expected: ObservedRecoveryLayout,
}

impl PhysicalRecoveryFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("R3 physical root");
        let sources = tempfile::tempdir().expect("R3 exact source root");
        let paths = v031_recovery_swap_paths(root.path());

        std::fs::write(
            paths.active(V031RecoveryComponent::UserDatabase),
            b"current-v040-user-slot",
        )
        .expect("current user slot");
        std::fs::create_dir_all(
            paths
                .active(V031RecoveryComponent::PrivacyDatabase)
                .parent()
                .expect("Privacy parent"),
        )
        .expect("Privacy parent creates");
        std::fs::write(
            paths.active(V031RecoveryComponent::PrivacyDatabase),
            b"current-v040-privacy-slot",
        )
        .expect("current Privacy slot");
        for component in [
            V031RecoveryComponent::VaultStore,
            V031RecoveryComponent::ApprovedWorkspace,
            V031RecoveryComponent::WorkProducts,
        ] {
            let active = paths.active(component);
            std::fs::create_dir_all(active).expect("current directory slot creates");
            std::fs::write(
                active.join("current-state.bin"),
                format!("current-v040-{}", component_wire(component)).as_bytes(),
            )
            .expect("current directory content");
        }
        for auxiliary in ["ticket-sessions", "qualification"] {
            let path = root.path().join("privacy/approved-mcp").join(auxiliary);
            std::fs::create_dir_all(&path).expect("auxiliary directory creates");
            std::fs::write(path.join("state.bin"), auxiliary.as_bytes())
                .expect("auxiliary content");
        }

        let current_slots = capture_v031_recovery_active_fingerprints(&paths)
            .expect("capture current five-slot identity");
        let expected = restored_observed_layout(&current_slots);
        let mut marker = requested_marker_with_slots(current_slots);

        let user_source = sources.path().join("user-v10.sqlite");
        let privacy_source = sources.path().join("privacy/privacy-v1.sqlite");
        create_exact_v031_user_database(&user_source);
        create_exact_privacy_v1_database(&privacy_source);
        let user_target_bytes = std::fs::read(&user_source).expect("read exact user v10");
        let privacy_target_bytes = std::fs::read(&privacy_source).expect("read exact Privacy v1");
        database::validate_v031_user_sqlite_image_read_only(&user_target_bytes)
            .expect("exact user-v10 bytes validate");
        privacy::validate_privacy_v1_sqlite_image_read_only(&privacy_target_bytes)
            .expect("exact Privacy-v1 bytes validate");
        marker.original_user_sha256 = sha256_hex(&user_target_bytes);
        marker.original_user_bytes = user_target_bytes.len() as u64;
        marker.original_privacy_sha256 = sha256_hex(&privacy_target_bytes);
        marker.original_privacy_bytes = privacy_target_bytes.len() as u64;
        validate_marker_static(&marker).expect("physical fixture marker");

        Self {
            root_path: root.path().to_path_buf(),
            paths,
            marker,
            user_target_bytes,
            privacy_target_bytes,
            target_slots: std::array::from_fn(|_| None),
            expected,
            _root: root,
            _sources: sources,
        }
    }

    fn target(&self, component: V031RecoveryComponent) -> V031RecoverySlotFingerprint {
        self.target_slots[component_index(component)]
            .clone()
            .expect("target fingerprint is staged")
    }

    fn apply_production(&mut self, mutation: PhysicalMutation) {
        match mutation {
            PhysicalMutation::StageUser => {
                let observed = ensure_target_database_incoming(
                    &self.paths,
                    V031RecoveryComponent::UserDatabase,
                    &self.user_target_bytes,
                    &self.marker.original_user_sha256,
                )
                .expect("stage exact user target");
                match &self.target_slots[0] {
                    Some(expected) => assert_eq!(&observed, expected),
                    None => self.target_slots[0] = Some(observed),
                }
            }
            PhysicalMutation::StagePrivacy => {
                let observed = ensure_target_database_incoming(
                    &self.paths,
                    V031RecoveryComponent::PrivacyDatabase,
                    &self.privacy_target_bytes,
                    &self.marker.original_privacy_sha256,
                )
                .expect("stage exact Privacy target");
                match &self.target_slots[1] {
                    Some(expected) => assert_eq!(&observed, expected),
                    None => self.target_slots[1] = Some(observed),
                }
            }
            PhysicalMutation::MoveUser => move_current_active_to_rollback(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::UserDatabase,
            )
            .expect("move user active to rollback"),
            PhysicalMutation::InstallUser => install_target_database_from_incoming(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::UserDatabase,
                &self.user_target_bytes,
                &self.marker.original_user_sha256,
            )
            .expect("install user target"),
            PhysicalMutation::MovePrivacy => move_current_active_to_rollback(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::PrivacyDatabase,
            )
            .expect("move Privacy active to rollback"),
            PhysicalMutation::InstallPrivacy => install_target_database_from_incoming(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::PrivacyDatabase,
                &self.privacy_target_bytes,
                &self.marker.original_privacy_sha256,
            )
            .expect("install Privacy target"),
            PhysicalMutation::MoveVault => move_current_active_to_rollback(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::VaultStore,
            )
            .expect("move Vault active to rollback"),
            PhysicalMutation::MoveApproved => move_current_active_to_rollback(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::ApprovedWorkspace,
            )
            .expect("move Approved active to rollback"),
            PhysicalMutation::MoveWorkProducts => move_current_active_to_rollback(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::WorkProducts,
            )
            .expect("move WorkProducts active to rollback"),
            PhysicalMutation::StageWorkProductsCleanup => stage_current_rollback_cleanup(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::WorkProducts,
            )
            .expect("stage WorkProducts cleanup tombstone"),
            PhysicalMutation::FinishWorkProductsCleanup => {
                finish_directory_cleanup_tombstone(&self.paths, V031RecoveryComponent::WorkProducts)
                    .expect("finish WorkProducts cleanup tombstone")
            }
            PhysicalMutation::StageApprovedCleanup => stage_current_rollback_cleanup(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::ApprovedWorkspace,
            )
            .expect("stage Approved cleanup tombstone"),
            PhysicalMutation::FinishApprovedCleanup => finish_directory_cleanup_tombstone(
                &self.paths,
                V031RecoveryComponent::ApprovedWorkspace,
            )
            .expect("finish Approved cleanup tombstone"),
            PhysicalMutation::StageVaultCleanup => stage_current_rollback_cleanup(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::VaultStore,
            )
            .expect("stage Vault cleanup tombstone"),
            PhysicalMutation::FinishVaultCleanup => {
                finish_directory_cleanup_tombstone(&self.paths, V031RecoveryComponent::VaultStore)
                    .expect("finish partially deleted Vault tombstone")
            }
            PhysicalMutation::RemovePrivacyRollback => stage_current_rollback_cleanup(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::PrivacyDatabase,
            )
            .expect("remove Privacy rollback"),
            PhysicalMutation::RemoveUserRollback => stage_current_rollback_cleanup(
                &self.paths,
                &self.marker,
                V031RecoveryComponent::UserDatabase,
            )
            .expect("remove user rollback"),
            PhysicalMutation::RemoveTicketSessions => {
                remove_v031_recovery_auxiliary_directory(&self.root_path, "ticket-sessions")
                    .expect("remove fixed ticket-sessions directory")
            }
            PhysicalMutation::RemoveQualificationAndParent => {
                remove_v031_recovery_auxiliary_directory(&self.root_path, "qualification")
                    .expect("remove fixed qualification directory");
                remove_v031_recovery_approved_parent_if_empty(&self.root_path)
                    .expect("remove empty Approved parent");
            }
        }
    }

    fn advance_model(&mut self, mutation: PhysicalMutation) {
        let user = component_index(V031RecoveryComponent::UserDatabase);
        let privacy = component_index(V031RecoveryComponent::PrivacyDatabase);
        let vault = component_index(V031RecoveryComponent::VaultStore);
        let approved = component_index(V031RecoveryComponent::ApprovedWorkspace);
        let work = component_index(V031RecoveryComponent::WorkProducts);
        match mutation {
            PhysicalMutation::StageUser => {
                self.expected.slots[user].incoming =
                    Some(self.target(V031RecoveryComponent::UserDatabase));
            }
            PhysicalMutation::StagePrivacy => {
                self.expected.slots[privacy].incoming =
                    Some(self.target(V031RecoveryComponent::PrivacyDatabase));
            }
            PhysicalMutation::MoveUser => {
                self.expected.slots[user].active = None;
                self.expected.slots[user].rollback = Some(self.marker.current_slots[user].clone());
            }
            PhysicalMutation::InstallUser => {
                self.expected.slots[user].active =
                    Some(self.target(V031RecoveryComponent::UserDatabase));
                self.expected.slots[user].incoming = None;
            }
            PhysicalMutation::MovePrivacy => {
                self.expected.slots[privacy].active = None;
                self.expected.slots[privacy].rollback =
                    Some(self.marker.current_slots[privacy].clone());
            }
            PhysicalMutation::InstallPrivacy => {
                self.expected.slots[privacy].active =
                    Some(self.target(V031RecoveryComponent::PrivacyDatabase));
                self.expected.slots[privacy].incoming = None;
            }
            PhysicalMutation::MoveVault => {
                self.expected.slots[vault].active = None;
                self.expected.slots[vault].rollback =
                    Some(self.marker.current_slots[vault].clone());
            }
            PhysicalMutation::MoveApproved => {
                self.expected.slots[approved].active = None;
                self.expected.slots[approved].rollback =
                    Some(self.marker.current_slots[approved].clone());
            }
            PhysicalMutation::MoveWorkProducts => {
                self.expected.slots[work].active = None;
                self.expected.slots[work].rollback = Some(self.marker.current_slots[work].clone());
            }
            PhysicalMutation::StageWorkProductsCleanup => {
                self.expected.slots[work].rollback = None;
                self.expected.slots[work].cleanup = Some(self.marker.current_slots[work].clone());
            }
            PhysicalMutation::FinishWorkProductsCleanup => {
                self.expected.slots[work].cleanup = None;
            }
            PhysicalMutation::StageApprovedCleanup => {
                self.expected.slots[approved].rollback = None;
                self.expected.slots[approved].cleanup =
                    Some(self.marker.current_slots[approved].clone());
            }
            PhysicalMutation::FinishApprovedCleanup => {
                self.expected.slots[approved].cleanup = None;
            }
            PhysicalMutation::StageVaultCleanup => {
                self.expected.slots[vault].rollback = None;
                self.expected.slots[vault].cleanup = Some(self.marker.current_slots[vault].clone());
            }
            PhysicalMutation::FinishVaultCleanup => {
                self.expected.slots[vault].cleanup = None;
            }
            PhysicalMutation::RemovePrivacyRollback => {
                self.expected.slots[privacy].rollback = None;
            }
            PhysicalMutation::RemoveUserRollback => {
                self.expected.slots[user].rollback = None;
            }
            PhysicalMutation::RemoveTicketSessions
            | PhysicalMutation::RemoveQualificationAndParent => {}
        }
    }

    fn actual(&self) -> ObservedRecoveryLayout {
        capture_recovery_layout(&self.paths, 0).expect("capture exact physical R3 layout")
    }
}

#[test]
fn r3_forward_and_postcommit_physical_crash_matrix_replays_every_atomic_action() {
    let mut fixture = PhysicalRecoveryFixture::new();
    assert_eq!(fixture.actual(), fixture.expected);

    for mutation in PhysicalMutation::ALL {
        fixture.apply_production(mutation);
        fixture.advance_model(mutation);
        let after = fixture.actual();
        assert_eq!(
            after, fixture.expected,
            "exact physical state after {mutation:?}"
        );

        fixture.apply_production(mutation);
        assert_eq!(
            fixture.actual(),
            after,
            "replay after crash boundary {mutation:?} is idempotent"
        );

        if mutation == PhysicalMutation::MoveWorkProducts {
            let slots = layout_to_audit_slots(&after);
            assert!(audit_inventory_shape_matches_kind(
                &fixture.marker.current_slots,
                AuditEvidenceKind::FiveSlotCommit,
                &slots,
            ));
            assert!(database_target_fingerprints_match(
                &slots,
                &fixture.target(V031RecoveryComponent::UserDatabase),
                &fixture.target(V031RecoveryComponent::PrivacyDatabase),
            ));
        }

        if mutation == PhysicalMutation::StageVaultCleanup {
            let cleanup = fixture
                .paths
                .cleanup(V031RecoveryComponent::VaultStore)
                .expect("Vault cleanup path");
            std::fs::remove_file(cleanup.join("current-state.bin"))
                .expect("simulate a crash after partial tombstone deletion");
        }
    }

    let terminal = fixture.actual();
    let terminal_slots = layout_to_audit_slots(&terminal);
    assert!(audit_inventory_shape_matches_kind(
        &fixture.marker.current_slots,
        AuditEvidenceKind::AppliedDowngrade,
        &terminal_slots,
    ));
    assert!(database_target_fingerprints_match(
        &terminal_slots,
        &fixture.target(V031RecoveryComponent::UserDatabase),
        &fixture.target(V031RecoveryComponent::PrivacyDatabase),
    ));
    assert!(!fixture
        .root_path
        .join("privacy/approved-mcp/ticket-sessions")
        .exists());
    assert!(!fixture
        .root_path
        .join("privacy/approved-mcp/qualification")
        .exists());
    assert!(!fixture.root_path.join("privacy/approved-mcp").exists());
    assert!(!database_staging_present(&fixture.paths).expect("database staging proof"));
}

fn apply_forward_layout_phase(
    layout: &mut ObservedRecoveryLayout,
    phase: RecoveryPhase,
    current: &[V031RecoverySlotFingerprint; 5],
    target: &[V031RecoverySlotFingerprint; 5],
) {
    let user = component_index(V031RecoveryComponent::UserDatabase);
    let privacy = component_index(V031RecoveryComponent::PrivacyDatabase);
    let vault = component_index(V031RecoveryComponent::VaultStore);
    let approved = component_index(V031RecoveryComponent::ApprovedWorkspace);
    let work = component_index(V031RecoveryComponent::WorkProducts);
    match phase {
        RecoveryPhase::Requested => {}
        RecoveryPhase::UserV10Staged => {
            layout.slots[user].incoming = Some(target[user].clone());
        }
        RecoveryPhase::SourcesStaged => {
            layout.slots[privacy].incoming = Some(target[privacy].clone());
        }
        RecoveryPhase::CommitReady => {}
        RecoveryPhase::UserMovedToRollback => {
            layout.slots[user].active = None;
            layout.slots[user].rollback = Some(current[user].clone());
        }
        RecoveryPhase::UserInstalled => {
            layout.slots[user].active = Some(target[user].clone());
            layout.slots[user].incoming = None;
        }
        RecoveryPhase::PrivacyMovedToRollback => {
            layout.slots[privacy].active = None;
            layout.slots[privacy].rollback = Some(current[privacy].clone());
        }
        RecoveryPhase::PrivacyInstalled => {
            layout.slots[privacy].active = Some(target[privacy].clone());
            layout.slots[privacy].incoming = None;
        }
        RecoveryPhase::VaultMovedToRollback => {
            layout.slots[vault].active = None;
            layout.slots[vault].rollback = Some(current[vault].clone());
        }
        RecoveryPhase::ApprovedMovedToRollback => {
            layout.slots[approved].active = None;
            layout.slots[approved].rollback = Some(current[approved].clone());
        }
        RecoveryPhase::WorkProductsMovedToRollback => {
            layout.slots[work].active = None;
            layout.slots[work].rollback = Some(current[work].clone());
        }
        _ => panic!("{phase:?} is not a precommit forward-layout phase"),
    }
}

fn legal_reverse_prefixes(
    initial: &ObservedRecoveryLayout,
    current: &[V031RecoverySlotFingerprint; 5],
) -> Vec<ObservedRecoveryLayout> {
    let mut state = initial.clone();
    let mut prefixes = vec![state.clone()];
    for component in [
        V031RecoveryComponent::WorkProducts,
        V031RecoveryComponent::ApprovedWorkspace,
        V031RecoveryComponent::VaultStore,
        V031RecoveryComponent::PrivacyDatabase,
        V031RecoveryComponent::UserDatabase,
    ] {
        let index = component_index(component);
        if state.slots[index].rollback.as_ref() == Some(&current[index]) {
            if matches!(
                component,
                V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
            ) && state.slots[index].active.is_some()
            {
                state.slots[index].active = None;
                prefixes.push(state.clone());
            }
            state.slots[index].active = Some(current[index].clone());
            state.slots[index].rollback = None;
            prefixes.push(state.clone());
        }
        if matches!(
            component,
            V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
        ) && state.slots[index].incoming.is_some()
        {
            state.slots[index].incoming = None;
            prefixes.push(state.clone());
        }
    }
    prefixes.dedup();
    prefixes
}

fn fully_restore_component_out_of_order(
    layout: &mut ObservedRecoveryLayout,
    current: &[V031RecoverySlotFingerprint; 5],
    component: V031RecoveryComponent,
) {
    let index = component_index(component);
    layout.slots[index].active = Some(current[index].clone());
    layout.slots[index].rollback = None;
    if matches!(
        component,
        V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
    ) {
        layout.slots[index].incoming = None;
    }
}

#[test]
fn r3_precommit_abort_crash_matrix_accepts_only_exact_reverse_prefixes() {
    let current = fingerprints("abort-current");
    let target = fingerprints("abort-target");
    let mut forward = restored_observed_layout(&current);
    let precommit_phases = PHASE_WIRE
        .iter()
        .map(|entry| entry.0)
        .take_while(|phase| *phase != RecoveryPhase::FiveSlotCommitted)
        .collect::<Vec<_>>();

    for phase in precommit_phases {
        apply_forward_layout_phase(&mut forward, phase, &current, &target);
        let intent_layout = forward.clone();
        let marker = marker_at_phase(&requested_marker_with_slots(current.clone()), phase);
        let intent_evidence = audit_evidence(
            &marker,
            AuditEvidenceKind::AbortToCurrent,
            phase,
            layout_to_audit_slots(&intent_layout),
            0,
            true,
        );
        let legal = legal_reverse_prefixes(&intent_layout, &current);
        for (prefix, candidate) in legal.iter().enumerate() {
            assert!(
                abort_layout_is_legal_reverse_prefix(candidate, &intent_evidence, &marker)
                    .unwrap_or_else(|error| panic!(
                        "legal abort prefix {prefix} for {phase:?}: {}",
                        error.error_type
                    )),
                "legal abort prefix {prefix} for {phase:?}"
            );
        }
        assert_eq!(
            legal.last().expect("at least the intent layout"),
            &restored_observed_layout(&current),
            "abort terminal state for {phase:?}"
        );

        for (prefix, accepted) in legal.iter().enumerate() {
            let mut foreign_cleanup = accepted.clone();
            foreign_cleanup.slots[component_index(V031RecoveryComponent::VaultStore)].cleanup =
                Some(fingerprint(
                    V031RecoveryComponent::VaultStore,
                    "foreign-cleanup",
                ));
            assert!(
                !matches!(
                    abort_layout_is_legal_reverse_prefix(
                        &foreign_cleanup,
                        &intent_evidence,
                        &marker,
                    ),
                    Ok(true)
                ),
                "foreign cleanup at prefix {prefix} for {phase:?}"
            );

            let mut deleted_credential = accepted.clone();
            deleted_credential.credential_delete_prefix = 1;
            assert!(
                !matches!(
                    abort_layout_is_legal_reverse_prefix(
                        &deleted_credential,
                        &intent_evidence,
                        &marker,
                    ),
                    Ok(true)
                ),
                "credential mutation at prefix {prefix} for {phase:?}"
            );
        }

        let moved = [
            V031RecoveryComponent::WorkProducts,
            V031RecoveryComponent::ApprovedWorkspace,
            V031RecoveryComponent::VaultStore,
            V031RecoveryComponent::PrivacyDatabase,
            V031RecoveryComponent::UserDatabase,
        ]
        .into_iter()
        .filter(|component| {
            let index = component_index(*component);
            intent_layout.slots[index].rollback.as_ref() == Some(&current[index])
        })
        .collect::<Vec<_>>();
        if moved.len() >= 2 {
            let mut out_of_order = intent_layout.clone();
            fully_restore_component_out_of_order(&mut out_of_order, &current, moved[1]);
            assert!(
                !matches!(
                    abort_layout_is_legal_reverse_prefix(&out_of_order, &intent_evidence, &marker),
                    Ok(true)
                ),
                "{phase:?} cannot restore a later component before {:?}",
                moved[0]
            );
        }
        let user = component_index(V031RecoveryComponent::UserDatabase);
        let privacy = component_index(V031RecoveryComponent::PrivacyDatabase);
        if intent_layout.slots[user].incoming.is_some()
            && intent_layout.slots[privacy].incoming.is_some()
        {
            let mut wrong_incoming_order = intent_layout.clone();
            wrong_incoming_order.slots[user].incoming = None;
            assert!(
                !matches!(
                    abort_layout_is_legal_reverse_prefix(
                        &wrong_incoming_order,
                        &intent_evidence,
                        &marker,
                    ),
                    Ok(true)
                ),
                "Privacy incoming must be removed before user incoming for {phase:?}"
            );
        }
    }
}

#[test]
fn r3_credential_delete_prefix_is_frozen_to_the_four_postcommit_phases() {
    for (phase, _) in PHASE_WIRE {
        let expected = match phase {
            RecoveryPhase::CredentialQualificationDeleted => 1,
            RecoveryPhase::CredentialTicketDeleted => 2,
            RecoveryPhase::CredentialWorkProductDeleted => 3,
            RecoveryPhase::CredentialApprovedDeleted
            | RecoveryPhase::TargetVerified
            | RecoveryPhase::ReportInstalled => 4,
            _ => 0,
        };
        assert_eq!(
            expected_credential_delete_prefix(phase),
            expected,
            "credential prefix at {phase:?}"
        );
    }
}

#[test]
fn r3_stage_request_and_recovery_namespace_accept_no_extra_authority() {
    let exact: StageV031MigrationRecoveryRequest = serde_json::from_value(serde_json::json!({
        "confirmation": V031_MIGRATION_RECOVERY_CONFIRMATION,
    }))
    .expect("exact stage request wire");
    assert_eq!(exact.confirmation, V031_MIGRATION_RECOVERY_CONFIRMATION);

    for extra in [
        ("path", serde_json::json!("C:\\rollback.lavbackup")),
        (
            "lineageId",
            serde_json::json!(protocol_hash("caller-lineage")),
        ),
        ("privacyCaseId", serde_json::json!("case_private")),
        ("credential", serde_json::json!("caller-secret")),
        ("backupBytes", serde_json::json!([1, 2, 3])),
    ] {
        let mut request = serde_json::json!({
            "confirmation": V031_MIGRATION_RECOVERY_CONFIRMATION,
        });
        request
            .as_object_mut()
            .expect("stage request object")
            .insert(extra.0.to_owned(), extra.1);
        assert!(
            serde_json::from_value::<StageV031MigrationRecoveryRequest>(request).is_err(),
            "caller-supplied {} must be rejected by the command wire",
            extra.0
        );
    }
    for wrong_confirmation in [
        "",
        "恢复到v0.3.1并退出当前应用",
        "恢复到 v0.3.1 并退出当前应用 ",
        "恢复到 v0.3.1 并重启当前应用",
    ] {
        let request: StageV031MigrationRecoveryRequest =
            serde_json::from_value(serde_json::json!({
                "confirmation": wrong_confirmation,
            }))
            .expect("wrong confirmation remains a structurally valid request");
        assert_ne!(request.confirmation, V031_MIGRATION_RECOVERY_CONFIRMATION);
    }

    let valid = format!("rcv_{}", "0123456789abcdef".repeat(2));
    assert!(valid_recovery_id(&valid));
    for invalid in [
        format!("rcv_{}", "0".repeat(31)),
        format!("rcv_{}", "0".repeat(33)),
        format!("rcv_{}", "A".repeat(32)),
        format!("rcv_{}", "g".repeat(32)),
        "recovery_0123456789abcdef0123456789abcdef".to_owned(),
        "rcv_../../escape".to_owned(),
    ] {
        assert!(!valid_recovery_id(&invalid), "reject recovery id {invalid}");
    }

    let root = tempfile::tempdir().expect("R3 namespace root");
    assert_eq!(
        audit_directory(root.path(), &valid).expect("canonical audit directory"),
        root.path().join(RECOVERY_AUDIT_DIRECTORY).join(&valid)
    );
    assert!(audit_directory(root.path(), "rcv_../../escape").is_err());
    let marker = requested_marker();
    for basename in [
        COMMIT_EVIDENCE_BASENAME,
        ABORT_INTENT_BASENAME,
        APPLIED_REPORT_BASENAME,
        ABORTED_REPORT_BASENAME,
    ] {
        assert_eq!(
            audit_evidence_path(root.path(), &marker, basename).expect("fixed audit evidence path"),
            root.path()
                .join(RECOVERY_AUDIT_DIRECTORY)
                .join(&marker.recovery_id)
                .join(basename)
        );
    }
    for basename in [
        "../five-slot-commit.evidence.dpapi",
        "unknown.evidence.dpapi",
        "five-slot-commit.evidence.dpapi.incoming",
    ] {
        assert!(audit_evidence_path(root.path(), &marker, basename).is_err());
    }
}

#[test]
fn r3_completed_audit_namespace_does_not_claim_recovery_or_ordinary_restore_slots() {
    let directory = tempfile::tempdir().expect("completed R3 audit fixture");
    let recovery_id = format!("rcv_{}", "5".repeat(32));
    let audit = directory
        .path()
        .join(RECOVERY_AUDIT_DIRECTORY)
        .join(recovery_id);
    std::fs::create_dir_all(&audit).expect("completed audit directory");
    for basename in [
        SAFETY_BACKUP_BASENAME,
        CREDENTIAL_ARCHIVE_BASENAME,
        COMMIT_EVIDENCE_BASENAME,
        APPLIED_REPORT_BASENAME,
    ] {
        std::fs::write(
            audit.join(basename),
            format!("retained-{basename}").as_bytes(),
        )
        .expect("retained audit file");
    }
    let before = snapshot_tree(directory.path());

    match observe_v031_migration_recovery_read_only(directory.path())
        .expect("completed audit has no R3 authority")
    {
        V031MigrationRecoveryObservation::Absent => {}
        V031MigrationRecoveryObservation::Authenticated(_) => {
            panic!("retained audit material cannot impersonate a formal marker")
        }
    }
    reject_unknown_v031_recovery_restore_siblings(directory.path())
        .expect("audit namespace is outside fixed restore siblings");
    match crate::commands::application_backup::observe_pending_application_restore_read_only(
        directory.path(),
    )
    .expect("ordinary V3 observer remains available")
    {
        crate::commands::application_backup::PendingApplicationRestoreObservation::Absent => {}
        crate::commands::application_backup::PendingApplicationRestoreObservation::Authenticated(
            _,
        ) => panic!("retained R3 audit cannot become an ordinary V3 restore marker"),
    }
    assert_eq!(
        snapshot_tree(directory.path()),
        before,
        "startup arbitration must retain completed audit bytes unchanged"
    );
}

#[test]
fn r3_migration_only_v2_and_old_schema_v3_are_rejected_by_ordinary_restore() {
    use privacy::original_rollback_v2::{
        create_v031_original_rollback_identity_v2, protect_v031_original_rollback_identity_v2,
        seal_v031_original_rollback_v2, V031OriginalRollbackCreateRequest,
    };

    let source_profile = protocol_hash("v031-source-profile");
    let user_physical = protocol_hash("v031-user-physical");
    let privacy_physical = protocol_hash("v031-privacy-physical");
    let user_logical = protocol_hash("v031-user-logical");
    let user_business = protocol_hash("v031-user-business");
    let privacy_logical = protocol_hash("v031-privacy-logical");
    let privacy_business = protocol_hash("v031-privacy-business");
    let lineage = protocol_hash("v031-lineage");
    let original_request = V031OriginalRollbackCreateRequest {
        source_profile_proof_sha256: &source_profile,
        source_user_physical_file_set_sha256: &user_physical,
        source_privacy_physical_file_set_sha256: &privacy_physical,
        source_user_logical_manifest_sha256: &user_logical,
        source_user_business_manifest_sha256: &user_business,
        source_privacy_logical_manifest_sha256: &privacy_logical,
        source_privacy_business_manifest_sha256: &privacy_business,
        envelope_binding_id: "ws_0123456789abcdef0123456789abcdef",
        lineage_id: &lineage,
        created_at_unix: 1_754_000_000,
        user_database: b"SQLite format 3\0R3-ORIGINAL-USER",
        privacy_store: b"SQLite format 3\0R3-ORIGINAL-PRIVACY",
    };
    let (original_bundle, original_metadata) =
        seal_v031_original_rollback_v2(&original_request).expect("seal migration-only V2");
    let original_identity = create_v031_original_rollback_identity_v2(&original_metadata)
        .expect("create migration-only V2 identity");
    let protected_identity = protect_v031_original_rollback_identity_v2(&original_identity)
        .expect("protect migration-only V2 identity");

    let workspace =
        privacy::vnext::WorkspaceInstanceId::parse("ws_99999999999999999999999999999999")
            .expect("ordinary restore workspace");
    let ordinary_context = privacy::ApplicationBackupOpenContext {
        expected_workspace_instance_id: &workspace,
        expected_app_version: CREATOR_APP_VERSION,
        expected_user_schema_version: database::USER_SCHEMA_VERSION,
        now_unix: 1_754_000_001,
    };
    assert_eq!(
        privacy::open_application_backup(&original_bundle, &ordinary_context),
        Err(privacy::ApplicationBackupError::UnsupportedSchema),
        "ordinary V3 restore must reject the independent Original V2 envelope"
    );
    assert_eq!(
        privacy::open_application_backup(&protected_identity, &ordinary_context),
        Err(privacy::ApplicationBackupError::Tampered),
        "ordinary V3 restore must reject opaque DPAPI migration-only identity bytes"
    );

    let vault_manifest = protocol_hash("old-schema-vault-manifest");
    let approved_manifest = protocol_hash("old-schema-approved-manifest");
    let work_manifest = protocol_hash("old-schema-work-manifest");
    let old_schema_request = privacy::ApplicationBackupCreateRequestV3 {
        backup_id: "appbkp_66666666666666666666666666666666",
        privacy_backup_id: "bkp_77777777777777777777777777777777",
        workspace_instance_id: &workspace,
        app_version: CREATOR_APP_VERSION,
        user_schema_version: database::V031_USER_SCHEMA_VERSION,
        created_at_unix: 1_754_000_000,
        expires_at_unix: 1_754_086_400,
        user_database: b"SQLite format 3\0OLD-SCHEMA-USER",
        encrypted_privacy_bundle: b"OLD-SCHEMA-PRIVACY",
        encrypted_vault_bundle: b"OLD-SCHEMA-VAULT",
        vault_manifest_sha256: &vault_manifest,
        approved_workspace_bundle: b"OLD-SCHEMA-APPROVED",
        approved_workspace_manifest_sha256: &approved_manifest,
        work_products_bundle: b"OLD-SCHEMA-WORK",
        work_products_manifest_sha256: &work_manifest,
    };
    let (old_schema_v3, old_schema_metadata) =
        privacy::seal_application_backup_v3(&old_schema_request).expect("seal old-schema V3");
    assert_eq!(
        privacy::open_application_backup(&old_schema_v3, &ordinary_context),
        Err(privacy::ApplicationBackupError::EnvironmentMismatch),
        "ordinary restore cannot relax its current user-schema requirement"
    );
    let migration_open = privacy::open_application_backup_for_migration_recovery(
        &old_schema_v3,
        &privacy::MigrationApplicationBackupOpenContext {
            expected_workspace_instance_id: &workspace,
            expected_user_schema_version: database::V031_USER_SCHEMA_VERSION,
            expected_backup_id: old_schema_request.backup_id,
            expected_privacy_backup_id: old_schema_request.privacy_backup_id,
            expected_app_version: old_schema_request.app_version,
            expected_created_at_unix: old_schema_request.created_at_unix,
            expected_expires_at_unix: old_schema_request.expires_at_unix,
            expected_bundle_sha256: &old_schema_metadata.bundle_sha256,
        },
    )
    .expect("only the migration-specific V3 opener may authenticate the old schema");
    assert_eq!(migration_open.metadata, old_schema_metadata);
}
