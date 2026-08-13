use crate::v031_upgrade_r2::{
    self, AuthenticatedLineageInventory, AuthenticatedReceiptFile, AuthenticatedReceiptMetadata,
    PlatformDirectorySync, R2InfrastructureError, ReceiptAuthenticationBridge, ReceiptExpectation,
};
use privacy::upgrade_receipt_v1::{
    discover_v031_upgrade_receipt_chain_context_v1, open_v031_upgrade_receipt_v1,
    seal_v031_upgrade_receipt_v1, V031UpgradeReceiptChainContext, V031UpgradeReceiptCountKey,
    V031UpgradeReceiptCreateRequest, V031UpgradeReceiptError, V031UpgradeReceiptStage,
};
use std::{
    collections::BTreeMap,
    fmt,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedV031ReceiptContext {
    pub(crate) lineage_id: String,
    pub(crate) envelope_binding_id: String,
    pub(crate) source_profile_proof_sha256: String,
}

impl OwnedV031ReceiptContext {
    pub(crate) fn as_borrowed(&self) -> V031UpgradeReceiptChainContext<'_> {
        V031UpgradeReceiptChainContext {
            lineage_id: &self.lineage_id,
            envelope_binding_id: &self.envelope_binding_id,
            source_profile_proof_sha256: &self.source_profile_proof_sha256,
        }
    }
}

#[derive(Debug)]
pub(crate) enum V031ReceiptPersistenceError {
    Codec(V031UpgradeReceiptError),
    Infrastructure,
    ContextUnavailable,
    ContextConflict,
    EvidenceConflict,
    Clock,
    Encoding,
}

impl V031ReceiptPersistenceError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.code(),
            Self::Infrastructure => "v031_upgrade_receipt_filesystem_failed",
            Self::ContextUnavailable => "v031_upgrade_receipt_context_unavailable",
            Self::ContextConflict => "v031_upgrade_receipt_context_conflict",
            Self::EvidenceConflict => "v031_upgrade_receipt_evidence_conflict",
            Self::Clock => "v031_upgrade_receipt_clock_unavailable",
            Self::Encoding => "v031_upgrade_receipt_metadata_encoding_failed",
        }
    }
}

impl fmt::Display for V031ReceiptPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031ReceiptPersistenceError {}

impl From<V031UpgradeReceiptError> for V031ReceiptPersistenceError {
    fn from(error: V031UpgradeReceiptError) -> Self {
        Self::Codec(error)
    }
}

impl From<R2InfrastructureError> for V031ReceiptPersistenceError {
    fn from(_: R2InfrastructureError) -> Self {
        Self::Infrastructure
    }
}

pub(crate) struct PrivacyReceiptAuthenticationBridge {
    context: Mutex<Option<OwnedV031ReceiptContext>>,
}

impl PrivacyReceiptAuthenticationBridge {
    pub(crate) fn new(context: OwnedV031ReceiptContext) -> Self {
        Self {
            context: Mutex::new(Some(context)),
        }
    }

    pub(crate) fn discovering() -> Self {
        Self {
            context: Mutex::new(None),
        }
    }

    pub(crate) fn context(&self) -> Result<OwnedV031ReceiptContext, V031ReceiptPersistenceError> {
        self.context
            .lock()
            .map_err(|_| V031ReceiptPersistenceError::ContextUnavailable)?
            .clone()
            .ok_or(V031ReceiptPersistenceError::ContextUnavailable)
    }

    fn authenticate(
        &self,
        protected_file_bytes: &[u8],
        expectation: ReceiptExpectation<'_>,
    ) -> Result<AuthenticatedReceiptMetadata, V031ReceiptPersistenceError> {
        let stage = V031UpgradeReceiptStage::from_ordinal(expectation.descriptor.ordinal)
            .filter(|stage| stage.as_str() == expectation.descriptor.stage)
            .ok_or(V031ReceiptPersistenceError::EvidenceConflict)?;

        let context = {
            let mut guard = self
                .context
                .lock()
                .map_err(|_| V031ReceiptPersistenceError::ContextUnavailable)?;
            if guard.is_none() {
                if stage != V031UpgradeReceiptStage::SourcePreflightVerified
                    || expectation.previous_receipt_sha256.is_some()
                {
                    return Err(V031ReceiptPersistenceError::ContextUnavailable);
                }
                let discovered = discover_v031_upgrade_receipt_chain_context_v1(
                    protected_file_bytes,
                    expectation.lineage_id,
                )?;
                let borrowed = discovered.as_borrowed();
                *guard = Some(OwnedV031ReceiptContext {
                    lineage_id: borrowed.lineage_id.to_owned(),
                    envelope_binding_id: borrowed.envelope_binding_id.to_owned(),
                    source_profile_proof_sha256: borrowed.source_profile_proof_sha256.to_owned(),
                });
            }
            guard
                .clone()
                .ok_or(V031ReceiptPersistenceError::ContextUnavailable)?
        };
        if context.lineage_id != expectation.lineage_id {
            return Err(V031ReceiptPersistenceError::ContextConflict);
        }
        let receipt = open_v031_upgrade_receipt_v1(
            protected_file_bytes,
            context.as_borrowed(),
            stage,
            expectation.previous_receipt_sha256,
        )?;
        let created_at_unix = i64::try_from(receipt.created_at_unix())
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)?;
        Ok(AuthenticatedReceiptMetadata {
            schema_version: privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_SCHEMA_VERSION
                .to_owned(),
            migration_id: privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
            lineage_id: context.lineage_id,
            envelope_binding_id: context.envelope_binding_id,
            ordinal: stage.ordinal(),
            stage: stage.as_str().to_owned(),
            previous_receipt_sha256: receipt.previous_receipt_sha256().map(str::to_owned),
            source_profile_proof_sha256: context.source_profile_proof_sha256,
            evidence_schema_version: receipt.evidence_schema_version().to_owned(),
            evidence_sha256: receipt.evidence_sha256().to_owned(),
            counts: receipt
                .counts()
                .iter()
                .map(|(key, value)| Ok((count_key_name(*key)?, *value)))
                .collect::<Result<BTreeMap<_, _>, V031ReceiptPersistenceError>>()?,
            created_at_unix,
            result_code: privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_RESULT_CODE.to_owned(),
        })
    }
}

impl ReceiptAuthenticationBridge for PrivacyReceiptAuthenticationBridge {
    type Error = V031ReceiptPersistenceError;

    fn authenticate_protected_receipt(
        &self,
        protected_file_bytes: &[u8],
        expectation: ReceiptExpectation<'_>,
    ) -> Result<AuthenticatedReceiptMetadata, Self::Error> {
        self.authenticate(protected_file_bytes, expectation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedV031Receipt {
    pub(crate) receipt: AuthenticatedReceiptFile,
    pub(crate) newly_installed: bool,
}

pub(crate) fn load_authenticated_v031_lineage(
    app_local_data_dir: &Path,
    lineage_id: &str,
    bridge: &PrivacyReceiptAuthenticationBridge,
) -> Result<AuthenticatedLineageInventory, V031ReceiptPersistenceError> {
    Ok(v031_upgrade_r2::enumerate_and_authenticate_lineage(
        app_local_data_dir,
        lineage_id,
        bridge,
    )?)
}

pub(crate) fn persist_v031_receipt(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    evidence_sha256: &str,
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    verify_live_state: impl Fn() -> Result<(), V031ReceiptPersistenceError>,
) -> Result<PersistedV031Receipt, V031ReceiptPersistenceError> {
    persist_v031_receipt_with_clock(
        app_local_data_dir,
        context,
        stage,
        evidence_sha256,
        counts,
        verify_live_state,
        unix_now,
    )
}

fn persist_v031_receipt_with_clock(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    evidence_sha256: &str,
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    verify_live_state: impl Fn() -> Result<(), V031ReceiptPersistenceError>,
    read_clock: impl FnOnce() -> Result<u64, V031ReceiptPersistenceError>,
) -> Result<PersistedV031Receipt, V031ReceiptPersistenceError> {
    verify_live_state()?;
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)?;
    let ordinal = usize::from(stage.ordinal());
    let expected_counts = counts
        .iter()
        .map(|(key, value)| Ok((count_key_name(*key)?, *value)))
        .collect::<Result<BTreeMap<_, _>, V031ReceiptPersistenceError>>()?;

    if let Some(existing) = inventory.final_receipts.get(ordinal) {
        validate_expected_metadata(existing, context, stage, evidence_sha256, &expected_counts)?;
        verify_live_state()?;
        return Ok(PersistedV031Receipt {
            receipt: existing.clone(),
            newly_installed: false,
        });
    }
    if inventory.final_receipts.len() != ordinal {
        return Err(V031ReceiptPersistenceError::EvidenceConflict);
    }
    let previous_sha256 = inventory
        .final_receipts
        .last()
        .map(|receipt| receipt.protected_file_sha256.as_str());

    let protected_bytes = if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
        validate_expected_metadata(incoming, context, stage, evidence_sha256, &expected_counts)?;
        let path =
            v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, &context.lineage_id)?
                .join(stage.incoming_basename());
        v031_upgrade_r2::read_bounded_file(
            &path,
            privacy::upgrade_receipt_v1::MAX_V031_UPGRADE_RECEIPT_PROTECTED_BYTES,
        )?
    } else {
        let current_time = read_clock()?;
        if current_time == 0 {
            return Err(V031ReceiptPersistenceError::Clock);
        }
        let previous_time = inventory
            .final_receipts
            .last()
            .map(|receipt| {
                u64::try_from(receipt.metadata.created_at_unix)
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(V031ReceiptPersistenceError::EvidenceConflict)
            })
            .transpose()?;
        seal_v031_upgrade_receipt_v1(&V031UpgradeReceiptCreateRequest {
            context: context.as_borrowed(),
            stage,
            previous_receipt_sha256: previous_sha256,
            evidence_sha256,
            counts,
            // Windows wall-clock rollback must never create an append-only
            // final receipt that the monotonic chain validator will reject
            // only after its no-replacement rename. Adjacent equal timestamps
            // are part of the frozen protocol, so clamp before any write.
            created_at_unix: previous_time
                .map_or(current_time, |previous| current_time.max(previous)),
        })?
        .into_protected_bytes()
    };
    verify_live_state()?;
    let installed = v031_upgrade_r2::install_next_receipt(
        app_local_data_dir,
        &context.lineage_id,
        stage.ordinal(),
        &protected_bytes,
        &bridge,
        &PlatformDirectorySync,
    )?;
    validate_expected_metadata(
        &installed.receipt,
        context,
        stage,
        evidence_sha256,
        &expected_counts,
    )?;
    verify_live_state()?;
    Ok(PersistedV031Receipt {
        receipt: installed.receipt,
        newly_installed: true,
    })
}

fn validate_expected_metadata(
    receipt: &AuthenticatedReceiptFile,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    evidence_sha256: &str,
    counts: &BTreeMap<String, u64>,
) -> Result<(), V031ReceiptPersistenceError> {
    if receipt.ordinal != stage.ordinal()
        || receipt.stage != stage.as_str()
        || receipt.metadata.lineage_id != context.lineage_id
        || receipt.metadata.envelope_binding_id != context.envelope_binding_id
        || receipt.metadata.source_profile_proof_sha256 != context.source_profile_proof_sha256
        || receipt.metadata.evidence_schema_version != stage.evidence_schema_version()
        || receipt.metadata.evidence_sha256 != evidence_sha256
        || &receipt.metadata.counts != counts
    {
        return Err(V031ReceiptPersistenceError::EvidenceConflict);
    }
    Ok(())
}

fn count_key_name(key: V031UpgradeReceiptCountKey) -> Result<String, V031ReceiptPersistenceError> {
    match serde_json::to_value(key).map_err(|_| V031ReceiptPersistenceError::Encoding)? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(V031ReceiptPersistenceError::Encoding),
    }
}

fn unix_now() -> Result<u64, V031ReceiptPersistenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .filter(|value| *value > 0)
        .ok_or(V031ReceiptPersistenceError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(stage: V031UpgradeReceiptStage) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
        let mut counts = stage
            .count_keys()
            .iter()
            .copied()
            .map(|key| (key, 1))
            .collect::<BTreeMap<_, _>>();
        match stage {
            V031UpgradeReceiptStage::SourcePreflightVerified => {
                counts.insert(V031UpgradeReceiptCountKey::UserSchemaObjects, 74);
                counts.insert(V031UpgradeReceiptCountKey::PrivacySchemaObjects, 11);
                counts.insert(V031UpgradeReceiptCountKey::PresentSlots, 2);
                counts.insert(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3);
                counts.insert(V031UpgradeReceiptCountKey::TargetAbsenceChecks, 26);
                counts.insert(V031UpgradeReceiptCountKey::CapacityChecks, 2);
            }
            V031UpgradeReceiptStage::OriginalRollbackVerified => {
                counts.insert(V031UpgradeReceiptCountKey::IdentityArtifacts, 1);
                counts.insert(V031UpgradeReceiptCountKey::BundleArtifacts, 1);
                counts.insert(V031UpgradeReceiptCountKey::RollbackSlots, 5);
                counts.insert(V031UpgradeReceiptCountKey::SqliteImages, 2);
                counts.insert(V031UpgradeReceiptCountKey::EncryptedChunks, 5);
                counts.insert(V031UpgradeReceiptCountKey::SourceRevalidations, 2);
                counts.insert(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3);
            }
            _ => panic!("timestamp persistence fixture only needs receipts zero and one"),
        }
        counts
    }

    #[test]
    fn count_key_bridge_uses_the_frozen_snake_case_wire_names() {
        assert_eq!(
            count_key_name(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots).unwrap(),
            "authenticated_absent_slots"
        );
        assert_eq!(
            count_key_name(V031UpgradeReceiptCountKey::PrivacyLineageRows).unwrap(),
            "privacy_lineage_rows"
        );
    }

    #[cfg(windows)]
    #[test]
    fn append_only_persistence_clamps_clock_rollback_before_installing_the_next_receipt() {
        let directory = tempfile::tempdir().expect("timestamp receipt root");
        let context = OwnedV031ReceiptContext {
            lineage_id: "1".repeat(64),
            envelope_binding_id: format!("ws_{}", "2".repeat(32)),
            source_profile_proof_sha256: "3".repeat(64),
        };
        let lineage =
            v031_upgrade_r2::canonical_lineage_directory(directory.path(), &context.lineage_id)
                .expect("canonical timestamp lineage");
        std::fs::create_dir_all(&lineage).expect("timestamp lineage creates");
        let future = 2_000_000_000_u64;
        let receipt_zero = persist_v031_receipt_with_clock(
            directory.path(),
            &context,
            V031UpgradeReceiptStage::SourcePreflightVerified,
            &"3".repeat(64),
            &counts(V031UpgradeReceiptStage::SourcePreflightVerified),
            || Ok(()),
            || Ok(future),
        )
        .expect("future-dated receipt zero installs");
        assert_eq!(
            receipt_zero.receipt.metadata.created_at_unix,
            i64::try_from(future).expect("fixture time fits i64")
        );

        std::fs::write(
            lineage.join(v031_upgrade_r2::V2_IDENTITY_FINAL),
            b"protected-identity",
        )
        .expect("V2 identity placeholder creates");
        std::fs::write(
            lineage.join(v031_upgrade_r2::V2_BUNDLE_FINAL),
            b"encrypted-bundle",
        )
        .expect("V2 bundle placeholder creates");

        let receipt_one = persist_v031_receipt_with_clock(
            directory.path(),
            &context,
            V031UpgradeReceiptStage::OriginalRollbackVerified,
            &"5".repeat(64),
            &counts(V031UpgradeReceiptStage::OriginalRollbackVerified),
            || Ok(()),
            || Ok(future - 10),
        )
        .expect("clock rollback clamps before the receipt-one write");
        assert_eq!(
            receipt_one.receipt.metadata.created_at_unix,
            receipt_zero.receipt.metadata.created_at_unix,
            "adjacent equal timestamps are the frozen monotonic recovery behavior"
        );
        assert!(!lineage
            .join(V031UpgradeReceiptStage::OriginalRollbackVerified.incoming_basename())
            .exists());
        assert!(lineage
            .join(V031UpgradeReceiptStage::OriginalRollbackVerified.final_basename())
            .is_file());

        let bridge = PrivacyReceiptAuthenticationBridge::new(context);
        let authenticated =
            load_authenticated_v031_lineage(directory.path(), &"1".repeat(64), &bridge)
                .expect("the clamped append-only chain authenticates");
        assert_eq!(authenticated.final_receipts.len(), 2);
        assert!(authenticated.next_incoming_receipt.is_none());
        assert_eq!(
            authenticated.final_receipts[0].metadata.created_at_unix,
            authenticated.final_receipts[1].metadata.created_at_unix
        );
    }
}
