use super::{
    case_dictionary_store, vault_broker, PrivacyWorkflowError, PrivacyWorkflowManager,
    StoredReviewPayload,
};
use material_processing::{ExtractionBackend, LocalMineruConfig};
use privacy::{
    deterministic::{
        detect_finding_candidates, DetectionContextV1, DeterministicDetectorError,
        PrivateValueSinkV1, StorePrivateValueRequestV1, StoredPrivateValueBindingV1,
    },
    finding_engine::{build_findings, FindingPolicyV1},
    local_ner::{
        detect_local_ner_candidates, LocalNerDocumentInputV1, LocalNerModelAttestationV1,
        LocalNerPageInputV1,
    },
    risk_engine::QualificationSnapshotV1,
    sha256_hex,
    vnext::{CaseId, ConfidencePpm, EntityType, MaterialId, PrivacyFindingV1, Sha256Hex},
    ReceiptSigner,
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

const DETECTOR_POLICY_ID: &str = "cn-legal-local-rules-ner-v1";
const DETECTOR_POLICY_VERSION: u64 = 1;
const DETECTOR_EVIDENCE_KIND: &str = "local-detector-evidence-v1";

pub(super) struct CompletedDetectorRunV1 {
    pub findings: Vec<PrivacyFindingV1>,
    pub finding_summary_hash: Sha256Hex,
    pub detector_evidence_hash: Sha256Hex,
    pub model_attestation: LocalNerModelAttestationV1,
    pub qualification: QualificationSnapshotV1,
    pub dictionary_revision_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrivateLocationKey {
    page_index: u32,
    block_id: String,
    start_offset: u32,
    end_offset: u32,
    entity_type: EntityType,
}

struct VaultBackedPrivateValueSink<'a> {
    broker: &'a dyn vault_broker::VaultBroker,
    signer: &'a ReceiptSigner,
    case_id: &'a CaseId,
    material_id: &'a MaterialId,
    document_version: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
    policy_revision: u64,
    bindings: BTreeMap<PrivateLocationKey, StoredPrivateValueBindingV1>,
}

impl PrivateValueSinkV1 for VaultBackedPrivateValueSink<'_> {
    fn store_private_values(
        &mut self,
        requests: &[StorePrivateValueRequestV1<'_>],
    ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        if requests.iter().any(|request| {
            request.case_id != self.case_id
                || request.material_id != self.material_id
                || request.document_version != self.document_version
                || request.private_value.is_empty()
        }) {
            return Err(DeterministicDetectorError::InvalidContext);
        }

        let mut fingerprints = Vec::with_capacity(requests.len());
        let mut locators = Vec::with_capacity(requests.len());
        let mut cached = Vec::with_capacity(requests.len());
        for request in requests {
            let fingerprint = self
                .signer
                .case_value_fingerprint(self.case_id, request.private_value)
                .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?;
            let key = location_key(request);
            if let Some(existing) = self.bindings.get(&key) {
                if existing.value_fingerprint != fingerprint {
                    return Err(DeterministicDetectorError::InvalidPrivateBinding);
                }
                cached.push(Some(existing.clone()));
            } else {
                cached.push(None);
            }
            let locator = Sha256Hex::parse(sha256_hex(
                format!(
                    "private-value-locator-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{:?}\0{}",
                    request.case_id.as_str(),
                    request.material_id.as_str(),
                    request.document_version,
                    request.page_index,
                    request.block_id,
                    request.start_offset,
                    request.entity_type,
                    fingerprint.as_str(),
                )
                .as_bytes(),
            ))
            .map_err(|_| DeterministicDetectorError::InvalidPrivateBinding)?;
            fingerprints.push(fingerprint);
            locators.push(locator);
        }

        let to_seal = requests
            .iter()
            .zip(&locators)
            .zip(&cached)
            .filter_map(|((request, locator), cached)| {
                cached
                    .is_none()
                    .then_some(vault_broker::PrivateValueToSeal {
                        value_locator_hash: locator.clone(),
                        private_value: request.private_value,
                    })
            })
            .collect::<Vec<_>>();
        let mut fresh_references = VecDeque::new();
        if !to_seal.is_empty() {
            let sealed = self
                .broker
                .seal_private_values(
                    self.case_id,
                    self.material_id,
                    &to_seal,
                    self.created_at_unix,
                )
                .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?;
            if sealed.references.len() != to_seal.len() {
                return Err(DeterministicDetectorError::InvalidPrivateBinding);
            }
            self.broker
                .bind_aux_retention(
                    &sealed.binding,
                    self.expires_at_unix,
                    false,
                    self.policy_revision,
                    self.created_at_unix,
                )
                .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?;
            fresh_references = sealed.references.into();
        }

        let mut output = Vec::with_capacity(requests.len());
        for (((request, fingerprint), locator), existing) in
            requests.iter().zip(fingerprints).zip(locators).zip(cached)
        {
            let binding = if let Some(binding) = existing {
                binding
            } else {
                let reference = fresh_references
                    .pop_front()
                    .ok_or(DeterministicDetectorError::InvalidPrivateBinding)?;
                if reference.value_locator_hash != locator {
                    return Err(DeterministicDetectorError::InvalidPrivateBinding);
                }
                StoredPrivateValueBindingV1 {
                    value_fingerprint: fingerprint,
                    private_value_ref: reference,
                    proposed_replacement: stable_replacement(request.entity_type, &locator),
                }
            };
            self.bindings.insert(location_key(request), binding.clone());
            output.push(binding);
        }
        if !fresh_references.is_empty() {
            return Err(DeterministicDetectorError::InvalidPrivateBinding);
        }
        Ok(output)
    }
}

pub(super) fn run_local_detectors(
    manager: &PrivacyWorkflowManager,
    stored: &StoredReviewPayload,
    mineru_config: Option<&LocalMineruConfig>,
    ocr_qualification: Option<&QualificationSnapshotV1>,
    now_unix: u64,
    dictionary: &case_dictionary_store::CaseDictionarySnapshotV1,
) -> Result<CompletedDetectorRunV1, PrivacyWorkflowError> {
    let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(|| {
        PrivacyWorkflowError::new("privacy_review_identity_invalid", "Missing case identity.")
    })?)
    .map_err(|_| {
        PrivacyWorkflowError::new("privacy_review_identity_invalid", "Invalid case identity.")
    })?;
    let material_id = MaterialId::parse(stored.material_id.clone()).map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_review_identity_invalid",
            "Invalid material identity.",
        )
    })?;
    if dictionary.case_id() != &case_id {
        return Err(PrivacyWorkflowError::new(
            "privacy_case_dictionary_binding_mismatch",
            "The local detector dictionary is not bound to this case.",
        ));
    }
    let connection = manager.open_connection()?;
    let lifecycle = manager.privacy_lifecycle(&connection)?;
    let retention = lifecycle
        .retention_policy(&connection)
        .map_err(PrivacyWorkflowError::lifecycle)?;
    let expires_at_unix = now_unix
        .checked_add(retention.review_retention_seconds)
        .ok_or_else(|| PrivacyWorkflowError::new("invalid_retention", "Retention overflow."))?;
    drop(connection);
    let signer = manager.receipt_signer()?;
    let mut sink = VaultBackedPrivateValueSink {
        broker: manager.shared.vault_broker.as_ref(),
        signer: &signer,
        case_id: &case_id,
        material_id: &material_id,
        document_version: 1,
        created_at_unix: now_unix,
        expires_at_unix,
        policy_revision: retention.revision,
        bindings: BTreeMap::new(),
    };

    let block_ids = stored
        .pages
        .iter()
        .enumerate()
        .map(|(index, _)| format!("page-{index}"))
        .collect::<Vec<_>>();
    let ner_pages = stored
        .pages
        .iter()
        .enumerate()
        .map(|(index, page)| {
            let page_index = u32::try_from(index).map_err(|_| {
                PrivacyWorkflowError::new("local_ner_input_invalid", "Page index overflow.")
            })?;
            Ok(LocalNerPageInputV1 {
                page_index,
                block_id: &block_ids[index],
                text: &page.original_text,
                ocr_confidence_ppm: minimum_page_confidence(page)?,
                layout_confidence_ppm: None,
            })
        })
        .collect::<Result<Vec<_>, PrivacyWorkflowError>>()?;
    let mut candidates = Vec::new();
    for page in &ner_pages {
        let context = DetectionContextV1 {
            case_id: &case_id,
            material_id: &material_id,
            document_version: 1,
            page_index: page.page_index,
            block_id: page.block_id,
            ocr_confidence_ppm: page.ocr_confidence_ppm,
            layout_confidence_ppm: page.layout_confidence_ppm,
        };
        candidates.extend(
            detect_finding_candidates(page.text, context, &mut sink).map_err(detector_error)?,
        );
        candidates.extend(case_dictionary_store::match_candidates(
            dictionary, page.text, context,
        )?);
    }
    let ner_batch = detect_local_ner_candidates(
        LocalNerDocumentInputV1 {
            case_id: &case_id,
            material_id: &material_id,
            document_version: 1,
            pages: &ner_pages,
        },
        &mut sink,
    )
    .map_err(|error| PrivacyWorkflowError::new(error.code(), "Local NER failed closed."))?;
    candidates.extend(ner_batch.candidates);
    let policy = FindingPolicyV1 {
        policy_id: DETECTOR_POLICY_ID.to_owned(),
        policy_version: DETECTOR_POLICY_VERSION,
        minimum_detector_agreement: 2,
        high_confidence_ppm: ConfidencePpm::new(900_000).map_err(|_| {
            PrivacyWorkflowError::new("privacy_risk_policy_invalid", "Invalid threshold.")
        })?,
        low_ocr_confidence_ppm: ConfidencePpm::new(800_000).map_err(|_| {
            PrivacyWorkflowError::new("privacy_risk_policy_invalid", "Invalid threshold.")
        })?,
    };
    let findings =
        build_findings(case_id.clone(), material_id, 1, candidates, &policy).map_err(|_| {
            PrivacyWorkflowError::new("finding_engine_failed", "Finding aggregation failed.")
        })?;
    case_dictionary_store::persist_finding_secret_evidence(
        manager,
        stored,
        &findings.findings,
        &signer,
        expires_at_unix,
        retention.revision,
        now_unix,
    )?;
    let qualification = qualification_snapshot(
        stored,
        mineru_config,
        ocr_qualification,
        &ner_batch.attestation,
        now_unix,
    )?;
    let evidence = DetectorEvidenceV1 {
        schema_version: DETECTOR_EVIDENCE_KIND,
        source_sha256: &stored.source_sha256,
        extraction_sha256: &stored.extraction_sha256,
        detector_policy_id: DETECTOR_POLICY_ID,
        detector_policy_version: DETECTOR_POLICY_VERSION,
        model_attestation: &ner_batch.attestation,
        finding_summary_hash: &findings.finding_summary_hash,
        finding_count: u32::try_from(findings.findings.len()).map_err(|_| {
            PrivacyWorkflowError::new("finding_engine_failed", "Finding count overflow.")
        })?,
        dictionary_revision_hash: dictionary.revision_hash(),
        qualification: &qualification,
    };
    let evidence_bytes = privacy::vnext::canonical_json_v1(&evidence).map_err(|_| {
        PrivacyWorkflowError::new("privacy_risk_evidence_invalid", "Evidence encoding failed.")
    })?;
    let detector_evidence_hash = Sha256Hex::parse(sha256_hex(&evidence_bytes)).map_err(|_| {
        PrivacyWorkflowError::new("privacy_risk_evidence_invalid", "Evidence hash failed.")
    })?;
    let evidence_binding = manager
        .shared
        .vault_broker
        .seal_aux_payload(&case_id, DETECTOR_EVIDENCE_KIND, &evidence_bytes, now_unix)
        .map_err(PrivacyWorkflowError::vault)?;
    manager
        .shared
        .vault_broker
        .bind_aux_retention(
            &evidence_binding,
            expires_at_unix,
            false,
            retention.revision,
            now_unix,
        )
        .map_err(PrivacyWorkflowError::vault)?;
    let verified = manager
        .shared
        .vault_broker
        .read_aux_payload(&evidence_binding)
        .map_err(PrivacyWorkflowError::vault)?;
    if verified.content() != evidence_bytes
        || evidence_binding.content_sha256 != detector_evidence_hash
    {
        return Err(PrivacyWorkflowError::new(
            "privacy_risk_evidence_invalid",
            "Encrypted detector evidence verification failed.",
        ));
    }
    Ok(CompletedDetectorRunV1 {
        findings: findings.findings,
        finding_summary_hash: findings.finding_summary_hash,
        detector_evidence_hash,
        model_attestation: ner_batch.attestation,
        qualification,
        dictionary_revision_hash: dictionary.revision_hash().clone(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetectorEvidenceV1<'a> {
    schema_version: &'static str,
    source_sha256: &'a str,
    extraction_sha256: &'a str,
    detector_policy_id: &'static str,
    detector_policy_version: u64,
    model_attestation: &'a LocalNerModelAttestationV1,
    finding_summary_hash: &'a Sha256Hex,
    finding_count: u32,
    dictionary_revision_hash: &'a Sha256Hex,
    qualification: &'a QualificationSnapshotV1,
}

fn qualification_snapshot(
    stored: &StoredReviewPayload,
    mineru_config: Option<&LocalMineruConfig>,
    ocr_qualification: Option<&QualificationSnapshotV1>,
    attestation: &LocalNerModelAttestationV1,
    now_unix: u64,
) -> Result<QualificationSnapshotV1, PrivacyWorkflowError> {
    let ocr_traces = stored
        .backend_trace
        .iter()
        .filter(|trace| trace.backend == ExtractionBackend::MineruLocal)
        .collect::<Vec<_>>();

    if ocr_traces.is_empty() {
        let report_id = format!(
            "qrep_native_{}",
            &attestation.model_manifest_sha256.as_str()[..24]
        );
        let report_sha256 = Sha256Hex::parse(sha256_hex(
            format!(
                "native-local-qualification-v1\0{}\0{}\0{}\0{}\0{}",
                report_id,
                stored.processing_version,
                stored.source_sha256,
                stored.extraction_sha256,
                attestation.model_manifest_sha256.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_risk_evidence_invalid",
                "Native qualification hash failed.",
            )
        })?;
        return Ok(QualificationSnapshotV1 {
            qualification_report_id: Some(report_id),
            qualification_report_sha256: Some(report_sha256),
            processing_chain_qualified: true,
            exact_worker_model_match: true,
            network_isolation_enforced: false,
            model_manifest_trust_established: true,
            production_case_ocr_authorized: false,
            expires_at_unix: Some(u64::MAX),
            revoked: false,
        });
    }

    let (Some(config), Some(signed)) = (mineru_config, ocr_qualification) else {
        return Ok(QualificationSnapshotV1 {
            qualification_report_id: ocr_qualification
                .and_then(|snapshot| snapshot.qualification_report_id.clone()),
            qualification_report_sha256: ocr_qualification
                .and_then(|snapshot| snapshot.qualification_report_sha256.clone()),
            processing_chain_qualified: false,
            exact_worker_model_match: false,
            network_isolation_enforced: false,
            model_manifest_trust_established: false,
            production_case_ocr_authorized: false,
            expires_at_unix: ocr_qualification.and_then(|snapshot| snapshot.expires_at_unix),
            revoked: ocr_qualification.is_some_and(|snapshot| snapshot.revoked),
        });
    };

    let trace_matches = ocr_traces.iter().all(|trace| {
        trace.worker_sha256.as_deref() == Some(config.expected_executable_sha256.as_str())
            && trace.model_manifest_sha256.as_deref()
                == Some(config.expected_model_manifest_sha256.as_str())
            && trace.config_sha256.as_deref() == Some(config.expected_config_sha256.as_str())
    });
    let report_matches =
        signed.qualification_report_id.as_deref() == Some(config.qualification_report_id.as_str());
    let report_current = signed
        .expires_at_unix
        .is_some_and(|expires_at| now_unix < expires_at)
        && !signed.revoked;
    let exact = signed.exact_worker_model_match && trace_matches && report_matches;
    let isolation = signed.network_isolation_enforced
        && config.strict_offline
        && config.network_isolation.verified
        && ocr_traces.iter().all(|trace| trace.isolation_verified);
    let model_trusted = signed.model_manifest_trust_established && trace_matches && report_matches;
    let production_ocr = signed.production_case_ocr_authorized
        && exact
        && isolation
        && model_trusted
        && report_current;

    Ok(QualificationSnapshotV1 {
        qualification_report_id: signed.qualification_report_id.clone(),
        qualification_report_sha256: signed.qualification_report_sha256.clone(),
        processing_chain_qualified: signed.processing_chain_qualified && exact && report_current,
        exact_worker_model_match: exact,
        network_isolation_enforced: isolation,
        model_manifest_trust_established: model_trusted,
        production_case_ocr_authorized: production_ocr,
        expires_at_unix: signed.expires_at_unix,
        revoked: signed.revoked,
    })
}

fn minimum_page_confidence(
    page: &super::StoredReviewPage,
) -> Result<Option<ConfidencePpm>, PrivacyWorkflowError> {
    page.spans
        .iter()
        .filter(|span| span.backend == ExtractionBackend::MineruLocal)
        .filter_map(|span| span.confidence)
        .map(super::confidence_ppm)
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.into_iter().min())
}

fn location_key(request: &StorePrivateValueRequestV1<'_>) -> PrivateLocationKey {
    PrivateLocationKey {
        page_index: request.page_index,
        block_id: request.block_id.to_owned(),
        start_offset: request.start_offset,
        end_offset: request.end_offset,
        entity_type: request.entity_type,
    }
}

fn stable_replacement(entity_type: EntityType, locator: &Sha256Hex) -> String {
    let stem = match entity_type {
        EntityType::PersonName => "person",
        EntityType::OrganizationName => "organization",
        EntityType::Address => "address",
        EntityType::IdentityNumber => "identity",
        EntityType::PhoneNumber | EntityType::LandlineNumber => "phone",
        EntityType::BankAccount | EntityType::AccountName => "account",
        _ => "sensitive",
    };
    format!("[{stem}-{}]", &locator.as_str()[..12])
}

fn detector_error(error: DeterministicDetectorError) -> PrivacyWorkflowError {
    let code = match error {
        DeterministicDetectorError::InvalidContext => "deterministic_detector_invalid_context",
        DeterministicDetectorError::PatternUnavailable => {
            "deterministic_detector_pattern_unavailable"
        }
        DeterministicDetectorError::MatchLimitExceeded => {
            "deterministic_detector_match_limit_exceeded"
        }
        DeterministicDetectorError::PrivateValueStoreFailed => {
            "deterministic_detector_private_store_failed"
        }
        DeterministicDetectorError::InvalidPrivateBinding => {
            "deterministic_detector_private_binding_invalid"
        }
    };
    PrivacyWorkflowError::new(code, "Local deterministic detector failed closed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use material_processing::{
        BackendTrace, DeviceSelection, MineruBackend, NetworkIsolationEvidence,
    };
    use std::path::PathBuf;

    fn digest(fill: char) -> Sha256Hex {
        Sha256Hex::parse(fill.to_string().repeat(64)).expect("synthetic digest")
    }

    fn attestation() -> LocalNerModelAttestationV1 {
        LocalNerModelAttestationV1 {
            model_version: "local-ner-test-v1".to_owned(),
            model_asset_sha256: digest('a'),
            model_manifest_sha256: digest('b'),
            feature_schema_version: "feature-test-v1".to_owned(),
            calibration_version: "calibration-test-v1".to_owned(),
            training_fixture_sha256: digest('c'),
        }
    }

    fn stored_with_traces(backend_trace: Vec<BackendTrace>) -> StoredReviewPayload {
        StoredReviewPayload {
            schema_version: 1,
            material_id: "mat_11111111111111111111111111111111".to_owned(),
            redaction_id: "red_11111111111111111111111111111111".to_owned(),
            case_id: Some("case_11111111111111111111111111111111".to_owned()),
            vault_object_id: None,
            vault_object_version: None,
            vault_isolation: None,
            source_display_name: "synthetic.pdf".to_owned(),
            source_sha256: "1".repeat(64),
            extraction_sha256: "2".repeat(64),
            suggested_redacted_content_sha256: "3".repeat(64),
            processing_version: "material-processing-test-v1".to_owned(),
            media_type: "application/pdf".to_owned(),
            page_count: 1,
            input_transform: None,
            backend_trace,
            summary: privacy::RedactionSummary::default(),
            forbidden_canaries: Vec::new(),
            pages: Vec::new(),
        }
    }

    fn mineru_config() -> LocalMineruConfig {
        LocalMineruConfig {
            executable: PathBuf::from("mineru-worker.exe"),
            expected_executable_sha256: "4".repeat(64),
            runtime_executables: Vec::new(),
            runtime_manifest: PathBuf::from("runtime-manifest.json"),
            expected_runtime_manifest_sha256: "5".repeat(64),
            support_manifest: PathBuf::from("support-manifest.json"),
            expected_support_manifest_sha256: "6".repeat(64),
            mineru_config: PathBuf::from("mineru-config.json"),
            expected_config_sha256: "7".repeat(64),
            model_root: PathBuf::from("models"),
            model_manifest: PathBuf::from("model-manifest.json"),
            expected_model_manifest_sha256: "8".repeat(64),
            temporary_root: PathBuf::from("temp"),
            backend: MineruBackend::Pipeline,
            device: DeviceSelection::Cpu,
            language: "ch".to_owned(),
            timeout_ms: 10_000,
            max_output_bytes: 1024 * 1024,
            strict_offline: true,
            network_isolation: NetworkIsolationEvidence {
                verified: true,
                mechanism: "windows_firewall_program_block_v1".to_owned(),
                checked_at_unix: 90,
                rules: Vec::new(),
            },
            qualification_report_id: "qrep_11111111111111111111111111111111".to_owned(),
            expected_worker_identity_sha256: "9".repeat(64),
        }
    }

    fn trace_for(config: &LocalMineruConfig) -> BackendTrace {
        BackendTrace {
            backend: ExtractionBackend::MineruLocal,
            worker_sha256: Some(config.expected_executable_sha256.clone()),
            model_manifest_sha256: Some(config.expected_model_manifest_sha256.clone()),
            config_sha256: Some(config.expected_config_sha256.clone()),
            device: "cpu".to_owned(),
            page_numbers: vec![1],
            isolation_verified: true,
            isolation_mechanism: Some("windows_firewall_program_block_v1".to_owned()),
        }
    }

    fn signed_snapshot(config: &LocalMineruConfig) -> QualificationSnapshotV1 {
        QualificationSnapshotV1 {
            qualification_report_id: Some(config.qualification_report_id.clone()),
            qualification_report_sha256: Some(digest('d')),
            processing_chain_qualified: true,
            exact_worker_model_match: true,
            network_isolation_enforced: true,
            model_manifest_trust_established: true,
            production_case_ocr_authorized: true,
            expires_at_unix: Some(200),
            revoked: false,
        }
    }

    #[test]
    fn native_qualification_is_content_bound_and_never_claims_ocr_authorization() {
        let mut stored = stored_with_traces(Vec::new());
        let model = attestation();
        let first =
            qualification_snapshot(&stored, None, None, &model, 100).expect("native qualification");

        assert!(first.processing_chain_qualified);
        assert!(first.exact_worker_model_match);
        assert!(first.model_manifest_trust_established);
        assert!(!first.network_isolation_enforced);
        assert!(!first.production_case_ocr_authorized);
        assert_eq!(first.expires_at_unix, Some(u64::MAX));

        stored.extraction_sha256 = "e".repeat(64);
        let changed = qualification_snapshot(&stored, None, None, &model, 100)
            .expect("changed native qualification");
        assert_ne!(
            first.qualification_report_sha256,
            changed.qualification_report_sha256
        );
    }

    #[test]
    fn ocr_qualification_fails_closed_on_trace_report_or_expiry_drift() {
        let config = mineru_config();
        let mut stored = stored_with_traces(vec![trace_for(&config)]);
        let mut signed = signed_snapshot(&config);
        let model = attestation();

        let qualified = qualification_snapshot(&stored, Some(&config), Some(&signed), &model, 100)
            .expect("matched qualification");
        assert!(qualified.processing_chain_qualified);
        assert!(qualified.exact_worker_model_match);
        assert!(qualified.network_isolation_enforced);
        assert!(qualified.model_manifest_trust_established);
        assert!(qualified.production_case_ocr_authorized);

        stored.backend_trace[0].worker_sha256 = Some("f".repeat(64));
        let drifted = qualification_snapshot(&stored, Some(&config), Some(&signed), &model, 100)
            .expect("drifted qualification");
        assert!(!drifted.processing_chain_qualified);
        assert!(!drifted.exact_worker_model_match);
        assert!(!drifted.model_manifest_trust_established);
        assert!(!drifted.production_case_ocr_authorized);

        stored.backend_trace[0] = trace_for(&config);
        signed.expires_at_unix = Some(100);
        let expired = qualification_snapshot(&stored, Some(&config), Some(&signed), &model, 100)
            .expect("expired qualification");
        assert!(!expired.processing_chain_qualified);
        assert!(!expired.production_case_ocr_authorized);

        let missing = qualification_snapshot(&stored, Some(&config), None, &model, 100)
            .expect("missing qualification");
        assert!(!missing.processing_chain_qualified);
        assert!(!missing.exact_worker_model_match);
        assert!(!missing.production_case_ocr_authorized);
    }
}
