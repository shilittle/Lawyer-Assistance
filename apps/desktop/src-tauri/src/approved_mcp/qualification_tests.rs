use super::{qualification::DesktopApprovedMcpQualificationProvider, *};
use std::sync::Arc;

struct TestKeys {
    epoch: Mutex<[u8; 32]>,
}

impl TestKeys {
    fn new() -> Self {
        Self {
            epoch: Mutex::new([0x44; 32]),
        }
    }
}

impl ApprovedMcpKeyProvider for TestKeys {
    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        match role {
            KeyRole::ApprovedManifest => Ok([0x11; 32]),
            KeyRole::WorkProductManifest => Ok([0x22; 32]),
            KeyRole::McpTicket => Ok([0x33; 32]),
            KeyRole::QualificationRevocationEpoch => self
                .epoch
                .lock()
                .map(|key| *key)
                .map_err(|_| key_store_error()),
        }
    }

    fn rotate(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        if !matches!(role, KeyRole::QualificationRevocationEpoch) {
            return Err(key_store_error());
        }
        let mut key = self.epoch.lock().map_err(|_| key_store_error())?;
        key[0] = key[0].wrapping_add(1);
        Ok(*key)
    }
}

fn workspace(
    root: PathBuf,
    test_keys: Arc<TestKeys>,
    binary_path: PathBuf,
) -> ApprovedMcpWorkspace {
    let keys: Arc<dyn ApprovedMcpKeyProvider> = test_keys;
    let qualification = Arc::new(DesktopApprovedMcpQualificationProvider::new(
        root.join("privacy")
            .join("approved-mcp")
            .join("qualification"),
        Arc::clone(&keys),
        binary_path,
    ));
    ApprovedMcpWorkspace::from_parts(root, qualification.clone(), keys, Some(qualification))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_release_binary_blocks_qualification_without_persisting_evidence() {
    let root = tempfile::tempdir().expect("qualification root");
    let keys = Arc::new(TestKeys::new());
    let binary = root
        .path()
        .join(legal_mcp::release_binary::binary_file_name());
    let first = workspace(root.path().to_path_buf(), Arc::clone(&keys), binary);
    assert_eq!(
        first.qualification_status().unwrap().reason_code,
        "BINARY_INVALID_OR_CHANGED"
    );
    let error = first
        .run_qualification(5 * 60)
        .await
        .expect_err("missing release binary must fail closed");
    assert_eq!(error.code(), "approved_mcp_release_binary_invalid");
    assert!(!root
        .path()
        .join("privacy/approved-mcp/qualification/active-evidence-v1.json")
        .exists());
}

#[test]
fn release_binary_trust_anchor_rejects_missing_malformed_and_mismatched_hashes() {
    let measured = Sha256Hex::parse("1".repeat(64)).expect("measured hash");
    for expected in [
        None,
        Some(""),
        Some("1"),
        Some("A111111111111111111111111111111111111111111111111111111111111111"),
        Some("2111111111111111111111111111111111111111111111111111111111111111"),
    ] {
        let error = super::qualification::validate_compiled_release_hash(expected, &measured)
            .expect_err("an absent, malformed, or mismatched release trust anchor is rejected");
        assert_eq!(error.code(), "approved_mcp_release_binary_untrusted");
    }
    super::qualification::validate_compiled_release_hash(
        Some("1111111111111111111111111111111111111111111111111111111111111111"),
        &measured,
    )
    .expect("the exact compile-time release hash is accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_canary_is_confined_to_unit_test_coverage() {
    let root = tempfile::tempdir().expect("in-process canary root");
    let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(TestKeys::new());
    let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> = Arc::new(AlwaysQualified);
    let workspace =
        ApprovedMcpWorkspace::from_parts(root.path().to_path_buf(), qualification, keys, None);
    let expected = super::qualification::ExpectedQualificationBinding {
        server_key_id: "mcpkey_unit_test".to_owned(),
        server_key_version: 1,
        revocation_epoch: 1,
        revocation_key_id: "mcpqepoch_unit_test".to_owned(),
        binary_path: root
            .path()
            .join(legal_mcp::release_binary::binary_file_name()),
        binary_path_identity_sha256: Sha256Hex::parse("1".repeat(64)).expect("path hash"),
        binary_file_identity_sha256: Sha256Hex::parse("2".repeat(64)).expect("file identity hash"),
        binary_sha256: Sha256Hex::parse("3".repeat(64)).expect("binary hash"),
        binary_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    super::qualification_canary::run_in_process(&workspace, &expected)
        .await
        .expect("unit-only in-process wire canary");
}
#[derive(Debug)]
struct AlwaysQualified;

impl ApprovedWorkspaceQualificationProvider for AlwaysQualified {
    fn current_qualification(
        &self,
        now_unix: u64,
    ) -> Result<
        ApprovedMcpQualificationSnapshotV1,
        legal_mcp::approved_backend::ApprovedWorkspaceQualificationError,
    > {
        Ok(ApprovedMcpQualificationSnapshotV1 {
            evidence_id: format!("mcpq_{}", "a".repeat(32)),
            evidence_sha256: Sha256Hex::parse("b".repeat(64)).expect("evidence hash"),
            stdio_canary_passed: true,
            streamable_http_canary_passed: true,
            exact_app_policy_binding: true,
            exact_server_key_binding: true,
            mcp_binary_path_identity_sha256: Sha256Hex::parse("c".repeat(64)).expect("path hash"),
            mcp_binary_file_identity_sha256: Sha256Hex::parse("d".repeat(64))
                .expect("file identity hash"),
            mcp_binary_sha256: Sha256Hex::parse("e".repeat(64)).expect("binary hash"),
            mcp_binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: legal_mcp::approved_backend::APPROVED_MCP_POLICY_ID.to_owned(),
            policy_version: legal_mcp::approved_backend::APPROVED_MCP_POLICY_VERSION,
            server_key_id: "test-server-key".to_owned(),
            server_key_version: 1,
            revocation_epoch: 1,
            issued_at_unix: now_unix.saturating_sub(1).max(1),
            expires_at_unix: now_unix.saturating_add(300),
            revoked: false,
        })
    }
}

fn approved_source(case_id: Option<&str>, now_unix: u64) -> ApprovedGenerationSource {
    let approved_payload =
        br#"{"schemaVersion":1,"pages":[{"pageNumber":1,"text":"[PERSON_001]"}]}"#.to_vec();
    let source_sha256 = sha256_hex(b"source");
    let extraction_sha256 = sha256_hex(b"extraction");
    let redacted_content_sha256 = sha256_hex(b"redacted");
    let approved_payload_sha256 = sha256_hex(&approved_payload);
    let receipt = privacy::ReceiptSigner::new([0x55; 32])
        .expect("receipt signer")
        .issue(privacy::RedactionReceiptClaims {
            receipt_id: format!("rct_{}", "9".repeat(32)),
            source_sha256: vec![source_sha256.clone()],
            extraction_sha256: extraction_sha256.clone(),
            redacted_content_sha256: redacted_content_sha256.clone(),
            approved_payload_sha256: approved_payload_sha256.clone(),
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: privacy::REDACTION_VERSION.to_owned(),
            destination: privacy::DestinationScope {
                kind: privacy::DestinationKind::ExternalMcpHost,
                identifier: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
            },
            purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
            unresolved_high_risk_count: 0,
            review_state: privacy::ReviewState::Approved,
            issued_at_unix: now_unix,
            expires_at_unix: Some(now_unix + 300),
            key_version: 1,
        })
        .expect("receipt");
    ApprovedGenerationSource {
        redaction_id: format!("red_{}", "7".repeat(32)),
        case_id: case_id.map(str::to_owned),
        material_id: format!("mat_{}", "1".repeat(32)),
        source_sha256,
        source_name_sha256: Sha256Hex::parse(sha256_hex(b"synthetic-source.pdf"))
            .expect("source-name hash"),
        source_revision_hash: Sha256Hex::parse(sha256_hex(b"source-revision-v1"))
            .expect("source revision hash"),
        extraction_sha256,
        redacted_content_sha256,
        approved_payload_sha256,
        content_media_type: "application/vnd.lawyer-assistance.approved+json".to_owned(),
        approved_payload,
        policy_id: "cn-legal-default".to_owned(),
        policy_version: 1,
        detector_version: privacy::REDACTION_VERSION.to_owned(),
        processing_version: "test-processing-v1".to_owned(),
        backend_trace: Vec::new(),
        summary: privacy::RedactionSummary::default(),
        dictionary_revision_hash: Sha256Hex::parse(sha256_hex(b"dictionary-v1"))
            .expect("dictionary hash"),
        mapping_revision_hash: Sha256Hex::parse(sha256_hex(b"mapping-v1")).expect("mapping hash"),
        case_dictionary_terms: zeroize::Zeroizing::new(vec!["Synthetic Raw Name".to_owned()]),
        source_terms: zeroize::Zeroizing::new(vec!["synthetic-source.pdf".to_owned()]),
        raw_canary_terms: zeroize::Zeroizing::new(vec!["Sensitive Canary 447700900123".to_owned()]),
        receipt,
    }
}

#[test]
fn cross_case_or_unbound_generation_is_rejected_before_any_workspace_write() {
    let root = tempfile::tempdir().expect("workspace root");
    let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(TestKeys::new());
    let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> = Arc::new(AlwaysQualified);
    let workspace =
        ApprovedMcpWorkspace::from_parts(root.path().to_path_buf(), qualification, keys, None);
    let now_unix = now_seconds().expect("clock");
    let case_a = format!("case_{}", "a".repeat(32));
    let case_b = format!("case_{}", "b".repeat(32));
    for source in [
        approved_source(Some(&case_a), now_unix),
        approved_source(None, now_unix),
    ] {
        let error = workspace
            .publish(&case_b, source)
            .expect_err("case binding must fail closed");
        assert_eq!(error.code(), "approved_generation_invalid");
    }
    assert!(!root
        .path()
        .join("privacy")
        .join("approved-mcp")
        .join(APPROVED_ROOT_NAME)
        .exists());
}

#[test]
fn publication_persists_only_blind_case_egress_evidence() {
    let root = tempfile::tempdir().expect("workspace root");
    let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(TestKeys::new());
    let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> = Arc::new(AlwaysQualified);
    let workspace =
        ApprovedMcpWorkspace::from_parts(root.path().to_path_buf(), qualification, keys, None);
    let now_unix = now_seconds().expect("clock");
    let case_id = format!("case_{}", "c".repeat(32));

    workspace
        .publish(&case_id, approved_source(Some(&case_id), now_unix))
        .expect("publish guarded generation");

    let mut pending = vec![root.path().to_path_buf()];
    let mut persisted_files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("read workspace tree") {
            let entry = entry.expect("workspace entry");
            let file_type = entry.file_type().expect("workspace entry type");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let path = entry.path();
                persisted_files.push((
                    path.clone(),
                    std::fs::read(path).expect("read workspace file"),
                ));
            }
        }
    }
    for raw in [
        "Synthetic Raw Name",
        "synthetic-source.pdf",
        "Sensitive Canary 447700900123",
    ] {
        for (path, bytes) in &persisted_files {
            assert!(
                !String::from_utf8_lossy(bytes).contains(raw),
                "raw guard term persisted in {}: {raw}",
                path.display()
            );
        }
    }
    assert!(persisted_files
        .iter()
        .any(|(_, bytes)| String::from_utf8_lossy(bytes).contains("approved-egress-guard-v2")));

    let second_case = format!("case_{}", "d".repeat(32));
    let mut leaking = approved_source(Some(&second_case), now_unix);
    leaking.raw_canary_terms = zeroize::Zeroizing::new(vec!["[PERSON_001]".to_owned()]);
    assert_eq!(
        workspace
            .publish(&second_case, leaking)
            .expect_err("case-specific canary must block publication")
            .code(),
        "workspace_residual_sensitive_content"
    );
}
