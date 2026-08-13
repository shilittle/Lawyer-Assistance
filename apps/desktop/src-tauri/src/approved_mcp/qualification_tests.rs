use super::{qualification::DesktopApprovedMcpQualificationProvider, *};
use crate::{
    commands::approved_mcp::{
        list_approved_generations_inner, publish_approved_generation_inner,
        revoke_approved_generation_inner, ListApprovedGenerationsRequest,
        PublishApprovedGenerationRequest, RevokeApprovedGenerationRequest,
    },
    privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig},
    privacy_workflow::{
        test_workspace_instance_id, ApplyCaseRedactionRiskReviewActionRequest,
        ApproveCaseRedactionReviewRequest, ApproveReviewForApprovedWorkspaceRequest,
        CaseRedactionReviewView, DeleteCaseRedactionReviewRequest, EditedRedactedPage,
        LocalOcrExecutionContext, PrivacyWorkflowManager, ReceiptDestinationInput,
    },
};
use privacy::{DestinationKind, ReceiptSigner, ReviewActionV1};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc,
};

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

struct StartupTestKeys {
    manifest: Mutex<Option<[u8; 32]>>,
    load_or_create_calls: AtomicUsize,
    mutations: AtomicUsize,
}

impl StartupTestKeys {
    fn missing() -> Self {
        Self {
            manifest: Mutex::new(None),
            load_or_create_calls: AtomicUsize::new(0),
            mutations: AtomicUsize::new(0),
        }
    }

    fn existing() -> Self {
        Self {
            manifest: Mutex::new(Some([0x66; 32])),
            load_or_create_calls: AtomicUsize::new(0),
            mutations: AtomicUsize::new(0),
        }
    }

    fn load_or_create_calls(&self) -> usize {
        self.load_or_create_calls.load(AtomicOrdering::SeqCst)
    }

    fn mutations(&self) -> usize {
        self.mutations.load(AtomicOrdering::SeqCst)
    }
}

impl ApprovedMcpKeyProvider for StartupTestKeys {
    fn load_existing(&self, role: KeyRole) -> Result<Option<[u8; 32]>, ApprovedMcpError> {
        if !matches!(role, KeyRole::ApprovedManifest) {
            return Ok(None);
        }
        self.manifest
            .lock()
            .map(|key| *key)
            .map_err(|_| key_store_error())
    }

    fn load_or_create(&self, role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        if !matches!(role, KeyRole::ApprovedManifest) {
            return Err(key_store_error());
        }
        self.load_or_create_calls
            .fetch_add(1, AtomicOrdering::SeqCst);
        let mut key = self.manifest.lock().map_err(|_| key_store_error())?;
        if key.is_none() {
            *key = Some([0x66; 32]);
            self.mutations.fetch_add(1, AtomicOrdering::SeqCst);
        }
        key.ok_or_else(key_store_error)
    }

    fn rotate(&self, _role: KeyRole) -> Result<[u8; 32], ApprovedMcpError> {
        self.mutations.fetch_add(1, AtomicOrdering::SeqCst);
        Err(key_store_error())
    }
}

fn startup_workspace(root: PathBuf, test_keys: Arc<StartupTestKeys>) -> ApprovedMcpWorkspace {
    let keys: Arc<dyn ApprovedMcpKeyProvider> = test_keys;
    let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> = Arc::new(AlwaysQualified);
    ApprovedMcpWorkspace::from_parts(root, qualification, keys, None)
}

fn install_startup_history(root: &Path, relative: &str, directory: bool) {
    let path = root.join(relative);
    if directory {
        std::fs::create_dir_all(path).expect("create startup history directory");
    } else {
        std::fs::create_dir_all(path.parent().expect("startup history parent"))
            .expect("create startup history parent");
        std::fs::write(path, b"existing-state").expect("write startup history file");
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

struct PublishCommandFixture {
    directory: tempfile::TempDir,
    workflow: PrivacyWorkflowManager,
    workspace: ApprovedMcpWorkspace,
    project_id: String,
    privacy_case_id: String,
    redaction_id: String,
    material_id: String,
    source_sha256: String,
    extraction_sha256: String,
    approved_payload_sha256: String,
}

impl PublishCommandFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("approved publish integration root");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("canonical user database");
        let project_id = format!("case-publish-{}", Uuid::new_v4().simple());
        let user_connection =
            database::open_user_database(&user_database_path).expect("user database");
        database::upsert_case_project(
            &user_connection,
            &database::CaseProjectRow {
                project_id: project_id.clone(),
                title: "Approved publication integration case".to_owned(),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("insert integration project");
        drop(user_connection);

        let keys: Arc<dyn ApprovedMcpKeyProvider> = Arc::new(TestKeys::new());
        let qualification: Arc<dyn ApprovedWorkspaceQualificationProvider> =
            Arc::new(AlwaysQualified);
        let workspace = ApprovedMcpWorkspace::from_parts(
            directory.path().to_path_buf(),
            qualification,
            keys,
            None,
        );
        let workflow = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
            Arc::new(workspace.clone()),
        )
        .expect("privacy workflow with real approved workspace invalidator");
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        workflow.set_test_runtime(
            ReceiptSigner::new([0x71; 32]).expect("test receipt signer"),
            now_unix,
        );

        let source_path = directory.path().join("approved-publish-integration.txt");
        fs::write(
            &source_path,
            b"Synthetic client 13800138000 submitted contract performance evidence.",
        )
        .expect("write integration source");
        let prepared = workflow
            .prepare_case_selected_material_with_qualification(
                &source_path,
                &PrivacyConfig::default(),
                &disabled_local_ocr_status(),
                LocalOcrExecutionContext {
                    mineru_config: None,
                    qualification: None,
                },
                project_id.clone(),
                Vec::new(),
            )
            .expect("prepare real Vault-backed case material");
        let prepared = workflow
            .case_redaction_review_view(project_id.clone(), prepared)
            .expect("project-scoped prepared review");
        let reviewed = confirm_case_review(&workflow, prepared);
        let risk_revision = reviewed
            .risk_review
            .as_ref()
            .expect("confirmed risk revision")
            .revision;
        let approval = workflow
            .approve_case_redaction_review(ApproveCaseRedactionReviewRequest {
                project_id: project_id.clone(),
                redaction_id: reviewed.redaction_id.clone(),
                expected_risk_revision: Some(risk_revision),
                expected_suggested_redacted_sha256: reviewed
                    .suggested_redacted_content_sha256
                    .clone(),
                edited_pages: edited_pages(&reviewed),
                reviewer: "approved-publish-integration-reviewer".to_owned(),
                destination: ReceiptDestinationInput {
                    kind: DestinationKind::VerifiedLocalProvider,
                    identifier: "local-safe-pdf-export-v1".to_owned(),
                },
                purpose: "local_safe_pdf_export".to_owned(),
                ttl_seconds: 3_600,
            })
            .expect("approve exact case generation");
        let dedicated = workflow
            .approve_review_for_approved_workspace(ApproveReviewForApprovedWorkspaceRequest {
                redaction_id: reviewed.redaction_id.clone(),
                expected_approved_payload_sha256: approval.approved_payload_sha256,
                reviewer: "approved-mcp-integration-reviewer".to_owned(),
                ttl_seconds: 3_600,
                confirmed: true,
            })
            .expect("issue dedicated approved workspace authorization");
        let selection = workflow
            .list_approved_review_selections()
            .expect("list exact approved selection")
            .into_iter()
            .find(|selection| selection.redaction_id == reviewed.redaction_id)
            .expect("integration selection");
        assert_eq!(selection.project_id, project_id);
        let privacy_case_id = workflow
            .with_existing_project_privacy_case(&project_id, |_project_id, privacy_case_id| {
                Ok::<String, ()>(privacy_case_id.as_str().to_owned())
            })
            .expect("resolve persisted project binding")
            .expect("read internal PrivacyCaseId in backend-only test");
        assert!(
            workspace
                .list(Some(&privacy_case_id))
                .expect("initialize empty approved workspace")
                .is_empty(),
            "fixture must begin without a publication"
        );

        Self {
            directory,
            workflow,
            workspace,
            project_id,
            privacy_case_id,
            redaction_id: reviewed.redaction_id,
            material_id: reviewed.material_id,
            source_sha256: reviewed.source_sha256,
            extraction_sha256: reviewed.extraction_sha256,
            approved_payload_sha256: dedicated.approved_payload_sha256,
        }
    }

    fn request(&self) -> PublishApprovedGenerationRequest {
        PublishApprovedGenerationRequest {
            redaction_id: self.redaction_id.clone(),
            project_id: self.project_id.clone(),
            expected_approved_payload_sha256: self.approved_payload_sha256.clone(),
        }
    }

    fn approved_root(&self) -> PathBuf {
        self.directory
            .path()
            .join("privacy")
            .join("approved-mcp")
            .join(APPROVED_ROOT_NAME)
    }
}

fn disabled_local_ocr_status() -> LocalOcrStatus {
    LocalOcrStatus {
        code: LocalOcrStatusCode::Disabled,
        message: "test".to_owned(),
        worker_version: None,
        model_version: None,
        worker_sha256: None,
        model_manifest_sha256: None,
        worker_present: false,
        model_directory_present: false,
        integrity_verified: false,
        network_isolation_verified: false,
        worker_protocol_version: None,
        worker_protocol_identity_sha256: None,
        worker_health_evidence_sha256: None,
        python_version: None,
        mineru_version: None,
        pytorch_version: None,
        cuda_runtime_version: None,
        gpu_driver_version: None,
    }
}

fn edited_pages(review: &CaseRedactionReviewView) -> Vec<EditedRedactedPage> {
    review
        .pages
        .iter()
        .map(|page| EditedRedactedPage {
            page_number: page.page_number,
            redacted_text: page.redacted_text.clone(),
        })
        .collect()
}

fn confirm_case_review(
    workflow: &PrivacyWorkflowManager,
    mut review: CaseRedactionReviewView,
) -> CaseRedactionReviewView {
    let target_pages = edited_pages(&review);
    let finding_ids = review
        .risk_review
        .as_ref()
        .expect("initial risk revision")
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    for finding_id in finding_ids {
        let revision = review
            .risk_review
            .as_ref()
            .expect("current finding revision")
            .revision;
        review = workflow
            .apply_case_redaction_risk_review_action(ApplyCaseRedactionRiskReviewActionRequest {
                project_id: review.project_id.clone(),
                redaction_id: review.redaction_id.clone(),
                expected_revision: revision,
                actor: "approved-publish-integration-reviewer".to_owned(),
                edited_pages: target_pages.clone(),
                action: ReviewActionV1::AcceptReplacement {
                    finding_id,
                    apply_cluster: false,
                },
            })
            .expect("accept detected replacement");
    }
    let revision = review
        .risk_review
        .as_ref()
        .expect("resolved risk revision")
        .revision;
    workflow
        .apply_case_redaction_risk_review_action(ApplyCaseRedactionRiskReviewActionRequest {
            project_id: review.project_id.clone(),
            redaction_id: review.redaction_id.clone(),
            expected_revision: revision,
            actor: "approved-publish-integration-reviewer".to_owned(),
            edited_pages: target_pages,
            action: ReviewActionV1::ConfirmEditedOutput,
        })
        .expect("confirm exact reviewed output")
}

fn approved_tree_hashes(root: &Path) -> BTreeMap<String, String> {
    fn visit(base: &Path, directory: &Path, output: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(directory).expect("read approved workspace tree") {
            let entry = entry.expect("approved workspace entry");
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("approved workspace metadata");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(base, &path, output);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .expect("relative approved workspace path")
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(
                    relative,
                    sha256_hex(&fs::read(path).expect("read approved workspace file")),
                );
            }
        }
    }

    let mut output = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut output);
    }
    output
}

fn assert_publish_rejected_without_workspace_write(fixture: &PublishCommandFixture) {
    let before = approved_tree_hashes(&fixture.approved_root());
    let error =
        publish_approved_generation_inner(&fixture.workflow, &fixture.workspace, fixture.request())
            .expect_err("invalidated source must fail before approved workspace commit");
    assert!(
        !error.error_type.is_empty(),
        "publish failure must retain a structured error"
    );
    assert_eq!(
        approved_tree_hashes(&fixture.approved_root()),
        before,
        "rejected publication changed approved workspace state"
    );
    assert!(
        fixture
            .workspace
            .list(Some(&fixture.privacy_case_id))
            .expect("list history after rejected publication")
            .is_empty(),
        "rejected publication created history"
    );
}

fn tamper_project_privacy_case_binding(fixture: &PublishCommandFixture) {
    let privacy_database = fixture
        .directory
        .path()
        .join("privacy")
        .join("privacy-workflow.sqlite");
    let connection = Connection::open(privacy_database).expect("privacy database");
    let trigger_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master
             WHERE type='trigger' AND name='trg_project_privacy_case_binding_no_update'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("canonical binding update guard");
    connection
        .execute_batch("DROP TRIGGER trg_project_privacy_case_binding_no_update;")
        .expect("open a test-only corruption window");
    connection
        .execute(
            "UPDATE project_privacy_case_bindings
             SET privacy_case_id=?2
             WHERE project_id=?1",
            rusqlite::params![fixture.project_id, format!("case_{}", "f".repeat(32))],
        )
        .expect("inject audited binding mismatch");
    connection
        .execute_batch(&format!("{trigger_sql};"))
        .expect("restore canonical binding guard");
}

#[test]
fn command_publish_commits_a_real_binding_authorized_generation() {
    let fixture = PublishCommandFixture::new();
    let published =
        publish_approved_generation_inner(&fixture.workflow, &fixture.workspace, fixture.request())
            .expect("publish through the command service boundary");
    assert_eq!(published.project_id, fixture.project_id);
    assert_eq!(published.material_id, fixture.material_id);
    let history = fixture
        .workspace
        .list(Some(&fixture.privacy_case_id))
        .expect("list committed publication");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].publication_id, published.publication_id);
}

#[test]
fn command_list_and_revoke_resolve_project_id_without_exposing_privacy_case_id() {
    let fixture = PublishCommandFixture::new();
    let published =
        publish_approved_generation_inner(&fixture.workflow, &fixture.workspace, fixture.request())
            .expect("publish through ProjectId boundary");
    let history = list_approved_generations_inner(
        &fixture.workflow,
        &fixture.workspace,
        ListApprovedGenerationsRequest {
            project_id: Some(fixture.project_id.clone()),
        },
    )
    .expect("list through ProjectId binding");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].project_id, fixture.project_id);
    let wire = serde_json::to_string(&history).expect("serialize safe history");
    assert!(!wire.contains("caseId"));
    assert!(!wire.contains("privacyCaseId"));
    assert!(!wire.contains(&fixture.privacy_case_id));

    revoke_approved_generation_inner(
        &fixture.workflow,
        &fixture.workspace,
        RevokeApprovedGenerationRequest {
            project_id: fixture.project_id.clone(),
            material_id: published.material_id,
            document_version: published.document_version,
            publication_id: published.publication_id,
        },
        || Ok(()),
    )
    .expect("revoke through ProjectId binding");
    let internal_history = fixture
        .workspace
        .list(Some(&fixture.privacy_case_id))
        .expect("read internal revoked generation");
    assert!(internal_history[0].revoked_at_unix.is_some());
}

#[test]
fn command_publish_rejects_mismatched_project_id_without_workspace_write() {
    let fixture = PublishCommandFixture::new();
    let before = approved_tree_hashes(&fixture.approved_root());
    let mut request = fixture.request();
    request.project_id = "case-another-project".to_owned();
    let error = publish_approved_generation_inner(&fixture.workflow, &fixture.workspace, request)
        .expect_err("redaction and caller ProjectId mismatch must fail closed");
    assert_eq!(error.error_type, "project_privacy_case_conflict");
    assert_eq!(approved_tree_hashes(&fixture.approved_root()), before);
}

#[test]
fn command_publish_rejects_binding_tamper_without_workspace_write() {
    let fixture = PublishCommandFixture::new();
    tamper_project_privacy_case_binding(&fixture);
    assert_publish_rejected_without_workspace_write(&fixture);
}

#[test]
fn command_list_and_revoke_reject_binding_tamper_without_workspace_write() {
    let fixture = PublishCommandFixture::new();
    let published =
        publish_approved_generation_inner(&fixture.workflow, &fixture.workspace, fixture.request())
            .expect("publish before binding tamper");
    tamper_project_privacy_case_binding(&fixture);
    let before = approved_tree_hashes(&fixture.approved_root());

    let list_error = list_approved_generations_inner(
        &fixture.workflow,
        &fixture.workspace,
        ListApprovedGenerationsRequest {
            project_id: Some(fixture.project_id.clone()),
        },
    )
    .expect_err("tampered binding must block ProjectId history resolution");
    assert!(!list_error.error_type.is_empty());

    let revoke_error = revoke_approved_generation_inner(
        &fixture.workflow,
        &fixture.workspace,
        RevokeApprovedGenerationRequest {
            project_id: fixture.project_id.clone(),
            material_id: published.material_id,
            document_version: published.document_version,
            publication_id: published.publication_id,
        },
        || Ok(()),
    )
    .expect_err("tampered binding must block ProjectId revocation resolution");
    assert!(!revoke_error.error_type.is_empty());
    assert_eq!(approved_tree_hashes(&fixture.approved_root()), before);
    let internal_history = fixture
        .workspace
        .list(Some(&fixture.privacy_case_id))
        .expect("read unchanged internal history");
    assert!(internal_history[0].revoked_at_unix.is_none());
}

#[test]
fn command_publish_rejects_completed_project_deletion_without_workspace_write() {
    let fixture = PublishCommandFixture::new();
    let user_database_path = database::user_database_path(fixture.directory.path());
    let mut user_connection =
        database::open_user_database(&user_database_path).expect("user database");
    assert!(fixture
        .workflow
        .delete_case_project_lifecycle(&mut user_connection, &fixture.project_id)
        .expect("complete project deletion"));
    drop(user_connection);

    assert_publish_rejected_without_workspace_write(&fixture);
}

#[test]
fn command_publish_rejects_material_generation_revocation_without_workspace_write() {
    let fixture = PublishCommandFixture::new();
    let deleted = fixture
        .workflow
        .delete_case_redaction_review(DeleteCaseRedactionReviewRequest {
            project_id: fixture.project_id.clone(),
            redaction_id: fixture.redaction_id.clone(),
            expected_source_sha256: fixture.source_sha256.clone(),
            expected_extraction_sha256: fixture.extraction_sha256.clone(),
        })
        .expect("revoke material and generation before publication");
    assert!(deleted.deleted);

    assert_publish_rejected_without_workspace_write(&fixture);
}

#[test]
fn startup_identity_preflight_never_mutates_a_missing_provider_when_history_exists() {
    for (index, relative) in STARTUP_IDENTITY_PRIMARY_HISTORY_PATHS.iter().enumerate() {
        let root = tempfile::tempdir().expect("startup identity root");
        install_startup_history(root.path(), relative, index >= 2);
        let keys = Arc::new(StartupTestKeys::missing());
        let workspace = startup_workspace(root.path().to_path_buf(), Arc::clone(&keys));

        let error = match workspace.preflight_startup_workspace_identity() {
            Ok(_) => panic!("existing component history without its identity must fail closed"),
            Err(error) => error,
        };

        assert_eq!(
            error.code(),
            "approved_mcp_identity_missing_for_existing_state",
            "history path {relative}"
        );
        assert_eq!(
            keys.load_or_create_calls(),
            0,
            "preflight called load_or_create for {relative}"
        );
        assert_eq!(
            keys.mutations(),
            0,
            "preflight mutated the key provider for {relative}"
        );
    }
}

#[test]
fn startup_identity_is_created_only_after_a_fresh_read_only_preflight() {
    let root = tempfile::tempdir().expect("startup identity root");
    let keys = Arc::new(StartupTestKeys::missing());
    let workspace = startup_workspace(root.path().to_path_buf(), Arc::clone(&keys));

    let preflight = workspace
        .preflight_startup_workspace_identity()
        .expect("fresh storage read-only preflight");
    assert_eq!(keys.load_or_create_calls(), 0);
    assert_eq!(keys.mutations(), 0);

    let first_identity = workspace
        .workspace_instance_id_after_startup_preflight(preflight)
        .expect("fresh identity initialization");
    assert_eq!(keys.load_or_create_calls(), 1);
    assert_eq!(keys.mutations(), 1);

    let existing_preflight = workspace
        .preflight_startup_workspace_identity()
        .expect("existing identity read-only preflight");
    let second_identity = workspace
        .workspace_instance_id_after_startup_preflight(existing_preflight)
        .expect("reuse existing identity");
    assert_eq!(second_identity, first_identity);
    assert_eq!(keys.load_or_create_calls(), 1);
    assert_eq!(keys.mutations(), 1);
}

#[test]
fn startup_identity_fresh_authorization_is_invalidated_by_new_history_without_mutation() {
    let root = tempfile::tempdir().expect("startup identity root");
    let keys = Arc::new(StartupTestKeys::missing());
    let workspace = startup_workspace(root.path().to_path_buf(), Arc::clone(&keys));
    let preflight = workspace
        .preflight_startup_workspace_identity()
        .expect("fresh storage read-only preflight");
    install_startup_history(
        root.path(),
        STARTUP_IDENTITY_PRIMARY_HISTORY_PATHS[0],
        false,
    );

    let error = workspace
        .workspace_instance_id_after_startup_preflight(preflight)
        .expect_err("history created after preflight invalidates fresh authorization");

    assert_eq!(error.code(), "approved_mcp_identity_preflight_failed");
    assert_eq!(keys.load_or_create_calls(), 0);
    assert_eq!(keys.mutations(), 0);
}

#[test]
fn startup_existing_identity_with_history_is_loaded_without_provider_mutation() {
    let root = tempfile::tempdir().expect("startup identity root");
    for (index, relative) in STARTUP_IDENTITY_PRIMARY_HISTORY_PATHS.iter().enumerate() {
        install_startup_history(root.path(), relative, index >= 2);
    }
    let keys = Arc::new(StartupTestKeys::existing());
    let workspace = startup_workspace(root.path().to_path_buf(), Arc::clone(&keys));

    let preflight = workspace
        .preflight_startup_workspace_identity()
        .expect("existing identity read-only preflight");
    let identity = workspace
        .workspace_instance_id_after_startup_preflight(preflight)
        .expect("existing identity");

    assert_eq!(
        identity,
        workspace_instance_id(&[0x66; 32]).expect("expected workspace identity")
    );
    assert_eq!(keys.load_or_create_calls(), 0);
    assert_eq!(keys.mutations(), 0);
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
