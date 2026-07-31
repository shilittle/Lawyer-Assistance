use super::*;
use crate::privacy_workflow::provider_qualification::{
    ProviderQualificationKeyProvider, ProviderQualificationKeyRole,
};
use providers::{ChatTransport, ProviderError, ProviderErrorKind, TransportRequest};
use serde_json::json;
use std::sync::{mpsc, Arc, Barrier, Condvar, Mutex};

const RAW_CANARY: &str = "SYNTHETIC_CASE_RAW_CANARY_ALPHA";
const TEST_TASK_INSTRUCTION: &str = "Summarize the approved claim and preserve every placeholder.";

struct TestKeys {
    signing: [u8; 32],
    epoch: Mutex<[u8; 32]>,
}

impl TestKeys {
    fn new() -> Self {
        Self {
            signing: [0x31; 32],
            epoch: Mutex::new([0x52; 32]),
        }
    }
}

impl ProviderQualificationKeyProvider for TestKeys {
    fn load_or_create(
        &self,
        role: ProviderQualificationKeyRole,
    ) -> Result<[u8; 32], PrivacyWorkflowError> {
        match role {
            ProviderQualificationKeyRole::EvidenceSigning => Ok(self.signing),
            ProviderQualificationKeyRole::RevocationEpoch => self
                .epoch
                .lock()
                .map(|value| *value)
                .map_err(|_| qualification_test_error()),
        }
    }

    fn rotate(&self, role: ProviderQualificationKeyRole) -> Result<[u8; 32], PrivacyWorkflowError> {
        if !matches!(role, ProviderQualificationKeyRole::RevocationEpoch) {
            return Err(qualification_test_error());
        }
        let mut epoch = self.epoch.lock().map_err(|_| qualification_test_error())?;
        epoch[0] = epoch[0].wrapping_add(1);
        Ok(*epoch)
    }
}

fn qualification_test_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new("test_key_error", "synthetic qualification key error")
}

struct Fixture {
    _directory: tempfile::TempDir,
    manager: PrivacyWorkflowManager,
    signer: ReceiptSigner,
    keys: Arc<TestKeys>,
    profile: ProviderProfile,
    review: PrivacyReviewView,
    approval: ApproveApprovedProviderTaskResponse,
    receipt_token: String,
    approved_payload_json: String,
}

fn provider_profile(base_url: &str) -> ProviderProfile {
    if base_url.starts_with("http://127.0.0.1:") {
        return canary_profile(base_url.to_owned());
    }
    ProviderProfile {
        id: "provider-test".to_owned(),
        display_name: "Approved Provider Test".to_owned(),
        kind: ProviderKind::Custom,
        model_id: "provider-model".to_owned(),
        base_url: base_url.to_owned(),
        credential_account_id: "default".to_owned(),
        capabilities: ProviderCapabilities::custom_openai_compatible_defaults(),
        options: ProviderOptions {
            allow_private_network: base_url.starts_with("http://").then_some(true),
            ..ProviderOptions::default()
        },
    }
}

fn approved_fixture(base_url: &str) -> Fixture {
    let directory = tempfile::tempdir().expect("temporary privacy directory");
    let project_id = format!("case-provider-{}", Uuid::new_v4().simple());
    let user_database_path =
        database::ensure_user_database(directory.path()).expect("user database");
    let user_connection =
        database::open_user_database(&user_database_path).expect("open user database");
    database::upsert_case_project(
        &user_connection,
        &database::CaseProjectRow {
            project_id: project_id.clone(),
            title: "Approved Provider synthetic case".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: None,
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .expect("insert synthetic Provider case");
    drop(user_connection);
    let manager = PrivacyWorkflowManager::new(
        directory.path().to_path_buf(),
        crate::privacy_workflow::test_workspace_instance_id(),
    )
    .expect("privacy workflow manager");
    let signer = ReceiptSigner::new([0x2a_u8; 32]).expect("test signer");
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let keys = Arc::new(TestKeys::new());
    manager.set_test_runtime(signer.clone(), now_unix);
    let trait_keys: Arc<dyn ProviderQualificationKeyProvider> = keys.clone();
    manager.set_test_provider_qualification_keys(trait_keys);
    let profile = provider_profile(base_url);
    let qualification = manager
        .run_provider_qualification(profile.clone(), 20 * 60)
        .expect("full synthetic real-loopback qualification succeeds");
    assert!(qualification.qualified);
    assert!(qualification.prepare_canary_passed);
    assert!(qualification.approval_restore_canary_passed);
    assert!(qualification.real_loopback_transport_passed);
    assert!(qualification.approved_output_persisted);
    assert!(qualification.raw_canary_absent);
    assert!(qualification.exactly_one_request);

    let source =
        format!("Claimant: {RAW_CANARY}. The approved synthetic claim requests repayment.");
    let source_file =
        SyntheticProviderCanaryFile::create(&manager, source.as_bytes()).expect("synthetic source");
    let review = manager
        .prepare_case_selected_material_with_qualification(
            source_file.path(),
            &PrivacyConfig::default(),
            &disabled_ocr_status(),
            LocalOcrExecutionContext {
                mineru_config: None,
                qualification: None,
            },
            project_id,
            vec![RAW_CANARY.to_owned()],
        )
        .expect("prepare case-bound synthetic review through Vault");
    drop(source_file);
    let review = complete_synthetic_provider_human_review(&manager, review)
        .expect("complete every synthetic high-risk finding and confirm edited output");
    let approval = manager
        .approve_approved_provider_task(
            &profile,
            ApproveApprovedProviderTaskRequest {
                redaction_id: review.redaction_id.clone(),
                expected_risk_revision: review.risk_review.as_ref().map(|risk| risk.revision),
                expected_suggested_redacted_sha256: review
                    .suggested_redacted_content_sha256
                    .clone(),
                edited_pages: review
                    .pages
                    .iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.redacted_text.clone(),
                    })
                    .collect(),
                reviewer: "local-reviewer".to_owned(),
                provider_id: profile.id.clone(),
                task: ApprovedProviderTask::Summary,
                instruction: TEST_TASK_INSTRUCTION.to_owned(),
                prior_output: None,
                max_tokens: 512,
                ttl_seconds: 3_600,
                confirmed: true,
            },
        )
        .expect("approve exact Provider, task input, model, generation, and output bound");
    let request = DispatchApprovedProviderRequest {
        redaction_id: review.redaction_id.clone(),
        provider_id: profile.id.clone(),
        task: ApprovedProviderTask::Summary,
        instruction: TEST_TASK_INSTRUCTION.to_owned(),
        prior_output: None,
        max_tokens: 512,
    };
    let connection = manager.open_connection().expect("privacy store");
    let restored = restore_provider_authorization(
        &manager,
        &connection,
        &signer,
        now_unix,
        &request,
        &profile,
    )
    .expect("restore exact Provider task approval");
    let receipt_token = restored.receipt_token;
    let approved_payload_json = restored.approved_payload_json;
    Fixture {
        _directory: directory,
        manager,
        signer,
        keys,
        profile,
        review,
        approval,
        receipt_token,
        approved_payload_json,
    }
}

fn dispatch_request(fixture: &Fixture) -> DispatchApprovedProviderRequest {
    DispatchApprovedProviderRequest {
        redaction_id: fixture.review.redaction_id.clone(),
        provider_id: fixture.profile.id.clone(),
        task: ApprovedProviderTask::Summary,
        instruction: TEST_TASK_INSTRUCTION.to_owned(),
        prior_output: None,
        max_tokens: 512,
    }
}

#[test]
fn provider_task_approval_requires_backend_human_confirmation() {
    let fixture = approved_fixture("https://example.com/v1");
    let review = fixture
        .manager
        .load_review(&fixture.review.redaction_id)
        .expect("reload approved review");
    let error = fixture
        .manager
        .approve_approved_provider_task(
            &fixture.profile,
            ApproveApprovedProviderTaskRequest {
                redaction_id: review.redaction_id,
                expected_risk_revision: review.risk_review.as_ref().map(|risk| risk.revision),
                expected_suggested_redacted_sha256: review.suggested_redacted_content_sha256,
                edited_pages: review
                    .pages
                    .into_iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.redacted_text,
                    })
                    .collect(),
                reviewer: "local-reviewer".to_owned(),
                provider_id: fixture.profile.id.clone(),
                task: ApprovedProviderTask::Summary,
                instruction: TEST_TASK_INSTRUCTION.to_owned(),
                prior_output: None,
                max_tokens: 512,
                ttl_seconds: 3_600,
                confirmed: false,
            },
        )
        .expect_err("the backend must reject an unconfirmed Provider approval");
    assert_eq!(error.code(), "provider_task_confirmation_required");
}

fn approve_task(
    fixture: &Fixture,
    task: ApprovedProviderTask,
    instruction: &str,
    prior_output: Option<ApprovedProviderPriorOutputRef>,
    max_tokens: u32,
) -> ApproveApprovedProviderTaskResponse {
    let review = fixture
        .manager
        .load_review(&fixture.review.redaction_id)
        .expect("reload exact approved review and current risk revision");
    fixture
        .manager
        .approve_approved_provider_task(
            &fixture.profile,
            ApproveApprovedProviderTaskRequest {
                redaction_id: review.redaction_id,
                expected_risk_revision: review.risk_review.as_ref().map(|risk| risk.revision),
                expected_suggested_redacted_sha256: review.suggested_redacted_content_sha256,
                edited_pages: review
                    .pages
                    .into_iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.redacted_text,
                    })
                    .collect(),
                reviewer: "local-reviewer".to_owned(),
                provider_id: fixture.profile.id.clone(),
                task,
                instruction: instruction.to_owned(),
                prior_output,
                max_tokens,
                ttl_seconds: 3_600,
                confirmed: true,
            },
        )
        .expect("approve exact Provider task binding")
}

#[derive(Clone)]
struct CapturingTransport {
    requests: Arc<Mutex<Vec<String>>>,
    response_content: Arc<String>,
    model: Arc<String>,
}

impl CapturingTransport {
    fn successful(content: &str, model: &str) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            response_content: Arc::new(content.to_owned()),
            model: Arc::new(model.to_owned()),
        }
    }

    fn request_bodies(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ChatTransport for CapturingTransport {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProviderError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.body().to_owned());
        Ok(TransportResponse {
            status: 200,
            body: json!({
                "choices": [{"message": {"content": self.response_content.as_str()}}],
                "model": self.model.as_str()
            })
            .to_string(),
            first_content_token_latency_ms: None,
            total_latency_ms: 1,
        })
    }
}

#[test]
fn blocked_material_and_revoked_generation_are_rejected_before_provider_transport() {
    let blocked = approved_fixture("https://example.com/v1");
    let connection = blocked.manager.open_connection().expect("privacy store");
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_materials
                 SET migration_status='blocked',state='blocked',row_version=row_version+1
                 WHERE material_id=?1",
                [&blocked.review.material_id],
            )
            .expect("block approved material"),
        1
    );
    drop(connection);

    let approval_error = blocked
        .manager
        .approve_approved_provider_task(
            &blocked.profile,
            ApproveApprovedProviderTaskRequest {
                redaction_id: blocked.review.redaction_id.clone(),
                expected_risk_revision: blocked
                    .review
                    .risk_review
                    .as_ref()
                    .map(|risk| risk.revision),
                expected_suggested_redacted_sha256: blocked
                    .review
                    .suggested_redacted_content_sha256
                    .clone(),
                edited_pages: blocked
                    .review
                    .pages
                    .iter()
                    .map(|page| EditedRedactedPage {
                        page_number: page.page_number,
                        redacted_text: page.redacted_text.clone(),
                    })
                    .collect(),
                reviewer: "local-reviewer".to_owned(),
                provider_id: blocked.profile.id.clone(),
                task: ApprovedProviderTask::Summary,
                instruction: TEST_TASK_INSTRUCTION.to_owned(),
                prior_output: None,
                max_tokens: 512,
                ttl_seconds: 3_600,
                confirmed: true,
            },
        )
        .expect_err("blocked unified material cannot receive a Provider approval");
    assert_eq!(approval_error.code(), "case_material_unavailable");

    let blocked_transport = CapturingTransport::successful(
        "must never be sent",
        &profile_model_binding(&blocked.profile),
    );
    let dispatch_error = blocked
        .manager
        .dispatch_approved_provider(
            blocked_transport.clone(),
            blocked.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&blocked),
        )
        .expect_err("blocked unified material fails before Provider transport");
    assert_eq!(dispatch_error.code(), "case_material_unavailable");
    assert!(blocked_transport.request_bodies().is_empty());

    let revoked = approved_fixture("https://example.com/v1");
    let connection = revoked.manager.open_connection().expect("privacy store");
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='revoked',revoked_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE redaction_id=?1",
                [&revoked.review.redaction_id],
            )
            .expect("revoke approved generation"),
        1
    );
    drop(connection);
    let revoked_transport = CapturingTransport::successful(
        "must never be sent",
        &profile_model_binding(&revoked.profile),
    );
    let revoked_error = revoked
        .manager
        .dispatch_approved_provider(
            revoked_transport.clone(),
            revoked.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&revoked),
        )
        .expect_err("revoked generation fails before Provider transport");
    assert_eq!(revoked_error.code(), "case_material_unavailable");
    assert!(revoked_transport.request_bodies().is_empty());
}

#[test]
fn minimal_ipc_rejects_frontend_tokens_payloads_and_free_purpose() {
    let parsed = serde_json::from_value::<DispatchApprovedProviderRequest>(json!({
        "redactionId": "red_123",
        "providerId": "provider-test",
        "task": "summary",
        "maxTokens": 512,
        "receiptToken": "must-not-cross-ipc",
        "approvedPayloadJson": "must-not-cross-ipc",
        "purpose": "free-form-must-not-cross-ipc"
    }));
    assert!(parsed.is_err());

    let fixture = approved_fixture("https://example.com/v1");
    let serialized = serde_json::to_string(&fixture.approval).expect("serialize approval response");
    assert!(!serialized.contains("receiptToken"));
    assert!(!serialized.contains("approvedPayloadJson"));
    assert!(!serialized.contains(&fixture.receipt_token));
    assert!(!serialized.contains(&fixture.approved_payload_json));
}

#[test]
fn fixed_task_contract_covers_every_case_workflow_without_duplicate_purpose() {
    let purposes = ApprovedProviderTask::ALL
        .iter()
        .map(|task| task.purpose())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(purposes.len(), ApprovedProviderTask::ALL.len());
    assert!(purposes.contains("assistant_case_response"));
    assert!(purposes.contains("case_organization"));
    assert!(purposes.contains("case_legal_qa"));
    assert!(purposes.contains("case_relationship_graph"));
    assert!(purposes.contains("case_document_generation"));
    assert!(purposes.contains("case_regenerate"));
    assert!(purposes.contains("case_repair"));
    assert_eq!(task_contract_sha256().len(), 64);
}

#[test]
fn every_non_prior_task_completes_real_loopback_dispatch_persistence_and_readback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test Provider listener");
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let fixture = approved_fixture(&base_url);
    let tasks = ApprovedProviderTask::ALL
        .into_iter()
        .filter(|task| {
            !matches!(
                task,
                ApprovedProviderTask::Regenerate | ApprovedProviderTask::Repair
            )
        })
        .collect::<Vec<_>>();
    let server = spawn_test_server(
        listener,
        "all-task approved output",
        CANARY_MODEL_ID,
        tasks.len(),
    );
    let mut dispatched = Vec::new();

    for task in &tasks {
        let instruction = if *task == ApprovedProviderTask::Summary {
            TEST_TASK_INSTRUCTION.to_owned()
        } else {
            format!("Execute the human-approved fixed task {}.", task.purpose())
        };
        if *task != ApprovedProviderTask::Summary {
            approve_task(&fixture, *task, &instruction, None, 512);
        }
        let request = DispatchApprovedProviderRequest {
            redaction_id: fixture.review.redaction_id.clone(),
            provider_id: fixture.profile.id.clone(),
            task: *task,
            instruction,
            prior_output: None,
            max_tokens: 512,
        };
        let result = fixture
            .manager
            .dispatch_approved_provider(
                ReqwestTransport::new_with_timeouts(
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .expect("Reqwest transport"),
                fixture.profile.clone(),
                ApiSecret::new("synthetic-provider-secret"),
                request,
            )
            .expect("non-prior fixed task dispatch succeeds");
        dispatched.push((*task, result));
    }

    let requests = server.finish();
    assert_eq!(requests.len(), tasks.len());
    assert!(requests.iter().all(|request| {
        let wire = String::from_utf8_lossy(request);
        !wire.contains(RAW_CANARY) && wire.contains("BEGIN APPROVED REDACTED MATERIAL")
    }));

    let summaries = fixture
        .manager
        .list_approved_provider_outputs(
            &fixture.profile,
            ListApprovedProviderOutputsRequest {
                redaction_id: fixture.review.redaction_id.clone(),
                provider_id: fixture.profile.id.clone(),
            },
        )
        .expect("list every persisted non-prior output");
    assert_eq!(summaries.len(), tasks.len());
    for (task, result) in dispatched {
        let loaded = fixture
            .manager
            .load_approved_provider_output(LoadApprovedProviderOutputRequest {
                output_id: result.result_id,
                redaction_id: fixture.review.redaction_id.clone(),
                provider_id: fixture.profile.id.clone(),
                model_id: profile_model_binding(&fixture.profile),
                task,
            })
            .expect("read back exact non-prior protected output");
        assert_eq!(loaded.content, "all-task approved output");
    }
}

#[test]
fn regenerate_and_repair_complete_real_loopback_with_protected_prior_readback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test Provider listener");
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let fixture = approved_fixture(&base_url);
    let server = spawn_test_server(listener, "prior-bound approved output", CANARY_MODEL_ID, 3);
    let seed = fixture
        .manager
        .dispatch_approved_provider(
            ReqwestTransport::new_with_timeouts(Duration::from_secs(10), Duration::from_secs(10))
                .expect("Reqwest transport"),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect("seed protected prior output");
    let prior = ApprovedProviderPriorOutputRef {
        output_id: seed.result_id,
        task: ApprovedProviderTask::Summary,
    };
    let mut dispatched = Vec::new();

    for task in [
        ApprovedProviderTask::Regenerate,
        ApprovedProviderTask::Repair,
    ] {
        let instruction = format!("Execute the prior-bound fixed task {}.", task.purpose());
        approve_task(&fixture, task, &instruction, Some(prior.clone()), 512);
        let result = fixture
            .manager
            .dispatch_approved_provider(
                ReqwestTransport::new_with_timeouts(
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .expect("Reqwest transport"),
                fixture.profile.clone(),
                ApiSecret::new("synthetic-provider-secret"),
                DispatchApprovedProviderRequest {
                    redaction_id: fixture.review.redaction_id.clone(),
                    provider_id: fixture.profile.id.clone(),
                    task,
                    instruction,
                    prior_output: Some(prior.clone()),
                    max_tokens: 512,
                },
            )
            .expect("prior-bound fixed task dispatch succeeds");
        dispatched.push((task, result));
    }

    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests
        .iter()
        .all(|request| !String::from_utf8_lossy(request).contains(RAW_CANARY)));
    assert!(requests.iter().skip(1).all(|request| {
        let wire = String::from_utf8_lossy(request);
        wire.contains("BEGIN APPROVED PRIOR WORK")
    }));
    for (task, result) in dispatched {
        let loaded = fixture
            .manager
            .load_approved_provider_output(LoadApprovedProviderOutputRequest {
                output_id: result.result_id,
                redaction_id: fixture.review.redaction_id.clone(),
                provider_id: fixture.profile.id.clone(),
                model_id: profile_model_binding(&fixture.profile),
                task,
            })
            .expect("read back exact prior-bound protected output");
        assert_eq!(loaded.content, "prior-bound approved output");
    }
}

#[test]
fn changed_task_input_or_output_bound_is_zero_network() {
    let fixture = approved_fixture("https://example.com/v1");

    let mut changed_instruction = dispatch_request(&fixture);
    changed_instruction.instruction =
        "Summarize the approved claim with a different human instruction.".to_owned();
    let instruction_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            instruction_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            changed_instruction,
        )
        .expect_err("changed human task input has no matching signed approval");
    assert_eq!(error.code(), "redaction_receipt_invalid");
    assert!(instruction_transport.request_bodies().is_empty());

    let mut changed_bound = dispatch_request(&fixture);
    changed_bound.max_tokens = 513;
    let bound_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            bound_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            changed_bound,
        )
        .expect_err("changed max token bound has no matching signed approval");
    assert_eq!(error.code(), "redaction_receipt_invalid");
    assert!(bound_transport.request_bodies().is_empty());

    let mut missing_prior = dispatch_request(&fixture);
    missing_prior.task = ApprovedProviderTask::Regenerate;
    let prior_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            prior_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            missing_prior,
        )
        .expect_err("regenerate cannot omit its protected prior output");
    assert_eq!(error.code(), "invalid_provider_task_binding");
    assert!(prior_transport.request_bodies().is_empty());
}

#[test]
fn regenerate_uses_only_active_same_generation_protected_prior_output() {
    let fixture = approved_fixture("https://example.com/v1");
    let first_transport =
        CapturingTransport::successful("approved prior work product", "provider-model");
    let first = fixture
        .manager
        .dispatch_approved_provider(
            first_transport,
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect("create protected prior output");

    let instruction =
        "Regenerate the approved prior work as a concise chronology while preserving placeholders.";
    let prior = ApprovedProviderPriorOutputRef {
        output_id: first.result_id.clone(),
        task: ApprovedProviderTask::Summary,
    };
    let approval = approve_task(
        &fixture,
        ApprovedProviderTask::Regenerate,
        instruction,
        Some(prior.clone()),
        768,
    );
    assert_eq!(approval.task, ApprovedProviderTask::Regenerate);
    assert_eq!(approval.task_binding_sha256.len(), 64);

    let request = DispatchApprovedProviderRequest {
        redaction_id: fixture.review.redaction_id.clone(),
        provider_id: fixture.profile.id.clone(),
        task: ApprovedProviderTask::Regenerate,
        instruction: instruction.to_owned(),
        prior_output: Some(prior),
        max_tokens: 768,
    };
    let regenerate_transport =
        CapturingTransport::successful("regenerated approved work", "provider-model");
    let result = fixture
        .manager
        .dispatch_approved_provider(
            regenerate_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            request.clone(),
        )
        .expect("dispatch regenerate with exact protected prior output");
    assert_eq!(result.task_binding_sha256, approval.task_binding_sha256);
    let wire = regenerate_transport.request_bodies().join("\n");
    assert!(wire.contains(instruction));
    assert!(wire.contains("approved prior work product"));
    assert!(wire.contains("BEGIN APPROVED PRIOR WORK"));
    assert!(!wire.contains(RAW_CANARY));

    fixture
        .manager
        .revoke_approved_provider_output(RevokeApprovedProviderOutputRequest {
            output_id: first.result_id,
            redaction_id: fixture.review.redaction_id.clone(),
        })
        .expect("revoke prior output");
    let revoked_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            revoked_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            request,
        )
        .expect_err("revoked prior output fails before transport");
    assert!(matches!(
        error.code(),
        "approved_prior_output_inactive"
            | "privacy_lifecycle_mapping_revoked"
            | "privacy_lifecycle_mapping_not_available"
    ));
    assert!(revoked_transport.request_bodies().is_empty());
}

#[test]
fn full_app_reqwest_loopback_sends_once_restores_backend_state_and_persists_output() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test Provider listener");
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let fixture = approved_fixture(&base_url);
    let server = spawn_test_server(listener, "approved synthetic answer", CANARY_MODEL_ID, 1);
    let result = fixture
        .manager
        .dispatch_approved_provider(
            ReqwestTransport::new_with_timeouts(Duration::from_secs(10), Duration::from_secs(10))
                .expect("Reqwest transport"),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect("approved Provider dispatch succeeds");
    let requests = server.finish();

    assert_eq!(requests.len(), 1);
    let wire = String::from_utf8_lossy(&requests[0]);
    assert!(!wire.contains(RAW_CANARY));
    assert!(!wire.contains(&fixture.receipt_token));
    assert!(!wire.contains(&fixture.approved_payload_json));
    assert!(wire.contains("BEGIN APPROVED REDACTED MATERIAL"));
    assert!(result.result_id.starts_with("out_"));
    assert_eq!(result.approval_generation_id, fixture.approval.receipt_id);
    assert_eq!(result.content_sha256, sha256_hex(result.content.as_bytes()));

    let restarted = PrivacyWorkflowManager::new(
        fixture._directory.path().to_path_buf(),
        crate::privacy_workflow::test_workspace_instance_id(),
    )
    .expect("restart after Provider dispatch");
    restarted.set_test_runtime(fixture.signer.clone(), fixture.approval.issued_at_unix);
    let restarted_keys: Arc<dyn ProviderQualificationKeyProvider> = fixture.keys.clone();
    restarted.set_test_provider_qualification_keys(restarted_keys);
    let replay_transport = CapturingTransport::successful("must not be reached", CANARY_MODEL_ID);
    let replay_error = restarted
        .dispatch_approved_provider(
            replay_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("a consumed Provider approval cannot be replayed after restart");
    assert_eq!(replay_error.code(), "redaction_receipt_consumed");
    assert!(replay_transport.request_bodies().is_empty());

    let summaries = fixture
        .manager
        .list_approved_provider_outputs(
            &fixture.profile,
            ListApprovedProviderOutputsRequest {
                redaction_id: fixture.review.redaction_id.clone(),
                provider_id: fixture.profile.id.clone(),
            },
        )
        .expect("list protected outputs");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].output_id, result.result_id);
    let loaded = fixture
        .manager
        .load_approved_provider_output(LoadApprovedProviderOutputRequest {
            output_id: result.result_id.clone(),
            redaction_id: fixture.review.redaction_id.clone(),
            provider_id: fixture.profile.id.clone(),
            model_id: fixture.profile.model_id.clone(),
            task: ApprovedProviderTask::Summary,
        })
        .expect("load exact protected output");
    assert_eq!(loaded.content, "approved synthetic answer");
    fixture
        .manager
        .revoke_approved_provider_output(RevokeApprovedProviderOutputRequest {
            output_id: result.result_id.clone(),
            redaction_id: fixture.review.redaction_id.clone(),
        })
        .expect("revoke protected output");
    let error = fixture
        .manager
        .load_approved_provider_output(LoadApprovedProviderOutputRequest {
            output_id: result.result_id,
            redaction_id: fixture.review.redaction_id,
            provider_id: fixture.profile.id,
            model_id: fixture.profile.model_id,
            task: ApprovedProviderTask::Summary,
        })
        .expect_err("revoked output cannot be loaded");
    assert_eq!(error.code(), "approved_output_access_denied");
}

#[test]
fn concurrent_process_managers_consume_one_provider_approval_exactly_once() {
    let fixture = approved_fixture("https://example.com/v1");
    let new_manager = || {
        let manager = PrivacyWorkflowManager::new(
            fixture._directory.path().to_path_buf(),
            crate::privacy_workflow::test_workspace_instance_id(),
        )
        .expect("independent restarted manager");
        manager.set_test_runtime(fixture.signer.clone(), fixture.approval.issued_at_unix);
        let keys: Arc<dyn ProviderQualificationKeyProvider> = fixture.keys.clone();
        manager.set_test_provider_qualification_keys(keys);
        manager
    };
    let manager_a = new_manager();
    let manager_b = new_manager();
    let barrier = Arc::new(Barrier::new(2));
    let transport = CapturingTransport::successful("single approved result", "provider-model");
    let request = dispatch_request(&fixture);
    let profile = fixture.profile.clone();

    let results = std::thread::scope(|scope| {
        let spawn = |manager: PrivacyWorkflowManager| {
            let barrier = Arc::clone(&barrier);
            let transport = transport.clone();
            let request = request.clone();
            let profile = profile.clone();
            scope.spawn(move || {
                barrier.wait();
                manager.dispatch_approved_provider(
                    transport,
                    profile,
                    ApiSecret::new("synthetic-provider-secret"),
                    request,
                )
            })
        };
        let first = spawn(manager_a);
        let second = spawn(manager_b);
        vec![
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ]
    });

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let errors = results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code(), "redaction_receipt_consumed");
    assert_eq!(transport.request_bodies().len(), 1);
}

#[test]
fn same_second_reapproval_selects_new_unconsumed_provider_receipt() {
    let fixture = approved_fixture("https://example.com/v1");
    let first_transport = CapturingTransport::successful("first result", "provider-model");
    fixture
        .manager
        .dispatch_approved_provider(
            first_transport,
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect("consume the first approval");

    let second_approval = approve_task(
        &fixture,
        ApprovedProviderTask::Summary,
        TEST_TASK_INSTRUCTION,
        None,
        512,
    );
    assert_eq!(
        second_approval.issued_at_unix,
        fixture.approval.issued_at_unix
    );
    assert_ne!(second_approval.receipt_id, fixture.approval.receipt_id);

    let second_transport = CapturingTransport::successful("second result", "provider-model");
    let second_result = fixture
        .manager
        .dispatch_approved_provider(
            second_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect("same-second reapproval must select the unconsumed receipt");
    assert_eq!(second_result.content, "second result");
    assert_eq!(second_transport.request_bodies().len(), 1);
}

#[test]
fn qualification_persists_across_restart_and_tamper_fails_closed() {
    let fixture = approved_fixture("https://example.com/v1");
    let restarted = PrivacyWorkflowManager::new(
        fixture._directory.path().to_path_buf(),
        crate::privacy_workflow::test_workspace_instance_id(),
    )
    .expect("restarted manager");
    let now_unix = fixture.approval.issued_at_unix;
    restarted.set_test_runtime(fixture.signer.clone(), now_unix);
    let trait_keys: Arc<dyn ProviderQualificationKeyProvider> = fixture.keys.clone();
    restarted.set_test_provider_qualification_keys(trait_keys);
    assert!(
        restarted
            .provider_qualification_status(&fixture.profile)
            .expect("restart status")
            .qualified
    );

    let evidence = fixture
        ._directory
        .path()
        .join("privacy")
        .join("provider-qualification")
        .join("active-evidence-v1.json");
    let mut bytes = std::fs::read(&evidence).expect("read qualification evidence");
    let index = bytes
        .iter()
        .position(|byte| *byte == b'a')
        .expect("evidence has an ASCII byte");
    bytes[index] = b'b';
    std::fs::write(&evidence, bytes).expect("tamper evidence");
    let status = restarted
        .provider_qualification_status(&fixture.profile)
        .expect("invalid evidence maps to unqualified status");
    assert!(!status.qualified);
    assert_eq!(status.reason_code, "EVIDENCE_INVALID");
    let transport = CapturingTransport::successful("not reached", "provider-model");
    let error = restarted
        .dispatch_approved_provider(
            transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("tampered evidence blocks before transport");
    assert_eq!(error.code(), "provider_not_qualified");
    assert!(transport.request_bodies().is_empty());
}

#[test]
fn drift_task_expiry_and_receipt_revoke_are_zero_network() {
    let fixture = approved_fixture("https://example.com/v1");

    let model_transport = CapturingTransport::successful("not reached", "changed-model");
    let mut changed_model = fixture.profile.clone();
    changed_model.model_id = "changed-model".to_owned();
    let error = fixture
        .manager
        .dispatch_approved_provider(
            model_transport.clone(),
            changed_model,
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("model drift is unqualified");
    assert_eq!(error.code(), "provider_not_qualified");
    assert!(model_transport.request_bodies().is_empty());

    let endpoint_transport = CapturingTransport::successful("not reached", "provider-model");
    let mut changed_endpoint = fixture.profile.clone();
    changed_endpoint.base_url = "https://changed.example/v1".to_owned();
    let error = fixture
        .manager
        .dispatch_approved_provider(
            endpoint_transport.clone(),
            changed_endpoint,
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("endpoint drift is unqualified");
    assert_eq!(error.code(), "provider_not_qualified");
    assert!(endpoint_transport.request_bodies().is_empty());

    let task_transport = CapturingTransport::successful("not reached", "provider-model");
    let mut wrong_task = dispatch_request(&fixture);
    wrong_task.task = ApprovedProviderTask::CaseLegalQa;
    let error = fixture
        .manager
        .dispatch_approved_provider(
            task_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            wrong_task,
        )
        .expect_err("fixed task without exact approval receipt is rejected");
    assert_eq!(error.code(), "redaction_receipt_invalid");
    assert!(task_transport.request_bodies().is_empty());

    fixture
        .manager
        .set_test_now(fixture.approval.expires_at_unix + 1);
    let expiry_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            expiry_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("expired qualification or receipt is rejected");
    assert!(matches!(
        error.code(),
        "provider_not_qualified" | "redaction_receipt_expired"
    ));
    assert!(expiry_transport.request_bodies().is_empty());

    fixture
        .manager
        .set_test_now(fixture.approval.issued_at_unix);
    let receipt = fixture
        .signer
        .decode_token(&fixture.receipt_token)
        .expect("decode parent receipt");
    let connection = fixture.manager.open_connection().expect("privacy store");
    PrivacyStore::revoke_receipt(
        &connection,
        &receipt.claims.receipt_id,
        fixture.approval.issued_at_unix + 1,
    )
    .expect("revoke parent receipt");
    let revoke_transport = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            revoke_transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("revoked receipt is rejected");
    assert_eq!(error.code(), "redaction_receipt_invalid");
    assert!(revoke_transport.request_bodies().is_empty());
}

#[test]
fn residual_output_is_quarantined_and_never_saved_as_normal_output() {
    let fixture = approved_fixture("https://example.com/v1");
    let transport = CapturingTransport::successful("13800138000", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("sensitive Provider output is quarantined");
    assert_eq!(error.code(), "residual_sensitive_content");
    assert_eq!(transport.request_bodies().len(), 1);
    let outputs = fixture
        .manager
        .list_approved_provider_outputs(
            &fixture.profile,
            ListApprovedProviderOutputsRequest {
                redaction_id: fixture.review.redaction_id,
                provider_id: fixture.profile.id.clone(),
            },
        )
        .expect("list output history");
    assert!(outputs.is_empty());
}

#[test]
fn exact_case_canary_output_is_quarantined_before_save_or_webview_return() {
    let fixture = approved_fixture("https://example.com/v1");
    let transport = CapturingTransport::successful(RAW_CANARY, "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            transport.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("an exact source canary must be quarantined even if generic rules miss it");
    assert_eq!(error.code(), "residual_sensitive_content");
    assert_eq!(transport.request_bodies().len(), 1);
    let outputs = fixture
        .manager
        .list_approved_provider_outputs(
            &fixture.profile,
            ListApprovedProviderOutputsRequest {
                redaction_id: fixture.review.redaction_id,
                provider_id: fixture.profile.id.clone(),
            },
        )
        .expect("list output history");
    assert!(outputs.is_empty());
}

#[derive(Clone)]
struct BlockingTransport {
    entered: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl ChatTransport for BlockingTransport {
    fn send(&self, _request: TransportRequest) -> Result<TransportResponse, ProviderError> {
        self.entered
            .send(())
            .map_err(|_| ProviderError::new(ProviderErrorKind::Network, "test channel closed"))?;
        let (lock, condition) = &*self.release;
        let mut released = lock
            .lock()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Network, "test lock poisoned"))?;
        while !*released {
            released = condition.wait(released).map_err(|_| {
                ProviderError::new(ProviderErrorKind::Network, "test wait poisoned")
            })?;
        }
        Ok(TransportResponse {
            status: 200,
            body: json!({
                "choices": [{"message": {"content": "lease-protected output"}}],
                "model": "provider-model"
            })
            .to_string(),
            first_content_token_latency_ms: None,
            total_latency_ms: 1,
        })
    }
}

#[test]
fn qualification_revoke_cannot_race_the_final_transport_lease() {
    let fixture = approved_fixture("https://example.com/v1");
    let (entered_sender, entered_receiver) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let dispatch_manager = fixture.manager.clone();
    let dispatch_profile = fixture.profile.clone();
    let dispatch_input = dispatch_request(&fixture);
    let dispatch_release = release.clone();
    let dispatch = thread::spawn(move || {
        dispatch_manager.dispatch_approved_provider(
            BlockingTransport {
                entered: entered_sender,
                release: dispatch_release,
            },
            dispatch_profile,
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_input,
        )
    });
    entered_receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("transport reached under operation lease");

    let revoke_manager = fixture.manager.clone();
    let revoke_profile = fixture.profile.clone();
    let (revoked_sender, revoked_receiver) = mpsc::channel();
    let revoke = thread::spawn(move || {
        let result = revoke_manager.revoke_provider_qualification(&revoke_profile);
        let _ = revoked_sender.send(result);
    });
    assert!(revoked_receiver
        .recv_timeout(Duration::from_millis(100))
        .is_err());
    {
        let (lock, condition) = &*release;
        *lock.lock().expect("release lock") = true;
        condition.notify_all();
    }
    assert!(dispatch.join().expect("dispatch joins").is_ok());
    let revoked = revoked_receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("revoke completes after transport")
        .expect("revoke succeeds");
    assert!(!revoked.qualified);
    assert!(revoked.revoked);
    revoke.join().expect("revoke joins");

    let blocked = CapturingTransport::successful("not reached", "provider-model");
    let error = fixture
        .manager
        .dispatch_approved_provider(
            blocked.clone(),
            fixture.profile.clone(),
            ApiSecret::new("synthetic-provider-secret"),
            dispatch_request(&fixture),
        )
        .expect_err("rotated epoch invalidates every later dispatch");
    assert_eq!(error.code(), "provider_not_qualified");
    assert!(blocked.request_bodies().is_empty());
}

struct TestProviderServer {
    shutdown: mpsc::Sender<()>,
    server_thread: Option<thread::JoinHandle<Vec<Vec<u8>>>>,
}

impl TestProviderServer {
    fn finish(mut self) -> Vec<Vec<u8>> {
        let _ = self.shutdown.send(());
        self.server_thread
            .take()
            .expect("test Provider server thread is owned")
            .join()
            .expect("test Provider server exits")
    }
}

impl Drop for TestProviderServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
        if let Some(server_thread) = self.server_thread.take() {
            if server_thread.join().is_err() {
                if thread::panicking() {
                    eprintln!("test Provider server thread terminated unexpectedly");
                } else {
                    panic!("test Provider server thread terminated unexpectedly");
                }
            }
        }
    }
}

fn spawn_test_server(
    listener: TcpListener,
    content: &'static str,
    model: &'static str,
    expected_requests: usize,
) -> TestProviderServer {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let (shutdown, shutdown_receiver) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let mut requests = Vec::new();
        if ready_sender.send(()).is_err() {
            return requests;
        }
        while requests.len() < expected_requests {
            match shutdown_receiver.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("test Provider connection becomes blocking");
                    requests.push(read_http_request(&mut stream));
                    let body = json!({
                        "model": model,
                        "choices": [{"message": {"content": content}}]
                    })
                    .to_string();
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).unwrap();
                    stream.write_all(body.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    stream.shutdown(std::net::Shutdown::Write).unwrap();
                    let mut peer_close = [0_u8; 1];
                    let _ = stream.read(&mut peer_close);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test Provider listener failed: {error}"),
            }
        }
        requests
    });
    let server = TestProviderServer {
        shutdown,
        server_thread: Some(server_thread),
    };
    ready_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("test Provider server becomes ready");
    server
}
