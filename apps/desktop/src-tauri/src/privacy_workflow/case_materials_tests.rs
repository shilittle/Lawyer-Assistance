use super::super::{
    test_workspace_instance_id, ApprovedPublicationInvalidator, LocalOcrExecutionContext,
};
use super::*;
use crate::privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig};
use material_processing::ExtractionBackend;
use privacy::{
    vnext::{CaseId, MaterialId},
    PrivacyStore, ReceiptSigner, RegisterPrivacyMaterial, SaveReviewDraft,
};
use rusqlite::params;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    sync::{mpsc, Arc, Barrier},
    thread,
    time::Duration,
};

const TEST_NOW: u64 = 1_800_000_000;
const PROJECT_A: &str = "case-project-material-a";
const PROJECT_B: &str = "case-project-material-b";

struct NoopPublicationInvalidator;

impl ApprovedPublicationInvalidator for NoopPublicationInvalidator {
    fn invalidate_case(
        &self,
        _case_id: &CaseId,
        _reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        Ok(0)
    }

    fn invalidate_material(
        &self,
        _case_id: &CaseId,
        _material_id: &MaterialId,
        _reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        Ok(0)
    }

    fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
        Ok(0)
    }

    fn invalidate_lifecycle_bindings(
        &self,
        _lifecycle_binding_ids: &BTreeSet<String>,
        _reason_code: &'static str,
    ) -> Result<u64, &'static str> {
        Ok(0)
    }
}

struct CaseFixture {
    directory: tempfile::TempDir,
    manager: PrivacyWorkflowManager,
}

impl CaseFixture {
    fn new(project_ids: &[&str]) -> Self {
        let directory = tempfile::tempdir().expect("temporary case-material workspace");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let user_connection =
            database::open_user_database(&user_database_path).expect("open user database");
        for project_id in project_ids {
            database::upsert_case_project(
                &user_connection,
                &database::CaseProjectRow {
                    project_id: (*project_id).to_owned(),
                    title: format!("Project {project_id}"),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .expect("insert case project");
        }
        drop(user_connection);

        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
            Arc::new(NoopPublicationInvalidator),
        )
        .expect("privacy workflow manager");
        let signer = ReceiptSigner::new([17_u8; 32]).expect("test receipt signer");
        manager.set_test_runtime(signer, TEST_NOW);
        Self { directory, manager }
    }

    fn prepare_text(&self, project_id: &str, source_name: &str) -> PrivacyReviewView {
        let path = self.directory.path().join(source_name);
        fs::write(
            &path,
            "Synthetic local-only client material: Alice Example, 13800138000.",
        )
        .expect("write local case material");
        self.manager
            .prepare_case_selected_material_with_qualification(
                &path,
                &PrivacyConfig::default(),
                &local_ocr_status(),
                LocalOcrExecutionContext {
                    mineru_config: None,
                    qualification: None,
                },
                project_id.to_owned(),
                Vec::new(),
            )
            .expect("prepare project-scoped material")
    }

    fn prepare_unassigned_local(&self, source_name: &str) -> PrivacyReviewView {
        self.manager
            .prepare_material_bytes(
                b"Synthetic unassigned local material: Alice Example, 13800138000.",
                source_name.to_owned(),
                &PrivacyConfig::default(),
                &local_ocr_status(),
                None,
                Vec::new(),
            )
            .expect("prepare unassigned local review")
    }
}

fn local_ocr_status() -> LocalOcrStatus {
    LocalOcrStatus {
        code: LocalOcrStatusCode::Disabled,
        message: "disabled for local text fixture".to_owned(),
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

fn assert_error_code<T: std::fmt::Debug>(
    result: Result<T, PrivacyWorkflowError>,
    expected: &'static str,
) {
    let error = result.expect_err("operation must fail closed");
    assert_eq!(error.code(), expected);
}

fn assert_no_private_case_identity(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, nested) in fields {
                assert!(
                    !matches!(
                        key.as_str(),
                        "caseId" | "privacyCaseId" | "case_id" | "privacy_case_id"
                    ),
                    "case-scoped DTO leaked private identity key {key}"
                );
                assert_no_private_case_identity(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_no_private_case_identity(nested);
            }
        }
        _ => {}
    }
}

fn set_review_case_id(manager: &PrivacyWorkflowManager, redaction_id: &str, case_id: Option<&str>) {
    let connection = manager.open_connection().expect("privacy database");
    let loaded =
        PrivacyStore::load_review_draft(&connection, redaction_id).expect("load review draft");
    let mut payload: Value =
        serde_json::from_slice(&loaded.review_payload_plaintext).expect("decode review payload");
    payload["caseId"] = case_id.map_or(Value::Null, |value| Value::String(value.to_owned()));
    let plaintext = serde_json::to_vec(&payload).expect("encode review payload");
    PrivacyStore::update_review_draft_exact(
        &connection,
        redaction_id,
        &loaded.redacted_content_sha256,
        &loaded.redacted_content_sha256,
        loaded.unresolved_high_risk_count,
        &plaintext,
    )
    .expect("update pending review identity");
}

fn set_review_payload_field(
    manager: &PrivacyWorkflowManager,
    redaction_id: &str,
    field: &str,
    value: Value,
) {
    let connection = manager.open_connection().expect("privacy database");
    let loaded =
        PrivacyStore::load_review_draft(&connection, redaction_id).expect("load review draft");
    let mut payload: Value =
        serde_json::from_slice(&loaded.review_payload_plaintext).expect("decode review payload");
    payload[field] = value;
    let plaintext = serde_json::to_vec(&payload).expect("encode review payload");
    PrivacyStore::update_review_draft_exact(
        &connection,
        redaction_id,
        &loaded.redacted_content_sha256,
        &loaded.redacted_content_sha256,
        loaded.unresolved_high_risk_count,
        &plaintext,
    )
    .expect("update protected review field");
}

fn append_pending_generation(
    manager: &PrivacyWorkflowManager,
    source_redaction_id: &str,
    redaction_id: &str,
) {
    let connection = manager.open_connection().expect("privacy database");
    let loaded = PrivacyStore::load_review_draft(&connection, source_redaction_id)
        .expect("load source review draft");
    let mut payload: Value =
        serde_json::from_slice(&loaded.review_payload_plaintext).expect("decode review payload");
    payload["redactionId"] = Value::String(redaction_id.to_owned());
    let plaintext = serde_json::to_vec(&payload).expect("encode second generation payload");
    PrivacyStore::save_review_draft(
        &connection,
        &SaveReviewDraft {
            redaction_id,
            material_id: &loaded.material_id,
            extraction_sha256: &loaded.extraction_sha256,
            redacted_content_sha256: &loaded.redacted_content_sha256,
            policy_id: &loaded.policy_id,
            policy_version: loaded.policy_version,
            detector_version: &loaded.detector_version,
            unresolved_high_risk_count: loaded.unresolved_high_risk_count,
            review_payload_plaintext: &plaintext,
        },
    )
    .expect("append pending generation");
}

fn unassigned_summary(
    manager: &PrivacyWorkflowManager,
    project_id: &str,
    material_id: &str,
) -> UnassignedCaseMaterialSummary {
    manager
        .list_unassigned_case_materials(ListUnassignedCaseMaterialsRequest {
            project_id: project_id.to_owned(),
        })
        .expect("list unassigned materials")
        .into_iter()
        .find(|material| material.material_id == material_id)
        .expect("unassigned material summary")
}

fn assignment_request(
    project_id: &str,
    material: &UnassignedCaseMaterialSummary,
) -> AssignUnassignedCaseMaterialRequest {
    AssignUnassignedCaseMaterialRequest {
        project_id: project_id.to_owned(),
        material_id: material.material_id.clone(),
        expected_row_version: material.row_version,
        actor: "local-reviewer".to_owned(),
    }
}

#[test]
fn assignment_schema_rejects_same_name_noop_audit_guards() {
    for (trigger_name, operation) in [
        ("trg_case_material_assignment_audit_no_update", "UPDATE"),
        ("trg_case_material_assignment_audit_no_delete", "DELETE"),
        ("trg_case_material_assignment_audit_no_replace", "INSERT"),
        ("trg_case_material_assignment_audit_scope_match", "INSERT"),
    ] {
        let fixture = CaseFixture::new(&[PROJECT_A]);
        let mut connection = fixture.manager.open_connection().expect("privacy database");
        connection
            .execute_batch(&format!(
                "DROP TRIGGER {trigger_name};
                 CREATE TRIGGER {trigger_name}
                 BEFORE {operation} ON case_material_assignment_audit
                 WHEN 0 BEGIN SELECT 1; END;"
            ))
            .expect("install same-name no-op trigger");
        assert!(
            initialize_assignment_schema(&mut connection).is_err(),
            "same-name no-op {trigger_name} must fail closed"
        );
        let stored_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [trigger_name],
                |row| row.get(0),
            )
            .expect("forged trigger remains visible");
        assert!(stored_sql.to_ascii_lowercase().contains("when 0"));
    }
}

#[test]
fn null_identity_assignment_updates_all_pending_generations_atomically_and_is_idempotent() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let review = fixture.prepare_unassigned_local("unassigned-null.txt");
    let second_redaction_id = "red_unassigned_null_second";
    append_pending_generation(&fixture.manager, &review.redaction_id, second_redaction_id);
    let summary = unassigned_summary(&fixture.manager, PROJECT_A, &review.material_id);
    assert!(summary.assignable);
    assert_eq!(summary.generation_count, 2);
    assert_eq!(summary.historical_identity, "missing");
    assert_no_private_case_identity(
        &serde_json::to_value(&summary).expect("serialize unassigned summary"),
    );
    let request = assignment_request(PROJECT_A, &summary);

    let assigned = fixture
        .manager
        .assign_unassigned_case_material(request.clone())
        .expect("assign null-identity material");
    assert_eq!(assigned.assignment_mode, "initialize_null_case");
    assert_eq!(assigned.binding_action, "created");
    assert!(!assigned.idempotent_replay);
    assert_no_private_case_identity(
        &serde_json::to_value(&assigned).expect("serialize assignment response"),
    );

    let connection = fixture.manager.open_connection().expect("privacy database");
    let project_id = ProjectId::parse(PROJECT_A).expect("project id");
    let privacy_case_id = ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
        .expect("resolve assignment binding")
        .expect("binding exists");
    for redaction_id in [&review.redaction_id, second_redaction_id] {
        let loaded = PrivacyStore::load_review_draft(&connection, redaction_id)
            .expect("load assigned pending generation");
        let payload: Value =
            serde_json::from_slice(&loaded.review_payload_plaintext).expect("decode payload");
        assert_eq!(
            payload.get("caseId").and_then(Value::as_str),
            Some(privacy_case_id.as_str())
        );
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT project_id,migration_status,row_version
                 FROM privacy_materials WHERE material_id=?1",
                [&review.material_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("assigned material row"),
        (
            Some(PROJECT_A.to_owned()),
            "ready".to_owned(),
            i64::try_from(assigned.material_row_version).expect("row version"),
        )
    );
    assert!(
        connection
            .execute(
                "UPDATE case_material_assignment_audit SET result='assigned'
                 WHERE assignment_id=?1",
                [&assigned.assignment_id],
            )
            .is_err(),
        "assignment audit UPDATE must be blocked"
    );
    assert!(
        connection
            .execute(
                "DELETE FROM case_material_assignment_audit WHERE assignment_id=?1",
                [&assigned.assignment_id],
            )
            .is_err(),
        "assignment audit DELETE must be blocked"
    );

    PrivacyStore::register_material(
        &connection,
        &RegisterPrivacyMaterial {
            material_id: "mat_assignment_event_collision",
            project_id: Some(PROJECT_A),
            attachment_id: None,
            source_sha256: &"7".repeat(64),
            source_name_sha256: &"8".repeat(64),
            media_type: "text/plain",
            page_count: Some(1),
        },
    )
    .expect("register collision-scope material");
    PrivacyStore::set_material_display_name(
        &connection,
        "mat_assignment_event_collision",
        Some(1),
        "collision.txt",
    )
    .expect("protect collision-scope display name");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO case_material_assignment_audit(
                    assignment_id,material_id,project_id,privacy_case_id,
                    assignment_mode,binding_action,actor_sha256,
                    expected_material_row_version,assigned_material_row_version,
                    previous_migration_status,previous_state,previous_event_hash,
                    event_hash,result,created_at
                 )
                 SELECT
                    'asn_event_hash_collision','mat_assignment_event_collision',
                    project_id,privacy_case_id,assignment_mode,binding_action,
                    actor_sha256,1,2,previous_migration_status,previous_state,
                    previous_event_hash,event_hash,result,created_at
                 FROM case_material_assignment_audit
                 WHERE assignment_id=?1",
                [&assigned.assignment_id],
            )
            .is_err(),
        "INSERT OR REPLACE with a colliding event hash must be blocked before replacement"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM case_material_assignment_audit",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("audit row count"),
        1
    );
    drop(connection);

    let catalog = fixture
        .manager
        .list_case_materials(ListCaseMaterialsRequest {
            project_id: PROJECT_A.to_owned(),
        })
        .expect("list manually assigned local review");
    let catalog_entry = catalog
        .iter()
        .find(|entry| entry.material_id == review.material_id)
        .expect("assigned local review appears in case catalog");
    assert_eq!(catalog_entry.source_kind, "local_review");
    assert_eq!(catalog_entry.migration_status, "ready");
    let generations = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: review.material_id.clone(),
        })
        .expect("list assigned local generations");
    assert_eq!(generations.len(), 2);
    let loaded = fixture
        .manager
        .load_case_redaction_review(LoadCaseRedactionReviewRequest {
            project_id: PROJECT_A.to_owned(),
            redaction_id: review.redaction_id.clone(),
        })
        .expect("load assigned local review in the case workbench");
    assert_eq!(loaded.material_id, review.material_id);
    assert_eq!(loaded.redaction_id, review.redaction_id);
    assert!(loaded.vault_object_id.is_none());
    assert!(loaded.vault_object_version.is_none());
    assert!(loaded.vault_isolation.is_none());

    let replay = fixture
        .manager
        .assign_unassigned_case_material(request)
        .expect("idempotent assignment replay");
    assert!(replay.idempotent_replay);
    assert_eq!(replay.assignment_id, assigned.assignment_id);
    assert_eq!(replay.material_row_version, assigned.material_row_version);
}

#[test]
fn assigned_local_review_scope_rejects_identity_vault_and_lifecycle_drift() {
    let fixture = CaseFixture::new(&[PROJECT_A, PROJECT_B]);
    let review = fixture.prepare_unassigned_local("assigned-local-scope.txt");
    let summary = unassigned_summary(&fixture.manager, PROJECT_A, &review.material_id);
    fixture
        .manager
        .assign_unassigned_case_material(assignment_request(PROJECT_A, &summary))
        .expect("assign local review to project");

    let load = || {
        fixture
            .manager
            .load_case_redaction_review(LoadCaseRedactionReviewRequest {
                project_id: PROJECT_A.to_owned(),
                redaction_id: review.redaction_id.clone(),
            })
    };
    load().expect("assigned local review is available");
    assert_error_code(
        fixture
            .manager
            .load_case_redaction_review(LoadCaseRedactionReviewRequest {
                project_id: PROJECT_B.to_owned(),
                redaction_id: review.redaction_id.clone(),
            }),
        "case_material_scope_mismatch",
    );

    let connection = fixture.manager.open_connection().expect("privacy database");
    let privacy_case_id = ProjectPrivacyCaseBindingStore::resolve(
        &connection,
        &ProjectId::parse(PROJECT_A).expect("project id"),
    )
    .expect("resolve binding")
    .expect("assigned binding");
    drop(connection);

    set_review_payload_field(
        &fixture.manager,
        &review.redaction_id,
        "caseId",
        Value::String(format!("case_{}", "9".repeat(32))),
    );
    assert_error_code(load(), "case_material_scope_mismatch");
    set_review_payload_field(
        &fixture.manager,
        &review.redaction_id,
        "caseId",
        Value::String(privacy_case_id.as_str().to_owned()),
    );
    set_review_payload_field(
        &fixture.manager,
        &review.redaction_id,
        "sourceSha256",
        Value::String("f".repeat(64)),
    );
    assert_error_code(load(), "case_material_scope_mismatch");
    set_review_payload_field(
        &fixture.manager,
        &review.redaction_id,
        "sourceSha256",
        Value::String(review.source_sha256.clone()),
    );

    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "INSERT INTO privacy_vault_material_refs(
                material_id,case_id,object_id,object_version,source_sha256,
                envelope_sha256,content_bytes,retention_expires_at_unix,
                retention_policy_revision,bound_at_unix,import_state,failure_code
             ) VALUES(?1,?2,'obj_forged_local_scope',1,?3,?4,1,?5,1,?6,'review_ready',NULL)",
            params![
                review.material_id,
                privacy_case_id.as_str(),
                review.source_sha256,
                "a".repeat(64),
                i64::try_from(TEST_NOW + 100).expect("test time"),
                i64::try_from(TEST_NOW).expect("test time"),
            ],
        )
        .expect("inject forged Vault tuple");
    drop(connection);
    assert_error_code(load(), "case_material_scope_mismatch");
    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "DELETE FROM privacy_vault_material_refs WHERE material_id=?1",
            [&review.material_id],
        )
        .expect("remove forged Vault tuple");
    connection
        .execute(
            "UPDATE privacy_materials
             SET migration_status='blocked',state='blocked',row_version=row_version+1
             WHERE material_id=?1",
            [&review.material_id],
        )
        .expect("block assigned local material");
    drop(connection);
    assert_error_code(load(), "case_material_unavailable");

    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "UPDATE privacy_materials
             SET migration_status='ready',state='review_required',
                 deleted_at=CURRENT_TIMESTAMP,row_version=row_version+1
             WHERE material_id=?1",
            [&review.material_id],
        )
        .expect("soft-delete assigned local material");
    drop(connection);
    assert_error_code(load(), "case_material_unavailable");

    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "UPDATE privacy_materials
             SET deleted_at=NULL,row_version=row_version+1
             WHERE material_id=?1",
            [&review.material_id],
        )
        .expect("restore material for revocation check");
    connection
        .execute(
            "UPDATE privacy_redactions
             SET revocation_state='revoked',revoked_at=CURRENT_TIMESTAMP,
                 row_version=row_version+1
             WHERE redaction_id=?1",
            [&review.redaction_id],
        )
        .expect("revoke assigned local generation");
    drop(connection);
    assert_error_code(load(), "case_material_unavailable");
}

#[test]
fn historical_identity_is_preserved_and_multiple_candidates_fail_closed() {
    let fixture = CaseFixture::new(&[PROJECT_A, PROJECT_B]);
    let historical = fixture.prepare_unassigned_local("historical-case.txt");
    let historical_case_id = format!("case_{}", "3".repeat(32));
    set_review_case_id(
        &fixture.manager,
        &historical.redaction_id,
        Some(&historical_case_id),
    );
    let summary = unassigned_summary(&fixture.manager, PROJECT_A, &historical.material_id);
    let assigned = fixture
        .manager
        .assign_unassigned_case_material(assignment_request(PROJECT_A, &summary))
        .expect("preserve exact historical identity");
    assert_eq!(assigned.assignment_mode, "preserve_historical_case");
    let connection = fixture.manager.open_connection().expect("privacy database");
    let project_id = ProjectId::parse(PROJECT_A).expect("project id");
    assert_eq!(
        ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
            .expect("resolve exact historical binding")
            .expect("binding exists")
            .as_str(),
        historical_case_id
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT legacy_case_id FROM privacy_materials WHERE material_id=?1",
                [&historical.material_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .expect("preserved material legacy identity")
            .as_deref(),
        Some(historical_case_id.as_str())
    );
    drop(connection);

    let ambiguous = fixture.prepare_unassigned_local("ambiguous-case.txt");
    set_review_case_id(
        &fixture.manager,
        &ambiguous.redaction_id,
        Some(&format!("case_{}", "4".repeat(32))),
    );
    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "UPDATE privacy_materials
             SET legacy_case_id=?2,row_version=row_version+1
             WHERE material_id=?1",
            params![ambiguous.material_id, format!("case_{}", "5".repeat(32))],
        )
        .expect("inject second historical candidate");
    drop(connection);
    let summary = unassigned_summary(&fixture.manager, PROJECT_B, &ambiguous.material_id);
    assert_error_code(
        fixture
            .manager
            .assign_unassigned_case_material(assignment_request(PROJECT_B, &summary)),
        "case_material_assignment_identity_ambiguous",
    );
    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .query_row(
                "SELECT project_id FROM privacy_materials WHERE material_id=?1",
                [&ambiguous.material_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .expect("ambiguous material remains"),
        None
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM case_material_assignment_audit
                 WHERE material_id=?1",
                [&ambiguous.material_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("no ambiguous assignment audit"),
        0
    );
}

#[test]
fn zero_generation_and_unbound_target_state_are_not_assignable() {
    let fixture = CaseFixture::new(&[PROJECT_A, PROJECT_B]);
    let zero_material_id = format!("mat_{}", "d".repeat(32));
    let connection = fixture.manager.open_connection().expect("privacy database");
    PrivacyStore::register_material(
        &connection,
        &RegisterPrivacyMaterial {
            material_id: &zero_material_id,
            project_id: None,
            attachment_id: None,
            source_sha256: &"9".repeat(64),
            source_name_sha256: &"a".repeat(64),
            media_type: "text/plain",
            page_count: Some(1),
        },
    )
    .expect("register zero-generation material");
    PrivacyStore::set_material_display_name(
        &connection,
        &zero_material_id,
        Some(1),
        "zero-generation.txt",
    )
    .expect("protect zero-generation display name");
    drop(connection);
    let zero = unassigned_summary(&fixture.manager, PROJECT_A, &zero_material_id);
    assert!(!zero.assignable);
    assert_error_code(
        fixture
            .manager
            .assign_unassigned_case_material(assignment_request(PROJECT_A, &zero)),
        "case_material_assignment_identity_invalid",
    );

    let orphan = fixture.prepare_unassigned_local("target-state-conflict.txt");
    let connection = fixture.manager.open_connection().expect("privacy database");
    PrivacyStore::register_material(
        &connection,
        &RegisterPrivacyMaterial {
            material_id: "mat_unbound_target_state",
            project_id: Some(PROJECT_B),
            attachment_id: None,
            source_sha256: &"b".repeat(64),
            source_name_sha256: &"c".repeat(64),
            media_type: "text/plain",
            page_count: Some(1),
        },
    )
    .expect("register unsafe unbound target state");
    drop(connection);
    let orphan_summary = unassigned_summary(&fixture.manager, PROJECT_B, &orphan.material_id);
    assert_error_code(
        fixture
            .manager
            .assign_unassigned_case_material(assignment_request(PROJECT_B, &orphan_summary)),
        "case_material_assignment_target_state_conflict",
    );
}

#[test]
fn blocked_and_revoked_unassigned_material_states_fail_closed() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let blocked = fixture.prepare_unassigned_local("blocked-unassigned.txt");
    let revoked = fixture.prepare_unassigned_local("revoked-unassigned.txt");
    let connection = fixture.manager.open_connection().expect("privacy database");
    connection
        .execute(
            "UPDATE privacy_materials
             SET state='blocked',row_version=row_version+1
             WHERE material_id=?1",
            [&blocked.material_id],
        )
        .expect("block unassigned material");
    connection
        .execute(
            "UPDATE privacy_materials
             SET state='revoked',row_version=row_version+1
             WHERE material_id=?1",
            [&revoked.material_id],
        )
        .expect("revoke unassigned material");
    drop(connection);
    for review in [&blocked, &revoked] {
        let summary = unassigned_summary(&fixture.manager, PROJECT_A, &review.material_id);
        assert!(!summary.assignable);
        assert_error_code(
            fixture
                .manager
                .assign_unassigned_case_material(assignment_request(PROJECT_A, &summary)),
            "case_material_assignment_conflict",
        );
    }
}

#[test]
fn concurrent_assignment_to_two_projects_commits_exactly_one_target_and_one_audit() {
    let fixture = CaseFixture::new(&[PROJECT_A, PROJECT_B]);
    let orphan = fixture.prepare_unassigned_local("concurrent-assignment.txt");
    let summary = unassigned_summary(&fixture.manager, PROJECT_A, &orphan.material_id);
    let second_manager = PrivacyWorkflowManager::new(
        fixture.directory.path().to_path_buf(),
        test_workspace_instance_id(),
    )
    .expect("second workflow manager");
    second_manager.set_test_runtime(
        ReceiptSigner::new([19_u8; 32]).expect("second signer"),
        TEST_NOW,
    );
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_manager = fixture.manager.clone();
    let first_summary = summary.clone();
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_manager
            .assign_unassigned_case_material(assignment_request(PROJECT_A, &first_summary))
            .map(|response| response.project_id)
            .map_err(|error| error.code().to_owned())
    });
    let second_barrier = Arc::clone(&barrier);
    let second_summary = summary;
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_manager
            .assign_unassigned_case_material(assignment_request(PROJECT_B, &second_summary))
            .map(|response| response.project_id)
            .map_err(|error| error.code().to_owned())
    });
    barrier.wait();
    let results = [
        first.join().expect("first assignment thread"),
        second.join().expect("second assignment thread"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                result.as_ref().err().map(String::as_str)
                    == Some("case_material_assignment_conflict")
            })
            .count(),
        1
    );
    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM case_material_assignment_audit
                 WHERE material_id=?1",
                [&orphan.material_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("single concurrent assignment audit"),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_bindings",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("single winning project binding"),
        1
    );
}

#[test]
fn prepare_creates_and_persists_unbound_project_privacy_case_binding() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let project_id = ProjectId::parse(PROJECT_A).expect("project id");
    {
        let connection = fixture.manager.open_connection().expect("privacy database");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve initial binding"),
            None
        );
    }

    let prepared = fixture.prepare_text(PROJECT_A, "binding-source.txt");
    let privacy_case_id = PrivacyCaseId::parse(
        prepared
            .case_id
            .clone()
            .expect("prepared review keeps internal Privacy CaseId"),
    )
    .expect("strict Privacy CaseId");
    assert_ne!(project_id.as_str(), privacy_case_id.as_str());
    assert!(prepared.backend_trace.iter().all(|trace| {
        trace.backend == ExtractionBackend::NativeText
            && trace.isolation_verified
            && trace.isolation_mechanism.as_deref() == Some("in_process_no_network_code_path")
    }));

    // Reopen SQLite so this assertion exercises the persisted one-to-one
    // binding rather than an in-memory value returned by preparation.
    let connection = fixture
        .manager
        .open_connection()
        .expect("reopen privacy database");
    assert_eq!(
        ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
            .expect("resolve persisted binding"),
        Some(privacy_case_id.clone())
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_binding_audit
                 WHERE project_id=?1 AND privacy_case_id=?2 AND result='created'",
                [project_id.as_str(), privacy_case_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("binding creation audit"),
        1
    );
    drop(connection);

    let loaded = fixture
        .manager
        .load_case_redaction_review(LoadCaseRedactionReviewRequest {
            project_id: PROJECT_A.to_owned(),
            redaction_id: prepared.redaction_id,
        })
        .expect("ProjectId resolves through the persistent binding");
    assert_eq!(loaded.project_id, PROJECT_A);
    assert_no_private_case_identity(
        &serde_json::to_value(loaded).expect("serialize case review DTO"),
    );
}

#[test]
fn lists_case_material_fields_and_generations_newest_first() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "catalog-source.txt");
    let connection = fixture.manager.open_connection().expect("privacy database");
    let loaded = PrivacyStore::load_review_draft(&connection, &prepared.redaction_id)
        .expect("load first generation draft");
    let second_redaction_id = "red_case_material_generation_two";
    PrivacyStore::save_review_draft(
        &connection,
        &SaveReviewDraft {
            redaction_id: second_redaction_id,
            material_id: &loaded.material_id,
            extraction_sha256: &loaded.extraction_sha256,
            redacted_content_sha256: &loaded.redacted_content_sha256,
            policy_id: &loaded.policy_id,
            policy_version: loaded.policy_version,
            detector_version: &loaded.detector_version,
            unresolved_high_risk_count: loaded.unresolved_high_risk_count,
            review_payload_plaintext: &loaded.review_payload_plaintext,
        },
    )
    .expect("insert second generation");
    drop(connection);

    let materials = fixture
        .manager
        .list_case_materials(ListCaseMaterialsRequest {
            project_id: PROJECT_A.to_owned(),
        })
        .expect("list case materials");
    assert_eq!(materials.len(), 1);
    let material = &materials[0];
    assert_eq!(material.project_id, PROJECT_A);
    assert_eq!(material.material_id, prepared.material_id);
    assert_eq!(material.display_name, "catalog-source.txt");
    assert_eq!(
        material.media_type.as_deref(),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(material.source_kind, "vault");
    assert_eq!(material.migration_status, "ready");
    assert_eq!(
        material.latest_review_state.as_deref(),
        Some("review_required")
    );
    assert_eq!(material.latest_generation_status.as_deref(), Some("ready"));
    assert_eq!(material.latest_revocation_state.as_deref(), Some("active"));
    assert_eq!(material.generation_count, 2);
    assert!(material.deleted_at.is_none());
    assert!(!material.extraction_status.is_empty());
    assert!(!material.state.is_empty());
    assert!(!material.updated_at.is_empty());
    let material_json = serde_json::to_value(material).expect("serialize material summary");
    assert_eq!(
        material_json
            .as_object()
            .expect("material object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "deletedAt",
            "displayName",
            "extractionStatus",
            "generationCount",
            "latestGenerationStatus",
            "latestReviewState",
            "latestRevocationState",
            "materialId",
            "mediaType",
            "migrationStatus",
            "projectId",
            "sourceKind",
            "state",
            "updatedAt",
        ]
        .into_iter()
        .collect()
    );

    let generations = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: prepared.material_id.clone(),
        })
        .expect("list redaction generations");
    assert_eq!(
        generations
            .iter()
            .map(|generation| generation.generation_number)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    assert_eq!(generations[0].redaction_id, second_redaction_id);
    for generation in &generations {
        assert_eq!(generation.project_id, PROJECT_A);
        assert_eq!(generation.material_id, prepared.material_id);
        assert_eq!(generation.generation_status, "ready");
        assert_eq!(generation.review_state, "review_required");
        assert_eq!(generation.revocation_state, "active");
        assert!(generation.approved_payload_sha256.is_none());
        assert!(generation.approved_at.is_none());
        assert!(generation.revoked_at.is_none());
        assert!(!generation.created_at.is_empty());
    }
    let generation_json =
        serde_json::to_value(&generations[0]).expect("serialize generation summary");
    assert_eq!(
        generation_json
            .as_object()
            .expect("generation object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "approvedAt",
            "approvedPayloadSha256",
            "createdAt",
            "generationNumber",
            "generationStatus",
            "materialId",
            "projectId",
            "redactionId",
            "reviewState",
            "revocationState",
            "revokedAt",
            "riskRevision",
        ]
        .into_iter()
        .collect()
    );

    let case_view = fixture
        .manager
        .load_case_redaction_review(LoadCaseRedactionReviewRequest {
            project_id: PROJECT_A.to_owned(),
            redaction_id: prepared.redaction_id,
        })
        .expect("load first generation");
    assert!(case_view.risk_review.is_some());
    for value in [
        serde_json::to_value(materials).expect("serialize material DTOs"),
        serde_json::to_value(generations).expect("serialize generation DTOs"),
        serde_json::to_value(case_view).expect("serialize review DTO"),
    ] {
        assert_no_private_case_identity(&value);
    }
}

#[test]
fn wrong_binding_cross_project_and_generation_payload_mismatches_fail_closed() {
    let fixture = CaseFixture::new(&[PROJECT_A, PROJECT_B]);
    let review_a = fixture.prepare_text(PROJECT_A, "scope-a.txt");
    let review_b = fixture.prepare_text(PROJECT_B, "scope-b.txt");

    assert_error_code(
        fixture
            .manager
            .load_case_redaction_review(LoadCaseRedactionReviewRequest {
                project_id: PROJECT_B.to_owned(),
                redaction_id: review_a.redaction_id.clone(),
            }),
        "case_material_scope_mismatch",
    );
    assert_error_code(
        fixture
            .manager
            .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
                project_id: PROJECT_A.to_owned(),
                material_id: review_b.material_id.clone(),
            }),
        "case_material_scope_mismatch",
    );

    let mut wrong_material_payload = review_a.clone();
    wrong_material_payload.material_id = review_b.material_id.clone();
    assert_error_code(
        fixture
            .manager
            .case_redaction_review_view(PROJECT_A.to_owned(), wrong_material_payload),
        "case_material_scope_mismatch",
    );
    let mut wrong_case_payload = review_a.clone();
    wrong_case_payload.case_id = review_b.case_id.clone();
    assert_error_code(
        fixture
            .manager
            .case_redaction_review_view(PROJECT_A.to_owned(), wrong_case_payload),
        "case_material_scope_mismatch",
    );

    let wrong_privacy_case_id = review_b.case_id.expect("Privacy CaseId for project B");
    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_vault_material_refs SET case_id=?2
                 WHERE material_id=?1",
                [
                    review_a.material_id.as_str(),
                    wrong_privacy_case_id.as_str()
                ],
            )
            .expect("inject mismatched Vault binding"),
        1
    );
    drop(connection);
    assert_error_code(
        fixture
            .manager
            .load_case_redaction_review(LoadCaseRedactionReviewRequest {
                project_id: PROJECT_A.to_owned(),
                redaction_id: review_a.redaction_id,
            }),
        "project_privacy_case_conflict",
    );
    assert_error_code(
        fixture
            .manager
            .list_case_materials(ListCaseMaterialsRequest {
                project_id: PROJECT_A.to_owned(),
            }),
        "project_privacy_case_conflict",
    );
    assert_error_code(
        fixture
            .manager
            .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
                project_id: PROJECT_A.to_owned(),
                material_id: review_a.material_id,
            }),
        "project_privacy_case_conflict",
    );
}

#[test]
fn blocked_deleted_revoked_and_stale_generations_fail_closed() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let blocked_material = fixture.prepare_text(PROJECT_A, "blocked-material.txt");
    let deleted_material = fixture.prepare_text(PROJECT_A, "deleted-material.txt");
    let blocked_generation = fixture.prepare_text(PROJECT_A, "blocked-generation.txt");
    let revoked_generation = fixture.prepare_text(PROJECT_A, "revoked-generation.txt");
    let stale_generation = fixture.prepare_text(PROJECT_A, "stale-generation.txt");

    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_materials
                 SET migration_status='blocked',state='blocked',row_version=row_version+1
                 WHERE material_id=?1",
                [blocked_material.material_id.as_str()],
            )
            .expect("block material"),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_materials
                 SET deleted_at=CURRENT_TIMESTAMP,row_version=row_version+1
                 WHERE material_id=?1",
                [deleted_material.material_id.as_str()],
            )
            .expect("soft-delete material"),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET generation_status='blocked',row_version=row_version+1
                 WHERE redaction_id=?1",
                [blocked_generation.redaction_id.as_str()],
            )
            .expect("block generation"),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='revoked',revoked_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE redaction_id=?1",
                [revoked_generation.redaction_id.as_str()],
            )
            .expect("revoke generation"),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='stale',row_version=row_version+1
                 WHERE redaction_id=?1",
                [stale_generation.redaction_id.as_str()],
            )
            .expect("mark generation stale"),
        1
    );
    drop(connection);

    let catalog = fixture
        .manager
        .list_case_materials(ListCaseMaterialsRequest {
            project_id: PROJECT_A.to_owned(),
        })
        .expect("list complete version history counts");
    let blocked_generation_material = catalog
        .iter()
        .find(|material| material.material_id == blocked_generation.material_id)
        .expect("blocked generation material remains in the catalog");
    assert_eq!(blocked_generation_material.generation_count, 1);
    assert_eq!(
        blocked_generation_material
            .latest_generation_status
            .as_deref(),
        Some("blocked")
    );

    for review in [
        &blocked_material,
        &deleted_material,
        &blocked_generation,
        &revoked_generation,
        &stale_generation,
    ] {
        assert_error_code(
            fixture
                .manager
                .load_case_redaction_review(LoadCaseRedactionReviewRequest {
                    project_id: PROJECT_A.to_owned(),
                    redaction_id: review.redaction_id.clone(),
                }),
            "case_material_unavailable",
        );
    }
    let blocked_material_history = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: blocked_material.material_id,
        })
        .expect("blocked material keeps read-only generation history");
    assert_eq!(blocked_material_history.len(), 1);
    let deleted_material_history = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: deleted_material.material_id,
        })
        .expect("deleted material keeps read-only generation history");
    assert_eq!(deleted_material_history.len(), 1);
    let blocked_history = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: blocked_generation.material_id,
        })
        .expect("blocked generation remains visible in version history");
    assert_eq!(blocked_history.len(), 1);
    assert_eq!(blocked_history[0].generation_status, "blocked");

    let revoked_history = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: revoked_generation.material_id,
        })
        .expect("revoked generation remains visible in version history");
    assert_eq!(revoked_history.len(), 1);
    assert_eq!(revoked_history[0].generation_status, "ready");
    assert_eq!(revoked_history[0].revocation_state, "revoked");

    let stale_history = fixture
        .manager
        .list_case_redaction_generations(ListCaseRedactionGenerationsRequest {
            project_id: PROJECT_A.to_owned(),
            material_id: stale_generation.material_id,
        })
        .expect("stale generation remains visible in version history");
    assert_eq!(stale_history.len(), 1);
    assert_eq!(stale_history[0].generation_status, "ready");
    assert_eq!(stale_history[0].review_state, "stale");
}

#[test]
fn scoped_mutation_rechecks_privacy_scope_after_validated_state_drifts() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "scope-drift.txt");
    let redaction_id = prepared.redaction_id.clone();
    let material_id = prepared.material_id.clone();
    let delete_request = DeletePrivacyReviewRequest {
        redaction_id: redaction_id.clone(),
        expected_source_sha256: prepared.source_sha256,
        expected_extraction_sha256: prepared.extraction_sha256,
    };

    let result = fixture.manager.with_case_redaction_scope(
        PROJECT_A.to_owned(),
        redaction_id,
        || {
            let connection = fixture
                .manager
                .open_connection()
                .expect("privacy database for state drift");
            assert_eq!(
                connection
                    .execute(
                        "UPDATE privacy_materials
                         SET state='blocked',row_version=row_version+1
                         WHERE material_id=?1",
                        [&material_id],
                    )
                    .expect("inject state drift"),
                1
            );
        },
        |authorization| {
            fixture
                .manager
                .delete_review_unlocked(delete_request, Some(authorization))
        },
    );
    assert_error_code(result, "case_material_unavailable");

    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_materials WHERE material_id=?1",
                [&material_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("material remains after denied mutation"),
        1
    );
}

#[test]
fn case_export_rechecks_scope_before_entering_the_atomic_install_closure() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "export-scope-drift.txt");
    let edited_pages = prepared
        .pages
        .iter()
        .map(|page| EditedRedactedPage {
            page_number: page.page_number,
            redacted_text: format!("{}\n人工复核完成。", page.redacted_text),
        })
        .collect::<Vec<_>>();
    let finding_ids = prepared
        .risk_review
        .as_ref()
        .expect("initial risk review")
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    let mut reviewed = prepared.clone();
    for finding_id in finding_ids {
        let revision = reviewed
            .risk_review
            .as_ref()
            .expect("current risk review")
            .revision;
        reviewed = fixture
            .manager
            .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                redaction_id: reviewed.redaction_id.clone(),
                expected_revision: revision,
                actor: "scope-test-reviewer".to_owned(),
                edited_pages: edited_pages.clone(),
                action: ReviewActionV1::AcceptReplacement {
                    finding_id,
                    apply_cluster: false,
                },
            })
            .expect("accept replacement");
    }
    let revision = reviewed
        .risk_review
        .as_ref()
        .expect("resolved risk review")
        .revision;
    reviewed = fixture
        .manager
        .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
            redaction_id: reviewed.redaction_id.clone(),
            expected_revision: revision,
            actor: "scope-test-reviewer".to_owned(),
            edited_pages: edited_pages.clone(),
            action: ReviewActionV1::ConfirmEditedOutput,
        })
        .expect("confirm edited output");
    let risk_revision = reviewed
        .risk_review
        .as_ref()
        .expect("confirmed risk review")
        .revision;
    fixture
        .manager
        .approve_review(ApprovePrivacyReviewRequest {
            redaction_id: reviewed.redaction_id.clone(),
            expected_risk_revision: Some(risk_revision),
            expected_suggested_redacted_sha256: reviewed.suggested_redacted_content_sha256.clone(),
            edited_pages,
            reviewer: "scope-test-reviewer".to_owned(),
            destination: ReceiptDestinationInput {
                kind: privacy::DestinationKind::VerifiedLocalProvider,
                identifier: SafeExportFormat::Txt.destination_identifier().to_owned(),
            },
            purpose: SafeExportFormat::Txt.purpose().to_owned(),
            ttl_seconds: 3_600,
        })
        .expect("approve case export");
    let case_request = ExportApprovedCaseRedactionRequest {
        project_id: PROJECT_A.to_owned(),
        redaction_id: reviewed.redaction_id.clone(),
        format: SafeExportFormat::Txt,
    };
    let built = fixture
        .manager
        .build_safe_export(&case_request.legacy_request())
        .expect("build approved export before drift");

    let connection = fixture.manager.open_connection().expect("privacy database");
    assert_eq!(
        connection
            .execute(
                "UPDATE privacy_materials
                 SET state='blocked',row_version=row_version+1
                 WHERE material_id=?1",
                [&reviewed.material_id],
            )
            .expect("block material after artifact build"),
        1
    );
    drop(connection);

    let install_entered = std::sync::atomic::AtomicBool::new(false);
    let error = fixture
        .manager
        .with_case_safe_export_authorization(
            &case_request,
            &built,
            || -> Result<(), PrivacyWorkflowError> {
                install_entered.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("scope drift must fail before filesystem installation");
    assert_eq!(error.code(), "case_material_unavailable");
    assert!(!install_entered.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn scoped_mutation_pins_project_until_privacy_commit_then_allows_project_delete() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "project-delete-race.txt");
    let redaction_id = prepared.redaction_id.clone();
    let material_id = prepared.material_id.clone();
    let user_database_path = database::user_database_path(fixture.directory.path());
    let delete_request = DeletePrivacyReviewRequest {
        redaction_id: redaction_id.clone(),
        expected_source_sha256: prepared.source_sha256,
        expected_extraction_sha256: prepared.extraction_sha256,
    };
    let (delete_started_tx, delete_started_rx) = mpsc::channel();
    let (delete_done_tx, delete_done_rx) = mpsc::channel();
    let mut deleter = None;
    let deletion_manager = fixture.manager.clone();

    let deleted = fixture
        .manager
        .with_case_redaction_scope(
            PROJECT_A.to_owned(),
            redaction_id,
            || {
                let path = user_database_path.clone();
                deleter = Some(thread::spawn(move || {
                    let mut connection =
                        database::open_user_database(&path).expect("open user database writer");
                    delete_started_tx
                        .send(())
                        .expect("signal project delete attempt");
                    let result =
                        deletion_manager.delete_case_project_lifecycle(&mut connection, PROJECT_A);
                    delete_done_tx
                        .send(result)
                        .expect("report project delete result");
                }));
                delete_started_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("project delete begins");
                assert!(
                    delete_done_rx
                        .recv_timeout(Duration::from_millis(200))
                        .is_err(),
                    "project deletion must remain blocked while the scoped operation is active"
                );
            },
            |authorization| {
                fixture
                    .manager
                    .delete_review_unlocked(delete_request, Some(authorization))
            },
        )
        .expect("privacy mutation commits against the pinned project");
    assert!(deleted.deleted);

    let deleted_projects = delete_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("project delete finishes after scoped commit")
        .expect("project delete succeeds");
    assert!(deleted_projects);
    deleter
        .take()
        .expect("project deleter thread")
        .join()
        .expect("project deleter joins");

    let user_connection =
        database::open_user_database_read_only(&user_database_path).expect("reopen user database");
    assert_eq!(
        user_connection
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id=?1",
                [PROJECT_A],
                |row| row.get::<_, i64>(0),
            )
            .expect("project count"),
        0
    );
    let privacy_connection = fixture.manager.open_connection().expect("privacy database");
    let retained = privacy_connection
        .query_row(
            "SELECT material.deleted_at IS NOT NULL,material.state,
                    generation.revocation_state,generation.revoked_at IS NOT NULL
             FROM privacy_materials AS material
             JOIN privacy_redactions AS generation
               ON generation.material_id=material.material_id
             WHERE material.material_id=?1",
            [&material_id],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .expect("retained material tombstone");
    assert_eq!(
        retained,
        (true, "revoked".to_owned(), "revoked".to_owned(), true)
    );
}

#[test]
fn material_catalog_read_pins_project_until_snapshot_commit() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "material-list-project-delete-race.txt");
    let user_database_path = database::user_database_path(fixture.directory.path());
    let (delete_started_tx, delete_started_rx) = mpsc::channel();
    let (delete_done_tx, delete_done_rx) = mpsc::channel();
    let mut deleter = None;
    let deletion_manager = fixture.manager.clone();

    let materials = fixture
        .manager
        .list_case_materials_with_test_hook(
            ListCaseMaterialsRequest {
                project_id: PROJECT_A.to_owned(),
            },
            || {
                let path = user_database_path.clone();
                deleter = Some(thread::spawn(move || {
                    let mut connection =
                        database::open_user_database(&path).expect("open user database writer");
                    delete_started_tx
                        .send(())
                        .expect("signal project delete attempt");
                    let result =
                        deletion_manager.delete_case_project_lifecycle(&mut connection, PROJECT_A);
                    delete_done_tx
                        .send(result)
                        .expect("report project delete result");
                }));
                delete_started_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("project delete begins");
                assert!(
                    delete_done_rx
                        .recv_timeout(Duration::from_millis(200))
                        .is_err(),
                    "project deletion must remain blocked while material catalog is read"
                );
            },
        )
        .expect("list materials against the pinned project snapshot");
    assert_eq!(materials.len(), 1);
    assert_eq!(materials[0].material_id, prepared.material_id);

    let deleted_projects = delete_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("project delete finishes after catalog snapshot commit")
        .expect("project delete succeeds");
    assert!(deleted_projects);
    deleter
        .take()
        .expect("project deleter thread")
        .join()
        .expect("project deleter joins");
}

#[test]
fn generation_catalog_read_pins_project_until_snapshot_commit() {
    let fixture = CaseFixture::new(&[PROJECT_A]);
    let prepared = fixture.prepare_text(PROJECT_A, "generation-list-project-delete-race.txt");
    let user_database_path = database::user_database_path(fixture.directory.path());
    let (delete_started_tx, delete_started_rx) = mpsc::channel();
    let (delete_done_tx, delete_done_rx) = mpsc::channel();
    let mut deleter = None;
    let deletion_manager = fixture.manager.clone();

    let generations = fixture
        .manager
        .list_case_redaction_generations_with_test_hook(
            ListCaseRedactionGenerationsRequest {
                project_id: PROJECT_A.to_owned(),
                material_id: prepared.material_id,
            },
            || {
                let path = user_database_path.clone();
                deleter = Some(thread::spawn(move || {
                    let mut connection =
                        database::open_user_database(&path).expect("open user database writer");
                    delete_started_tx
                        .send(())
                        .expect("signal project delete attempt");
                    let result =
                        deletion_manager.delete_case_project_lifecycle(&mut connection, PROJECT_A);
                    delete_done_tx
                        .send(result)
                        .expect("report project delete result");
                }));
                delete_started_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("project delete begins");
                assert!(
                    delete_done_rx
                        .recv_timeout(Duration::from_millis(200))
                        .is_err(),
                    "project deletion must remain blocked while generation catalog is read"
                );
            },
        )
        .expect("list generations against the pinned project snapshot");
    assert_eq!(generations.len(), 1);
    assert_eq!(generations[0].redaction_id, prepared.redaction_id);

    let deleted_projects = delete_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("project delete finishes after generation snapshot commit")
        .expect("project delete succeeds");
    assert!(deleted_projects);
    deleter
        .take()
        .expect("project deleter thread")
        .join()
        .expect("project deleter joins");
}
