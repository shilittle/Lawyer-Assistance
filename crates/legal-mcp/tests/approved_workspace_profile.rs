use legal_mcp::{
    registry::{
        PrivacyProfile, ToolRegistry, APPROVED_CASE_WORKSPACE_PROFILE_TOOL_NAMES, TOOL_NAMES,
    },
    service_adapter::ServiceAdapter,
};
use legal_services::{LegalServices, ServiceConfig};
use rmcp::model::JsonObject;
use serde_json::{json, Value};

fn services() -> (tempfile::TempDir, LegalServices) {
    let directory = tempfile::tempdir().expect("temporary service root");
    let legal = directory.path().join("legal.sqlite");
    let user = directory.path().join("user.sqlite");
    let materials = directory.path().join("materials");
    let output = directory.path().join("output");
    std::fs::write(&legal, []).expect("legal placeholder");
    std::fs::write(&user, []).expect("user placeholder");
    std::fs::create_dir(&materials).expect("materials root");
    std::fs::create_dir(&output).expect("output root");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: legal,
        user_database_path: user,
        allowed_file_roots: vec![materials],
        allowed_output_root: output,
    })
    .expect("service configuration");
    (directory, services)
}

fn object(value: Value) -> JsonObject {
    value.as_object().cloned().expect("object fixture")
}

#[test]
fn approved_profile_is_exactly_public_five_plus_workspace_ten_plus_diagram_six() {
    let registry = ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace);
    let names = registry
        .list()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        APPROVED_CASE_WORKSPACE_PROFILE_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(names.len(), TOOL_NAMES.len() + 10 + 6);
    assert!(!names.iter().any(|name| name == "citation_validate"));
    assert!(!names.iter().any(|name| name == "case_get_state"));
    assert_eq!(
        "approved-case-workspace".parse::<PrivacyProfile>(),
        Ok(PrivacyProfile::ApprovedCaseWorkspace)
    );
    for name in [
        "diagram.list_templates",
        "diagram.get_schema",
        "diagram.validate",
        "diagram.render",
        "diagram.update",
        "diagram.export",
    ] {
        let tool = registry.get(name).expect("approved diagram tool");
        let schema = serde_json::to_string(&tool.input_schema).expect("diagram schema JSON");
        assert!(schema.contains("access_ticket"), "{name}");
        assert!(!schema.contains("artifact_uri"), "{name}");
        assert!(!schema.contains("file_name"), "{name}");
        assert!(!schema.contains("\"uri\""), "{name}");
    }

    let default_names = ToolRegistry::new()
        .list()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        default_names,
        TOOL_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn approved_diagram_calls_fail_closed_and_reject_raw_location_fields() {
    let (_directory, services) = services();
    let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::ApprovedCaseWorkspace);
    let unavailable = adapter
        .call(
            "diagram.list_templates",
            Some(object(json!({"schema_version":1}))),
        )
        .await
        .expect("approved diagram contract is discoverable");
    let unavailable = serde_json::to_value(unavailable).expect("unavailable result JSON");
    assert_eq!(
        unavailable["structuredContent"]["reason_code"],
        "PROFILE_NOT_QUALIFIED"
    );

    let error = adapter
        .call(
            "diagram.export",
            Some(object(json!({
                "schema_version":1,
                "case_id":format!("case_{}", "a".repeat(32)),
                "work_product_id":format!("wp_{}", "b".repeat(32)),
                "version":1,
                "format":"html",
                "path":"C:\\private-canary\\diagram.html"
            }))),
        )
        .await
        .expect_err("raw location is rejected before backend execution");
    let wire = serde_json::to_string(&error).expect("error JSON");
    assert!(!wire.contains("private-canary"));
    assert!(!wire.contains("diagram.html"));
}

#[tokio::test]
async fn valid_approved_tool_call_is_anonymous_and_fails_closed() {
    let (_directory, services) = services();
    let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::ApprovedCaseWorkspace);
    let result = adapter
        .call("case_list", Some(object(json!({"schema_version": 1}))))
        .await
        .expect("contract is discoverable");
    let wire = serde_json::to_value(result).expect("result JSON");
    assert_eq!(
        wire["structuredContent"],
        json!({
            "schema_version": 1,
            "status": "unavailable",
            "reason_code": "PROFILE_NOT_QUALIFIED"
        })
    );
    assert_eq!(wire["isError"], true);
    let serialized = serde_json::to_string(&wire).expect("serialize result");
    for forbidden in ["case_", "mat_", "pub_", "C:\\\\", "private-canary"] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
}

#[tokio::test]
async fn invalid_approved_tool_arguments_are_rejected_without_echo() {
    let (_directory, services) = services();
    let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::ApprovedCaseWorkspace);
    let canary = "C:\\private-canary\\raw-case.pdf";
    let error = adapter
        .call(
            "case_read_approved_material",
            Some(object(json!({
                "schema_version": 1,
                "case_id": format!("case_{}", "a".repeat(32)),
                "material_id": format!("mat_{}", "b".repeat(32)),
                "publication_id": format!("pub_{}", "c".repeat(32)),
                "path": canary
            }))),
        )
        .await
        .expect_err("unknown location field is rejected");
    let serialized = serde_json::to_string(&error).expect("serialize error");
    assert!(!serialized.contains(canary));
    assert!(!serialized.contains("raw-case.pdf"));
}
