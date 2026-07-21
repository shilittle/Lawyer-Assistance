use legal_mcp::{
    registry::{
        PrivacyProfile, ToolRegistry, DIAGRAM_AUTHORING_TOOL_NAMES, REDACTED_CASE_TOOL_NAMES,
        TOOL_NAMES,
    },
    service_adapter::ServiceAdapter,
};
use legal_services::{LegalServices, ServiceConfig};
use rmcp::model::JsonObject;
use serde_json::{json, Value};

#[test]
fn diagram_profile_is_explicit_and_existing_profiles_are_unchanged() {
    let public = ToolRegistry::for_profile(PrivacyProfile::PublicLawOnly);
    let redacted = ToolRegistry::for_profile(PrivacyProfile::RedactedCase);
    let diagrams = ToolRegistry::for_profile(PrivacyProfile::DiagramAuthoring);
    assert_eq!(names(&public), TOOL_NAMES.map(str::to_owned));
    assert_eq!(
        names(&redacted),
        REDACTED_CASE_TOOL_NAMES.map(str::to_owned)
    );
    assert_eq!(
        names(&diagrams),
        DIAGRAM_AUTHORING_TOOL_NAMES.map(str::to_owned)
    );
    for name in DIAGRAM_AUTHORING_TOOL_NAMES.iter().skip(5) {
        assert!(public.get(name).is_none(), "{name}");
        assert!(redacted.get(name).is_none(), "{name}");
        let tool = diagrams.get(name).expect("diagram tool is registered");
        assert!(tool.output_schema.is_some(), "{name}");
        assert_eq!(
            tool.annotations
                .as_ref()
                .and_then(|item| item.open_world_hint),
            Some(false),
            "{name}"
        );
    }
}

#[tokio::test]
async fn diagram_mcp_lists_validates_and_renders_without_echoing_input_text() {
    let directory = tempfile::tempdir().expect("temporary diagram MCP root");
    let legal = directory.path().join("legal.sqlite");
    let user = directory.path().join("user.sqlite");
    let materials = directory.path().join("materials");
    let output = directory.path().join("output");
    std::fs::write(&legal, []).expect("legal database placeholder");
    std::fs::write(&user, []).expect("user database placeholder");
    std::fs::create_dir(&materials).expect("materials directory");
    std::fs::create_dir(&output).expect("output directory");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: legal,
        user_database_path: user,
        allowed_file_roots: vec![materials],
        allowed_output_root: output.clone(),
    })
    .expect("service configuration");
    let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::DiagramAuthoring);

    let listed = adapter
        .call(
            "diagram.list_templates",
            Some(object(json!({"schema_version":1}))),
        )
        .await
        .expect("list call succeeds");
    let listed = serde_json::to_value(listed).expect("list result serializes");
    assert_eq!(
        listed["structuredContent"]["templates"]
            .as_array()
            .map(Vec::len),
        Some(7)
    );
    for template in listed["structuredContent"]["templates"]
        .as_array()
        .expect("template list")
    {
        assert_eq!(
            template["example"]["template_id"], template["id"],
            "each template exposes its bundled fictional example"
        );
    }
    let list_wire = serde_json::to_string(&listed).expect("list result JSON");
    assert!(!list_wire.contains("example_path"));
    assert!(!list_wire.contains(&directory.path().display().to_string()));

    let mut invalid_shape: Value = serde_json::from_str(include_str!(
        "../../diagrams/examples/case_issue_evidence_law_v1.json"
    ))
    .expect("bundled diagram example parses");
    invalid_shape["nodes"][0]["type"] = Value::String("not_a_registered_type".to_owned());
    let invalid_shape = adapter
        .call(
            "diagram.validate",
            Some(object(json!({"schema_version":1,"spec":invalid_shape}))),
        )
        .await
        .expect("schema failure is returned as a structured tool result");
    let invalid_shape =
        serde_json::to_value(invalid_shape).expect("schema failure result serializes");
    assert_eq!(
        invalid_shape["structuredContent"]["error"]["code"],
        "invalid_request"
    );
    assert_eq!(
        invalid_shape["structuredContent"]["error"]["path"],
        "/spec/nodes/0/type"
    );

    let mut path_probe: Value = serde_json::from_str(include_str!(
        "../../diagrams/examples/case_issue_evidence_law_v1.json"
    ))
    .expect("bundled diagram example parses");
    path_probe["nodes"][0]["metadata"]
        .as_object_mut()
        .expect("metadata object")
        .insert("private-diagram-canary".to_owned(), json!(true));
    let path_probe = adapter
        .call(
            "diagram.validate",
            Some(object(json!({"schema_version":1,"spec":path_probe}))),
        )
        .await
        .expect("semantic validation call succeeds");
    let path_probe = serde_json::to_value(path_probe).expect("path probe result serializes");
    let path_wire = serde_json::to_string(&path_probe).expect("path probe JSON");
    assert!(!path_wire.contains("private-diagram-canary"));
    assert!(path_wire.contains("/nodes/0/metadata"));

    let mut spec: Value = serde_json::from_str(include_str!(
        "../../diagrams/examples/case_issue_evidence_law_v1.json"
    ))
    .expect("bundled diagram example parses");
    spec["title"] = Value::String("原告：张三 private-diagram-canary".to_owned());
    spec["nodes"][1]["id"] = spec["nodes"][0]["id"].clone();
    let validated = adapter
        .call(
            "diagram.validate",
            Some(object(json!({"schema_version":1,"spec":spec}))),
        )
        .await
        .expect("validation call succeeds");
    let validated = serde_json::to_value(validated).expect("validation result serializes");
    assert_eq!(validated["structuredContent"]["valid"], false);
    let validation_wire = serde_json::to_string(&validated).expect("validation result JSON");
    assert!(!validation_wire.contains("张三"));
    assert!(!validation_wire.contains("private-diagram-canary"));
    assert!(validation_wire.contains("id.duplicate_node"));

    let spec: Value = serde_json::from_str(include_str!(
        "../../diagrams/examples/case_issue_evidence_law_v1.json"
    ))
    .expect("bundled diagram example parses");
    let rendered = adapter
        .call(
            "diagram.render",
            Some(object(json!({"schema_version":1,"spec":spec}))),
        )
        .await
        .expect("render call succeeds");
    let rendered = serde_json::to_value(rendered).expect("render result serializes");
    assert_eq!(rendered["structuredContent"]["valid"], true);
    let artifact_uri = rendered["structuredContent"]["artifact_uri"]
        .as_str()
        .expect("content-addressed artifact URI");
    assert!(artifact_uri.starts_with("lawyer-assistance://diagrams/"));
    let html_files = std::fs::read_dir(output.join("diagrams"))
        .expect("diagram output directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("html"))
        .count();
    assert_eq!(html_files, 1);
}

fn names(registry: &ToolRegistry) -> Vec<String> {
    registry
        .list()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect()
}

fn object(value: Value) -> JsonObject {
    value.as_object().cloned().expect("object")
}
