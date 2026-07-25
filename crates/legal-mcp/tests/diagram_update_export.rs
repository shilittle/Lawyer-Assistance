use legal_mcp::{registry::PrivacyProfile, service_adapter::ServiceAdapter};
use legal_services::{LegalServices, ServiceConfig};
use rmcp::model::JsonObject;
use serde_json::{json, Value};

#[tokio::test]
async fn diagram_update_and_export_use_hash_cas_and_immutable_artifact_references() {
    let directory = tempfile::tempdir().expect("temporary diagram root");
    let legal = directory.path().join("legal.sqlite");
    let user = directory.path().join("user.sqlite");
    let output = directory.path().join("output");
    std::fs::write(&legal, []).expect("legal database placeholder");
    std::fs::write(&user, []).expect("user database placeholder");
    std::fs::create_dir(&output).expect("output directory");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: legal,
        user_database_path: user,
        allowed_file_roots: Vec::new(),
        allowed_output_root: output,
    })
    .expect("service configuration");
    let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::DiagramAuthoring);
    let spec: Value = serde_json::from_str(include_str!(
        "../../diagrams/examples/case_timeline_v1.json"
    ))
    .expect("timeline example");

    let rendered = call(
        &adapter,
        "diagram.render",
        json!({"schema_version":1,"spec":spec}),
    )
    .await;
    let original_uri = rendered["structuredContent"]["artifact_uri"]
        .as_str()
        .expect("original artifact URI")
        .to_owned();
    let original_hash = rendered["structuredContent"]["spec_hash"]
        .as_str()
        .expect("original spec hash")
        .to_owned();

    let updated = call(
        &adapter,
        "diagram.update",
        json!({
            "schema_version":1,
            "artifact_uri":original_uri,
            "expected_spec_hash":original_hash,
            "patch":{
                "title":"虚构时间轴修订版 private-update-canary",
                "change_summary":"虚构样例标题修订"
            }
        }),
    )
    .await;
    assert_eq!(updated["isError"], false);
    let updated_uri = updated["structuredContent"]["artifact_uri"]
        .as_str()
        .expect("updated artifact URI");
    assert_ne!(updated_uri, original_uri);
    let updated_wire = serde_json::to_string(&updated).expect("updated result JSON");
    assert!(!updated_wire.contains("private-update-canary"));

    let exported = call(
        &adapter,
        "diagram.export",
        json!({"schema_version":1,"artifact_uri":updated_uri,"format":"html"}),
    )
    .await;
    assert_eq!(exported["isError"], false);
    assert_eq!(exported["structuredContent"]["mime_type"], "text/html");
    assert!(exported["structuredContent"]["byte_len"]
        .as_u64()
        .is_some_and(|value| value > 0));
}

async fn call(adapter: &ServiceAdapter, name: &str, arguments: Value) -> Value {
    let arguments: JsonObject = arguments.as_object().cloned().expect("object arguments");
    let result = adapter
        .call(name, Some(arguments))
        .await
        .unwrap_or_else(|error| panic!("{name}: {error:?}"));
    serde_json::to_value(result).expect("MCP result serializes")
}
