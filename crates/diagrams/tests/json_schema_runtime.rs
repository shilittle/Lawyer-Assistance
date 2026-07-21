use diagrams::{diagram_spec_schema, validate_json_schema};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../examples/case_issue_evidence_law_v1.json"))
        .expect("bundled example is valid JSON")
}

#[test]
fn bundled_schema_is_valid_draft_2020_12_and_accepts_the_canonical_fixture() {
    let schema = diagram_spec_schema();
    assert!(jsonschema::draft202012::meta::is_valid(&schema));
    validate_json_schema(&fixture()).expect("canonical fixture satisfies the runtime schema");
}

#[test]
fn runtime_schema_rejects_invalid_enums_unknown_fields_and_length_constraints() {
    let mut invalid_enum = fixture();
    invalid_enum["nodes"][0]["status"] = Value::String("court_confirmed".to_owned());
    let error = validate_json_schema(&invalid_enum).expect_err("unknown status must fail");
    assert_eq!(error.instance_path, "/nodes/0/status");

    let mut unknown_field = fixture();
    unknown_field["nodes"][0]["script"] = Value::String("alert(1)".to_owned());
    let error = validate_json_schema(&unknown_field).expect_err("unknown fields must fail");
    assert_eq!(error.instance_path, "/nodes/0");

    let mut oversized_title = fixture();
    oversized_title["title"] = Value::String("x".repeat(257));
    let error = validate_json_schema(&oversized_title).expect_err("long title must fail");
    assert_eq!(error.instance_path, "/title");
}
