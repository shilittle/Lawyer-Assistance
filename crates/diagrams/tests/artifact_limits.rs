use diagrams::{DiagramService, DiagramSpec};
use serde_json::Value;

#[test]
fn oversized_canonical_spec_is_rejected_before_any_artifact_is_written() {
    let directory = tempfile::tempdir().expect("temporary output root");
    let service = DiagramService::new(directory.path()).expect("diagram service");
    let mut value: Value =
        serde_json::from_str(include_str!("../examples/case_party_relationship_v1.json"))
            .expect("bundled party example parses");
    let nodes = value["nodes"].as_array_mut().expect("nodes array");
    let template = nodes.last().expect("party template").clone();
    while nodes.len() < 500 {
        let index = nodes.len();
        let mut node = template.clone();
        node["id"] = Value::String(format!("large_party_{index:03}"));
        node["label"] = Value::String(format!("虚构主体{index:03}"));
        node["details"] = Value::String("虚构的大图容量边界文本。".repeat(900));
        nodes.push(node);
    }
    let spec: DiagramSpec =
        serde_json::from_value(value).expect("expanded party specification parses");
    let error = service
        .render(&spec)
        .expect_err("specification beyond four MiB must fail before rendering");
    assert_eq!(error.code(), "artifact_too_large");
    assert_eq!(
        std::fs::read_dir(directory.path().join("diagrams"))
            .expect("artifact directory")
            .count(),
        0
    );
}
