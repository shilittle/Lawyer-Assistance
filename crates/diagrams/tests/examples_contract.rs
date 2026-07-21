use diagrams::{validate_spec, DiagramSpec, TemplateRegistry};

const EXAMPLES: [(&str, &str); 7] = [
    (
        "examples/legal_hierarchy_v1.json",
        include_str!("../examples/legal_hierarchy_v1.json"),
    ),
    (
        "examples/legal_application_chain_v1.json",
        include_str!("../examples/legal_application_chain_v1.json"),
    ),
    (
        "examples/legal_conflict_priority_v1.json",
        include_str!("../examples/legal_conflict_priority_v1.json"),
    ),
    (
        "examples/case_party_relationship_v1.json",
        include_str!("../examples/case_party_relationship_v1.json"),
    ),
    (
        "examples/case_issue_evidence_law_v1.json",
        include_str!("../examples/case_issue_evidence_law_v1.json"),
    ),
    (
        "examples/case_money_flow_v1.json",
        include_str!("../examples/case_money_flow_v1.json"),
    ),
    (
        "examples/case_timeline_v1.json",
        include_str!("../examples/case_timeline_v1.json"),
    ),
];

#[test]
fn every_registered_example_parses_and_has_no_validation_errors() {
    let registry = TemplateRegistry::new();
    for (path, json) in EXAMPLES {
        let spec: DiagramSpec =
            serde_json::from_str(json).unwrap_or_else(|error| panic!("{path}: {error}"));
        let descriptor = registry
            .get(spec.template_id)
            .unwrap_or_else(|| panic!("{path}: unregistered template"));
        assert_eq!(descriptor.example_path, path);
        let report = validate_spec(&spec);
        let errors = report
            .errors()
            .map(|item| format!("{} {} {}", item.code, item.path, item.message))
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{path}:\n{}", errors.join("\n"));
    }
}
