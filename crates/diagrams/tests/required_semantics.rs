use diagrams::{validate_spec, DiagramSpec, NodeStatus, NodeType};

fn fixture() -> DiagramSpec {
    serde_json::from_str(include_str!("../examples/case_issue_evidence_law_v1.json"))
        .expect("bundled issue/evidence example parses")
}

fn codes(spec: &DiagramSpec) -> Vec<&'static str> {
    validate_spec(spec)
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn facts_require_sources_and_supported_facts_require_evidence() {
    let mut missing_source = fixture();
    let fact = missing_source
        .nodes
        .iter_mut()
        .find(|node| node.node_type == NodeType::Fact)
        .expect("fact fixture");
    fact.source_refs.clear();
    assert!(codes(&missing_source).contains(&"fact.source_missing"));

    let mut missing_evidence = fixture();
    let fact_id = {
        let fact = missing_evidence
            .nodes
            .iter_mut()
            .find(|node| node.node_type == NodeType::Fact)
            .expect("fact fixture");
        fact.status = NodeStatus::Supported;
        fact.id.clone()
    };
    missing_evidence.edges.retain(|edge| {
        !(edge.target == fact_id
            && matches!(
                edge.relation,
                diagrams::Relation::Supports | diagrams::Relation::Proves
            ))
    });
    for evidence in missing_evidence
        .nodes
        .iter_mut()
        .filter(|node| node.node_type == NodeType::Evidence)
    {
        evidence.metadata.remove("supports_facts");
        evidence.metadata.remove("proves");
    }
    assert!(codes(&missing_evidence).contains(&"fact.supporting_evidence_missing"));
}

#[test]
fn rule_nodes_require_version_and_source_paths_are_rejected() {
    let mut spec = fixture();
    let rule = spec
        .nodes
        .iter_mut()
        .find(|node| node.node_type == NodeType::Rule)
        .expect("rule fixture");
    rule.metadata.remove("version");
    rule.source_refs.clear();
    assert!(codes(&spec).contains(&"law.version_missing"));

    let mut path_spec = fixture();
    path_spec.sources[0].file_name = Some("C:\\Users\\private\\record.pdf".to_owned());
    path_spec.sources[0].locator = "C:\\Users\\private\\record.pdf，第 1 页".to_owned();

    let result = codes(&path_spec);
    assert!(result.contains(&"source.file_name_not_basename"));
    assert!(result.contains(&"source.absolute_path_forbidden"));

    path_spec.sources[0].file_name = Some("../record.pdf".to_owned());
    assert!(codes(&path_spec).contains(&"source.file_name_not_basename"));
}

#[test]
fn provenance_source_file_ids_are_identifiers_not_local_paths() {
    let mut spec = fixture();
    spec.provenance.source_file_ids = vec!["C:\\private\\matter\\secret.pdf".to_owned()];
    let report = validate_spec(&spec);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "schema.invalid_identifier"
            && diagnostic.path == "/provenance/source_file_ids/0"
    }));
}
