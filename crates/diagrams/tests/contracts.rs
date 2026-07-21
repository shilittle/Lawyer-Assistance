use std::collections::BTreeMap;

use diagrams::{
    canonical_json, spec_hash, validate_spec, DiagramSpec, DiagramType, Direction, DisplayOptions,
    Edge, GeneratedBy, GroupBy, Importance, LayoutHints, Metadata, MetadataScalar, MetadataValue,
    Node, NodeStatus, NodeType, PrintPageSize, Provenance, Relation, Source, SourceKind, Strength,
    TemplateId, Theme, TimelineLane, VerificationStatus,
};

fn node(id: &str, node_type: NodeType) -> Node {
    Node {
        id: id.to_owned(),
        node_type,
        subtype: None,
        label: id.to_owned(),
        short_label: None,
        details: String::new(),
        status: NodeStatus::Unknown,
        importance: Importance::Normal,
        source_refs: Vec::new(),
        tags: Vec::new(),
        metadata: Metadata::new(),
    }
}

fn edge(id: &str, source: &str, target: &str, relation: Relation) -> Edge {
    Edge {
        id: id.to_owned(),
        source: source.to_owned(),
        target: target.to_owned(),
        relation,
        label: String::new(),
        strength: Strength::Unknown,
        source_refs: Vec::new(),
        metadata: Metadata::new(),
    }
}

fn base_spec() -> DiagramSpec {
    DiagramSpec {
        schema_version: "1.0".to_owned(),
        diagram_type: DiagramType::CasePartyRelationship,
        template_id: TemplateId::CasePartyRelationshipV1,
        title: "虚构主体关系".to_owned(),
        summary: String::new(),
        nodes: vec![
            node("party_a", NodeType::Party),
            node("party_b", NodeType::Party),
        ],
        edges: vec![edge(
            "contract_1",
            "party_a",
            "party_b",
            Relation::ContractsWith,
        )],
        groups: Vec::new(),
        sources: Vec::new(),
        layout_hints: LayoutHints {
            direction: Direction::Radial,
            preferred_root_ids: vec!["party_a".to_owned()],
            group_by: GroupBy::None,
            max_initial_nodes: 100,
            timeline_lane: TimelineLane::Single,
        },
        display_options: DisplayOptions {
            theme: Theme::Light,
            show_legend: true,
            show_sources: true,
            hide_weak_edges: false,
            collapse_low_importance: false,
            print_page_size: PrintPageSize::A4Landscape,
        },
        provenance: Provenance {
            generated_by: GeneratedBy::Codex,
            generated_at: "2026-07-21T00:00:00+08:00".to_owned(),
            diagram_spec_version: "1.0".to_owned(),
            template_version: "1.0.0".to_owned(),
            source_file_ids: Vec::new(),
            human_confirmed: false,
            parent_spec_hash: None,
            change_summary: None,
            model_content_scope: "模型仅提取和分析结构化数据".to_owned(),
            deterministic_content_scope: "HTML、CSS、JS 和布局来自固定模板".to_owned(),
        },
    }
}

fn string_metadata(value: &str) -> MetadataValue {
    MetadataValue::Scalar(MetadataScalar::String(value.to_owned()))
}

fn codes(spec: &DiagramSpec) -> Vec<&'static str> {
    validate_spec(spec)
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn minimal_registered_template_is_valid() {
    let report = validate_spec(&base_spec());
    assert!(report.is_valid(), "{:?}", report.diagnostics);
}

#[test]
fn serde_rejects_unknown_fields_at_every_structured_level() {
    let value = serde_json::to_value(base_spec()).unwrap();

    let mut top = value.clone();
    top.as_object_mut()
        .unwrap()
        .insert("script".to_owned(), serde_json::json!("alert(1)"));
    assert!(serde_json::from_value::<DiagramSpec>(top).is_err());

    let mut nested = value;
    nested["nodes"][0]
        .as_object_mut()
        .unwrap()
        .insert("style".to_owned(), serde_json::json!("display:none"));
    assert!(serde_json::from_value::<DiagramSpec>(nested).is_err());
}

#[test]
fn serde_rejects_deep_or_non_scalar_metadata() {
    let mut value = serde_json::to_value(base_spec()).unwrap();
    value["nodes"][0]["metadata"] = serde_json::json!({
        "payload": { "nested": { "script": "alert(1)" } }
    });
    assert!(serde_json::from_value::<DiagramSpec>(value).is_err());
}

#[test]
fn canonical_json_and_hash_are_stable_across_map_insertion_order() {
    let mut first = base_spec();
    first.nodes[0]
        .metadata
        .insert("z_key".to_owned(), string_metadata("last"));
    first.nodes[0]
        .metadata
        .insert("a_key".to_owned(), string_metadata("first"));

    let mut second = base_spec();
    second.nodes[0]
        .metadata
        .insert("a_key".to_owned(), string_metadata("first"));
    second.nodes[0]
        .metadata
        .insert("z_key".to_owned(), string_metadata("last"));

    assert_eq!(
        canonical_json(&first).unwrap(),
        canonical_json(&second).unwrap()
    );
    let hash = spec_hash(&first).unwrap();
    assert_eq!(hash, spec_hash(&second).unwrap());
    assert!(hash.starts_with("sha256:"));
    assert_eq!(hash.len(), 71);
}

#[test]
fn duplicate_and_cross_kind_ids_are_errors() {
    let mut spec = base_spec();
    spec.nodes.push(node("party_a", NodeType::Party));
    spec.edges[0].id = "party_b".to_owned();
    let codes = codes(&spec);
    assert!(codes.contains(&"id.duplicate_node"));
    assert!(codes.contains(&"id.node_edge_collision"));
}

#[test]
fn dangling_edges_and_incompatible_relations_are_errors() {
    let mut dangling = base_spec();
    dangling.edges[0].target = "missing".to_owned();
    assert!(codes(&dangling).contains(&"edge.dangling_target"));

    let mut incompatible = base_spec();
    incompatible.edges[0].relation = Relation::Proves;
    assert!(codes(&incompatible).contains(&"relation.incompatible_node_types"));
}

#[test]
fn template_and_diagram_type_must_match() {
    let mut spec = base_spec();
    spec.template_id = TemplateId::CaseTimelineV1;
    let codes = codes(&spec);
    assert!(codes.contains(&"template.diagram_type_mismatch"));
}

#[test]
fn malicious_bidirectional_controls_are_rejected() {
    let mut spec = base_spec();
    spec.title = "安全标题\u{202e}lmth".to_owned();
    assert!(codes(&spec).contains(&"security.unsafe_unicode_control"));
}

#[test]
fn source_and_evidence_semantics_are_checked() {
    let mut spec = base_spec();
    spec.diagram_type = DiagramType::CaseIssueEvidenceLaw;
    spec.template_id = TemplateId::CaseIssueEvidenceLawV1;
    spec.nodes = vec![
        node("issue", NodeType::Issue),
        node("evidence", NodeType::Evidence),
    ];
    spec.edges.clear();
    spec.layout_hints.preferred_root_ids = vec!["issue".to_owned()];
    let result = codes(&spec);
    assert!(result.contains(&"evidence.source_missing"));
    assert!(result.contains(&"issue.isolated"));

    spec.sources.push(Source {
        id: "law_source".to_owned(),
        kind: SourceKind::Law,
        title: "虚构法律".to_owned(),
        locator: "内部索引".to_owned(),
        artifact_id: None,
        uri: None,
        file_name: None,
        page: None,
        paragraph: None,
        table: None,
        attachment: None,
        law_document: Some("虚构法律".to_owned()),
        law_version: None,
        article: None,
        quote: None,
        content_hash: None,
        verification_status: VerificationStatus::Unverified,
    });
    let result = codes(&spec);
    assert!(result.contains(&"source.law_version_missing"));
    assert!(result.contains(&"source.law_location_missing"));
}

#[test]
fn legal_norm_requires_version_and_checks_hierarchy_direction() {
    let mut spec = base_spec();
    spec.diagram_type = DiagramType::LegalHierarchy;
    spec.template_id = TemplateId::LegalHierarchyV1;
    spec.nodes = vec![
        node("department_rule", NodeType::DepartmentRule),
        node("law", NodeType::Law),
    ];
    spec.edges = vec![edge(
        "bad_hierarchy",
        "department_rule",
        "law",
        Relation::SuperiorTo,
    )];
    spec.layout_hints.preferred_root_ids = vec!["law".to_owned()];
    let result = codes(&spec);
    assert!(result.contains(&"law.version_missing"));
    assert!(result.contains(&"law.relation_direction_reversed"));
}

#[test]
fn core_money_flow_requires_amount_currency_date_and_voucher() {
    let mut spec = base_spec();
    spec.diagram_type = DiagramType::CaseMoneyFlow;
    spec.template_id = TemplateId::CaseMoneyFlowV1;
    spec.edges[0].relation = Relation::PaidTo;
    let result = codes(&spec);
    assert!(result.contains(&"money.amount_missing"));
    assert!(result.contains(&"money.currency_missing"));
    assert!(result.contains(&"money.date_missing"));
    assert!(result.contains(&"money.voucher_source_missing"));
}

#[test]
fn timeline_detects_date_order_conflicts_and_cycles() {
    let mut first = node("first", NodeType::Event);
    first
        .metadata
        .insert("date".to_owned(), string_metadata("2026-07-22"));
    let mut second = node("second", NodeType::Procedure);
    second
        .metadata
        .insert("date".to_owned(), string_metadata("2026-07-21"));

    let mut spec = base_spec();
    spec.diagram_type = DiagramType::CaseTimeline;
    spec.template_id = TemplateId::CaseTimelineV1;
    spec.nodes = vec![first, second];
    spec.edges = vec![
        edge("before", "first", "second", Relation::OccurredBefore),
        edge("after", "second", "first", Relation::OccurredBefore),
    ];
    spec.layout_hints.preferred_root_ids = vec!["first".to_owned()];
    let result = codes(&spec);
    assert!(result.contains(&"timeline.order_conflict"));
    assert!(result.contains(&"timeline.order_cycle"));
}

#[test]
fn invalid_metadata_keys_and_group_cycles_are_errors() {
    let mut spec = base_spec();
    spec.nodes[0]
        .metadata
        .insert("Bad-Key".to_owned(), string_metadata("x"));
    spec.groups = vec![
        diagrams::Group {
            id: "one".to_owned(),
            label: "一".to_owned(),
            node_ids: vec!["party_a".to_owned()],
            parent_group_id: Some("two".to_owned()),
            collapsed_by_default: false,
            source_refs: Vec::new(),
        },
        diagrams::Group {
            id: "two".to_owned(),
            label: "二".to_owned(),
            node_ids: vec!["party_b".to_owned()],
            parent_group_id: Some("one".to_owned()),
            collapsed_by_default: false,
            source_refs: Vec::new(),
        },
    ];
    let result = codes(&spec);
    assert!(result.contains(&"metadata.invalid_key"));
    assert!(result.contains(&"group.parent_cycle"));
}

#[test]
fn related_to_always_warns_and_excess_is_reported() {
    let mut spec = base_spec();
    spec.edges[0].relation = Relation::RelatedTo;
    let report = validate_spec(&spec);
    assert!(report.is_valid());
    let codes: Vec<_> = report
        .warnings()
        .map(|diagnostic| diagnostic.code)
        .collect();
    assert!(codes.contains(&"relation.fallback_used"));
    assert!(codes.contains(&"relation.excessive_fallback"));
}

#[test]
fn metadata_object_order_is_lexical() {
    let mut spec = base_spec();
    let mut object = BTreeMap::new();
    object.insert("z".to_owned(), MetadataScalar::String("2".to_owned()));
    object.insert("a".to_owned(), MetadataScalar::String("1".to_owned()));
    spec.nodes[0]
        .metadata
        .insert("object".to_owned(), MetadataValue::Object(object));
    let json = canonical_json(&spec).unwrap();
    assert!(json.find("\"a\":\"1\"").unwrap() < json.find("\"z\":\"2\"").unwrap());
}
