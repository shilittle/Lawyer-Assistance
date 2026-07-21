use std::time::{Duration, Instant};

use diagrams::{render_html, validate_spec, DiagramSpec};
use serde_json::Value;

#[test]
fn performance_tiers_are_bounded_and_large_graphs_start_reduced() {
    let started = Instant::now();

    for node_count in [20, 100, 101, 500] {
        let spec = party_spec_with_nodes(node_count);
        let report = validate_spec(&spec);
        assert!(
            !report.has_errors(),
            "{node_count}-node fixture must remain valid: {:?}",
            report.errors().collect::<Vec<_>>()
        );
        assert_eq!(
            report
                .warnings()
                .any(|diagnostic| diagnostic.code == "performance.large_graph"),
            node_count > 100,
            "the large-graph warning boundary is part of the v1 contract"
        );

        let html = render_html(&spec);
        assert_eq!(
            html.contains("data-testid=\"weak-toggle\" data-initial=\"true\" checked"),
            node_count > 100
        );
        assert_eq!(
            html.contains("data-testid=\"low-toggle\" data-initial=\"true\" checked"),
            node_count > 50
        );
        assert_eq!(
            html.contains("data-testid=\"performance-warning\""),
            node_count > 100
        );
    }

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the four documented size tiers must validate and render without pathological slowdown"
    );
}

fn party_spec_with_nodes(node_count: usize) -> DiagramSpec {
    let mut value: Value =
        serde_json::from_str(include_str!("../examples/case_party_relationship_v1.json"))
            .expect("bundled party example parses");
    let nodes = value["nodes"].as_array_mut().expect("nodes array");
    let template = nodes.last().expect("template party node").clone();
    while nodes.len() < node_count {
        let index = nodes.len();
        let mut node = template.clone();
        node["id"] = Value::String(format!("large_party_{index:03}"));
        node["label"] = Value::String(format!("虚构主体{index:03}"));
        node["importance"] = Value::String("low".to_owned());
        nodes.push(node);
    }
    serde_json::from_value(value).expect("expanded party example satisfies the frozen schema")
}
