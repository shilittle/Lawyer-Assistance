use diagrams::{layout, DiagramSpec, LayoutNode};

#[test]
fn ordinary_and_parallel_edges_end_at_node_boundaries() {
    let mut spec: DiagramSpec =
        serde_json::from_str(include_str!("../examples/case_party_relationship_v1.json"))
            .expect("bundled party example parses");
    let mut parallel = spec.edges[0].clone();
    parallel.id = "parallel_ownership".to_owned();
    parallel.label = "并行测试关系".to_owned();
    spec.edges.push(parallel);

    let scene = layout(&spec);
    let routed: Vec<_> = scene
        .edges
        .iter()
        .filter(|edge| edge.source == spec.edges[0].source && edge.target == spec.edges[0].target)
        .collect();
    assert_eq!(routed.len(), 2);
    assert_ne!(routed[0].path, routed[1].path);

    let source = scene
        .nodes
        .iter()
        .find(|node| node.id == routed[0].source)
        .expect("source node");
    let target = scene
        .nodes
        .iter()
        .find(|node| node.id == routed[0].target)
        .expect("target node");
    for edge in routed {
        let coordinates = path_numbers(&edge.path);
        assert!(on_boundary(source, coordinates[0], coordinates[1]));
        let end = coordinates.len() - 2;
        assert!(on_boundary(target, coordinates[end], coordinates[end + 1]));
    }
}

#[test]
fn self_loop_is_visible_outside_the_node_card() {
    let mut spec: DiagramSpec =
        serde_json::from_str(include_str!("../examples/case_timeline_v1.json"))
            .expect("bundled timeline example parses");
    let node_id = spec.nodes[0].id.clone();
    let mut self_loop = spec.edges[0].clone();
    self_loop.id = "same_event_self_loop".to_owned();
    self_loop.source = node_id.clone();
    self_loop.target = node_id.clone();
    self_loop.relation = diagrams::Relation::SameEventAs;
    spec.edges.push(self_loop);

    let scene = layout(&spec);
    let node = scene
        .nodes
        .iter()
        .find(|node| node.id == node_id)
        .expect("loop node");
    let edge = scene
        .edges
        .iter()
        .find(|edge| edge.id == "same_event_self_loop")
        .expect("self loop");
    let coordinates = path_numbers(&edge.path);
    assert!(on_boundary(node, coordinates[0], coordinates[1]));
    let end = coordinates.len() - 2;
    assert!(on_boundary(node, coordinates[end], coordinates[end + 1]));
    assert!(
        coordinates
            .chunks_exact(2)
            .any(|point| point[0] > node.x + node.width + 20.0),
        "self-loop control points must extend beyond the opaque card"
    );
}

fn path_numbers(path: &str) -> Vec<f64> {
    path.split(|character: char| !(character.is_ascii_digit() || matches!(character, '.' | '-')))
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<f64>().expect("numeric path coordinate"))
        .collect()
}

fn on_boundary(node: &LayoutNode, x: f64, y: f64) -> bool {
    let tolerance = 0.11;
    let inside_x = x >= node.x - tolerance && x <= node.x + node.width + tolerance;
    let inside_y = y >= node.y - tolerance && y <= node.y + node.height + tolerance;
    let touches_side = (x - node.x).abs() <= tolerance
        || (x - (node.x + node.width)).abs() <= tolerance
        || (y - node.y).abs() <= tolerance
        || (y - (node.y + node.height)).abs() <= tolerance;
    inside_x && inside_y && touches_side
}
