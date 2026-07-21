use diagrams::{render_html, validate_spec, DiagramSpec};
use serde_json::{json, Value};

fn timeline_value() -> Value {
    serde_json::from_str(include_str!("../examples/case_timeline_v1.json"))
        .expect("bundled timeline example parses")
}

fn codes(spec: &DiagramSpec) -> Vec<&'static str> {
    validate_spec(spec)
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn fuzzy_dates_and_unknown_dates_follow_explicit_precision() {
    let mut month = timeline_value();
    month["nodes"][0]["metadata"]["date"] = json!("2026-02");
    month["nodes"][0]["metadata"]["date_precision"] = json!("month");
    let month: DiagramSpec = serde_json::from_value(month).expect("month precision parses");
    assert!(!codes(&month).contains(&"timeline.invalid_date"));
    assert!(render_html(&month).contains("日期精度 month"));

    let mut unknown = timeline_value();
    unknown["nodes"][0]["metadata"]
        .as_object_mut()
        .expect("metadata")
        .remove("date");
    unknown["nodes"][0]["metadata"]["date_precision"] = json!("unknown");
    let unknown: DiagramSpec = serde_json::from_value(unknown).expect("unknown precision parses");
    let result = validate_spec(&unknown);
    assert!(!result.has_errors(), "{:?}", result.diagnostics);
    assert!(result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "timeline.date_unknown"));
}

#[test]
fn limitation_deadlines_are_validated_and_visually_flagged() {
    let mut invalid = timeline_value();
    invalid["nodes"][0]["metadata"]["limitation_deadline"] = json!("2026-99-99");
    let invalid: DiagramSpec = serde_json::from_value(invalid).expect("deadline shape parses");
    assert!(codes(&invalid).contains(&"timeline.invalid_limitation_deadline"));

    let mut review = timeline_value();
    review["nodes"][0]["metadata"]["limitation_deadline"] = json!("2029-02-01");
    let review: DiagramSpec = serde_json::from_value(review).expect("deadline shape parses");
    let report = validate_spec(&review);
    assert!(!report.has_errors(), "{:?}", report.diagnostics);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "timeline.limitation_review_required"));
    let html = render_html(&review);
    assert!(html.contains("has-limitation"));
    assert!(html.contains("时效 2029-02-01"));
}
