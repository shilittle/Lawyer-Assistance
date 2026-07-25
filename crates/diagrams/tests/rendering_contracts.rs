use diagrams::model::DiagramSpec;
use diagrams::render::{render_html, render_svg};

fn load(json: &str) -> DiagramSpec {
    serde_json::from_str(json).expect("fixture must satisfy DiagramSpec")
}

const SEVEN_TEMPLATES: [(&str, &str); 7] = [
    (
        "legal-hierarchy",
        include_str!("../examples/legal-hierarchy-fictional.json"),
    ),
    (
        "legal-application-chain",
        include_str!("../examples/legal-application-chain-fictional-loan.json"),
    ),
    (
        "legal-conflict-priority",
        include_str!("../examples/legal-conflict-priority-fictional.json"),
    ),
    (
        "case-party-relationship",
        include_str!("../examples/case-party-equity-control-fictional.json"),
    ),
    (
        "case-issue-evidence-law",
        include_str!("../examples/case-issue-evidence-labor-fictional.json"),
    ),
    (
        "case-money-flow",
        include_str!("../examples/case-money-flow-sales-fictional.json"),
    ),
    (
        "case-timeline",
        include_str!("../examples/case-timeline-conflict-fictional.json"),
    ),
];

#[test]
fn all_seven_templates_use_their_specialized_layouts() {
    for (strategy, fixture) in SEVEN_TEMPLATES {
        let html = render_html(&load(fixture));
        assert!(
            html.contains(&format!("data-layout-strategy=\"{strategy}\"")),
            "missing layout marker for {strategy}"
        );
        assert!(html.contains("data-testid=\"diagram-svg\""));
        assert!(html.contains("class=\"node type-"));
        assert!(html.contains("class=\"edge strength-"));
    }
}

#[test]
fn repeated_rendering_is_byte_stable() {
    let spec = load(SEVEN_TEMPLATES[4].1);
    assert_eq!(render_html(&spec).as_bytes(), render_html(&spec).as_bytes());
    assert_eq!(render_svg(&spec).as_bytes(), render_svg(&spec).as_bytes());
}

#[test]
fn self_contained_html_has_strict_csp_and_no_dynamic_code_or_network() {
    let html = render_html(&load(SEVEN_TEMPLATES[4].1));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("connect-src 'none'"));
    assert!(html.contains("style-src 'nonce-la-diagrams-renderer-v1'"));
    assert!(html.contains("script-src 'nonce-la-diagrams-renderer-v1'"));
    assert!(html.contains("<style nonce=\"la-diagrams-renderer-v1\">"));
    assert!(html.contains("<script nonce=\"la-diagrams-renderer-v1\">"));
    for forbidden in [
        "PLACEHOLDER",
        "unsafe-inline",
        "style=\"",
        "innerHTML",
        "eval(",
        "new Function",
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "<link ",
        "src=\"http",
    ] {
        assert!(
            !html.contains(forbidden),
            "found forbidden marker {forbidden}"
        );
    }
}

#[test]
fn print_media_forces_a_light_palette_for_every_screen_theme() {
    let html = render_html(&load(SEVEN_TEMPLATES[4].1));
    assert!(html.contains("@media print{body,body.theme-dark,body.theme-auto{"));
    assert!(html.contains(
        "--bg:#fff;--panel:#fff;--ink:#111827;--muted:#4b5563;--line:#9ca3af;--accent:#245ec7;color-scheme:light"
    ));
    assert!(html.contains("@page{size:A4 landscape;margin:10mm}"));
}

#[test]
fn user_text_and_untrusted_uri_are_never_interpreted() {
    let mut spec = load(SEVEN_TEMPLATES[4].1);
    let payload = "</text><script>alert(1)</script><g onload=\"boom\">";
    spec.title = payload.to_owned();
    spec.summary = "x\" autofocus onfocus=\"boom".to_owned();
    spec.nodes[0].label = payload.to_owned();
    spec.nodes[0].details = "<img src=x onerror=boom>".to_owned();
    if let Some(source) = spec.sources.first_mut() {
        source.uri = Some("javascript:alert(1)".to_owned());
        source.quote = Some(payload.to_owned());
    }
    let html = render_html(&spec);
    assert!(html.contains("&lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("&lt;img src=x onerror=boom&gt;"));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("onload=\"boom\""));
    assert!(!html.contains("javascript:alert(1)"));
}

#[test]
fn stable_accessible_markers_cover_the_required_interactions() {
    let html = render_html(&load(SEVEN_TEMPLATES[6].1));
    for test_id in [
        "diagram-toolbar",
        "diagram-search",
        "type-filter",
        "status-filter",
        "weak-toggle",
        "low-toggle",
        "focus-upstream",
        "focus-downstream",
        "focus-clear",
        "focus-both",
        "progressive-expand",
        "advanced-toolbar",
        "zoom-in",
        "zoom-out",
        "fit-view",
        "reset-view",
        "print-diagram",
        "diagram-svg",
        "viewport",
        "detail-sidebar",
        "detail-title",
        "source-list",
        "diagram-legend",
        "diagram-provenance",
    ] {
        assert!(
            html.contains(&format!("data-testid=\"{test_id}\"")),
            "missing interaction marker {test_id}"
        );
    }
    assert!(html.contains("aria-labelledby=\"svg-title svg-desc\""));
    assert!(html.contains("role=\"button\""));
    assert!(html.contains("class=\"type-icon\""));
    assert!(html.contains("class=\"status-mark\""));
    assert!(html.contains("strength-moderate"));
    assert!(html.contains("lane-line"));
    assert!(html.contains("role=\"group\""));
    assert!(html.contains(".node:focus-visible"));
    assert!(html.contains("edge.addEventListener('keydown'"));
    assert!(html.contains("focusClear.addEventListener('click'"));
    assert!(html.contains("clearAdvancedFocus"));

    let issue_html = render_html(&load(SEVEN_TEMPLATES[4].1));
    assert!(issue_html.contains("data-testid=\"issue-filter\""));
    let party_html = render_html(&load(SEVEN_TEMPLATES[3].1));
    assert!(party_html.contains("data-testid=\"subject-filter\""));
    assert!(party_html.contains("data-group-toggle="));
    assert!(party_html.contains("class=\"group-record\""));
}
