use diagrams::{render_html, DiagramSpec};

#[test]
fn show_sources_false_omits_source_records_and_node_source_links_from_html() {
    let mut spec: DiagramSpec =
        serde_json::from_str(include_str!("../examples/case_issue_evidence_law_v1.json"))
            .expect("bundled example parses");
    spec.sources[0].title = "private-source-title-canary".to_owned();
    spec.sources[0].quote = Some("private-source-quote-canary".to_owned());
    spec.sources[0].locator = "private-source-locator-canary".to_owned();
    spec.sources[0].uri = Some("https://example.invalid/private-uri-canary".to_owned());
    spec.sources[0].file_name = Some("private-file-canary.pdf".to_owned());
    spec.sources[0].artifact_id = Some("private_artifact_canary".to_owned());
    spec.sources[0].law_version = Some("private-law-version-canary".to_owned());
    spec.display_options.show_sources = true;
    let visible = render_html(&spec);
    for canary in [
        "private-source-title-canary",
        "private-source-quote-canary",
        "private-source-locator-canary",
        "private-uri-canary",
        "private-file-canary.pdf",
        "private_artifact_canary",
        "private-law-version-canary",
    ] {
        assert!(visible.contains(canary), "visible source field {canary}");
    }

    spec.display_options.show_sources = false;
    let hidden = render_html(&spec);
    for canary in [
        "private-source-title-canary",
        "private-source-quote-canary",
        "private-source-locator-canary",
        "private-uri-canary",
        "private-file-canary.pdf",
        "private_artifact_canary",
        "private-law-version-canary",
    ] {
        assert!(!hidden.contains(canary), "hidden source field {canary}");
    }
    assert!(!hidden.contains("class=\"source-record\""));
}
