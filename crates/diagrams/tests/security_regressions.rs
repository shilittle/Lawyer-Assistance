use diagrams::{validate_spec, DiagramSpec};

#[test]
fn unicode_at_date_boundaries_is_rejected_without_panicking() {
    let mut spec: DiagramSpec =
        serde_json::from_str(include_str!("../examples/case_timeline_v1.json"))
            .expect("bundled timeline example parses");
    for malicious in [
        "2026-07-😀T12:00:00Z",
        "２026-07-21T12:00:00Z",
        "2026-07-21T12:00:😀Z",
    ] {
        spec.provenance.generated_at = malicious.to_owned();
        let result = std::panic::catch_unwind(|| validate_spec(&spec));
        let report = result.expect("untrusted Unicode must not panic validation");
        assert!(report.has_errors(), "{malicious}");
    }
}
