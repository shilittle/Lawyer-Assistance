use diagrams::{DiagramService, DiagramSpec};
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_identical_renders_converge_on_one_immutable_artifact() {
    let directory = tempfile::tempdir().expect("temporary output root");
    let service = Arc::new(DiagramService::new(directory.path()).expect("diagram service"));
    let spec: DiagramSpec =
        serde_json::from_str(include_str!("../examples/case_party_relationship_v1.json"))
            .expect("bundled example parses");
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            let spec = spec.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.render(&spec).expect("concurrent render succeeds")
            })
        })
        .collect::<Vec<_>>();
    let responses = handles
        .into_iter()
        .map(|handle| handle.join().expect("render thread joins"))
        .collect::<Vec<_>>();
    let expected = responses[0].artifact_uri.as_deref();
    assert!(expected.is_some());
    assert!(responses
        .iter()
        .all(|response| response.artifact_uri.as_deref() == expected));
    let files = std::fs::read_dir(directory.path().join("diagrams"))
        .expect("diagram directory")
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 1, "one atomically committed artifact bundle");
    let siblings = std::fs::read_dir(files[0].path())
        .expect("artifact bundle")
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert_eq!(
        siblings.len(),
        2,
        "one HTML and one canonical sibling DiagramSpec"
    );
}
