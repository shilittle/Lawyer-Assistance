use diagrams::{validate_json_schema, validate_spec, DiagramSpec};
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn every_bundled_json_example_is_parseable_and_semantically_valid() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut paths = std::fs::read_dir(&directory)
        .expect("example directory exists")
        .map(|entry| entry.expect("example directory entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    assert!(paths.len() >= 10, "phase one ships at least ten examples");
    for path in paths {
        let json = std::fs::read_to_string(&path).expect("example is readable UTF-8");
        let value: Value = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        validate_json_schema(&value).unwrap_or_else(|error| {
            panic!(
                "{}: JSON Schema failed at {}",
                path.display(),
                error.instance_path
            )
        });
        let spec: DiagramSpec = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("{}: typed decode failed: {error}", path.display()));
        let report = validate_spec(&spec);
        let errors = report
            .errors()
            .map(|item| format!("{} {} {}", item.code, item.path, item.message))
            .collect::<Vec<_>>();
        assert!(
            errors.is_empty(),
            "{}:\n{}",
            path.display(),
            errors.join("\n")
        );
    }
}
