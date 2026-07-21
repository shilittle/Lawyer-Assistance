pub mod layout;
pub mod model;
pub mod relations;
pub mod render;
pub mod service;
pub mod templates;
pub mod validation;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub use layout::{layout, Layout, LayoutEdge, LayoutNode, LayoutStrategy};
pub use model::*;
pub use relations::{
    all_relation_descriptors, relation_descriptor, relation_is_compatible, RelationDescriptor,
};
pub use render::{render_html, render_svg};
pub use service::*;
pub use templates::{TemplateDescriptor, TemplateRegistry, TEMPLATES};
pub use validation::{validate, validate_spec, Diagnostic, DiagnosticSeverity, ValidationReport};

pub type DiagramNode = Node;
pub type DiagramEdge = Edge;
pub type DiagramGroup = Group;
pub type DiagramSource = Source;

pub const DIAGRAM_SPEC_SCHEMA_JSON: &str = include_str!("../schema/diagram-spec-v1.schema.json");

/// Returns the frozen v1 JSON Schema used by MCP schema discovery.
pub fn diagram_spec_schema() -> Value {
    serde_json::from_str(DIAGRAM_SPEC_SCHEMA_JSON).expect("bundled diagram schema is valid JSON")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonSchemaViolation {
    pub instance_path: String,
}

/// Validates an untyped JSON value against the exact Draft 2020-12 schema
/// returned by `diagram.get_schema`.
///
/// The validator has every external resolver feature disabled. The frozen
/// schema contains only local `$defs` references, so schema validation never
/// reads files or performs network I/O.
pub fn validate_json_schema(instance: &Value) -> Result<(), JsonSchemaViolation> {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    let validator = VALIDATOR.get_or_init(|| {
        let schema = diagram_spec_schema();
        jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("bundled DiagramSpec v1 schema must compile")
    });
    validator.validate(instance).map_err(|error| {
        let instance_path = error.instance_path().to_string();
        JsonSchemaViolation {
            instance_path: if instance_path.is_empty() {
                "/".to_owned()
            } else {
                instance_path
            },
        }
    })
}

/// Serializes a value with recursively sorted object keys and no insignificant whitespace.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = canonicalize_value(serde_json::to_value(value)?);
    serde_json::to_string(&value)
}

/// Returns the canonical UTF-8 bytes used by content addressing.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json(value).map(String::into_bytes)
}

/// Returns a stable, lower-case SHA-256 content hash prefixed with `sha256:`.
pub fn spec_hash(spec: &DiagramSpec) -> Result<String, serde_json::Error> {
    let digest = Sha256::digest(canonical_json_bytes(spec)?);
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Object(values) => {
            let mut sorted: Vec<_> = values.into_iter().collect();
            sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut object = serde_json::Map::new();
            for (key, value) in sorted {
                object.insert(key, canonicalize_value(value));
            }
            Value::Object(object)
        }
        scalar => scalar,
    }
}
