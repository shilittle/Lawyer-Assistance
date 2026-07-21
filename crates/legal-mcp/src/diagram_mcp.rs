use diagrams::{
    diagram_spec_schema, validate_json_schema, DiagramService, DiagramServiceError, DiagramSpec,
    DiagramUpdateRequest, ExportFormat, TemplateDescriptor, TemplateId, TemplateRegistry,
};
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use serde_path_to_error::{Path as SerdePath, Segment};
use std::sync::Arc;

pub(crate) const DIAGRAM_TOOL_NAMES: [&str; 6] = [
    "diagram.list_templates",
    "diagram.get_schema",
    "diagram.validate",
    "diagram.render",
    "diagram.update",
    "diagram.export",
];

const RESULT_POLICY: &str = "Returns only fixed template metadata, bundled fictional examples, schema, validation codes/paths, statistics, hashes, and content-addressed artifact references. Diagram input text is never echoed. Use only synthetic/public data or data separately approved for trusted local processing.";

pub(crate) fn tools() -> Vec<Tool> {
    let spec = diagram_spec_schema();
    vec![
        make_tool(
            "diagram.list_templates",
            "List diagram templates",
            "List the seven frozen phase-one legal diagram templates.",
            version_only_input(),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "templates":{"type":"array","items":template_output_schema()}
                },
                "required":["schema_version","templates"],
                "additionalProperties":false
            }),
            true,
        ),
        make_tool(
            "diagram.get_schema",
            "Get diagram schema",
            "Read the frozen DiagramSpec v1 JSON Schema and optional template descriptor.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "template_id":{"type":["string","null"],"enum":[
                        "legal_hierarchy_v1","legal_application_chain_v1",
                        "legal_conflict_priority_v1","case_party_relationship_v1",
                        "case_issue_evidence_law_v1","case_money_flow_v1",
                        "case_timeline_v1",null
                    ]}
                },
                "required":["schema_version"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "diagram_spec_schema":{"type":"object"},
                    "template":{"anyOf":[template_output_schema(),{"type":"null"}]}
                },
                "required":["schema_version","diagram_spec_schema","template"],
                "additionalProperties":false
            }),
            true,
        ),
        make_tool(
            "diagram.validate",
            "Validate diagram specification",
            "Run structural, semantic, legal-version, source, timeline, money-flow, and template validation without writing a file.",
            spec_input(spec.clone()),
            validation_output_schema(),
            true,
        ),
        make_tool(
            "diagram.render",
            "Render legal diagram",
            "Validate and deterministically render an offline interactive HTML artifact beneath the configured output root.",
            spec_input(spec.clone()),
            render_output_schema(),
            false,
        ),
        make_tool(
            "diagram.update",
            "Update legal diagram",
            "Apply an optimistic-concurrency patch to a content-addressed artifact or supplied base specification and render the new immutable artifact.",
            update_input(spec),
            render_output_schema(),
            false,
        ),
        make_tool(
            "diagram.export",
            "Export legal diagram",
            "Verify an existing content-addressed HTML artifact and return its immutable export descriptor.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "artifact_uri":artifact_uri_schema(),
                    "format":{"type":"string","const":"html"}
                },
                "required":["schema_version","artifact_uri","format"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "artifact_uri":artifact_uri_schema(),
                    "mime_type":{"type":"string","const":"text/html"},
                    "format":{"type":"string","const":"html"},
                    "byte_len":{"type":"integer","minimum":0,"maximum":12582912},
                    "html_sha256":prefixed_sha256_schema()
                },
                "required":["artifact_uri","mime_type","format","byte_len","html_sha256"],
                "additionalProperties":false
            }),
            false,
        ),
    ]
}

pub(crate) fn execute(
    service: &DiagramService,
    tool_name: &str,
    arguments: JsonObject,
) -> Result<Value, DiagramMcpError> {
    match tool_name {
        "diagram.list_templates" => {
            let input: VersionInput = decode(arguments)?;
            check_version(input.schema_version)?;
            let templates = TemplateRegistry::new()
                .iter()
                .map(template_projection)
                .collect::<Vec<_>>();
            Ok(json!({"schema_version":1,"templates":templates}))
        }
        "diagram.get_schema" => {
            let input: SchemaInput = decode(arguments)?;
            check_version(input.schema_version)?;
            let template = input
                .template_id
                .and_then(|id| TemplateRegistry::new().get(id).map(template_projection));
            Ok(json!({
                "schema_version":1,
                "diagram_spec_schema":diagram_spec_schema(),
                "template":template
            }))
        }
        "diagram.validate" => {
            validate_spec_argument(&arguments, "spec")?;
            let input: SpecInput = decode(arguments)?;
            check_version(input.schema_version)?;
            serialize_public(service.validate(&input.spec))
        }
        "diagram.render" => {
            validate_spec_argument(&arguments, "spec")?;
            let input: SpecInput = decode(arguments)?;
            check_version(input.schema_version)?;
            serialize_public(
                service
                    .render(&input.spec)
                    .map_err(DiagramMcpError::service)?,
            )
        }
        "diagram.update" => {
            validate_spec_argument(&arguments, "base_spec")?;
            let input: UpdateInput = decode(arguments)?;
            check_version(input.schema_version)?;
            serialize_public(
                service
                    .update(input.request)
                    .map_err(DiagramMcpError::service)?,
            )
        }
        "diagram.export" => {
            let input: ExportInput = decode(arguments)?;
            check_version(input.schema_version)?;
            serialize_public(
                service
                    .export(&input.artifact_uri, input.format)
                    .map_err(DiagramMcpError::service)?,
            )
        }
        _ => Err(DiagramMcpError::new("unknown_tool")),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DiagramMcpError {
    code: &'static str,
    path: Option<String>,
}

impl DiagramMcpError {
    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    const fn new(code: &'static str) -> Self {
        Self { code, path: None }
    }

    fn with_path(code: &'static str, path: String) -> Self {
        Self {
            code,
            path: Some(path),
        }
    }

    fn service(error: DiagramServiceError) -> Self {
        Self::new(error.code())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionInput {
    schema_version: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaInput {
    schema_version: u16,
    #[serde(default)]
    template_id: Option<TemplateId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecInput {
    schema_version: u16,
    spec: DiagramSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateInput {
    schema_version: u16,
    #[serde(flatten)]
    request: DiagramUpdateRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportInput {
    schema_version: u16,
    artifact_uri: String,
    format: ExportFormat,
}

fn validate_spec_argument(arguments: &JsonObject, field: &str) -> Result<(), DiagramMcpError> {
    let Some(instance) = arguments.get(field) else {
        return Ok(());
    };
    validate_json_schema(instance).map_err(|error| {
        let path = if error.instance_path == "/" {
            format!("/{field}")
        } else {
            format!("/{field}{}", error.instance_path)
        };
        DiagramMcpError::with_path("invalid_request", sanitize_pointer(&path))
    })
}

fn decode<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, DiagramMcpError> {
    let value = Value::Object(arguments);
    let bytes =
        serde_json::to_vec(&value).map_err(|_| DiagramMcpError::new("serialization_failed"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        DiagramMcpError::with_path("invalid_request", safe_diagnostic_path(error.path()))
    })
}

fn check_version(version: u16) -> Result<(), DiagramMcpError> {
    if version == 1 {
        Ok(())
    } else {
        Err(DiagramMcpError::new("unsupported_schema_version"))
    }
}

fn serialize_public(value: impl serde::Serialize) -> Result<Value, DiagramMcpError> {
    let mut value =
        serde_json::to_value(value).map_err(|_| DiagramMcpError::new("serialization_failed"))?;
    sanitize_diagnostic_messages(&mut value);
    Ok(value)
}

fn sanitize_diagnostic_messages(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "message" {
                    *value = Value::String("请按诊断 code 与 path 修正图示规范。".to_owned());
                } else if key == "path" {
                    if let Some(path) = value.as_str() {
                        *value = Value::String(sanitize_pointer(path));
                    }
                } else {
                    sanitize_diagnostic_messages(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sanitize_diagnostic_messages),
        _ => {}
    }
}

fn safe_diagnostic_path(path: &SerdePath) -> String {
    let mut pointer = String::new();
    for segment in path {
        match segment {
            Segment::Seq { index } => pointer.push_str(&format!("/{index}")),
            Segment::Map { key } | Segment::Enum { variant: key } => {
                if !safe_path_segment(key) {
                    break;
                }
                pointer.push('/');
                pointer.push_str(key);
                if key == "metadata" {
                    break;
                }
            }
            Segment::Unknown => break,
        }
    }
    if pointer.is_empty() {
        "/".to_owned()
    } else {
        pointer
    }
}

fn sanitize_pointer(path: &str) -> String {
    let mut pointer = String::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        if !segment.bytes().all(|byte| byte.is_ascii_digit()) && !safe_path_segment(segment) {
            break;
        }
        pointer.push('/');
        pointer.push_str(segment);
        if segment == "metadata" {
            break;
        }
    }
    if pointer.is_empty() {
        "/".to_owned()
    } else {
        pointer
    }
}

fn safe_path_segment(segment: &str) -> bool {
    matches!(
        segment,
        "schema_version"
            | "spec"
            | "base_spec"
            | "patch"
            | "diagram_type"
            | "template_id"
            | "title"
            | "summary"
            | "nodes"
            | "edges"
            | "groups"
            | "sources"
            | "layout_hints"
            | "display_options"
            | "provenance"
            | "id"
            | "type"
            | "subtype"
            | "label"
            | "short_label"
            | "details"
            | "status"
            | "importance"
            | "source_refs"
            | "tags"
            | "metadata"
            | "source"
            | "target"
            | "relation"
            | "strength"
            | "node_ids"
            | "parent_group_id"
            | "collapsed_by_default"
            | "kind"
            | "locator"
            | "artifact_id"
            | "uri"
            | "file_name"
            | "page"
            | "paragraph"
            | "table"
            | "attachment"
            | "law_document"
            | "law_version"
            | "article"
            | "quote"
            | "content_hash"
            | "verification_status"
            | "generated_by"
            | "generated_at"
            | "diagram_spec_version"
            | "template_version"
            | "source_file_ids"
            | "human_confirmed"
            | "parent_spec_hash"
            | "change_summary"
            | "model_content_scope"
            | "deterministic_content_scope"
    )
}

fn template_projection(template: &TemplateDescriptor) -> Value {
    json!({
        "id":template.id,
        "diagram_type":template.diagram_type,
        "semantic_version":template.semantic_version,
        "example":bundled_example(template.id.as_str()),
        "name_zh":template.name_zh,
        "scenario_zh":template.scenario_zh,
        "supported_node_types":template.supported_node_types,
        "required_node_types":template.required_node_types,
        "allowed_relations":template.allowed_relations,
        "default_direction":template.default_direction
    })
}

fn bundled_example(template_id: &str) -> Value {
    let raw = match template_id {
        "legal_hierarchy_v1" => include_str!("../../diagrams/examples/legal_hierarchy_v1.json"),
        "legal_application_chain_v1" => {
            include_str!("../../diagrams/examples/legal_application_chain_v1.json")
        }
        "legal_conflict_priority_v1" => {
            include_str!("../../diagrams/examples/legal_conflict_priority_v1.json")
        }
        "case_party_relationship_v1" => {
            include_str!("../../diagrams/examples/case_party_relationship_v1.json")
        }
        "case_issue_evidence_law_v1" => {
            include_str!("../../diagrams/examples/case_issue_evidence_law_v1.json")
        }
        "case_money_flow_v1" => include_str!("../../diagrams/examples/case_money_flow_v1.json"),
        "case_timeline_v1" => include_str!("../../diagrams/examples/case_timeline_v1.json"),
        _ => return json!({}),
    };
    serde_json::from_str(raw).expect("bundled diagram example must remain valid JSON")
}

fn make_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
    output: Value,
    read_only: bool,
) -> Tool {
    Tool::new(
        name,
        format!("{description} {RESULT_POLICY}"),
        json_object(input),
    )
    .with_title(title)
    .with_raw_output_schema(json_object(output))
    .with_annotations(
        ToolAnnotations::with_title(title)
            .read_only(read_only)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn version_only_input() -> Value {
    json!({
        "type":"object",
        "properties":{"schema_version":schema_version()},
        "required":["schema_version"],
        "additionalProperties":false
    })
}

fn spec_input(spec: Value) -> Value {
    let spec = rebase_local_refs(spec, "#/properties/spec");
    json!({
        "type":"object",
        "properties":{"schema_version":schema_version(),"spec":spec},
        "required":["schema_version","spec"],
        "additionalProperties":false
    })
}

fn update_input(spec: Value) -> Value {
    let spec = rebase_local_refs(spec, "#/properties/base_spec/anyOf/0");
    json!({
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            "artifact_uri":artifact_uri_schema(),
            "base_spec":{"anyOf":[spec,{"type":"null"}]},
            "expected_spec_hash":prefixed_sha256_schema(),
            "patch":{
                "type":"object",
                "properties":{
                    "title":{"type":["string","null"],"maxLength":256},
                    "summary":{"type":["string","null"],"maxLength":4096},
                    "layout_hints":{"type":["object","null"]},
                    "display_options":{"type":["object","null"]},
                    "upsert_nodes":{"type":"array","maxItems":500,"items":{"type":"object"}},
                    "remove_node_ids":{"type":"array","maxItems":500,"items":{"type":"string"}},
                    "upsert_edges":{"type":"array","maxItems":1200,"items":{"type":"object"}},
                    "remove_edge_ids":{"type":"array","maxItems":1200,"items":{"type":"string"}},
                    "upsert_groups":{"type":"array","maxItems":100,"items":{"type":"object"}},
                    "remove_group_ids":{"type":"array","maxItems":100,"items":{"type":"string"}},
                    "upsert_sources":{"type":"array","maxItems":1000,"items":{"type":"object"}},
                    "remove_source_ids":{"type":"array","maxItems":1000,"items":{"type":"string"}},
                    "change_summary":{"type":["string","null"],"maxLength":1024}
                },
                "additionalProperties":false
            }
        },
        "required":["schema_version","expected_spec_hash","patch"],
        "additionalProperties":false
    })
}

fn validation_output_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "schema_version":{"type":"string","const":"1.0"},
            "template_id":{"type":"string"},
            "template_version":{"type":"string"},
            "valid":{"type":"boolean"},
            "spec_hash":{"anyOf":[prefixed_sha256_schema(),{"type":"null"}]},
            "diagnostics":{"type":"array","items":diagnostic_schema()},
            "warnings":{"type":"array","items":{"type":"string"}},
            "statistics":statistics_schema()
        },
        "required":["schema_version","template_id","template_version","valid","spec_hash","diagnostics","warnings","statistics"],
        "additionalProperties":false
    })
}

fn render_output_schema() -> Value {
    let validation = validation_output_schema();
    let mut properties = validation["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    properties.insert(
        "artifact_uri".to_owned(),
        json!({"anyOf":[artifact_uri_schema(),{"type":"null"}]}),
    );
    properties.insert(
        "mime_type".to_owned(),
        json!({"type":"string","const":"text/html"}),
    );
    properties.insert(
        "html_sha256".to_owned(),
        json!({"anyOf":[prefixed_sha256_schema(),{"type":"null"}]}),
    );
    properties.insert("reused".to_owned(), json!({"type":"boolean"}));
    json!({
        "type":"object",
        "properties":properties,
        "required":["artifact_uri","mime_type","template_id","template_version","schema_version","spec_hash","html_sha256","valid","diagnostics","warnings","statistics","reused"],
        "additionalProperties":false
    })
}

fn template_output_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "id":{"type":"string"},"diagram_type":{"type":"string"},
            "semantic_version":{"type":"string"},"name_zh":{"type":"string"},
            "scenario_zh":{"type":"string"},
            "example":{"type":"object"},
            "supported_node_types":{"type":"array","items":{"type":"string"}},
            "required_node_types":{"type":"array","items":{"type":"string"}},
            "allowed_relations":{"type":"array","items":{"type":"string"}},
            "default_direction":{"type":"string"}
        },
        "required":["id","diagram_type","semantic_version","name_zh","scenario_zh","example","supported_node_types","required_node_types","allowed_relations","default_direction"],
        "additionalProperties":false
    })
}

fn diagnostic_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "severity":{"type":"string","enum":["info","warning","error"]},
            "code":{"type":"string"},"path":{"type":"string"},"message":{"type":"string"}
        },
        "required":["severity","code","path","message"],
        "additionalProperties":false
    })
}

fn statistics_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "nodes":{"type":"integer","minimum":0},"edges":{"type":"integer","minimum":0},
            "unsupported_facts":{"type":"integer","minimum":0},
            "disputed_facts":{"type":"integer","minimum":0},
            "missing_sources":{"type":"integer","minimum":0},
            "invalid_legal_versions":{"type":"integer","minimum":0},
            "performance_class":{"type":"string","enum":["small","medium","large"]}
        },
        "required":["nodes","edges","unsupported_facts","disputed_facts","missing_sources","invalid_legal_versions","performance_class"],
        "additionalProperties":false
    })
}

fn artifact_uri_schema() -> Value {
    json!({"type":"string","pattern":"^lawyer-assistance://diagrams/[a-f0-9]{64}$"})
}

fn prefixed_sha256_schema() -> Value {
    json!({"type":"string","pattern":"^sha256:[a-f0-9]{64}$"})
}

fn schema_version() -> Value {
    json!({"type":"integer","const":1})
}

fn rebase_local_refs(mut value: Value, base: &str) -> Value {
    match &mut value {
        Value::Object(object) => {
            if let Some(reference) = object.get_mut("$ref") {
                if let Some(suffix) = reference
                    .as_str()
                    .and_then(|value| value.strip_prefix("#/$defs/"))
                {
                    *reference = Value::String(format!("{base}/$defs/{suffix}"));
                }
            }
            for nested in object.values_mut() {
                let current = std::mem::take(nested);
                *nested = rebase_local_refs(current, base);
            }
        }
        Value::Array(values) => {
            for nested in values {
                let current = std::mem::take(nested);
                *nested = rebase_local_refs(current, base);
            }
        }
        _ => {}
    }
    value
}

fn json_object(value: Value) -> Arc<JsonObject> {
    match value {
        Value::Object(object) => Arc::new(object),
        _ => Arc::new(Map::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_are_fixed_closed_world_and_use_machine_outputs() {
        let tools = tools();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            DIAGRAM_TOOL_NAMES
        );
        for tool in tools {
            assert_eq!(tool.input_schema["additionalProperties"], false);
            assert!(tool.output_schema.is_some());
            assert_eq!(
                tool.annotations
                    .as_ref()
                    .and_then(|item| item.open_world_hint),
                Some(false)
            );
        }
    }

    #[test]
    fn diagnostic_projection_does_not_echo_user_text() {
        let mut value = json!({
            "diagnostics":[{"message":"原告：张三","code":"fixture","path":"/nodes/0"}]
        });
        sanitize_diagnostic_messages(&mut value);
        let wire = serde_json::to_string(&value).expect("diagnostic projection serializes");
        assert!(!wire.contains("张三"));
        assert!(wire.contains("code"));
        assert!(wire.contains("path"));
    }

    #[test]
    fn embedded_diagram_schemas_rebase_every_local_reference() {
        let tools = tools();
        let validate = tools
            .iter()
            .find(|tool| tool.name == "diagram.validate")
            .expect("validation tool");
        let validate_wire = serde_json::to_string(&validate.input_schema)
            .expect("validation input schema serializes");
        assert!(!validate_wire.contains("\"#/$defs/"));
        assert!(validate_wire.contains("#/properties/spec/$defs/"));

        let update = tools
            .iter()
            .find(|tool| tool.name == "diagram.update")
            .expect("update tool");
        let update_wire =
            serde_json::to_string(&update.input_schema).expect("update input schema serializes");
        assert!(!update_wire.contains("\"#/$defs/"));
        assert!(update_wire.contains("#/properties/base_spec/anyOf/0/$defs/"));
    }
}
