use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub const APPROVED_CASE_WORKSPACE_TOOL_NAMES: [&str; 10] = [
    "case_list",
    "case_get_public_metadata",
    "case_list_approved_materials",
    "case_read_approved_material",
    "case_search_approved_materials",
    "case_list_work_products",
    "case_read_work_product",
    "case_write_work_product",
    "case_update_work_product",
    "case_export_work_product_manifest",
];

const SCHEMA_VERSION: u8 = 1;
const MAX_QUERY_BYTES: usize = 512;
const MAX_WORK_PRODUCT_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_REFS: usize = 128;
const MAX_ACCESS_TICKET_BYTES: usize = 16 * 1024;
const MAX_CURSOR_BYTES: usize = 512;

const APPROVED_OUTPUT_INSTRUCTION: &str =
    "Only a currently verified CASE_REDACTED_APPROVED generation may reach either content or structuredContent. Raw material, private OCR, review drafts, mappings, paths, filenames, URIs, URLs, secrets, and vault diagnostics are forbidden. This contract is discoverable but execution remains fail closed until the approved workspace backend is qualified.";

pub(crate) fn is_approved_workspace_tool(name: &str) -> bool {
    APPROVED_CASE_WORKSPACE_TOOL_NAMES.contains(&name)
}

pub(crate) fn build_tools() -> Vec<Tool> {
    build_host_tools()
        .into_iter()
        .map(with_access_ticket)
        .collect()
}

pub(crate) fn build_host_tools() -> Vec<Tool> {
    vec![
        make_tool(
            "case_list",
            "List approved cases",
            "List only cases that contain a currently readable approved generation.",
            paged_input(None),
            Hints::read_only(),
        ),
        make_tool(
            "case_get_public_metadata",
            "Get approved case metadata",
            "Read bounded public metadata for one opaque case identifier.",
            object_schema(
                [("schema_version", schema_version()), ("case_id", case_id())],
                &["schema_version", "case_id"],
            ),
            Hints::read_only(),
        ),
        make_tool(
            "case_list_approved_materials",
            "List approved materials",
            "List committed, non-revoked approved material generations for one case.",
            paged_input(Some(("case_id", case_id()))),
            Hints::read_only(),
        ),
        make_tool(
            "case_read_approved_material",
            "Read approved material",
            "Read one exact committed approved generation after manifest, revocation, purpose, and dual-channel egress verification.",
            object_schema(
                [
                    ("schema_version", schema_version()),
                    ("case_id", case_id()),
                    ("material_id", material_id()),
                    ("publication_id", publication_id()),
                ],
                &[
                    "schema_version",
                    "case_id",
                    "material_id",
                    "publication_id",
                ],
            ),
            Hints::read_only(),
        ),
        make_tool(
            "case_search_approved_materials",
            "Search approved materials",
            "Search only currently verified approved material content within one case.",
            object_schema(
                [
                    ("schema_version", schema_version()),
                    ("case_id", case_id()),
                    (
                        "query",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                    ("cursor", cursor()),
                    ("limit", limit()),
                ],
                &["schema_version", "case_id", "query"],
            ),
            Hints::read_only(),
        ),
        make_tool(
            "case_list_work_products",
            "List work products",
            "List verified redacted work products for one case.",
            paged_input(Some(("case_id", case_id()))),
            Hints::read_only(),
        ),
        make_tool(
            "case_read_work_product",
            "Read work product",
            "Read one immutable work-product generation by opaque identifiers and version.",
            object_schema(
                [
                    ("schema_version", schema_version()),
                    ("case_id", case_id()),
                    ("work_product_id", work_product_id()),
                    ("version", version()),
                ],
                &["schema_version", "case_id", "work_product_id", "version"],
            ),
            Hints::read_only(),
        ),
        make_tool(
            "case_write_work_product",
            "Write work product",
            "Create an immutable, residual-scanned work product from explicit approved-generation references.",
            work_product_write_input(false),
            Hints::mutating(),
        ),
        make_tool(
            "case_update_work_product",
            "Update work product",
            "Create the next immutable work-product generation with optimistic concurrency.",
            work_product_write_input(true),
            Hints::mutating(),
        ),
        make_tool(
            "case_export_work_product_manifest",
            "Export work-product manifest",
            "Return the verified signed manifest for one immutable work-product generation; this tool never accepts a filesystem destination.",
            object_schema(
                [
                    ("schema_version", schema_version()),
                    ("case_id", case_id()),
                    ("work_product_id", work_product_id()),
                    ("version", version()),
                ],
                &["schema_version", "case_id", "work_product_id", "version"],
            ),
            Hints::read_only(),
        ),
    ]
}

pub(crate) fn request_is_valid(tool_name: &str, arguments: &JsonObject) -> bool {
    let value = Value::Object(arguments.clone());
    match tool_name {
        "case_list" => decode::<CaseListInput>(value).is_some_and(CaseListInput::validate),
        "case_get_public_metadata" => decode::<CaseInput>(value).is_some_and(CaseInput::validate),
        "case_list_approved_materials" | "case_list_work_products" => {
            decode::<CasePagedInput>(value).is_some_and(CasePagedInput::validate)
        }
        "case_read_approved_material" => decode::<ReadApprovedMaterialInput>(value)
            .is_some_and(ReadApprovedMaterialInput::validate),
        "case_search_approved_materials" => decode::<SearchApprovedMaterialsInput>(value)
            .is_some_and(SearchApprovedMaterialsInput::validate),
        "case_read_work_product" | "case_export_work_product_manifest" => {
            decode::<ReadWorkProductInput>(value).is_some_and(ReadWorkProductInput::validate)
        }
        "case_write_work_product" => {
            decode::<WriteWorkProductInput>(value).is_some_and(WriteWorkProductInput::validate)
        }
        "case_update_work_product" => {
            decode::<UpdateWorkProductInput>(value).is_some_and(UpdateWorkProductInput::validate)
        }
        _ => false,
    }
}

pub(crate) fn split_access_ticket(mut arguments: JsonObject) -> Result<(String, JsonObject), ()> {
    let ticket = arguments.remove("access_ticket").ok_or(())?;
    let ticket = ticket.as_str().ok_or(())?;
    if ticket.is_empty() || ticket.len() > MAX_ACCESS_TICKET_BYTES {
        return Err(());
    }
    Ok((ticket.to_owned(), arguments))
}

pub(crate) fn remove_optional_access_ticket(mut arguments: JsonObject) -> JsonObject {
    arguments.remove("access_ticket");
    arguments
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseListInput {
    schema_version: u8,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
}

impl CaseListInput {
    fn validate(self) -> bool {
        valid_common_page(self.schema_version, self.cursor.as_deref(), self.limit)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    schema_version: u8,
    case_id: String,
}

impl CaseInput {
    fn validate(self) -> bool {
        self.schema_version == SCHEMA_VERSION && valid_id(&self.case_id, "case_")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasePagedInput {
    schema_version: u8,
    case_id: String,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
}

impl CasePagedInput {
    fn validate(self) -> bool {
        valid_id(&self.case_id, "case_")
            && valid_common_page(self.schema_version, self.cursor.as_deref(), self.limit)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadApprovedMaterialInput {
    schema_version: u8,
    case_id: String,
    material_id: String,
    publication_id: String,
}

impl ReadApprovedMaterialInput {
    fn validate(self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && valid_id(&self.case_id, "case_")
            && valid_id(&self.material_id, "mat_")
            && valid_id(&self.publication_id, "pub_")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchApprovedMaterialsInput {
    schema_version: u8,
    case_id: String,
    query: String,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
}

impl SearchApprovedMaterialsInput {
    fn validate(self) -> bool {
        valid_id(&self.case_id, "case_")
            && valid_common_page(self.schema_version, self.cursor.as_deref(), self.limit)
            && !self.query.is_empty()
            && self.query.len() <= MAX_QUERY_BYTES
            && !self.query.chars().any(char::is_control)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadWorkProductInput {
    schema_version: u8,
    case_id: String,
    work_product_id: String,
    version: u64,
}

impl ReadWorkProductInput {
    fn validate(self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && valid_id(&self.case_id, "case_")
            && valid_id(&self.work_product_id, "wp_")
            && self.version > 0
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkProductTaskType {
    CaseAnalysis,
    LegalResearch,
    DraftPleading,
    EvidenceSummary,
    Timeline,
    CitationReview,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkProductStatus {
    Draft,
    Final,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedSourceRefInput {
    material_id: String,
    publication_id: String,
}

impl ApprovedSourceRefInput {
    fn is_valid(&self) -> bool {
        valid_id(&self.material_id, "mat_") && valid_id(&self.publication_id, "pub_")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteWorkProductInput {
    schema_version: u8,
    case_id: String,
    task_type: WorkProductTaskType,
    status: WorkProductStatus,
    source_approved_refs: Vec<ApprovedSourceRefInput>,
    content_media_type: String,
    content: String,
    idempotency_key: String,
}

impl WriteWorkProductInput {
    fn validate(self) -> bool {
        let _ = (self.task_type, self.status);
        self.schema_version == SCHEMA_VERSION
            && valid_id(&self.case_id, "case_")
            && valid_source_refs(&self.source_approved_refs)
            && valid_media_type(&self.content_media_type)
            && !self.content.is_empty()
            && self.content.len() <= MAX_WORK_PRODUCT_BYTES
            && valid_idempotency_key(&self.idempotency_key)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateWorkProductInput {
    schema_version: u8,
    case_id: String,
    work_product_id: String,
    expected_parent_version: u64,
    status: WorkProductStatus,
    source_approved_refs: Vec<ApprovedSourceRefInput>,
    content_media_type: String,
    content: String,
    idempotency_key: String,
}

impl UpdateWorkProductInput {
    fn validate(self) -> bool {
        let _ = self.status;
        self.schema_version == SCHEMA_VERSION
            && valid_id(&self.case_id, "case_")
            && valid_id(&self.work_product_id, "wp_")
            && self.expected_parent_version > 0
            && valid_source_refs(&self.source_approved_refs)
            && valid_media_type(&self.content_media_type)
            && !self.content.is_empty()
            && self.content.len() <= MAX_WORK_PRODUCT_BYTES
            && valid_idempotency_key(&self.idempotency_key)
    }
}

fn valid_common_page(schema_version: u8, cursor: Option<&str>, limit: Option<u16>) -> bool {
    schema_version == SCHEMA_VERSION
        && cursor.is_none_or(valid_cursor)
        && limit.is_none_or(|value| (1..=100).contains(&value))
}

fn valid_cursor(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("cur_") else {
        return false;
    };
    (32..=MAX_CURSOR_BYTES - 4).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_idempotency_key(value: &str) -> bool {
    value.strip_prefix("idem_").is_some_and(|suffix| {
        (32..=96).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn valid_media_type(value: &str) -> bool {
    matches!(value, "text/plain" | "text/markdown")
}

fn valid_source_refs(values: &[ApprovedSourceRefInput]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_SOURCE_REFS
        && values.iter().all(ApprovedSourceRefInput::is_valid)
        && values.iter().enumerate().all(|(index, current)| {
            values[..index].iter().all(|previous| {
                previous.material_id != current.material_id
                    || previous.publication_id != current.publication_id
            })
        })
}

#[derive(Clone, Copy)]
struct Hints {
    read_only: bool,
}

impl Hints {
    const fn read_only() -> Self {
        Self { read_only: true }
    }

    const fn mutating() -> Self {
        Self { read_only: false }
    }
}

fn make_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
    hints: Hints,
) -> Tool {
    let description = format!("{description} {APPROVED_OUTPUT_INSTRUCTION}");
    Tool::new(name, description, json_object(input))
        .with_title(title)
        .with_raw_output_schema(json_object(approved_output_schema()))
        .with_annotations(
            ToolAnnotations::with_title(title)
                .read_only(hints.read_only)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
}

fn with_access_ticket(mut tool: Tool) -> Tool {
    let input = Value::Object(tool.input_schema.as_ref().clone());
    tool.input_schema = json_object(input_with_access_ticket(input));
    tool
}

fn input_with_access_ticket(mut input: Value) -> Value {
    if let Value::Object(root) = &mut input {
        if let Some(Value::Object(properties)) = root.get_mut("properties") {
            properties.insert(
                "access_ticket".to_owned(),
                json!({
                    "type":"string",
                    "minLength":1,
                    "maxLength":MAX_ACCESS_TICKET_BYTES
                }),
            );
        }
        if let Some(Value::Array(required)) = root.get_mut("required") {
            required.push(json!("access_ticket"));
        }
    }
    input
}

fn approved_output_schema() -> Value {
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            "status":{"type":"string","enum":["success","error","unavailable"]},
            "tool":{
                "type":"string",
                "enum":APPROVED_CASE_WORKSPACE_TOOL_NAMES
            },
            "data":{"type":"object"},
            "reason_code":{"type":"string","minLength":1,"maxLength":96,"pattern":"^[A-Z0-9_]+$"}
        },
        "required":["schema_version","status"],
        "additionalProperties":false
    })
}

fn schema_version() -> Value {
    json!({"type":"integer","const":SCHEMA_VERSION})
}

fn case_id() -> Value {
    opaque_id("case_")
}

fn material_id() -> Value {
    opaque_id("mat_")
}

fn publication_id() -> Value {
    opaque_id("pub_")
}

fn work_product_id() -> Value {
    opaque_id("wp_")
}

fn opaque_id(prefix: &str) -> Value {
    json!({
        "type":"string",
        "minLength":prefix.len() + 32,
        "maxLength":prefix.len() + 32,
        "pattern":format!("^{prefix}[a-f0-9]{{32}}$")
    })
}

fn cursor() -> Value {
    json!({
        "type":["string","null"],
        "minLength":36,
        "maxLength":MAX_CURSOR_BYTES,
        "pattern":"^cur_[A-Za-z0-9_-]{32,508}$"
    })
}

fn limit() -> Value {
    json!({"type":["integer","null"],"minimum":1,"maximum":100})
}

fn version() -> Value {
    json!({"type":"integer","minimum":1,"maximum":9223372036854775807_u64})
}

fn idempotency_key() -> Value {
    json!({
        "type":"string",
        "minLength":37,
        "maxLength":101,
        "pattern":"^idem_[A-Za-z0-9_-]{32,96}$"
    })
}

fn source_refs() -> Value {
    json!({
        "type":"array",
        "minItems":1,
        "maxItems":128,
        "uniqueItems":true,
        "items":{
            "type":"object",
            "properties":{
                "material_id":material_id(),
                "publication_id":publication_id()
            },
            "required":["material_id","publication_id"],
            "additionalProperties":false
        }
    })
}

fn paged_input(case_property: Option<(&'static str, Value)>) -> Value {
    let mut properties = Map::from_iter([
        ("schema_version".to_owned(), schema_version()),
        ("cursor".to_owned(), cursor()),
        ("limit".to_owned(), limit()),
    ]);
    let mut required = vec![json!("schema_version")];
    if let Some((name, schema)) = case_property {
        properties.insert(name.to_owned(), schema);
        required.push(json!(name));
    }
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn work_product_write_input(update: bool) -> Value {
    let mut properties = Map::from_iter([
        ("schema_version".to_owned(), schema_version()),
        ("case_id".to_owned(), case_id()),
        (
            "status".to_owned(),
            json!({"type":"string","enum":["draft","final"]}),
        ),
        ("source_approved_refs".to_owned(), source_refs()),
        (
            "content_media_type".to_owned(),
            json!({"type":"string","enum":["text/plain","text/markdown"]}),
        ),
        (
            "content".to_owned(),
            json!({"type":"string","minLength":1,"maxLength":1048576}),
        ),
        ("idempotency_key".to_owned(), idempotency_key()),
    ]);
    let mut required = vec![
        json!("schema_version"),
        json!("case_id"),
        json!("status"),
        json!("source_approved_refs"),
        json!("content_media_type"),
        json!("content"),
        json!("idempotency_key"),
    ];
    if update {
        properties.insert("work_product_id".to_owned(), work_product_id());
        properties.insert("expected_parent_version".to_owned(), version());
        required.push(json!("work_product_id"));
        required.push(json!("expected_parent_version"));
    } else {
        properties.insert(
            "task_type".to_owned(),
            json!({
                "type":"string",
                "enum":[
                    "case_analysis",
                    "legal_research",
                    "draft_pleading",
                    "evidence_summary",
                    "timeline",
                    "citation_review"
                ]
            }),
        );
        required.push(json!("task_type"));
    }
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn object_schema<const N: usize>(
    properties: [(&'static str, Value); N],
    required: &[&str],
) -> Value {
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_owned(), schema))
        .collect::<Map<_, _>>();
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
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

    fn object(value: Value) -> JsonObject {
        value.as_object().cloned().expect("fixture object")
    }

    fn id(prefix: &str, character: char) -> String {
        format!("{prefix}{}", character.to_string().repeat(32))
    }

    #[test]
    fn runtime_contract_rejects_unknown_fields_and_non_opaque_ids() {
        let valid = object(json!({
            "schema_version":1,
            "case_id":id("case_", 'a'),
            "material_id":id("mat_", 'b'),
            "publication_id":id("pub_", 'c')
        }));
        assert!(request_is_valid("case_read_approved_material", &valid));

        let mut unknown = valid.clone();
        unknown.insert("path".to_owned(), json!("C:\\private\\raw.pdf"));
        assert!(!request_is_valid("case_read_approved_material", &unknown));

        let mut wrong_id = valid;
        wrong_id.insert("material_id".to_owned(), json!("raw.pdf"));
        assert!(!request_is_valid("case_read_approved_material", &wrong_id));
    }

    #[test]
    fn work_product_contract_has_no_free_metadata_or_location_fields() {
        let tools = build_tools();
        for tool in tools {
            let serialized = serde_json::to_string(&tool.input_schema).expect("serialize schema");
            for forbidden in [
                "path",
                "filename",
                "file_name",
                "uri",
                "url",
                "directory",
                "glob",
                "command",
                "shell",
                "metadata",
            ] {
                assert!(
                    !serialized.to_ascii_lowercase().contains(forbidden),
                    "{} contains forbidden token {forbidden}",
                    tool.name
                );
            }
            assert_eq!(tool.input_schema["additionalProperties"], false);
            assert_eq!(
                tool.annotations
                    .as_ref()
                    .and_then(|value| value.open_world_hint),
                Some(false)
            );
        }
    }

    #[test]
    fn standalone_host_contract_hides_internal_access_tickets() {
        let tools = build_host_tools();
        assert_eq!(tools.len(), APPROVED_CASE_WORKSPACE_TOOL_NAMES.len());
        for tool in tools {
            let schema = serde_json::to_string(&tool.input_schema).expect("serialize host schema");
            assert!(!schema.contains("access_ticket"), "{}", tool.name);
            assert_eq!(tool.input_schema["additionalProperties"], false);
        }
    }
    #[test]
    fn write_contract_requires_exact_approved_refs_and_concurrency_fields() {
        let write = object(json!({
            "schema_version":1,
            "case_id":id("case_", 'a'),
            "task_type":"case_analysis",
            "status":"draft",
            "source_approved_refs":[{
                "material_id":id("mat_", 'b'),
                "publication_id":id("pub_", 'c')
            }],
            "content_media_type":"text/markdown",
            "content":"[PERSON_1]",
            "idempotency_key":format!("idem_{}", "A".repeat(32))
        }));
        assert!(request_is_valid("case_write_work_product", &write));

        let mut duplicate = write;
        let first = duplicate["source_approved_refs"][0].clone();
        duplicate.insert(
            "source_approved_refs".to_owned(),
            json!([first.clone(), first]),
        );
        assert!(!request_is_valid("case_write_work_product", &duplicate));
    }
}
