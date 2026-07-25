use diagrams::{
    diagram_spec_schema, render_html, spec_hash, validate_json_schema, validation_response,
    DiagramPatch, DiagramService, DiagramServiceError, DiagramSpec, DiagramUpdateRequest,
    DiagramValidationResponse, ExportFormat, TemplateDescriptor, TemplateId, TemplateRegistry,
};
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use serde_path_to_error::{Path as SerdePath, Segment};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};

pub(crate) const DIAGRAM_TOOL_NAMES: [&str; 6] = [
    "diagram.list_templates",
    "diagram.get_schema",
    "diagram.validate",
    "diagram.render",
    "diagram.update",
    "diagram.export",
];

const RESULT_POLICY: &str = "Returns only fixed template metadata, bundled fictional examples, schema, validation codes/paths, statistics, hashes, and content-addressed artifact references. Diagram input text is never echoed. This plaintext local-artifact contract is permanently limited to synthetic/public data; real approved case material must use approved_case_workspace.";
const APPROVED_RESULT_POLICY: &str = "Approved case diagrams require live approved source references and an exact one-time App-issued ticket. The host never supplies paths, filenames, artifact URIs, receipts, or access tickets. Rendered HTML is published only as an encrypted protected work product; responses contain bounded diagnostics, statistics, hashes, opaque identifiers, and verified descriptor metadata bound to the signed work-product manifest.";
const APPROVED_REQUEST_MAX_BYTES: usize = 256 * 1024;
const APPROVED_HTML_MAX_BYTES: usize = privacy::work_products::MAX_WORK_PRODUCT_CONTENT_BYTES;
const MAX_ACCESS_TICKET_BYTES: usize = 16 * 1024;
const APPROVED_LOCATION_SCAN_MAX_DEPTH: usize = 16;
const APPROVED_LOCATION_SCAN_MAX_VALUES: usize = APPROVED_REQUEST_MAX_BYTES;
const APPROVED_METADATA_KEYS: &[&str] = &[
    "amount",
    "applicable_subjects",
    "article_locator",
    "authenticity",
    "authority_level",
    "collateral",
    "contradicts_facts",
    "control_basis",
    "currency",
    "date",
    "date_end",
    "date_precision",
    "date_start",
    "defects",
    "defense_basis",
    "document_number",
    "effective_date",
    "effective_from",
    "evidence_name",
    "evidence_type",
    "examined",
    "formed_at",
    "formed_on",
    "full_name",
    "human_confirmation",
    "is_original",
    "issuer",
    "legality",
    "limitation_deadline",
    "official_source",
    "opponent_view",
    "organization_type",
    "owner",
    "ownership_percent",
    "party",
    "probative_value",
    "procedure",
    "proves",
    "publication_date",
    "purpose",
    "relevance",
    "requested_item",
    "requested_remedy",
    "role",
    "scope",
    "sequence",
    "short_name",
    "source_file",
    "stage",
    "statement_variant",
    "submitted_by",
    "supports_facts",
    "territory",
    "validity_status",
    "verified_by",
    "version",
    "voucher_source_ref",
];

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

pub(crate) fn is_approved_diagram_tool(name: &str) -> bool {
    DIAGRAM_TOOL_NAMES.contains(&name)
}

pub(crate) fn build_approved_tools() -> Vec<Tool> {
    build_approved_host_tools()
        .into_iter()
        .map(with_access_ticket)
        .collect()
}

pub(crate) fn build_approved_host_tools() -> Vec<Tool> {
    let spec = approved_diagram_spec_schema();
    vec![
        make_approved_tool(
            "diagram.list_templates",
            "List approved diagram templates",
            "List the frozen legal-diagram templates without reading case content.",
            version_only_input(),
            true,
        ),
        make_approved_tool(
            "diagram.get_schema",
            "Get approved diagram schema",
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
            true,
        ),
        make_approved_tool(
            "diagram.validate",
            "Validate approved diagram specification",
            "Validate a structured diagram against currently readable approved source generations without writing an artifact.",
            approved_spec_input(rebase_local_refs(spec.clone(), "#/properties/spec"), false),
            true,
        ),
        make_approved_tool(
            "diagram.render",
            "Render approved legal diagram",
            "Deterministically render approved structured data and publish only an encrypted protected HTML work product.",
            approved_spec_input(rebase_local_refs(spec.clone(), "#/properties/spec"), true),
            false,
        ),
        make_approved_tool(
            "diagram.update",
            "Update approved legal diagram",
            "Verify the exact protected parent, apply a bounded optimistic-concurrency patch, and publish the next encrypted work-product version.",
            approved_update_input(rebase_local_refs(spec, "#/properties/base_spec")),
            false,
        ),
        make_approved_tool(
            "diagram.export",
            "Export approved diagram manifest",
            "Return only verified descriptor metadata bound to the signed manifest of an encrypted protected HTML work product; no path or HTML is returned.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "case_id":opaque_id_schema("case_"),
                    "work_product_id":opaque_id_schema("wp_"),
                    "version":version_schema(),
                    "format":{"type":"string","const":"html"}
                },
                "required":["schema_version","case_id","work_product_id","version","format"],
                "additionalProperties":false
            }),
            true,
        ),
    ]
}

pub(crate) fn approved_request_is_valid(tool_name: &str, arguments: &JsonObject) -> bool {
    if serde_json::to_vec(arguments).map_or(true, |bytes| bytes.len() > APPROVED_REQUEST_MAX_BYTES)
    {
        return false;
    }
    if matches!(tool_name, "diagram.validate" | "diagram.render")
        && !approved_spec_argument_is_valid(arguments, "spec")
    {
        return false;
    }
    if tool_name == "diagram.update" && !approved_spec_argument_is_valid(arguments, "base_spec") {
        return false;
    }
    let value = Value::Object(arguments.clone());
    match tool_name {
        "diagram.list_templates" => {
            decode::<ApprovedVersionInput>(arguments.clone()).is_ok_and(|value| value.validate())
        }
        "diagram.get_schema" => {
            decode::<ApprovedSchemaInput>(arguments.clone()).is_ok_and(|value| value.validate())
        }
        "diagram.validate" => serde_json::from_value::<ApprovedValidateInput>(value)
            .is_ok_and(|input| input.validate()),
        "diagram.render" => {
            serde_json::from_value::<ApprovedRenderInput>(value).is_ok_and(|input| input.validate())
        }
        "diagram.update" => {
            serde_json::from_value::<ApprovedUpdateInput>(value).is_ok_and(|input| input.validate())
        }
        "diagram.export" => {
            serde_json::from_value::<ApprovedExportInput>(value).is_ok_and(|input| input.validate())
        }
        _ => false,
    }
}

pub(crate) fn approved_static_response(
    tool_name: &str,
    arguments: &JsonObject,
) -> Result<Value, DiagramMcpError> {
    match tool_name {
        "diagram.list_templates" => {
            let input: ApprovedVersionInput = decode(arguments.clone())?;
            if !input.validate() {
                return Err(DiagramMcpError::new("unsupported_schema_version"));
            }
            let templates = TemplateRegistry::new()
                .iter()
                .map(approved_template_projection)
                .collect::<Vec<_>>();
            Ok(json!({"schema_version":1,"templates":templates}))
        }
        "diagram.get_schema" => {
            let input: ApprovedSchemaInput = decode(arguments.clone())?;
            if !input.validate() {
                return Err(DiagramMcpError::new("unsupported_schema_version"));
            }
            let template = input.template_id.and_then(|id| {
                TemplateRegistry::new()
                    .get(id)
                    .map(approved_template_projection)
            });
            Ok(json!({
                "schema_version":1,
                "diagram_spec_schema":approved_diagram_spec_schema(),
                "template":template
            }))
        }
        _ => Err(DiagramMcpError::new("unknown_tool")),
    }
}

pub(crate) fn approved_spec_from_arguments(
    arguments: &JsonObject,
    field: &str,
) -> Result<DiagramSpec, DiagramMcpError> {
    let value = arguments
        .get(field)
        .cloned()
        .ok_or_else(|| DiagramMcpError::new("invalid_request"))?;
    validate_json_schema(&value).map_err(|error| {
        let path = if error.instance_path == "/" {
            format!("/{field}")
        } else {
            format!("/{field}{}", error.instance_path)
        };
        DiagramMcpError::with_path("invalid_request", sanitize_pointer(&path))
    })?;
    let spec: DiagramSpec =
        serde_json::from_value(value).map_err(|_| DiagramMcpError::new("invalid_request"))?;
    if !approved_spec_has_no_raw_location_fields(&spec) {
        return Err(DiagramMcpError::new("invalid_request"));
    }
    Ok(spec)
}

pub(crate) fn approved_patch_from_arguments(
    arguments: &JsonObject,
) -> Result<DiagramPatch, DiagramMcpError> {
    arguments
        .get("patch")
        .cloned()
        .ok_or_else(|| DiagramMcpError::new("invalid_request"))
        .and_then(|value| {
            let patch: DiagramPatch = serde_json::from_value(value)
                .map_err(|_| DiagramMcpError::new("invalid_request"))?;
            if !approved_patch_shape_is_bounded(&patch) {
                return Err(DiagramMcpError::new("invalid_request"));
            }
            Ok(patch)
        })
}

pub(crate) fn approved_spec_sources_are_bound(
    spec: &DiagramSpec,
    publication_ids: &BTreeSet<String>,
) -> bool {
    approved_spec_bound_publication_ids(spec)
        .is_some_and(|source_ids| &source_ids == publication_ids)
}

pub(crate) fn approved_spec_sources_are_subset_bound(
    spec: &DiagramSpec,
    publication_ids: &BTreeSet<String>,
) -> bool {
    !publication_ids.is_empty()
        && publication_ids
            .iter()
            .all(|value| valid_opaque_id(value, "pub_"))
        && approved_spec_bound_publication_ids(spec)
            .is_some_and(|source_ids| source_ids.is_subset(publication_ids))
}

fn approved_spec_bound_publication_ids(spec: &DiagramSpec) -> Option<BTreeSet<String>> {
    if spec.sources.is_empty() {
        return None;
    }
    let source_ids = spec
        .sources
        .iter()
        .map(|source| source.id.clone())
        .collect::<BTreeSet<_>>();
    let provenance_ids = spec
        .provenance
        .source_file_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let used_ids = spec
        .nodes
        .iter()
        .flat_map(|node| node.source_refs.iter())
        .chain(spec.edges.iter().flat_map(|edge| edge.source_refs.iter()))
        .chain(
            spec.groups
                .iter()
                .flat_map(|group| group.source_refs.iter()),
        )
        .cloned()
        .collect::<BTreeSet<_>>();

    let internally_exact = spec.sources.len() == source_ids.len()
        && spec.provenance.source_file_ids.len() == provenance_ids.len()
        && provenance_ids == source_ids
        && used_ids == source_ids
        && spec.sources.iter().all(|source| {
            valid_opaque_id(&source.id, "pub_")
                && source
                    .artifact_id
                    .as_ref()
                    .is_some_and(|value| value == &source.id)
        });
    internally_exact.then_some(source_ids)
}

pub(crate) fn validate_approved_spec(
    spec: &DiagramSpec,
) -> Result<DiagramValidationResponse, DiagramMcpError> {
    spec_hash(spec).map_err(|_| DiagramMcpError::new("serialization_failed"))?;
    Ok(validation_response(spec))
}

pub(crate) struct ApprovedRenderedDiagram {
    pub(crate) validation: DiagramValidationResponse,
    pub(crate) html: Vec<u8>,
    pub(crate) html_sha256: String,
}

pub(crate) fn render_approved_spec(
    spec: &DiagramSpec,
) -> Result<ApprovedRenderedDiagram, DiagramMcpError> {
    let validation = validate_approved_spec(spec)?;
    if !validation.valid {
        return Err(DiagramMcpError::new("diagram_invalid"));
    }
    let html = render_html(spec).into_bytes();
    if html.len() > APPROVED_HTML_MAX_BYTES {
        return Err(DiagramMcpError::new("artifact_too_large"));
    }
    let digest = Sha256::digest(&html);
    let mut html_sha256 = String::with_capacity(71);
    html_sha256.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut html_sha256, "{byte:02x}")
            .map_err(|_| DiagramMcpError::new("serialization_failed"))?;
    }
    Ok(ApprovedRenderedDiagram {
        validation,
        html,
        html_sha256,
    })
}

pub(crate) fn sanitized_validation_value(
    validation: &DiagramValidationResponse,
) -> Result<Value, DiagramMcpError> {
    serialize_public(validation)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedVersionInput {
    schema_version: u8,
}

impl ApprovedVersionInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedSchemaInput {
    schema_version: u8,
    #[serde(default)]
    template_id: Option<TemplateId>,
}

impl ApprovedSchemaInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedSourceRefInput {
    material_id: String,
    publication_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedValidateInput {
    schema_version: u8,
    case_id: String,
    source_approved_refs: Vec<ApprovedSourceRefInput>,
    spec: DiagramSpec,
}

impl ApprovedValidateInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
            && valid_opaque_id(&self.case_id, "case_")
            && valid_approved_sources(&self.source_approved_refs)
            && approved_spec_has_no_raw_location_fields(&self.spec)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRenderInput {
    schema_version: u8,
    case_id: String,
    source_approved_refs: Vec<ApprovedSourceRefInput>,
    spec: DiagramSpec,
    status: String,
    idempotency_key: String,
}

impl ApprovedRenderInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
            && valid_opaque_id(&self.case_id, "case_")
            && valid_approved_sources(&self.source_approved_refs)
            && approved_spec_has_no_raw_location_fields(&self.spec)
            && valid_status(&self.status)
            && valid_idempotency_key(&self.idempotency_key)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedUpdateInput {
    schema_version: u8,
    case_id: String,
    work_product_id: String,
    expected_parent_version: u64,
    source_approved_refs: Vec<ApprovedSourceRefInput>,
    base_spec: DiagramSpec,
    expected_spec_hash: String,
    patch: DiagramPatch,
    status: String,
    idempotency_key: String,
}

impl ApprovedUpdateInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
            && valid_opaque_id(&self.case_id, "case_")
            && valid_opaque_id(&self.work_product_id, "wp_")
            && self.expected_parent_version > 0
            && valid_approved_sources(&self.source_approved_refs)
            && approved_spec_has_no_raw_location_fields(&self.base_spec)
            && valid_prefixed_sha256(&self.expected_spec_hash)
            && valid_status(&self.status)
            && valid_idempotency_key(&self.idempotency_key)
            && approved_patch_shape_is_bounded(&self.patch)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedExportInput {
    schema_version: u8,
    case_id: String,
    work_product_id: String,
    version: u64,
    format: ExportFormat,
}

impl ApprovedExportInput {
    fn validate(&self) -> bool {
        self.schema_version == 1
            && valid_opaque_id(&self.case_id, "case_")
            && valid_opaque_id(&self.work_product_id, "wp_")
            && self.version > 0
            && self.format == ExportFormat::Html
    }
}

fn approved_spec_argument_is_valid(arguments: &JsonObject, field: &str) -> bool {
    arguments
        .get(field)
        .is_some_and(|value| validate_json_schema(value).is_ok())
}

fn valid_approved_sources(values: &[ApprovedSourceRefInput]) -> bool {
    if values.is_empty() || values.len() > 128 {
        return false;
    }
    let mut unique = BTreeSet::new();
    values.iter().all(|value| {
        valid_opaque_id(&value.material_id, "mat_")
            && valid_opaque_id(&value.publication_id, "pub_")
            && unique.insert((&value.material_id, &value.publication_id))
    })
}

fn approved_spec_has_no_raw_location_fields(spec: &DiagramSpec) -> bool {
    spec.sources.iter().all(approved_source_is_opaque)
        && spec
            .provenance
            .source_file_ids
            .iter()
            .all(|value| valid_opaque_id(value, "pub_"))
        && spec
            .nodes
            .iter()
            .all(|node| approved_metadata_is_closed(&node.metadata))
        && spec
            .edges
            .iter()
            .all(|edge| approved_metadata_is_closed(&edge.metadata))
        && serializable_has_no_raw_location(spec)
}

fn approved_source_is_opaque(source: &diagrams::Source) -> bool {
    source.uri.is_none()
        && source.file_name.is_none()
        && source.attachment.is_none()
        && source
            .artifact_id
            .as_deref()
            .is_some_and(|value| valid_opaque_id(value, "pub_"))
}

fn approved_patch_shape_is_bounded(patch: &DiagramPatch) -> bool {
    patch.title.as_ref().is_none_or(|value| value.len() <= 256)
        && patch
            .summary
            .as_ref()
            .is_none_or(|value| value.len() <= 4096)
        && patch
            .change_summary
            .as_ref()
            .is_none_or(|value| value.len() <= 1024)
        && patch.upsert_nodes.len() <= 500
        && patch.remove_node_ids.len() <= 500
        && patch.upsert_edges.len() <= 1200
        && patch.remove_edge_ids.len() <= 1200
        && patch.upsert_groups.len() <= 100
        && patch.remove_group_ids.len() <= 100
        && patch.upsert_sources.len() <= 1000
        && patch.remove_source_ids.len() <= 1000
        && patch.upsert_sources.iter().all(approved_source_is_opaque)
        && patch
            .upsert_nodes
            .iter()
            .all(|node| approved_metadata_is_closed(&node.metadata))
        && patch
            .upsert_edges
            .iter()
            .all(|edge| approved_metadata_is_closed(&edge.metadata))
        && patch
            .title
            .as_deref()
            .is_none_or(approved_location_value_is_safe)
        && patch
            .summary
            .as_deref()
            .is_none_or(approved_location_value_is_safe)
        && patch
            .change_summary
            .as_deref()
            .is_none_or(approved_location_value_is_safe)
        && serializable_has_no_raw_location(&patch.layout_hints)
        && serializable_has_no_raw_location(&patch.display_options)
        && serializable_has_no_raw_location(&patch.upsert_nodes)
        && serializable_has_no_raw_location(&patch.remove_node_ids)
        && serializable_has_no_raw_location(&patch.upsert_edges)
        && serializable_has_no_raw_location(&patch.remove_edge_ids)
        && serializable_has_no_raw_location(&patch.upsert_groups)
        && serializable_has_no_raw_location(&patch.remove_group_ids)
        && serializable_has_no_raw_location(&patch.upsert_sources)
        && serializable_has_no_raw_location(&patch.remove_source_ids)
}

fn approved_metadata_is_closed(metadata: &diagrams::Metadata) -> bool {
    metadata.len() <= APPROVED_METADATA_KEYS.len()
        && metadata.iter().all(|(key, value)| {
            APPROVED_METADATA_KEYS.contains(&key.as_str())
                && approved_metadata_value_is_safe(key, value)
        })
}

fn approved_metadata_value_is_safe(key: &str, value: &diagrams::MetadataValue) -> bool {
    if matches!(
        key,
        "official_source" | "source_file" | "voucher_source_ref"
    ) {
        return matches!(
            value,
            diagrams::MetadataValue::Scalar(diagrams::MetadataScalar::String(value))
                if valid_opaque_id(value, "pub_")
        );
    }
    if matches!(key, "contradicts_facts" | "proves" | "supports_facts") {
        return match value {
            diagrams::MetadataValue::Scalar(diagrams::MetadataScalar::String(value)) => {
                valid_diagram_identifier(value)
            }
            diagrams::MetadataValue::Array(values) => {
                values.len() <= 100
                    && values.iter().all(|value| {
                        matches!(
                            value,
                            diagrams::MetadataScalar::String(value)
                                if valid_diagram_identifier(value)
                        )
                    })
            }
            diagrams::MetadataValue::Scalar(_) | diagrams::MetadataValue::Object(_) => false,
        };
    }
    match value {
        diagrams::MetadataValue::Scalar(value) => approved_metadata_scalar_is_safe(value),
        diagrams::MetadataValue::Array(values) => {
            values.len() <= 100 && values.iter().all(approved_metadata_scalar_is_safe)
        }
        diagrams::MetadataValue::Object(_) => false,
    }
}

fn valid_diagram_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=96).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn approved_metadata_scalar_is_safe(value: &diagrams::MetadataScalar) -> bool {
    match value {
        diagrams::MetadataScalar::String(value) => approved_location_value_is_safe(value),
        diagrams::MetadataScalar::Number(value) => {
            value.as_i64().is_some() || value.as_u64().is_some()
        }
        diagrams::MetadataScalar::Null | diagrams::MetadataScalar::Bool(_) => true,
    }
}

fn serializable_has_no_raw_location<T: Serialize>(value: &T) -> bool {
    let Ok(value) = serde_json::to_value(value) else {
        return false;
    };
    let mut remaining = APPROVED_LOCATION_SCAN_MAX_VALUES;
    json_value_has_no_raw_location(&value, 0, &mut remaining)
}

fn json_value_has_no_raw_location(value: &Value, depth: usize, remaining: &mut usize) -> bool {
    if depth > APPROVED_LOCATION_SCAN_MAX_DEPTH || *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    match value {
        Value::String(value) => approved_location_value_is_safe(value),
        Value::Array(values) => values
            .iter()
            .all(|value| json_value_has_no_raw_location(value, depth + 1, remaining)),
        Value::Object(values) => values
            .values()
            .all(|value| json_value_has_no_raw_location(value, depth + 1, remaining)),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

fn approved_location_value_is_safe(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value.contains('\\')
        && !lower.contains("file://")
        && !lower.contains("file:/")
        && !lower.contains("lawyer-assistance://")
        && !lower.contains("lawyer-assistance:/")
        && !lower.contains("://")
        && !contains_uri_scheme(value)
        && !contains_windows_drive_designator(value)
        && !contains_unc_path(value)
        && !contains_slash_separated_path(value)
        && !contains_filename(value)
}

fn contains_uri_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_alphabetic()
            || (start > 0 && !scheme_start_boundary(bytes[start - 1]))
        {
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len()
            && end - start <= 32
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'-' | b'.'))
        {
            end += 1;
        }
        if bytes.get(end) != Some(&b':') {
            continue;
        }
        let scheme = value[start..end].to_ascii_lowercase();
        if bytes.get(end + 1) == Some(&b'/')
            || matches!(scheme.as_str(), "blob" | "data" | "file" | "mailto" | "urn")
        {
            return true;
        }
    }
    false
}

fn contains_windows_drive_designator(value: &str) -> bool {
    let bytes = value.as_bytes();
    (0..bytes.len().saturating_sub(1)).any(|index| {
        bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
            && bytes
                .get(index + 2)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
    })
}

fn contains_unc_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (0..bytes.len().saturating_sub(2)).any(|index| {
        ((bytes[index] == b'\\' && bytes[index + 1] == b'\\')
            || (bytes[index] == b'/' && bytes[index + 1] == b'/'))
            && !matches!(bytes.get(index + 2), None | Some(b'\\' | b'/'))
    })
}

fn scheme_start_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'-' | b'.')
}

fn contains_slash_separated_path(value: &str) -> bool {
    if !value.contains('/') {
        return false;
    }
    value
        .split_whitespace()
        .filter(|token| token.contains('/'))
        .any(|token| {
            let token = token.trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\''
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | ','
                        | ';'
                        | '!'
                        | '?'
                        | '，'
                        | '。'
                        | '；'
                        | '！'
                        | '？'
                )
            });
            !allowed_natural_slash_expression(token)
        })
}

fn allowed_natural_slash_expression(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "and/or"
            | "either/or"
            | "he/she"
            | "his/her"
            | "input/output"
            | "read/write"
            | "true/false"
            | "yes/no"
    ) || matches!(value, "和/或" | "是/否" | "输入/输出" | "读/写")
    {
        return true;
    }
    let mut segments = value.split('/');
    let mut count = 0_usize;
    for segment in &mut segments {
        if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    count >= 2
}

fn contains_filename(value: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        "7z", "csv", "db", "dll", "doc", "docx", "eml", "exe", "gif", "htm", "html", "jpeg", "jpg",
        "json", "log", "md", "msg", "ods", "odt", "parquet", "pdf", "png", "ppt", "pptx", "rar",
        "rtf", "sqlite", "tif", "tiff", "txt", "xls", "xlsx", "xml", "yaml", "yml", "zip",
    ];
    let lower = value.to_ascii_lowercase();
    EXTENSIONS.iter().any(|extension| {
        let needle = format!(".{extension}");
        lower.match_indices(&needle).any(|(index, _)| {
            let end = index + needle.len();
            (index > 0 || value.starts_with('.'))
                && lower
                    .as_bytes()
                    .get(end)
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        })
    })
}

fn valid_opaque_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(is_lower_hex))
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|suffix| suffix.len() == 64 && suffix.bytes().all(is_lower_hex))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn valid_status(value: &str) -> bool {
    matches!(value, "draft" | "final")
}

fn valid_idempotency_key(value: &str) -> bool {
    (37..=101).contains(&value.len())
        && value.starts_with("idem_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
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

fn approved_template_projection(template: &TemplateDescriptor) -> Value {
    json!({
        "id":template.id,
        "diagram_type":template.diagram_type,
        "semantic_version":template.semantic_version,
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

fn make_approved_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
    read_only: bool,
) -> Tool {
    Tool::new(
        name,
        format!("{description} {APPROVED_RESULT_POLICY}"),
        json_object(input),
    )
    .with_title(title)
    .with_raw_output_schema(json_object(approved_output_schema()))
    .with_annotations(
        ToolAnnotations::with_title(title)
            .read_only(read_only)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn with_access_ticket(mut tool: Tool) -> Tool {
    let mut input = Value::Object(tool.input_schema.as_ref().clone());
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
    tool.input_schema = json_object(input);
    tool
}

fn approved_output_schema() -> Value {
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            "status":{"type":"string","enum":["success","error","unavailable"]},
            "tool":{"type":"string","enum":DIAGRAM_TOOL_NAMES},
            "data":{"type":"object"},
            "reason_code":{"type":"string","minLength":1,"maxLength":96,"pattern":"^[A-Z0-9_]+$"}
        },
        "required":["schema_version","status"],
        "additionalProperties":false
    })
}

fn approved_diagram_spec_schema() -> Value {
    let mut schema = diagram_spec_schema();
    if let Some(definitions) = schema.get_mut("$defs").and_then(Value::as_object_mut) {
        definitions.remove("metadata_scalar");
        definitions.remove("metadata_value");
        definitions.insert("metadata".to_owned(), approved_metadata_schema());
    }
    if let Some(properties) = schema
        .pointer_mut("/$defs/source/properties")
        .and_then(Value::as_object_mut)
    {
        properties.remove("uri");
        properties.remove("file_name");
        properties.remove("attachment");
        properties.insert("id".to_owned(), opaque_id_schema("pub_"));
        properties.insert("artifact_id".to_owned(), opaque_id_schema("pub_"));
    }
    if let Some(required) = schema
        .pointer_mut("/$defs/source/required")
        .and_then(Value::as_array_mut)
    {
        if !required.iter().any(|value| value == "artifact_id") {
            required.push(json!("artifact_id"));
        }
    }
    if let Some(kinds) = schema
        .pointer_mut("/$defs/source/properties/kind/enum")
        .and_then(Value::as_array_mut)
    {
        kinds.retain(|value| {
            !matches!(
                value.as_str(),
                Some("file" | "file_page" | "attachment" | "uri")
            )
        });
    }
    if let Some(items) = schema.pointer_mut("/$defs/provenance/properties/source_file_ids/items") {
        *items = opaque_id_schema("pub_");
    }
    schema
}

fn approved_spec_input(spec: Value, mutating: bool) -> Value {
    let mut properties = Map::from_iter([
        ("schema_version".to_owned(), schema_version()),
        ("case_id".to_owned(), opaque_id_schema("case_")),
        (
            "source_approved_refs".to_owned(),
            approved_source_refs_schema(),
        ),
        ("spec".to_owned(), spec),
    ]);
    let mut required = vec![
        json!("schema_version"),
        json!("case_id"),
        json!("source_approved_refs"),
        json!("spec"),
    ];
    if mutating {
        properties.insert(
            "status".to_owned(),
            json!({"type":"string","enum":["draft","final"]}),
        );
        properties.insert("idempotency_key".to_owned(), idempotency_key_schema());
        required.push(json!("status"));
        required.push(json!("idempotency_key"));
    }
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn approved_update_input(base_spec: Value) -> Value {
    json!({
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            "case_id":opaque_id_schema("case_"),
            "work_product_id":opaque_id_schema("wp_"),
            "expected_parent_version":version_schema(),
            "source_approved_refs":approved_source_refs_schema(),
            "base_spec":base_spec,
            "expected_spec_hash":prefixed_sha256_schema(),
            "patch":approved_patch_schema(),
            "status":{"type":"string","enum":["draft","final"]},
            "idempotency_key":idempotency_key_schema()
        },
        "required":[
            "schema_version","case_id","work_product_id","expected_parent_version",
            "source_approved_refs","base_spec","expected_spec_hash","patch","status",
            "idempotency_key"
        ],
        "additionalProperties":false
    })
}

fn approved_metadata_schema() -> Value {
    let generic_value = approved_metadata_value_schema();
    let mut properties = Map::new();
    for key in APPROVED_METADATA_KEYS {
        properties.insert((*key).to_owned(), generic_value.clone());
    }
    for key in ["official_source", "source_file", "voucher_source_ref"] {
        properties.insert(key.to_owned(), opaque_id_schema("pub_"));
    }
    for key in ["contradicts_facts", "proves", "supports_facts"] {
        properties.insert(key.to_owned(), approved_metadata_identifier_value_schema());
    }
    json!({
        "type":"object",
        "maxProperties":APPROVED_METADATA_KEYS.len(),
        "properties":properties,
        "additionalProperties":false
    })
}

fn approved_metadata_value_schema() -> Value {
    let scalar = json!({
        "type":["string","integer","boolean","null"],
        "maxLength":16384
    });
    json!({
        "oneOf":[
            scalar.clone(),
            {
                "type":"array",
                "maxItems":100,
                "items":scalar
            }
        ]
    })
}

fn approved_metadata_identifier_value_schema() -> Value {
    json!({
        "oneOf":[
            {"$ref":"#/$defs/identifier"},
            {
                "type":"array",
                "maxItems":100,
                "items":{"$ref":"#/$defs/identifier"}
            }
        ]
    })
}

fn approved_patch_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "title":{"type":["string","null"],"maxLength":256},
            "summary":{"type":["string","null"],"maxLength":4096},
            "layout_hints":{
                "oneOf":[
                    {"$ref":"#/properties/base_spec/$defs/layout_hints"},
                    {"type":"null"}
                ]
            },
            "display_options":{
                "oneOf":[
                    {"$ref":"#/properties/base_spec/$defs/display_options"},
                    {"type":"null"}
                ]
            },
            "upsert_nodes":{
                "type":"array",
                "maxItems":500,
                "items":{"$ref":"#/properties/base_spec/$defs/node"}
            },
            "remove_node_ids":{
                "type":"array",
                "maxItems":500,
                "items":{"$ref":"#/properties/base_spec/$defs/identifier"}
            },
            "upsert_edges":{
                "type":"array",
                "maxItems":1200,
                "items":{"$ref":"#/properties/base_spec/$defs/edge"}
            },
            "remove_edge_ids":{
                "type":"array",
                "maxItems":1200,
                "items":{"$ref":"#/properties/base_spec/$defs/identifier"}
            },
            "upsert_groups":{
                "type":"array",
                "maxItems":100,
                "items":{"$ref":"#/properties/base_spec/$defs/group"}
            },
            "remove_group_ids":{
                "type":"array",
                "maxItems":100,
                "items":{"$ref":"#/properties/base_spec/$defs/identifier"}
            },
            "upsert_sources":{
                "type":"array",
                "maxItems":1000,
                "items":{"$ref":"#/properties/base_spec/$defs/source"}
            },
            "remove_source_ids":{
                "type":"array",
                "maxItems":1000,
                "items":{"$ref":"#/properties/base_spec/$defs/identifier"}
            },
            "change_summary":{"type":["string","null"],"maxLength":1024}
        },
        "additionalProperties":false
    })
}

fn approved_source_refs_schema() -> Value {
    json!({
        "type":"array",
        "minItems":1,
        "maxItems":128,
        "uniqueItems":true,
        "items":{
            "type":"object",
            "properties":{
                "material_id":opaque_id_schema("mat_"),
                "publication_id":opaque_id_schema("pub_")
            },
            "required":["material_id","publication_id"],
            "additionalProperties":false
        }
    })
}

fn opaque_id_schema(prefix: &str) -> Value {
    json!({
        "type":"string",
        "minLength":prefix.len() + 32,
        "maxLength":prefix.len() + 32,
        "pattern":format!("^{prefix}[a-f0-9]{{32}}$")
    })
}

fn version_schema() -> Value {
    json!({"type":"integer","minimum":1,"maximum":9223372036854775807_u64})
}

fn idempotency_key_schema() -> Value {
    json!({
        "type":"string",
        "minLength":37,
        "maxLength":101,
        "pattern":"^idem_[A-Za-z0-9_-]{32,96}$"
    })
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
            "patch":patch_schema()
        },
        "required":["schema_version","expected_spec_hash","patch"],
        "additionalProperties":false
    })
}

fn patch_schema() -> Value {
    json!({
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

    fn approved_qualification_arguments() -> Value {
        let publication_id = format!("pub_{}", "a".repeat(32));
        let mut spec: Value = serde_json::from_str(include_str!(
            "../../diagrams/examples/case_issue_evidence_law_v1.json"
        ))
        .expect("qualification fixture JSON");
        spec["title"] = json!("[PERSON_001] approved diagram qualification");
        spec["summary"] = json!("Alias-only synthetic approved diagram qualification.");
        spec["sources"] = json!([{
            "id":publication_id,
            "kind":"case_record",
            "title":"Approved source",
            "locator":"Approved publication",
            "artifact_id":publication_id,
            "verification_status":"human_confirmed"
        }]);
        for collection in ["nodes", "edges", "groups"] {
            for item in spec[collection].as_array_mut().expect("fixture collection") {
                item["source_refs"] = json!([publication_id]);
                if let Some(metadata) = item
                    .as_object_mut()
                    .and_then(|object| object.get_mut("metadata"))
                    .and_then(Value::as_object_mut)
                {
                    if metadata.contains_key("official_source") {
                        metadata.insert("official_source".to_owned(), json!(publication_id));
                    }
                }
            }
        }
        spec["provenance"]["source_file_ids"] = json!([publication_id]);
        validate_json_schema(&spec).expect("qualification spec satisfies DiagramSpec v1");

        json!({
            "schema_version":1,
            "case_id":format!("case_{}", "b".repeat(32)),
            "source_approved_refs":[{
                "material_id":format!("mat_{}", "c".repeat(32)),
                "publication_id":publication_id
            }],
            "spec":spec
        })
    }

    fn approved_update_arguments() -> Value {
        let qualification = approved_qualification_arguments();
        json!({
            "schema_version":1,
            "case_id":qualification["case_id"],
            "work_product_id":format!("wp_{}", "d".repeat(32)),
            "expected_parent_version":1,
            "source_approved_refs":qualification["source_approved_refs"],
            "base_spec":qualification["spec"],
            "expected_spec_hash":format!("sha256:{}", "e".repeat(64)),
            "patch":{"change_summary":"Approved semantic correction"},
            "status":"draft",
            "idempotency_key":format!("idem_{}", "f".repeat(32))
        })
    }

    fn assert_recursively_closed_object_schemas(value: &Value, path: &str) {
        let declares_object = value.get("type").is_some_and(|kind| {
            kind == "object"
                || kind
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "object"))
        });
        if declares_object {
            assert_eq!(
                value.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "object schema at {path} must be recursively closed"
            );
        }
        match value {
            Value::Object(object) => {
                for (key, nested) in object {
                    assert_recursively_closed_object_schemas(nested, &format!("{path}/{key}"));
                }
            }
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    assert_recursively_closed_object_schemas(nested, &format!("{path}/{index}"));
                }
            }
            _ => {}
        }
    }

    fn assert_all_local_refs_resolve(root: &Value, value: &Value) {
        if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
            let pointer = reference
                .strip_prefix('#')
                .expect("approved diagram schemas use only local references");
            assert!(
                root.pointer(pointer).is_some(),
                "local schema reference {reference} must resolve"
            );
        }
        match value {
            Value::Object(object) => {
                for nested in object.values() {
                    assert_all_local_refs_resolve(root, nested);
                }
            }
            Value::Array(values) => {
                for nested in values {
                    assert_all_local_refs_resolve(root, nested);
                }
            }
            _ => {}
        }
    }

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

    #[test]
    fn approved_qualification_fixture_is_a_valid_ticket_request() {
        let arguments = approved_qualification_arguments();
        let arguments = arguments.as_object().expect("request object");
        assert!(
            approved_request_is_valid("diagram.validate", arguments),
            "approved pub_ identifiers and closed metadata must remain signable"
        );

        for natural in [
            "This matter remains private and requires human review.",
            "read/write",
            "2026/07/25",
        ] {
            let mut natural_arguments = approved_qualification_arguments();
            natural_arguments["spec"]["nodes"][0]["metadata"]["scope"] = json!(natural);
            assert!(
                approved_request_is_valid(
                    "diagram.validate",
                    natural_arguments.as_object().expect("request object")
                ),
                "ordinary non-location text must remain valid: {natural}"
            );
        }
    }

    #[test]
    fn approved_spec_sources_are_exactly_bound_to_the_envelope() {
        let arguments = approved_qualification_arguments();
        let arguments_object = arguments.as_object().expect("request object");
        let spec =
            approved_spec_from_arguments(arguments_object, "spec").expect("approved fixture spec");
        let publication_id = format!("pub_{}", "a".repeat(32));
        let exact = BTreeSet::from([publication_id.clone()]);
        assert!(approved_spec_sources_are_bound(&spec, &exact));

        let extra_publication_id = format!("pub_{}", "9".repeat(32));
        let envelope_with_unused_extra =
            BTreeSet::from([publication_id.clone(), extra_publication_id.clone()]);
        assert!(
            !approved_spec_sources_are_bound(&spec, &envelope_with_unused_extra),
            "an approved envelope must not carry a publication absent from the spec"
        );
        assert!(
            approved_spec_sources_are_subset_bound(&spec, &envelope_with_unused_extra),
            "update lineage may carry a strict envelope superset while the spec stays internally exact"
        );

        let mut missing_provenance_arguments = approved_qualification_arguments();
        missing_provenance_arguments["spec"]["provenance"]["source_file_ids"] = json!([]);
        let missing_provenance = approved_spec_from_arguments(
            missing_provenance_arguments
                .as_object()
                .expect("request object"),
            "spec",
        )
        .expect("structurally valid spec");
        assert!(
            !approved_spec_sources_are_bound(&missing_provenance, &exact),
            "provenance must bind the same exact publication set"
        );
        assert!(!approved_spec_sources_are_subset_bound(
            &missing_provenance,
            &exact
        ));

        let mut unused_source_arguments = approved_qualification_arguments();
        let mut unused_source = unused_source_arguments["spec"]["sources"][0].clone();
        unused_source["id"] = json!(extra_publication_id);
        unused_source["artifact_id"] = json!(extra_publication_id);
        unused_source_arguments["spec"]["sources"]
            .as_array_mut()
            .expect("sources array")
            .push(unused_source);
        unused_source_arguments["spec"]["provenance"]["source_file_ids"] =
            json!([publication_id, extra_publication_id]);
        let unused_source_spec = approved_spec_from_arguments(
            unused_source_arguments.as_object().expect("request object"),
            "spec",
        )
        .expect("structurally valid spec");
        assert!(
            !approved_spec_sources_are_bound(&unused_source_spec, &envelope_with_unused_extra),
            "every bound publication must be used by a node, edge, or group"
        );
        assert!(!approved_spec_sources_are_subset_bound(
            &unused_source_spec,
            &envelope_with_unused_extra
        ));
    }

    #[test]
    fn approved_schemas_close_metadata_and_every_patch_object() {
        let approved_tools = build_approved_host_tools();
        for name in ["diagram.validate", "diagram.render", "diagram.update"] {
            let tool = approved_tools
                .iter()
                .find(|tool| tool.name == name)
                .expect("approved spec-bearing tool");
            let schema = Value::Object(tool.input_schema.as_ref().clone());
            assert_all_local_refs_resolve(&schema, &schema);
        }
        let update = approved_tools
            .iter()
            .find(|tool| tool.name == "diagram.update")
            .expect("approved update tool");
        let update_schema = Value::Object(update.input_schema.as_ref().clone());
        assert_recursively_closed_object_schemas(&update_schema, "#");
        assert_eq!(
            update_schema.pointer("/properties/patch/properties/upsert_nodes/items/$ref"),
            Some(&json!("#/properties/base_spec/$defs/node"))
        );
        assert_eq!(
            update_schema.pointer("/properties/patch/properties/upsert_sources/items/$ref"),
            Some(&json!("#/properties/base_spec/$defs/source"))
        );
        let metadata = update_schema
            .pointer("/properties/base_spec/$defs/metadata")
            .expect("approved metadata projection");
        assert_eq!(metadata["additionalProperties"], false);
        assert!(metadata["properties"].get("official_source").is_some());
        let generic_metadata_wire = serde_json::to_string(&metadata["properties"]["sequence"])
            .expect("generic approved metadata schema");
        assert!(generic_metadata_wire.contains("\"integer\""));
        assert!(
            !generic_metadata_wire.contains("\"number\""),
            "approved tools/list must not advertise floats that ticket canonicalization rejects"
        );
        for forbidden in [
            "artifact_uri",
            "attachment",
            "file_name",
            "filename",
            "locator",
            "path",
        ] {
            assert!(
                metadata["properties"].get(forbidden).is_none(),
                "{forbidden} must not be advertised as approved metadata"
            );
        }

        let raw_update = tools()
            .into_iter()
            .find(|tool| tool.name == "diagram.update")
            .expect("raw update tool");
        let raw_update_schema = Value::Object(raw_update.input_schema.as_ref().clone());
        assert_eq!(
            raw_update_schema.pointer("/properties/patch/properties/upsert_nodes/items/type"),
            Some(&json!("object")),
            "the synthetic/public raw profile remains unchanged"
        );
    }

    #[test]
    fn approved_specs_reject_location_aliases_in_metadata_and_free_text() {
        let variants = [
            ("metadata.case_path", "C:\\private\\raw.pdf"),
            (
                "metadata.artifact_uri",
                "lawyer-assistance://diagrams/deadbeef",
            ),
            ("metadata.filename", "raw.pdf"),
            ("metadata.attachment", "B1"),
            ("locator.drive", "C:/private/raw.pdf"),
            ("locator.unc", "\\\\server\\matter\\raw.pdf"),
            ("locator.file_uri", "file:///C:/private/raw.pdf"),
            (
                "locator.artifact_uri",
                "lawyer-assistance://diagrams/deadbeef",
            ),
            ("locator.https_uri", "https://example.test/matter"),
            ("locator.data_uri", "data:text/plain;base64,QUJD"),
            ("locator.filename", "raw.pdf"),
            ("locator.traversal_backslash", "..\\..\\private\\matter"),
            ("locator.root_backslash", "\\private\\matter"),
            ("locator.drive_relative", "C:private\\matter"),
            ("locator.drive_relative_single", "C:private"),
            ("locator.root_slash", "/private/matter"),
            ("locator.relative_slash", "private/matter"),
            ("locator.diagnostic_pointer", "/nodes/0"),
        ];
        for (variant, value) in variants {
            let mut arguments = approved_qualification_arguments();
            if let Some(key) = variant.strip_prefix("metadata.") {
                arguments["spec"]["nodes"][0]["metadata"][key] = json!(value);
            } else {
                arguments["spec"]["sources"][0]["locator"] = json!(value);
            }
            assert!(
                !approved_request_is_valid(
                    "diagram.validate",
                    arguments.as_object().expect("request object")
                ),
                "{variant} must not cross the approved diagram boundary"
            );
        }

        for value in [
            "..\\..\\private\\matter",
            "\\private\\matter",
            "C:private\\matter",
            "C:private",
            "/private/matter",
            "private/matter",
            "/nodes/0",
        ] {
            let mut arguments = approved_qualification_arguments();
            arguments["spec"]["nodes"][0]["metadata"]["scope"] = json!(value);
            assert!(
                !approved_request_is_valid(
                    "diagram.validate",
                    arguments.as_object().expect("request object")
                ),
                "approved metadata must reject location value {value:?}"
            );
        }

        let mut nested = approved_qualification_arguments();
        nested["spec"]["nodes"][0]["metadata"]["scope"] =
            json!({"note":"file:///C:/private/raw.pdf"});
        assert!(
            !approved_request_is_valid(
                "diagram.validate",
                nested.as_object().expect("request object")
            ),
            "approved metadata must not retain an open nested object escape hatch"
        );

        let mut invalid_reference = approved_qualification_arguments();
        invalid_reference["spec"]["nodes"][0]["metadata"]["supports_facts"] =
            json!("not a valid identifier");
        assert!(
            !approved_request_is_valid(
                "diagram.validate",
                invalid_reference.as_object().expect("request object")
            ),
            "runtime must enforce the identifier shape advertised for reference metadata"
        );

        for tool_name in ["diagram.validate", "diagram.render"] {
            let mut float_arguments = approved_qualification_arguments();
            float_arguments["spec"]["nodes"][0]["metadata"]["sequence"] = json!(0.5);
            if tool_name == "diagram.render" {
                float_arguments
                    .as_object_mut()
                    .expect("request object")
                    .insert("status".to_owned(), json!("draft"));
                float_arguments
                    .as_object_mut()
                    .expect("request object")
                    .insert(
                        "idempotency_key".to_owned(),
                        json!(format!("idem_{}", "1".repeat(32))),
                    );
            }
            assert!(
                !approved_request_is_valid(
                    tool_name,
                    float_arguments.as_object().expect("request object")
                ),
                "{tool_name} must reject floats before ticket canonicalization"
            );
        }

        for field in ["uri", "file_name", "attachment"] {
            let mut arguments = approved_qualification_arguments();
            arguments["spec"]["sources"][0][field] = json!("raw.pdf");
            assert!(
                !approved_request_is_valid(
                    "diagram.validate",
                    arguments.as_object().expect("request object")
                ),
                "source.{field} must remain outside the approved projection"
            );
        }
    }

    #[test]
    fn approved_patch_upserts_reject_location_aliases() {
        let safe = approved_update_arguments();
        assert!(approved_request_is_valid(
            "diagram.update",
            safe.as_object().expect("request object")
        ));

        let mut node_path = approved_update_arguments();
        let mut node = node_path["base_spec"]["nodes"][0].clone();
        node["metadata"]["evidence_name"] = json!("C:\\private\\raw.pdf");
        node_path["patch"]["upsert_nodes"] = json!([node]);
        assert!(!approved_request_is_valid(
            "diagram.update",
            node_path.as_object().expect("request object")
        ));

        let mut source_uri = approved_update_arguments();
        let mut source = source_uri["base_spec"]["sources"][0].clone();
        source["locator"] = json!("lawyer-assistance://diagrams/deadbeef");
        source_uri["patch"]["upsert_sources"] = json!([source]);
        assert!(!approved_request_is_valid(
            "diagram.update",
            source_uri.as_object().expect("request object")
        ));

        let mut summary_filename = approved_update_arguments();
        summary_filename["patch"]["change_summary"] = json!("Imported from raw.pdf");
        assert!(!approved_request_is_valid(
            "diagram.update",
            summary_filename.as_object().expect("request object")
        ));

        for value in [
            "..\\..\\private\\matter",
            "\\private\\matter",
            "C:private\\matter",
            "C:private",
            "/private/matter",
            "private/matter",
            "/nodes/0",
        ] {
            let mut upsert = approved_update_arguments();
            let mut node = upsert["base_spec"]["nodes"][0].clone();
            node["metadata"]["scope"] = json!(value);
            upsert["patch"]["upsert_nodes"] = json!([node]);
            assert!(
                !approved_request_is_valid(
                    "diagram.update",
                    upsert.as_object().expect("request object")
                ),
                "patch upsert must reject location value {value:?}"
            );

            let mut free_text = approved_update_arguments();
            free_text["patch"]["change_summary"] = json!(value);
            assert!(
                !approved_request_is_valid(
                    "diagram.update",
                    free_text.as_object().expect("request object")
                ),
                "patch free text must reject location value {value:?}"
            );
        }

        let mut float_metadata = approved_update_arguments();
        let mut node = float_metadata["base_spec"]["nodes"][0].clone();
        node["metadata"]["sequence"] = json!(0.5);
        float_metadata["patch"]["upsert_nodes"] = json!([node]);
        assert!(
            !approved_request_is_valid(
                "diagram.update",
                float_metadata.as_object().expect("request object")
            ),
            "diagram.update must reject floats before ticket canonicalization"
        );
    }
}
