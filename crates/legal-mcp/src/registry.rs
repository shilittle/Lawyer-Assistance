use clap::ValueEnum;
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{str::FromStr, sync::Arc};

const PUBLIC_OUTPUT_INSTRUCTION: &str = "content 与 structuredContent 只提供经本地边界检查的公开法律资料。不得将案件材料、当事人信息或未经脱敏的文书输入或转发给外部宿主。";
const PRIVACY_OUTPUT_INSTRUCTION: &str = "仅返回后台已发布的脱敏任务状态或脱敏文本。不得返回原文、映射、原始文件名、磁盘路径或后台诊断。";

/// The public-law contract is frozen for existing integrations.
pub const TOOL_NAMES: [&str; 7] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
    "legal_search_cases",
    "legal_get_case",
];

pub const PRIVACY_WORKSPACE_TOOL_NAMES: [&str; 10] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
    "legal_search_cases",
    "legal_get_case",
    "privacy_workspace.submit",
    "privacy_workspace.status",
    "privacy_workspace.read_result",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyProfile {
    #[default]
    #[value(name = "public_law_only", alias = "public-law-only")]
    PublicLawOnly,
    #[value(name = "privacy_workspace", alias = "privacy-workspace")]
    PrivacyWorkspace,
    /// Kept only so old configurations receive the explicit profile_disabled
    /// startup failure instead of silently acquiring a different capability.
    #[value(name = "redacted_case", alias = "redacted-case")]
    RedactedCase,
    #[value(name = "approved_case_workspace", alias = "approved-case-workspace")]
    ApprovedCaseWorkspace,
    #[value(name = "diagram_authoring", alias = "diagram-authoring")]
    DiagramAuthoring,
}

impl PrivacyProfile {
    pub const fn is_disabled(self) -> bool {
        matches!(
            self,
            Self::RedactedCase | Self::ApprovedCaseWorkspace | Self::DiagramAuthoring
        )
    }

    pub(crate) fn allows_tool(self, name: &str) -> bool {
        match self {
            Self::PublicLawOnly => TOOL_NAMES.contains(&name),
            Self::PrivacyWorkspace => PRIVACY_WORKSPACE_TOOL_NAMES.contains(&name),
            Self::RedactedCase | Self::ApprovedCaseWorkspace | Self::DiagramAuthoring => false,
        }
    }
}

impl FromStr for PrivacyProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public_law_only" | "public-law-only" => Ok(Self::PublicLawOnly),
            "privacy_workspace" | "privacy-workspace" => Ok(Self::PrivacyWorkspace),
            "redacted_case" | "redacted-case" => Ok(Self::RedactedCase),
            "approved_case_workspace" | "approved-case-workspace" => {
                Ok(Self::ApprovedCaseWorkspace)
            }
            "diagram_authoring" | "diagram-authoring" => Ok(Self::DiagramAuthoring),
            _ => Err("unsupported privacy profile"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolRegistry {
    profile: PrivacyProfile,
    tools: Arc<Vec<Tool>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::for_profile(PrivacyProfile::default())
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_profile(profile: PrivacyProfile) -> Self {
        let mut tools = public_tools();
        if profile == PrivacyProfile::PrivacyWorkspace {
            tools.extend(privacy_workspace_tools());
        }
        let tools = tools
            .into_iter()
            .filter(|tool| profile.allows_tool(tool.name.as_ref()))
            .collect();
        Self {
            profile,
            tools: Arc::new(tools),
        }
    }

    pub fn profile(&self) -> PrivacyProfile {
        self.profile
    }

    pub fn list(&self) -> Vec<Tool> {
        self.tools.as_ref().clone()
    }

    pub fn get(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|tool| tool.name == name).cloned()
    }

    pub fn schema_snapshot(&self) -> Value {
        serde_json::to_value(self.tools.as_ref()).unwrap_or_else(|_| Value::Array(Vec::new()))
    }
}

fn public_tools() -> Vec<Tool> {
    vec![
        public_tool(
            "system_status",
            "System status",
            "Inspect local legal database readiness without exposing configured paths.",
            json!({
                "type": "object",
                "properties": { "schema_version": schema_version() },
                "required": ["schema_version"],
                "additionalProperties": false
            }),
        ),
        public_tool(
            "legal_search",
            "Search local law",
            "Search the configured offline legal corpus. Results are source-addressable and do not use a model or the public internet.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version": schema_version(),
                    "query":{"type":"string","minLength":1,"maxLength":16384},
                    "document_id":nullable_identifier(),
                    "case_date":nullable_date(),
                    "limit":{"type":["integer","null"],"minimum":1,"maximum":50}
                },
                "required":["schema_version","query"],
                "additionalProperties":false
            }),
        ),
        public_tool(
            "legal_get_article",
            "Get legal article",
            "Read one exact article and its version/source metadata from the offline legal corpus.",
            id_input("article_id"),
        ),
        public_tool(
            "legal_get_versions",
            "Get law versions",
            "List known versions of a law document from the offline legal corpus.",
            id_input("document_id"),
        ),
        public_tool(
            "legal_get_relations",
            "Get law relations",
            "List deterministic incoming, outgoing, or bidirectional relations for a law document.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "document_id":identifier(),
                    "direction":{"type":["string","null"],"enum":["both","outgoing","incoming",null]}
                },
                "required":["schema_version","document_id"],
                "additionalProperties":false
            }),
        ),
        public_tool(
            "legal_search_cases",
            "Search Supreme People's Court cases",
            "Search the optional local Supreme People's Court case corpus. Query may contain AI-understood legal issues or Chinese keywords; results remain offline and source-addressable.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer","const":1},
                    "query":{"type":"string","minLength":1,"maxLength":16384},
                    "case_type":{"type":["string","null"],"enum":["guiding","reference","typical",null]},
                    "limit":{"type":["integer","null"],"minimum":1,"maximum":50},
                    "offset":{"type":["integer","null"],"minimum":0,"maximum":10000},
                    "include_withdrawn":{"type":["boolean","null"]}
                },
                "required":["schema_version","query"],
                "additionalProperties":false
            }),
        ),
        public_tool(
            "legal_get_case",
            "Get Supreme People's Court case",
            "Read one source-traceable case, including its official public full text, from the optional local Supreme People's Court case corpus.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer","const":1},
                    "case_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"}
                },
                "required":["schema_version","case_id"],
                "additionalProperties":false
            }),
        ),
    ]
}

fn privacy_workspace_tools() -> Vec<Tool> {
    vec![
        privacy_tool(
            "privacy_workspace.submit",
            "Submit privacy workspace files",
            "Submit configured inbox-relative TXT/DOCX paths for local redaction. The request is idempotent by request_id.",
            json!({
                "type":"object",
                "properties":{
                    "request_id":{"type":"string","minLength":16,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"},
                    "inbox_relative_paths":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","minLength":1,"maxLength":4096}}
                },
                "required":["request_id","inbox_relative_paths"],
                "additionalProperties":false
            }),
            false,
        ),
        privacy_tool(
            "privacy_workspace.status",
            "Get privacy workspace task status",
            "Read task status, safe reason codes, and published result identifiers. It never reads source material.",
            json!({
                "type":"object",
                "properties":{"task_id":identifier()},
                "required":["task_id"],
                "additionalProperties":false
            }),
            true,
        ),
        privacy_tool(
            "privacy_workspace.read_result",
            "Read published redacted result",
            "Read a page of a current, published redacted text result. Original material and mappings are unavailable.",
            json!({
                "type":"object",
                "properties":{
                    "result_id":identifier(),
                    "cursor":{"type":["string","null"],"minLength":1,"maxLength":2048}
                },
                "required":["result_id"],
                "additionalProperties":false
            }),
            true,
        ),
    ]
}

fn public_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
) -> Tool {
    Tool::new(
        name,
        format!("{description} {PUBLIC_OUTPUT_INSTRUCTION}"),
        json_object(input),
    )
    .with_title(title)
    .with_raw_output_schema(json_object(public_result_schema()))
    .with_annotations(
        ToolAnnotations::with_title(title)
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn privacy_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
    read_only: bool,
) -> Tool {
    Tool::new(
        name,
        format!("{description} {PRIVACY_OUTPUT_INSTRUCTION}"),
        json_object(input),
    )
    .with_title(title)
    .with_raw_output_schema(json_object(json!({"type":"object"})))
    .with_annotations(
        ToolAnnotations::with_title(title)
            .read_only(read_only)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn public_result_schema() -> Value {
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object",
        "properties":{
            "结果":{"type":"string","enum":["已完成","未完成"]},
            "说明":{"type":"string","minLength":1,"maxLength":262144},
            "内容":{"type":["object","array","null"]},
            "提示":{"type":"array","maxItems":64,"items":{"type":"string","maxLength":1024}}
        },
        "required":["结果","说明","内容","提示"],
        "additionalProperties":false
    })
}

fn schema_version() -> Value {
    json!({"type":"integer","const":1})
}

fn identifier() -> Value {
    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"})
}

fn nullable_identifier() -> Value {
    json!({"type":["string","null"],"minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"})
}

fn nullable_date() -> Value {
    json!({"type":["string","null"],"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"})
}

fn id_input(field: &'static str) -> Value {
    let mut properties = Map::new();
    properties.insert("schema_version".to_owned(), schema_version());
    properties.insert(field.to_owned(), identifier());
    json!({
        "type":"object",
        "properties":properties,
        "required":["schema_version",field],
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

    #[test]
    fn public_contract_has_the_five_frozen_law_tools_and_two_case_tools() {
        let registry = ToolRegistry::for_profile(PrivacyProfile::PublicLawOnly);
        assert_eq!(
            registry
                .list()
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            TOOL_NAMES
        );
        let search = registry.get("legal_search").expect("legal search tool");
        assert_eq!(
            search.input_schema["required"],
            json!(["schema_version", "query"])
        );
        assert!(search.input_schema["properties"].get("case_date").is_some());
    }

    #[test]
    fn public_input_schemas_remain_frozen_for_existing_clients() {
        let schemas = ToolRegistry::for_profile(PrivacyProfile::PublicLawOnly)
            .list()
            .into_iter()
            .map(|tool| {
                (
                    tool.name.to_string(),
                    Value::Object((*tool.input_schema).clone()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            schemas,
            std::collections::BTreeMap::from([
                (
                    "system_status".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1}},"required":["schema_version"],"additionalProperties":false}),
                ),
                (
                    "legal_search".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"query":{"type":"string","minLength":1,"maxLength":16384},"document_id":{"type":["string","null"],"minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"},"case_date":{"type":["string","null"],"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},"limit":{"type":["integer","null"],"minimum":1,"maximum":50}},"required":["schema_version","query"],"additionalProperties":false}),
                ),
                (
                    "legal_get_article".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"article_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"}},"required":["schema_version","article_id"],"additionalProperties":false}),
                ),
                (
                    "legal_get_versions".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"document_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"}},"required":["schema_version","document_id"],"additionalProperties":false}),
                ),
                (
                    "legal_get_relations".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"document_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"},"direction":{"type":["string","null"],"enum":["both","outgoing","incoming",null]}},"required":["schema_version","document_id"],"additionalProperties":false}),
                ),
                (
                    "legal_search_cases".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"query":{"type":"string","minLength":1,"maxLength":16384},"case_type":{"type":["string","null"],"enum":["guiding","reference","typical",null]},"limit":{"type":["integer","null"],"minimum":1,"maximum":50},"offset":{"type":["integer","null"],"minimum":0,"maximum":10000},"include_withdrawn":{"type":["boolean","null"]}},"required":["schema_version","query"],"additionalProperties":false}),
                ),
                (
                    "legal_get_case".to_owned(),
                    json!({"type":"object","properties":{"schema_version":{"type":"integer","const":1},"case_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"}},"required":["schema_version","case_id"],"additionalProperties":false}),
                ),
            ])
        );
    }

    #[test]
    fn privacy_workspace_is_exactly_ten_tools_and_legacy_has_none() {
        let registry = ToolRegistry::for_profile(PrivacyProfile::PrivacyWorkspace);
        assert_eq!(
            registry
                .list()
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            PRIVACY_WORKSPACE_TOOL_NAMES
        );
        for profile in [
            PrivacyProfile::RedactedCase,
            PrivacyProfile::ApprovedCaseWorkspace,
            PrivacyProfile::DiagramAuthoring,
        ] {
            assert!(profile.is_disabled());
            assert!(ToolRegistry::for_profile(profile).list().is_empty());
        }
    }
}
