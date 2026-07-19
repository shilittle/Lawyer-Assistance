use clap::ValueEnum;
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{str::FromStr, sync::Arc};

const PUBLIC_OUTPUT_INSTRUCTION: &str = "content 与 structuredContent 只提供经本地边界检查的公开法律资料。不得将案件材料、当事人信息或未经脱敏的文书输入或转发给外部宿主。";

pub const TOOL_NAMES: [&str; 5] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
];
pub const REDACTED_CASE_TOOL_NAMES: [&str; 6] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
    "citation_validate",
];

pub const DISABLED_SENSITIVE_TOOL_NAMES: [&str; 7] = [
    "citation_validate",
    "case_get_state",
    "case_propose_patch",
    "case_apply_patch",
    "case_analyze_gaps",
    "document_generate",
    "document_export",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyProfile {
    /// Only offline public-law tools are visible and callable.
    #[default]
    #[value(name = "public_law_only", alias = "public-law-only")]
    PublicLawOnly,
    /// Public-law tools plus exact-receipt-gated citation validation.
    #[value(name = "redacted_case", alias = "redacted-case")]
    RedactedCase,
}

impl PrivacyProfile {
    pub(crate) fn allows_tool(self, name: &str) -> bool {
        match self {
            Self::PublicLawOnly => TOOL_NAMES.contains(&name),
            Self::RedactedCase => REDACTED_CASE_TOOL_NAMES.contains(&name),
        }
    }
}

impl FromStr for PrivacyProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public_law_only" | "public-law-only" => Ok(Self::PublicLawOnly),
            "redacted_case" | "redacted-case" => Ok(Self::RedactedCase),
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
        let tools = build_tools(profile)
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

fn build_tools(profile: PrivacyProfile) -> Vec<Tool> {
    vec![
        make_tool(
            "system_status",
            "System status",
            "Inspect local legal and user database readiness without exposing configured paths.",
            json!({
                "type": "object",
                "properties": { "schema_version": schema_version() },
                "required": ["schema_version"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {
                    "schema_version": schema_version(),
                    "status": {"type":"string", "enum":["ready","degraded"]},
                    "legal_database": database_status_schema(),
                    "user_database": database_status_schema(),
                    "file_policy": {
                        "type":"object",
                        "properties": {
                            "allowed_file_root_count":{"type":"integer","minimum":0,"maximum":64},
                            "output_root_available":{"type":"boolean"}
                        },
                        "required":["allowed_file_root_count","output_root_available"],
                        "additionalProperties":false
                    }
                },
                "required":["schema_version","status","legal_database","user_database","file_policy"],
                "additionalProperties":false
            }),
            Hints::read_only(),
        ),
        make_tool(
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
            standard_legal_data(json!({
                "laws":{"type":"array"},
                "articles":{"type":"array"}
            }), &["laws", "articles"]),
            Hints::read_only(),
        ),
        make_tool(
            "legal_get_article",
            "Get legal article",
            "Read one exact article and its version/source metadata from the offline legal corpus.",
            id_input("article_id"),
            standard_legal_data(json!({"article":{"type":"object"}}), &["article"]),
            Hints::read_only(),
        ),
        make_tool(
            "legal_get_versions",
            "Get law versions",
            "List known versions of a law document from the offline legal corpus.",
            id_input("document_id"),
            standard_legal_data(json!({"versions":{"type":"array"}}), &["versions"]),
            Hints::read_only(),
        ),
        make_tool(
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
            standard_legal_data(json!({"relations":{"type":"array"}}), &["relations"]),
            Hints::read_only(),
        ),
        make_tool(
            "citation_validate",
            "Validate citations",
            "Validate source markers and temporal applicability against the configured offline legal corpus. This does not claim semantic support verification.",
            citation_validate_input(profile),
            standard_legal_data(json!({"report":{"type":"object"}}), &["report"]),
            Hints::read_only(),
        ),
        make_tool(
            "case_get_state",
            "Read case state",
            "Read one bounded page of confirmed case state. Use the returned opaque cursor for the next page.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "project_id":identifier(),
                    "cursor":{"type":["string","null"],"minLength":16,"maxLength":2048},
                    "limit":{"type":["integer","null"],"minimum":1,"maximum":100}
                },
                "required":["schema_version","project_id"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "revision":{"type":"string"},
                    "page":{"type":"integer"},
                    "page_size":{"type":"integer"},
                    "has_more":{"type":"boolean"},
                    "counts":{"type":"object"},
                    "workspace":{"type":"object"}
                },
                "required":["schema_version","revision","page","page_size","has_more","counts","workspace"],
                "additionalProperties":false
            }),
            Hints::read_only(),
        ),
        make_tool(
            "case_propose_patch",
            "Propose case patch",
            "Validate and canonicalize a bounded additive case change without writing the user database. A missing project may be reviewed with project_bootstrap plus the documented all-zero base revision; allowed-root material paths are sealed without absolute paths (opaque root identity plus root-relative locator) and are imported only by confirmed case_apply_patch.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "project_id":identifier(),
                    "base_revision":sha256(),
                    "changes":case_change_schema(),
                    "project_bootstrap":{
                        "type":["object","null"],
                        "properties":{
                            "title":{"type":"string","minLength":1,"maxLength":256},
                            "case_type":{"type":"string","minLength":1,"maxLength":64},
                            "opened_on":nullable_date(),
                            "summary":{"type":"string","maxLength":16384}
                        },
                        "required":["title","case_type","summary"],
                        "additionalProperties":false
                    },
                    "material_imports":{
                        "type":"array",
                        "maxItems":2,
                        "items":{
                            "type":"object",
                            "properties":{
                                "material_id":identifier(),
                                "path":{"type":"string","minLength":1,"maxLength":4096},
                                "title":{"type":"string","minLength":1,"maxLength":256}
                            },
                            "required":["material_id","path","title"],
                            "additionalProperties":false
                        }
                    }
                },
                "required":["schema_version","project_id","base_revision","changes"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "proposal_id":identifier(),
                    "canonical_proposal":{"type":"string"},
                    "proposal_hash":sha256(),
                    "base_revision":sha256(),
                    "confidence":{"type":"number","minimum":0,"maximum":1},
                    "uncertainties":{"type":"array","items":{"type":"string"}}
                },
                "required":["schema_version","proposal_id","canonical_proposal","proposal_hash","base_revision","confidence","uncertainties"],
                "additionalProperties":false
            }),
            Hints::read_only(),
        ),
        make_tool(
            "case_apply_patch",
            "Apply confirmed case patch",
            "Apply only a previously canonicalized proposal after explicit confirmation, proposal-hash verification, and optimistic revision checking.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "project_id":identifier(),
                    "canonical_proposal":{"type":"string","minLength":2,"maxLength":589824},
                    "proposal_hash":sha256(),
                    "expected_revision":sha256(),
                    "confirmed":{"const":true},
                    "idempotency_key":idempotency_key()
                },
                "required":["schema_version","project_id","canonical_proposal","proposal_hash","expected_revision","confirmed","idempotency_key"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "audit_id":identifier(),
                    "proposal_hash":sha256(),
                    "previous_revision":sha256(),
                    "revision":sha256(),
                    "applied":{"type":"boolean"},
                    "replayed":{"type":"boolean"}
                },
                "required":["schema_version","audit_id","proposal_hash","previous_revision","revision","applied","replayed"],
                "additionalProperties":false
            }),
            Hints::mutating(false),
        ),
        make_tool(
            "case_analyze_gaps",
            "Analyze case gaps",
            "Run deterministic local completeness checks over confirmed case state.",
            id_input("project_id"),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "revision":sha256(),
                    "gaps":{"type":"array"}
                },
                "required":["schema_version","revision","gaps"],
                "additionalProperties":false
            }),
            Hints::read_only(),
        ),
        make_tool(
            "document_generate",
            "Generate document",
            "Deterministically render a bounded document from confirmed case state without exporting a file.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "project_id":identifier(),
                    "template_id":document_template_id(),
                    "model_draft":{"type":["string","null"],"maxLength":65536}
                },
                "required":["schema_version","project_id","template_id"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "project_id":identifier(),
                    "case_revision":sha256(),
                    "generation_hash":sha256(),
                    "document":generated_document_schema(),
                    "warnings":{"type":"array","items":{"type":"string"}}
                },
                "required":["schema_version","project_id","case_revision","generation_hash","document","warnings"],
                "additionalProperties":false
            }),
            Hints::read_only(),
        ),
        make_tool(
            "document_export",
            "Export document",
            "Export a verified deterministic document beneath the configured output root using an atomic write and an audit record.",
            json!({
                "type":"object",
                "properties":{
                    "schema_version":schema_version(),
                    "project_id":identifier(),
                    "template_id":document_template_id(),
                    "model_draft":{"type":["string","null"],"maxLength":65536},
                    "expected_revision":sha256(),
                    "generation_hash":sha256(),
                    "relative_path":{"type":"string","minLength":1,"maxLength":4096},
                    "format":{"type":"string","enum":["docx","markdown"]},
                    "overwrite":{"type":"boolean"},
                    "confirmed":{"const":true},
                    "idempotency_key":idempotency_key()
                },
                "required":["schema_version","project_id","template_id","expected_revision","generation_hash","relative_path","format","overwrite","confirmed","idempotency_key"],
                "additionalProperties":false
            }),
            json!({
                "type":"object",
                "properties":{
                    "schema_version":{"type":"integer"},
                    "audit_id":identifier(),
                    "record_id":identifier(),
                    "project_id":identifier(),
                    "case_revision":sha256(),
                    "generation_hash":sha256(),
                    "export_path":{"type":"string","description":"Path relative to the configured output root"},
                    "format":{"type":"string","enum":["docx","markdown"]},
                    "media_type":{"type":"string"},
                    "byte_len":{"type":"integer","minimum":0,"maximum":4194304},
                    "sha256":sha256(),
                    "replayed":{"type":"boolean"}
                },
                "required":["schema_version","audit_id","record_id","project_id","case_revision","generation_hash","export_path","format","media_type","byte_len","sha256","replayed"],
                "additionalProperties":false
            }),
            Hints::mutating(true),
        ),
    ]
}

#[derive(Clone, Copy)]
struct Hints {
    read_only: bool,
    destructive: bool,
    idempotent: bool,
}

impl Hints {
    const fn read_only() -> Self {
        Self {
            read_only: true,
            destructive: false,
            idempotent: true,
        }
    }

    const fn mutating(destructive: bool) -> Self {
        Self {
            read_only: false,
            destructive,
            idempotent: true,
        }
    }
}

fn make_tool(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input: Value,
    _data_schema: Value,
    hints: Hints,
) -> Tool {
    let description = format!("{description} {PUBLIC_OUTPUT_INSTRUCTION}");
    Tool::new(name, description, json_object(input))
        .with_title(title)
        .with_raw_output_schema(json_object(public_result_schema()))
        .with_annotations(
            ToolAnnotations::with_title(title)
                .read_only(hints.read_only)
                .destructive(hints.destructive)
                .idempotent(hints.idempotent)
                .open_world(false),
        )
}

fn citation_validate_input(profile: PrivacyProfile) -> Value {
    match profile {
        PrivacyProfile::PublicLawOnly => json!({
            "type":"object",
            "properties":{
                "schema_version":schema_version(),
                "answer":{"type":"string","minLength":1,"maxLength":262144},
                "allowed_source_ids":{"type":"array","maxItems":128,"uniqueItems":true,"items":identifier()},
                "case_date":nullable_date(),
                "include_expired":{"type":"boolean"}
            },
            "required":["schema_version","answer","allowed_source_ids","include_expired"],
            "additionalProperties":false
        }),
        PrivacyProfile::RedactedCase => json!({
            "type":"object",
            "properties":{
                "approved_payload_json":{
                    "type":"string",
                    "minLength":1,
                    "maxLength":524288,
                    "description":"Exact UTF-8 JSON bytes of one App-approved CitationValidateRequest. Current page-material receipts are not valid for this tool."
                },
                "redaction_receipt":{
                    "type":"string",
                    "minLength":72,
                    "maxLength":16384,
                    "pattern":"^rct_v1\\.[A-Za-z0-9_-]+\\.[A-Fa-f0-9]{64}$"
                }
            },
            "required":["approved_payload_json","redaction_receipt"],
            "additionalProperties":false
        }),
    }
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

fn standard_legal_data(extra_properties: Value, extra_required: &[&str]) -> Value {
    let mut properties = extra_properties.as_object().cloned().unwrap_or_default();
    properties.insert("schema_version".into(), json!({"type":"integer"}));
    properties.insert("database_version".into(), json!({"type":"string"}));
    properties.insert(
        "warnings".into(),
        json!({"type":"array","items":{"type":"string"}}),
    );
    let mut required = vec![
        json!("schema_version"),
        json!("database_version"),
        json!("warnings"),
    ];
    required.extend(extra_required.iter().map(|name| json!(name)));
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn database_status_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "available":{"type":"boolean"},
            "schema_version":{"type":["string","null"]},
            "runtime_schema_version":{"type":["string","null"]},
            "dataset_name":{"type":["string","null"]},
            "dataset_version":{"type":["string","null"]},
            "distribution_profile":{"type":["string","null"]},
            "error":{
                "type":["object","null"],
                "properties":{
                    "schema_version":schema_version(),
                    "code":{"type":"string"},
                    "message":{"type":"string"},
                    "retryable":{"type":"boolean"},
                    "details":{"type":"object"}
                },
                "required":["schema_version","code","message","retryable","details"],
                "additionalProperties":false
            }
        },
        "required":[
            "available",
            "schema_version",
            "runtime_schema_version",
            "dataset_name",
            "dataset_version",
            "distribution_profile",
            "error"
        ],
        "additionalProperties":false
    })
}

fn id_input(field: &str) -> Value {
    json!({
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            (field):identifier()
        },
        "required":["schema_version",field],
        "additionalProperties":false
    })
}

fn case_change_schema() -> Value {
    let source_refs =
        json!({"type":"array","maxItems":128,"uniqueItems":true,"items":identifier()});
    json!({
        "type":"object",
        "properties":{
            "schema_version":schema_version(),
            "facts":{
                "type":"array","maxItems":64,"items":{
                    "type":"object",
                    "properties":{
                        "id":identifier(),
                        "statement":{"type":"string","minLength":1,"maxLength":8192},
                        "occurred_on":nullable_date(),
                        "source_refs":source_refs
                    },
                    "required":["id","statement","source_refs"],
                    "additionalProperties":false
                }
            },
            "evidence":{
                "type":"array","maxItems":64,"items":{
                    "type":"object",
                    "properties":{
                        "id":identifier(),
                        "title":{"type":"string","minLength":1,"maxLength":256},
                        "summary":{"type":"string","minLength":1,"maxLength":8192},
                        "proves_fact_ids":{"type":"array","maxItems":32,"uniqueItems":true,"items":identifier()},
                        "source_refs":source_refs
                    },
                    "required":["id","title","summary","proves_fact_ids","source_refs"],
                    "additionalProperties":false
                }
            },
            "issues":{
                "type":"array","maxItems":32,"items":{
                    "type":"object",
                    "properties":{
                        "id":identifier(),
                        "title":{"type":"string","minLength":1,"maxLength":256},
                        "analysis":{"type":"string","minLength":1,"maxLength":8192},
                        "related_fact_ids":{"type":"array","maxItems":32,"uniqueItems":true,"items":identifier()},
                        "source_refs":source_refs
                    },
                    "required":["id","title","analysis","related_fact_ids","source_refs"],
                    "additionalProperties":false
                }
            },
            "legal_basis":{
                "type":"array","maxItems":64,"items":{
                    "type":"object",
                    "properties":{
                        "id":identifier(),
                        "issue_ids":{"type":"array","maxItems":32,"uniqueItems":true,"items":identifier()},
                        "source_ref":identifier(),
                        "marker":{"type":"string","minLength":1,"maxLength":256},
                        "citation":{"type":"string","minLength":1,"maxLength":2048},
                        "proposition":{"type":"string","minLength":1,"maxLength":4096}
                    },
                    "required":["id","issue_ids","source_ref","marker","citation","proposition"],
                    "additionalProperties":false
                }
            },
            "attachment_transfers":{
                "type":"array","maxItems":2,"items":{
                    "type":"object",
                    "properties":{"attachment_id":identifier(),"title":{"type":"string","minLength":1,"maxLength":256}},
                    "required":["attachment_id","title"],
                    "additionalProperties":false
                }
            },
            "artifact_transfers":{
                "type":"array","maxItems":16,"items":{
                    "type":"object",
                    "properties":{"artifact_id":identifier(),"title":{"type":"string","minLength":1,"maxLength":256}},
                    "required":["artifact_id","title"],
                    "additionalProperties":false
                }
            }
        },
        "required":["schema_version","facts","evidence","issues","legal_basis","attachment_transfers","artifact_transfers"],
        "additionalProperties":false
    })
}

fn document_template_id() -> Value {
    json!({
        "type":"string",
        "enum":[
            "complaint",
            "defence",
            "evidence_schedule",
            "fact_timeline",
            "legal_research_report",
            "lawyer_letter"
        ]
    })
}

fn generated_document_schema() -> Value {
    let source_ids = json!({"type":"array","items":{"type":"string"}});
    json!({
        "type":"object",
        "properties":{
            "template":{
                "type":"object",
                "properties":{
                    "template_id":document_template_id(),
                    "name":{"type":"string"},
                    "scenario":{"type":"string"},
                    "required_fields":{"type":"array","items":{"type":"string"}},
                    "optional_fields":{"type":"array","items":{"type":"string"}},
                    "citation_policy":{"type":"string"},
                    "version":{"type":"string"}
                },
                "required":["template_id","name","scenario","required_fields","optional_fields","citation_policy","version"],
                "additionalProperties":false
            },
            "title":{"type":"string"},
            "fields":{
                "type":"array","items":{
                    "type":"object",
                    "properties":{
                        "key":{"type":"string"},
                        "value":{"type":"string"},
                        "source_kind":{"type":"string"},
                        "source_id":{"type":"string"}
                    },
                    "required":["key","value","source_kind","source_id"],
                    "additionalProperties":false
                }
            },
            "sections":{
                "type":"array","items":{
                    "type":"object",
                    "properties":{
                        "heading":{"type":"string"},
                        "level":{"type":"integer","minimum":1},
                        "paragraphs":{"type":"array","items":{"type":"string"}},
                        "source_ids":source_ids
                    },
                    "required":["heading","level","paragraphs","source_ids"],
                    "additionalProperties":false
                }
            },
            "tables":{
                "type":"array","items":{
                    "type":"object",
                    "properties":{
                        "section_heading":{"type":"string"},
                        "headers":{"type":"array","items":{"type":"string"}},
                        "column_widths_dxa":{"type":"array","items":{"type":"integer","minimum":0}},
                        "rows":{
                            "type":"array","items":{
                                "type":"object",
                                "properties":{
                                    "cells":{"type":"array","items":{"type":"string"}},
                                    "source_ids":source_ids
                                },
                                "required":["cells","source_ids"],
                                "additionalProperties":false
                            }
                        },
                        "source_ids":source_ids
                    },
                    "required":["section_heading","headers","column_widths_dxa","rows","source_ids"],
                    "additionalProperties":false
                }
            },
            "citations":{
                "type":"array","items":{
                    "type":"object",
                    "properties":{
                        "kind":{"type":"string","enum":["law","judicialCase"]},
                        "title":{"type":"string"},
                        "locator":{"type":"string"},
                        "effective_or_decided_on":{"type":"string"},
                        "source_id":{"type":"string"},
                        "canonical_label":{"type":"string"},
                        "excerpt":{"type":"string"},
                        "document_id":{"type":"string"},
                        "version_id":{"type":"string"},
                        "article_id":{"type":"string"}
                    },
                    "required":["kind","title","locator","effective_or_decided_on","source_id","canonical_label","excerpt","document_id","version_id","article_id"],
                    "additionalProperties":false
                }
            },
            "markdown":{"type":"string"}
        },
        "required":["template","title","fields","sections","tables","citations","markdown"],
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

fn sha256() -> Value {
    json!({"type":"string","pattern":"^[a-f0-9]{64}$"})
}

fn idempotency_key() -> Value {
    json!({
        "type":"string",
        "minLength":16,
        "maxLength":128,
        "pattern":"^[A-Za-z0-9_.:-]+$",
        "description":"Opaque operation key. A retry, including after an HTTP timeout with unknown outcome, must reuse the exact same idempotency_key and arguments."
    })
}

fn nullable_date() -> Value {
    json!({"type":["string","null"],"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"})
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
    fn redacted_case_exposes_only_receipt_gated_citation_validation() {
        let registry = ToolRegistry::for_profile(PrivacyProfile::RedactedCase);
        assert_eq!(registry.profile(), PrivacyProfile::RedactedCase);
        assert_eq!(
            registry
                .list()
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            REDACTED_CASE_TOOL_NAMES
        );

        let citation = registry
            .get("citation_validate")
            .expect("receipt-gated citation tool");
        let properties = citation.input_schema["properties"]
            .as_object()
            .expect("citation wrapper properties");
        assert_eq!(
            properties.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approved_payload_json", "redaction_receipt"]
        );
        assert_eq!(
            citation.input_schema["required"],
            json!(["approved_payload_json", "redaction_receipt"])
        );
        assert_eq!(citation.input_schema["additionalProperties"], false);
        for forbidden in [
            "answer",
            "allowed_source_ids",
            "case_date",
            "include_expired",
            "path",
            "raw",
        ] {
            assert!(
                !properties.contains_key(forbidden),
                "business input must be inside exact approved bytes: {forbidden}"
            );
        }
        let annotations = citation.annotations.expect("citation annotations");
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));

        for name in &DISABLED_SENSITIVE_TOOL_NAMES[1..] {
            assert!(registry.get(name).is_none(), "{name}");
            assert!(!registry.profile().allows_tool(name), "{name}");
        }
        assert_eq!(
            "redacted_case".parse::<PrivacyProfile>(),
            Ok(PrivacyProfile::RedactedCase)
        );
    }

    #[test]
    fn registry_is_fixed_and_strict() {
        let registry = ToolRegistry::new();
        let tools = registry.list();
        assert_eq!(tools.len(), TOOL_NAMES.len());
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            TOOL_NAMES
        );
        for tool in tools {
            assert_eq!(
                tool.input_schema.get("additionalProperties"),
                Some(&json!(false))
            );
            assert!(tool.output_schema.is_some());
            assert_eq!(
                tool.annotations.as_ref().and_then(|a| a.open_world_hint),
                Some(false)
            );
            let output = tool.output_schema.as_ref().expect("output schema");
            assert_eq!(output.get("type"), Some(&json!("object")));
            assert!(output.get("oneOf").is_none());
            assert_eq!(output["required"], json!(["结果", "说明", "内容", "提示"]));
            assert_eq!(output["additionalProperties"], false);
            let serialized = serde_json::to_string(output).expect("output schema serializes");
            for forbidden in [
                "schema_version",
                "request_id",
                "protocol_version",
                "server_version",
                "revision",
                "hash",
                "snippet",
                "path",
                "endpoint",
                "raw",
            ] {
                assert!(!serialized.contains(forbidden), "{tool:?}: {forbidden}");
            }
        }
    }

    #[test]
    fn public_profile_exposes_only_read_only_tools() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.profile(), PrivacyProfile::PublicLawOnly);
        for name in TOOL_NAMES {
            let annotations = registry
                .get(name)
                .and_then(|tool| tool.annotations)
                .expect("read annotation");
            assert_eq!(annotations.read_only_hint, Some(true), "{name}");
            assert_eq!(annotations.destructive_hint, Some(false), "{name}");
            assert_eq!(annotations.idempotent_hint, Some(true), "{name}");
        }
    }

    #[test]
    fn legal_search_uses_the_canonical_case_date_field() {
        let registry = ToolRegistry::new();
        let search = registry.get("legal_search").expect("legal search tool");
        let properties = search.input_schema["properties"]
            .as_object()
            .expect("legal search properties");

        assert!(properties.contains_key("case_date"));
        assert!(!properties.contains_key("as_of"));
    }

    #[test]
    fn sensitive_and_case_tools_are_absent_from_the_public_profile() {
        let registry = ToolRegistry::new();
        for name in DISABLED_SENSITIVE_TOOL_NAMES {
            assert!(registry.get(name).is_none(), "{name}");
            assert!(!registry.profile().allows_tool(name), "{name}");
        }
        assert!("public_law_only".parse::<PrivacyProfile>().is_ok());
        assert!("full".parse::<PrivacyProfile>().is_err());
    }

    #[test]
    fn every_tool_declares_both_result_channels_as_public_only() {
        let registry = ToolRegistry::new();
        for name in TOOL_NAMES {
            let tool = registry.get(name).expect("registered tool");
            let description = tool.description.as_ref().expect("tool description");
            assert!(description.contains("不得将案件材料"), "{name}");
            assert!(description.contains("content"), "{name}");
            assert!(description.contains("structuredContent"), "{name}");
            assert!(description.contains("未经脱敏"), "{name}");
        }
    }
}
