#[cfg(test)]
use serde_json::Map;
use serde_json::Value;

const MAX_PUBLIC_CONTENT_BYTES: usize = 256 * 1024;
const MAX_PUBLIC_LIST_ITEMS: usize = 10;

/// Render the text a person reads. The structured MCP value is intentionally
/// richer and is reserved for machine-to-machine workflow coordination.
pub(crate) fn success_text(tool_name: &str, data: &Value) -> String {
    let text = match tool_name {
        "system_status" => system_status(data),
        "legal_search" => legal_search(data),
        "legal_get_article" => legal_article(data),
        "legal_get_versions" => legal_versions(data),
        "legal_get_relations" => legal_relations(data),
        "citation_validate" => citation_validation(data),
        "case_get_state" => case_state(data),
        "case_propose_patch" => case_proposal(data),
        "case_apply_patch" => case_apply(data),
        "case_analyze_gaps" => case_gaps(data),
        "document_generate" => generated_document(data),
        "document_export" => document_export(data),
        _ => "操作已完成。请在应用中查看结果。".to_owned(),
    };
    bounded(text)
}

/// Build the only structured value that may cross the MCP boundary.
///
/// Service responses contain identifiers, revisions, hashes and storage
/// locators that are useful for local auditing but are not part of a lawyer's
/// answer.  Never pass a service value through directly: every tool is
/// projected into this deliberately small, Chinese, user-facing DTO.
pub(crate) fn success_structured_content(
    tool_name: &str,
    data: &Value,
    public_text: &str,
) -> Value {
    let mut content = match tool_name {
        "system_status" => public_status_content(data),
        "legal_search" => public_search_content(data),
        "legal_get_article" => public_article_content(data),
        "legal_get_versions" => public_versions_content(data),
        "legal_get_relations" => public_relations_content(data),
        "citation_validate" => public_citation_validation_content(data),
        "case_get_state" => public_case_state_content(data),
        "case_propose_patch" => public_case_proposal_content(data),
        "case_apply_patch" => public_case_apply_content(data),
        "case_analyze_gaps" => public_case_gaps_content(data),
        "document_generate" => public_document_content(data, public_text),
        "document_export" => public_document_export_content(data),
        _ => Value::Null,
    };
    prune_empty_public_values(&mut content);
    json_object([
        ("结果", Value::String("已完成".to_owned())),
        ("说明", Value::String(bounded(public_text.to_owned()))),
        ("内容", content),
        ("提示", Value::Array(public_warnings(data))),
    ])
}

/// Error DTOs intentionally expose neither stable machine codes nor raw
/// diagnostics. Raw service messages and details are discarded at the MCP boundary.
pub(crate) fn error_structured_content(code: &str) -> Value {
    json_object([
        ("结果", Value::String("未完成".to_owned())),
        ("说明", Value::String(error_message(code).to_owned())),
        ("内容", Value::Null),
        ("提示", Value::Array(Vec::new())),
    ])
}

fn public_status_content(data: &Value) -> Value {
    json_object([
        (
            "法规检索",
            availability(bool_field(data, "legal_database", "available")),
        ),
        (
            "案件资料",
            availability(bool_field(data, "user_database", "available")),
        ),
        (
            "文书导出",
            availability(bool_field(data, "file_policy", "output_root_available")),
        ),
    ])
}

fn public_search_content(data: &Value) -> Value {
    let laws = array(data, "laws")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|law| {
            json_object([
                ("法律名称", public_title(law, "title", "相关法律", 200)),
                ("文件类型", public_string(law, "document_type", 80)),
                ("制定机关", public_string(law, "authority_name", 160)),
                ("效力层级", public_string(law, "effectiveness_level", 80)),
                (
                    "效力状态",
                    Value::String(public_version_status(string(law, "status")).to_owned()),
                ),
                ("施行日期", public_string(law, "current_effective_from", 32)),
                ("终止日期", public_string(law, "current_effective_to", 32)),
                ("内容摘要", public_string(law, "summary", 1_000)),
            ])
        })
        .collect();
    let articles = array(data, "articles")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|article| {
            let summary = public_string(article, "snippet", 1_000);
            json_object([
                (
                    "法律名称",
                    public_title(article, "document_title", "相关法律", 200),
                ),
                (
                    "条文",
                    Value::String(normalize_article_number(string(article, "article_number"))),
                ),
                (
                    "条文名称",
                    public_optional_title(article, "article_title", 160),
                ),
                ("施行日期", public_string(article, "effective_from", 32)),
                ("终止日期", public_string(article, "effective_to", 32)),
                (
                    "效力状态",
                    Value::String(
                        public_version_status(string(article, "version_status")).to_owned(),
                    ),
                ),
                (
                    "内容摘要",
                    if summary.as_str().is_some_and(contains_cjk) {
                        summary
                    } else {
                        Value::String(String::new())
                    },
                ),
            ])
        })
        .collect();
    json_object([
        ("相关法律", Value::Array(laws)),
        ("相关条文", Value::Array(articles)),
    ])
}

fn public_article_content(data: &Value) -> Value {
    let article = data.get("article").unwrap_or(&Value::Null);
    json_object([
        (
            "法律名称",
            public_title(article, "document_title", "相关法律", 200),
        ),
        ("版本名称", public_string(article, "version_label", 160)),
        (
            "条文",
            Value::String(normalize_article_number(string(article, "article_number"))),
        ),
        (
            "条文名称",
            public_optional_title(article, "article_title", 160),
        ),
        ("条文内容", public_multiline(article, "content", 128 * 1024)),
        ("施行日期", public_string(article, "effective_from", 32)),
        ("终止日期", public_string(article, "effective_to", 32)),
        (
            "效力状态",
            Value::String(public_version_status(string(article, "version_status")).to_owned()),
        ),
        (
            "主题",
            Value::Array(
                array(article, "topics")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|value| Value::String(safe_public_inline(value, 120)))
                    .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
                    .collect(),
            ),
        ),
    ])
}

fn public_versions_content(data: &Value) -> Value {
    Value::Array(
        array(data, "versions")
            .iter()
            .take(MAX_PUBLIC_LIST_ITEMS)
            .map(|version| {
                json_object([
                    ("版本名称", public_string(version, "version_label", 160)),
                    (
                        "效力状态",
                        Value::String(public_version_status(string(version, "status")).to_owned()),
                    ),
                    ("施行日期", public_string(version, "effective_from", 32)),
                    ("终止日期", public_string(version, "effective_to", 32)),
                    ("公布日期", public_string(version, "published_on", 32)),
                    (
                        "条文数量",
                        Value::Number(number(version, "article_count").into()),
                    ),
                ])
            })
            .collect(),
    )
}

fn public_relations_content(data: &Value) -> Value {
    Value::Array(
        array(data, "relations")
            .iter()
            .take(MAX_PUBLIC_LIST_ITEMS)
            .map(|relation| {
                json_object([
                    (
                        "相关法律",
                        public_title(relation, "from_title", "相关法律", 200),
                    ),
                    (
                        "关系",
                        Value::String(
                            public_relation_type(string(relation, "relation_type")).to_owned(),
                        ),
                    ),
                    (
                        "目标法律",
                        public_title(relation, "to_title", "相关法律", 200),
                    ),
                    ("说明", public_string(relation, "description", 1_000)),
                ])
            })
            .collect(),
    )
}

fn public_citation_validation_content(data: &Value) -> Value {
    let report = data.get("report").unwrap_or(&Value::Null);
    json_object([
        (
            "有效引用数量",
            Value::Number(number(report, "valid_count").into()),
        ),
        (
            "无效引用数量",
            Value::Number(number(report, "invalid_count").into()),
        ),
        (
            "存在缺少依据的法律结论",
            Value::Bool(boolean(report, "unsupported_legal_conclusion")),
        ),
        (
            "论证内容已经人工核实",
            Value::Bool(boolean(report, "semantic_support_verified")),
        ),
    ])
}

fn public_case_state_content(data: &Value) -> Value {
    let workspace = data.get("workspace").unwrap_or(&Value::Null);
    let project = workspace.get("project").unwrap_or(&Value::Null);
    let counts = data.get("counts").unwrap_or(&Value::Null);
    let files = array(workspace, "files")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|file| {
            json_object([
                ("材料名称", public_string(file, "title", 200)),
                ("材料类型", public_string(file, "file_type", 80)),
                ("内容摘要", public_string(file, "summary", 2_000)),
            ])
        })
        .collect();
    let parties = array(workspace, "parties")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|party| {
            json_object([
                ("当事人", public_string(party, "name", 200)),
                (
                    "诉讼地位",
                    Value::String(public_party_role(string(party, "role")).to_owned()),
                ),
                ("联系方式", public_string(party, "contact", 500)),
                ("备注", public_string(party, "notes", 2_000)),
            ])
        })
        .collect();
    let facts = array(workspace, "facts")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|fact| {
            json_object([
                ("发生日期", public_string(fact, "occurred_on", 32)),
                ("事实名称", public_string(fact, "title", 200)),
                ("事实内容", public_string(fact, "description", 4_000)),
                ("事实来源", public_string(fact, "source", 1_000)),
            ])
        })
        .collect();
    let evidence = array(workspace, "evidence")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|item| {
            json_object([
                ("证据编号", public_string(item, "evidence_number", 80)),
                ("证据名称", public_string(item, "title", 200)),
                ("证据来源", public_string(item, "source", 1_000)),
                ("形成日期", public_string(item, "formed_on", 32)),
                ("内容摘要", public_string(item, "summary", 2_000)),
            ])
        })
        .collect();
    let legal_issues = array(workspace, "legal_issues")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|issue| {
            json_object([
                ("争议焦点", public_string(issue, "title", 200)),
                ("焦点说明", public_string(issue, "description", 4_000)),
                ("当事人主张", public_string(issue, "claim", 4_000)),
                (
                    "处理状态",
                    Value::String(public_issue_status(string(issue, "status")).to_owned()),
                ),
            ])
        })
        .collect();
    let legal_basis = array(workspace, "legal_basis")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(public_legal_basis)
        .collect();
    let uncertainties = array(workspace, "uncertainties")
        .iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|item| {
            json_object([
                ("待核对事项", public_string(item, "description", 2_000)),
                (
                    "事项类别",
                    Value::String(
                        public_uncertainty_type(string(item, "related_entity_type")).to_owned(),
                    ),
                ),
                (
                    "处理状态",
                    Value::String(public_issue_status(string(item, "status")).to_owned()),
                ),
                ("处理结果", public_string(item, "resolution", 2_000)),
            ])
        })
        .collect();
    let gaps = public_gap_values(array(workspace, "gaps"));
    json_object([
        (
            "案件概况",
            json_object([
                ("案件名称", public_title(project, "title", "当前案件", 200)),
                ("案件类型", public_string(project, "case_type", 80)),
                (
                    "案件状态",
                    Value::String(public_project_status(string(project, "status")).to_owned()),
                ),
                ("立案日期", public_string(project, "opened_on", 32)),
                ("案情摘要", public_string(project, "summary", 4_000)),
            ]),
        ),
        (
            "内容数量",
            json_object([
                ("材料", Value::Number(number(counts, "files").into())),
                ("当事人", Value::Number(number(counts, "parties").into())),
                ("案件事实", Value::Number(number(counts, "facts").into())),
                ("证据", Value::Number(number(counts, "evidence").into())),
                (
                    "争议焦点",
                    Value::Number(number(counts, "legal_issues").into()),
                ),
                (
                    "法律依据",
                    Value::Number(number(counts, "legal_basis").into()),
                ),
                ("待核对事项", Value::Number(number(counts, "gaps").into())),
            ]),
        ),
        ("案件材料", Value::Array(files)),
        ("当事人", Value::Array(parties)),
        ("案件事实", Value::Array(facts)),
        ("证据", Value::Array(evidence)),
        ("争议焦点", Value::Array(legal_issues)),
        ("法律依据", Value::Array(legal_basis)),
        ("不确定事项", Value::Array(uncertainties)),
        ("待补充事项", Value::Array(gaps)),
        ("尚有后续内容", Value::Bool(boolean(data, "has_more"))),
    ])
}

fn public_case_proposal_content(data: &Value) -> Value {
    let canonical = string(data, "canonical_proposal");
    let proposal = serde_json::from_str::<Value>(canonical).unwrap_or(Value::Null);
    let changes = get_any(&proposal, &["changes"]).unwrap_or(&Value::Null);
    let bootstrap =
        get_any(&proposal, &["projectBootstrap", "project_bootstrap"]).unwrap_or(&Value::Null);
    let public_items = |name: &str, fields: &[(&str, &[&str], usize)]| {
        get_any(changes, &[name])
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .take(MAX_PUBLIC_LIST_ITEMS)
                    .map(|item| {
                        let mut pairs = Vec::new();
                        for (label, candidates, limit) in fields {
                            let value = candidates
                                .iter()
                                .find_map(|candidate| item.get(*candidate))
                                .and_then(Value::as_str)
                                .map(|value| safe_public_inline(value, *limit))
                                .unwrap_or_default();
                            pairs.push((*label, Value::String(value)));
                        }
                        json_object(pairs)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let material_imports = get_any(&proposal, &["materialImports", "material_imports"])
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(MAX_PUBLIC_LIST_ITEMS)
                .map(|item| {
                    json_object([(
                        "材料名称",
                        public_any_string(item, &["title", "originalName", "original_name"], 200),
                    )])
                })
                .collect()
        })
        .unwrap_or_default();
    json_object([
        (
            "案件基本信息",
            if bootstrap.is_object() {
                json_object([
                    ("案件名称", public_any_string(bootstrap, &["title"], 200)),
                    (
                        "案件类型",
                        public_any_string(bootstrap, &["caseType", "case_type"], 80),
                    ),
                    (
                        "立案日期",
                        public_any_string(bootstrap, &["openedOn", "opened_on"], 32),
                    ),
                    (
                        "案情摘要",
                        public_any_string(bootstrap, &["summary"], 4_000),
                    ),
                ])
            } else {
                Value::Null
            },
        ),
        (
            "拟新增事实",
            Value::Array(public_items(
                "facts",
                &[
                    ("发生日期", &["occurredOn", "occurred_on"], 32),
                    ("事实内容", &["statement"], 4_000),
                ],
            )),
        ),
        (
            "拟新增证据",
            Value::Array(public_items(
                "evidence",
                &[
                    ("证据名称", &["title"], 200),
                    ("内容摘要", &["summary"], 2_000),
                ],
            )),
        ),
        (
            "拟新增争议焦点",
            Value::Array(public_items(
                "issues",
                &[
                    ("争议焦点", &["title"], 200),
                    ("焦点分析", &["analysis"], 4_000),
                ],
            )),
        ),
        (
            "拟新增法律依据",
            Value::Array(public_items(
                "legalBasis",
                &[
                    ("法条引用", &["citation"], 500),
                    ("证明事项", &["proposition"], 2_000),
                ],
            )),
        ),
        ("拟导入材料", Value::Array(material_imports)),
        (
            "待核对事项",
            Value::Array(
                array(data, "uncertainties")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|value| Value::String(safe_public_inline(value, 2_000)))
                    .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
                    .collect(),
            ),
        ),
    ])
}

fn public_case_apply_content(data: &Value) -> Value {
    json_object([(
        "案件变更",
        Value::String(
            if boolean(data, "applied") {
                "已成功应用"
            } else {
                "未写入"
            }
            .to_owned(),
        ),
    )])
}

fn public_case_gaps_content(data: &Value) -> Value {
    Value::Array(public_gap_values(array(data, "gaps")))
}

fn public_document_content(data: &Value, public_text: &str) -> Value {
    let document = data.get("document").unwrap_or(&Value::Null);
    json_object([
        ("文书名称", public_title(document, "title", "法律文书", 240)),
        ("文书正文", Value::String(bounded(public_text.to_owned()))),
    ])
}

fn public_document_export_content(data: &Value) -> Value {
    let format = match string(data, "format") {
        "docx" => "文字处理文档",
        "markdown" => "纯文本文档",
        _ => "法律文书",
    };
    json_object([
        ("导出结果", Value::String("已完成".to_owned())),
        ("文件类型", Value::String(format.to_owned())),
    ])
}

fn public_legal_basis(value: &Value) -> Value {
    json_object([
        (
            "法律名称",
            public_title(value, "document_title", "相关法律", 200),
        ),
        (
            "条文",
            Value::String(normalize_article_number(string(value, "article_number"))),
        ),
        (
            "条文名称",
            public_optional_title(value, "article_title", 160),
        ),
        ("施行日期", public_string(value, "effective_from", 32)),
        ("终止日期", public_string(value, "effective_to", 32)),
        ("法条原文", public_string(value, "excerpt", 2_000)),
        ("适用说明", public_string(value, "note", 2_000)),
    ])
}

fn public_gap_values(gaps: &[Value]) -> Vec<Value> {
    gaps.iter()
        .take(MAX_PUBLIC_LIST_ITEMS)
        .map(|gap| {
            json_object([
                (
                    "处理要求",
                    Value::String(
                        if string(gap, "severity") == "blocking" {
                            "必须处理"
                        } else {
                            "建议核对"
                        }
                        .to_owned(),
                    ),
                ),
                (
                    "事项说明",
                    Value::String(public_gap_kind(string(gap, "kind")).to_owned()),
                ),
            ])
        })
        .collect()
}

fn public_warnings(data: &Value) -> Vec<Value> {
    let mut output: Vec<Value> = Vec::new();
    for warning in array(data, "warnings") {
        let Some(warning) = warning.as_str() else {
            continue;
        };
        let warning = public_warning(warning);
        if !output.iter().any(|value| value.as_str() == Some(warning)) {
            output.push(Value::String(warning.to_owned()));
        }
    }
    output
}

fn availability(available: bool) -> Value {
    Value::String(if available { "可用" } else { "暂不可用" }.to_owned())
}

fn public_party_role(value: &str) -> &'static str {
    match value {
        "plaintiff" => "原告",
        "defendant" => "被告",
        "claimant" => "申请人",
        "respondent" => "被申请人",
        "third_party" => "第三人",
        _ => "其他当事人",
    }
}

fn public_project_status(value: &str) -> &'static str {
    match value {
        "active" => "办理中",
        "archived" => "已归档",
        _ => "",
    }
}

fn public_issue_status(value: &str) -> &'static str {
    match value {
        "open" => "待处理",
        "resolved" => "已处理",
        _ => "",
    }
}

fn public_uncertainty_type(value: &str) -> &'static str {
    match value {
        "party" => "当事人",
        "fact" => "案件事实",
        "evidence" => "证据",
        "legal_issue" => "争议焦点",
        _ => "一般事项",
    }
}

fn public_string(value: &Value, field: &str, max_chars: usize) -> Value {
    Value::String(safe_public_inline(string(value, field), max_chars))
}

fn public_title(value: &Value, field: &str, fallback: &str, max_chars: usize) -> Value {
    let title = safe_public_inline(string(value, field), max_chars);
    Value::String(meaningful_title(&title).unwrap_or(fallback).to_owned())
}

fn public_optional_title(value: &Value, field: &str, max_chars: usize) -> Value {
    let title = safe_public_inline(string(value, field), max_chars);
    Value::String(meaningful_title(&title).unwrap_or_default().to_owned())
}

fn public_multiline(value: &Value, field: &str, max_chars: usize) -> Value {
    Value::String(safe_public_multiline(string(value, field), max_chars))
}

fn public_any_string(value: &Value, fields: &[&str], max_chars: usize) -> Value {
    let value = fields
        .iter()
        .find_map(|field| value.get(*field))
        .and_then(Value::as_str)
        .unwrap_or_default();
    Value::String(safe_public_inline(value, max_chars))
}

fn get_any<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a Value> {
    fields.iter().find_map(|field| value.get(*field))
}

fn prune_empty_public_values(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, value| {
                prune_empty_public_values(value);
                !matches!(value, Value::Null)
                    && !matches!(value, Value::String(text) if text.trim().is_empty())
            });
        }
        Value::Array(values) => {
            for value in values {
                prune_empty_public_values(value);
            }
        }
        _ => {}
    }
}

fn json_object<'a>(pairs: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn safe_public_inline(value: &str, max_chars: usize) -> String {
    let value = clean_inline(value, max_chars);
    if contains_internal_detail(&value) {
        String::new()
    } else {
        value
    }
}

fn safe_public_multiline(value: &str, max_chars: usize) -> String {
    let value = clean_multiline(value, max_chars);
    if contains_internal_detail(&value) {
        String::new()
    } else {
        value
    }
}

fn contains_internal_detail(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let forbidden = [
        "schema_version",
        "schemaversion",
        "request_id",
        "requestid",
        "request_uuid",
        "requestuuid",
        "article_id",
        "articleid",
        "case_id",
        "caseid",
        "document_id",
        "documentid",
        "version_id",
        "versionid",
        "project_id",
        "projectid",
        "file_id",
        "fileid",
        "source_ref",
        "sourceref",
        "source_id",
        "sourceid",
        "proposal_hash",
        "proposalhash",
        "generation_hash",
        "generationhash",
        "structuredcontent",
        "raw_output",
        "rawoutput",
        "snippet",
        "snnipet",
        "endpoint",
        "base_url",
        "baseurl",
        "appdata",
        "file://",
        "http://",
        "https://",
        "urn:",
        "[src:",
        "service-",
    ];
    forbidden.iter().any(|needle| lower.contains(needle))
        || looks_like_local_path(trimmed)
        || contains_uuid(trimmed)
        || contains_sha256(trimmed)
        || ((trimmed.starts_with('{') || trimmed.starts_with('['))
            && serde_json::from_str::<Value>(trimmed).is_ok())
}

fn contains_uuid(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .any(|candidate| {
            candidate.len() == 36
                && [8, 13, 18, 23]
                    .into_iter()
                    .all(|index| candidate.as_bytes().get(index) == Some(&b'-'))
                && candidate.chars().enumerate().all(|(index, character)| {
                    [8, 13, 18, 23].contains(&index) || character.is_ascii_hexdigit()
                })
        })
}

fn contains_sha256(value: &str) -> bool {
    let mut run = 0;
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Scrub textual diagnostics that are embedded in otherwise successful
/// structured responses. Machine identifiers stay available where the output
/// schema requires them, while human-readable error and warning fields remain
/// public-safe.
#[cfg(test)]
pub(crate) fn sanitize_structured_data(tool_name: &str, mut data: Value) -> Value {
    if let Some(warnings) = data.get_mut("warnings").and_then(Value::as_array_mut) {
        *warnings = warnings
            .iter()
            .filter_map(Value::as_str)
            .map(public_warning)
            .map(|warning| Value::String(warning.to_owned()))
            .collect();
    }
    if tool_name == "system_status" {
        for field in ["legal_database", "user_database"] {
            let Some(error) = data
                .get_mut(field)
                .and_then(|status| status.get_mut("error"))
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            let code = error
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            error.insert(
                "message".to_owned(),
                Value::String(error_message(&code).to_owned()),
            );
            let details = error.remove("details").unwrap_or(Value::Null);
            error.insert("details".to_owned(), safe_error_details(details));
        }
    }
    data
}

/// Stable public messages. Original service messages belong only in logs.
pub(crate) fn error_message(code: &str) -> &'static str {
    match code {
        "invalid_request" | "unsupported_schema_version" | "invalid_cursor" => {
            "提交的内容不符合要求，请检查后重试。"
        }
        "not_found" => "未找到请求的内容，请刷新后重试。",
        "revision_conflict" | "idempotency_conflict" => "案件内容已发生变化，请刷新后重新操作。",
        "confirmation_required" => "该操作尚未执行，请先审阅并明确确认。",
        "proposal_hash_mismatch" | "invalid_proposal" => {
            "待应用的变更方案已发生变化，请重新生成并审阅。"
        }
        "generation_hash_mismatch" | "document_validation_failed" => {
            "文书内容已发生变化或校验未通过，请重新生成并审阅。"
        }
        "legal_database_missing"
        | "legal_database_incompatible"
        | "user_database_missing"
        | "database_path_rejected"
        | "database_error"
        | "database_busy" => "本地数据暂时不可用，请检查应用状态后重试。",
        "material_path_rejected"
        | "output_path_rejected"
        | "file_policy_rejected"
        | "path_identity_changed" => "所选文件或导出位置不符合安全要求，请重新选择。",
        "limit_exceeded" => "内容超过单次处理上限，请缩小范围后重试。",
        "sensitive_content_blocked" => {
            "结果包含疑似敏感个人信息，已在本地阻止返回。请先在应用内完成脱敏审核。"
        }
        "document_render_failed"
        | "export_integrity_failed"
        | "artifact_export_failed"
        | "file_write" => "文书处理未能完成，请稍后重试。",
        _ => "操作未能完成，请稍后重试；如问题持续存在，请联系服务人员。",
    }
}

/// Preserve only small, non-sensitive protocol hints in structured errors.
#[cfg(test)]
pub(crate) fn safe_error_details(details: Value) -> Value {
    let Value::Object(details) = details else {
        return Value::Object(Map::new());
    };
    let mut safe = Map::new();
    for (key, value) in details {
        if !matches!(
            key.as_str(),
            "field"
                | "reason"
                | "resource"
                | "supported"
                | "actual"
                | "limit"
                | "outcome"
                | "remediation"
                | "format"
                | "kind"
                | "expected_type"
                | "actual_type"
                | "missing_fields"
        ) {
            continue;
        }
        if let Some(value) = safe_detail_value(value) {
            safe.insert(key, value);
        }
    }
    Value::Object(safe)
}

fn public_warning(warning: &str) -> &'static str {
    if warning == "no_local_results_found" {
        "未找到足够相关的本地法规结果。"
    } else if warning == "semantic_support_not_verified" {
        "引用校验未判断论证内容是否充分，请人工复核。"
    } else if warning.starts_with("allowed_source_not_found:") {
        "有一项引用来源未找到。"
    } else {
        "有内容需要人工复核。"
    }
}

#[cfg(test)]
fn safe_detail_value(value: Value) -> Option<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Some(value),
        Value::String(text) if text.len() <= 256 && !looks_like_local_path(&text) => {
            Some(Value::String(text))
        }
        Value::Array(values) if values.len() <= 32 => Some(Value::Array(
            values.into_iter().filter_map(safe_detail_value).collect(),
        )),
        _ => None,
    }
}

fn system_status(data: &Value) -> String {
    let legal_ready = bool_field(data, "legal_database", "available");
    let case_ready = bool_field(data, "user_database", "available");
    let export_ready = bool_field(data, "file_policy", "output_root_available");
    if legal_ready && case_ready && export_ready {
        return "应用服务已就绪，法规检索、案件数据和文书导出均可使用。".to_owned();
    }
    let mut unavailable = Vec::new();
    if !legal_ready {
        unavailable.push("法规检索");
    }
    if !case_ready {
        unavailable.push("案件数据");
    }
    if !export_ready {
        unavailable.push("文书导出");
    }
    format!(
        "应用服务当前部分可用。暂不可用的功能：{}。请在应用设置中检查后重试。",
        unavailable.join("、")
    )
}

fn legal_search(data: &Value) -> String {
    let laws = array(data, "laws");
    let articles = array(data, "articles");
    if laws.is_empty() && articles.is_empty() {
        return "未在本地法规库中找到足够相关的结果。可尝试缩短关键词，或补充法规名称和条文主题。"
            .to_owned();
    }
    let mut output = format!(
        "本地法规检索完成：找到 {} 部相关法规、{} 条相关条文。",
        laws.len(),
        articles.len()
    );
    if !articles.is_empty() {
        output.push_str("\n\n相关条文：");
        for (index, article) in articles.iter().take(MAX_PUBLIC_LIST_ITEMS).enumerate() {
            let label = article_label_from_result(article);
            output.push_str(&format!("\n{}. {label}", index + 1));
            let summary = safe_public_inline(string(article, "snippet"), 360);
            // English tokenizer/debug fragments are not legal summaries for
            // this Chinese corpus and must never be surfaced to the user.
            if contains_cjk(&summary) {
                output.push_str(&format!("\n   内容摘要：{summary}"));
            }
        }
        if articles.len() > MAX_PUBLIC_LIST_ITEMS {
            output.push_str("\n其余结果可继续查询。");
        }
    }
    if !laws.is_empty() {
        output.push_str("\n\n相关法规：");
        for law in laws.iter().take(MAX_PUBLIC_LIST_ITEMS) {
            let safe_title = safe_public_inline(string(law, "title"), 160);
            let title = meaningful_title(&safe_title).unwrap_or("相关法规");
            output.push_str(&format!("\n- 《{title}》"));
            let summary = safe_public_inline(string(law, "summary"), 240);
            if contains_cjk(&summary) {
                output.push_str(&format!("：{summary}"));
            }
        }
    }
    output
}

fn legal_article(data: &Value) -> String {
    let article = data.get("article").unwrap_or(&Value::Null);
    let mut output = article_label_from_result(article);
    let content = safe_public_multiline(string(article, "content"), 128 * 1024);
    if !content.is_empty() {
        output.push_str("\n\n");
        output.push_str(&content);
    }
    output
}

fn legal_versions(data: &Value) -> String {
    let versions = array(data, "versions");
    if versions.is_empty() {
        return "未找到可展示的法规版本记录。".to_owned();
    }
    let mut output = format!("找到 {} 个法规版本：", versions.len());
    for version in versions.iter().take(MAX_PUBLIC_LIST_ITEMS) {
        let label = safe_public_inline(string(version, "version_label"), 160);
        let from = safe_public_inline(string(version, "effective_from"), 32);
        let to = safe_public_inline(string(version, "effective_to"), 32);
        let status = public_version_status(string(version, "status"));
        output.push_str("\n- ");
        output.push_str(if label.is_empty() {
            "法规版本"
        } else {
            &label
        });
        if !from.is_empty() {
            output.push_str(&format!("（{from}"));
            if !to.is_empty() {
                output.push_str(&format!("至{to}"));
            }
            output.push('）');
        }
        if !status.is_empty() {
            output.push_str(&format!("，{status}"));
        }
    }
    output
}

fn legal_relations(data: &Value) -> String {
    let relations = array(data, "relations");
    if relations.is_empty() {
        return "未找到可展示的法规关联关系。".to_owned();
    }
    let mut output = format!("找到 {} 条法规关联关系：", relations.len());
    for relation in relations.iter().take(MAX_PUBLIC_LIST_ITEMS) {
        let safe_from = safe_public_inline(string(relation, "from_title"), 160);
        let safe_to = safe_public_inline(string(relation, "to_title"), 160);
        let from = meaningful_title(&safe_from).unwrap_or("相关法规");
        let to = meaningful_title(&safe_to).unwrap_or("相关法规");
        output.push_str(&format!(
            "\n- 《{}》{}《{}》",
            safe_public_inline(from, 160),
            public_relation_type(string(relation, "relation_type")),
            safe_public_inline(to, 160)
        ));
        let description = safe_public_inline(string(relation, "description"), 240);
        if contains_cjk(&description) {
            output.push_str(&format!("：{description}"));
        }
    }
    output
}

fn citation_validation(data: &Value) -> String {
    let report = data.get("report").unwrap_or(&Value::Null);
    let mut output = format!(
        "引证校验完成：有效 {} 处，无效 {} 处。",
        number(report, "valid_count"),
        number(report, "invalid_count")
    );
    if boolean(report, "unsupported_legal_conclusion") {
        output.push_str("仍有法律结论缺少相邻的有效依据，请补充或调整引证。");
    }
    if !boolean(report, "semantic_support_verified") {
        output.push_str("此次校验仅确认引用格式、来源和适用时间，未判断论证内容是否充分。");
    }
    output
}

fn case_state(data: &Value) -> String {
    let workspace = data.get("workspace").unwrap_or(&Value::Null);
    let project = workspace.get("project").unwrap_or(&Value::Null);
    let public_title = safe_public_inline(string(project, "title"), 200);
    let title = meaningful_title(&public_title).unwrap_or("当前案件");
    let summary = safe_public_multiline(string(project, "summary"), 2_000);
    let counts = data.get("counts").unwrap_or(&Value::Null);
    let mut output = format!(
        "已读取案件“{}”的已确认内容。",
        safe_public_inline(title, 200)
    );
    if !summary.is_empty() {
        output.push_str(&format!("\n案件概况：{summary}"));
    }
    output.push_str(&format!(
        "\n当前包含：当事人 {} 名、案件事实 {} 项、证据 {} 项、争议焦点 {} 项、法律依据 {} 项、待补充事项 {} 项。",
        number(counts, "parties"), number(counts, "facts"), number(counts, "evidence"),
        number(counts, "legal_issues"), number(counts, "legal_basis"), number(counts, "gaps")
    ));
    if boolean(data, "has_more") {
        output.push_str("另有后续内容，可继续读取。");
    }
    output
}

fn case_proposal(data: &Value) -> String {
    let uncertainty_count = array(data, "uncertainties").len();
    let mut output = "案件变更方案已生成，但尚未写入案件。请先审阅，再决定是否应用。".to_owned();
    if uncertainty_count > 0 {
        output.push_str(&format!(
            "\n有 {uncertainty_count} 项不确定内容需要人工核对。"
        ));
    }
    output
}

fn case_apply(data: &Value) -> String {
    if boolean(data, "applied") {
        "案件变更已成功应用。".to_owned()
    } else {
        "案件变更未写入，请刷新案件后重试。".to_owned()
    }
}

fn case_gaps(data: &Value) -> String {
    let gaps = array(data, "gaps");
    if gaps.is_empty() {
        return "案件完整性检查完成，暂未发现需要补充的事项。".to_owned();
    }
    let mut output = format!("案件完整性检查发现 {} 项需要处理的内容：", gaps.len());
    for gap in gaps.iter().take(MAX_PUBLIC_LIST_ITEMS) {
        let severity = if string(gap, "severity") == "blocking" {
            "必须处理"
        } else {
            "建议核对"
        };
        output.push_str(&format!(
            "\n- {severity}：{}",
            public_gap_kind(string(gap, "kind"))
        ));
    }
    output
}

fn generated_document(data: &Value) -> String {
    let document = data.get("document").unwrap_or(&Value::Null);
    let safe_title = safe_public_inline(string(document, "title"), 240);
    let title = meaningful_title(&safe_title).unwrap_or("法律文书");
    let sections = array(document, "sections");
    let tables = array(document, "tables");
    let mut output = format!("# {}", safe_public_inline(title, 240));
    for section in sections {
        let heading = safe_public_inline(string(section, "heading"), 200);
        if heading.is_empty() || internal_section(&heading) {
            continue;
        }
        output.push_str(&format!("\n\n## {heading}"));
        for paragraph in array(section, "paragraphs") {
            if let Some(paragraph) = paragraph.as_str() {
                let paragraph = safe_public_multiline(paragraph, 8_000);
                if !paragraph.is_empty() {
                    output.push_str("\n\n");
                    output.push_str(&paragraph);
                }
            }
        }
        for table in tables
            .iter()
            .filter(|table| string(table, "section_heading") == string(section, "heading"))
        {
            render_public_table(&mut output, table);
        }
    }
    let has_public_reference_table = tables
        .iter()
        .any(|table| string(table, "section_heading") == "法律依据与案例引用表");
    if !has_public_reference_table {
        render_public_citations(&mut output, array(document, "citations"));
    }
    if sections.is_empty() {
        output.push_str("\n\n文书内容已生成，请复核。");
    }
    output
}

fn render_public_table(output: &mut String, table: &Value) {
    let headers = array(table, "headers");
    let visible_columns = headers
        .iter()
        .enumerate()
        .filter_map(|(index, header)| {
            let header = header.as_str()?;
            (!internal_column(header)).then_some((index, safe_public_inline(header, 120)))
        })
        .collect::<Vec<_>>();
    if visible_columns.is_empty() {
        return;
    }
    output.push_str("\n\n|");
    for (_, header) in &visible_columns {
        output.push_str(&format!(" {header} |"));
    }
    output.push_str("\n|");
    for _ in &visible_columns {
        output.push_str(" --- |");
    }
    for row in array(table, "rows") {
        let cells = array(row, "cells");
        output.push_str("\n|");
        for (index, _) in &visible_columns {
            let cell = cells
                .get(*index)
                .and_then(Value::as_str)
                .map(|value| safe_public_inline(value, 1_000))
                .unwrap_or_default()
                .replace('|', "｜");
            output.push_str(&format!(" {cell} |"));
        }
    }
}

fn render_public_citations(output: &mut String, citations: &[Value]) {
    if citations.is_empty() {
        return;
    }
    output.push_str("\n\n## 法律依据与案例引用表\n\n| 类型 | 法律或案例名称 | 条款或案号 | 施行或裁判年份 | 引用内容 |\n| --- | --- | --- | --- | --- |");
    let mut rendered = 0;
    for citation in citations.iter().take(MAX_PUBLIC_LIST_ITEMS) {
        let kind = string(citation, "kind");
        let canonical = safe_public_inline(string(citation, "canonical_label"), 240);
        let (fallback_name, fallback_clause) = split_canonical_label(&canonical);
        let safe_title = safe_public_inline(string(citation, "title"), 200);
        let name = meaningful_title(&safe_title)
            .map(str::to_owned)
            .unwrap_or(fallback_name);
        let locator = safe_public_inline(string(citation, "locator"), 160);
        let clause = if locator.is_empty() {
            fallback_clause
        } else {
            locator
        };
        let judicial_case = matches!(kind, "judicialCase" | "judicial_case");
        let (kind_label, name) = if judicial_case {
            ("案例", name)
        } else {
            ("法条", format!("《{name}》"))
        };
        let Some(year) = public_year(citation) else {
            continue;
        };
        if (!judicial_case && (!clause.contains('条') || !clause.contains('款')))
            || (judicial_case && clause.trim().is_empty())
        {
            continue;
        }
        let year = if judicial_case {
            format!("{year}年裁判")
        } else {
            format!("{year}年起施行")
        };
        let excerpt = safe_public_inline(string(citation, "excerpt"), 1_000).replace('|', "｜");
        output.push_str(&format!(
            "\n| {} | {} | {} | {} | {} |",
            kind_label,
            name.replace('|', "｜"),
            clause.replace('|', "｜"),
            year,
            excerpt
        ));
        rendered += 1;
    }
    if rendered == 0 {
        output.push_str("\n| 未引用 | 本文未列明经核对的法律或案例依据 | — | — | — |");
    }
}

fn document_export(data: &Value) -> String {
    let format = match string(data, "format") {
        "docx" => "文字处理文档",
        "markdown" => "纯文本文档",
        _ => "文书文件",
    };
    format!("{format}已成功导出。")
}

fn article_label_from_result(article: &Value) -> String {
    let safe_document_title = safe_public_inline(string(article, "document_title"), 160);
    let document_title = meaningful_title(&safe_document_title).unwrap_or("相关法规");
    let article_number = normalize_article_number(string(article, "article_number"));
    let safe_article_title = safe_public_inline(string(article, "article_title"), 120);
    let article_title = meaningful_title(&safe_article_title);
    let mut label = format!("《{document_title}》{article_number}");
    if let Some(title) = article_title {
        label.push_str(&format!("（{}）", safe_public_inline(title, 120)));
    }
    if let Some(year) = public_year(article) {
        label.push_str(&format!("（{year}年起施行）"));
    }
    label
}

fn normalize_article_number(value: &str) -> String {
    let value = safe_public_inline(value, 80);
    if value.is_empty() {
        "相关条文".to_owned()
    } else if value.starts_with('第') && value.contains('条') {
        value
    } else if value.chars().all(|character| character.is_ascii_digit()) {
        format!("第{value}条")
    } else {
        value
    }
}

fn public_year(value: &Value) -> Option<&str> {
    for field in [
        "display_year",
        "effective_or_decided_on",
        "effective_from",
        "decided_on",
        "year",
    ] {
        let value = string(value, field);
        if let Some(year) = value
            .get(..4)
            .filter(|year| year.chars().all(|character| character.is_ascii_digit()))
        {
            return Some(year);
        }
    }
    None
}

fn split_canonical_label(value: &str) -> (String, String) {
    if let Some(rest) = value.strip_prefix('《') {
        if let Some((name, clause)) = rest.split_once('》') {
            return (name.to_owned(), clause.trim().to_owned());
        }
    }
    (value.to_owned(), "未注明".to_owned())
}

fn public_gap_kind(kind: &str) -> &'static str {
    match kind {
        "evidence_missing_source" => "有证据尚未填写来源。",
        "evidence_missing_formed_on" => "有证据尚未填写形成日期。",
        "fact_missing_evidence" => "有案件事实尚未关联证据。",
        "invalid_evidence_id" => "有证据关联指向不存在的内容。",
        "timeline_conflict" => "同一事实存在日期冲突。",
        "party_name_inconsistent" => "同一当事人的名称写法不一致。",
        "legal_issue_missing_basis" => "有争议焦点尚未关联有效法律依据。",
        _ => "有案件内容需要人工核对。",
    }
}

fn public_version_status(status: &str) -> &'static str {
    match status {
        "in_force" | "effective" => "现行有效",
        "repealed" => "已废止",
        "expired" => "已失效",
        "not_yet_effective" => "尚未施行",
        _ => "",
    }
}

fn public_relation_type(relation_type: &str) -> &'static str {
    match relation_type {
        "amends" | "amended_by" => "修订了",
        "repeals" | "repealed_by" => "废止了",
        "implements" | "implemented_by" => "配套实施于",
        "interprets" | "interpreted_by" => "解释了",
        _ => "关联",
    }
}

fn meaningful_title(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "无标题" | "未命名" | "untitled" | "none" | "null" | "n/a"
        )
    {
        None
    } else {
        Some(value)
    }
}

fn internal_section(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains("引用来源映射")
        || value.contains("内部追溯")
        || lower.contains("source mapping")
        || lower.contains("diagnostic")
}

fn internal_column(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    value.contains("追溯标识")
        || value.contains("内部标识")
        || value.contains("来源 ID")
        || value.contains("文档 ID")
        || value.contains("版本 ID")
        || value.contains("条文 ID")
        || value.contains("本地路径")
        || lower == "id"
        || lower.ends_with("_id")
        || lower.contains("hash")
        || lower.contains("revision")
        || lower.contains("local path")
}

fn looks_like_local_path(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains(":\\")
        || trimmed.contains(":/")
        || trimmed.to_ascii_lowercase().starts_with("file:")
        || trimmed.to_ascii_lowercase().contains("appdata")
}

fn contains_cjk(value: &str) -> bool {
    value.chars().any(
        |character| matches!(character as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF),
    )
}

fn clean_inline(value: &str, max_chars: usize) -> String {
    let value = strip_markup(value);
    let mut output = String::new();
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space {
            output.push(' ');
            pending_space = false;
        }
        output.push(character);
        if output.chars().count() >= max_chars {
            break;
        }
    }
    output.trim().to_owned()
}

fn clean_multiline(value: &str, max_chars: usize) -> String {
    let value = strip_markup(value)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut output = String::new();
    let mut previous_blank = false;
    for line in value.lines() {
        let line = clean_inline(line, max_chars);
        if line.is_empty() {
            if !previous_blank && !output.is_empty() {
                output.push('\n');
            }
            previous_blank = true;
        } else {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&line);
            previous_blank = false;
        }
        if output.chars().count() >= max_chars {
            break;
        }
    }
    output.trim().to_owned()
}

fn strip_markup(value: &str) -> String {
    value
        .replace("<b>", "")
        .replace("</b>", "")
        .replace("<mark>", "")
        .replace("</mark>", "")
        .replace("<em>", "")
        .replace("</em>", "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn bounded(mut text: String) -> String {
    if text.len() <= MAX_PUBLIC_CONTENT_BYTES {
        return text;
    }
    const SUFFIX: &str = "\n\n（内容较长，已省略其余部分；可在应用中继续查看。）";
    let mut end = MAX_PUBLIC_CONTENT_BYTES.saturating_sub(SUFFIX.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(SUFFIX);
    text
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("")
}

fn boolean(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn bool_field(value: &Value, parent: &str, field: &str) -> bool {
    value
        .get(parent)
        .and_then(|value| value.get(field))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn number(value: &Value, field: &str) -> u64 {
    value.get(field).and_then(Value::as_u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legal_search_is_public_chinese_and_uses_a_canonical_fallback_title() {
        let data = json!({
            "schema_version":1,
            "laws":[{"document_id":"doc-secret","title":"中华人民共和国民法典","summary":"调整民事关系。"}],
            "articles":[{
                "article_id":"article-secret",
                "version_id":"version-secret",
                "document_title":"中华人民共和国民法典",
                "article_number":"第五百七十七条",
                "article_title":"无标题",
                "snippet":"An English tokenizer debug snippet.",
                "effective_from":"2021-01-01"
            }]
        });
        let text = success_text("legal_search", &data);
        assert!(text.contains("《中华人民共和国民法典》第五百七十七条（2021年起施行）"));
        let structured = success_structured_content("legal_search", &data, &text);
        assert_eq!(
            structured["内容"]["相关条文"][0]["法律名称"],
            "中华人民共和国民法典"
        );
        assert!(structured["内容"]["相关条文"][0].get("条文名称").is_none());
        for forbidden in [
            "article_id",
            "schema_version",
            "doc-secret",
            "article-secret",
            "version-secret",
            "tokenizer debug",
            "无标题",
        ] {
            assert!(!text.contains(forbidden), "leaked {forbidden}: {text}");
        }
    }

    #[test]
    fn generated_document_filters_internal_tables_and_adds_a_public_citation_table() {
        let data = json!({
            "project_id":"project-secret",
            "generation_hash":"b".repeat(64),
            "document":{
                "title":"民事起诉状",
                "sections":[
                    {"heading":"法律依据","paragraphs":["依法提出以下请求。"]},
                    {"heading":"引用来源映射","paragraphs":[]}
                ],
                "tables":[{
                    "section_heading":"法律依据",
                    "headers":["法律依据","已校验原文摘录","本地追溯标识"],
                    "rows":[{"cells":["《民法典》第五百七十七条","当事人一方不履行合同义务……","law:secret"]}]
                }],
                "citations":[{
                    "kind":"law",
                    "title":"中华人民共和国民法典",
                    "locator":"第五百七十七条第一款",
                    "effective_or_decided_on":"2021-01-01",
                    "canonical_label":"《民法典》第五百七十七条",
                    "excerpt":"当事人一方不履行合同义务，应当承担违约责任。",
                    "source_id":"law:secret",
                    "document_id":"doc-secret",
                    "article_id":"article-secret"
                }]
            }
        });
        let text = success_text("document_generate", &data);
        assert!(text.contains("| 类型 | 法律或案例名称 | 条款或案号 | 施行或裁判年份 | 引用内容 |"));
        assert!(text
            .contains("| 法条 | 《中华人民共和国民法典》 | 第五百七十七条第一款 | 2021年起施行 |"));
        for forbidden in [
            "project-secret",
            "generation_hash",
            "引用来源映射",
            "本地追溯标识",
            "来源 ID",
            "law:secret",
            "doc-secret",
            "article-secret",
        ] {
            assert!(!text.contains(forbidden), "leaked {forbidden}: {text}");
        }
    }

    #[test]
    fn generated_document_does_not_duplicate_an_existing_public_reference_table() {
        let text = success_text(
            "document_generate",
            &json!({
                "document":{
                    "title":"法律检索报告",
                    "sections":[{"heading":"法律依据与案例引用表","paragraphs":[]}],
                    "tables":[{
                        "section_heading":"法律依据与案例引用表",
                        "headers":["类型","法律或案例名称","条款或案号","施行或裁判年份","引用内容"],
                        "rows":[{"cells":["案例","张某与甲公司买卖合同纠纷案","（2025）京01民终1234号","2025年","法院认定逾期交付构成违约。"]}]
                    }],
                    "citations":[{
                        "kind":"judicialCase",
                        "title":"张某与甲公司买卖合同纠纷案",
                        "locator":"（2025）京01民终1234号",
                        "effective_or_decided_on":"2025-06-18",
                        "excerpt":"法院认定逾期交付构成违约。",
                        "source_id":"case-secret"
                    }]
                }
            }),
        );
        assert_eq!(text.matches("## 法律依据与案例引用表").count(), 1);
        assert_eq!(text.matches("（2025）京01民终1234号").count(), 1);
        assert!(!text.contains("case-secret"));
    }

    #[test]
    fn error_boundary_removes_paths_identifiers_and_nested_diagnostics() {
        let safe = safe_error_details(json!({
            "field":"relative_path",
            "reason":"outside_allowed_root",
            "resource":"artifact",
            "path":"C:\\Users\\person\\AppData\\secret.txt",
            "document_id":"doc-secret",
            "proposal_hash":"a".repeat(64),
            "debug":{"backtrace":"stack"},
            "actual":"C:\\private\\db.sqlite"
        }));
        assert_eq!(safe["field"], "relative_path");
        assert_eq!(safe["reason"], "outside_allowed_root");
        assert_eq!(safe["resource"], "artifact");
        for forbidden in ["path", "document_id", "proposal_hash", "debug", "actual"] {
            assert!(safe.get(forbidden).is_none());
        }
    }

    #[test]
    fn successful_status_and_warning_texts_are_public_safe() {
        let data = sanitize_structured_data(
            "system_status",
            json!({
                "warnings":["allowed_source_not_found:law:secret"],
                "legal_database":{
                    "error":{
                        "code":"legal_database_missing",
                        "message":"failed to open C:\\private\\legal.sqlite",
                        "retryable":false,
                        "details":{"path":"C:\\private\\legal.sqlite","reason":"open_failed"}
                    }
                },
                "user_database":{"error":null}
            }),
        );
        let serialized = serde_json::to_string(&data).expect("fixture serializes");
        assert!(serialized.contains("本地数据暂时不可用"));
        assert!(serialized.contains("有一项引用来源未找到"));
        assert!(!serialized.contains("law:secret"));
        assert!(!serialized.contains("C:\\\\private"));
        assert!(!serialized.contains("legal.sqlite"));
    }

    #[test]
    fn gap_summary_does_not_repeat_internal_ids_or_english_diagnostics() {
        let text = success_text(
            "case_analyze_gaps",
            &json!({
                "revision":"a".repeat(64),
                "gaps":[{
                    "gap_id":"gap:internal-id:invalid_evidence_id",
                    "project_id":"project-secret",
                    "entity_id":"link-secret",
                    "kind":"invalid_evidence_id",
                    "severity":"blocking",
                    "message":"Evidence link link-secret references a missing fact."
                }]
            }),
        );
        assert!(text.contains("证据关联"));
        assert!(!text.contains("link-secret"));
        assert!(!text.contains("Evidence link"));
        assert!(!text.contains("revision"));
    }

    #[test]
    fn case_proposal_never_exposes_model_scores_or_binding_values() {
        let text = success_text(
            "case_propose_patch",
            &json!({
                "proposal_id":"proposal-secret",
                "proposal_hash":"a".repeat(64),
                "base_revision":"b".repeat(64),
                "confidence":0.87,
                "uncertainties":[{"message":"交付日期仍需核对"}]
            }),
        );
        assert!(text.contains("有 1 项不确定内容需要人工核对"));
        for forbidden in ["置信度", "87%", "0.87", "proposal-secret", "proposal_hash"] {
            assert!(!text.contains(forbidden), "leaked {forbidden}: {text}");
        }
    }

    #[test]
    fn every_tool_projects_only_public_business_content() {
        let canonical_proposal = serde_json::to_string(&json!({
            "schemaVersion":1,
            "projectId":"project-secret",
            "baseRevision":"a".repeat(64),
            "changes":{
                "facts":[{"id":"fact-secret","statement":"双方于2025年签订买卖合同。","occurredOn":"2025-01-02","sourceRefs":["file-secret"]}],
                "evidence":[{"id":"evidence-secret","title":"买卖合同","summary":"载明交付期限。","sourceRefs":["file-secret"]}],
                "issues":[{"id":"issue-secret","title":"是否构成逾期交付","analysis":"应结合约定期限判断。","sourceRefs":["file-secret"]}],
                "legalBasis":[{"id":"basis-secret","citation":"《中华人民共和国民法典》第五百七十七条（2021年起施行）","proposition":"不履行合同义务应承担违约责任。","sourceRef":"law-secret"}],
                "attachmentTransfers":[],
                "artifactTransfers":[]
            },
            "projectBootstrap":{"title":"买卖合同纠纷","caseType":"民事案件","openedOn":"2026-07-17","summary":"审查逾期交付责任。"},
            "materialImports":[{"materialId":"material-secret","relativePath":"private/secret.pdf","contentSha256":"b".repeat(64),"title":"买卖合同"}],
            "sourceRefs":["file-secret"]
        }))
        .expect("canonical proposal fixture serializes");
        let fixtures = vec![
            (
                "system_status",
                json!({
                    "schema_version":1,
                    "status":"ready",
                    "legal_database":{"available":true,"schema_version":"4","dataset_version":"secret"},
                    "user_database":{"available":true,"schema_version":"10"},
                    "file_policy":{"allowed_file_root_count":1,"output_root_available":true},
                    "endpoint":"https://private.example"
                }),
            ),
            (
                "legal_search",
                json!({
                    "schema_version":1,
                    "database_version":"secret",
                    "laws":[{"document_id":"doc-secret","title":"中华人民共和国民法典","document_type":"法律","authority_name":"全国人民代表大会","effectiveness_level":"法律","status":"in_force","current_version_id":"version-secret","current_effective_from":"2021-01-01","summary":"调整民事关系。","score":0.99}],
                    "articles":[{"article_id":"article-secret","document_id":"doc-secret","version_id":"version-secret","document_title":"中华人民共和国民法典","article_number":"第五百七十七条","article_title":null,"snippet":"当事人一方不履行合同义务的，应当承担违约责任。","citation_id":"law-secret","effective_from":"2021-01-01","effective_to":null,"version_status":"in_force","score":0.88}],
                    "warnings":[]
                }),
            ),
            (
                "legal_get_article",
                json!({
                    "schema_version":1,
                    "database_version":"secret",
                    "article":{"article_id":"article-secret","document_id":"doc-secret","version_id":"version-secret","document_title":"中华人民共和国民法典","version_label":"现行版本","article_number":"第五百七十七条","article_title":null,"content":"当事人一方不履行合同义务的，应当承担违约责任。","citation_id":"law-secret","canonical_label":"《中华人民共和国民法典》第五百七十七条","effective_from":"2021-01-01","effective_to":null,"version_status":"in_force","topics":["合同责任"]},
                    "warnings":[]
                }),
            ),
            (
                "legal_get_versions",
                json!({
                    "schema_version":1,
                    "database_version":"secret",
                    "versions":[{"version_id":"version-secret","document_id":"doc-secret","version_label":"现行版本","status":"in_force","effective_from":"2021-01-01","effective_to":null,"published_on":"2020-05-28","source_reference":"https://private.example","article_count":1260}],
                    "warnings":[]
                }),
            ),
            (
                "legal_get_relations",
                json!({
                    "schema_version":1,
                    "database_version":"secret",
                    "relations":[{"relation_id":"relation-secret","from_document_id":"doc-secret","from_title":"中华人民共和国民法典","to_document_id":"target-secret","to_title":"中华人民共和国合同法","relation_type":"repeals","description":"该法施行后相关旧法同时废止。","source_reference":"C:\\private\\source.json"}],
                    "warnings":[]
                }),
            ),
            (
                "citation_validate",
                json!({
                    "schema_version":1,
                    "database_version":"secret",
                    "report":{"citations":[{"raw_marker":"[SRC:law-secret]","source_id":"law-secret","status":"valid","source":{"article_id":"article-secret"}}],"valid_count":1,"invalid_count":0,"unsupported_legal_conclusion":false,"semantic_support_verified":false},
                    "warnings":["semantic_support_not_verified"]
                }),
            ),
            (
                "case_get_state",
                json!({
                    "schema_version":1,
                    "revision":"a".repeat(64),
                    "page":0,
                    "page_size":50,
                    "has_more":false,
                    "counts":{"files":1,"parties":1,"facts":1,"evidence":1,"evidence_links":1,"fact_issue_links":0,"legal_issues":1,"legal_basis":1,"uncertainties":1,"gaps":1},
                    "workspace":{
                        "project":{"project_id":"project-secret","title":"service-deadbeef-1","case_type":"民事案件","status":"active","opened_on":"2026-07-17","summary":"fileId=file-secret","created_at":"2026-07-17","updated_at":"2026-07-17"},
                        "files":[{"file_id":"file-secret","project_id":"project-secret","title":"买卖合同","file_type":"合同","storage_reference":"C:\\private\\contract.pdf","summary":"载明交付期限。","created_at":"2026-07-17"}],
                        "parties":[{"party_id":"party-secret","project_id":"project-secret","name":"甲公司","normalized_name":"甲公司","role":"plaintiff","contact":"","notes":""}],
                        "facts":[{"fact_id":"fact-secret","project_id":"project-secret","occurred_on":"2025-01-02","title":"签订合同","description":"双方约定交付期限。","source":"当事人陈述","confirmation_status":"confirmed"}],
                        "evidence":[{"evidence_id":"evidence-secret","project_id":"project-secret","evidence_number":"证据一","title":"买卖合同","source":"甲公司提交","formed_on":"2025-01-02","summary":"载明交付期限。","storage_reference":"file://private","confirmation_status":"confirmed"}],
                        "evidence_links":[{"link_id":"link-secret","project_id":"project-secret","fact_id":"fact-secret","evidence_id":"evidence-secret"}],
                        "fact_issue_links":[],
                        "legal_issues":[{"issue_id":"issue-secret","project_id":"project-secret","title":"是否逾期交付","description":"审查交付期限。","claim":"请求承担违约责任。","status":"open","confirmation_status":"confirmed"}],
                        "legal_basis":[{"basis_id":"basis-secret","project_id":"project-secret","source_id":"law-secret","article_id":"article-secret","document_id":"doc-secret","version_id":"version-secret","document_title":"中华人民共和国民法典","article_number":"第五百七十七条","article_title":null,"effective_from":"2021-01-01","effective_to":null,"excerpt":"不履行合同义务的，应当承担违约责任。","note":"适用于违约责任认定。"}],
                        "uncertainties":[{"uncertainty_id":"uncertainty-secret","project_id":"project-secret","description":"交付通知送达时间尚待核对。","related_entity_type":"fact","related_entity_id":"fact-secret","source_file_ids":["file-secret"],"status":"open","resolution":""}],
                        "gaps":[{"gap_id":"gap-secret","project_id":"project-secret","entity_id":"fact-secret","kind":"fact_missing_evidence","severity":"blocking","message":"internal fact-secret"}]
                    }
                }),
            ),
            (
                "case_propose_patch",
                json!({
                    "schema_version":1,
                    "proposal_id":"proposal-secret",
                    "canonical_proposal":canonical_proposal,
                    "proposal_hash":"c".repeat(64),
                    "base_revision":"a".repeat(64),
                    "confidence":0.87,
                    "uncertainties":["交付日期尚待核对。"]
                }),
            ),
            (
                "case_apply_patch",
                json!({"schema_version":1,"audit_id":"audit-secret","proposal_hash":"c".repeat(64),"previous_revision":"a".repeat(64),"revision":"b".repeat(64),"applied":true,"replayed":false}),
            ),
            (
                "case_analyze_gaps",
                json!({"schema_version":1,"revision":"a".repeat(64),"gaps":[{"gap_id":"gap-secret","project_id":"project-secret","entity_id":"fact-secret","kind":"fact_missing_evidence","severity":"blocking","message":"internal fact-secret"}]}),
            ),
            (
                "document_generate",
                json!({
                    "schema_version":1,
                    "project_id":"project-secret",
                    "case_revision":"a".repeat(64),
                    "generation_hash":"b".repeat(64),
                    "document":{"title":"民事起诉状","sections":[{"heading":"诉讼请求","paragraphs":["判令被告承担违约责任。"],"source_ids":["fact-secret"]}],"tables":[],"citations":[{"kind":"law","title":"中华人民共和国民法典","locator":"第五百七十七条","effective_or_decided_on":"2021-01-01","source_id":"law-secret","document_id":"doc-secret","version_id":"version-secret","article_id":"article-secret","excerpt":"不履行合同义务的，应当承担违约责任。"}],"markdown":"raw-secret"},
                    "warnings":[]
                }),
            ),
            (
                "document_export",
                json!({"schema_version":1,"audit_id":"audit-secret","record_id":"record-secret","project_id":"project-secret","case_revision":"a".repeat(64),"generation_hash":"b".repeat(64),"export_path":"C:\\private\\complaint.docx","format":"docx","media_type":"application/secret","byte_len":1024,"sha256":"c".repeat(64),"replayed":false}),
            ),
        ];

        assert_eq!(fixtures.len(), 12);
        for (tool, raw) in fixtures {
            let text = success_text(tool, &raw);
            let public = success_structured_content(tool, &raw, &text);
            assert_eq!(public["结果"], "已完成", "{tool}: {public:#}");
            assert!(public["说明"]
                .as_str()
                .is_some_and(|value| !value.is_empty()));
            assert_public_boundary(&public, tool);
            assert!(
                !contains_internal_detail(&text),
                "{tool} content leaked: {text}"
            );
        }
    }

    #[test]
    fn error_dto_contains_only_a_public_chinese_message() {
        for code in [
            "invalid_request",
            "not_found",
            "revision_conflict",
            "confirmation_required",
            "database_error",
            "output_path_rejected",
            "internal_contract_error",
        ] {
            let public = error_structured_content(code);
            assert_eq!(public["结果"], "未完成");
            assert!(public["内容"].is_null());
            assert_public_boundary(&public, code);
            let wire = serde_json::to_string(&public).expect("public error serializes");
            assert!(!wire.contains(code));
            assert!(!wire.contains("诊断"));
        }
    }

    #[test]
    fn legacy_polluted_case_title_and_summary_degrade_without_leaking() {
        let raw = json!({
            "counts":{"parties":0,"facts":0,"evidence":0,"legal_issues":0,"legal_basis":0,"gaps":0},
            "has_more":false,
            "workspace":{
                "project":{
                    "title":"service-deadbeef-1",
                    "case_type":"民事案件",
                    "status":"active",
                    "opened_on":"2026-07-17",
                    "summary":"fileId=file-secret; C:\\private\\case.json"
                },
                "files":[],"parties":[],"facts":[],"evidence":[],"legal_issues":[],
                "legal_basis":[],"uncertainties":[],"gaps":[]
            }
        });
        let text = success_text("case_get_state", &raw);
        let public = success_structured_content("case_get_state", &raw, &text);
        assert!(text.contains("当前案件"));
        assert_eq!(public["内容"]["案件概况"]["案件名称"], "当前案件");
        assert!(public["内容"]["案件概况"].get("案情摘要").is_none());
        assert_public_boundary(&public, "legacy polluted case");
    }

    fn assert_public_boundary(value: &Value, context: &str) {
        let top = value.as_object().expect("public result object");
        assert_eq!(
            top.keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["内容", "提示", "结果", "说明"].into_iter().collect(),
            "{context}"
        );
        walk_public_value(value, context);
        let wire = serde_json::to_string(value).expect("public result serializes");
        for forbidden in [
            "-secret",
            "secret.",
            "C:\\\\",
            "file://",
            "https://",
            "[SRC:",
            "service-deadbeef",
            "raw-secret",
        ] {
            assert!(
                !wire.contains(forbidden),
                "{context} leaked {forbidden}: {wire}"
            );
        }
    }

    fn walk_public_value(value: &Value, context: &str) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let lower = key.to_ascii_lowercase();
                    for forbidden in [
                        "id", "hash", "revision", "schema", "protocol", "request", "score",
                        "snippet", "path", "endpoint", "raw", "cursor", "meta",
                    ] {
                        assert!(
                            !lower.contains(forbidden),
                            "{context} exposed machine key {key}"
                        );
                    }
                    walk_public_value(value, context);
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk_public_value(value, context);
                }
            }
            Value::String(text) => {
                assert!(
                    !contains_internal_detail(text),
                    "{context} exposed internal text: {text}"
                );
            }
            _ => {}
        }
    }
}
