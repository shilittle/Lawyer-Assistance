use serde_json::{json, Map, Value};

const MAX_TEXT: usize = 128 * 1024;
const MAX_ITEMS: usize = 50;

/// Project legal-service responses to the stable, public MCP envelope.  The
/// projection is deliberately limited to legal titles, provisions, dates,
/// and source-facing metadata; opaque identifiers and storage metadata never
/// cross this adapter.
pub(crate) fn success_text(tool_name: &str, data: &Value) -> String {
    let text = match tool_name {
        "system_status" => {
            if bool_at(data, &["legal_database", "available"]) {
                "本地法律数据库可用。".to_owned()
            } else {
                "本地法律数据库暂时不可用。".to_owned()
            }
        }
        "legal_search" => format!(
            "检索到 {} 部相关法律和 {} 条相关条文。",
            array_at(data, &["laws"]).len(),
            array_at(data, &["articles"]).len()
        ),
        "legal_get_article" => article_text(data),
        "legal_get_versions" => {
            format!("找到 {} 个法律版本。", array_at(data, &["versions"]).len())
        }
        "legal_get_relations" => {
            format!("找到 {} 项法规关联。", array_at(data, &["relations"]).len())
        }
        _ => "操作已完成。".to_owned(),
    };
    bounded(text)
}

pub(crate) fn success_structured_content(
    tool_name: &str,
    data: &Value,
    public_text: &str,
) -> Value {
    let content = match tool_name {
        "system_status" => status_content(data),
        "legal_search" => search_content(data),
        "legal_get_article" => article_content(data),
        "legal_get_versions" => versions_content(data),
        "legal_get_relations" => relations_content(data),
        _ => Value::Null,
    };
    object([
        ("结果", Value::String("已完成".to_owned())),
        ("说明", Value::String(bounded(public_text.to_owned()))),
        ("内容", content),
        ("提示", Value::Array(Vec::new())),
    ])
}

pub(crate) fn error_structured_content(code: &str) -> Value {
    object([
        ("结果", Value::String("未完成".to_owned())),
        ("说明", Value::String(error_message(code).to_owned())),
        ("内容", Value::Null),
        ("提示", Value::Array(Vec::new())),
    ])
}

pub(crate) fn error_message(code: &str) -> &'static str {
    match code {
        "invalid_request" | "unsupported_schema_version" => "请求参数不符合工具契约。",
        "legal_database_missing" | "legal_database_incompatible" => "本地法律数据库暂时不可用。",
        "not_found" => "未找到对应的公开法律资料。",
        "sensitive_content_blocked" => "结果未通过本地内容安全检查。",
        _ => "请求未完成，请检查本地服务状态后重试。",
    }
}

fn status_content(data: &Value) -> Value {
    object([
        (
            "法规检索",
            Value::String(if bool_at(data, &["legal_database", "available"]) {
                "可用".to_owned()
            } else {
                "暂不可用".to_owned()
            }),
        ),
        ("用户工作区", Value::String("不适用".to_owned())),
    ])
}

fn search_content(data: &Value) -> Value {
    let laws = array_at(data, &["laws"])
        .iter()
        .take(MAX_ITEMS)
        .map(|law| {
            object([
                ("法律名称", string_value(law, "title", 200)),
                ("文件类型", string_value(law, "document_type", 80)),
                ("制定机关", string_value(law, "authority_name", 160)),
                ("效力层级", string_value(law, "effectiveness_level", 80)),
                ("效力状态", status_value(law, "status")),
                ("施行日期", string_value(law, "current_effective_from", 32)),
                ("终止日期", string_value(law, "current_effective_to", 32)),
                ("内容摘要", string_value(law, "summary", 1000)),
            ])
        })
        .collect();
    let articles = array_at(data, &["articles"])
        .iter()
        .take(MAX_ITEMS)
        .map(|article| {
            object([
                ("法律名称", string_value(article, "document_title", 200)),
                ("条文", string_value(article, "article_number", 64)),
                ("条文名称", string_value(article, "article_title", 160)),
                ("施行日期", string_value(article, "effective_from", 32)),
                ("终止日期", string_value(article, "effective_to", 32)),
                ("效力状态", status_value(article, "version_status")),
                ("内容摘要", string_value(article, "snippet", 1000)),
            ])
        })
        .collect();
    object([
        ("相关法律", Value::Array(laws)),
        ("相关条文", Value::Array(articles)),
    ])
}

fn article_content(data: &Value) -> Value {
    let article = data.get("article").unwrap_or(&Value::Null);
    object([
        ("法律名称", string_value(article, "document_title", 200)),
        ("版本名称", string_value(article, "version_label", 160)),
        ("条文", string_value(article, "article_number", 64)),
        ("条文名称", string_value(article, "article_title", 160)),
        ("条文内容", string_value(article, "content", MAX_TEXT)),
        ("施行日期", string_value(article, "effective_from", 32)),
        ("终止日期", string_value(article, "effective_to", 32)),
        ("效力状态", status_value(article, "version_status")),
        ("主题", string_array(article, "topics", 120)),
    ])
}

fn versions_content(data: &Value) -> Value {
    Value::Array(
        array_at(data, &["versions"])
            .iter()
            .take(MAX_ITEMS)
            .map(|version| {
                object([
                    ("版本名称", string_value(version, "version_label", 160)),
                    ("效力状态", status_value(version, "status")),
                    ("施行日期", string_value(version, "effective_from", 32)),
                    ("终止日期", string_value(version, "effective_to", 32)),
                    ("公布日期", string_value(version, "published_on", 32)),
                    (
                        "条文数量",
                        version
                            .get("article_count")
                            .cloned()
                            .filter(Value::is_number)
                            .unwrap_or_else(|| json!(0)),
                    ),
                ])
            })
            .collect(),
    )
}

fn relations_content(data: &Value) -> Value {
    Value::Array(
        array_at(data, &["relations"])
            .iter()
            .take(MAX_ITEMS)
            .map(|relation| {
                object([
                    ("相关法律", string_value(relation, "from_title", 200)),
                    (
                        "关系",
                        relation_value(relation.get("relation_type").and_then(Value::as_str)),
                    ),
                    ("目标法律", string_value(relation, "to_title", 200)),
                    ("说明", string_value(relation, "description", 1000)),
                ])
            })
            .collect(),
    )
}

fn article_text(data: &Value) -> String {
    let article = data.get("article").unwrap_or(&Value::Null);
    let title = limited(
        article
            .get("document_title")
            .and_then(Value::as_str)
            .unwrap_or("相关法律"),
        200,
    );
    let number = limited(
        article
            .get("article_number")
            .and_then(Value::as_str)
            .unwrap_or(""),
        64,
    );
    let content = limited(
        article.get("content").and_then(Value::as_str).unwrap_or(""),
        MAX_TEXT,
    );
    if number.is_empty() {
        format!("《{title}》\n{content}")
    } else {
        format!("《{title}》{number}\n{content}")
    }
}

fn bool_at(value: &Value, path: &[&str]) -> bool {
    path.iter()
        .try_fold(value, |current, field| current.get(*field))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> &'a [Value] {
    path.iter()
        .try_fold(value, |current, field| current.get(*field))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string_value(value: &Value, field: &str, max: usize) -> Value {
    Value::String(limited(
        value.get(field).and_then(Value::as_str).unwrap_or(""),
        max,
    ))
}

fn string_array(value: &Value, field: &str, max: usize) -> Value {
    Value::Array(
        value
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(MAX_ITEMS)
            .map(|item| Value::String(limited(item, max)))
            .collect(),
    )
}

fn status_value(value: &Value, field: &str) -> Value {
    Value::String(
        match value.get(field).and_then(Value::as_str).unwrap_or("") {
            "in_force" => "现行有效",
            "not_yet_effective" => "尚未施行",
            "repealed" | "invalid" => "已失效",
            _ => "状态待核对",
        }
        .to_owned(),
    )
}

fn relation_value(value: Option<&str>) -> Value {
    Value::String(
        match value.unwrap_or("") {
            "amends" => "修订",
            "repeals" => "废止",
            "cites" => "引用",
            "implements" => "实施",
            _ => "关联",
        }
        .to_owned(),
    )
}

fn object<'a>(pairs: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<Map<_, _>>(),
    )
}

fn limited(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(max)
        .collect()
}

fn bounded(value: String) -> String {
    limited(&value, MAX_TEXT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_legal_projection_drops_identifiers_and_paths() {
        let data = json!({"article":{"article_id":"secret","document_title":"中华人民共和国民法典","article_number":"第五百七十七条","content":"应承担违约责任。","source":"C:\\\\secret"}});
        let text = success_text("legal_get_article", &data);
        let output = success_structured_content("legal_get_article", &data, &text);
        let wire = serde_json::to_string(&output).expect("JSON");
        assert!(text.contains("第五百七十七条"));
        assert!(!wire.contains("article_id"));
        assert!(!wire.contains("C:\\\\secret"));
    }

    #[test]
    fn error_has_no_internal_code_or_details() {
        let error = error_structured_content("database_path_rejected");
        let wire = serde_json::to_string(&error).expect("JSON");
        assert_eq!(error["结果"], "未完成");
        assert!(!wire.contains("database_path_rejected"));
    }
}
