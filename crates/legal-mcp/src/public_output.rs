use regex::RegexSet;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;
use url::Url;

const MAX_TEXT: usize = 128 * 1024;
const MAX_ITEMS: usize = 50;

static CREDENTIAL_VALUE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\bbearer\s+[a-z0-9._~+/-]{16,}",
        r"(?i)\b(?:api[_ -]?key|client[_ -]?secret|credential|password)\s*[:=]\s*[^\s]{8,}",
        r"(?i)\bauthorization\s*[:=]\s*bearer\s+[^\s]{8,}",
    ])
    .expect("credential patterns are valid")
});

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
        "legal_search_cases" => {
            format!(
                "检索到 {} 个相关最高人民法院案例。",
                array_at(data, &["cases"]).len()
            )
        }
        "legal_get_case" => "已读取来源可追溯的最高人民法院案例全文。".to_owned(),
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
        "legal_search_cases" => case_search_content(data),
        "legal_get_case" => case_content(data),
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
        "case_output_blocked" => "案例结果未通过公开来源与输出边界核验。",
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

fn case_search_content(data: &Value) -> Value {
    let cases = array_at(data, &["cases"])
        .iter()
        .take(MAX_ITEMS)
        .filter(|case| official_case_source(case.get("source_url").and_then(Value::as_str)))
        .map(case_summary_content)
        .collect();
    object([
        (
            "匹配总数",
            data.get("total")
                .cloned()
                .filter(Value::is_number)
                .unwrap_or_else(|| json!(0)),
        ),
        ("本页数量", json!(array_at(data, &["cases"]).len())),
        ("数据库版本", string_value(data, "database_version", 256)),
        ("提示", string_array(data, "warnings", 256)),
        ("案例", Value::Array(cases)),
    ])
}

fn case_content(data: &Value) -> Value {
    let case = data.get("case").unwrap_or(&Value::Null);
    if !official_case_source(case.get("source_url").and_then(Value::as_str)) {
        return Value::Null;
    }
    object([
        ("数据库版本", string_value(data, "database_version", 256)),
        ("提示", string_array(data, "warnings", 256)),
        ("案例", case_summary_content(case)),
        ("裁判要点", string_array(case, "key_points", 1000)),
        ("基本案情", string_value(case, "basic_facts", MAX_TEXT)),
        ("裁判结果", string_value(case, "judgment_result", MAX_TEXT)),
        ("裁判理由", string_value(case, "reasoning", MAX_TEXT)),
        ("相关法条", string_array(case, "related_laws", 1000)),
        ("案例全文", string_value(case, "full_text", MAX_TEXT)),
        ("抓取时间", string_value(case, "fetched_at", 64)),
    ])
}

fn case_summary_content(case: &Value) -> Value {
    object([
        ("案例编号", string_value(case, "case_id", 128)),
        ("标题", string_value(case, "title", 512)),
        (
            "案例类型",
            Value::String(
                match case.get("case_type").and_then(Value::as_str) {
                    Some("guiding") => "指导案例",
                    Some("reference") => "参考案例",
                    Some("typical") => "典型案例合集",
                    _ => "案例",
                }
                .to_owned(),
            ),
        ),
        (
            "指导案例号",
            case.get("guiding_number")
                .cloned()
                .filter(Value::is_number)
                .unwrap_or(Value::Null),
        ),
        ("参考案例号", string_value(case, "reference_number", 256)),
        ("关键词", string_array(case, "keywords", 256)),
        ("发布日期", string_value(case, "publication_date", 64)),
        ("审理法院", string_value(case, "court", 512)),
        ("案号", string_value(case, "case_number", 512)),
        ("状态", string_value(case, "status", 64)),
        ("官方来源", string_value(case, "source_url", 2048)),
        ("命中内容", string_value(case, "matched_text", 1500)),
    ])
}

/// The services layer verifies this again while decoding database rows. This
/// projection-side check prevents a future adapter bypass from making a
/// non-official URL or arbitrary text model-visible.
pub(crate) fn verified_case_output_is_safe(tool_name: &str, data: &Value) -> bool {
    let evidence_valid = match tool_name {
        "legal_search_cases" => array_at(data, &["cases"])
            .iter()
            .all(|case| official_case_source(case.get("source_url").and_then(Value::as_str))),
        "legal_get_case" => official_case_source(
            data.get("case")
                .and_then(|case| case.get("source_url"))
                .and_then(Value::as_str),
        ),
        _ => false,
    };
    evidence_valid && no_internal_case_data(data)
}

fn no_internal_case_data(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            let key = key.to_ascii_lowercase();
            let forbidden_key = key != "source_url"
                && [
                    "path",
                    "filename",
                    "file_name",
                    "diagnostic",
                    "stack",
                    "trace",
                    "credential",
                    "secret",
                    "token",
                    "authorization",
                    "api_key",
                    "password",
                    "workspace",
                    "raw",
                ]
                .iter()
                .any(|forbidden| key.contains(forbidden));
            !forbidden_key && no_internal_case_data(value)
        }),
        Value::Array(items) => items.iter().all(no_internal_case_data),
        Value::String(text) => {
            !local_path_in_text(text) && !CREDENTIAL_VALUE_PATTERNS.is_match(text)
        }
        _ => true,
    }
}

fn local_path_in_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    bytes.windows(3).enumerate().any(|(index, window)| {
        (index == 0 || !bytes[index - 1].is_ascii_alphabetic())
            && window[0].is_ascii_alphabetic()
            && window[1] == b':'
            && matches!(window[2], b'\\' | b'/')
    }) || text.contains("\\\\")
        || lower.contains("file://")
        || ["/home/", "/users/", "/data/", "/private/", "/var/", "/tmp/"]
            .iter()
            .any(|prefix| lower.contains(prefix))
}

fn official_case_source(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some(
                "court.gov.cn"
                    | "www.court.gov.cn"
                    | "gongbao.court.gov.cn"
                    | "rmfyalk.court.gov.cn"
                    | "ipc.court.gov.cn"
                    | "hnlyzy.hncourt.gov.cn"
            )
        )
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
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

    #[test]
    fn official_case_evidence_does_not_whitelist_paths_or_credentials() {
        let case = json!({
            "case": {"source_url":"https://www.court.gov.cn/shenpan/1.html", "full_text":"原告：张三"}
        });
        assert!(verified_case_output_is_safe("legal_get_case", &case));
        for unsafe_text in [
            "D:\\workspace\\private.txt",
            "Authorization: Bearer test-secret-value-1234",
            "file:///data/private.txt",
        ] {
            let case = json!({
                "case": {"source_url":"https://www.court.gov.cn/shenpan/1.html", "full_text":unsafe_text}
            });
            assert!(
                !verified_case_output_is_safe("legal_get_case", &case),
                "{unsafe_text}"
            );
        }
    }

    #[test]
    fn case_search_projection_keeps_pagination_and_dataset_context() {
        let data = json!({
            "total": 82,
            "database_version": "spc-cases-v1",
            "warnings": ["withdrawn_cases_excluded"],
            "cases": [{
                "case_id":"spc-guiding-1", "title":"指导案例", "case_type":"guiding",
                "guiding_number":1, "keywords":[], "status":"published",
                "source_url":"https://www.court.gov.cn/shenpan/1.html", "matched_text":"劳动关系"
            }]
        });
        let content = case_search_content(&data);
        assert_eq!(content["匹配总数"], 82);
        assert_eq!(content["本页数量"], 1);
        assert_eq!(content["数据库版本"], "spc-cases-v1");
        assert_eq!(content["案例"][0]["案例编号"], "spc-guiding-1");
    }
}
