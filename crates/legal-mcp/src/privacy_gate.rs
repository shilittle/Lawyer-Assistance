use regex::RegexSet;
use serde_json::Value;
use std::sync::LazyLock;
/// Conservative phase-one scanner at the final MCP boundary.
///
/// This is not the product redaction engine. It scans the exact model-visible
/// text and structured JSON after projection. A match blocks the whole result;
/// source text is never returned or logged.
static SENSITIVE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?:^|[^0-9A-Za-z])[1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx](?:[^0-9A-Za-z]|$)",
        r"(?:^|[^0-9A-Za-z])[1-9][0-9]{5}[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}(?:[^0-9A-Za-z]|$)",
        r"(?:^|[^0-9])(?:\+?86[\s-]?)?1[3-9](?:[\s-]?[0-9]){9}(?:[^0-9]|$)",
        r"(?i)(?:^|[^A-Z0-9._%+\-])[A-Z0-9._%+\-]{1,64}@[A-Z0-9.\-]{1,253}\.[A-Z]{2,63}(?:[^A-Z0-9._%+\-]|$)",
        r"(?:^|[^0-9])[0-9](?:[\s-]?[0-9]){15,18}(?:[^0-9]|$)",
        r#"(?:银行卡号|银行账户|收款账户|账号|账户|卡号)[\"'\s]*[:：=为][\"'\s]*[0-9](?:[\s-]?[0-9]){5,29}"#,
        r#"(?:姓名|原告|被告|申请人|被申请人|联系人|委托人|法定代表人|负责人)[\"'\s]*[:：=为][\"'\s]*[\p{Han}·]{2,12}"#,
        r#"(?:住址|家庭地址|联系地址|户籍地址|户籍地|住所地|地址)[\"'\s]*[:：=为][\"'\s]*[\p{Han}A-Za-z0-9#号栋单元室路街巷镇乡村区县市省自治区特别行政区\-]{6,96}"#,
        r#"(?:护照号|护照号码)[\"'\s]*[:：=为][\"'\s]*[A-Za-z][A-Za-z0-9]{6,17}"#,
    ])
    .expect("phase-one privacy patterns are valid")
});

pub(crate) fn model_visible_output_is_safe(text: &str, structured: &Value) -> bool {
    if SENSITIVE_PATTERNS.is_match(text) {
        return false;
    }
    let Ok(serialized) = serde_json::to_vec(structured) else {
        return false;
    };
    if SENSITIVE_PATTERNS.is_match(std::str::from_utf8(&serialized).unwrap_or_default()) {
        return false;
    }
    privacy::scan_residual(text.as_bytes()).is_ok_and(|scan| scan.passed)
        && privacy::scan_residual(&serialized).is_ok_and(|scan| scan.passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_high_risk_values_in_either_result_channel() {
        for value in [
            "原告：张三",
            "身份证号 11010519491231002X",
            "联系电话 +86 138-0013-8000",
            "邮箱 alice.case@example.com",
            "银行卡号：6222 0202 0000 0000 000",
            "住址：北京市朝阳区测试路88号",
            "护照号码：E12345678",
        ] {
            assert!(
                !model_visible_output_is_safe(value, &json!({"结果":"已完成"})),
                "{value}"
            );
            assert!(
                !model_visible_output_is_safe("安全文本", &json!({"内容":value})),
                "{value}"
            );
        }
    }

    #[test]
    fn ordinary_public_statutory_text_remains_available() {
        let text = "《中华人民共和国民法典》第四百六十五条：依法成立的合同，受法律保护。当事人应当按照约定履行义务。";
        let structured = json!({
            "结果":"已完成",
            "说明":text,
            "内容":{"法律名称":"中华人民共和国民法典","条文":"第四百六十五条"},
            "提示":[]
        });
        assert!(model_visible_output_is_safe(text, &structured));
    }
}
