use std::collections::BTreeSet;

use assistant::{parse_public_citation, PublicCitationKind};

pub(super) fn render_research_markdown(
    title: &str,
    answer: &str,
    assumptions: &[String],
    missing_information: &[String],
    risk_warnings: &[String],
) -> String {
    let mut output = format!(
        "# {}\n\n> 本研究结果依据现有材料整理，具体法律结论应结合完整事实、证据和有效法律规范审慎核定。\n\n{}",
        escape_markdown_text(title),
        escape_markdown_text(answer)
    );
    append_list(&mut output, "待确认假设", assumptions);
    append_list(&mut output, "缺失信息", missing_information);
    append_list(&mut output, "风险提示", risk_warnings);
    append_reference_table(&mut output, answer);
    output
}

fn append_list(output: &mut String, heading: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    output.push_str(&format!("\n\n## {heading}\n"));
    for item in items {
        output.push_str(&format!("\n- {}", escape_markdown_text(item)));
    }
}

fn append_reference_table(output: &mut String, answer: &str) {
    output.push_str(
        "\n\n## 法律依据与案例引用表\n\n| 类型 | 法律或案例名称 | 条款或案号 | 施行或裁判年份 | 引用说明 |\n| --- | --- | --- | --- | --- |\n",
    );
    let citations = collect_public_citations(answer);
    if citations.is_empty() {
        output.push_str("| 未引用 | 本文未列明经核对的法律或案例依据 | — | — | — |\n");
        return;
    }
    for citation in citations {
        let Some(parts) = parse_public_citation(&citation) else {
            continue;
        };
        let (kind, title, locator, year) = match parts.kind {
            PublicCitationKind::Law => (
                "法条",
                format!("《{}》", parts.title),
                parts.locator.to_owned(),
                format!("{}年起施行", parts.year),
            ),
            PublicCitationKind::JudicialCase => (
                "案例",
                parts.title.to_owned(),
                format!("案号：{}", parts.locator),
                format!("{}年裁判", parts.year),
            ),
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | 支持正文所列法律结论 |\n",
            escape_table_cell(kind),
            escape_table_cell(&title),
            escape_table_cell(&locator),
            escape_table_cell(&year),
        ));
    }
}

fn collect_public_citations(value: &str) -> Vec<String> {
    let mut citations = BTreeSet::new();
    collect_law_citations(value, &mut citations);
    collect_case_citations(value, &mut citations);
    citations.into_iter().collect()
}

fn collect_law_citations(value: &str, citations: &mut BTreeSet<String>) {
    let suffix = "年起施行）";
    let mut search_from = 0;
    while let Some(relative_start) = value[search_from..].find('《') {
        let start = search_from + relative_start;
        let Some(relative_end) = value[start..].find(suffix) else {
            break;
        };
        let end = start + relative_end + suffix.len();
        let candidate = &value[start..end];
        if parse_public_citation(candidate)
            .is_some_and(|parts| parts.kind == PublicCitationKind::Law)
        {
            citations.insert(candidate.to_owned());
        }
        search_from = start + '《'.len_utf8();
    }
}

fn collect_case_citations(value: &str, citations: &mut BTreeSet<String>) {
    let marker = "（案号：";
    let suffix = "年裁判）";
    let mut search_from = 0;
    while let Some(relative_marker) = value[search_from..].find(marker) {
        let marker_start = search_from + relative_marker;
        let Some(relative_end) = value[marker_start..].find(suffix) else {
            break;
        };
        let end = marker_start + relative_end + suffix.len();
        let title_start = value[..marker_start]
            .char_indices()
            .rev()
            .find_map(|(index, character)| {
                matches!(
                    character,
                    '。' | '！' | '？' | '；' | '：' | '，' | '、' | '\n' | '\r' | '\t'
                )
                .then_some(index + character.len_utf8())
            })
            .unwrap_or(0);
        let candidate = value[title_start..end]
            .trim()
            .trim_start_matches("参见")
            .trim_start_matches('见')
            .trim();
        if parse_public_citation(candidate)
            .is_some_and(|parts| parts.kind == PublicCitationKind::JudicialCase)
        {
            citations.insert(candidate.to_owned());
        }
        search_from = marker_start + marker.len();
    }
}

fn escape_markdown_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_table_cell(value: &str) -> String {
    escape_markdown_text(value)
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_delivery_ends_with_deduplicated_public_reference_table() {
        let answer = "违约方应承担违约责任。《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）\n参见张某与甲公司买卖合同纠纷案（案号：（2025）京01民终1234号；2025年裁判）。再次引用《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）";
        let rendered = render_research_markdown("合同履行研究", answer, &[], &[], &[]);
        assert_eq!(rendered.matches("第五百七十七条第一款").count(), 3);
        assert_eq!(rendered.matches("案号：（2025）京01民终1234号").count(), 2);
        assert!(rendered.ends_with("| 案例 | 张某与甲公司买卖合同纠纷案 | 案号：（2025）京01民终1234号 | 2025年裁判 | 支持正文所列法律结论 |\n"));
        for forbidden in ["sourceRef", "article_id", "schemaVersion", "[SRC:"] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    fn research_delivery_still_ends_with_reference_table_when_no_citation_exists() {
        let rendered = render_research_markdown(
            "待补充研究",
            "现有资料不足，尚不能形成法律结论。",
            &[],
            &[],
            &[],
        );
        assert!(rendered.ends_with("| 未引用 | 本文未列明经核对的法律或案例依据 | — | — | — |\n"));
    }
}
