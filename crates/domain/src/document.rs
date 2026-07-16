use crate::{
    case::{analyze_case_gaps, CaseWorkspace, ConfirmationStatus, PartyRole},
    qa::CitationStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentTemplateId {
    Complaint,
    Defence,
    EvidenceSchedule,
    FactTimeline,
    LegalResearchReport,
    LawyerLetter,
}

impl DocumentTemplateId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complaint => "complaint",
            Self::Defence => "defence",
            Self::EvidenceSchedule => "evidence_schedule",
            Self::FactTimeline => "fact_timeline",
            Self::LegalResearchReport => "legal_research_report",
            Self::LawyerLetter => "lawyer_letter",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTemplateMetadata {
    pub template_id: DocumentTemplateId,
    pub name: String,
    pub scenario: String,
    pub required_fields: Vec<String>,
    pub optional_fields: Vec<String>,
    pub citation_policy: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentField {
    pub key: String,
    pub value: String,
    pub source_kind: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSection {
    pub heading: String,
    pub level: u8,
    pub paragraphs: Vec<String>,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTableRow {
    pub cells: Vec<String>,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTable {
    /// Matches the heading of the section that owns this table. Keeping the
    /// relationship explicit lets Markdown, DOCX and future exporters retain
    /// the same content order without inferring structure from prose.
    pub section_heading: String,
    pub headers: Vec<String>,
    /// Fixed Word table geometry. Every generated table is exactly 9360 DXA,
    /// the usable width of the selected `standard_business_brief` preset.
    pub column_widths_dxa: Vec<u32>,
    pub rows: Vec<DocumentTableRow>,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentCitation {
    pub source_id: String,
    pub canonical_label: String,
    pub excerpt: String,
    pub document_id: String,
    pub version_id: String,
    pub article_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedDocument {
    pub template: DocumentTemplateMetadata,
    pub title: String,
    pub fields: Vec<DocumentField>,
    pub sections: Vec<DocumentSection>,
    #[serde(default)]
    pub tables: Vec<DocumentTable>,
    pub citations: Vec<DocumentCitation>,
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentValidationError {
    pub code: String,
    pub missing_fields: Vec<String>,
    pub invalid_citation_ids: Vec<String>,
}

pub fn template_catalog() -> Vec<DocumentTemplateMetadata> {
    use DocumentTemplateId::*;
    [
        (
            Complaint,
            "民事起诉状",
            "代表原告提起民事诉讼",
            vec!["plaintiff", "defendant", "claims", "facts"],
        ),
        (
            Defence,
            "民事答辩状",
            "代表被告回应诉讼请求",
            vec!["defendant", "plaintiff", "claims", "facts"],
        ),
        (
            EvidenceSchedule,
            "证据目录",
            "整理证据及证明目的",
            vec!["evidence"],
        ),
        (
            FactTimeline,
            "案件事实时间线",
            "按日期复核案件事实",
            vec!["dated_facts"],
        ),
        (
            LegalResearchReport,
            "法律检索报告",
            "汇总争点与已校验法律依据",
            vec!["issues", "valid_citations"],
        ),
        (
            LawyerLetter,
            "律师函",
            "向相对方正式陈述事实和要求",
            vec!["sender", "recipient", "claims", "facts"],
        ),
    ]
    .into_iter()
    .map(
        |(template_id, name, scenario, required)| DocumentTemplateMetadata {
            template_id,
            name: name.to_owned(),
            scenario: scenario.to_owned(),
            required_fields: required.into_iter().map(str::to_owned).collect(),
            optional_fields: vec!["case_date".to_owned(), "model_draft".to_owned()],
            citation_policy: "仅插入案件中已校验且状态为 valid 的本地法律引用".to_owned(),
            version: "2.0.0".to_owned(),
        },
    )
    .collect()
}

pub fn validate_document(
    workspace: &CaseWorkspace,
    template_id: DocumentTemplateId,
) -> Result<(), DocumentValidationError> {
    let workspace = confirmed_workspace(workspace);
    validate_confirmed_document(&workspace, template_id)
}

fn validate_confirmed_document(
    workspace: &CaseWorkspace,
    template_id: DocumentTemplateId,
) -> Result<(), DocumentValidationError> {
    let mut present = HashSet::new();
    if workspace
        .parties
        .iter()
        .any(|p| p.role == PartyRole::Plaintiff)
    {
        present.insert("plaintiff");
    }
    if workspace
        .parties
        .iter()
        .any(|p| p.role == PartyRole::Defendant)
    {
        present.insert("defendant");
    }
    if workspace
        .parties
        .iter()
        .any(|party| matches!(party.role, PartyRole::Plaintiff | PartyRole::Claimant))
    {
        present.insert("sender");
    }
    if workspace
        .parties
        .iter()
        .any(|party| matches!(party.role, PartyRole::Defendant | PartyRole::Respondent))
    {
        present.insert("recipient");
    }
    if workspace
        .legal_issues
        .iter()
        .any(|issue| !issue.claim.trim().is_empty())
    {
        present.insert("claims");
    }
    if !workspace.facts.is_empty() {
        present.insert("facts");
    }
    if workspace
        .facts
        .iter()
        .any(|fact| fact.occurred_on.is_some())
    {
        present.insert("dated_facts");
    }
    if !workspace.evidence.is_empty() {
        present.insert("evidence");
    }
    if !workspace.legal_issues.is_empty() {
        present.insert("issues");
    }
    if workspace
        .legal_basis
        .iter()
        .any(|basis| basis.status == CitationStatus::Valid)
    {
        present.insert("valid_citations");
    }
    let template = template_catalog()
        .into_iter()
        .find(|item| item.template_id == template_id)
        .expect("catalog is exhaustive");
    let missing_fields = template
        .required_fields
        .iter()
        .filter(|field| !present.contains(field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing_fields.is_empty() {
        Ok(())
    } else {
        Err(DocumentValidationError {
            code: "missing_required_fields".to_owned(),
            missing_fields,
            invalid_citation_ids: Vec::new(),
        })
    }
}

pub fn generate_document(
    workspace: &CaseWorkspace,
    template_id: DocumentTemplateId,
    model_draft: Option<&str>,
) -> Result<GeneratedDocument, DocumentValidationError> {
    let workspace = confirmed_workspace(workspace);
    validate_confirmed_document(&workspace, template_id)?;
    let workspace = &workspace;
    let template = template_catalog()
        .into_iter()
        .find(|item| item.template_id == template_id)
        .expect("catalog is exhaustive");
    let mut citations = Vec::new();
    let mut seen = HashSet::new();
    for basis in &workspace.legal_basis {
        if basis.status != CitationStatus::Valid || !seen.insert(basis.source_id.clone()) {
            continue;
        }
        citations.push(DocumentCitation {
            source_id: basis.source_id.clone(),
            canonical_label: basis.canonical_label.clone(),
            excerpt: basis.excerpt.clone(),
            document_id: basis.document_id.clone(),
            version_id: basis.version_id.clone(),
            article_id: basis.article_id.clone(),
        });
    }
    let mut sections = Vec::new();
    let mut tables = Vec::new();
    let project_source = vec![workspace.project.project_id.clone()];

    match template_id {
        DocumentTemplateId::Complaint => {
            push_party_table(workspace, "当事人信息", &mut sections, &mut tables);
            push_issue_section(workspace, "诉讼请求", &mut sections);
            push_fact_section(workspace, "事实与理由", &mut sections);
            push_citation_table(&citations, "法律依据", &mut sections, &mut tables);
            if !workspace.evidence.is_empty() {
                push_evidence_table(workspace, "证据概览", &mut sections, &mut tables);
            }
            sections.push(section(
                "结语",
                vec!["以上请求及事实依据均由案件工作区中的已确认数据装配；提交前应由承办律师结合管辖、诉讼时效和具体诉讼策略作最终复核。".to_owned()],
                project_source.clone(),
            ));
        }
        DocumentTemplateId::Defence => {
            push_party_table(workspace, "当事人信息", &mut sections, &mut tables);
            push_issue_section(workspace, "答辩意见", &mut sections);
            push_fact_section(workspace, "事实与理由", &mut sections);
            push_citation_table(&citations, "法律依据", &mut sections, &mut tables);
            if !workspace.evidence.is_empty() {
                push_evidence_table(workspace, "证据概览", &mut sections, &mut tables);
            }
            sections.push(section(
                "复核说明",
                vec!["本答辩状依据案件工作区中已确认的当事人、事实、争点和有效法律引用生成；正式提交前应补充法院、案号及签章信息。".to_owned()],
                project_source.clone(),
            ));
        }
        DocumentTemplateId::EvidenceSchedule => {
            sections.push(section(
                "编制说明",
                vec![format!(
                    "本目录对应案件“{}”，按案件工作区中的证据编号列示名称、来源、形成日期、证明目的和存储位置。",
                    workspace.project.title
                )],
                project_source.clone(),
            ));
            push_evidence_table(workspace, "证据目录", &mut sections, &mut tables);
        }
        DocumentTemplateId::FactTimeline => {
            sections.push(section(
                "案件概览",
                project_overview(workspace),
                project_source.clone(),
            ));
            push_timeline_table(workspace, "事实时间线", &mut sections, &mut tables);
            if !workspace.gaps.is_empty() {
                sections.push(section(
                    "待核对事项",
                    workspace
                        .gaps
                        .iter()
                        .map(|gap| gap.message.clone())
                        .collect(),
                    workspace
                        .gaps
                        .iter()
                        .map(|gap| gap.entity_id.clone())
                        .collect(),
                ));
            }
        }
        DocumentTemplateId::LegalResearchReport => {
            sections.push(section(
                "检索范围与目的",
                vec![format!(
                    "围绕案件“{}”中已确认的法律争点，汇总本地法律库中已通过版本与效力校验的法律依据。",
                    workspace.project.title
                )],
                project_source.clone(),
            ));
            push_issue_section(workspace, "争点清单", &mut sections);
            push_citation_table(&citations, "法律依据与检索结果", &mut sections, &mut tables);
            sections.push(section(
                "检索结论使用说明",
                vec!["本报告仅呈现已经本地引用校验的条文及其原文摘录，不替代承办律师结合案件日期、裁判规则和完整上下文作出的专业判断。".to_owned()],
                citations.iter().map(|citation| citation.source_id.clone()).collect(),
            ));
        }
        DocumentTemplateId::LawyerLetter => {
            push_party_table(workspace, "收发函主体", &mut sections, &mut tables);
            sections.push(section(
                "事项说明",
                project_overview(workspace),
                project_source.clone(),
            ));
            push_fact_section(workspace, "事实陈述", &mut sections);
            push_issue_section(workspace, "正式要求", &mut sections);
            push_citation_table(&citations, "法律依据", &mut sections, &mut tables);
            sections.push(section(
                "办理要求",
                vec!["请收函方在合理期限内就上述事项书面回复并与发函方协商处理；逾期未妥善处理的，发函方将依法保留采取进一步措施的权利。".to_owned()],
                project_source.clone(),
            ));
        }
    }

    if let Some(draft) = model_draft.filter(|draft| !draft.trim().is_empty()) {
        sections.push(section(
            "模型草稿（待律师复核）",
            vec![draft.trim().to_owned()],
            vec!["model_draft".to_owned()],
        ));
    }
    push_source_mapping_table(&citations, &mut sections, &mut tables);
    let title = format!("{}——{}", template.name, workspace.project.title);
    let fields = collect_fields(workspace);
    let markdown = render_markdown(&title, &sections, &tables);
    Ok(GeneratedDocument {
        template,
        title,
        fields,
        sections,
        tables,
        citations,
        markdown,
    })
}

/// Exportable work product is built only from facts, evidence and issues that
/// a lawyer has explicitly confirmed. Model suggestions remain visible in the
/// case review workflow but can never silently become assertions in a filing.
fn confirmed_workspace(workspace: &CaseWorkspace) -> CaseWorkspace {
    let mut confirmed = workspace.clone();
    confirmed
        .facts
        .retain(|fact| fact.confirmation_status == ConfirmationStatus::Confirmed);
    confirmed
        .evidence
        .retain(|item| item.confirmation_status == ConfirmationStatus::Confirmed);
    confirmed
        .legal_issues
        .retain(|issue| issue.confirmation_status == ConfirmationStatus::Confirmed);

    let fact_ids = confirmed
        .facts
        .iter()
        .map(|fact| fact.fact_id.as_str())
        .collect::<HashSet<_>>();
    let evidence_ids = confirmed
        .evidence
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect::<HashSet<_>>();
    let issue_ids = confirmed
        .legal_issues
        .iter()
        .map(|issue| issue.issue_id.as_str())
        .collect::<HashSet<_>>();
    confirmed.evidence_links.retain(|link| {
        fact_ids.contains(link.fact_id.as_str()) && evidence_ids.contains(link.evidence_id.as_str())
    });
    confirmed.fact_issue_links.retain(|link| {
        fact_ids.contains(link.fact_id.as_str()) && issue_ids.contains(link.issue_id.as_str())
    });
    confirmed.legal_basis.retain(|basis| {
        basis
            .issue_id
            .as_deref()
            .is_none_or(|issue_id| issue_ids.contains(issue_id))
    });
    confirmed.gaps = analyze_case_gaps(
        &confirmed.project.project_id,
        &confirmed.parties,
        &confirmed.facts,
        &confirmed.evidence,
        &confirmed.evidence_links,
        &confirmed.legal_issues,
        &confirmed.legal_basis,
    );
    confirmed
}

fn push_party_table(
    workspace: &CaseWorkspace,
    heading: &str,
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    let source_ids = workspace
        .parties
        .iter()
        .map(|party| party.party_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec!["诉讼地位", "名称", "联系方式", "备注"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![1_200, 2_400, 2_400, 3_360],
        rows: workspace
            .parties
            .iter()
            .map(|party| DocumentTableRow {
                cells: vec![
                    party_role_label(&party.role).to_owned(),
                    party.name.clone(),
                    value_or_dash(&party.contact),
                    value_or_dash(&party.notes),
                ],
                source_ids: vec![party.party_id.clone()],
            })
            .collect(),
        source_ids,
    });
}

fn push_fact_section(
    workspace: &CaseWorkspace,
    heading: &str,
    sections: &mut Vec<DocumentSection>,
) {
    sections.push(section(
        heading,
        workspace
            .facts
            .iter()
            .map(|fact| {
                let date = fact
                    .occurred_on
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("{value}，"))
                    .unwrap_or_default();
                format!("{date}{}：{}", fact.title, fact.description)
            })
            .collect(),
        workspace
            .facts
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect(),
    ));
}

fn push_issue_section(
    workspace: &CaseWorkspace,
    heading: &str,
    sections: &mut Vec<DocumentSection>,
) {
    sections.push(section(
        heading,
        workspace
            .legal_issues
            .iter()
            .map(|issue| {
                if issue.description.trim().is_empty() {
                    format!("{}：{}", issue.title, issue.claim)
                } else {
                    format!("{}：{}（{}）", issue.title, issue.claim, issue.description)
                }
            })
            .collect(),
        workspace
            .legal_issues
            .iter()
            .map(|issue| issue.issue_id.clone())
            .collect(),
    ));
}

fn push_evidence_table(
    workspace: &CaseWorkspace,
    heading: &str,
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    let source_ids = workspace
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec!["序号", "证据名称", "来源及形成日期", "证明目的", "存储位置"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![600, 1_800, 1_800, 3_000, 2_160],
        rows: workspace
            .evidence
            .iter()
            .map(|evidence| DocumentTableRow {
                cells: vec![
                    evidence.evidence_number.clone(),
                    evidence.title.clone(),
                    format!(
                        "{}\n{}",
                        evidence.source,
                        evidence.formed_on.as_deref().unwrap_or("日期未记录")
                    ),
                    evidence.summary.clone(),
                    value_or_dash(&evidence.storage_reference),
                ],
                source_ids: vec![evidence.evidence_id.clone()],
            })
            .collect(),
        source_ids,
    });
}

fn push_timeline_table(
    workspace: &CaseWorkspace,
    heading: &str,
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    let source_ids = workspace
        .facts
        .iter()
        .map(|fact| fact.fact_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec!["日期", "事件", "事实摘要", "来源"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![1_500, 1_800, 3_660, 2_400],
        rows: workspace
            .facts
            .iter()
            .map(|fact| DocumentTableRow {
                cells: vec![
                    fact.occurred_on
                        .as_deref()
                        .unwrap_or("日期未记录")
                        .to_owned(),
                    fact.title.clone(),
                    fact.description.clone(),
                    value_or_dash(&fact.source),
                ],
                source_ids: vec![fact.fact_id.clone()],
            })
            .collect(),
        source_ids,
    });
}

fn push_citation_table(
    citations: &[DocumentCitation],
    heading: &str,
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    if citations.is_empty() {
        return;
    }
    let source_ids = citations
        .iter()
        .map(|citation| citation.source_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec!["法律依据", "已校验原文摘录", "本地追溯标识"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![2_520, 4_200, 2_640],
        rows: citations
            .iter()
            .map(|citation| DocumentTableRow {
                cells: vec![
                    citation.canonical_label.clone(),
                    citation.excerpt.clone(),
                    citation.source_id.clone(),
                ],
                source_ids: vec![citation.source_id.clone()],
            })
            .collect(),
        source_ids,
    });
}

fn push_source_mapping_table(
    citations: &[DocumentCitation],
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    if citations.is_empty() {
        return;
    }
    let heading = "引用来源映射";
    let source_ids = citations
        .iter()
        .map(|citation| citation.source_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec!["来源 ID", "法律文档 ID", "版本 ID", "条文 ID"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![2_520, 2_280, 2_280, 2_280],
        rows: citations
            .iter()
            .map(|citation| DocumentTableRow {
                cells: vec![
                    citation.source_id.clone(),
                    citation.document_id.clone(),
                    citation.version_id.clone(),
                    citation.article_id.clone(),
                ],
                source_ids: vec![citation.source_id.clone()],
            })
            .collect(),
        source_ids,
    });
}

fn project_overview(workspace: &CaseWorkspace) -> Vec<String> {
    let mut paragraphs = vec![format!("案件名称：{}", workspace.project.title)];
    paragraphs.push(format!("案件类型：{}", workspace.project.case_type));
    if let Some(opened_on) = workspace
        .project
        .opened_on
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        paragraphs.push(format!("立项日期：{opened_on}"));
    }
    if !workspace.project.summary.trim().is_empty() {
        paragraphs.push(format!("案件摘要：{}", workspace.project.summary));
    }
    paragraphs
}

fn party_role_label(role: &PartyRole) -> &'static str {
    match role {
        PartyRole::Plaintiff => "原告",
        PartyRole::Defendant => "被告",
        PartyRole::Claimant => "申请人",
        PartyRole::Respondent => "被申请人",
        PartyRole::ThirdParty => "第三人",
        PartyRole::Other => "其他",
    }
}

fn value_or_dash(value: &str) -> String {
    if value.trim().is_empty() {
        "—".to_owned()
    } else {
        value.trim().to_owned()
    }
}

fn section(heading: &str, paragraphs: Vec<String>, source_ids: Vec<String>) -> DocumentSection {
    DocumentSection {
        heading: heading.to_owned(),
        level: 2,
        paragraphs,
        source_ids,
    }
}

fn collect_fields(workspace: &CaseWorkspace) -> Vec<DocumentField> {
    let mut values = BTreeMap::new();
    values.insert(
        "project_title",
        (
            workspace.project.title.clone(),
            "case_project",
            workspace.project.project_id.clone(),
        ),
    );
    values.insert(
        "case_type",
        (
            workspace.project.case_type.clone(),
            "case_project",
            workspace.project.project_id.clone(),
        ),
    );
    if let Some(opened_on) = workspace
        .project
        .opened_on
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        values.insert(
            "opened_on",
            (
                opened_on.to_owned(),
                "case_project",
                workspace.project.project_id.clone(),
            ),
        );
    }
    if !workspace.project.summary.trim().is_empty() {
        values.insert(
            "project_summary",
            (
                workspace.project.summary.clone(),
                "case_project",
                workspace.project.project_id.clone(),
            ),
        );
    }
    values
        .into_iter()
        .map(|(key, (value, kind, id))| DocumentField {
            key: key.to_owned(),
            value,
            source_kind: kind.to_owned(),
            source_id: id,
        })
        .collect()
}

fn render_markdown(title: &str, sections: &[DocumentSection], tables: &[DocumentTable]) -> String {
    let mut output = format!("# {title}\n\n");
    for section in sections {
        output.push_str(&format!("## {}\n\n", section.heading));
        for paragraph in &section.paragraphs {
            output.push_str(paragraph);
            output.push_str("\n\n");
        }
        for table in tables
            .iter()
            .filter(|table| table.section_heading == section.heading)
        {
            output.push('|');
            for header in &table.headers {
                output.push_str(&format!(" {} |", markdown_cell(header)));
            }
            output.push('\n');
            output.push('|');
            for _ in &table.headers {
                output.push_str(" --- |");
            }
            output.push('\n');
            for row in &table.rows {
                output.push('|');
                for cell in &row.cells {
                    output.push_str(&format!(" {} |", markdown_cell(cell)));
                }
                output.push('\n');
            }
            output.push('\n');
        }
        if !section.source_ids.is_empty() {
            output.push_str(&format!(
                "_来源标识：{}_\n\n",
                section.source_ids.join("、")
            ));
        }
    }
    output
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::*;
    fn workspace() -> CaseWorkspace {
        CaseWorkspace {
            project: CaseProject {
                project_id: "p1".into(),
                title: "买卖合同纠纷".into(),
                case_type: "civil".into(),
                status: CaseProjectStatus::Active,
                opened_on: Some("2026-01-01".into()),
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
            files: vec![],
            parties: vec![
                CaseParty {
                    party_id: "pa".into(),
                    project_id: "p1".into(),
                    name: "甲公司".into(),
                    normalized_name: String::new(),
                    role: PartyRole::Plaintiff,
                    contact: String::new(),
                    notes: String::new(),
                },
                CaseParty {
                    party_id: "pb".into(),
                    project_id: "p1".into(),
                    name: "乙公司".into(),
                    normalized_name: String::new(),
                    role: PartyRole::Defendant,
                    contact: String::new(),
                    notes: String::new(),
                },
            ],
            facts: vec![CaseFact {
                fact_id: "f1".into(),
                project_id: "p1".into(),
                occurred_on: Some("2025-01-01".into()),
                title: "交付".into(),
                description: "甲方交付货物".into(),
                source: "合同".into(),
                confirmation_status: ConfirmationStatus::Confirmed,
            }],
            evidence: vec![EvidenceItem {
                evidence_id: "e1".into(),
                project_id: "p1".into(),
                evidence_number: "1".into(),
                title: "合同".into(),
                source: "当事人提交".into(),
                formed_on: Some("2024-12-01".into()),
                summary: "证明合同关系".into(),
                storage_reference: String::new(),
                confirmation_status: ConfirmationStatus::Confirmed,
            }],
            evidence_links: vec![],
            fact_issue_links: vec![],
            legal_issues: vec![LegalIssue {
                issue_id: "i1".into(),
                project_id: "p1".into(),
                title: "付款".into(),
                description: String::new(),
                claim: "支付货款".into(),
                status: LegalIssueStatus::Open,
                confirmation_status: ConfirmationStatus::Confirmed,
            }],
            legal_basis: vec![LegalBasis {
                basis_id: "b1".into(),
                project_id: "p1".into(),
                issue_id: Some("i1".into()),
                source_id: "law:1".into(),
                status: CitationStatus::Valid,
                invalid_reason: None,
                case_date: None,
                article_id: "a1".into(),
                document_id: "d1".into(),
                version_id: "v1".into(),
                document_title: "民法典".into(),
                version_label: "现行".into(),
                article_number: "第五百七十七条".into(),
                article_title: None,
                canonical_label: "《民法典》第五百七十七条".into(),
                effective_from: "2021-01-01".into(),
                effective_to: None,
                version_status: "effective".into(),
                excerpt: "违约方应承担违约责任。".into(),
                note: String::new(),
                created_at: String::new(),
            }],
            uncertainties: vec![],
            gaps: vec![],
        }
    }
    #[test]
    fn every_template_has_real_validation_and_generates_structure() {
        for item in template_catalog() {
            let doc = generate_document(&workspace(), item.template_id, None)
                .expect("complete case generates");
            assert!(!doc.sections.is_empty());
            assert!(doc.markdown.starts_with("# "));
            assert_eq!(doc.template.version, "2.0.0");
            assert!(doc
                .tables
                .iter()
                .all(|table| table.column_widths_dxa.iter().sum::<u32>() == 9_360));
            assert!(doc.markdown.contains("来源标识："));
        }
    }

    #[test]
    fn all_template_structures_match_the_reviewed_golden_file() {
        let actual = template_catalog()
            .into_iter()
            .map(|item| {
                let document = generate_document(&workspace(), item.template_id, None).unwrap();
                format!(
                    "{} | {} | sections={} | tables={}",
                    item.template_id.as_str(),
                    document.title,
                    document
                        .sections
                        .iter()
                        .map(|section| section.heading.as_str())
                        .collect::<Vec<_>>()
                        .join(" > "),
                    document
                        .tables
                        .iter()
                        .map(|table| table.section_heading.as_str())
                        .collect::<Vec<_>>()
                        .join(" > ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            actual,
            include_str!("../testdata/document_templates.golden").trim_end()
        );
    }
    #[test]
    fn missing_fields_block_generation_with_structured_report() {
        let mut w = workspace();
        w.evidence.clear();
        let err = generate_document(&w, DocumentTemplateId::EvidenceSchedule, None)
            .expect_err("missing evidence blocks");
        assert_eq!(err.missing_fields, vec!["evidence"]);
    }
    #[test]
    fn citations_are_valid_only_deduplicated_and_traceable() {
        let mut w = workspace();
        let mut duplicate = w.legal_basis[0].clone();
        duplicate.basis_id = "b2".into();
        w.legal_basis.push(duplicate);
        let mut invalid = w.legal_basis[0].clone();
        invalid.basis_id = "b3".into();
        invalid.source_id = "law:invalid".into();
        invalid.status = CitationStatus::Invalid;
        invalid.invalid_reason = Some(crate::qa::CitationInvalidReason::NotFound);
        w.legal_basis.push(invalid);
        let doc = generate_document(&w, DocumentTemplateId::LegalResearchReport, None).unwrap();
        assert_eq!(doc.citations.len(), 1);
        assert_eq!(doc.citations[0].article_id, "a1");
        assert!(!doc.markdown.contains("law:invalid"));
        let mapping = doc
            .tables
            .iter()
            .find(|table| table.section_heading == "引用来源映射")
            .expect("valid citations have an explicit source mapping table");
        assert_eq!(mapping.rows.len(), 1);
        assert_eq!(mapping.rows[0].cells, vec!["law:1", "d1", "v1", "a1"]);
    }

    #[test]
    fn evidence_schedule_is_structured_as_a_real_table() {
        let doc = generate_document(&workspace(), DocumentTemplateId::EvidenceSchedule, None)
            .expect("complete evidence generates");
        let table = doc
            .tables
            .iter()
            .find(|table| table.section_heading == "证据目录")
            .expect("evidence schedule owns a structured table");
        assert_eq!(
            table.headers,
            vec!["序号", "证据名称", "来源及形成日期", "证明目的", "存储位置"]
        );
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].source_ids, vec!["e1"]);
        assert!(doc.markdown.contains("| 序号 | 证据名称 |"));
    }

    #[test]
    fn lawyer_letter_requires_distinct_sender_and_recipient_roles() {
        let mut w = workspace();
        w.parties.retain(|party| party.role == PartyRole::Plaintiff);
        let error = generate_document(&w, DocumentTemplateId::LawyerLetter, None)
            .expect_err("one-sided party data cannot produce a lawyer letter");
        assert_eq!(error.missing_fields, vec!["recipient"]);
    }

    #[test]
    fn model_suggestions_never_satisfy_required_fields_or_enter_an_export() {
        let mut w = workspace();
        w.facts[0].confirmation_status = ConfirmationStatus::ModelSuggested;
        let error = generate_document(&w, DocumentTemplateId::Complaint, None)
            .expect_err("an unconfirmed fact cannot satisfy a filing requirement");
        assert_eq!(error.missing_fields, vec!["facts"]);

        w.facts[0].confirmation_status = ConfirmationStatus::Confirmed;
        w.evidence.push(EvidenceItem {
            evidence_id: "suggested-evidence".into(),
            project_id: "p1".into(),
            evidence_number: "2".into(),
            title: "模型猜测的证据".into(),
            source: "model".into(),
            formed_on: None,
            summary: "不得导出".into(),
            storage_reference: String::new(),
            confirmation_status: ConfirmationStatus::ModelSuggested,
        });
        w.gaps.push(CaseGap {
            gap_id: "suggested-gap".into(),
            project_id: "p1".into(),
            kind: CaseGapKind::EvidenceMissingSource,
            severity: CaseGapSeverity::Warning,
            entity_id: "suggested-evidence".into(),
            message: "模型建议实体的残留缺口不得导出".into(),
        });
        let document = generate_document(&w, DocumentTemplateId::EvidenceSchedule, None)
            .expect("confirmed evidence remains exportable");
        assert!(!document.markdown.contains("模型猜测的证据"));
        assert!(!document
            .sections
            .iter()
            .flat_map(|section| &section.source_ids)
            .any(|source_id| source_id == "suggested-evidence"));
        let timeline = generate_document(&w, DocumentTemplateId::FactTimeline, None).unwrap();
        assert!(!timeline.markdown.contains("模型建议实体的残留缺口不得导出"));
    }

    #[test]
    fn template_identifiers_are_stable_snake_case_values() {
        assert_eq!(DocumentTemplateId::Complaint.as_str(), "complaint");
        assert_eq!(
            DocumentTemplateId::EvidenceSchedule.as_str(),
            "evidence_schedule"
        );
        assert_eq!(
            DocumentTemplateId::LegalResearchReport.as_str(),
            "legal_research_report"
        );
    }
}
