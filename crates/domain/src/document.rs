use crate::{
    case::{analyze_case_gaps, CaseWorkspace, ConfirmationStatus, LegalBasis, PartyRole},
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
    /// relationship explicit lets Markdown, PDF and future renderers retain
    /// the same content order without inferring structure from prose.
    pub section_heading: String,
    pub headers: Vec<String>,
    /// Fixed Word table geometry. Every generated table is exactly 9360 DXA,
    /// the usable width of the selected `standard_business_brief` preset.
    pub column_widths_dxa: Vec<u32>,
    pub rows: Vec<DocumentTableRow>,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DocumentCitationKind {
    #[default]
    Law,
    JudicialCase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentCitation {
    /// Public, human-readable citation fields. Internal identifiers below are
    /// retained for validation and audit only and are never rendered.
    #[serde(default)]
    pub kind: DocumentCitationKind,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub locator: String,
    #[serde(default)]
    pub effective_or_decided_on: String,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandaloneDocumentInput {
    pub title: String,
    pub party_a: String,
    pub party_b: String,
    pub facts: String,
    pub requests: String,
    pub evidence: String,
    pub requirements: String,
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
            citation_policy: "仅采用经核验且现行有效的法律依据".to_owned(),
            version: "2.1.0".to_owned(),
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
        .any(legal_basis_has_public_citation)
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

fn legal_basis_has_public_citation(basis: &LegalBasis) -> bool {
    if basis.status != CitationStatus::Valid
        || basis.document_title.trim().is_empty()
        || basis.article_number.trim().is_empty()
        || [
            basis.document_title.as_str(),
            basis.article_number.as_str(),
            basis.canonical_label.as_str(),
            basis.excerpt.as_str(),
        ]
        .into_iter()
        .any(public_text_is_non_deliverable)
    {
        return false;
    }
    let year = basis.effective_from.get(..4).unwrap_or_default();
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && public_law_locator(&basis.article_number, &basis.canonical_label).contains('款')
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
        if !legal_basis_has_public_citation(basis) || !seen.insert(basis.source_id.clone()) {
            continue;
        }
        citations.push(DocumentCitation {
            kind: DocumentCitationKind::Law,
            title: basis.document_title.clone(),
            locator: public_law_locator(&basis.article_number, &basis.canonical_label),
            effective_or_decided_on: basis.effective_from.clone(),
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
            push_citation_section(&citations, "法律依据", &mut sections);
            if !workspace.evidence.is_empty() {
                push_evidence_table(workspace, "证据概览", &mut sections, &mut tables);
            }
            sections.push(section(
                "结语",
                vec!["以上请求及事实依据根据现有案件材料拟具；提交前应由承办律师结合管辖、诉讼时效和具体诉讼策略作最终复核。".to_owned()],
                project_source.clone(),
            ));
        }
        DocumentTemplateId::Defence => {
            push_party_table(workspace, "当事人信息", &mut sections, &mut tables);
            push_issue_section(workspace, "答辩意见", &mut sections);
            push_fact_section(workspace, "事实与理由", &mut sections);
            push_citation_section(&citations, "法律依据", &mut sections);
            if !workspace.evidence.is_empty() {
                push_evidence_table(workspace, "证据概览", &mut sections, &mut tables);
            }
            sections.push(section(
                "复核说明",
                vec!["本答辩状根据现有案件材料、事实、争点和法律依据拟具；正式提交前应补充法院、案号及签章信息。".to_owned()],
                project_source.clone(),
            ));
        }
        DocumentTemplateId::EvidenceSchedule => {
            sections.push(section(
                "编制说明",
                vec![format!(
                    "本目录对应案件“{}”，按现有证据编号列示名称、来源、形成日期和证明目的。",
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
                    "围绕案件“{}”的法律争点，汇总经核验的现行有效法律依据。",
                    workspace.project.title
                )],
                project_source.clone(),
            ));
            push_issue_section(workspace, "争点清单", &mut sections);
            push_citation_section(&citations, "法律依据与检索结果", &mut sections);
            sections.push(section(
                "检索结论使用说明",
                vec!["本报告列示经核验的条文及其原文摘录，不替代承办律师结合案件日期、裁判规则和完整上下文作出的专业判断。".to_owned()],
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
            push_citation_section(&citations, "法律依据", &mut sections);
            sections.push(section(
                "办理要求",
                vec!["请收函方在合理期限内就上述事项书面回复并与发函方协商处理；逾期未妥善处理的，发函方将依法保留采取进一步措施的权利。".to_owned()],
                project_source.clone(),
            ));
        }
    }

    let public_draft = public_model_draft_paragraphs(model_draft);
    if !public_draft.is_empty() {
        sections.push(section(
            "补充陈述（待律师复核）",
            public_draft,
            vec!["model_draft".to_owned()],
        ));
    }
    push_reference_table(&citations, &mut sections, &mut tables);
    let mut title = format!("{} - {}", template.name, workspace.project.title);
    let mut fields = collect_fields(workspace);
    enforce_public_document_boundary(
        &mut title,
        &template.name,
        &mut fields,
        &mut sections,
        &mut tables,
    );
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

pub fn generate_standalone_document(
    input: &StandaloneDocumentInput,
    template_id: DocumentTemplateId,
    model_draft: Option<&str>,
) -> Result<GeneratedDocument, DocumentValidationError> {
    let has_content = [
        &input.title,
        &input.party_a,
        &input.party_b,
        &input.facts,
        &input.requests,
        &input.evidence,
        &input.requirements,
    ]
    .into_iter()
    .any(|value| !value.trim().is_empty());
    if !has_content {
        return Err(DocumentValidationError {
            code: "missing_required_fields".to_owned(),
            missing_fields: vec!["standalone_content".to_owned()],
            invalid_citation_ids: Vec::new(),
        });
    }

    let template = template_catalog()
        .into_iter()
        .find(|item| item.template_id == template_id)
        .expect("catalog is exhaustive");
    let mut sections = Vec::new();
    let mut tables = Vec::new();

    let party_paragraphs = [
        (!input.party_a.trim().is_empty()).then(|| {
            format!(
                "{}：{}",
                standalone_party_a_label(template_id),
                input.party_a.trim()
            )
        }),
        (!input.party_b.trim().is_empty()).then(|| {
            format!(
                "{}：{}",
                standalone_party_b_label(template_id),
                input.party_b.trim()
            )
        }),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !party_paragraphs.is_empty() {
        sections.push(section("相关主体", party_paragraphs, Vec::new()));
    }

    let request_heading = match template_id {
        DocumentTemplateId::Complaint => "诉讼请求",
        DocumentTemplateId::Defence => "答辩主张",
        DocumentTemplateId::EvidenceSchedule => "目录编制要求",
        DocumentTemplateId::FactTimeline => "时间线整理要求",
        DocumentTemplateId::LegalResearchReport => "争点与检索问题",
        DocumentTemplateId::LawyerLetter => "正式要求",
    };
    push_standalone_text(&mut sections, request_heading, &input.requests);

    let facts_heading = match template_id {
        DocumentTemplateId::FactTimeline => "事实时间线材料",
        DocumentTemplateId::LawyerLetter => "事实陈述",
        _ => "事实与背景",
    };
    push_standalone_text(&mut sections, facts_heading, &input.facts);

    if template_id == DocumentTemplateId::EvidenceSchedule && !input.evidence.trim().is_empty() {
        let rows = text_paragraphs(&input.evidence)
            .into_iter()
            .enumerate()
            .map(|(index, value)| DocumentTableRow {
                cells: vec![(index + 1).to_string(), value],
                source_ids: Vec::new(),
            })
            .collect::<Vec<_>>();
        sections.push(section("证据目录", Vec::new(), Vec::new()));
        tables.push(DocumentTable {
            section_heading: "证据目录".to_owned(),
            headers: vec!["序号".to_owned(), "证据名称、来源及证明目的".to_owned()],
            column_widths_dxa: vec![900, 8_460],
            rows,
            source_ids: Vec::new(),
        });
    } else {
        push_standalone_text(&mut sections, "证据与补充材料", &input.evidence);
    }
    push_standalone_text(&mut sections, "写作及处理要求", &input.requirements);

    let public_draft = public_model_draft_paragraphs(model_draft);
    if !public_draft.is_empty() {
        sections.push(section("补充陈述（待律师复核）", public_draft, Vec::new()));
    }
    sections.push(section(
        "复核提示",
        vec![
            "本稿根据现有材料拟具。正式使用前请核对主体、日期、金额、管辖、时效、证据和法律依据。"
                .to_owned(),
        ],
        Vec::new(),
    ));

    push_reference_table(&[], &mut sections, &mut tables);

    let mut title = if input.title.trim().is_empty() {
        template.name.clone()
    } else {
        input.title.trim().to_owned()
    };
    let mut fields = standalone_fields(input);
    enforce_public_document_boundary(
        &mut title,
        &template.name,
        &mut fields,
        &mut sections,
        &mut tables,
    );
    let markdown = render_markdown(&title, &sections, &tables);
    Ok(GeneratedDocument {
        template,
        title,
        fields,
        sections,
        tables,
        citations: Vec::new(),
        markdown,
    })
}

fn standalone_party_a_label(template_id: DocumentTemplateId) -> &'static str {
    match template_id {
        DocumentTemplateId::Complaint => "原告",
        DocumentTemplateId::Defence => "答辩人",
        DocumentTemplateId::LawyerLetter => "发函方",
        _ => "委托方或主要主体",
    }
}

fn standalone_party_b_label(template_id: DocumentTemplateId) -> &'static str {
    match template_id {
        DocumentTemplateId::Complaint => "被告",
        DocumentTemplateId::Defence => "对方当事人",
        DocumentTemplateId::LawyerLetter => "收函方",
        _ => "相对方或其他主体",
    }
}

fn push_standalone_text(sections: &mut Vec<DocumentSection>, heading: &str, value: &str) {
    let paragraphs = text_paragraphs(value);
    if !paragraphs.is_empty() {
        sections.push(section(heading, paragraphs, Vec::new()));
    }
}

fn text_paragraphs(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Model drafts are optional wording assistance, so an unsafe paragraph is
/// omitted instead of being allowed to cross the lawyer-facing export
/// boundary. Confirmed case data and validated citations remain unaffected.
fn public_model_draft_paragraphs(model_draft: Option<&str>) -> Vec<String> {
    let Some(draft) = model_draft.map(str::trim).filter(|draft| !draft.is_empty()) else {
        return Vec::new();
    };
    if matches!(
        serde_json::from_str::<serde_json::Value>(draft),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    ) {
        return Vec::new();
    }

    draft
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !public_text_is_non_deliverable(line))
        .map(str::to_owned)
        .collect()
}

fn public_text_is_non_deliverable(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if matches!(value, "{" | "}" | "[" | "]")
        || value.starts_with('#')
        || value.contains("```")
        || value.contains("](")
        || [
            "[src:",
            "无标题",
            "结构化文书预览",
            "模型措辞",
            "内部标识",
            "内部路径",
            "本地路径",
            "应用内路径",
            "系统字段",
            "内部变量",
            "工程字段",
            "技术字段",
            "原始json",
            "原始 json",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }

    contains_json_member(value)
        || contains_forbidden_draft_field(&lower)
        || contains_draft_path_or_uri(value, &lower)
        || contains_draft_uuid(value)
        || contains_draft_hash(value)
        || contains_draft_namespaced_identifier(value)
}

fn contains_json_member(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let mut escaped = false;
        while index < bytes.len() {
            match (bytes[index], escaped) {
                (_, true) => escaped = false,
                (b'\\', false) => escaped = true,
                (b'"', false) => break,
                _ => {}
            }
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b':') {
            return true;
        }
    }
    false
}

fn contains_forbidden_draft_field(lower: &str) -> bool {
    lower
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "id" | "article_id"
                    | "articleid"
                    | "case_id"
                    | "caseid"
                    | "citation_id"
                    | "citationid"
                    | "conversation_id"
                    | "conversationid"
                    | "document_id"
                    | "documentid"
                    | "evidence_id"
                    | "evidenceid"
                    | "fact_id"
                    | "factid"
                    | "file_id"
                    | "fileid"
                    | "issue_id"
                    | "issueid"
                    | "message_id"
                    | "messageid"
                    | "model_id"
                    | "modelid"
                    | "project_id"
                    | "projectid"
                    | "proposal_id"
                    | "proposalid"
                    | "provider_id"
                    | "providerid"
                    | "record_id"
                    | "recordid"
                    | "version_id"
                    | "versionid"
                    | "source_id"
                    | "sourceid"
                    | "source_ref"
                    | "sourceref"
                    | "source_refs"
                    | "sourcerefs"
                    | "request_id"
                    | "requestid"
                    | "request_uuid"
                    | "requestuuid"
                    | "run_id"
                    | "runid"
                    | "artifact_id"
                    | "artifactid"
                    | "attachment_id"
                    | "attachmentid"
                    | "schema"
                    | "schema_version"
                    | "schemaversion"
                    | "as_of"
                    | "asof"
                    | "snippet"
                    | "snnipet"
                    | "proposal_hash"
                    | "proposalhash"
                    | "service_hash"
                    | "servicehash"
                    | "canonical_label"
                    | "canonicallabel"
                    | "model_draft"
                    | "modeldraft"
                    | "endpoint"
                    | "path"
                    | "localpath"
                    | "query"
                    | "limit"
                    | "params"
                    | "parameters"
                    | "payload"
                    | "json"
                    | "uuid"
                    | "hash"
            )
        })
}

fn contains_draft_path_or_uri(value: &str, lower: &str) -> bool {
    if value.contains('\\')
        || [
            "file://",
            "http://",
            "https://",
            "/users/",
            "/home/",
            "/tmp/",
            "/var/",
            "/etc/",
            "/workspace/",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.windows(3).any(|part| {
        part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
    }) || lower.match_indices("://").any(|(index, _)| {
        let scheme = lower[..index]
            .rsplit(|character: char| !character.is_ascii_alphanumeric() && character != '+')
            .next()
            .unwrap_or_default();
        !scheme.is_empty() && scheme.as_bytes()[0].is_ascii_alphabetic()
    })
}

fn contains_draft_uuid(value: &str) -> bool {
    value.as_bytes().windows(36).any(|candidate| {
        [8, 13, 18, 23]
            .iter()
            .all(|index| candidate[*index] == b'-')
            && candidate
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
    })
}

fn contains_draft_hash(value: &str) -> bool {
    let mut length = 0usize;
    let mut has_digit = false;
    let mut has_hex_letter = false;
    for byte in value.bytes().chain(std::iter::once(b' ')) {
        if byte.is_ascii_hexdigit() {
            length += 1;
            has_digit |= byte.is_ascii_digit();
            has_hex_letter |= matches!(byte.to_ascii_lowercase(), b'a'..=b'f');
        } else {
            if length >= 16 && has_digit && has_hex_letter {
                return true;
            }
            length = 0;
            has_digit = false;
            has_hex_letter = false;
        }
    }
    false
}

fn contains_draft_namespaced_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b':' || bytes.get(index + 1) == Some(&b'/') {
            continue;
        }
        let left_start = bytes[..index]
            .iter()
            .rposition(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
            .map_or(0, |position| position + 1);
        let right_end = bytes[index + 1..]
            .iter()
            .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
            .map_or(bytes.len(), |position| index + 1 + position);
        let left = &bytes[left_start..index];
        let right = &bytes[index + 1..right_end];
        if left.len() >= 2
            && left[0].is_ascii_alphabetic()
            && !right.is_empty()
            && right.iter().any(|byte| byte.is_ascii_alphanumeric())
        {
            return true;
        }
    }
    false
}

fn enforce_public_document_boundary(
    title: &mut String,
    fallback_title: &str,
    fields: &mut [DocumentField],
    sections: &mut [DocumentSection],
    tables: &mut [DocumentTable],
) {
    *title = public_single_line(title).unwrap_or_else(|| fallback_title.to_owned());

    for field in fields {
        field.value = public_multiline_text(&field.value).unwrap_or_else(|| "待核对".to_owned());
    }
    for section in sections {
        section.heading = public_single_line(&section.heading).unwrap_or_else(|| "正文".to_owned());
        section.paragraphs = std::mem::take(&mut section.paragraphs)
            .into_iter()
            .flat_map(|paragraph| public_text_lines(&paragraph))
            .collect();
    }
    for table in tables {
        table.section_heading =
            public_single_line(&table.section_heading).unwrap_or_else(|| "正文".to_owned());
        for header in &mut table.headers {
            *header = public_single_line(header).unwrap_or_else(|| "内容".to_owned());
        }
        for row in &mut table.rows {
            for cell in &mut row.cells {
                *cell = public_multiline_text(cell).unwrap_or_else(|| "待核对".to_owned());
            }
        }
    }
}

fn public_single_line(value: &str) -> Option<String> {
    public_text_lines(value).into_iter().next()
}

fn public_multiline_text(value: &str) -> Option<String> {
    let lines = public_text_lines(value);
    (!lines.is_empty()).then(|| lines.join("；"))
}

fn public_text_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !public_text_is_non_deliverable(line))
        .map(str::to_owned)
        .collect()
}

fn standalone_fields(input: &StandaloneDocumentInput) -> Vec<DocumentField> {
    [
        ("title", &input.title),
        ("party_a", &input.party_a),
        ("party_b", &input.party_b),
        ("facts", &input.facts),
        ("requests", &input.requests),
        ("evidence", &input.evidence),
        ("requirements", &input.requirements),
    ]
    .into_iter()
    .filter(|(_, value)| !value.trim().is_empty())
    .map(|(key, value)| DocumentField {
        key: key.to_owned(),
        value: value.trim().to_owned(),
        source_kind: "user_input".to_owned(),
        source_id: String::new(),
    })
    .collect()
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
        headers: vec!["序号", "证据名称", "来源及形成日期", "证明目的"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        column_widths_dxa: vec![720, 2_160, 2_160, 4_320],
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

fn push_citation_section(
    citations: &[DocumentCitation],
    heading: &str,
    sections: &mut Vec<DocumentSection>,
) {
    if citations.is_empty() {
        return;
    }
    let source_ids = citations
        .iter()
        .map(|citation| citation.source_id.clone())
        .collect::<Vec<_>>();
    let paragraphs = citations
        .iter()
        .map(|citation| {
            format!(
                "{}：{}",
                public_citation_label(citation),
                citation.excerpt.trim()
            )
        })
        .collect();
    sections.push(section(heading, paragraphs, source_ids));
}

fn push_reference_table(
    citations: &[DocumentCitation],
    sections: &mut Vec<DocumentSection>,
    tables: &mut Vec<DocumentTable>,
) {
    let heading = "法律依据与案例引用表";
    let source_ids = citations
        .iter()
        .map(|citation| citation.source_id.clone())
        .collect::<Vec<_>>();
    sections.push(section(heading, Vec::new(), source_ids.clone()));
    tables.push(DocumentTable {
        section_heading: heading.to_owned(),
        headers: vec![
            "类型",
            "法律或案例名称",
            "条款或案号",
            "施行或裁判年份",
            "引用内容",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        column_widths_dxa: vec![720, 2_160, 1_800, 1_320, 3_360],
        rows: if citations.is_empty() {
            vec![DocumentTableRow {
                cells: vec![
                    "未引用".to_owned(),
                    "本文未列明法律或案例依据".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                ],
                source_ids: Vec::new(),
            }]
        } else {
            citations
                .iter()
                .map(|citation| DocumentTableRow {
                    cells: vec![
                        match citation.kind {
                            DocumentCitationKind::Law => "法条".to_owned(),
                            DocumentCitationKind::JudicialCase => "案例".to_owned(),
                        },
                        public_reference_title(citation),
                        citation.locator.clone(),
                        public_reference_date_label(citation),
                        citation.excerpt.clone(),
                    ],
                    source_ids: vec![citation.source_id.clone()],
                })
                .collect()
        },
        source_ids,
    });
}

fn public_law_locator(article_number: &str, canonical_label: &str) -> String {
    let article_number = article_number.trim();
    if article_number.contains('款') {
        return article_number.to_owned();
    }
    let paragraph = explicit_paragraph_label(canonical_label);
    match paragraph {
        Some(paragraph) => format!("{article_number}{paragraph}"),
        None => article_number.to_owned(),
    }
}

fn explicit_paragraph_label(value: &str) -> Option<&str> {
    let paragraph_end = value.find('款')? + '款'.len_utf8();
    let before = &value[..paragraph_end];
    let paragraph_start = before.rfind('第')?;
    let label = &before[paragraph_start..paragraph_end];
    (label.chars().count() >= 3).then_some(label)
}

fn public_citation_label(citation: &DocumentCitation) -> String {
    let year = public_reference_year(citation);
    match citation.kind {
        DocumentCitationKind::Law => format!(
            "{}{}（{}起施行）",
            public_reference_title(citation),
            citation.locator,
            year
        ),
        DocumentCitationKind::JudicialCase => format!(
            "{}（案号：{}；{}裁判）",
            public_reference_title(citation),
            citation.locator,
            year
        ),
    }
}

fn public_reference_title(citation: &DocumentCitation) -> String {
    let title = if citation.title.trim().is_empty() {
        canonical_reference_title(&citation.canonical_label).unwrap_or("名称未载明")
    } else {
        citation.title.trim()
    };
    match citation.kind {
        DocumentCitationKind::Law => format!("《{title}》"),
        DocumentCitationKind::JudicialCase => title.to_owned(),
    }
}

fn canonical_reference_title(value: &str) -> Option<&str> {
    let start = value.find('《')? + '《'.len_utf8();
    let end = value[start..].find('》')? + start;
    (start < end).then_some(&value[start..end])
}

fn public_reference_date_label(citation: &DocumentCitation) -> String {
    let year = public_reference_year(citation);
    match citation.kind {
        DocumentCitationKind::Law => format!("{year}起施行"),
        DocumentCitationKind::JudicialCase => format!("{year}裁判"),
    }
}

fn public_reference_year(citation: &DocumentCitation) -> String {
    let value = citation.effective_or_decided_on.trim();
    if value.len() >= 4 && value[..4].bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}年", &value[..4])
    } else {
        "年份未载明".to_owned()
    }
}

fn project_overview(workspace: &CaseWorkspace) -> Vec<String> {
    let mut paragraphs = vec![format!("案件名称：{}", workspace.project.title)];
    paragraphs.push(format!(
        "案件类型：{}",
        public_case_type_label(&workspace.project.case_type)
    ));
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

fn public_case_type_label(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "civil" | "civil_case" => "民事案件".to_owned(),
        "criminal" | "criminal_case" => "刑事案件".to_owned(),
        "administrative" | "administrative_case" => "行政案件".to_owned(),
        "arbitration" => "仲裁案件".to_owned(),
        "enforcement" => "执行案件".to_owned(),
        "labor" | "labour" => "劳动争议案件".to_owned(),
        "other" => "其他案件".to_owned(),
        _ => value.trim().to_owned(),
    }
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
        "-".to_owned()
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
            public_case_type_label(&workspace.project.case_type),
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
    }
    output
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], "；")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::*;

    fn normalize_golden_text(value: &str) -> String {
        value.replace("\r\n", "\n").trim_end().to_owned()
    }

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
                article_number: "第五百七十七条第一款".into(),
                article_title: None,
                canonical_label: "《民法典》第五百七十七条第一款".into(),
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
            assert_eq!(doc.template.version, "2.1.0");
            assert!(doc
                .tables
                .iter()
                .all(|table| table.column_widths_dxa.iter().sum::<u32>() == 9_360));
            assert!(!doc.markdown.contains("来源标识"));
            assert!(doc
                .sections
                .iter()
                .any(|section| !section.source_ids.is_empty()));
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
        let expected = normalize_golden_text(include_str!("../testdata/document_templates.golden"));
        assert_eq!(actual, expected);
    }

    #[test]
    fn template_golden_comparison_normalizes_windows_line_endings() {
        assert_eq!(
            normalize_golden_text("第一行\r\n第二行\r\n"),
            "第一行\n第二行"
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
    fn citations_are_valid_only_deduplicated_and_internal_ids_are_not_rendered() {
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
        assert!(!doc.markdown.contains("law:1"));
        assert!(!doc.markdown.contains("d1"));
        assert!(!doc.markdown.contains("v1"));
        assert!(!doc.markdown.contains("a1"));
        assert!(!doc
            .tables
            .iter()
            .any(|table| table.section_heading == "引用来源映射"));
        let references = doc
            .tables
            .iter()
            .find(|table| table.section_heading == "法律依据与案例引用表")
            .expect("deliverable ends with a public citation table");
        assert_eq!(
            references.rows[0].cells,
            vec![
                "法条",
                "《民法典》",
                "第五百七十七条第一款",
                "2021年起施行",
                "违约方应承担违约责任。"
            ]
        );
        assert!(doc
            .markdown
            .contains("《民法典》第五百七十七条第一款（2021年起施行）"));
    }

    #[test]
    fn unknown_paragraph_is_never_inferred_from_multi_paragraph_article_text() {
        let mut unknown = workspace();
        unknown.legal_basis[0].article_number = "第五百七十七条".into();
        unknown.legal_basis[0].canonical_label = "《民法典》第五百七十七条".into();
        unknown.legal_basis[0].excerpt =
            "债务人未履行合同义务，应当承担违约责任。\n当事人另有约定的，依照其约定。".into();

        let error = generate_document(&unknown, DocumentTemplateId::LegalResearchReport, None)
            .expect_err("an article without an explicit paragraph cannot become a formal citation");
        assert!(error.missing_fields.contains(&"valid_citations".to_owned()));

        let mut explicit_second = workspace();
        explicit_second.legal_basis[0].article_number = "第五百七十七条".into();
        explicit_second.legal_basis[0].canonical_label = "《民法典》第五百七十七条第二款".into();
        let document = generate_document(
            &explicit_second,
            DocumentTemplateId::LegalResearchReport,
            None,
        )
        .expect("an explicitly verified second paragraph remains citable");
        assert_eq!(document.citations[0].locator, "第五百七十七条第二款");
        assert!(!document.markdown.contains("第五百七十七条第一款"));
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
            vec!["序号", "证据名称", "来源及形成日期", "证明目的"]
        );
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].source_ids, vec!["e1"]);
        assert!(doc.markdown.contains("| 序号 | 证据名称 |"));
        assert!(!doc.markdown.contains("存储位置"));
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
    fn model_draft_exports_only_public_legal_paragraphs() {
        let draft = concat!(
            "依照双方确认的合同内容，付款义务已经届期。\n",
            "article_id=art-deadbeef0123456789abcdef\n",
            "{\"schema_version\":1,\"snippet\":\"内部摘要\"}\n",
            "[SRC:law:1] 内部法源\n",
            "C:\\cases\\private\\draft.json\n",
            "https://local.invalid/internal\n",
            "019f6e3e-6822-70c1-86a7-6f88022a815e\n",
            "deadbeef0123456789abcdef\n",
            "无标题\n",
            "结构化文书预览\n",
            "模型措辞\n",
        );

        let document = generate_document(&workspace(), DocumentTemplateId::Complaint, Some(draft))
            .expect("safe draft paragraphs remain exportable");
        let supplemental = document
            .sections
            .iter()
            .find(|section| section.heading == "补充陈述（待律师复核）")
            .expect("one safe public paragraph remains");
        assert_eq!(
            supplemental.paragraphs,
            vec!["依照双方确认的合同内容，付款义务已经届期。"]
        );
        for internal in [
            "article_id",
            "schema_version",
            "snippet",
            "[SRC:",
            "C:\\cases",
            "https://",
            "019f6e3e",
            "deadbeef",
            "无标题",
            "结构化文书预览",
            "模型措辞",
        ] {
            assert!(
                !document.markdown.contains(internal),
                "traditional document leaked {internal}"
            );
        }

        let input = StandaloneDocumentInput {
            title: "催款函".into(),
            facts: "乙方尚欠到期货款。".into(),
            ..Default::default()
        };
        let standalone =
            generate_standalone_document(&input, DocumentTemplateId::LawyerLetter, Some(draft))
                .expect("standalone document uses the same hard boundary");
        assert!(standalone
            .markdown
            .contains("依照双方确认的合同内容，付款义务已经届期。"));
        assert!(!standalone.markdown.contains("article_id"));
        assert!(!standalone.markdown.contains("[SRC:"));
    }

    #[test]
    fn persisted_case_text_is_projected_through_the_same_markdown_and_pdf_boundary() {
        let mut workspace = workspace();
        workspace.project.title = "proposalHash=deadbeef0123456789abcdef".into();
        workspace.project.summary = r#"{"sourceRefs":["material:1"]}"#.into();
        workspace.parties[0].name = "sourceRefs=party:1".into();
        workspace.parties[0].contact = r"C:\cases\client.txt".into();
        workspace.parties[0].notes = "service-hash=deadbeef0123456789abcdef".into();
        workspace.facts[0].title = "无标题".into();
        workspace.facts[0].description = "proposalHash=deadbeef0123456789abcdef".into();
        workspace.evidence[0].title = "019f6e3e-6822-70c1-86a7-6f88022a815e".into();
        workspace.evidence[0].source = r"C:\cases\evidence.pdf".into();
        workspace.evidence[0].summary = r#"{"schema_version":1,"snippet":"内部"}"#.into();
        workspace.legal_issues[0].title = "sourceRefs=issue:1".into();
        workspace.legal_issues[0].claim = "[SRC:law:1]".into();
        workspace.legal_basis[0].excerpt = "snippet=内部摘要".into();

        let document = generate_document(&workspace, DocumentTemplateId::Complaint, None)
            .expect("contaminated persisted text is isolated from the deliverable");
        assert_eq!(document.title, "民事起诉状");
        assert!(document.citations.is_empty());

        // The desktop PDF renderer consumes these exact title/section/table
        // fields, so testing this projection covers both Markdown and PDF.
        let mut public_payload = document.title.clone();
        for field in &document.fields {
            public_payload.push_str(&field.value);
        }
        for section in &document.sections {
            public_payload.push_str(&section.heading);
            for paragraph in &section.paragraphs {
                public_payload.push_str(paragraph);
            }
        }
        for table in &document.tables {
            public_payload.push_str(&table.section_heading);
            for header in &table.headers {
                public_payload.push_str(header);
            }
            for row in &table.rows {
                for cell in &row.cells {
                    public_payload.push_str(cell);
                }
            }
        }
        public_payload.push_str(&document.markdown);

        for internal in [
            "proposalHash",
            "sourceRefs",
            "service-hash",
            "deadbeef0123456789abcdef",
            "C:\\cases",
            "schema_version",
            "snippet",
            "[SRC:",
            "019f6e3e-6822-70c1-86a7-6f88022a815e",
            "无标题",
        ] {
            assert!(
                !public_payload.contains(internal),
                "public document projection leaked {internal}"
            );
        }
        assert!(public_payload.contains("待核对"));
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

    #[test]
    fn standalone_generation_needs_no_case_project_and_hides_internal_sources() {
        let input = StandaloneDocumentInput {
            title: "关于催付货款的律师函".into(),
            party_a: "甲公司".into(),
            party_b: "乙公司".into(),
            facts: "2026年1月交付货物，乙公司尚欠货款10万元。".into(),
            requests: "收到函件后七日内支付全部货款。".into(),
            requirements: "语气正式、简洁。".into(),
            ..Default::default()
        };

        let document = generate_standalone_document(&input, DocumentTemplateId::LawyerLetter, None)
            .expect("direct user material generates without a case");

        assert_eq!(document.title, input.title);
        assert!(document.markdown.contains("发函方：甲公司"));
        assert!(document.markdown.contains("七日内支付全部货款"));
        assert!(!document.markdown.contains("来源标识"));
        assert!(document
            .markdown
            .trim_end()
            .ends_with("| 未引用 | 本文未列明法律或案例依据 | — | — | — |"));
        assert!(document.citations.is_empty());
    }

    #[test]
    fn standalone_generation_rejects_an_entirely_empty_brief() {
        let error = generate_standalone_document(
            &StandaloneDocumentInput::default(),
            DocumentTemplateId::Complaint,
            None,
        )
        .expect_err("empty standalone input is not useful");

        assert_eq!(error.missing_fields, vec!["standalone_content"]);
    }

    #[test]
    fn judicial_case_citations_use_a_human_case_number_and_decision_year() {
        let citation = DocumentCitation {
            kind: DocumentCitationKind::JudicialCase,
            title: "张某与甲公司买卖合同纠纷案".into(),
            locator: "（2025）京01民终1234号".into(),
            effective_or_decided_on: "2025-06-18".into(),
            source_id: "internal-case-source".into(),
            canonical_label: String::new(),
            excerpt: "裁判要旨".into(),
            document_id: "internal-document".into(),
            version_id: "internal-version".into(),
            article_id: "internal-record".into(),
        };

        assert_eq!(
            public_citation_label(&citation),
            "张某与甲公司买卖合同纠纷案（案号：（2025）京01民终1234号；2025年裁判）"
        );
    }
}
