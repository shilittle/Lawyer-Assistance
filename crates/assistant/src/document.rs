use crate::validation::{
    add_text_bytes, insert_unique, validate_count, validate_identifier, validate_nonempty_count,
    validate_optional_text, validate_required_text, validate_schema_version, validate_total_text,
};
use crate::{ContractError, ContractErrorType, ValidationContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_DOCUMENT_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_DOCUMENT_TITLE_BYTES: usize = 256;
pub const MAX_DOCUMENT_PARTIES: usize = 32;
pub const MAX_DOCUMENT_SECTIONS: usize = 64;
pub const MAX_CLAUSES_PER_SECTION: usize = 64;
pub const MAX_DOCUMENT_ASSUMPTIONS: usize = 64;
pub const MAX_DOCUMENT_MISSING_INFORMATION: usize = 64;
pub const MAX_DOCUMENT_SOURCE_MATERIALS: usize = 128;
pub const MAX_DOCUMENT_LEGAL_CITATIONS: usize = 128;
pub const MAX_DOCUMENT_RISK_WARNINGS: usize = 64;
pub const MAX_PROVENANCE_REFS_PER_ITEM: usize = 16;

pub const MAX_PARTY_NAME_BYTES: usize = 256;
pub const MAX_PARTY_ROLE_BYTES: usize = 128;
pub const MAX_PARTY_DETAILS_BYTES: usize = 2 * 1024;
pub const MAX_SECTION_HEADING_BYTES: usize = 256;
pub const MAX_SECTION_BODY_BYTES: usize = 32 * 1024;
pub const MAX_CLAUSE_HEADING_BYTES: usize = 256;
pub const MAX_CLAUSE_BODY_BYTES: usize = 16 * 1024;
pub const MAX_ASSUMPTION_BYTES: usize = 2 * 1024;
pub const MAX_MISSING_INFORMATION_BYTES: usize = 2 * 1024;
pub const MAX_SOURCE_LABEL_BYTES: usize = 512;
pub const MAX_SOURCE_LOCATOR_BYTES: usize = 256;
pub const MAX_CITATION_TEXT_BYTES: usize = 2 * 1024;
pub const MAX_CITATION_PROPOSITION_BYTES: usize = 4 * 1024;
pub const MAX_CITATION_MARKER_BYTES: usize = 256;
pub const MAX_RISK_WARNING_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentType {
    Contract,
    Complaint,
    Defence,
    EvidenceSchedule,
    FactTimeline,
    LegalResearchReport,
    LawyerLetter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMaterialKind {
    UserMaterial,
    ConfirmedCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    UserMaterial,
    ConfirmedCase,
    ModelWording,
    LocalLegalSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceRef {
    pub kind: ProvenanceKind,
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentParty {
    pub id: String,
    pub name: String,
    pub role: String,
    pub details: Option<String>,
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentClause {
    pub id: String,
    pub heading: Option<String>,
    pub body: String,
    pub factual: bool,
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentSection {
    pub id: String,
    pub heading: String,
    pub body: String,
    pub factual: bool,
    pub provenance: Vec<ProvenanceRef>,
    pub clauses: Vec<DocumentClause>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentAssumption {
    pub text: String,
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissingInformation {
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceMaterial {
    pub id: String,
    pub kind: SourceMaterialKind,
    pub label: String,
    pub locator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalCitation {
    pub id: String,
    pub source_ref: String,
    pub marker: String,
    pub citation: String,
    pub proposition: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicCitationKind {
    Law,
    JudicialCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicCitationParts<'a> {
    pub kind: PublicCitationKind,
    pub title: &'a str,
    pub locator: &'a str,
    pub year: &'a str,
}

/// Parses the only two citation forms allowed to cross the public document
/// boundary. Opaque source identifiers remain in the adjacent machine fields.
pub fn parse_public_citation(value: &str) -> Option<PublicCitationParts<'_>> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('《') {
        let (title, rest) = rest.split_once('》')?;
        let rest = rest.strip_prefix('第')?;
        let (article, rest) = rest.split_once("条第")?;
        let (paragraph, year) = rest.split_once("款（")?;
        let year = year.strip_suffix("年起施行）")?;
        if [title, article, paragraph]
            .iter()
            .any(|part| part.trim().is_empty())
            || !valid_public_year(year)
        {
            return None;
        }
        let locator_start = title.len() + '《'.len_utf8() + '》'.len_utf8();
        let locator_end = value.rfind('（')?;
        return Some(PublicCitationParts {
            kind: PublicCitationKind::Law,
            title,
            locator: &value[locator_start..locator_end],
            year,
        });
    }

    let (title, rest) = value.split_once("（案号：")?;
    let (case_number, year) = rest.split_once('；')?;
    let year = year.strip_suffix("年裁判）")?;
    if title.trim().is_empty() || case_number.trim().is_empty() || !valid_public_year(year) {
        return None;
    }
    Some(PublicCitationParts {
        kind: PublicCitationKind::JudicialCase,
        title,
        locator: case_number,
        year,
    })
}

fn valid_public_year(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentSpec {
    pub schema_version: u16,
    pub document_type: DocumentType,
    pub title: String,
    pub parties: Vec<DocumentParty>,
    pub sections: Vec<DocumentSection>,
    pub assumptions: Vec<DocumentAssumption>,
    pub missing_information: Vec<MissingInformation>,
    pub source_materials: Vec<SourceMaterial>,
    pub legal_citations: Vec<LegalCitation>,
    pub risk_warnings: Vec<String>,
}

impl DocumentSpec {
    pub fn validate(&self, context: &ValidationContext) -> Result<(), ContractError> {
        validate_schema_version("document.schemaVersion", self.schema_version)?;
        validate_required_text("document.title", &self.title, MAX_DOCUMENT_TITLE_BYTES)?;
        validate_public_output_text("document.title", &self.title)?;
        validate_count("document.parties", self.parties.len(), MAX_DOCUMENT_PARTIES)?;
        validate_nonempty_count(
            "document.sections",
            self.sections.len(),
            MAX_DOCUMENT_SECTIONS,
        )?;
        validate_count(
            "document.assumptions",
            self.assumptions.len(),
            MAX_DOCUMENT_ASSUMPTIONS,
        )?;
        validate_count(
            "document.missingInformation",
            self.missing_information.len(),
            MAX_DOCUMENT_MISSING_INFORMATION,
        )?;
        validate_count(
            "document.sourceMaterials",
            self.source_materials.len(),
            MAX_DOCUMENT_SOURCE_MATERIALS,
        )?;
        validate_count(
            "document.legalCitations",
            self.legal_citations.len(),
            MAX_DOCUMENT_LEGAL_CITATIONS,
        )?;
        validate_count(
            "document.riskWarnings",
            self.risk_warnings.len(),
            MAX_DOCUMENT_RISK_WARNINGS,
        )?;

        let mut total_text = self.title.len();
        let source_kinds = self.validate_sources(context, &mut total_text)?;
        let legal_sources = self.validate_citations(context, &mut total_text)?;
        let mut all_ids = BTreeSet::new();

        for (index, party) in self.parties.iter().enumerate() {
            let path = format!("document.parties[{index}]");
            insert_unique(&mut all_ids, &format!("{path}.id"), &party.id)?;
            validate_required_text(&format!("{path}.name"), &party.name, MAX_PARTY_NAME_BYTES)?;
            validate_required_text(&format!("{path}.role"), &party.role, MAX_PARTY_ROLE_BYTES)?;
            validate_optional_text(
                &format!("{path}.details"),
                party.details.as_deref(),
                MAX_PARTY_DETAILS_BYTES,
            )?;
            validate_public_output_text(&format!("{path}.name"), &party.name)?;
            validate_public_output_text(&format!("{path}.role"), &party.role)?;
            if let Some(details) = &party.details {
                validate_public_output_text(&format!("{path}.details"), details)?;
            }
            validate_provenance(
                &format!("{path}.provenance"),
                &party.provenance,
                false,
                &source_kinds,
                &legal_sources,
            )?;
            add_text_bytes(&mut total_text, &party.name);
            add_text_bytes(&mut total_text, &party.role);
            if let Some(details) = &party.details {
                add_text_bytes(&mut total_text, details);
            }
        }

        for (index, section) in self.sections.iter().enumerate() {
            let path = format!("document.sections[{index}]");
            insert_unique(&mut all_ids, &format!("{path}.id"), &section.id)?;
            validate_required_text(
                &format!("{path}.heading"),
                &section.heading,
                MAX_SECTION_HEADING_BYTES,
            )?;
            validate_required_text(
                &format!("{path}.body"),
                &section.body,
                MAX_SECTION_BODY_BYTES,
            )?;
            validate_public_output_text(&format!("{path}.heading"), &section.heading)?;
            validate_public_output_text(&format!("{path}.body"), &section.body)?;
            validate_provenance(
                &format!("{path}.provenance"),
                &section.provenance,
                section.factual,
                &source_kinds,
                &legal_sources,
            )?;
            validate_count(
                &format!("{path}.clauses"),
                section.clauses.len(),
                MAX_CLAUSES_PER_SECTION,
            )?;
            add_text_bytes(&mut total_text, &section.heading);
            add_text_bytes(&mut total_text, &section.body);
            for (clause_index, clause) in section.clauses.iter().enumerate() {
                let clause_path = format!("{path}.clauses[{clause_index}]");
                insert_unique(&mut all_ids, &format!("{clause_path}.id"), &clause.id)?;
                validate_optional_text(
                    &format!("{clause_path}.heading"),
                    clause.heading.as_deref(),
                    MAX_CLAUSE_HEADING_BYTES,
                )?;
                validate_required_text(
                    &format!("{clause_path}.body"),
                    &clause.body,
                    MAX_CLAUSE_BODY_BYTES,
                )?;
                if let Some(heading) = &clause.heading {
                    validate_public_output_text(&format!("{clause_path}.heading"), heading)?;
                }
                validate_public_output_text(&format!("{clause_path}.body"), &clause.body)?;
                validate_provenance(
                    &format!("{clause_path}.provenance"),
                    &clause.provenance,
                    clause.factual,
                    &source_kinds,
                    &legal_sources,
                )?;
                if let Some(heading) = &clause.heading {
                    add_text_bytes(&mut total_text, heading);
                }
                add_text_bytes(&mut total_text, &clause.body);
            }
        }

        for (index, assumption) in self.assumptions.iter().enumerate() {
            let path = format!("document.assumptions[{index}]");
            validate_required_text(
                &format!("{path}.text"),
                &assumption.text,
                MAX_ASSUMPTION_BYTES,
            )?;
            validate_public_output_text(&format!("{path}.text"), &assumption.text)?;
            validate_provenance(
                &format!("{path}.provenance"),
                &assumption.provenance,
                false,
                &source_kinds,
                &legal_sources,
            )?;
            add_text_bytes(&mut total_text, &assumption.text);
        }

        for (index, missing) in self.missing_information.iter().enumerate() {
            validate_required_text(
                &format!("document.missingInformation[{index}].description"),
                &missing.description,
                MAX_MISSING_INFORMATION_BYTES,
            )?;
            validate_public_output_text(
                &format!("document.missingInformation[{index}].description"),
                &missing.description,
            )?;
            add_text_bytes(&mut total_text, &missing.description);
        }
        for (index, warning) in self.risk_warnings.iter().enumerate() {
            validate_required_text(
                &format!("document.riskWarnings[{index}]"),
                warning,
                MAX_RISK_WARNING_BYTES,
            )?;
            validate_public_output_text(&format!("document.riskWarnings[{index}]"), warning)?;
            add_text_bytes(&mut total_text, warning);
        }
        validate_total_text("document", total_text, MAX_DOCUMENT_TEXT_BYTES)
    }

    fn validate_sources(
        &self,
        context: &ValidationContext,
        total_text: &mut usize,
    ) -> Result<BTreeMap<String, SourceMaterialKind>, ContractError> {
        let mut source_kinds = BTreeMap::new();
        for (index, source) in self.source_materials.iter().enumerate() {
            let path = format!("document.sourceMaterials[{index}]");
            validate_identifier(&format!("{path}.id"), &source.id)?;
            if source_kinds
                .insert(source.id.clone(), source.kind)
                .is_some()
            {
                return Err(ContractError::new(
                    ContractErrorType::DuplicateIdentifier,
                    format!("{path}.id"),
                    "source material identifier must be unique",
                ));
            }
            if !context.is_source_allowed(&source.id) {
                return Err(ContractError::new(
                    ContractErrorType::UnknownReference,
                    format!("{path}.id"),
                    "source material is not owned by the current run",
                ));
            }
            validate_required_text(
                &format!("{path}.label"),
                &source.label,
                MAX_SOURCE_LABEL_BYTES,
            )?;
            validate_public_output_text(&format!("{path}.label"), &source.label)?;
            validate_optional_text(
                &format!("{path}.locator"),
                source.locator.as_deref(),
                MAX_SOURCE_LOCATOR_BYTES,
            )?;
            add_text_bytes(total_text, &source.label);
            if let Some(locator) = &source.locator {
                add_text_bytes(total_text, locator);
            }
        }
        Ok(source_kinds)
    }

    fn validate_citations(
        &self,
        context: &ValidationContext,
        total_text: &mut usize,
    ) -> Result<BTreeSet<String>, ContractError> {
        let mut ids = BTreeSet::new();
        let mut legal_sources = BTreeSet::new();
        for (index, citation) in self.legal_citations.iter().enumerate() {
            let path = format!("document.legalCitations[{index}]");
            insert_unique(&mut ids, &format!("{path}.id"), &citation.id)?;
            validate_identifier(&format!("{path}.sourceRef"), &citation.source_ref)?;
            if !context.is_legal_source_validated(&citation.source_ref) {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.sourceRef"),
                    "legal citation was not validated against the local source set",
                ));
            }
            validate_required_text(
                &format!("{path}.marker"),
                &citation.marker,
                MAX_CITATION_MARKER_BYTES,
            )?;
            if citation.marker != format!("[SRC:{}]", citation.source_ref) {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.marker"),
                    "citation marker does not match its validated local source",
                ));
            }
            validate_required_text(
                &format!("{path}.citation"),
                &citation.citation,
                MAX_CITATION_TEXT_BYTES,
            )?;
            if parse_public_citation(&citation.citation).is_none() {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.citation"),
                    "public citation must include the legal or case name, exact locator, and year",
                ));
            }
            validate_public_output_text(&format!("{path}.citation"), &citation.citation)?;
            validate_required_text(
                &format!("{path}.proposition"),
                &citation.proposition,
                MAX_CITATION_PROPOSITION_BYTES,
            )?;
            validate_public_output_text(&format!("{path}.proposition"), &citation.proposition)?;
            legal_sources.insert(citation.source_ref.clone());
            add_text_bytes(total_text, &citation.marker);
            add_text_bytes(total_text, &citation.citation);
            add_text_bytes(total_text, &citation.proposition);
        }
        Ok(legal_sources)
    }
}

/// Enforces the final user-document boundary independently of model prompts.
/// Machine identifiers are still accepted in the adjacent structured fields,
/// but never in text that a renderer can place in Markdown or Word output.
pub fn validate_public_output_text(path: &str, value: &str) -> Result<(), ContractError> {
    if contains_non_deliverable_public_content(value) {
        return Err(ContractError::new(
            ContractErrorType::InvalidEnvelope,
            path,
            "public document text contains non-deliverable content",
        ));
    }
    Ok(())
}

fn contains_non_deliverable_public_content(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if [
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
        "内部日志",
        "诊断日志",
        "调试信息",
        "工程信息",
        "模型输出",
        "模型生成",
        "模型建议",
        "服务端保存",
        "后端预览",
        "前端净化",
        "导出边界",
        "公开输出边界",
        "内部过程",
        "工程过程",
        "请求参数",
        "调用参数",
        "工具调用",
        "系统提示词",
        "原始请求",
        "原始响应",
        "协议字段",
        "接口字段",
        "渲染器",
        "原始json",
        "原始 json",
        "internal field",
        "internal identifier",
        "internal id",
        "internal path",
        "engineering field",
        "schema field",
        "protocol field",
        "debug log",
        "diagnostic log",
        "stack trace",
        "traceback",
        "system prompt",
        "tool call",
        "raw request",
        "raw response",
        "model output",
        "model generated",
        "backend",
        "frontend",
        "renderer",
        "tauri command",
        "ipc command",
        "mcp server",
        "stdio",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    contains_raw_json(trimmed)
        || contains_forbidden_ascii_field(&lower)
        || contains_path_or_uri(trimmed, &lower)
        || contains_relative_engineering_path(trimmed, &lower)
        || contains_uuid(trimmed)
        || contains_hash(trimmed)
        || contains_opaque_service_identifier(&lower)
        || contains_namespaced_identifier(trimmed)
}

fn contains_relative_engineering_path(value: &str, lower: &str) -> bool {
    if [
        "../",
        "./",
        "src/",
        "apps/",
        "crates/",
        "target/",
        "node_modules/",
        ".git/",
        ".github/",
        ".codex/",
        "frontend-dist/",
        "integrations/",
        "resources/",
        "docs/",
        "scripts/",
        "tests/",
        "vendor/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    value
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '，' | '。' | '；' | '：' | ',' | ';' | '(' | ')' | '（' | '）' | '<' | '>'
                )
        })
        .map(|token| {
            token.trim_matches(|character: char| matches!(character, '"' | '\'' | '`' | '[' | ']'))
        })
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            [
                ".rs", ".toml", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs", ".py", ".ps1",
                ".sqlite", ".db", ".exe", ".dll",
            ]
            .iter()
            .any(|extension| lower.ends_with(extension))
        })
}

fn contains_opaque_service_identifier(lower: &str) -> bool {
    lower
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .any(|token| {
            let Some(value) = token.strip_prefix("service-") else {
                return false;
            };
            let mut parts = value.split('-');
            let Some(digest) = parts.next() else {
                return false;
            };
            let Some(sequence) = parts.next() else {
                return false;
            };
            parts.next().is_none()
                && (8..=64).contains(&digest.len())
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !sequence.is_empty()
                && sequence.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn contains_raw_json(value: &str) -> bool {
    if value.contains("```") {
        return true;
    }
    if matches!(
        serde_json::from_str::<serde_json::Value>(value),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    ) {
        return true;
    }

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

fn contains_forbidden_ascii_field(lower: &str) -> bool {
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
                    | "tool_call_id"
                    | "toolcallid"
                    | "user_id"
                    | "userid"
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
                    | "base_case_digest"
                    | "basecasedigest"
                    | "case_date"
                    | "casedate"
                    | "cursor"
                    | "generation_hash"
                    | "generationhash"
                    | "input_audit"
                    | "inputaudit"
                    | "metadata"
                    | "output_audit"
                    | "outputaudit"
                    | "provider_snapshot"
                    | "providersnapshot"
                    | "score"
                    | "sha"
                    | "sha256"
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
                    | "source_audit"
                    | "sourceaudit"
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

fn contains_path_or_uri(value: &str, lower: &str) -> bool {
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
            "localhost",
            "127.0.0.1",
            "[::1]",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }

    let bytes = value.as_bytes();
    if bytes.windows(3).any(|part| {
        part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
    }) {
        return true;
    }

    lower.match_indices("://").any(|(index, _)| {
        let scheme = lower[..index]
            .rsplit(|character: char| !character.is_ascii_alphanumeric() && character != '+')
            .next()
            .unwrap_or_default();
        !scheme.is_empty() && scheme.as_bytes()[0].is_ascii_alphabetic()
    })
}

fn contains_uuid(value: &str) -> bool {
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

fn contains_hash(value: &str) -> bool {
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

fn contains_namespaced_identifier(value: &str) -> bool {
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

fn validate_provenance(
    path: &str,
    provenance: &[ProvenanceRef],
    factual: bool,
    source_kinds: &BTreeMap<String, SourceMaterialKind>,
    legal_sources: &BTreeSet<String>,
) -> Result<(), ContractError> {
    validate_count(path, provenance.len(), MAX_PROVENANCE_REFS_PER_ITEM)?;
    let mut seen = BTreeSet::new();
    let mut has_grounded_fact_source = false;
    for (index, item) in provenance.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        match item.kind {
            ProvenanceKind::ModelWording => {
                if item.source_ref.is_some() {
                    return Err(ContractError::new(
                        ContractErrorType::InvalidProvenance,
                        format!("{item_path}.sourceRef"),
                        "model wording must not claim an external source",
                    ));
                }
                if !seen.insert((item.kind as u8, String::new())) {
                    return Err(ContractError::new(
                        ContractErrorType::DuplicateIdentifier,
                        item_path,
                        "provenance entries must be unique",
                    ));
                }
            }
            ProvenanceKind::UserMaterial | ProvenanceKind::ConfirmedCase => {
                let source_ref = item.source_ref.as_deref().ok_or_else(|| {
                    ContractError::new(
                        ContractErrorType::MissingProvenance,
                        format!("{item_path}.sourceRef"),
                        "grounded provenance requires a source reference",
                    )
                })?;
                validate_identifier(&format!("{item_path}.sourceRef"), source_ref)?;
                let expected_kind = match item.kind {
                    ProvenanceKind::UserMaterial => SourceMaterialKind::UserMaterial,
                    ProvenanceKind::ConfirmedCase => SourceMaterialKind::ConfirmedCase,
                    _ => unreachable!(),
                };
                if source_kinds.get(source_ref) != Some(&expected_kind) {
                    return Err(ContractError::new(
                        ContractErrorType::InvalidProvenance,
                        format!("{item_path}.sourceRef"),
                        "provenance does not match a declared source material of the same kind",
                    ));
                }
                if !seen.insert((item.kind as u8, source_ref.to_owned())) {
                    return Err(ContractError::new(
                        ContractErrorType::DuplicateIdentifier,
                        item_path,
                        "provenance entries must be unique",
                    ));
                }
                has_grounded_fact_source = true;
            }
            ProvenanceKind::LocalLegalSource => {
                let source_ref = item.source_ref.as_deref().ok_or_else(|| {
                    ContractError::new(
                        ContractErrorType::MissingProvenance,
                        format!("{item_path}.sourceRef"),
                        "legal provenance requires a source reference",
                    )
                })?;
                validate_identifier(&format!("{item_path}.sourceRef"), source_ref)?;
                if !legal_sources.contains(source_ref) {
                    return Err(ContractError::new(
                        ContractErrorType::UnvalidatedLegalCitation,
                        format!("{item_path}.sourceRef"),
                        "legal provenance must reference a declared validated citation",
                    ));
                }
                if !seen.insert((item.kind as u8, source_ref.to_owned())) {
                    return Err(ContractError::new(
                        ContractErrorType::DuplicateIdentifier,
                        item_path,
                        "provenance entries must be unique",
                    ));
                }
            }
        }
    }
    if factual && !has_grounded_fact_source {
        return Err(ContractError::new(
            ContractErrorType::MissingProvenance,
            path,
            "factual content requires user material or confirmed-case provenance",
        ));
    }
    Ok(())
}
