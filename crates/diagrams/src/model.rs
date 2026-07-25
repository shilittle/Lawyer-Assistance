use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub enum $name {
            $(#[serde(rename = $value)] $variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

string_enum!(DiagramType {
    LegalHierarchy => "legal_hierarchy",
    LegalApplicationChain => "legal_application_chain",
    LegalConflictPriority => "legal_conflict_priority",
    CasePartyRelationship => "case_party_relationship",
    CaseIssueEvidenceLaw => "case_issue_evidence_law",
    CaseMoneyFlow => "case_money_flow",
    CaseTimeline => "case_timeline",
});

string_enum!(TemplateId {
    LegalHierarchyV1 => "legal_hierarchy_v1",
    LegalApplicationChainV1 => "legal_application_chain_v1",
    LegalConflictPriorityV1 => "legal_conflict_priority_v1",
    CasePartyRelationshipV1 => "case_party_relationship_v1",
    CaseIssueEvidenceLawV1 => "case_issue_evidence_law_v1",
    CaseMoneyFlowV1 => "case_money_flow_v1",
    CaseTimelineV1 => "case_timeline_v1",
});

string_enum!(NodeType {
    Party => "party",
    Account => "account",
    Event => "event",
    LegalRelationship => "legal_relationship",
    Fact => "fact",
    Issue => "issue",
    Evidence => "evidence",
    Rule => "rule",
    Claim => "claim",
    Defense => "defense",
    Amount => "amount",
    Procedure => "procedure",
    Law => "law",
    Regulation => "regulation",
    SupervisoryRegulation => "supervisory_regulation",
    JudicialInterpretation => "judicial_interpretation",
    DepartmentRule => "department_rule",
    LocalRegulation => "local_regulation",
    LocalGovernmentRule => "local_government_rule",
    NormativeDocument => "normative_document",
    GuidingCase => "guiding_case",
    LegalPrinciple => "legal_principle",
    Element => "element",
    LegalConsequence => "legal_consequence",
    ExceptionRule => "exception_rule",
    ApplicationConclusion => "application_conclusion",
    MissingInformation => "missing_information",
});

impl NodeType {
    pub const ALL: &'static [Self] = &[
        Self::Party,
        Self::Account,
        Self::Event,
        Self::LegalRelationship,
        Self::Fact,
        Self::Issue,
        Self::Evidence,
        Self::Rule,
        Self::Claim,
        Self::Defense,
        Self::Amount,
        Self::Procedure,
        Self::Law,
        Self::Regulation,
        Self::SupervisoryRegulation,
        Self::JudicialInterpretation,
        Self::DepartmentRule,
        Self::LocalRegulation,
        Self::LocalGovernmentRule,
        Self::NormativeDocument,
        Self::GuidingCase,
        Self::LegalPrinciple,
        Self::Element,
        Self::LegalConsequence,
        Self::ExceptionRule,
        Self::ApplicationConclusion,
        Self::MissingInformation,
    ];

    pub const fn is_legal_norm(self) -> bool {
        matches!(
            self,
            Self::Rule
                | Self::ExceptionRule
                | Self::Law
                | Self::Regulation
                | Self::SupervisoryRegulation
                | Self::JudicialInterpretation
                | Self::DepartmentRule
                | Self::LocalRegulation
                | Self::LocalGovernmentRule
                | Self::NormativeDocument
        )
    }

    pub const fn is_timeline_item(self) -> bool {
        matches!(self, Self::Event | Self::Procedure)
    }
}

string_enum!(NodeStatus {
    Alleged => "alleged",
    Admitted => "admitted",
    Supported => "supported",
    Disputed => "disputed",
    Contradicted => "contradicted",
    Established => "established",
    Unsupported => "unsupported",
    Unknown => "unknown",
    Active => "active",
    Inactive => "inactive",
    Pending => "pending",
    Completed => "completed",
    Effective => "effective",
    Repealed => "repealed",
    Expired => "expired",
    NotYetEffective => "not_yet_effective",
    Uncertain => "uncertain",
    NotApplicable => "not_applicable",
});

string_enum!(Importance {
    Critical => "critical",
    High => "high",
    Normal => "normal",
    Low => "low",
});

string_enum!(Relation {
    Supports => "supports",
    Contradicts => "contradicts",
    Proves => "proves",
    Alleges => "alleges",
    Admits => "admits",
    Disputes => "disputes",
    Raises => "raises",
    AppliesTo => "applies_to",
    Requires => "requires",
    LeadsTo => "leads_to",
    BasedOn => "based_on",
    Involves => "involves",
    OccurredBefore => "occurred_before",
    OccurredAfter => "occurred_after",
    SameEventAs => "same_event_as",
    ConflictsInTimeWith => "conflicts_in_time_with",
    PaidTo => "paid_to",
    TransferredTo => "transferred_to",
    Owes => "owes",
    Guarantees => "guarantees",
    Controls => "controls",
    Owns => "owns",
    Represents => "represents",
    Employs => "employs",
    ContractsWith => "contracts_with",
    RelatedPartyOf => "related_party_of",
    SuperiorTo => "superior_to",
    AuthorizedBy => "authorized_by",
    Implements => "implements",
    References => "references",
    Supplements => "supplements",
    Interprets => "interprets",
    ExceptionTo => "exception_to",
    Limits => "limits",
    ConflictsWith => "conflicts_with",
    Repeals => "repeals",
    Amends => "amends",
    Replaces => "replaces",
    AppliesBefore => "applies_before",
    Contains => "contains",
    BelongsTo => "belongs_to",
    RelatedTo => "related_to",
});

impl Relation {
    pub const ALL: &'static [Self] = &[
        Self::Supports,
        Self::Contradicts,
        Self::Proves,
        Self::Alleges,
        Self::Admits,
        Self::Disputes,
        Self::Raises,
        Self::AppliesTo,
        Self::Requires,
        Self::LeadsTo,
        Self::BasedOn,
        Self::Involves,
        Self::OccurredBefore,
        Self::OccurredAfter,
        Self::SameEventAs,
        Self::ConflictsInTimeWith,
        Self::PaidTo,
        Self::TransferredTo,
        Self::Owes,
        Self::Guarantees,
        Self::Controls,
        Self::Owns,
        Self::Represents,
        Self::Employs,
        Self::ContractsWith,
        Self::RelatedPartyOf,
        Self::SuperiorTo,
        Self::AuthorizedBy,
        Self::Implements,
        Self::References,
        Self::Supplements,
        Self::Interprets,
        Self::ExceptionTo,
        Self::Limits,
        Self::ConflictsWith,
        Self::Repeals,
        Self::Amends,
        Self::Replaces,
        Self::AppliesBefore,
        Self::Contains,
        Self::BelongsTo,
        Self::RelatedTo,
    ];
}

string_enum!(Strength {
    Conclusive => "conclusive",
    Strong => "strong",
    Moderate => "moderate",
    Weak => "weak",
    Unknown => "unknown",
});

string_enum!(SourceKind {
    File => "file",
    FilePage => "file_page",
    Paragraph => "paragraph",
    Table => "table",
    Attachment => "attachment",
    Law => "law",
    CaseRecord => "case_record",
    Artifact => "artifact",
    Uri => "uri",
    ModelAnalysis => "model_analysis",
    HumanInput => "human_input",
});

string_enum!(VerificationStatus {
    OriginalMaterial => "original_material",
    ModelExtracted => "model_extracted",
    ModelAnalyzed => "model_analyzed",
    DatabaseVerified => "database_verified",
    HumanConfirmed => "human_confirmed",
    Unverified => "unverified",
});

string_enum!(Direction {
    TopDown => "top_down",
    LeftRight => "left_right",
    Radial => "radial",
    Timeline => "timeline",
});

string_enum!(GroupBy {
    None => "none",
    NodeType => "node_type",
    Status => "status",
    Issue => "issue",
    Party => "party",
    Source => "source",
});

string_enum!(TimelineLane {
    Single => "single",
    ByParty => "by_party",
    ByProcedure => "by_procedure",
    ByStatement => "by_statement",
});

string_enum!(Theme {
    Light => "light",
    Dark => "dark",
    Auto => "auto",
});

string_enum!(PrintPageSize {
    A4Landscape => "a4_landscape",
    A4Portrait => "a4_portrait",
});

string_enum!(GeneratedBy {
    Workbuddy => "workbuddy",
    Codex => "codex",
    LocalModel => "local_model",
    Human => "human",
    Importer => "importer",
});

/// A JSON scalar accepted inside bounded metadata values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataScalar {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
}

/// Metadata is deliberately limited to scalars, scalar arrays, or one-level scalar maps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataValue {
    Scalar(MetadataScalar),
    Array(Vec<MetadataScalar>),
    Object(BTreeMap<String, MetadataScalar>),
}

pub type Metadata = BTreeMap<String, MetadataValue>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagramSpec {
    pub schema_version: String,
    pub diagram_type: DiagramType,
    pub template_id: TemplateId,
    pub title: String,
    pub summary: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub groups: Vec<Group>,
    pub sources: Vec<Source>,
    pub layout_hints: LayoutHints,
    pub display_options: DisplayOptions,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_label: Option<String>,
    pub details: String,
    pub status: NodeStatus,
    pub importance: Importance,
    pub source_refs: Vec<String>,
    pub tags: Vec<String>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relation: Relation,
    pub label: String,
    pub strength: Strength,
    pub source_refs: Vec<String>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub label: String,
    pub node_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_group_id: Option<String>,
    pub collapsed_by_default: bool,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub kind: SourceKind,
    pub title: String,
    pub locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paragraph: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub article: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutHints {
    pub direction: Direction,
    pub preferred_root_ids: Vec<String>,
    pub group_by: GroupBy,
    pub max_initial_nodes: u16,
    pub timeline_lane: TimelineLane,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayOptions {
    pub theme: Theme,
    pub show_legend: bool,
    pub show_sources: bool,
    pub hide_weak_edges: bool,
    pub collapse_low_importance: bool,
    pub print_page_size: PrintPageSize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub generated_by: GeneratedBy,
    pub generated_at: String,
    pub diagram_spec_version: String,
    pub template_version: String,
    pub source_file_ids: Vec<String>,
    pub human_confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_spec_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_summary: Option<String>,
    pub model_content_scope: String,
    pub deterministic_content_scope: String,
}
