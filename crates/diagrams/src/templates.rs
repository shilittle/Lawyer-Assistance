use serde::Serialize;

use crate::model::{DiagramSpec, DiagramType, Direction, NodeType, Relation, TemplateId};
use crate::validation::{Diagnostic, DiagnosticSeverity, ValidationReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TemplateDescriptor {
    pub id: TemplateId,
    pub diagram_type: DiagramType,
    pub semantic_version: &'static str,
    pub name_zh: &'static str,
    pub scenario_zh: &'static str,
    pub supported_node_types: &'static [NodeType],
    pub required_node_types: &'static [NodeType],
    pub allowed_relations: &'static [Relation],
    pub default_direction: Direction,
    pub example_path: &'static str,
}

const LEGAL_TYPES: &[NodeType] = &[
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
    NodeType::GuidingCase,
    NodeType::LegalPrinciple,
    NodeType::Rule,
    NodeType::ExceptionRule,
];
const APPLICATION_TYPES: &[NodeType] = &[
    NodeType::Issue,
    NodeType::Element,
    NodeType::Rule,
    NodeType::Fact,
    NodeType::Evidence,
    NodeType::Law,
    NodeType::Regulation,
    NodeType::JudicialInterpretation,
    NodeType::LegalPrinciple,
    NodeType::LegalConsequence,
    NodeType::ExceptionRule,
    NodeType::ApplicationConclusion,
    NodeType::Claim,
    NodeType::Defense,
    NodeType::MissingInformation,
];
const PARTY_TYPES: &[NodeType] = &[
    NodeType::Party,
    NodeType::LegalRelationship,
    NodeType::Claim,
    NodeType::Defense,
    NodeType::Fact,
    NodeType::Event,
    NodeType::Amount,
    NodeType::Evidence,
    NodeType::Issue,
];
const ISSUE_TYPES: &[NodeType] = &[
    NodeType::Party,
    NodeType::Event,
    NodeType::Fact,
    NodeType::Issue,
    NodeType::Evidence,
    NodeType::Rule,
    NodeType::Claim,
    NodeType::Defense,
    NodeType::Amount,
    NodeType::Procedure,
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
    NodeType::GuidingCase,
    NodeType::LegalPrinciple,
    NodeType::Element,
    NodeType::LegalConsequence,
    NodeType::ExceptionRule,
    NodeType::ApplicationConclusion,
    NodeType::MissingInformation,
];
const MONEY_TYPES: &[NodeType] = &[
    NodeType::Party,
    NodeType::Account,
    NodeType::Amount,
    NodeType::Event,
    NodeType::Fact,
    NodeType::Evidence,
    NodeType::LegalRelationship,
    NodeType::MissingInformation,
];
const TIMELINE_TYPES: &[NodeType] = &[
    NodeType::Event,
    NodeType::Procedure,
    NodeType::Party,
    NodeType::Fact,
    NodeType::Evidence,
    NodeType::Amount,
    NodeType::MissingInformation,
];

const LEGAL_RELATIONS: &[Relation] = &[
    Relation::SuperiorTo,
    Relation::AuthorizedBy,
    Relation::Implements,
    Relation::References,
    Relation::Supplements,
    Relation::Interprets,
    Relation::ExceptionTo,
    Relation::Limits,
    Relation::ConflictsWith,
    Relation::Repeals,
    Relation::Amends,
    Relation::Replaces,
    Relation::AppliesBefore,
    Relation::Contains,
    Relation::BelongsTo,
    Relation::RelatedTo,
];
const APPLICATION_RELATIONS: &[Relation] = &[
    Relation::Supports,
    Relation::Contradicts,
    Relation::Proves,
    Relation::Disputes,
    Relation::Raises,
    Relation::AppliesTo,
    Relation::Requires,
    Relation::LeadsTo,
    Relation::BasedOn,
    Relation::References,
    Relation::ExceptionTo,
    Relation::Limits,
    Relation::RelatedTo,
];
const PARTY_RELATIONS: &[Relation] = &[
    Relation::Supports,
    Relation::Contradicts,
    Relation::Proves,
    Relation::Alleges,
    Relation::Admits,
    Relation::Disputes,
    Relation::Raises,
    Relation::BasedOn,
    Relation::Involves,
    Relation::PaidTo,
    Relation::TransferredTo,
    Relation::Owes,
    Relation::Guarantees,
    Relation::Controls,
    Relation::Owns,
    Relation::Represents,
    Relation::Employs,
    Relation::ContractsWith,
    Relation::RelatedPartyOf,
    Relation::BelongsTo,
    Relation::RelatedTo,
];
const ISSUE_RELATIONS: &[Relation] = &[
    Relation::Supports,
    Relation::Contradicts,
    Relation::Proves,
    Relation::Alleges,
    Relation::Admits,
    Relation::Disputes,
    Relation::Raises,
    Relation::AppliesTo,
    Relation::Requires,
    Relation::LeadsTo,
    Relation::BasedOn,
    Relation::Involves,
    Relation::References,
    Relation::Interprets,
    Relation::ExceptionTo,
    Relation::Limits,
    Relation::RelatedTo,
];
const MONEY_RELATIONS: &[Relation] = &[
    Relation::Supports,
    Relation::Contradicts,
    Relation::Proves,
    Relation::Involves,
    Relation::PaidTo,
    Relation::TransferredTo,
    Relation::Owes,
    Relation::Guarantees,
    Relation::Owns,
    Relation::RelatedTo,
];
const TIMELINE_RELATIONS: &[Relation] = &[
    Relation::Supports,
    Relation::Contradicts,
    Relation::Proves,
    Relation::Alleges,
    Relation::Admits,
    Relation::Disputes,
    Relation::Involves,
    Relation::OccurredBefore,
    Relation::OccurredAfter,
    Relation::SameEventAs,
    Relation::ConflictsInTimeWith,
    Relation::RelatedTo,
];

pub const TEMPLATES: &[TemplateDescriptor] = &[
    TemplateDescriptor {
        id: TemplateId::LegalHierarchyV1,
        diagram_type: DiagramType::LegalHierarchy,
        semantic_version: "1.0.0",
        name_zh: "法律效力层级图",
        scenario_zh: "展示法律规范的效力层级、授权和实施关系",
        supported_node_types: LEGAL_TYPES,
        required_node_types: &[],
        allowed_relations: LEGAL_RELATIONS,
        default_direction: Direction::TopDown,
        example_path: "examples/legal_hierarchy_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::LegalApplicationChainV1,
        diagram_type: DiagramType::LegalApplicationChain,
        semantic_version: "1.0.0",
        name_zh: "法律适用链图",
        scenario_zh: "展示问题、要件、规则和法律后果的适用链",
        supported_node_types: APPLICATION_TYPES,
        required_node_types: &[NodeType::Issue, NodeType::Rule],
        allowed_relations: APPLICATION_RELATIONS,
        default_direction: Direction::LeftRight,
        example_path: "examples/legal_application_chain_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::LegalConflictPriorityV1,
        diagram_type: DiagramType::LegalConflictPriority,
        semantic_version: "1.0.0",
        name_zh: "规范冲突优先图",
        scenario_zh: "展示冲突规范和适用优先顺序",
        supported_node_types: LEGAL_TYPES,
        required_node_types: &[],
        allowed_relations: LEGAL_RELATIONS,
        default_direction: Direction::LeftRight,
        example_path: "examples/legal_conflict_priority_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::CasePartyRelationshipV1,
        diagram_type: DiagramType::CasePartyRelationship,
        semantic_version: "1.0.0",
        name_zh: "案件主体关系图",
        scenario_zh: "展示案件主体、法律关系和主体间联系",
        supported_node_types: PARTY_TYPES,
        required_node_types: &[NodeType::Party],
        allowed_relations: PARTY_RELATIONS,
        default_direction: Direction::Radial,
        example_path: "examples/case_party_relationship_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::CaseIssueEvidenceLawV1,
        diagram_type: DiagramType::CaseIssueEvidenceLaw,
        semantic_version: "1.0.0",
        name_zh: "争点—证据—法律图",
        scenario_zh: "围绕案件争点组织事实、证据、主张和法律依据",
        supported_node_types: ISSUE_TYPES,
        required_node_types: &[NodeType::Issue],
        allowed_relations: ISSUE_RELATIONS,
        default_direction: Direction::TopDown,
        example_path: "examples/case_issue_evidence_law_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::CaseMoneyFlowV1,
        diagram_type: DiagramType::CaseMoneyFlow,
        semantic_version: "1.0.0",
        name_zh: "案件资金流图",
        scenario_zh: "展示主体、账户、金额和凭证构成的有向资金流",
        supported_node_types: MONEY_TYPES,
        required_node_types: &[],
        allowed_relations: MONEY_RELATIONS,
        default_direction: Direction::LeftRight,
        example_path: "examples/case_money_flow_v1.json",
    },
    TemplateDescriptor {
        id: TemplateId::CaseTimelineV1,
        diagram_type: DiagramType::CaseTimeline,
        semantic_version: "1.0.0",
        name_zh: "案件时间轴",
        scenario_zh: "按时间顺序和陈述轨道展示案件事件与程序",
        supported_node_types: TIMELINE_TYPES,
        required_node_types: &[],
        allowed_relations: TIMELINE_RELATIONS,
        default_direction: Direction::Timeline,
        example_path: "examples/case_timeline_v1.json",
    },
];

#[derive(Debug, Clone, Copy, Default)]
pub struct TemplateRegistry;

impl TemplateRegistry {
    pub const fn new() -> Self {
        Self
    }

    pub fn list(&self) -> &'static [TemplateDescriptor] {
        TEMPLATES
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static TemplateDescriptor> {
        TEMPLATES.iter()
    }

    pub fn get(&self, id: TemplateId) -> Option<&'static TemplateDescriptor> {
        TEMPLATES.iter().find(|template| template.id == id)
    }

    pub fn validate(&self, spec: &DiagramSpec) -> ValidationReport {
        let mut report = ValidationReport::default();
        let Some(template) = self.get(spec.template_id) else {
            report.push(Diagnostic::new(
                DiagnosticSeverity::Error,
                "template.unknown",
                "/template_id",
                "template_id is not registered",
            ));
            return report;
        };

        if template.diagram_type != spec.diagram_type {
            report.push(Diagnostic::new(
                DiagnosticSeverity::Error,
                "template.diagram_type_mismatch",
                "/diagram_type",
                format!(
                    "template {} requires diagram_type {}",
                    template.id, template.diagram_type
                ),
            ));
        }

        for required in template.required_node_types {
            if !spec.nodes.iter().any(|node| node.node_type == *required) {
                report.push(Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "template.required_node_type_missing",
                    "/nodes",
                    format!("template {} requires a {} node", template.id, required),
                ));
            }
        }

        for (index, node) in spec.nodes.iter().enumerate() {
            if !template.supported_node_types.contains(&node.node_type) {
                report.push(Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "template.node_type_not_supported",
                    format!("/nodes/{index}/type"),
                    format!(
                        "node type {} is not supported by template {}",
                        node.node_type, template.id
                    ),
                ));
            }
        }

        for (index, edge) in spec.edges.iter().enumerate() {
            if !template.allowed_relations.contains(&edge.relation) {
                report.push(Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "template.relation_not_allowed",
                    format!("/edges/{index}/relation"),
                    format!(
                        "relation {} is not allowed by template {}",
                        edge.relation, template.id
                    ),
                ));
            }
        }

        let legal_norm_count = spec
            .nodes
            .iter()
            .filter(|node| node.node_type.is_legal_norm() || node.node_type == NodeType::Rule)
            .count();
        match template.id {
            TemplateId::LegalHierarchyV1 if legal_norm_count < 2 => report.push(Diagnostic::new(
                DiagnosticSeverity::Error,
                "template.hierarchy_too_small",
                "/nodes",
                "legal hierarchy requires at least two legal norm or rule nodes",
            )),
            TemplateId::LegalConflictPriorityV1 => {
                if legal_norm_count < 2 {
                    report.push(Diagnostic::new(
                        DiagnosticSeverity::Error,
                        "template.conflict_too_small",
                        "/nodes",
                        "legal conflict diagram requires at least two legal norm or rule nodes",
                    ));
                }
                if !spec.edges.iter().any(|edge| {
                    matches!(
                        edge.relation,
                        Relation::ConflictsWith
                            | Relation::AppliesBefore
                            | Relation::SuperiorTo
                            | Relation::Repeals
                            | Relation::Replaces
                    )
                }) {
                    report.push(Diagnostic::new(
                        DiagnosticSeverity::Error,
                        "template.conflict_relation_missing",
                        "/edges",
                        "legal conflict diagram requires a conflict or priority relation",
                    ));
                }
            }
            TemplateId::CaseMoneyFlowV1
                if !spec.edges.iter().any(|edge| {
                    matches!(edge.relation, Relation::PaidTo | Relation::TransferredTo)
                }) =>
            {
                report.push(Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "template.money_flow_missing",
                    "/edges",
                    "money-flow template requires at least one directed payment or transfer",
                ));
            }
            TemplateId::CaseTimelineV1
                if !spec.nodes.iter().any(|node| {
                    matches!(node.node_type, NodeType::Event | NodeType::Procedure)
                }) =>
            {
                report.push(Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "template.timeline_event_missing",
                    "/nodes",
                    "timeline template requires at least one event or procedure node",
                ));
            }
            _ => {}
        }

        report
    }
}
