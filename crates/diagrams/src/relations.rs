use crate::model::{NodeType, Relation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationDescriptor {
    pub relation: Relation,
    pub name_zh: &'static str,
    pub semantics: &'static str,
    pub source_types: &'static [NodeType],
    pub target_types: &'static [NodeType],
    pub symmetric: bool,
    pub fallback: bool,
}

const PARTY: &[NodeType] = &[NodeType::Party];
const PARTY_ACCOUNT_AMOUNT: &[NodeType] = &[NodeType::Party, NodeType::Account, NodeType::Amount];
const EVENT_PROCEDURE: &[NodeType] = &[NodeType::Event, NodeType::Procedure];
const EVIDENCE: &[NodeType] = &[NodeType::Evidence];
const FACT: &[NodeType] = &[NodeType::Fact];
const FACT_ISSUE: &[NodeType] = &[NodeType::Fact, NodeType::Issue];
const FACT_ISSUE_CLAIM: &[NodeType] = &[NodeType::Fact, NodeType::Issue, NodeType::Claim];
const FACT_CLAIM_DEFENSE: &[NodeType] = &[NodeType::Fact, NodeType::Claim, NodeType::Defense];
const FACT_EVENT_AMOUNT: &[NodeType] = &[NodeType::Fact, NodeType::Event, NodeType::Amount];
const ISSUE_FACT_RELATIONSHIP_PARTY: &[NodeType] = &[
    NodeType::Issue,
    NodeType::Fact,
    NodeType::LegalRelationship,
    NodeType::Party,
];
const ISSUE_EVENT_RELATIONSHIP: &[NodeType] = &[
    NodeType::Issue,
    NodeType::Event,
    NodeType::LegalRelationship,
];
const PARTY_AMOUNT: &[NodeType] = &[NodeType::Party, NodeType::Amount];
const PARTY_AMOUNT_RELATIONSHIP: &[NodeType] = &[
    NodeType::Party,
    NodeType::Amount,
    NodeType::LegalRelationship,
];
const RULE_CLAIM: &[NodeType] = &[NodeType::Rule, NodeType::Claim];
const ELEMENT_EVIDENCE_FACT: &[NodeType] = &[NodeType::Element, NodeType::Evidence, NodeType::Fact];
const FACT_ELEMENT_RULE_EVENT: &[NodeType] = &[
    NodeType::Fact,
    NodeType::Element,
    NodeType::Rule,
    NodeType::Event,
];
const CONSEQUENCE_CONCLUSION_EVENT: &[NodeType] = &[
    NodeType::LegalConsequence,
    NodeType::ApplicationConclusion,
    NodeType::Event,
];
const CLAIM_DEFENSE_CONCLUSION: &[NodeType] = &[
    NodeType::Claim,
    NodeType::Defense,
    NodeType::ApplicationConclusion,
];
const RULE_FACT_EVIDENCE: &[NodeType] = &[NodeType::Rule, NodeType::Fact, NodeType::Evidence];
const PARTY_CLAIM: &[NodeType] = &[NodeType::Party, NodeType::Claim];
const PARTY_DEFENSE: &[NodeType] = &[NodeType::Party, NodeType::Defense];
const CLAIM_DEFENSE_PARTY: &[NodeType] = &[NodeType::Claim, NodeType::Defense, NodeType::Party];
const ISSUE: &[NodeType] = &[NodeType::Issue];
const SUPPORT_SOURCE: &[NodeType] = &[NodeType::Evidence, NodeType::Rule, NodeType::Fact];
const SUPPORT_TARGET: &[NodeType] = &[
    NodeType::Fact,
    NodeType::Issue,
    NodeType::Claim,
    NodeType::ApplicationConclusion,
];
const CONTRADICT_SOURCE: &[NodeType] = &[NodeType::Evidence, NodeType::Fact];
const LEGAL_NORMS: &[NodeType] = &[
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
];
const LEGAL_SOURCE: &[NodeType] = &[
    NodeType::Rule,
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
    NodeType::LegalPrinciple,
];
const LEGAL_RULE_SOURCE: &[NodeType] = &[
    NodeType::Rule,
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
];
const INTERPRETATION_RULE: &[NodeType] = &[NodeType::JudicialInterpretation, NodeType::Rule];
const EXCEPTION_RULE: &[NodeType] = &[NodeType::ExceptionRule, NodeType::Rule];
const RULE: &[NodeType] = &[NodeType::Rule];
const RULE_NORM_SUBJECT: &[NodeType] = &[
    NodeType::Rule,
    NodeType::Law,
    NodeType::Regulation,
    NodeType::SupervisoryRegulation,
    NodeType::JudicialInterpretation,
    NodeType::DepartmentRule,
    NodeType::LocalRegulation,
    NodeType::LocalGovernmentRule,
    NodeType::NormativeDocument,
    NodeType::Party,
];

macro_rules! descriptor {
    ($relation:expr, $name:literal, $semantics:literal, $sources:expr, $targets:expr) => {
        RelationDescriptor {
            relation: $relation,
            name_zh: $name,
            semantics: $semantics,
            source_types: $sources,
            target_types: $targets,
            symmetric: false,
            fallback: false,
        }
    };
    (symmetric $relation:expr, $name:literal, $semantics:literal, $sources:expr, $targets:expr) => {
        RelationDescriptor {
            relation: $relation,
            name_zh: $name,
            semantics: $semantics,
            source_types: $sources,
            target_types: $targets,
            symmetric: true,
            fallback: false,
        }
    };
}

pub fn relation_descriptor(relation: Relation) -> RelationDescriptor {
    match relation {
        Relation::Supports => descriptor!(
            relation,
            "支持",
            "来源实体支持目标，但不自动确认目标事实",
            SUPPORT_SOURCE,
            SUPPORT_TARGET
        ),
        Relation::Contradicts => descriptor!(
            relation,
            "反驳",
            "来源实体与目标陈述冲突",
            CONTRADICT_SOURCE,
            FACT_CLAIM_DEFENSE
        ),
        Relation::Proves => descriptor!(
            relation,
            "证明对象",
            "证据拟证明目标",
            EVIDENCE,
            FACT_EVENT_AMOUNT
        ),
        Relation::Alleges => descriptor!(
            relation,
            "主张",
            "主体或请求提出未确认陈述",
            PARTY_CLAIM,
            FACT_ISSUE
        ),
        Relation::Admits => descriptor!(
            relation,
            "自认",
            "主体或抗辩明确承认事实",
            PARTY_DEFENSE,
            FACT
        ),
        Relation::Disputes => descriptor!(
            relation,
            "争议",
            "主体或抗辩明确提出争议",
            PARTY_DEFENSE,
            FACT_ISSUE_CLAIM
        ),
        Relation::Raises => descriptor!(
            relation,
            "提出争点",
            "主张、抗辩或主体形成争议焦点",
            CLAIM_DEFENSE_PARTY,
            ISSUE
        ),
        Relation::AppliesTo => descriptor!(
            relation,
            "适用于",
            "规范适用于目标问题或对象",
            LEGAL_SOURCE,
            ISSUE_FACT_RELATIONSHIP_PARTY
        ),
        Relation::Requires => descriptor!(
            relation,
            "要求满足",
            "规则或请求要求构成或证明条件",
            RULE_CLAIM,
            ELEMENT_EVIDENCE_FACT
        ),
        Relation::LeadsTo => descriptor!(
            relation,
            "导致",
            "事实、要件、规则或事件导致后果",
            FACT_ELEMENT_RULE_EVENT,
            CONSEQUENCE_CONCLUSION_EVENT
        ),
        Relation::BasedOn => descriptor!(
            relation,
            "基于",
            "分析、抗辩或结论基于目标依据",
            CLAIM_DEFENSE_CONCLUSION,
            RULE_FACT_EVIDENCE
        ),
        Relation::Involves => descriptor!(
            relation,
            "涉及",
            "问题、事件或关系涉及参与对象",
            ISSUE_EVENT_RELATIONSHIP,
            PARTY_AMOUNT
        ),
        Relation::OccurredBefore => descriptor!(
            relation,
            "先于",
            "来源时间项先于目标时间项",
            EVENT_PROCEDURE,
            EVENT_PROCEDURE
        ),
        Relation::OccurredAfter => descriptor!(
            relation,
            "后于",
            "来源时间项后于目标时间项",
            EVENT_PROCEDURE,
            EVENT_PROCEDURE
        ),
        Relation::SameEventAs => descriptor!(
            symmetric relation,
            "同一事件",
            "两个陈述指向同一事件",
            EVENT_PROCEDURE,
            EVENT_PROCEDURE
        ),
        Relation::ConflictsInTimeWith => descriptor!(
            symmetric relation,
            "时间冲突",
            "两个时间陈述互相矛盾",
            EVENT_PROCEDURE,
            EVENT_PROCEDURE
        ),
        Relation::PaidTo => descriptor!(relation, "支付给", "来源主体向目标主体支付", PARTY, PARTY),
        Relation::TransferredTo => descriptor!(
            relation,
            "转给",
            "来源主体、账户或金额转向目标",
            PARTY_ACCOUNT_AMOUNT,
            PARTY_ACCOUNT_AMOUNT
        ),
        Relation::Owes => descriptor!(
            relation,
            "负有债务",
            "来源主体对目标负债",
            PARTY,
            PARTY_AMOUNT
        ),
        Relation::Guarantees => descriptor!(
            relation,
            "担保",
            "来源主体或关系担保目标",
            &[NodeType::Party, NodeType::LegalRelationship],
            PARTY_AMOUNT_RELATIONSHIP
        ),
        Relation::Controls => descriptor!(relation, "控制", "来源主体控制目标主体", PARTY, PARTY),
        Relation::Owns => descriptor!(relation, "持有", "来源主体持有目标", PARTY, PARTY_AMOUNT),
        Relation::Represents => descriptor!(relation, "代理", "来源主体代理目标主体", PARTY, PARTY),
        Relation::Employs => descriptor!(relation, "雇佣", "来源主体雇佣目标主体", PARTY, PARTY),
        Relation::ContractsWith => descriptor!(
            symmetric relation,
            "订约",
            "两个主体互为合同相对方",
            PARTY,
            PARTY
        ),
        Relation::RelatedPartyOf => descriptor!(
            symmetric relation,
            "关联主体",
            "两个主体存在有据可查的关联",
            PARTY,
            PARTY
        ),
        Relation::SuperiorTo => descriptor!(
            relation,
            "效力高于",
            "上位规范指向下位规范",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::AuthorizedBy => descriptor!(
            relation,
            "依据授权",
            "下位规范指向授权依据",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::Implements => descriptor!(
            relation,
            "实施细化",
            "下位或具体规范指向上位或一般规范",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::References => descriptor!(
            relation,
            "引用",
            "来源规则或规范引用目标",
            LEGAL_RULE_SOURCE,
            LEGAL_RULE_SOURCE
        ),
        Relation::Supplements => descriptor!(
            relation,
            "补充",
            "来源规则或规范补充目标",
            LEGAL_RULE_SOURCE,
            LEGAL_RULE_SOURCE
        ),
        Relation::Interprets => descriptor!(
            relation,
            "解释",
            "解释文件或规则指向被解释规范",
            INTERPRETATION_RULE,
            LEGAL_RULE_SOURCE
        ),
        Relation::ExceptionTo => descriptor!(
            relation,
            "构成例外",
            "特别例外指向一般规则",
            EXCEPTION_RULE,
            RULE
        ),
        Relation::Limits => descriptor!(
            relation,
            "限制",
            "来源规则或规范限制目标范围",
            LEGAL_RULE_SOURCE,
            RULE_NORM_SUBJECT
        ),
        Relation::ConflictsWith => descriptor!(
            symmetric relation,
            "规范冲突",
            "两个规范或规则内容冲突",
            LEGAL_RULE_SOURCE,
            LEGAL_RULE_SOURCE
        ),
        Relation::Repeals => descriptor!(
            relation,
            "废止",
            "较新规范废止较旧规范",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::Amends => descriptor!(
            relation,
            "修改",
            "较新规范修改旧规范或版本",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::Replaces => descriptor!(
            relation,
            "替代",
            "较新规范替代旧规范",
            LEGAL_NORMS,
            LEGAL_NORMS
        ),
        Relation::AppliesBefore => descriptor!(
            relation,
            "优先适用",
            "冲突时来源规则或规范优先",
            LEGAL_RULE_SOURCE,
            LEGAL_RULE_SOURCE
        ),
        Relation::Contains => descriptor!(
            relation,
            "包含",
            "规范节点包含规则或其他结构节点",
            LEGAL_NORMS,
            NodeType::ALL
        ),
        Relation::BelongsTo => descriptor!(
            relation,
            "属于",
            "来源节点归属于规范或法律关系节点",
            NodeType::ALL,
            &[NodeType::Law, NodeType::LegalRelationship]
        ),
        Relation::RelatedTo => RelationDescriptor {
            relation,
            name_zh: "其他关联",
            semantics: "无更具体注册关系可用时的兜底关联",
            source_types: NodeType::ALL,
            target_types: NodeType::ALL,
            symmetric: false,
            fallback: true,
        },
    }
}

pub fn relation_is_compatible(
    relation: Relation,
    source_type: NodeType,
    target_type: NodeType,
) -> bool {
    let descriptor = relation_descriptor(relation);
    descriptor.source_types.contains(&source_type) && descriptor.target_types.contains(&target_type)
}

pub fn all_relation_descriptors() -> Vec<RelationDescriptor> {
    Relation::ALL
        .iter()
        .copied()
        .map(relation_descriptor)
        .collect()
}
