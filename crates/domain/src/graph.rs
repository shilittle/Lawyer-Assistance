use crate::{
    case::{CaseWorkspace, ConfirmationStatus},
    law::LawRelationInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub category: String,
    pub source_kind: String,
    pub source_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub category: String,
    pub label: String,
    pub provenance: GraphProvenance,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphProvenance {
    pub source_kind: String,
    pub source_id: String,
    pub description: String,
    pub source_reference: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

pub fn case_graph(workspace: &CaseWorkspace) -> GraphData {
    let mut graph = GraphData::default();
    let confirmed_facts = workspace
        .facts
        .iter()
        .filter(|fact| fact.confirmation_status == ConfirmationStatus::Confirmed)
        .collect::<Vec<_>>();
    let confirmed_evidence = workspace
        .evidence
        .iter()
        .filter(|item| item.confirmation_status == ConfirmationStatus::Confirmed)
        .collect::<Vec<_>>();
    let confirmed_issues = workspace
        .legal_issues
        .iter()
        .filter(|issue| issue.confirmation_status == ConfirmationStatus::Confirmed)
        .collect::<Vec<_>>();
    let fact_ids = confirmed_facts
        .iter()
        .map(|fact| fact.fact_id.as_str())
        .collect::<HashSet<_>>();
    let evidence_ids = confirmed_evidence
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect::<HashSet<_>>();
    let issue_ids = confirmed_issues
        .iter()
        .map(|issue| issue.issue_id.as_str())
        .collect::<HashSet<_>>();

    for fact in confirmed_facts {
        graph.nodes.push(node(
            &format!("fact:{}", fact.fact_id),
            &fact.fact_id,
            &fact.title,
            "fact",
            "case_fact",
        ));
    }
    for evidence in confirmed_evidence {
        graph.nodes.push(node(
            &format!("evidence:{}", evidence.evidence_id),
            &evidence.evidence_id,
            &format!("{} {}", evidence.evidence_number, evidence.title),
            "evidence",
            "evidence_item",
        ));
    }
    for issue in confirmed_issues {
        graph.nodes.push(node(
            &format!("issue:{}", issue.issue_id),
            &issue.issue_id,
            &issue.title,
            "legal_issue",
            "legal_issue",
        ));
    }
    for basis in workspace.legal_basis.iter().filter(|basis| {
        basis.status == crate::qa::CitationStatus::Valid
            && basis
                .issue_id
                .as_deref()
                .is_none_or(|issue_id| issue_ids.contains(issue_id))
    }) {
        graph.nodes.push(node(
            &format!("citation:{}", basis.source_id),
            &basis.source_id,
            &basis.canonical_label,
            "legal_citation",
            "verified_citation",
        ));
        if let Some(issue_id) = &basis.issue_id {
            graph.edges.push(edge(
                &format!("basis:{}", basis.basis_id),
                &format!("issue:{issue_id}"),
                &format!("citation:{}", basis.source_id),
                "issue_citation",
                "适用法律",
                provenance("verified_citation", &basis.basis_id, "适用法律", None),
            ));
        }
    }
    for link in &workspace.evidence_links {
        if !fact_ids.contains(link.fact_id.as_str())
            || !evidence_ids.contains(link.evidence_id.as_str())
        {
            continue;
        }
        graph.edges.push(edge(
            &format!("evidence_link:{}", link.link_id),
            &format!("fact:{}", link.fact_id),
            &format!("evidence:{}", link.evidence_id),
            "fact_evidence",
            "证据支持",
            provenance("case_evidence_link", &link.link_id, "证据支持", None),
        ));
    }
    for link in &workspace.fact_issue_links {
        if !fact_ids.contains(link.fact_id.as_str()) || !issue_ids.contains(link.issue_id.as_str())
        {
            continue;
        }
        graph.edges.push(edge(
            &format!("fact_issue_link:{}", link.link_id),
            &format!("fact:{}", link.fact_id),
            &format!("issue:{}", link.issue_id),
            "fact_issue",
            "关联争点",
            provenance("case_fact_issue_link", &link.link_id, "关联争点", None),
        ));
    }
    dedupe_nodes(&mut graph.nodes);
    graph
}

pub fn law_graph(relations: &[LawRelationInfo]) -> GraphData {
    let mut graph = GraphData::default();
    for r in relations {
        graph.nodes.push(node(
            &format!("law_document:{}", r.from_document_id),
            &r.from_document_id,
            &r.from_title,
            "law_document",
            "legal_core",
        ));
        graph.nodes.push(node(
            &format!("law_document:{}", r.to_document_id),
            &r.to_document_id,
            &r.to_title,
            "law_document",
            "legal_core",
        ));
        graph.edges.push(edge(
            &format!("law_relation:{}", r.relation_id),
            &format!("law_document:{}", r.from_document_id),
            &format!("law_document:{}", r.to_document_id),
            &r.relation_type,
            &r.description,
            provenance(
                "law_relation",
                &r.relation_id,
                &r.description,
                Some(&r.source_reference),
            ),
        ));
    }
    dedupe_nodes(&mut graph.nodes);
    graph
}
fn node(id: &str, source_id: &str, label: &str, category: &str, source_kind: &str) -> GraphNode {
    GraphNode {
        id: id.into(),
        label: label.into(),
        category: category.into(),
        source_kind: source_kind.into(),
        source_id: source_id.into(),
    }
}
fn edge(
    id: &str,
    from: &str,
    to: &str,
    category: &str,
    label: &str,
    provenance: GraphProvenance,
) -> GraphEdge {
    GraphEdge {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        category: category.into(),
        label: label.into(),
        provenance,
    }
}
fn provenance(
    source_kind: &str,
    source_id: &str,
    description: &str,
    source_reference: Option<&str>,
) -> GraphProvenance {
    GraphProvenance {
        source_kind: source_kind.into(),
        source_id: source_id.into(),
        description: description.into(),
        source_reference: source_reference.map(str::to_owned),
    }
}
fn dedupe_nodes(nodes: &mut Vec<GraphNode>) {
    let mut ids = HashSet::new();
    nodes.retain(|n| ids.insert(n.id.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{case::*, qa::CitationStatus};

    fn case_workspace() -> CaseWorkspace {
        let fact = |id: &str, confirmation_status| CaseFact {
            fact_id: id.into(),
            project_id: "p1".into(),
            occurred_on: None,
            title: id.into(),
            description: String::new(),
            source: String::new(),
            confirmation_status,
        };
        let evidence = |id: &str, confirmation_status| EvidenceItem {
            evidence_id: id.into(),
            project_id: "p1".into(),
            evidence_number: id.into(),
            title: id.into(),
            source: String::new(),
            formed_on: None,
            summary: String::new(),
            storage_reference: String::new(),
            confirmation_status,
        };
        let issue = |id: &str, confirmation_status| LegalIssue {
            issue_id: id.into(),
            project_id: "p1".into(),
            title: id.into(),
            description: String::new(),
            claim: String::new(),
            status: LegalIssueStatus::Open,
            confirmation_status,
        };
        CaseWorkspace {
            project: CaseProject {
                project_id: "p1".into(),
                title: "case".into(),
                case_type: "civil".into(),
                status: CaseProjectStatus::Active,
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
            files: vec![],
            parties: vec![],
            facts: vec![
                fact("f1", ConfirmationStatus::Confirmed),
                fact("f-suggested", ConfirmationStatus::ModelSuggested),
            ],
            evidence: vec![
                evidence("e1", ConfirmationStatus::Confirmed),
                evidence("e-orphan", ConfirmationStatus::Confirmed),
            ],
            evidence_links: vec![
                EvidenceLink {
                    link_id: "link-1".into(),
                    project_id: "p1".into(),
                    fact_id: "f1".into(),
                    evidence_id: "e1".into(),
                },
                EvidenceLink {
                    link_id: "link-suggested".into(),
                    project_id: "p1".into(),
                    fact_id: "f-suggested".into(),
                    evidence_id: "e1".into(),
                },
            ],
            fact_issue_links: vec![
                FactIssueLink {
                    link_id: "fact-issue-1".into(),
                    project_id: "p1".into(),
                    fact_id: "f1".into(),
                    issue_id: "i1".into(),
                },
                FactIssueLink {
                    link_id: "fact-issue-suggested".into(),
                    project_id: "p1".into(),
                    fact_id: "f-suggested".into(),
                    issue_id: "i1".into(),
                },
            ],
            legal_issues: vec![
                issue("i1", ConfirmationStatus::Confirmed),
                issue("i-suggested", ConfirmationStatus::ModelSuggested),
            ],
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
                document_title: "law".into(),
                version_label: "current".into(),
                article_number: "1".into(),
                article_title: None,
                canonical_label: "law 1".into(),
                effective_from: "2020-01-01".into(),
                effective_to: None,
                version_status: "effective".into(),
                excerpt: String::new(),
                note: String::new(),
                created_at: String::new(),
            }],
            uncertainties: vec![],
            gaps: vec![],
        }
    }

    #[test]
    fn legal_edges_are_always_provenanced_and_typed() {
        let g = law_graph(&[LawRelationInfo {
            relation_id: "r1".into(),
            from_document_id: "a".into(),
            from_title: "A法".into(),
            to_document_id: "b".into(),
            to_title: "B法".into(),
            relation_type: "amends".into(),
            description: "修订".into(),
            source_reference: "official".into(),
        }]);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges[0].provenance.source_kind, "law_relation");
        assert!(!g.edges[0].provenance.source_id.is_empty());
        assert_eq!(
            g.edges[0].provenance.source_reference.as_deref(),
            Some("official")
        );
    }

    #[test]
    fn case_graph_contains_only_persisted_confirmed_relationships_and_keeps_orphans() {
        let graph = case_graph(&case_workspace());
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.id == "evidence:e-orphan"));
        assert!(!graph
            .nodes
            .iter()
            .any(|node| node.source_id == "f-suggested" || node.source_id == "i-suggested"));
        assert!(graph.edges.iter().any(|edge| {
            edge.id == "evidence_link:link-1"
                && edge.category == "fact_evidence"
                && edge.provenance.source_kind == "case_evidence_link"
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.category == "issue_citation"
                && edge.from == "issue:i1"
                && edge.to == "citation:law:1"
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.id == "fact_issue_link:fact-issue-1"
                && edge.from == "fact:f1"
                && edge.to == "issue:i1"
                && edge.category == "fact_issue"
                && edge.provenance.source_kind == "case_fact_issue_link"
                && edge.provenance.source_id == "fact-issue-1"
        }));
        assert!(!graph.edges.iter().any(|edge| {
            edge.id == "evidence_link:link-suggested"
                || edge.id == "fact_issue_link:fact-issue-suggested"
        }));
    }

    #[test]
    fn case_graph_serialization_preserves_provenance_and_orphan_nodes() {
        let value = serde_json::to_value(case_graph(&case_workspace())).unwrap();
        assert!(value["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["id"] == "evidence:e-orphan"));
        assert!(value["edges"].as_array().unwrap().iter().all(|edge| {
            edge["provenance"]["sourceKind"].as_str().is_some()
                && edge["provenance"]["sourceId"].as_str().is_some()
        }));
    }

    #[test]
    fn persisted_fact_issue_link_forms_the_fact_issue_citation_chain() {
        let graph = case_graph(&case_workspace());
        let fact_issue = graph
            .edges
            .iter()
            .find(|edge| edge.id == "fact_issue_link:fact-issue-1")
            .expect("persisted confirmed fact-issue relationship is present");
        let issue_citation = graph
            .edges
            .iter()
            .find(|edge| edge.id == "basis:b1")
            .expect("validated issue citation is present");

        assert_eq!(fact_issue.from, "fact:f1");
        assert_eq!(fact_issue.to, issue_citation.from);
        assert_eq!(issue_citation.to, "citation:law:1");
        assert_eq!(fact_issue.provenance.source_kind, "case_fact_issue_link");
    }

    #[test]
    fn node_ids_are_namespaced_when_source_tables_reuse_the_same_identifier() {
        let mut workspace = case_workspace();
        workspace.evidence[0].evidence_id = "f1".into();
        workspace.evidence_links[0].evidence_id = "f1".into();
        let graph = case_graph(&workspace);

        assert!(graph.nodes.iter().any(|node| {
            node.id == "fact:f1" && node.category == "fact" && node.source_id == "f1"
        }));
        assert!(graph.nodes.iter().any(|node| {
            node.id == "evidence:f1" && node.category == "evidence" && node.source_id == "f1"
        }));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.from == "fact:f1" && edge.to == "evidence:f1"));
    }
}
