use assistant::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn context() -> ValidationContext {
    let mut context = ValidationContext::default();
    context.allow_source_ref("material:1");
    context.allow_validated_legal_source("law:1");
    context.allow_attachment("attachment:1");
    context.allow_artifact("artifact:1");
    context.allow_case_fact("fact:existing");
    context.allow_case_issue("issue:existing");
    context
}

fn user_provenance() -> Vec<ProvenanceRef> {
    vec![ProvenanceRef {
        kind: ProvenanceKind::UserMaterial,
        source_ref: Some("material:1".to_owned()),
    }]
}

fn valid_document() -> DocumentSpec {
    DocumentSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        document_type: DocumentType::Contract,
        title: "服务合同".to_owned(),
        parties: vec![DocumentParty {
            id: "party:1".to_owned(),
            name: "甲方".to_owned(),
            role: "委托方".to_owned(),
            details: None,
            provenance: user_provenance(),
        }],
        sections: vec![DocumentSection {
            id: "section:1".to_owned(),
            heading: "服务范围".to_owned(),
            body: "双方确认服务范围以用户材料为准。".to_owned(),
            factual: true,
            provenance: user_provenance(),
            clauses: vec![DocumentClause {
                id: "clause:1".to_owned(),
                heading: Some("表述".to_owned()),
                body: "本条为模型辅助措辞。".to_owned(),
                factual: false,
                provenance: vec![ProvenanceRef {
                    kind: ProvenanceKind::ModelWording,
                    source_ref: None,
                }],
            }],
        }],
        assumptions: vec![DocumentAssumption {
            text: "签署日期待确认。".to_owned(),
            provenance: vec![],
        }],
        missing_information: vec![MissingInformation {
            description: "补充付款日期。".to_owned(),
        }],
        source_materials: vec![SourceMaterial {
            id: "material:1".to_owned(),
            kind: SourceMaterialKind::UserMaterial,
            label: "用户上传合同要点".to_owned(),
            locator: Some("paragraph:1".to_owned()),
        }],
        legal_citations: vec![LegalCitation {
            id: "citation:1".to_owned(),
            source_ref: "law:1".to_owned(),
            marker: "[SRC:law:1]".to_owned(),
            citation: "《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）".to_owned(),
            proposition: "支持合同约定。".to_owned(),
        }],
        risk_warnings: vec!["请在签署前核对主体信息。".to_owned()],
    }
}

fn valid_map() -> MapSpec {
    MapSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        title: "争点导图".to_owned(),
        layout_hint: LayoutHint::Mindmap,
        nodes: vec![
            MapNode {
                id: "node:root".to_owned(),
                label: "争议".to_owned(),
                summary: "<script>只是被转义展示的文本</script>".to_owned(),
                parent_id: None,
                source_refs: vec!["material:1".to_owned()],
            },
            MapNode {
                id: "node:child".to_owned(),
                label: "法源".to_owned(),
                summary: "本地法源".to_owned(),
                parent_id: Some("node:root".to_owned()),
                source_refs: vec!["law:1".to_owned()],
            },
        ],
        edges: vec![MapEdge {
            id: "edge:1".to_owned(),
            source: "node:root".to_owned(),
            target: "node:child".to_owned(),
            label: "适用".to_owned(),
            relation: "supports".to_owned(),
            source_refs: vec!["law:1".to_owned()],
        }],
    }
}

fn valid_case_change() -> CaseChangeSpec {
    CaseChangeSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        facts: vec![FactAddition {
            id: "fact:new".to_owned(),
            statement: "用户材料记载了交付事实。".to_owned(),
            occurred_on: Some("2026-07-16".to_owned()),
            source_refs: vec!["material:1".to_owned()],
        }],
        evidence: vec![EvidenceAddition {
            id: "evidence:new".to_owned(),
            title: "交付记录".to_owned(),
            summary: "记录显示已交付。".to_owned(),
            proves_fact_ids: vec!["fact:new".to_owned(), "fact:existing".to_owned()],
            source_refs: vec!["material:1".to_owned()],
        }],
        issues: vec![IssueAddition {
            id: "issue:new".to_owned(),
            title: "是否完成交付".to_owned(),
            analysis: "需结合记录判断。".to_owned(),
            related_fact_ids: vec!["fact:new".to_owned()],
            source_refs: vec![],
        }],
        legal_basis: vec![LegalBasisAddition {
            id: "basis:new".to_owned(),
            issue_ids: vec!["issue:new".to_owned(), "issue:existing".to_owned()],
            source_ref: "law:1".to_owned(),
            marker: "[SRC:law:1]".to_owned(),
            citation: "《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）".to_owned(),
            proposition: "用于判断履行。".to_owned(),
        }],
        attachment_transfers: vec![AttachmentTransfer {
            attachment_id: "attachment:1".to_owned(),
            title: "交付记录".to_owned(),
        }],
        artifact_transfers: vec![ArtifactTransfer {
            artifact_id: "artifact:1".to_owned(),
            title: "研究结果".to_owned(),
        }],
    }
}

#[test]
fn registry_is_exact_unique_bounded_and_confirmation_is_enforced() {
    let expected = [
        "legal.search",
        "legal.read",
        "file.import",
        "file.extract",
        "case.read",
        "case.propose_changes",
        "case.apply_changes",
        "document.draft",
        "document.render",
        "map.build",
        "assistant.interactive_chat",
        "assistant.case_work",
    ];
    let registry = capability_registry();
    assert_eq!(registry.len(), CAPABILITY_COUNT);
    assert_eq!(
        registry
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        registry
            .iter()
            .map(|item| item.name.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        CAPABILITY_COUNT
    );
    for descriptor in registry {
        assert!(descriptor.version.len() <= MAX_CAPABILITY_VERSION_BYTES);
        assert!(descriptor.max_calls_per_run <= MAX_TOOL_CALLS_PER_RUN);
        assert!(descriptor.max_input_bytes <= MAX_INPUT_BODY_BYTES_PER_RUN);
        assert!(descriptor.max_output_bytes <= MAX_MODEL_RESPONSE_BYTES);
        assert!(descriptor.allowed_error_types.len() <= MAX_ALLOWED_ERRORS_PER_CAPABILITY);
        assert!(descriptor.audit_fields.len() <= MAX_AUDIT_FIELDS_PER_CAPABILITY);
        assert!(descriptor.cancellable);
    }
    assert_eq!(
        find_capability("case.apply_changes")
            .unwrap()
            .validate_call(1, 1, 1, false)
            .unwrap_err()
            .error_type,
        ContractErrorType::ConfirmationRequired
    );
    assert!(find_capability("case.apply_changes")
        .unwrap()
        .validate_call(1, 1, 1, true)
        .is_ok());
    let interactive = find_capability("assistant.interactive_chat").unwrap();
    assert_eq!(
        interactive.access,
        CapabilityAccess {
            read: true,
            write: false,
        }
    );
    assert!(!interactive.requires_user_confirmation);
    assert_eq!(interactive.max_calls_per_run, 1);
    assert_eq!(interactive.max_input_bytes, MAX_INPUT_BODY_BYTES_PER_RUN);
    assert_eq!(interactive.max_output_bytes, MAX_MODEL_RESPONSE_BYTES);
    assert!(interactive
        .allowed_error_types
        .contains(&CapabilityErrorType::ProviderFailure));
    assert!(interactive
        .allowed_error_types
        .contains(&CapabilityErrorType::Conflict));
    assert!(interactive
        .audit_fields
        .contains(&AuditField::ProviderSnapshot));
    assert!(interactive
        .audit_fields
        .contains(&AuditField::Classification));
    assert!(interactive.audit_fields.contains(&AuditField::InputHashes));
    assert!(interactive.audit_fields.contains(&AuditField::OutputHashes));
    assert!(interactive.audit_fields.contains(&AuditField::OutputIds));
    assert!(!interactive.audit_fields.contains(&AuditField::SourceRefs));
    let case_work = find_capability("assistant.case_work").unwrap();
    assert_eq!(
        case_work.access,
        CapabilityAccess {
            read: true,
            write: true,
        }
    );
    assert!(!case_work.requires_user_confirmation);
    assert_eq!(case_work.max_calls_per_run, 1);
    assert!(case_work
        .allowed_error_types
        .contains(&CapabilityErrorType::ProviderFailure));
    assert!(case_work.audit_fields.contains(&AuditField::Classification));
    assert!(case_work.audit_fields.contains(&AuditField::InputHashes));
    assert!(case_work.audit_fields.contains(&AuditField::OutputHashes));
    assert!(case_work.audit_fields.contains(&AuditField::SourceRefs));
    assert!(case_work.audit_fields.contains(&AuditField::Confirmation));
    assert_eq!(
        find_capability("shell.exec").unwrap_err().error_type,
        ContractErrorType::UnknownCapability
    );
}

#[test]
fn interactive_chat_capability_serde_wire_contract_is_exact_and_closed() {
    let wire =
        serde_json::to_string(&CapabilityName::AssistantInteractiveChat).expect("serialize name");
    assert_eq!(wire, "\"assistant.interactive_chat\"");
    assert_eq!(
        serde_json::from_str::<CapabilityName>(&wire).expect("deserialize name"),
        CapabilityName::AssistantInteractiveChat
    );
    assert!(serde_json::from_str::<CapabilityName>("\"assistant.interactive\"").is_err());
}

#[test]
fn case_work_capability_serde_wire_contract_is_exact_and_closed() {
    let wire = serde_json::to_string(&CapabilityName::AssistantCaseWork)
        .expect("serialize case-work capability name");
    assert_eq!(wire, "\"assistant.case_work\"");
    assert_eq!(
        serde_json::from_str::<CapabilityName>(&wire).expect("deserialize case-work name"),
        CapabilityName::AssistantCaseWork
    );
    assert!(serde_json::from_str::<CapabilityName>("\"assistant.case\"").is_err());
}

#[test]
fn run_budget_accepts_exact_caps_and_rejects_each_overrun() {
    let budget = RunBudget::default();
    budget
        .check_usage(&RunBudgetUsage {
            tool_calls: MAX_TOOL_CALLS_PER_RUN,
            provider_round_trips: MAX_PROVIDER_ROUND_TRIPS_PER_RUN,
            input_body_bytes: MAX_INPUT_BODY_BYTES_PER_RUN,
            visible_attachments: MAX_MODEL_VISIBLE_ATTACHMENTS_PER_RUN,
            model_response_bytes: MAX_MODEL_RESPONSE_BYTES,
        })
        .unwrap();
    for usage in [
        RunBudgetUsage {
            tool_calls: MAX_TOOL_CALLS_PER_RUN + 1,
            ..Default::default()
        },
        RunBudgetUsage {
            provider_round_trips: MAX_PROVIDER_ROUND_TRIPS_PER_RUN + 1,
            ..Default::default()
        },
        RunBudgetUsage {
            input_body_bytes: MAX_INPUT_BODY_BYTES_PER_RUN + 1,
            ..Default::default()
        },
        RunBudgetUsage {
            visible_attachments: MAX_MODEL_VISIBLE_ATTACHMENTS_PER_RUN + 1,
            ..Default::default()
        },
        RunBudgetUsage {
            model_response_bytes: MAX_MODEL_RESPONSE_BYTES + 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            budget.check_usage(&usage).unwrap_err().error_type,
            ContractErrorType::BudgetExceeded
        );
    }
}

#[test]
fn envelope_accepts_raw_or_one_json_fence_only() {
    let envelope = StructuredEnvelope {
        schema_version: CONTRACT_SCHEMA_VERSION,
        output: StructuredOutput::DocumentSpec(valid_document()),
    };
    let raw = serde_json::to_string(&envelope).unwrap();
    parse_and_validate_envelope(&raw, &context()).unwrap();
    parse_and_validate_envelope(&format!("```json\n{raw}\n```"), &context()).unwrap();

    for rejected in [
        format!("answer: {raw}"),
        format!("```JSON\n{raw}\n```"),
        format!("```json\n{raw}\n```\n```json\n{raw}\n```"),
        format!("{raw} {raw}"),
    ] {
        assert!(parse_structured_envelope(&rejected).is_err());
    }
    assert_eq!(
        parse_structured_envelope(&"x".repeat(MAX_MODEL_RESPONSE_BYTES + 1))
            .unwrap_err()
            .error_type,
        ContractErrorType::ResponseTooLarge
    );
}

#[test]
fn envelope_and_nested_specs_deny_unknown_fields_and_versions() {
    let envelope = StructuredEnvelope {
        schema_version: CONTRACT_SCHEMA_VERSION,
        output: StructuredOutput::DocumentSpec(valid_document()),
    };
    let mut value = serde_json::to_value(envelope).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("command".to_owned(), json!("case.apply"));
    assert_eq!(
        parse_structured_envelope(&value.to_string())
            .unwrap_err()
            .error_type,
        ContractErrorType::InvalidJson
    );

    let mut nested = serde_json::to_value(StructuredEnvelope {
        schema_version: CONTRACT_SCHEMA_VERSION,
        output: StructuredOutput::MapSpec(valid_map()),
    })
    .unwrap();
    nested["output"]["payload"]
        .as_object_mut()
        .unwrap()
        .insert("cytoscapeConfig".to_owned(), json!({}));
    assert!(parse_structured_envelope(&nested.to_string()).is_err());

    let mut wrong_version = valid_document();
    wrong_version.schema_version += 1;
    assert_eq!(
        wrong_version.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnsupportedSchemaVersion
    );
}

#[test]
fn document_validates_text_count_provenance_references_and_citations() {
    let mut document = valid_document();
    document.validate(&context()).unwrap();
    document.title = "x".repeat(MAX_DOCUMENT_TITLE_BYTES);
    document.validate(&context()).unwrap();
    document.title.push('x');
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::TextTooLong
    );

    let mut document = valid_document();
    document.risk_warnings = vec!["risk".to_owned(); MAX_DOCUMENT_RISK_WARNINGS];
    document.validate(&context()).unwrap();
    document.risk_warnings.push("overflow".to_owned());
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::TooManyItems
    );

    let mut document = valid_document();
    document.sections[0].provenance = vec![ProvenanceRef {
        kind: ProvenanceKind::ModelWording,
        source_ref: None,
    }];
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::MissingProvenance
    );

    let mut document = valid_document();
    document.legal_citations[0].source_ref = "law:unverified".to_owned();
    document.legal_citations[0].marker = "[SRC:law:unverified]".to_owned();
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnvalidatedLegalCitation
    );

    let mut document = valid_document();
    document.legal_citations[0].citation = "中华人民共和国民法典第四百六十五条".to_owned();
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnvalidatedLegalCitation
    );

    let mut document = valid_document();
    document.source_materials[0].id = "material:unowned".to_owned();
    assert_eq!(
        document.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnknownReference
    );
}

#[test]
fn document_rejects_internal_data_in_every_user_visible_text_family() {
    let mutations: Vec<fn(&mut DocumentSpec)> = vec![
        |document| document.title = "[SRC:law:1] 内部标题".to_owned(),
        |document| document.parties[0].name = "article_id=art-1".to_owned(),
        |document| document.parties[0].role = "schema_version=1".to_owned(),
        |document| document.parties[0].details = Some(r"C:\cases\secret.txt".to_owned()),
        |document| document.sections[0].heading = "无标题".to_owned(),
        |document| document.sections[0].body = r#"{"snippet":"不得进入正文"}"#.to_owned(),
        |document| document.sections[0].body = "内部日志 service-deadbeef-1".to_owned(),
        |document| {
            document.sections[0].clauses[0].heading =
                Some("019f6e3e-6822-70c1-86a7-6f88022a815e".to_owned())
        },
        |document| document.sections[0].clauses[0].body = "deadbeef0123456789abcdef".to_owned(),
        |document| document.sections[0].body = "a".repeat(64),
        |document| document.assumptions[0].text = "as_of=2026-01-01".to_owned(),
        |document| document.missing_information[0].description = "snippet 待补充".to_owned(),
        |document| document.risk_warnings[0] = "结构化文书预览".to_owned(),
        |document| {
            document.source_materials[0].label = "file:///Users/test/material.pdf".to_owned()
        },
        |document| {
            document.legal_citations[0].citation =
                "《schema_version》第四百六十五条第一款（2021年起施行）".to_owned()
        },
        |document| document.legal_citations[0].proposition = "模型措辞".to_owned(),
        |document| document.legal_citations[0].proposition = "模型输出不得进入文书".to_owned(),
        |document| document.sections[0].body = "详见 crates/assistant/src/document.rs".to_owned(),
        |document| document.sections[0].body = "backend renderer debug log".to_owned(),
        |document| document.sections[0].body = "localhost:39127".to_owned(),
    ];

    for mutate in mutations {
        let mut document = valid_document();
        mutate(&mut document);
        let error = document
            .validate(&context())
            .expect_err("non-deliverable model text must fail before rendering");
        assert_eq!(error.error_type, ContractErrorType::InvalidEnvelope);
        assert_eq!(
            error.message,
            "public document text contains non-deliverable content"
        );
    }
}

#[test]
fn map_validates_uniqueness_endpoints_parent_cycles_counts_and_sources() {
    valid_map().validate(&context()).unwrap();
    let mut map = valid_map();
    map.nodes[1].id = map.nodes[0].id.clone();
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::DuplicateIdentifier
    );

    let mut map = valid_map();
    map.edges[0].target = "node:missing".to_owned();
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::InvalidEndpoint
    );

    let mut map = valid_map();
    map.nodes[0].parent_id = Some("node:child".to_owned());
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::ParentCycle
    );

    let mut map = valid_map();
    map.nodes = (0..MAX_MAP_NODES)
        .map(|index| MapNode {
            id: format!("node:{index}"),
            label: "n".to_owned(),
            summary: "s".to_owned(),
            parent_id: None,
            source_refs: vec![],
        })
        .collect();
    map.edges.clear();
    map.validate(&context()).unwrap();
    map.nodes.push(MapNode {
        id: "node:overflow".to_owned(),
        label: "n".to_owned(),
        summary: "s".to_owned(),
        parent_id: None,
        source_refs: vec![],
    });
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::TooManyItems
    );

    let mut map = valid_map();
    map.edges = (0..MAX_MAP_EDGES)
        .map(|index| MapEdge {
            id: format!("edge:{index}"),
            source: "node:root".to_owned(),
            target: "node:child".to_owned(),
            label: "relation".to_owned(),
            relation: "supports".to_owned(),
            source_refs: vec![],
        })
        .collect();
    map.validate(&context()).unwrap();
    map.edges.push(MapEdge {
        id: "edge:overflow".to_owned(),
        source: "node:root".to_owned(),
        target: "node:child".to_owned(),
        label: "relation".to_owned(),
        relation: "supports".to_owned(),
        source_refs: vec![],
    });
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::TooManyItems
    );

    let mut map = valid_map();
    map.nodes[0].source_refs = vec!["source:unowned".to_owned()];
    assert_eq!(
        map.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnknownReference
    );
}

#[test]
fn case_changes_are_add_only_owned_bounded_and_endpoint_checked() {
    valid_case_change().validate(&context()).unwrap();
    let mut spec = valid_case_change();
    spec.attachment_transfers.push(AttachmentTransfer {
        attachment_id: "attachment:2".to_owned(),
        title: "二".to_owned(),
    });
    spec.attachment_transfers.push(AttachmentTransfer {
        attachment_id: "attachment:3".to_owned(),
        title: "三".to_owned(),
    });
    assert_eq!(
        spec.validate(&context()).unwrap_err().error_type,
        ContractErrorType::TooManyItems
    );

    let mut spec = valid_case_change();
    spec.evidence[0].proves_fact_ids = vec!["fact:unknown".to_owned()];
    assert_eq!(
        spec.validate(&context()).unwrap_err().error_type,
        ContractErrorType::InvalidEndpoint
    );

    let mut spec = valid_case_change();
    spec.artifact_transfers[0].artifact_id = "artifact:unowned".to_owned();
    assert_eq!(
        spec.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnknownReference
    );

    let mut spec = valid_case_change();
    spec.legal_basis[0].source_ref = "law:unverified".to_owned();
    spec.legal_basis[0].marker = "[SRC:law:unverified]".to_owned();
    assert_eq!(
        spec.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnvalidatedLegalCitation
    );

    let mut spec = valid_case_change();
    spec.legal_basis[0].citation = "某案（案号未载明）".to_owned();
    assert_eq!(
        spec.validate(&context()).unwrap_err().error_type,
        ContractErrorType::UnvalidatedLegalCitation
    );

    let envelope = StructuredEnvelope {
        schema_version: CONTRACT_SCHEMA_VERSION,
        output: StructuredOutput::CaseChangeSpec(valid_case_change()),
    };
    let mut value: Value = serde_json::to_value(envelope).unwrap();
    for forbidden in ["sql", "path", "command"] {
        value["output"]["payload"]
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), json!("forbidden"));
        assert!(parse_structured_envelope(&value.to_string()).is_err());
        value["output"]["payload"]
            .as_object_mut()
            .unwrap()
            .remove(forbidden);
    }
}
