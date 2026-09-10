use privacy_text::{
    analyze, analyze_with_ai, export, export_local_document, extract, validate_analysis,
    validate_result, verify_analysis_source, AiFinding, CloudFinding, DictionaryEntry, TextError,
};

#[test]
fn deterministic_and_dictionary_matches_are_replaced_with_stable_aliases() {
    let text = "原告：张三，身份证号：11010519491231002X，联系电话：13800138000。张三已签收。";
    let dictionary = [DictionaryEntry {
        text: "张三".to_owned(),
        kind: "person_name".to_owned(),
        alias: None,
    }];
    let analysis = analyze(text, "group-salt-1", &dictionary, &[], &[]).expect("analysis");
    assert!(!analysis.needs_review);
    assert!(!analysis.text.contains("张三"));
    assert!(!analysis.text.contains("11010519491231002X"));
    assert!(!analysis.text.contains("13800138000"));
    assert_eq!(analysis.text.matches("[PERSON_").count(), 2);
    validate_result(&analysis.text, &analysis.findings).expect("validated result");

    let docx = export(&analysis.text, "docx").expect("docx export");
    assert_eq!(
        extract("redacted.docx", &docx, None).expect("reextract docx"),
        analysis.text
    );
}

#[test]
fn deterministic_phone_result_is_namespace_invariant_over_many_salts() {
    let text = "请在联系时使用号码 13800138000。";
    for sequence in 0..128_u16 {
        let namespace = format!("namespace-invariance-{sequence}");
        let analysis = analyze(text, &namespace, &[], &[], &[]).expect("phone analysis");
        assert!(
            !analysis.needs_review,
            "namespace sequence {sequence} unexpectedly needs review"
        );
        assert_eq!(
            analysis.findings.len(),
            1,
            "namespace sequence {sequence} finding count"
        );
        let finding = &analysis.findings[0];
        assert!(
            finding.resolved && finding.source == "deterministic",
            "namespace sequence {sequence} deterministic source"
        );
        assert!(
            finding
                .alias
                .as_deref()
                .is_some_and(|alias| alias.chars().all(|character| !character.is_ascii_digit())),
            "namespace sequence {sequence} alias must not mimic a numeric residual"
        );
        assert_eq!(analysis.replacements.len(), 1);
        verify_analysis_source(text, &analysis).expect("namespace source evidence");
        validate_analysis(&analysis).expect("namespace output evidence");
    }
}

#[test]
fn generic_address_label_without_a_location_is_not_a_local_ner_address() {
    let analysis = analyze(
        "送达地址已另案保管，详见回证。",
        "address-label-negative",
        &[],
        &[],
        &[],
    )
    .expect("address label analysis");
    assert!(!analysis.needs_review);
    assert!(analysis.findings.is_empty());
    validate_analysis(&analysis).expect("clean address-label result validates");
}

#[test]
fn ner_guess_requires_exact_cloud_corroboration_or_explicit_dismissal() {
    let text = "申请人：王伟，请求依法裁判。";
    let pending = analyze(text, "group-salt-2", &[], &[], &[]).expect("pending analysis");
    assert!(pending.needs_review);
    let ner = pending
        .findings
        .iter()
        .find(|finding| finding.source == "local_ner")
        .expect("synthetic NER finding");
    assert!(!ner.resolved);

    let cloud = [CloudFinding {
        text: "王伟".to_owned(),
        kind: "person_name".to_owned(),
    }];
    let corroborated = analyze(text, "group-salt-2", &[], &cloud, &[]).expect("cloud analysis");
    assert!(!corroborated.needs_review);
    assert!(!corroborated.text.contains("王伟"));
    validate_result(&corroborated.text, &corroborated.findings).expect("cloud validated");

    let dismissed = analyze(
        text,
        "group-salt-2",
        &[],
        &[],
        std::slice::from_ref(&ner.id),
    )
    .expect("dismiss");
    assert!(!dismissed.needs_review);
    assert!(dismissed.text.contains("王伟"));
    assert!(dismissed.findings.iter().any(|finding| finding.dismissed));
    validate_result(&dismissed.text, &dismissed.findings).expect("dismissed semantic guess");
}

#[test]
fn explicit_review_can_dismiss_only_a_model_custom_candidate() {
    let role_text = "原告。";
    let role_start = role_text.find("原告").expect("procedural role");
    let role_finding = AiFinding {
        text: "原告".to_owned(),
        kind: "custom".to_owned(),
        start: role_start,
        end: role_start + "原告".len(),
        confidence_ppm: Some(900_000),
    };
    let pending = analyze_with_ai(
        role_text,
        "ai-custom-dismissal",
        &[],
        std::slice::from_ref(&role_finding),
        &[],
    )
    .expect("model custom analysis");
    let pending_role = pending
        .findings
        .iter()
        .find(|finding| finding.text == "原告")
        .expect("model custom finding");
    assert_eq!(pending_role.source, "ai");
    assert!(!pending_role.resolved);
    assert!(pending.needs_review);

    let dismissed = analyze_with_ai(
        role_text,
        "ai-custom-dismissal",
        &[],
        std::slice::from_ref(&role_finding),
        std::slice::from_ref(&pending_role.id),
    )
    .expect("explicit model custom dismissal");
    assert!(!dismissed.needs_review);
    assert!(dismissed.text.contains("原告"));
    assert!(dismissed
        .findings
        .iter()
        .any(|finding| finding.text == "原告" && finding.dismissed && finding.resolved));
    assert!(dismissed.ai_findings.as_deref() == Some(&[role_finding][..]));
    validate_analysis(&dismissed).expect("dismissed model custom result validates");

    let person_text = "当事人林砚应到庭。";
    let person_start = person_text.find("林砚").expect("person");
    let person_finding = AiFinding {
        text: "林砚".to_owned(),
        kind: "person_name".to_owned(),
        start: person_start,
        end: person_start + "林砚".len(),
        confidence_ppm: Some(899_999),
    };
    let pending_person = analyze_with_ai(
        person_text,
        "ai-custom-dismissal-person",
        &[],
        std::slice::from_ref(&person_finding),
        &[],
    )
    .expect("low-confidence model person analysis");
    let person_id = pending_person
        .findings
        .iter()
        .find(|finding| finding.text == "林砚")
        .expect("model person finding")
        .id
        .clone();
    let still_pending = analyze_with_ai(
        person_text,
        "ai-custom-dismissal-person",
        &[],
        std::slice::from_ref(&person_finding),
        &[person_id],
    )
    .expect("model person is reanalyzed");
    assert!(still_pending.needs_review);
    assert!(still_pending
        .findings
        .iter()
        .any(|finding| finding.text == "林砚" && !finding.dismissed && !finding.resolved));
}

#[test]
fn cloud_must_reference_exact_original_text_and_cannot_dismiss_deterministic_fields() {
    let absent = [CloudFinding {
        text: "不存在的人".to_owned(),
        kind: "person_name".to_owned(),
    }];
    assert!(matches!(
        analyze("申请人：王伟。", "group-salt-3", &[], &absent, &[]),
        Err(TextError::CloudFindingAbsent)
    ));

    let text = "身份证号：11010519491231002X。";
    let original = analyze(text, "group-salt-3", &[], &[], &[]).expect("identity analysis");
    let identity = original
        .findings
        .iter()
        .find(|finding| finding.kind == "identity_number")
        .expect("deterministic identity");
    let again = analyze(
        text,
        "group-salt-3",
        &[],
        &[],
        std::slice::from_ref(&identity.id),
    )
    .expect("again");
    let identity_again = again
        .findings
        .iter()
        .find(|finding| finding.kind == "identity_number")
        .expect("identity persists");
    assert!(identity_again.resolved);
    assert!(!identity_again.dismissed);
    assert!(!again.text.contains("11010519491231002X"));

    let mut forged = identity_again.clone();
    forged.dismissed = true;
    assert!(matches!(
        validate_result(&again.text, &[forged]),
        Err(TextError::InvalidInput)
    ));
}

#[test]
fn serialized_private_payloads_round_trip_without_debug_surface() {
    let analysis = analyze(
        "原告：张三。",
        "group-salt-4",
        &[DictionaryEntry {
            text: "张三".to_owned(),
            kind: "person_name".to_owned(),
            alias: None,
        }],
        &[],
        &[],
    )
    .expect("analysis");
    let encoded = serde_json::to_vec(&analysis).expect("encrypted-store payload serializes");
    let decoded = serde_json::from_slice(&encoded).expect("payload decodes");
    assert!(analysis == decoded);

    let mut legacy = serde_json::to_value(&analysis).expect("legacy payload shape");
    let fields = legacy
        .as_object_mut()
        .expect("analysis serializes as an object");
    fields.remove("replacements");
    fields.remove("sourceSha256");
    let legacy: privacy_text::Analysis =
        serde_json::from_value(legacy).expect("pre-span payload remains deserializable");
    assert!(legacy.replacements.is_empty());
    assert!(legacy.source_sha256.is_empty());
    assert!(matches!(
        validate_analysis(&legacy),
        Err(TextError::EvidenceVerificationFailed)
    ));
}

#[test]
fn cloud_kind_conflict_and_dictionary_alias_conflict_remain_in_review() {
    let cloud_conflict = analyze(
        "申请人：王伟，请求依法裁判。",
        "group-salt-5",
        &[],
        &[CloudFinding {
            text: "王伟".to_owned(),
            kind: "organization".to_owned(),
        }],
        &[],
    )
    .expect("cloud kind conflict is a valid response");
    assert!(cloud_conflict.needs_review);
    assert!(cloud_conflict.text.contains("王伟"));
    assert!(cloud_conflict
        .findings
        .iter()
        .all(|finding| !finding.resolved));

    let alias_conflict = analyze(
        "保密代号QX-7仅限内部使用。",
        "group-salt-5",
        &[
            DictionaryEntry {
                text: "QX-7".to_owned(),
                kind: "custom".to_owned(),
                alias: Some("[CUSTOM_A]".to_owned()),
            },
            DictionaryEntry {
                text: "QX-7".to_owned(),
                kind: "custom".to_owned(),
                alias: Some("[CUSTOM_B]".to_owned()),
            },
        ],
        &[],
        &[],
    )
    .expect("alias conflict is a valid response");
    assert!(alias_conflict.needs_review);
    assert!(alias_conflict.text.contains("QX-7"));
}

#[test]
fn dictionary_alias_is_stable_across_paragraphs() {
    let text = "张三提交材料。\n\n第二段仍由张三说明。";
    let analysis = analyze(
        text,
        "group-salt-6",
        &[DictionaryEntry {
            text: "张三".to_owned(),
            kind: "person_name".to_owned(),
            alias: None,
        }],
        &[],
        &[],
    )
    .expect("analysis");
    assert!(!analysis.needs_review);
    let aliases = analysis
        .findings
        .iter()
        .filter(|finding| finding.text == "张三")
        .map(|finding| finding.alias.as_deref().expect("resolved alias"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(aliases.len(), 1);
    let alias = aliases.iter().next().expect("one stable alias");
    assert_eq!(analysis.text.matches(alias).count(), 2);
    assert_eq!(analysis.replacements.len(), 2);
    assert!(analysis.replacements[0].source_end < analysis.replacements[1].source_start);
    for replacement in &analysis.replacements {
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.id == replacement.finding_id)
            .expect("replacement finding");
        assert_eq!(
            text.get(replacement.source_start..replacement.source_end),
            Some(finding.text.as_str())
        );
        assert_eq!(
            analysis
                .text
                .get(replacement.output_start..replacement.output_end),
            Some(replacement.alias.as_str())
        );
    }
    verify_analysis_source(text, &analysis).expect("source span evidence");
    validate_analysis(&analysis).expect("persisted span evidence");

    let mut tampered = analysis.clone();
    tampered.replacements[0].output_start = tampered.replacements[0].output_start.saturating_add(1);
    assert!(matches!(
        validate_analysis(&tampered),
        Err(TextError::EvidenceVerificationFailed)
    ));
    assert!(matches!(
        verify_analysis_source("李四提交材料。\n\n第二段仍由李四说明。", &analysis),
        Err(TextError::EvidenceVerificationFailed)
    ));
}

#[test]
fn local_template_export_is_separate_from_redacted_result_export() {
    let template = "授权委托书\n委托人：张三\n联系电话：13800138000";
    assert!(matches!(
        export(template, "txt"),
        Err(TextError::ResidualRisk)
    ));
    assert_eq!(
        String::from_utf8(export_local_document(template, "txt").expect("local txt"))
            .expect("UTF-8 local txt"),
        template
    );
    let docx = export_local_document(template, "docx").expect("local docx");
    assert_eq!(
        extract("local-template.docx", &docx, None).expect("local docx reextract"),
        template
    );
}

#[test]
fn ai_occurrences_expand_from_one_verified_span_to_equal_local_text() {
    let text = "联系人：李明；再次出现李明。";
    let first = text.find("李明").expect("first occurrence");
    let analysis = analyze_with_ai(
        text,
        "ai-occurrence-span",
        &[],
        &[AiFinding {
            text: "李明".to_owned(),
            kind: "person_name".to_owned(),
            start: first,
            end: first + "李明".len(),
            confidence_ppm: Some(950_000),
        }],
        &[],
    )
    .expect("first AI occurrence");

    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert_eq!(analysis.replacements.len(), 2);
    assert!(!analysis.text.contains("李明"));
    validate_analysis(&analysis).expect("AI span analysis validates");
}

#[test]
fn ai_span_must_match_utf8_boundaries_and_exact_source_text() {
    let text = "甲方：李明。";
    let start = text.find("李明").expect("name");
    let invalid_boundary = analyze_with_ai(
        text,
        "ai-utf8-boundary",
        &[],
        &[AiFinding {
            text: "李明".to_owned(),
            kind: "person_name".to_owned(),
            start: start + 1,
            end: start + "李明".len(),
            confidence_ppm: None,
        }],
        &[],
    );
    assert!(matches!(
        invalid_boundary,
        Err(TextError::CloudFindingAbsent)
    ));

    let forged_text = analyze_with_ai(
        text,
        "ai-utf8-boundary",
        &[],
        &[AiFinding {
            text: "李华".to_owned(),
            kind: "person_name".to_owned(),
            start,
            end: start + "李明".len(),
            confidence_ppm: None,
        }],
        &[],
    );
    assert!(matches!(forged_text, Err(TextError::CloudFindingAbsent)));
}

#[test]
fn ai_range_enclosing_local_candidate_can_resolve_without_internal_error() {
    let text = "东岚云栖供应链（合成）有限公司签署协议。";
    let start = text
        .find("东岚云栖供应链（合成）有限公司")
        .expect("organization");
    let analysis = analyze_with_ai(
        text,
        "ai-overlap-review",
        &[],
        &[AiFinding {
            text: "东岚云栖供应链（合成）有限公司".to_owned(),
            kind: "organization_name".to_owned(),
            start,
            end: start + "东岚云栖供应链（合成）有限公司".len(),
            confidence_ppm: Some(990_000),
        }],
        &[],
    )
    .expect("enclosing AI range resolves the local NER overlap");
    assert!(!analysis.needs_review);
    assert!(!analysis.text.contains("东岚云栖供应链（合成）有限公司"));
    assert_eq!(analysis.replacements.len(), 1);
    verify_analysis_source(text, &analysis).expect("source evidence");
}

#[test]
fn residual_validation_does_not_treat_iso_dates_as_long_digit_secrets() {
    validate_result("签署日期：2020-12-20；履行日期：2021-01-15。", &[])
        .expect("ordinary legal dates are not identifiers");
    assert!(matches!(
        validate_result("收款账号：1234-5678-9012。", &[]),
        Err(TextError::ResidualRisk)
    ));
}

#[test]
fn redacted_exports_allow_ordinary_iso_dates() {
    let text = "签署日期：2020-12-20；履行日期：2021-01-15。";
    assert_eq!(export(text, "txt").expect("TXT export"), text.as_bytes());
    export(text, "docx").expect("DOCX export");
}

#[test]
fn residual_validation_blocks_unredacted_credential_assignments_but_accepts_aliases() {
    assert!(matches!(
        validate_result("附件中的 API_KEY=TEST-ONLY-DO-NOT-USE。", &[]),
        Err(TextError::ResidualRisk)
    ));
    export("附件中的 API_KEY=[CUSTOM_abcdefghijkl]。", "txt")
        .expect("credential alias is safe to export");
}

#[test]
fn local_credential_assignment_is_redacted_before_model_findings() {
    let text = "附件中的 API_KEY=TEST-ONLY-DO-NOT-USE。";
    let analysis = analyze(text, "credential-assignment", &[], &[], &[]).expect("analysis");
    assert!(!analysis.needs_review);
    assert!(!analysis.text.contains("TEST-ONLY-DO-NOT-USE"));
    assert!(analysis
        .findings
        .iter()
        .any(|finding| finding.kind == "custom" && finding.source == "deterministic"));
    validate_analysis(&analysis).expect("credential result validates");
}

#[test]
fn explicit_organization_abbreviation_shares_the_full_name_alias() {
    let text = "东岚云栖科技有限公司（简称东岚科技）与东岚云栖科技有限公司签约，东岚科技负责履行。";
    let full = "东岚云栖科技有限公司";
    let short = "东岚科技";
    let ai = [
        (0..2)
            .map(|occurrence| ai_occurrence(text, full, occurrence, "organization_name"))
            .collect::<Vec<_>>(),
        (0..2)
            .map(|occurrence| ai_occurrence(text, short, occurrence, "organization_name"))
            .collect::<Vec<_>>(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let analysis = analyze_with_ai(text, "organization-alias", &[], &ai, &[])
        .expect("explicit organization alias analysis");
    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert!(!analysis.text.contains(full));
    assert!(!analysis.text.contains(short));
    let aliases = analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == "organization_name")
        .filter_map(|finding| finding.alias.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(aliases.len(), 1);
    assert_eq!(analysis.replacements.len(), 4);
    validate_analysis(&analysis).expect("organization alias result validates");
}

#[test]
fn repeated_person_name_with_conflicting_party_context_stays_for_review() {
    let text = "甲方联系人：周宁；乙方联系人：周宁。";
    let ai = (0..2)
        .map(|occurrence| ai_occurrence(text, "周宁", occurrence, "person_name"))
        .collect::<Vec<_>>();
    let analysis =
        analyze_with_ai(text, "same-person-name", &[], &ai, &[]).expect("same-name analysis");
    assert!(analysis.needs_review);
    assert!(analysis.text.contains("周宁"));
    assert_eq!(analysis.replacements.len(), 0);
    assert!(analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == "person_name" && finding.text == "周宁")
        .all(|finding| !finding.resolved));
}

#[test]
fn repeated_person_name_without_identity_conflict_is_redacted_with_one_alias() {
    let text = "周宁提交材料，后续由周宁补充说明。";
    let ai = (0..2)
        .map(|occurrence| ai_occurrence(text, "周宁", occurrence, "person_name"))
        .collect::<Vec<_>>();
    let analysis =
        analyze_with_ai(text, "same-person-name", &[], &ai, &[]).expect("same-name analysis");

    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert!(!analysis.text.contains("周宁"));
    assert_eq!(analysis.replacements.len(), 2);
    let aliases = analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == "person_name" && finding.text == "周宁")
        .filter_map(|finding| finding.alias.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(aliases.len(), 1);
    validate_analysis(&analysis).expect("same-person result validates");
}

#[test]
fn one_model_occurrence_covers_every_exact_repeated_name() {
    let text = "李明提交材料，后续由李明补充说明。";
    let analysis = analyze_with_ai(
        text,
        "all-local-occurrences",
        &[],
        &[ai_occurrence(text, "李明", 0, "person_name")],
        &[],
    )
    .expect("one occurrence establishes the spelling");

    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert!(!analysis.text.contains("李明"));
    assert_eq!(analysis.replacements.len(), 2);
    let aliases = analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == "person_name" && finding.text == "李明")
        .filter_map(|finding| finding.alias.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(aliases.len(), 1);
    validate_analysis(&analysis).expect("all repeated occurrences validate");
}

#[test]
fn same_name_with_explicit_identity_ambiguity_stays_for_review() {
    let text = "材料中有两位姓名均为周宁的人员；另一位周宁要求核对身份是否相同。";
    let analysis = analyze_with_ai(
        text,
        "explicit-identity-ambiguity",
        &[],
        &[ai_occurrence(text, "周宁", 0, "person_name")],
        &[],
    )
    .expect("identity ambiguity analysis");

    assert!(analysis.needs_review);
    assert_eq!(analysis.replacements.len(), 0);
    assert!(analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == "person_name" && finding.text == "周宁")
        .all(|finding| !finding.resolved));
}

#[test]
fn local_ner_grammar_tokens_do_not_block_identity_review() {
    let text = "材料中有两位姓名均为周宁的人员；另一位周宁要求核对身份是否相同。";
    let analysis = analyze_with_ai(
        text,
        "local-ner-grammar",
        &[],
        &[ai_occurrence(text, "周宁", 0, "person_name")],
        &[],
    )
    .expect("grammar filtering analysis");

    assert!(
        analysis.needs_review,
        "the two identities must remain reviewable"
    );
    assert!(!analysis.findings.iter().any(|finding| {
        finding.source == "local_ner"
            && finding.kind == "person_name"
            && matches!(finding.text.as_str(), "均为" | "相同" | "当成" | "电话")
    }));
}

#[test]
fn structured_opaque_identifier_is_covered_without_model_output() {
    let text = "项目代码：PRJ-EDU-2.4。";
    let analysis = analyze(text, "structured-identifier", &[], &[], &[])
        .expect("deterministic structured identifier analysis");

    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert!(!analysis.text.contains("PRJ-EDU-2.4"));
    assert!(analysis.findings.iter().any(|finding| {
        finding.kind == "custom" && finding.source == "deterministic" && finding.resolved
    }));
    validate_analysis(&analysis).expect("structured identifier result validates");
}

#[test]
fn structured_identifier_corrobates_an_ai_custom_without_changing_its_alias() {
    let text = "项目代码：PRJ-EDU-2.4。";
    let analysis = analyze_with_ai(
        text,
        "structured-identifier-ai",
        &[],
        &[ai_occurrence(text, "PRJ-EDU-2.4", 0, "custom")],
        &[],
    )
    .expect("structured identifier analysis");

    assert!(!analysis.needs_review, "output: {}", analysis.text);
    assert!(!analysis.text.contains("PRJ-EDU-2.4"));
    assert!(analysis.findings.iter().any(|finding| {
        finding.kind == "custom" && finding.source == "ai+deterministic" && finding.resolved
    }));
    validate_analysis(&analysis).expect("corroborated structured identifier validates");
}

#[test]
fn model_only_custom_date_stays_for_review_and_preserves_the_fact() {
    let text = "履行日期为2025年1月8日。";
    let analysis = analyze_with_ai(
        text,
        "custom-date-review",
        &[],
        &[ai_occurrence(text, "2025年1月8日", 0, "custom")],
        &[],
    )
    .expect("custom date analysis");

    assert!(analysis.needs_review);
    assert_eq!(analysis.replacements.len(), 0);
    assert!(analysis.text.contains("2025年1月8日"));
    assert!(analysis
        .findings
        .iter()
        .any(|finding| finding.kind == "custom" && !finding.resolved));
    verify_analysis_source(text, &analysis).expect("review source evidence remains valid");
}

#[test]
fn low_confidence_ai_entity_remains_reviewable_and_is_persisted_as_evidence() {
    let text = "协作方北极星已经签署协议。";
    let analysis = analyze_with_ai(
        text,
        "low-confidence-ai",
        &[],
        &[AiFinding {
            text: "北极星".to_owned(),
            kind: "organization_name".to_owned(),
            start: text.find("北极星").expect("entity start"),
            end: text.find("北极星").expect("entity start") + "北极星".len(),
            confidence_ppm: Some(899_999),
        }],
        &[],
    )
    .expect("low-confidence AI analysis");

    assert!(analysis.needs_review);
    assert!(analysis.text.contains("北极星"));
    assert_eq!(analysis.ai_findings.as_ref().map(Vec::len), Some(1));
    assert!(analysis
        .findings
        .iter()
        .any(|finding| finding.text == "北极星"
            && finding.source.contains("ai")
            && !finding.resolved));
    verify_analysis_source(text, &analysis).expect("persisted AI evidence remains source-bound");
}

fn ai_occurrence(text: &str, needle: &str, occurrence: usize, kind: &str) -> AiFinding {
    let (start, value) = text
        .match_indices(needle)
        .nth(occurrence)
        .expect("AI occurrence");
    AiFinding {
        text: value.to_owned(),
        kind: kind.to_owned(),
        start,
        end: start + value.len(),
        confidence_ppm: Some(950_000),
    }
}
