use privacy_text::{
    analyze, export, export_local_document, extract, validate_analysis, validate_result,
    verify_analysis_source, CloudFinding, DictionaryEntry, TextError,
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
