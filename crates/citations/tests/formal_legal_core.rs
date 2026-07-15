use citations::{build_legal_answer_context, validate_answer_citations};
use domain::qa::{CitationInvalidReason, LegalAnswerCandidatesRequest};
use rusqlite::{Connection, OpenFlags};
use std::{collections::HashSet, env, path::PathBuf};

const FORMAL_DB_ENV: &str = "LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE";
const HISTORY_LAW: &str = "贵州省林地管理条例";
const MINIMUM_FORMAL_DATASET_VERSION: (u32, u32, u32, u32) = (2026, 7, 14, 2);

fn formal_dataset_version_key(value: &str) -> Option<(u32, u32, u32, u32)> {
    let (date, revision) = value.split_once("-stage1c.")?;
    let mut date_parts = date.split('.').map(str::parse::<u32>);
    let year = date_parts.next()?.ok()?;
    let month = date_parts.next()?.ok()?;
    let day = date_parts.next()?.ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    Some((year, month, day, revision.parse().ok()?))
}

fn formal_connection() -> Connection {
    let path = env::var_os(FORMAL_DB_ENV)
        .map(PathBuf::from)
        .expect("set LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE to the Stage 1C legal_core.sqlite");
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("formal legal database opens read-only")
}

fn candidates_request(
    question: &str,
    law_name: Option<&str>,
    article_number: Option<&str>,
    keywords: &[&str],
    case_date: &str,
    effectiveness_levels: &[&str],
) -> LegalAnswerCandidatesRequest {
    LegalAnswerCandidatesRequest {
        question: question.to_owned(),
        law_name: law_name.map(str::to_owned),
        article_number: article_number.map(str::to_owned),
        keywords: keywords.iter().map(|value| (*value).to_owned()).collect(),
        case_date: Some(case_date.to_owned()),
        effectiveness_levels: effectiveness_levels
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        include_expired: false,
        limit: Some(16),
    }
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_database_metadata_and_history_volume_are_release_grade() {
    let connection = formal_connection();
    let metadata = |key: &str| {
        connection
            .query_row(
                "SELECT value FROM database_metadata WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .expect("required formal metadata exists")
    };

    assert_eq!(metadata("dataset_name"), "official-china-legal-core");
    assert_eq!(metadata("coverage_status"), "complete");
    assert_eq!(metadata("schema_version"), "4");
    let dataset_version = metadata("dataset_version");
    let dataset_version_key = formal_dataset_version_key(&dataset_version)
        .unwrap_or_else(|| panic!("unexpected formal dataset version format: {dataset_version}"));
    assert!(
        dataset_version_key >= MINIMUM_FORMAL_DATASET_VERSION,
        "formal dataset {dataset_version} predates the accepted history fix baseline"
    );
    assert_eq!(
        metadata("source_manifest_sha256"),
        "011551065b404507bce7b2cf542cb3b18da79a14437d094d067e685a438cd9fa"
    );
    assert_eq!(
        metadata("stage_1c_data_status"),
        "complete_with_declared_history_date_exceptions"
    );

    let multi_version_documents: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (
               SELECT document_id FROM law_versions GROUP BY document_id HAVING COUNT(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .expect("multi-version document count reads");
    let bounded_history_versions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM law_versions WHERE effective_to IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("bounded history count reads");

    assert!(multi_version_documents >= 4_481);
    assert!(bounded_history_versions >= 5_744);
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_context_applies_multi_law_article_and_effectiveness_filters() {
    let connection = formal_connection();
    let request = candidates_request(
        "《中华人民共和国民法典》和《贵州省林地管理条例》的第一条",
        None,
        None,
        &["保护"],
        "2024-01-01",
        &["national_law", "local_regulation"],
    );

    let context = build_legal_answer_context(&connection, &request).expect("formal context builds");
    let titles = context
        .sources
        .iter()
        .map(|source| source.document_title.as_str())
        .collect::<HashSet<_>>();

    assert_eq!(context.query.law_names.len(), 2);
    assert_eq!(context.query.article_numbers, ["第一条"]);
    assert_eq!(context.query.effectiveness_levels.len(), 2);
    assert!(titles.contains("中华人民共和国民法典"));
    assert!(titles.contains(HISTORY_LAW));
    assert!(context
        .sources
        .iter()
        .all(|source| source.article_number == "第一条"));
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_history_selects_three_date_correct_versions_and_validates_stable_ids() {
    let connection = formal_connection();
    let probes = [
        ("2011-01-01", "flk-version-4028abcc612777930161288eb0914501"),
        ("2019-01-01", "flk-version-ff8080816eb1afb8016ebb8313bf15e8"),
        ("2024-01-01", "flk-version-ff8081818d0c98f0018d116caa8d163f"),
    ];

    for (case_date, expected_version_id) in probes {
        let request = candidates_request(
            "贵州省林地管理条例第一条",
            Some(HISTORY_LAW),
            Some("第一条"),
            &[],
            case_date,
            &["local_regulation"],
        );
        let context =
            build_legal_answer_context(&connection, &request).expect("dated context builds");
        assert!(!context.sources.is_empty(), "no source for {case_date}");
        assert!(context.sources.iter().all(|source| {
            source.document_title == HISTORY_LAW && source.version_id == expected_version_id
        }));
    }

    let historical_request = candidates_request(
        "贵州省林地管理条例第一条",
        Some(HISTORY_LAW),
        Some("第一条"),
        &[],
        "2011-01-01",
        &["local_regulation"],
    );
    let historical_context = build_legal_answer_context(&connection, &historical_request)
        .expect("historical context builds");
    let historical_source = historical_context
        .sources
        .first()
        .expect("historical source exists");
    assert!(!historical_source.source_id.contains(&format!(
        "law:{}:{}",
        historical_source.document_id, historical_source.version_id
    )));

    let (prefix, _) = historical_source
        .source_id
        .rsplit_once(":art:")
        .expect("formal source uses stable citation id");
    let missing_marker = format!("[SRC:{prefix}:art:999999]");
    let report = validate_answer_citations(
        &connection,
        &missing_marker,
        &historical_context.sources,
        Some("2011-01-01"),
        false,
    )
    .expect("formal historical citation validates");

    assert_eq!(
        report.citations[0].reason,
        Some(CitationInvalidReason::ParagraphNotFound)
    );
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_contract_law_article_107_is_available_in_2019() {
    let connection = formal_connection();
    let historical = candidates_request(
        "2019年合同违约应如何承担责任",
        Some("中华人民共和国合同法"),
        Some("第一百零七条"),
        &["违约责任", "继续履行", "赔偿损失"],
        "2019-01-01",
        &["national_law"],
    );
    let historical_context =
        build_legal_answer_context(&connection, &historical).expect("2019 context builds");

    assert!(!historical_context.sources.is_empty());
    assert!(historical_context.sources.iter().all(|source| {
        source.document_title == "中华人民共和国合同法"
            && source.article_number == "第一百零七条"
            && source.effective_from.as_str() <= "2019-01-01"
            && source
                .effective_to
                .as_deref()
                .is_some_and(|effective_to| effective_to >= "2019-01-01")
    }));
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_contract_law_article_107_is_excluded_in_2022() {
    let connection = formal_connection();
    let after_repeal = candidates_request(
        "2022年合同违约应如何承担责任",
        Some("中华人民共和国合同法"),
        Some("第一百零七条"),
        &["违约责任", "继续履行", "赔偿损失"],
        "2022-01-01",
        &["national_law"],
    );
    let after_repeal_context =
        build_legal_answer_context(&connection, &after_repeal).expect("2022 context builds");
    assert!(after_repeal_context.sources.is_empty());
}

#[test]
#[ignore = "requires the formal Stage 1C legal_core.sqlite via LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"]
fn formal_2024_context_handles_natural_chinese_arabic_articles_and_paired_laws() {
    let connection = formal_connection();
    let case_date = "2024-06-01";

    let natural = candidates_request("合同违约责任如何承担？", None, None, &[], case_date, &[]);
    let natural_context =
        build_legal_answer_context(&connection, &natural).expect("natural context builds");
    assert!(natural_context
        .query
        .keywords
        .iter()
        .any(|keyword| keyword == "违约责任"));
    assert!(natural_context.sources.iter().any(|source| {
        source.document_title == "中华人民共和国民法典" && source.article_number == "第五百七十七条"
    }));
    assert!(!natural_context
        .sources
        .iter()
        .any(|source| source.document_title == "中华人民共和国合同法"));

    let arabic = candidates_request("《民法典》第577条", None, None, &[], case_date, &[]);
    let arabic_context =
        build_legal_answer_context(&connection, &arabic).expect("Arabic article context builds");
    assert_eq!(arabic_context.query.article_numbers, ["第五百七十七条"]);
    assert!(arabic_context.query.keywords.is_empty());
    assert!(arabic_context.sources.iter().all(|source| {
        source.document_title == "中华人民共和国民法典" && source.article_number == "第五百七十七条"
    }));

    let subarticle =
        candidates_request("第120条之1", None, Some("第120条之1"), &[], case_date, &[]);
    let subarticle_context = build_legal_answer_context(&connection, &subarticle)
        .expect("mixed-numeral sub-article context builds");
    assert!(!subarticle_context.sources.is_empty());
    assert!(subarticle_context.sources.iter().all(|source| {
        matches!(
            source.article_number.as_str(),
            "第一百二十条之一"
                | "第一百二十条之1"
                | "第120条之一"
                | "第120条之1"
                | "120条之一"
                | "120条之1"
        )
    }));

    let nonexistent_subarticle = candidates_request(
        "《民法典》第577条之99999",
        Some("民法典"),
        Some("第577条之99999"),
        &[],
        case_date,
        &[],
    );
    let nonexistent_subarticle_context =
        build_legal_answer_context(&connection, &nonexistent_subarticle)
            .expect("nonexistent sub-article search fails closed");
    assert!(nonexistent_subarticle_context.sources.is_empty());

    let multi_keyword = candidates_request(
        "违约责任、继续履行、赔偿损失",
        None,
        None,
        &["违约责任", "继续履行", "赔偿损失"],
        case_date,
        &[],
    );
    let multi_keyword_context = build_legal_answer_context(&connection, &multi_keyword)
        .expect("multi-keyword context builds");
    let first = multi_keyword_context
        .sources
        .first()
        .expect("multi-keyword context contains a source");
    assert_eq!(first.document_title, "中华人民共和国民法典");
    assert_eq!(first.article_number, "第五百七十七条");
    assert!(!multi_keyword_context
        .sources
        .iter()
        .any(|source| source.document_title == "中华人民共和国合同法"));

    let paired = candidates_request(
        "《中华人民共和国民法典》第577条；《中华人民共和国刑法》第264条",
        None,
        None,
        &[],
        case_date,
        &[],
    );
    let paired_context =
        build_legal_answer_context(&connection, &paired).expect("paired context builds");
    assert!(paired_context.sources.iter().any(|source| {
        source.document_title == "中华人民共和国民法典" && source.article_number == "第五百七十七条"
    }));
    assert!(paired_context.sources.iter().any(|source| {
        source.document_title == "中华人民共和国刑法" && source.article_number == "第二百六十四条"
    }));
    assert!(paired_context.sources.iter().all(|source| {
        (source.document_title == "中华人民共和国民法典"
            && source.article_number == "第五百七十七条")
            || (source.document_title == "中华人民共和国刑法"
                && source.article_number == "第二百六十四条")
    }));

    let civil_source = arabic_context
        .sources
        .first()
        .expect("Civil Code article 577 is available")
        .clone();
    let attack = concat!(
        "甲方应支付全部价款且乙方应承担刑事责任。",
        "[SRC:law:placeholder]"
    )
    .replace("law:placeholder", &civil_source.source_id);
    let attack_report = validate_answer_citations(
        &connection,
        &attack,
        std::slice::from_ref(&civil_source),
        Some(case_date),
        false,
    )
    .expect("conjunction attack validates");
    assert_eq!(attack_report.valid_count, 1);
    assert!(attack_report.unsupported_legal_conclusion);

    let enumeration = concat!("甲方应继续履行并且赔偿损失。", "[SRC:law:placeholder]")
        .replace("law:placeholder", &civil_source.source_id);
    let enumeration_report = validate_answer_citations(
        &connection,
        &enumeration,
        std::slice::from_ref(&civil_source),
        Some(case_date),
        false,
    )
    .expect("remedy enumeration validates");
    assert!(!enumeration_report.unsupported_legal_conclusion);
}
