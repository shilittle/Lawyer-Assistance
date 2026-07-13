use citations::{build_legal_answer_context, validate_answer_citations};
use domain::qa::{CitationInvalidReason, LegalAnswerCandidatesRequest};
use rusqlite::{Connection, OpenFlags};
use std::{collections::HashSet, env, path::PathBuf};

const FORMAL_DB_ENV: &str = "LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE";
const HISTORY_LAW: &str = "贵州省林地管理条例";

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
    assert_eq!(metadata("dataset_version"), "2026.07.11-stage1c.1");
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
