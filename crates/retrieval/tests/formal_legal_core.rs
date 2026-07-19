use domain::law::{
    GetLawRelationsRequest, RelationDirection, SearchArticlesRequest, SearchLawsRequest,
};
use rusqlite::OptionalExtension;
use std::{env, path::PathBuf};

const FORMAL_DATABASE_ENV: &str = "LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE";
const EXPECTED_DATASET_VERSION: &str = "2026.07.14-stage1c.2";

fn formal_connection() -> rusqlite::Connection {
    let path = env::var_os(FORMAL_DATABASE_ENV)
        .map(PathBuf::from)
        .expect("set LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE to the audited Stage 1C database");
    let connection = database::open_legal_core_read_only(path).expect("formal database opens");
    let dataset_version: String = connection
        .query_row(
            "SELECT value FROM database_metadata WHERE key = 'dataset_version'",
            [],
            |row| row.get(0),
        )
        .expect("formal database has a dataset version");
    assert_eq!(dataset_version, EXPECTED_DATASET_VERSION);
    connection
}

#[test]
#[ignore = "requires the audited multi-gigabyte Stage 1C legal database"]
fn formal_law_search_excludes_future_and_expired_versions_from_current_version() {
    let connection = formal_connection();
    let today: String = connection
        .query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))
        .expect("SQLite returns the local date");

    let future_probe: Option<(String, String, String)> = connection
        .query_row(
            "
            SELECT documents.id, documents.title, versions.id
            FROM law_versions versions
            JOIN law_documents documents ON documents.id = versions.document_id
            WHERE versions.status = 'not_yet_effective'
              AND versions.effective_from > date('now', 'localtime')
              AND (
                SELECT COUNT(*) FROM law_documents same_title
                WHERE same_title.title = documents.title
              ) = 1
            ORDER BY versions.effective_from, versions.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .expect("future-version probe is queryable");
    let (future_document_id, future_title, future_version_id) =
        future_probe.expect("formal snapshot contains a declared future version");
    let future_search = retrieval::search_laws(
        &connection,
        SearchLawsRequest {
            query: future_title,
            limit: Some(50),
        },
    )
    .expect("formal law search succeeds");
    let future_document = future_search
        .results
        .iter()
        .find(|result| result.document_id == future_document_id)
        .expect("future-version document appears in title search");
    assert_ne!(
        future_document.current_version_id.as_deref(),
        Some(future_version_id.as_str())
    );
    assert!(
        future_document
            .current_effective_from
            .as_deref()
            .map(|effective_from| effective_from <= today.as_str())
            .unwrap_or(true),
        "law search exposed a future effective date as current"
    );

    let expired_probe: (String, String) = connection
        .query_row(
            "
            SELECT documents.id, documents.title
            FROM law_documents documents
            WHERE EXISTS (
                SELECT 1 FROM law_versions versions
                WHERE versions.document_id = documents.id
            )
              AND NOT EXISTS (
                SELECT 1 FROM law_versions versions
                WHERE versions.document_id = documents.id
                  AND versions.effective_from <= date('now', 'localtime')
                  AND (
                    versions.effective_to IS NULL
                    OR versions.effective_to >= date('now', 'localtime')
                  )
                  AND versions.status <> 'not_yet_effective'
              )
              AND (
                SELECT COUNT(*) FROM law_documents same_title
                WHERE same_title.title = documents.title
              ) = 1
            ORDER BY documents.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("formal snapshot contains a fully expired document");
    let expired_search = retrieval::search_laws(
        &connection,
        SearchLawsRequest {
            query: expired_probe.1,
            limit: Some(50),
        },
    )
    .expect("expired law title search succeeds");
    let expired_document = expired_search
        .results
        .iter()
        .find(|result| result.document_id == expired_probe.0)
        .expect("expired document appears in title search");
    assert!(expired_document.current_version_id.is_none());
}

#[test]
#[ignore = "requires the audited multi-gigabyte Stage 1C legal database"]
fn formal_dated_article_search_enforces_known_historical_boundaries() {
    let connection = formal_connection();
    let contract_document_id: String = connection
        .query_row(
            "SELECT id FROM law_documents WHERE title = '中华人民共和国合同法' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("formal snapshot contains Contract Law");

    let historical = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "违约责任".to_owned(),
            document_id: Some(contract_document_id.clone()),
            case_date: Some("2019-01-01".to_owned()),
            limit: Some(50),
        },
    )
    .expect("2019 Contract Law search succeeds");
    assert!(!historical.results.is_empty());
    assert!(historical
        .results
        .iter()
        .all(|result| result.effective_to.as_deref() == Some("2020-12-31")));

    let after_repeal = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "违约责任".to_owned(),
            document_id: Some(contract_document_id),
            case_date: Some("2021-01-01".to_owned()),
            limit: Some(50),
        },
    )
    .expect("2021 Contract Law search succeeds");
    assert!(after_repeal.results.is_empty());

    let unknown_probe: (String, String, String) = connection
        .query_row(
            "
            SELECT versions.document_id, versions.id, versions.effective_from
            FROM law_versions versions
            WHERE versions.status = 'repealed'
              AND versions.effective_to IS NULL
              AND versions.effective_from <> '0001-01-01'
              AND (SELECT COUNT(*) FROM law_versions same_document
                   WHERE same_document.document_id = versions.document_id) = 1
              AND (SELECT COUNT(*) FROM law_articles articles
                   WHERE articles.version_id = versions.id) BETWEEN 1 AND 50
            ORDER BY versions.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("formal snapshot contains a bounded-size unknown-end historical version");
    let undated_review = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: String::new(),
            document_id: Some(unknown_probe.0.clone()),
            case_date: None,
            limit: Some(50),
        },
    )
    .expect("undated historical review succeeds");
    assert!(undated_review
        .results
        .iter()
        .any(|result| result.version_id == unknown_probe.1));

    let dated = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: String::new(),
            document_id: Some(unknown_probe.0),
            case_date: Some(unknown_probe.2),
            limit: Some(50),
        },
    )
    .expect("dated unknown-end search succeeds");
    assert!(!dated
        .results
        .iter()
        .any(|result| result.version_id == unknown_probe.1));
}

#[test]
#[ignore = "requires the audited Stage 1C legal database"]
fn formal_chinese_keyword_expansion_recalls_substantive_civil_code_article() {
    let connection = formal_connection();

    for query in ["违约责任", "违约责任、继续履行、赔偿损失"] {
        let response = retrieval::search_articles(
            &connection,
            SearchArticlesRequest {
                query: query.to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("bounded Chinese keyword search succeeds");
        let substantive_position = response
            .results
            .iter()
            .position(|result| {
                result.document_title == "中华人民共和国民法典"
                    && result.article_number == "第五百七十七条"
            })
            .expect("Civil Code article 577 is recalled in the top ten");
        assert!(response.results.iter().all(|result| {
            result.effective_from.as_str() <= "2024-06-01"
                && result
                    .effective_to
                    .as_deref()
                    .is_none_or(|effective_to| effective_to >= "2024-06-01")
        }));
        assert!(!response
            .results
            .iter()
            .any(|result| result.document_title == "中华人民共和国合同法"));
        if query.contains('、') {
            assert_eq!(substantive_position, 0, "article 577 must lead for {query}");
        }
        if let Some(heading_position) = response.results.iter().position(|result| {
            result.document_title == "中华人民共和国民法典"
                && result.article_number == "第五百七十六条"
        }) {
            assert!(
                substantive_position < heading_position,
                "substantive article must precede the embedded chapter heading for {query}"
            );
        }
    }
}

#[test]
#[ignore = "requires the audited Stage 1C legal database"]
fn formal_explicit_law_alias_scopes_contract_performance_search() {
    let connection = formal_connection();
    let response = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "民法典 合同履行 逾期交付".to_owned(),
            document_id: None,
            case_date: Some("2025-11-10".to_owned()),
            limit: Some(10),
        },
    )
    .expect("explicit Civil Code search succeeds");

    assert!(!response.results.is_empty());
    assert!(response
        .results
        .iter()
        .all(|result| result.document_title == "中华人民共和国民法典"));
    for expected_article in ["第五百一十三条", "第五百八十四条", "第八百零一条"]
    {
        assert!(
            response
                .results
                .iter()
                .any(|result| result.article_number == expected_article),
            "missing {expected_article}: {:?}",
            response.results
        );
    }
}

#[test]
#[ignore = "requires the audited Stage 1C legal database"]
fn formal_structured_article_subarticle_and_natural_question_searches_are_exact() {
    let connection = formal_connection();
    for query in ["民法典第577条", "民法典 第577条"] {
        let response = retrieval::search_articles(
            &connection,
            SearchArticlesRequest {
                query: query.to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("structured Civil Code search succeeds");
        let first = response
            .results
            .first()
            .unwrap_or_else(|| panic!("no result for {query}"));
        assert_eq!(first.document_title, "中华人民共和国民法典");
        assert_eq!(first.article_number, "第五百七十七条");
    }

    let natural = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "合同违约责任如何承担".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(10),
        },
    )
    .expect("natural Chinese question search succeeds");
    assert!(natural.results.iter().any(|result| {
        result.document_title == "中华人民共和国民法典" && result.article_number == "第五百七十七条"
    }));
    assert!(!natural
        .results
        .iter()
        .any(|result| result.document_title == "中华人民共和国合同法"));

    let subarticle = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "第120条之1".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(20),
        },
    )
    .expect("mixed-numeral sub-article search succeeds");
    assert!(!subarticle.results.is_empty());
    assert!(subarticle.results.iter().all(|result| {
        matches!(
            result.article_number.as_str(),
            "第一百二十条之一"
                | "第一百二十条之1"
                | "第120条之一"
                | "第120条之1"
                | "120条之一"
                | "120条之1"
        )
    }));

    let nonexistent = retrieval::search_articles(
        &connection,
        SearchArticlesRequest {
            query: "民法典第577条之99999".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(10),
        },
    )
    .expect("nonexistent sub-article search fails closed");
    assert!(nonexistent.results.is_empty());
}

#[test]
#[ignore = "requires the audited Stage 1C legal database"]
fn formal_runtime_law_relations_build_a_provenanced_law_graph() {
    let connection = formal_connection();
    let (document_id, expected_relation_id): (String, String) = connection
        .query_row(
            "
            SELECT relations.from_document_id, relations.id
            FROM law_relations AS relations
            WHERE length(relations.source_reference) > 0
              AND EXISTS (
                  SELECT 1 FROM law_documents
                  WHERE id = relations.from_document_id
              )
              AND EXISTS (
                  SELECT 1 FROM law_documents
                  WHERE id = relations.to_document_id
              )
            ORDER BY relations.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("formal database contains a source-backed law relation");

    let response = retrieval::get_law_relations(
        &connection,
        GetLawRelationsRequest {
            document_id: document_id.clone(),
            direction: Some(RelationDirection::Both),
        },
    )
    .expect("runtime relation query succeeds against the packaged schema");
    assert!(response
        .relations
        .iter()
        .any(|relation| relation.relation_id == expected_relation_id));

    let graph = domain::graph::law_graph(&response.relations);
    let expected_edge_id = format!("law_relation:{expected_relation_id}");
    let edge = graph
        .edges
        .iter()
        .find(|edge| edge.id == expected_edge_id)
        .expect("formal relation becomes a law graph edge");
    assert_eq!(edge.provenance.source_kind, "law_relation");
    assert_eq!(edge.provenance.source_id, expected_relation_id);
    assert!(edge
        .provenance
        .source_reference
        .as_deref()
        .is_some_and(|reference| !reference.trim().is_empty()));
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.id == format!("law_document:{document_id}")));
}
