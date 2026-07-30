use assistant::{
    ArtifactTransfer, AttachmentTransfer, CaseChangeSpec, EvidenceAddition, FactAddition,
    LegalBasisAddition, CONTRACT_SCHEMA_VERSION,
};
use database::{CaseFactRow, CaseProjectRow};
use domain::document::DocumentTemplateId;
use legal_services::{
    CanonicalCaseProposal, CaseApplyPatchRequest, CaseGetStateRequest, CaseMaterialImportRequest,
    CaseProjectBootstrap, CaseProposePatchRequest, CitationValidateRequest, DocumentExportFormat,
    DocumentExportRequest, DocumentGenerateRequest, LegalGetArticleRequest,
    LegalGetRelationsRequest, LegalGetVersionsRequest, LegalSearchRequest, LegalServices,
    ServiceConfig, ABSENT_CASE_REVISION, SERVICE_SCHEMA_VERSION,
};
use rusqlite::Connection;
use std::{fs, io::Read, path::Path};

struct Fixture {
    _root: tempfile::TempDir,
    legal_path: std::path::PathBuf,
    user_path: std::path::PathBuf,
    output_root: std::path::PathBuf,
    services: LegalServices,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("temporary fixture root");
    let legal_path = root.path().join("legal.sqlite");
    let legal = Connection::open(&legal_path).expect("open legal fixture");
    database::initialize_legal_core_database(&legal).expect("initialize legal schema");
    legal
        .execute_batch(include_str!("fixtures/legal_core.sql"))
        .expect("populate legal fixture");
    drop(legal);

    let user_path = root.path().join("user.sqlite");
    database::validate_and_migrate_user_database(&user_path).expect("initialize user schema");
    let user = database::open_user_database(&user_path).expect("open user fixture");
    database::upsert_case_project(
        &user,
        &CaseProjectRow {
            project_id: "case-1".to_owned(),
            title: "合同争议".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: Some("2026-01-01".to_owned()),
            summary: "测试案件".to_owned(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .expect("insert project");
    database::upsert_case_fact(
        &user,
        &CaseFactRow {
            fact_id: "fact-existing".to_owned(),
            project_id: "case-1".to_owned(),
            occurred_on: Some("2026-01-02".to_owned()),
            title: "合同签订".to_owned(),
            description: "双方签订书面合同。".to_owned(),
            source: "case-1".to_owned(),
            confirmation_status: "confirmed".to_owned(),
        },
    )
    .expect("insert fact");
    drop(user);

    let output_root = root.path().join("exports");
    fs::create_dir_all(output_root.join("reports")).expect("create output root");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: legal_path.clone(),
        user_database_path: user_path.clone(),
        allowed_file_roots: vec![root.path().to_path_buf(), root.path().to_path_buf()],
        allowed_output_root: output_root.clone(),
    })
    .expect("construct services");
    Fixture {
        _root: root,
        legal_path,
        user_path,
        output_root,
        services,
    }
}

fn proposal_request(revision: String, fact_id: &str) -> CaseProposePatchRequest {
    CaseProposePatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-1".to_owned(),
        base_revision: revision,
        project_bootstrap: None,
        material_imports: Vec::new(),
        changes: CaseChangeSpec {
            schema_version: CONTRACT_SCHEMA_VERSION,
            facts: vec![FactAddition {
                id: fact_id.to_owned(),
                statement: "被告未按期履行付款义务。".to_owned(),
                occurred_on: Some("2026-02-01".to_owned()),
                source_refs: vec!["case-1".to_owned()],
            }],
            evidence: Vec::new(),
            issues: Vec::new(),
            legal_basis: Vec::new(),
            attachment_transfers: Vec::new(),
            artifact_transfers: Vec::new(),
        },
    }
}

fn current_revision(fixture: &Fixture) -> String {
    fixture
        .services
        .case_get_state(CaseGetStateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            page: None,
            page_size: None,
        })
        .expect("case state")
        .revision
}

fn empty_changes() -> CaseChangeSpec {
    CaseChangeSpec {
        schema_version: CONTRACT_SCHEMA_VERSION,
        facts: Vec::new(),
        evidence: Vec::new(),
        issues: Vec::new(),
        legal_basis: Vec::new(),
        attachment_transfers: Vec::new(),
        artifact_transfers: Vec::new(),
    }
}

fn empty_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("temporary empty fixture root");
    let legal_path = root.path().join("legal.sqlite");
    let legal = Connection::open(&legal_path).expect("open legal fixture");
    database::initialize_legal_core_database(&legal).expect("initialize legal schema");
    legal
        .execute_batch(include_str!("fixtures/legal_core.sql"))
        .expect("populate legal fixture");
    drop(legal);
    let user_path = root.path().join("user.sqlite");
    database::validate_and_migrate_user_database(&user_path).expect("initialize empty user db");
    let material_root = root.path().join("materials");
    let output_root = root.path().join("exports");
    fs::create_dir(&material_root).expect("material root");
    fs::create_dir(&output_root).expect("output root");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: legal_path.clone(),
        user_database_path: user_path.clone(),
        allowed_file_roots: vec![material_root],
        allowed_output_root: output_root.clone(),
    })
    .expect("empty services");
    Fixture {
        _root: root,
        legal_path,
        user_path,
        output_root,
        services,
    }
}

fn bootstrap_request(path: &Path) -> CaseProposePatchRequest {
    let mut changes = empty_changes();
    changes.facts.push(FactAddition {
        id: "fact-bootstrap".to_owned(),
        statement: "The reviewed contract records an agreement.".to_owned(),
        occurred_on: Some("2026-07-17".to_owned()),
        source_refs: vec!["material-contract".to_owned()],
    });
    CaseProposePatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-bootstrap".to_owned(),
        base_revision: ABSENT_CASE_REVISION.to_owned(),
        changes,
        project_bootstrap: Some(CaseProjectBootstrap {
            title: "Bootstrap case".to_owned(),
            case_type: "civil".to_owned(),
            opened_on: Some("2026-07-17".to_owned()),
            summary: "Created through a reviewed MCP proposal.".to_owned(),
        }),
        material_imports: vec![CaseMaterialImportRequest {
            material_id: "material-contract".to_owned(),
            path: path.to_string_lossy().into_owned(),
            title: "Reviewed contract".to_owned(),
        }],
    }
}

fn user_count(path: &Path, table: &str) -> i64 {
    let connection = database::open_user_database_read_only(path).expect("read user database");
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count user rows")
}

#[test]
fn status_and_legal_tools_use_validated_external_databases() {
    let fixture = fixture();
    let status = fixture.services.system_status().expect("system status");
    assert_eq!(status.status, "ready");
    assert_eq!(status.legal_database.schema_version.as_deref(), Some("4"));
    assert_eq!(status.legal_database.runtime_schema_version, None);
    assert_eq!(status.user_database.schema_version.as_deref(), Some("10"));
    assert_eq!(status.file_policy.allowed_file_root_count, 1);

    let search = fixture
        .services
        .legal_search(LegalSearchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: "合同".to_owned(),
            document_id: None,
            case_date: Some("2026-01-01".to_owned()),
            limit: Some(10),
        })
        .expect("legal search");
    assert!(!search.laws.is_empty());
    assert_eq!(search.articles[0].article_id, "civil-code-465");
    assert_eq!(search.database_version, "legal-services-fixture-v1");

    let article = fixture
        .services
        .legal_get_article(LegalGetArticleRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            article_id: "civil-code-465".to_owned(),
        })
        .expect("article");
    assert_eq!(article.article.document_id, "civil-code");
    let versions = fixture
        .services
        .legal_get_versions(LegalGetVersionsRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            document_id: "civil-code".to_owned(),
        })
        .expect("versions");
    assert_eq!(versions.versions.len(), 1);
    let relations = fixture
        .services
        .legal_get_relations(LegalGetRelationsRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            document_id: "civil-code".to_owned(),
            direction: None,
        })
        .expect("relations");
    assert_eq!(relations.relations.len(), 1);
}

#[test]
fn system_status_accepts_runtime_slim_law_articles_view() {
    let fixture = empty_fixture();
    fs::remove_file(&fixture.legal_path).expect("replace archive fixture with runtime database");
    let legal = Connection::open(&fixture.legal_path).expect("open legal runtime fixture");
    legal
        .execute_batch(include_str!("../../../data/schema/legal_core_runtime.sql"))
        .expect("initialize canonical legal runtime schema");
    legal
        .execute_batch(
            "
            BEGIN;
            INSERT INTO database_metadata (key, value, updated_at) VALUES
              ('schema_version', '4', '2026-07-17T00:00:00Z'),
              ('runtime_schema_version', '1', '2026-07-17T00:00:00Z'),
              ('distribution_profile', 'runtime-slim-v1', '2026-07-17T00:00:00Z'),
              ('dataset_version', 'runtime-fixture-v1', '2026-07-17T00:00:00Z');
            INSERT INTO issuing_authorities (id, name, authority_type, country_region)
            VALUES ('npc', 'National legislature', 'legislature', 'CN');
            INSERT INTO law_documents (
              id, title, document_type, authority_id, jurisdiction, effectiveness_level,
              status, promulgated_on, summary
            ) VALUES (
              'runtime-law', 'Runtime fixture law', 'law', 'npc', 'CN', 'national_law',
              'in_force', '2020-05-28', 'Canonical runtime view fixture'
            );
            INSERT INTO law_versions (
              id, document_id, version_label, status, effective_from, published_on,
              source_reference
            ) VALUES (
              'runtime-law-v1', 'runtime-law', '2021 version', 'in_force', '2021-01-01',
              '2020-05-28', 'runtime fixture'
            );
            INSERT INTO law_article_contents (content_id, content)
            VALUES (1, 'Café runtime article content from the deduplicated content table.');
            INSERT INTO law_article_rows (
              article_rowid, id, document_id, version_id, article_number, article_order,
              title, content_id, updated_on
            ) VALUES (
              1, 'runtime-law-1', 'runtime-law', 'runtime-law-v1', 'Article 1', 1,
              'Runtime article', 1, '2026-07-17'
            );
            INSERT INTO citation_metadata (article_id, citation_id, canonical_label)
            VALUES ('runtime-law-1', 'law:runtime-law:runtime-law-v1:art:1',
                    'Runtime fixture law, Article 1');
            INSERT INTO law_articles_fts (
              rowid, article_id, document_id, version_id, document_title, article_number,
              article_title, content
            ) VALUES (
              1, 'runtime-law-1', 'runtime-law', 'runtime-law-v1', 'Runtime fixture law',
              'Article 1', 'Runtime article',
              'Café runtime article content from the deduplicated content table.'
            );
            COMMIT;
            ",
        )
        .expect("populate canonical runtime-slim fixture");

    let fts_view_join_count: i64 = legal
        .query_row(
            "
            SELECT COUNT(*)
            FROM law_articles_fts
            JOIN law_article_rows AS rows
              ON rows.article_rowid = law_articles_fts.rowid
            JOIN law_articles AS articles
              ON articles.rowid = law_articles_fts.rowid
            WHERE law_articles_fts MATCH 'cafe'
              AND rows.id = articles.id
            ",
            [],
            |row| row.get(0),
        )
        .expect("canonical contentless FTS rowids join to the runtime view");
    assert_eq!(fts_view_join_count, 1);
    drop(legal);

    let status = fixture.services.system_status().expect("runtime status");
    assert_eq!(status.status, "ready");
    assert_eq!(
        status.legal_database.runtime_schema_version.as_deref(),
        Some("1")
    );
    assert_eq!(
        status.legal_database.distribution_profile.as_deref(),
        Some("runtime-slim-v1")
    );

    let article = fixture
        .services
        .legal_get_article(LegalGetArticleRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            article_id: "runtime-law-1".to_owned(),
        })
        .expect("runtime article lookup traverses canonical view");
    assert_eq!(article.article.document_id, "runtime-law");
    assert_eq!(
        article.article.content,
        "Café runtime article content from the deduplicated content table."
    );

    let search = fixture
        .services
        .legal_search(LegalSearchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: "cafe".to_owned(),
            document_id: None,
            case_date: Some("2026-07-17".to_owned()),
            limit: Some(1),
        })
        .expect("runtime legal search traverses authority, FTS, and article view tables");
    assert_eq!(search.articles.len(), 1);
    assert_eq!(search.articles[0].article_id, "runtime-law-1");
}

#[test]
fn system_status_rejects_runtime_marker_on_archive_article_table() {
    let fixture = empty_fixture();
    let legal = Connection::open(&fixture.legal_path).expect("open archive fixture");
    legal
        .execute_batch(
            "
            INSERT INTO database_metadata (key, value, updated_at)
            VALUES ('runtime_schema_version', '1', CURRENT_TIMESTAMP);
            PRAGMA user_version = 1;
            ",
        )
        .expect("add inconsistent runtime marker");
    drop(legal);

    let status = fixture
        .services
        .system_status()
        .expect("incompatible status");
    assert_eq!(status.status, "degraded");
    let error = status
        .legal_database
        .error
        .expect("archive table is rejected for runtime marker");
    assert_eq!(error.code, "legal_database_incompatible");
    assert_eq!(error.details["relation"], "law_articles");
    assert_eq!(error.details["expectedType"], "view");
    assert_eq!(error.details["foundType"], "table");
}

#[test]
fn system_status_rejects_runtime_without_content_table() {
    let fixture = empty_fixture();
    let legal = Connection::open(&fixture.legal_path).expect("open archive fixture");
    legal
        .execute_batch(
            "
            ALTER TABLE law_articles RENAME TO law_article_rows;
            CREATE VIEW law_articles AS SELECT * FROM law_article_rows;
            INSERT INTO database_metadata (key, value, updated_at)
            VALUES ('runtime_schema_version', '1', CURRENT_TIMESTAMP);
            PRAGMA user_version = 1;
            ",
        )
        .expect("shape incomplete runtime fixture");
    drop(legal);

    let status = fixture
        .services
        .system_status()
        .expect("incompatible status");
    assert_eq!(status.status, "degraded");
    let error = status
        .legal_database
        .error
        .expect("missing runtime content table is reported");
    assert_eq!(error.code, "legal_database_incompatible");
    assert_eq!(error.details["relation"], "law_article_contents");
    assert_eq!(error.details["expectedType"], "table");
    assert!(error.details["foundType"].is_null());
}

#[test]
fn system_status_rejects_runtime_without_article_rows_table() {
    let fixture = empty_fixture();
    let legal = Connection::open(&fixture.legal_path).expect("open archive fixture");
    legal
        .execute_batch(
            "
            ALTER TABLE law_articles RENAME TO article_rows_backing;
            CREATE VIEW law_articles AS SELECT * FROM article_rows_backing;
            CREATE TABLE law_article_contents (
              content_id INTEGER PRIMARY KEY,
              content TEXT NOT NULL
            );
            INSERT INTO database_metadata (key, value, updated_at)
            VALUES ('runtime_schema_version', '1', CURRENT_TIMESTAMP);
            PRAGMA user_version = 1;
            ",
        )
        .expect("shape runtime fixture without canonical rows table");
    drop(legal);

    let status = fixture
        .services
        .system_status()
        .expect("incompatible status");
    assert_eq!(status.status, "degraded");
    let error = status
        .legal_database
        .error
        .expect("missing runtime rows table is reported");
    assert_eq!(error.code, "legal_database_incompatible");
    assert_eq!(error.details["relation"], "law_article_rows");
    assert_eq!(error.details["expectedType"], "table");
    assert!(error.details["foundType"].is_null());
}

#[test]
fn system_status_rejects_views_for_required_archive_tables() {
    for table in [
        "law_articles",
        "law_documents",
        "law_versions",
        "law_relations",
        "issuing_authorities",
        "law_aliases",
        "citation_metadata",
        "legal_topics",
        "article_topics",
    ] {
        let fixture = empty_fixture();
        let legal = Connection::open(&fixture.legal_path).expect("open archive fixture");
        let backing_table = format!("{table}_backing");
        legal
            .execute_batch(&format!(
                "ALTER TABLE {table} RENAME TO {backing_table};\n\
                 CREATE VIEW {table} AS SELECT * FROM {backing_table};"
            ))
            .expect("replace required table with a view");
        drop(legal);

        let status = fixture.services.system_status().expect("archive status");
        assert_eq!(status.status, "degraded", "relation {table}");
        let error = status
            .legal_database
            .error
            .expect("wrong relation type is reported");
        assert_eq!(error.code, "legal_database_incompatible", "{table}");
        assert_eq!(error.details["relation"], table, "{table}");
        assert_eq!(error.details["expectedType"], "table", "{table}");
        assert_eq!(error.details["foundType"], "view", "{table}");
    }
}

#[test]
fn legal_search_scopes_articles_to_an_explicit_law_alias() {
    let fixture = fixture();
    let search = fixture
        .services
        .legal_search(LegalSearchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: "民法典 合同".to_owned(),
            document_id: None,
            case_date: None,
            limit: Some(10),
        })
        .expect("explicit Civil Code search");

    assert!(!search.articles.is_empty());
    assert!(search
        .articles
        .iter()
        .all(|article| article.document_id == "civil-code"));
}

#[test]
fn citation_validation_is_source_bounded_and_explicitly_non_semantic() {
    let fixture = fixture();
    let source = "law:civil-code:civil-code-v1:art:465";
    let response = fixture
        .services
        .citation_validate(CitationValidateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            answer: format!("依法成立的合同受保护。[SRC:{source}]"),
            allowed_source_ids: vec![source.to_owned()],
            case_date: Some("2026-01-01".to_owned()),
            include_expired: false,
        })
        .expect("citation validation");
    assert_eq!(response.report.valid_count, 1);
    assert!(!response.report.semantic_support_verified);
    assert!(response
        .warnings
        .contains(&"semantic_support_not_verified".to_owned()));
}

#[test]
fn historical_article_search_and_citation_follow_case_date_boundaries() {
    let fixture = fixture();
    let historical = fixture
        .services
        .legal_search(LegalSearchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: "违约责任".to_owned(),
            document_id: None,
            case_date: Some("2020-06-01".to_owned()),
            limit: Some(10),
        })
        .expect("historical search");
    assert!(historical
        .articles
        .iter()
        .any(|article| article.article_id == "contract-law-107"));
    let current = fixture
        .services
        .legal_search(LegalSearchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: "违约责任".to_owned(),
            document_id: None,
            case_date: Some("2026-01-01".to_owned()),
            limit: Some(10),
        })
        .expect("current search");
    assert!(!current
        .articles
        .iter()
        .any(|article| article.article_id == "contract-law-107"));

    let source = "law:old-contract-law:contract-law-v1:art:107";
    let valid = fixture
        .services
        .citation_validate(CitationValidateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            answer: format!("旧法违约责任。[SRC:{source}]"),
            allowed_source_ids: vec![source.to_owned()],
            case_date: Some("2020-06-01".to_owned()),
            include_expired: false,
        })
        .expect("historical citation");
    assert_eq!(valid.report.valid_count, 1);
    let invalid = fixture
        .services
        .citation_validate(CitationValidateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            answer: format!("当前仍适用旧法。[SRC:{source}]"),
            allowed_source_ids: vec![source.to_owned()],
            case_date: Some("2026-01-01".to_owned()),
            include_expired: false,
        })
        .expect("out-of-range citation report");
    assert_eq!(invalid.report.invalid_count, 1);
}

#[test]
fn proposal_is_stateless_and_apply_is_revision_guarded_audited_and_idempotent() {
    let fixture = fixture();
    let before = current_revision(&fixture);
    let connection = database::open_user_database(&fixture.user_path).expect("open user db");
    let fact_count_before: i64 = connection
        .query_row("SELECT COUNT(*) FROM case_facts", [], |row| row.get(0))
        .expect("count facts");
    let audit_count_before: i64 = connection
        .query_row("SELECT COUNT(*) FROM operation_audit", [], |row| row.get(0))
        .expect("count audits");
    drop(connection);

    let proposal = fixture
        .services
        .case_propose_patch(proposal_request(before.clone(), "fact-added"))
        .expect("propose patch");
    let canonical: CanonicalCaseProposal =
        serde_json::from_str(&proposal.canonical_proposal).expect("canonical proposal");
    assert_eq!(canonical.base_revision, before);

    let connection = database::open_user_database(&fixture.user_path).expect("open user db");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM case_facts", [], |row| row
                .get::<_, i64>(0))
            .expect("count facts"),
        fact_count_before
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM operation_audit", [], |row| row
                .get::<_, i64>(0))
            .expect("count audits"),
        audit_count_before
    );
    drop(connection);

    let apply_request = CaseApplyPatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-1".to_owned(),
        canonical_proposal: proposal.canonical_proposal,
        proposal_hash: proposal.proposal_hash,
        expected_revision: before,
        confirmed: true,
        idempotency_key: "apply-case-1-fact-added".to_owned(),
    };
    let applied = fixture
        .services
        .case_apply_patch(apply_request.clone())
        .expect("apply patch");
    assert!(applied.applied);
    assert!(!applied.replayed);
    assert_ne!(applied.previous_revision, applied.revision);
    let replay = fixture
        .services
        .case_apply_patch(apply_request)
        .expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(replay.audit_id, applied.audit_id);

    let connection = database::open_user_database(&fixture.user_path).expect("open user db");
    let status: String = connection
        .query_row(
            "SELECT status FROM operation_audit WHERE audit_id = ?1",
            [&applied.audit_id],
            |row| row.get(0),
        )
        .expect("audit status");
    assert_eq!(status, "succeeded");
}

#[test]
fn confirmed_case_business_fields_do_not_expose_internal_trace_metadata() {
    const ATTACHMENT_ID: &str = "attachment:private-transfer-identifier";
    const CONTENT_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let fixture = fixture();
    let connection = database::open_user_database(&fixture.user_path).expect("open user db");
    assert!(matches!(
        database::insert_attachment(
            &connection,
            &database::NewAttachmentRow {
                attachment_id: ATTACHMENT_ID.to_owned(),
                project_id: None,
                original_name: "reviewed-contract.txt".to_owned(),
                extension: "txt".to_owned(),
                detected_mime: "text/plain".to_owned(),
                sha256: CONTENT_SHA256.to_owned(),
                size_bytes: 8,
                content_blob: b"reviewed".to_vec(),
                extraction_status: "succeeded".to_owned(),
                extracted_text: Some("reviewed".to_owned()),
                segments_json: "[]".to_owned(),
                error_code: None,
            },
        )
        .expect("insert transferable attachment"),
        database::AttachmentInsertResult::Inserted(_)
    ));
    database::upsert_evidence_item(
        &connection,
        &database::EvidenceItemRow {
            evidence_id: "evidence-existing-public-number".to_owned(),
            project_id: "case-1".to_owned(),
            evidence_number: "1".to_owned(),
            title: "既有证据".to_owned(),
            source: "当事人提供".to_owned(),
            formed_on: None,
            summary: "用于验证新增证据编号不会冲突。".to_owned(),
            storage_reference: String::new(),
            confirmation_status: "confirmed".to_owned(),
        },
    )
    .expect("insert existing public evidence number");
    drop(connection);

    let before = current_revision(&fixture);
    let mut changes = empty_changes();
    changes.facts.push(FactAddition {
        id: "fact-public-boundary".to_owned(),
        statement: "双方已经签订书面买卖合同。".to_owned(),
        occurred_on: Some("2026-01-02".to_owned()),
        source_refs: vec!["case-1".to_owned()],
    });
    changes.evidence.push(EvidenceAddition {
        id: "evidence-public-boundary".to_owned(),
        title: "买卖合同".to_owned(),
        summary: "证明双方买卖合同关系成立。".to_owned(),
        proves_fact_ids: vec!["fact-public-boundary".to_owned()],
        source_refs: vec![ATTACHMENT_ID.to_owned()],
    });
    changes.attachment_transfers.push(AttachmentTransfer {
        attachment_id: ATTACHMENT_ID.to_owned(),
        title: "买卖合同".to_owned(),
    });
    let proposal = fixture
        .services
        .case_propose_patch(CaseProposePatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            base_revision: before.clone(),
            changes,
            project_bootstrap: None,
            material_imports: Vec::new(),
        })
        .expect("propose public-boundary case changes");
    let applied = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash.clone(),
            expected_revision: before,
            confirmed: true,
            idempotency_key: "apply-public-boundary-case-changes".to_owned(),
        })
        .expect("apply public-boundary case changes");

    let state = fixture
        .services
        .case_get_state(CaseGetStateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            page: None,
            page_size: None,
        })
        .expect("read applied case state");
    let fact = state
        .workspace
        .facts
        .iter()
        .find(|fact| fact.fact_id == "fact-public-boundary")
        .expect("applied fact");
    let evidence = state
        .workspace
        .evidence
        .iter()
        .find(|evidence| evidence.evidence_id == "evidence-public-boundary")
        .expect("applied evidence");
    let file = state
        .workspace
        .files
        .iter()
        .find(|file| file.title == "买卖合同")
        .expect("transferred case file");

    assert_eq!(fact.source, "经确认的案件信息");
    assert_eq!(evidence.source, "经确认的案件信息");
    assert_eq!(evidence.evidence_number, "2");
    assert_eq!(file.summary, "经确认纳入本案的材料。");
    let public_business_fields = format!(
        "{}\n{}\n{}\n{}",
        fact.source, evidence.source, evidence.evidence_number, file.summary
    );
    for forbidden in [
        proposal.proposal_hash.as_str(),
        ATTACHMENT_ID,
        CONTENT_SHA256,
        "proposalHash",
        "sourceRefs",
        "attachmentId",
        "sha256",
        "legal_services_case_proposal",
        "service-",
        "{",
        "}",
    ] {
        assert!(
            !public_business_fields.contains(forbidden),
            "public case field leaked internal trace data: {forbidden}"
        );
    }

    let connection =
        database::open_user_database_read_only(&fixture.user_path).expect("inspect internal audit");
    let audit_details: String = connection
        .query_row(
            "SELECT details_json FROM operation_audit WHERE audit_id = ?1",
            [&applied.audit_id],
            |row| row.get(0),
        )
        .expect("completed audit details");
    assert!(audit_details.contains(&proposal.proposal_hash));
}

#[test]
fn stale_or_tampered_case_proposals_never_write() {
    let fixture = fixture();
    let before = current_revision(&fixture);
    let proposal = fixture
        .services
        .case_propose_patch(proposal_request(before.clone(), "fact-stale"))
        .expect("proposal");
    let connection = database::open_user_database(&fixture.user_path).expect("open user db");
    database::upsert_case_project(
        &connection,
        &CaseProjectRow {
            project_id: "case-1".to_owned(),
            title: "合同争议（已更新）".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: Some("2026-01-01".to_owned()),
            summary: "revision changed".to_owned(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .expect("mutate case");
    drop(connection);
    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal.clone(),
            proposal_hash: proposal.proposal_hash.clone(),
            expected_revision: before.clone(),
            confirmed: true,
            idempotency_key: "stale-proposal".to_owned(),
        })
        .expect_err("stale proposal must fail");
    assert_eq!(error.code, "revision_conflict");

    let mut tampered = proposal.canonical_proposal;
    tampered.push(' ');
    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: tampered,
            proposal_hash: proposal.proposal_hash,
            expected_revision: before,
            confirmed: true,
            idempotency_key: "tampered-proposal".to_owned(),
        })
        .expect_err("tampered proposal must fail");
    assert_eq!(error.code, "proposal_hash_mismatch");
}

#[test]
fn proposal_rejects_legal_dataset_drift_before_any_case_write() {
    let fixture = fixture();
    let before = current_revision(&fixture);
    let proposal = fixture
        .services
        .case_propose_patch(proposal_request(before.clone(), "fact-dataset-drift"))
        .expect("proposal");
    let legal = Connection::open(&fixture.legal_path).expect("open legal database for mutation");
    legal
        .execute(
            "UPDATE database_metadata SET value = 'legal-services-fixture-v2' WHERE key = 'dataset_version'",
            [],
        )
        .expect("change dataset identity");
    drop(legal);

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: before.clone(),
            confirmed: true,
            idempotency_key: "dataset-drift".to_owned(),
        })
        .expect_err("dataset drift must invalidate review");
    assert_eq!(error.code, "proposal_snapshot_drift");
    assert_eq!(current_revision(&fixture), before);
}

#[test]
fn proposal_rejects_referenced_legal_source_content_drift() {
    let fixture = fixture();
    let before = current_revision(&fixture);
    let source_id = "law:civil-code:civil-code-v1:art:465";
    let mut request = proposal_request(before.clone(), "fact-source-drift");
    request.changes.legal_basis.push(LegalBasisAddition {
        id: "basis-source-drift".to_owned(),
        issue_ids: Vec::new(),
        source_ref: source_id.to_owned(),
        marker: format!("[SRC:{source_id}]"),
        citation: "《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）".to_owned(),
        proposition: "依法成立的合同受法律保护。".to_owned(),
    });
    let proposal = fixture
        .services
        .case_propose_patch(request)
        .expect("proposal with legal source snapshot");
    let legal = Connection::open(&fixture.legal_path).expect("open legal database for mutation");
    legal
        .execute(
            "UPDATE law_articles SET content = content || ' changed after review' WHERE id = 'civil-code-465'",
            [],
        )
        .expect("change referenced legal source");
    drop(legal);

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: before.clone(),
            confirmed: true,
            idempotency_key: "legal-source-drift".to_owned(),
        })
        .expect_err("legal source drift must invalidate review");
    assert_eq!(error.code, "proposal_snapshot_drift");
    assert_eq!(current_revision(&fixture), before);
}

#[test]
fn proposal_rejects_artifact_version_and_content_drift() {
    let fixture = fixture();
    let user = database::open_user_database(&fixture.user_path).expect("open user database");
    database::create_artifact(
        &user,
        &database::NewArtifactRow {
            artifact_id: "artifact-transfer".to_owned(),
            conversation_id: None,
            project_id: None,
            kind: "document".to_owned(),
            title: "Reviewed memo".to_owned(),
            status: "draft".to_owned(),
        },
        &database::NewArtifactVersionRow {
            version_id: "artifact-transfer-v1".to_owned(),
            artifact_id: "artifact-transfer".to_owned(),
            content_json: r#"{"schemaVersion":1,"body":"reviewed"}"#.to_owned(),
            rendered_text: "reviewed".to_owned(),
            source_refs_json: "[]".to_owned(),
            citation_report_json: "{}".to_owned(),
            provider_snapshot_json: "{}".to_owned(),
        },
    )
    .expect("create artifact");
    drop(user);
    let before = current_revision(&fixture);
    let mut request = proposal_request(before.clone(), "fact-artifact-drift");
    request.changes.artifact_transfers.push(ArtifactTransfer {
        artifact_id: "artifact-transfer".to_owned(),
        title: "Reviewed memo".to_owned(),
    });
    let proposal = fixture
        .services
        .case_propose_patch(request)
        .expect("proposal with artifact snapshot");

    let user = database::open_user_database(&fixture.user_path).expect("reopen user database");
    let update = database::create_artifact_version(
        &user,
        &database::NewArtifactVersionRow {
            version_id: "artifact-transfer-v2".to_owned(),
            artifact_id: "artifact-transfer".to_owned(),
            content_json: r#"{"schemaVersion":1,"body":"changed"}"#.to_owned(),
            rendered_text: "changed".to_owned(),
            source_refs_json: "[]".to_owned(),
            citation_report_json: "{}".to_owned(),
            provider_snapshot_json: "{}".to_owned(),
        },
        1,
    )
    .expect("append artifact version");
    assert!(matches!(
        update,
        database::ArtifactVersionCreateResult::Created(_)
    ));
    drop(user);

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: before.clone(),
            confirmed: true,
            idempotency_key: "artifact-drift".to_owned(),
        })
        .expect_err("artifact drift must invalidate review");
    assert_eq!(error.code, "proposal_snapshot_drift");
    assert_eq!(current_revision(&fixture), before);
}

#[test]
fn proposal_rejects_attachment_content_or_extraction_drift() {
    let fixture = fixture();
    let user = database::open_user_database(&fixture.user_path).expect("open user database");
    assert!(matches!(
        database::insert_attachment(
            &user,
            &database::NewAttachmentRow {
                attachment_id: "attachment:transfer-drift".to_owned(),
                project_id: None,
                original_name: "reviewed.txt".to_owned(),
                extension: "txt".to_owned(),
                detected_mime: "text/plain".to_owned(),
                sha256: "a".repeat(64),
                size_bytes: 8,
                content_blob: b"reviewed".to_vec(),
                extraction_status: "pending".to_owned(),
                extracted_text: None,
                segments_json: "[]".to_owned(),
                error_code: None,
            },
        )
        .expect("insert attachment"),
        database::AttachmentInsertResult::Inserted(_)
    ));
    drop(user);
    let before = current_revision(&fixture);
    let mut request = proposal_request(before.clone(), "fact-attachment-drift");
    request
        .changes
        .attachment_transfers
        .push(AttachmentTransfer {
            attachment_id: "attachment:transfer-drift".to_owned(),
            title: "Reviewed attachment".to_owned(),
        });
    let proposal = fixture
        .services
        .case_propose_patch(request)
        .expect("proposal with attachment snapshot");

    let user = database::open_user_database(&fixture.user_path).expect("reopen user database");
    assert!(database::update_attachment_extraction(
        &user,
        "attachment:transfer-drift",
        "pending",
        "succeeded",
        Some("changed extraction after review"),
        r#"[{"index":0,"text":"changed"}]"#,
        None,
    )
    .expect("update attachment extraction"));
    drop(user);

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: before.clone(),
            confirmed: true,
            idempotency_key: "attachment-drift".to_owned(),
        })
        .expect_err("attachment drift must invalidate review");
    assert_eq!(error.code, "proposal_snapshot_drift");
    assert_eq!(current_revision(&fixture), before);
}

#[test]
fn document_generation_and_markdown_docx_exports_are_separate_and_audited() {
    let fixture = fixture();
    let generated = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: None,
        })
        .expect("generate document");
    assert!(!generated.document.markdown.is_empty());
    assert!(!fixture.output_root.join("reports/timeline.md").exists());

    let base_export = |format, path: &str, key: &str| DocumentExportRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-1".to_owned(),
        template_id: DocumentTemplateId::FactTimeline,
        model_draft: None,
        expected_revision: generated.case_revision.clone(),
        generation_hash: generated.generation_hash.clone(),
        relative_path: path.to_owned(),
        format,
        overwrite: false,
        confirmed: true,
        idempotency_key: key.to_owned(),
    };
    let markdown_request = base_export(
        DocumentExportFormat::Markdown,
        "reports/timeline.md",
        "export-markdown",
    );
    let markdown = fixture
        .services
        .document_export(markdown_request.clone())
        .expect("markdown export");
    assert!(Path::new(&markdown.export_path).is_file());
    assert_eq!(
        fs::read(&markdown.export_path).expect("read markdown"),
        generated.document.markdown.as_bytes()
    );
    assert!(
        fixture
            .services
            .document_export(markdown_request)
            .expect("replay export")
            .replayed
    );
    let user = database::open_user_database(&fixture.user_path).expect("inspect export audit");
    let details_json: String = user
        .query_row(
            "SELECT details_json FROM operation_audit WHERE audit_id = ?1",
            [&markdown.audit_id],
            |row| row.get(0),
        )
        .expect("completed audit details");
    let details: serde_json::Value = serde_json::from_str(&details_json).expect("audit JSON");
    assert!(details["exportPath"].is_null());
    assert_eq!(details["relativeExportPath"], "reports/timeline.md");
    assert_eq!(details["outputRootId"].as_str().map(str::len), Some(64));
    let stored_export: String = user
        .query_row(
            "SELECT export_path FROM document_generation_records WHERE record_id = ?1",
            [&markdown.record_id],
            |row| row.get(0),
        )
        .expect("generation record");
    let stored_export: serde_json::Value =
        serde_json::from_str(&stored_export).expect("root-relative export reference");
    assert_eq!(stored_export["relativePath"], "reports/timeline.md");
    assert!(!stored_export
        .to_string()
        .contains(&fixture.output_root.to_string_lossy().to_string()));
    drop(user);

    let docx = fixture
        .services
        .document_export(base_export(
            DocumentExportFormat::Docx,
            "reports/timeline.docx",
            "export-docx",
        ))
        .expect("DOCX export");
    let bytes = fs::read(&docx.export_path).expect("read DOCX");
    assert!(bytes.starts_with(b"PK"));
    assert_eq!(docx.sha256.len(), 64);
}

#[test]
fn document_generation_normalizes_a_legacy_single_paragraph_basis_from_the_legal_library() {
    let fixture = fixture();
    let user = database::open_user_database(&fixture.user_path).expect("open user fixture");
    for (party_id, name, role) in [
        ("party-plaintiff", "甲公司", "plaintiff"),
        ("party-defendant", "乙公司", "defendant"),
    ] {
        database::upsert_case_party(
            &user,
            &database::CasePartyRow {
                party_id: party_id.to_owned(),
                project_id: "case-1".to_owned(),
                name: name.to_owned(),
                normalized_name: name.to_owned(),
                role: role.to_owned(),
                contact: String::new(),
                notes: String::new(),
            },
        )
        .expect("insert party");
    }
    database::upsert_legal_issue(
        &user,
        &database::LegalIssueRow {
            issue_id: "issue-performance".to_owned(),
            project_id: "case-1".to_owned(),
            title: "合同履行责任".to_owned(),
            description: "审查合同是否依法成立并受法律保护。".to_owned(),
            claim: "请求依法确认合同效力并判令继续履行。".to_owned(),
            status: "open".to_owned(),
            confirmation_status: "confirmed".to_owned(),
        },
    )
    .expect("insert issue");
    database::upsert_legal_basis(
        &user,
        &database::LegalBasisRow {
            basis_id: "basis-legacy-465".to_owned(),
            project_id: "case-1".to_owned(),
            issue_id: Some("issue-performance".to_owned()),
            source_id: "law:civil-code:civil-code-v1:art:465".to_owned(),
            status: "valid".to_owned(),
            invalid_reason: None,
            case_date: Some("2026-01-02".to_owned()),
            article_id: "civil-code-465".to_owned(),
            document_id: "civil-code".to_owned(),
            version_id: "civil-code-v1".to_owned(),
            document_title: "中华人民共和国民法典".to_owned(),
            version_label: "2021年施行版本".to_owned(),
            article_number: "第四百六十五条".to_owned(),
            article_title: Some("依法成立合同的效力".to_owned()),
            canonical_label: "《中华人民共和国民法典》第四百六十五条".to_owned(),
            effective_from: "2021-01-01".to_owned(),
            effective_to: None,
            version_status: "in_force".to_owned(),
            excerpt: "依法成立的合同，受法律保护。".to_owned(),
            note: String::new(),
            created_at: String::new(),
        },
    )
    .expect("insert legacy legal basis");
    drop(user);

    let generated = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::Complaint,
            model_draft: None,
        })
        .expect("legacy basis generates after authoritative normalization");
    assert_eq!(
        generated.document.citations[0].locator,
        "第四百六十五条第一款"
    );
    assert!(generated
        .document
        .markdown
        .contains("| 法条 | 《中华人民共和国民法典》 | 第四百六十五条第一款 | 2021年起施行 |"));
}

#[test]
fn delivered_legal_document_hides_internal_provenance_but_keeps_public_citations() {
    const SOURCE_ID: &str = "law:internal-source-id-never-deliver";
    const DOCUMENT_ID: &str = "internal-document-id-never-deliver";
    const VERSION_ID: &str = "internal-version-id-never-deliver";
    const ARTICLE_ID: &str = "internal-article-id-never-deliver";
    const STORAGE_REFERENCE: &str =
        r"C:\Users\internal\AppData\Local\Lawyer-Assistance\materials\secret-contract.pdf";

    let fixture = fixture();
    let user = database::open_user_database(&fixture.user_path).expect("open user fixture");
    database::upsert_case_file(
        &user,
        &database::CaseFileRow {
            file_id: "internal-file-id-never-deliver".to_owned(),
            project_id: "case-1".to_owned(),
            title: "买卖合同".to_owned(),
            file_type: "application/pdf".to_owned(),
            storage_reference: STORAGE_REFERENCE.to_owned(),
            summary: "双方签订的买卖合同。".to_owned(),
            created_at: String::new(),
        },
    )
    .expect("insert case file with internal storage reference");
    for (party_id, name, role) in [
        ("internal-party-plaintiff", "甲公司", "plaintiff"),
        ("internal-party-defendant", "乙公司", "defendant"),
    ] {
        database::upsert_case_party(
            &user,
            &database::CasePartyRow {
                party_id: party_id.to_owned(),
                project_id: "case-1".to_owned(),
                name: name.to_owned(),
                normalized_name: name.to_owned(),
                role: role.to_owned(),
                contact: String::new(),
                notes: String::new(),
            },
        )
        .expect("insert case party");
    }
    database::upsert_evidence_item(
        &user,
        &database::EvidenceItemRow {
            evidence_id: "internal-evidence-id-never-deliver".to_owned(),
            project_id: "case-1".to_owned(),
            evidence_number: "1".to_owned(),
            title: "买卖合同".to_owned(),
            source: "原告提供".to_owned(),
            formed_on: Some("2025-12-01".to_owned()),
            summary: "证明双方买卖合同关系成立并生效。".to_owned(),
            storage_reference: STORAGE_REFERENCE.to_owned(),
            confirmation_status: "confirmed".to_owned(),
        },
    )
    .expect("insert evidence with internal storage reference");
    database::upsert_legal_issue(
        &user,
        &database::LegalIssueRow {
            issue_id: "internal-issue-id-never-deliver".to_owned(),
            project_id: "case-1".to_owned(),
            title: "继续履行与违约责任".to_owned(),
            description: "被告未按约履行合同义务。".to_owned(),
            claim: "请求判令被告继续履行合同并承担违约责任。".to_owned(),
            status: "open".to_owned(),
            confirmation_status: "confirmed".to_owned(),
        },
    )
    .expect("insert legal issue");
    database::upsert_legal_basis(
        &user,
        &database::LegalBasisRow {
            basis_id: "internal-basis-id-never-deliver".to_owned(),
            project_id: "case-1".to_owned(),
            issue_id: Some("internal-issue-id-never-deliver".to_owned()),
            source_id: SOURCE_ID.to_owned(),
            status: "valid".to_owned(),
            invalid_reason: None,
            case_date: Some("2026-01-02".to_owned()),
            article_id: ARTICLE_ID.to_owned(),
            document_id: DOCUMENT_ID.to_owned(),
            version_id: VERSION_ID.to_owned(),
            document_title: "中华人民共和国民法典".to_owned(),
            version_label: "2021年施行版本".to_owned(),
            article_number: "第四百六十五条".to_owned(),
            article_title: Some("依法成立合同的效力".to_owned()),
            canonical_label: "《中华人民共和国民法典》第四百六十五条第一款".to_owned(),
            effective_from: "2021-01-01".to_owned(),
            effective_to: None,
            version_status: "in_force".to_owned(),
            excerpt: "依法成立的合同，受法律保护。".to_owned(),
            note: "仅供内部追溯，不得进入交付文书。".to_owned(),
            created_at: String::new(),
        },
    )
    .expect("insert legal basis with internal provenance");
    drop(user);

    let generated = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::Complaint,
            model_draft: None,
        })
        .expect("generate reviewed legal document");

    let citation = generated
        .document
        .citations
        .first()
        .expect("internal citation metadata is retained for audit");
    assert_eq!(citation.source_id, SOURCE_ID);
    assert_eq!(citation.document_id, DOCUMENT_ID);
    assert_eq!(citation.version_id, VERSION_ID);
    assert_eq!(citation.article_id, ARTICLE_ID);

    let assert_public_delivery = |delivery: &str| {
        for forbidden in [
            SOURCE_ID,
            DOCUMENT_ID,
            VERSION_ID,
            ARTICLE_ID,
            STORAGE_REFERENCE,
            "internal-file-id-never-deliver",
            "internal-evidence-id-never-deliver",
            "internal-issue-id-never-deliver",
            "internal-basis-id-never-deliver",
            "source_id",
            "document_id",
            "version_id",
            "article_id",
            "storage_reference",
            "来源标识",
            "来源映射",
            "本地路径",
            "内部追溯",
            "[SRC:",
        ] {
            assert!(
                !delivery.contains(forbidden),
                "public delivery leaked internal value or label: {forbidden}"
            );
        }
        assert!(delivery.contains("《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）"));
        assert!(delivery.contains("## 法律依据与案例引用表"));
        assert!(delivery.contains(
            "| 法条 | 《中华人民共和国民法典》 | 第四百六十五条第一款 | 2021年起施行 | 依法成立的合同，受法律保护。 |"
        ));
        let reference_table = delivery
            .find("## 法律依据与案例引用表")
            .expect("public reference table");
        assert!(
            !delivery[reference_table + "## 法律依据与案例引用表".len()..].contains("\n## "),
            "the legal authority and case reference table must be the final section"
        );
    };
    assert_public_delivery(&generated.document.markdown);

    let exported = fixture
        .services
        .document_export(DocumentExportRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::Complaint,
            model_draft: None,
            expected_revision: generated.case_revision.clone(),
            generation_hash: generated.generation_hash.clone(),
            relative_path: "reports/public-complaint.md".to_owned(),
            format: DocumentExportFormat::Markdown,
            overwrite: false,
            confirmed: true,
            idempotency_key: "public-complaint-no-internal-provenance".to_owned(),
        })
        .expect("export reviewed public document");
    let delivered = fs::read_to_string(exported.export_path).expect("read exported document");
    assert_public_delivery(&delivered);

    let docx = fixture
        .services
        .document_export(DocumentExportRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::Complaint,
            model_draft: None,
            expected_revision: generated.case_revision,
            generation_hash: generated.generation_hash,
            relative_path: "reports/public-complaint.docx".to_owned(),
            format: DocumentExportFormat::Docx,
            overwrite: false,
            confirmed: true,
            idempotency_key: "public-complaint-docx-no-internal-provenance".to_owned(),
        })
        .expect("export reviewed public DOCX document");
    let docx_bytes = fs::read(docx.export_path).expect("read exported DOCX document");
    let docx_payload = String::from_utf8_lossy(&docx_bytes);
    for forbidden in [
        SOURCE_ID,
        DOCUMENT_ID,
        VERSION_ID,
        ARTICLE_ID,
        STORAGE_REFERENCE,
        "internal-file-id-never-deliver",
        "internal-evidence-id-never-deliver",
        "internal-issue-id-never-deliver",
        "internal-basis-id-never-deliver",
        "Confirmed case source",
        "Structured section",
        "Generated from confirmed local case state",
        "[SRC:",
    ] {
        assert!(
            !docx_payload.contains(forbidden),
            "public DOCX leaked an internal value or process label: {forbidden}"
        );
    }
    assert!(docx_payload.contains("《中华人民共和国民法典》第四百六十五条第一款（2021年起施行）"));
    assert_eq!(
        docx_payload.matches("法律依据与案例引用表").count(),
        1,
        "the public DOCX must contain exactly one final citation table"
    );
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(&docx_bytes)).expect("open public DOCX archive");
    let mut document_xml = String::new();
    archive
        .by_name("word/document.xml")
        .expect("public DOCX document XML")
        .read_to_string(&mut document_xml)
        .expect("read public DOCX document XML");
    let reference_heading = document_xml
        .find("法律依据与案例引用表")
        .expect("public citation table heading in document XML");
    let final_heading_style = document_xml
        .rfind("<w:sz w:val=\"28\"/>")
        .expect("at least one first-level heading in document XML");
    assert!(
        final_heading_style < reference_heading,
        "the citation table must be the final first-level section"
    );
    let reference_tail = &document_xml[reference_heading..];
    let table_end = reference_tail
        .find("</w:tbl>")
        .expect("complete public citation table")
        + "</w:tbl>".len();
    assert!(
        !reference_tail[table_end..].contains("<w:p>"),
        "the public DOCX must not append another paragraph after the citation table"
    );
}

#[test]
fn hardlinked_user_database_is_rejected_by_read_and_write_services() {
    let fixture = fixture();
    let hardlink = fixture._root.path().join("hardlinked-user.sqlite");
    fs::hard_link(&fixture.user_path, &hardlink).expect("create hard link");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: fixture.legal_path.clone(),
        user_database_path: hardlink,
        allowed_file_roots: Vec::new(),
        allowed_output_root: fixture.output_root.clone(),
    })
    .expect("construct service");
    let status = services.system_status().expect("status");
    assert_eq!(
        status.user_database.error.expect("hardlink error").code,
        "filesystem_hardlink_rejected"
    );
    let error = services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: "{}".to_owned(),
            proposal_hash: "0".repeat(64),
            expected_revision: "0".repeat(64),
            confirmed: true,
            idempotency_key: "hardlink-write".to_owned(),
        })
        .expect_err("write open rejects hardlink before request processing");
    assert_eq!(error.code, "filesystem_hardlink_rejected");
}

#[test]
fn export_requires_confirmation_and_rejects_escape_and_overwrite() {
    let fixture = fixture();
    let generated = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: None,
        })
        .expect("generate document");
    let request = |relative_path: &str, confirmed: bool, key: &str| DocumentExportRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-1".to_owned(),
        template_id: DocumentTemplateId::FactTimeline,
        model_draft: None,
        expected_revision: generated.case_revision.clone(),
        generation_hash: generated.generation_hash.clone(),
        relative_path: relative_path.to_owned(),
        format: DocumentExportFormat::Markdown,
        overwrite: false,
        confirmed,
        idempotency_key: key.to_owned(),
    };
    assert_eq!(
        fixture
            .services
            .document_export(request("reports/unconfirmed.md", false, "unconfirmed"))
            .expect_err("confirmation required")
            .code,
        "confirmation_required"
    );
    assert_eq!(
        fixture
            .services
            .document_export(request("../escape.md", true, "escape"))
            .expect_err("escape rejected")
            .code,
        "output_path_rejected"
    );
    fixture
        .services
        .document_export(request("reports/existing.md", true, "first"))
        .expect("first export");
    assert_eq!(
        fixture
            .services
            .document_export(request("reports/existing.md", true, "second"))
            .expect_err("overwrite disabled")
            .code,
        "output_exists"
    );
}

#[test]
fn confirmed_overwrite_replaces_an_existing_file_atomically() {
    let fixture = fixture();
    let first = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: None,
        })
        .expect("first generation");
    let request = |generated: &legal_services::DocumentGenerateResponse,
                   model_draft: Option<String>,
                   overwrite: bool,
                   key: &str| DocumentExportRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-1".to_owned(),
        template_id: DocumentTemplateId::FactTimeline,
        model_draft,
        expected_revision: generated.case_revision.clone(),
        generation_hash: generated.generation_hash.clone(),
        relative_path: "reports/atomic.md".to_owned(),
        format: DocumentExportFormat::Markdown,
        overwrite,
        confirmed: true,
        idempotency_key: key.to_owned(),
    };
    let first_export = fixture
        .services
        .document_export(request(&first, None, false, "atomic-first"))
        .expect("first export");
    let first_bytes = fs::read(&first_export.export_path).expect("first bytes");

    let second_draft = Some("律师复核后的补充说明。".to_owned());
    let second = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: second_draft.clone(),
        })
        .expect("second generation");
    fixture
        .services
        .document_export(request(
            &second,
            second_draft.clone(),
            true,
            "atomic-second",
        ))
        .expect("confirmed overwrite");
    let second_bytes = fs::read(&first_export.export_path).expect("second bytes");
    assert_ne!(first_bytes, second_bytes);
    assert!(String::from_utf8_lossy(&second_bytes).contains("律师复核后的补充说明"));
}

#[test]
fn symlinked_output_parent_cannot_escape_configured_root() {
    let fixture = fixture();
    let outside = fixture._root.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    let link = fixture.output_root.join("linked");
    if create_directory_symlink(&outside, &link).is_err() {
        // Windows without Developer Mode may prohibit symlink creation. The
        // same test runs unconditionally on Unix CI where creation is allowed.
        return;
    }
    let generated = fixture
        .services
        .document_generate(DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: None,
        })
        .expect("generation");
    let error = fixture
        .services
        .document_export(DocumentExportRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            template_id: DocumentTemplateId::FactTimeline,
            model_draft: None,
            expected_revision: generated.case_revision,
            generation_hash: generated.generation_hash,
            relative_path: "linked/escape.md".to_owned(),
            format: DocumentExportFormat::Markdown,
            overwrite: false,
            confirmed: true,
            idempotency_key: "symlink-escape".to_owned(),
        })
        .expect_err("symlink escape rejected");
    assert_eq!(error.code, "output_path_rejected");
    assert!(!outside.join("escape.md").exists());
}

#[cfg(unix)]
fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    use std::{
        io,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    match std::os::windows::fs::symlink_dir(target, link) {
        Ok(()) => Ok(()),
        Err(symlink_error) => {
            // Directory junctions do not require Windows Developer Mode. Keep
            // this fallback inside the test helper so production code never
            // invokes a shell.
            // Rebuilding from components also normalizes mixed `/` separators:
            // cmd.exe otherwise parses the suffix after `/` as another switch.
            let normalized_link = link.components().collect::<std::path::PathBuf>();
            let normalized_target = target.components().collect::<std::path::PathBuf>();
            let status = Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(normalized_link)
                .arg(normalized_target)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::new(
                    symlink_error.kind(),
                    "failed to create a directory symlink or junction",
                ))
            }
        }
    }
}

#[test]
fn missing_and_incompatible_databases_are_structured_status_not_panics() {
    let root = tempfile::tempdir().expect("temp root");
    let output = root.path().join("output");
    fs::create_dir(&output).expect("output");
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: root.path().join("missing-legal.sqlite"),
        user_database_path: root.path().join("missing-user.sqlite"),
        allowed_file_roots: Vec::new(),
        allowed_output_root: output,
    })
    .expect("service config");
    let status = services.system_status().expect("status");
    assert_eq!(status.status, "degraded");
    assert_eq!(
        status.legal_database.error.expect("legal error").code,
        "legal_database_missing"
    );
    assert_eq!(
        status.user_database.error.expect("user error").code,
        "user_database_missing"
    );

    let incompatible_legal = root.path().join("incompatible-legal.sqlite");
    drop(Connection::open(&incompatible_legal).expect("blank SQLite database"));
    let incompatible = LegalServices::new(ServiceConfig {
        legal_core_path: incompatible_legal,
        user_database_path: root.path().join("missing-user.sqlite"),
        allowed_file_roots: Vec::new(),
        allowed_output_root: root.path().join("output"),
    })
    .expect("incompatible database can be reported by status");
    assert_eq!(
        incompatible
            .system_status()
            .expect("status")
            .legal_database
            .error
            .expect("incompatible legal error")
            .code,
        "legal_database_incompatible"
    );
}

#[test]
fn fixture_paths_are_external_and_not_embedded_in_service_configuration() {
    let fixture = fixture();
    assert!(fixture.legal_path.is_file());
    assert!(fixture.user_path.is_file());
    assert!(fixture.services.config().legal_core_path.is_absolute());
    assert_eq!(fixture.services.config().allowed_file_roots.len(), 1);
}

#[test]
fn fresh_project_and_allowed_root_material_use_reviewed_atomic_apply_and_replay() {
    let fixture = empty_fixture();
    let source = fixture._root.path().join("materials/contract.txt");
    fs::write(
        &source,
        "Agreement amount: 100000 CNY.\nSigned by both parties.",
    )
    .expect("write source material");
    let user_database_before = fs::read(&fixture.user_path).expect("user database before propose");

    let proposal = fixture
        .services
        .case_propose_patch(bootstrap_request(&source))
        .expect("read-only bootstrap proposal");
    assert_eq!(proposal.base_revision, ABSENT_CASE_REVISION);
    assert!(!proposal
        .canonical_proposal
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    let canonical: CanonicalCaseProposal =
        serde_json::from_str(&proposal.canonical_proposal).expect("canonical proposal");
    assert_eq!(canonical.material_imports.len(), 1);
    assert_eq!(canonical.material_imports[0].relative_path, "contract.txt");
    assert_eq!(canonical.material_imports[0].content_sha256.len(), 64);
    assert_eq!(user_count(&fixture.user_path, "projects"), 0);
    assert_eq!(user_count(&fixture.user_path, "attachments"), 0);
    assert_eq!(user_count(&fixture.user_path, "case_files"), 0);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 0);
    assert_eq!(
        fs::read(&fixture.user_path).expect("user database after propose"),
        user_database_before
    );

    let apply = CaseApplyPatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "case-bootstrap".to_owned(),
        canonical_proposal: proposal.canonical_proposal.clone(),
        proposal_hash: proposal.proposal_hash.clone(),
        expected_revision: ABSENT_CASE_REVISION.to_owned(),
        confirmed: true,
        idempotency_key: "bootstrap-material-apply".to_owned(),
    };
    let applied = fixture
        .services
        .case_apply_patch(apply.clone())
        .expect("apply bootstrap");
    assert_eq!(applied.previous_revision, ABSENT_CASE_REVISION);
    assert!(applied.applied);
    assert!(!applied.replayed);
    assert_eq!(user_count(&fixture.user_path, "projects"), 1);
    assert_eq!(user_count(&fixture.user_path, "attachments"), 1);
    assert_eq!(user_count(&fixture.user_path, "case_files"), 1);
    assert_eq!(user_count(&fixture.user_path, "case_facts"), 1);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 1);
    let database = database::open_user_database_read_only(&fixture.user_path)
        .expect("inspect imported material");
    let attachment =
        database::get_attachment(&database, &canonical.material_imports[0].attachment_id)
            .expect("read attachment")
            .expect("imported attachment");
    assert_eq!(attachment.project_id.as_deref(), Some("case-bootstrap"));
    assert_eq!(
        attachment.sha256,
        canonical.material_imports[0].content_sha256
    );
    assert_eq!(
        attachment.content_blob,
        fs::read(&source).expect("source bytes")
    );
    assert!(attachment
        .extracted_text
        .as_deref()
        .is_some_and(|text| text.contains("Agreement amount")));
    let segments: serde_json::Value =
        serde_json::from_str(&attachment.segments_json).expect("segments JSON");
    assert!(segments.as_array().is_some_and(|items| !items.is_empty()));
    let rows = database::get_case_workspace_rows(&database, "case-bootstrap")
        .expect("workspace rows")
        .expect("bootstrap workspace");
    assert_eq!(
        rows.files[0].storage_reference,
        canonical.material_imports[0].attachment_id
    );
    assert_eq!(
        rows.files[0].summary,
        "已导入案件材料，材料内容已完成提取。"
    );
    assert_eq!(rows.facts[0].source, "经确认的案件信息");
    let audit_details: String = database
        .query_row(
            "SELECT details_json FROM operation_audit WHERE audit_id = ?1",
            [&applied.audit_id],
            |row| row.get(0),
        )
        .expect("audit details");
    let absolute_root = fixture._root.path().to_string_lossy().to_string();
    assert!(!audit_details.contains(&absolute_root));
    assert!(!rows.files[0].summary.contains(&absolute_root));
    for forbidden in [
        proposal.proposal_hash.as_str(),
        canonical.material_imports[0].attachment_id.as_str(),
        canonical.material_imports[0].content_sha256.as_str(),
        "proposalHash",
        "attachmentId",
        "sha256",
        "sourceRefs",
        "{",
        "}",
    ] {
        assert!(
            !rows.files[0].summary.contains(forbidden),
            "material summary leaked internal trace data: {forbidden}"
        );
        assert!(
            !rows.facts[0].source.contains(forbidden),
            "fact source leaked internal trace data: {forbidden}"
        );
    }
    let audit_json: serde_json::Value =
        serde_json::from_str(&audit_details).expect("completed audit JSON");
    let audited_material = &audit_json["caseMaterials"][0];
    assert_eq!(audited_material["materialId"], "material-contract");
    assert_eq!(
        audited_material["attachmentId"],
        canonical.material_imports[0].attachment_id
    );
    assert_eq!(
        audited_material["rootId"],
        canonical.material_imports[0].root_id
    );
    assert_eq!(audited_material["relativePath"], "contract.txt");
    assert_eq!(
        audited_material["contentSha256"],
        canonical.material_imports[0].content_sha256
    );
    assert!(!audit_details.contains("Agreement amount"));
    drop(database);
    let state = fixture
        .services
        .case_get_state(CaseGetStateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-bootstrap".to_owned(),
            page: None,
            page_size: None,
        })
        .expect("bootstrap state");
    assert_eq!(state.workspace.files[0].file_id, "material-contract");
    assert_eq!(state.workspace.facts[0].fact_id, "fact-bootstrap");

    let replay = fixture
        .services
        .case_apply_patch(apply)
        .expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(replay.audit_id, applied.audit_id);
    assert_eq!(replay.revision, applied.revision);
    assert_eq!(user_count(&fixture.user_path, "attachments"), 1);
    assert_eq!(user_count(&fixture.user_path, "case_files"), 1);
}

#[test]
fn unconfirmed_bootstrap_never_creates_project_material_or_audit() {
    let fixture = empty_fixture();
    let source = fixture._root.path().join("materials/unconfirmed.txt");
    fs::write(&source, "unconfirmed source").expect("source");
    let proposal = fixture
        .services
        .case_propose_patch(bootstrap_request(&source))
        .expect("proposal");
    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-bootstrap".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: ABSENT_CASE_REVISION.to_owned(),
            confirmed: false,
            idempotency_key: "unconfirmed-bootstrap".to_owned(),
        })
        .expect_err("confirmation required");
    assert_eq!(error.code, "confirmation_required");
    for table in ["projects", "attachments", "case_files", "operation_audit"] {
        assert_eq!(user_count(&fixture.user_path, table), 0, "{table}");
    }
}

#[test]
fn existing_project_rejects_bootstrap_without_mutation() {
    let fixture = fixture();
    let revision = current_revision(&fixture);
    let mut request = proposal_request(revision.clone(), "fact-bootstrap-conflict");
    request.project_bootstrap = Some(CaseProjectBootstrap {
        title: "Replacement title".to_owned(),
        case_type: "civil".to_owned(),
        opened_on: None,
        summary: String::new(),
    });
    let error = fixture
        .services
        .case_propose_patch(request)
        .expect_err("existing project bootstrap rejected");
    assert_eq!(error.code, "project_bootstrap_conflict");
    assert_eq!(current_revision(&fixture), revision);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 0);
}

#[test]
fn bootstrap_rejects_project_ids_already_used_by_another_case_entity() {
    let fixture = fixture();
    let request = CaseProposePatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "fact-existing".to_owned(),
        base_revision: ABSENT_CASE_REVISION.to_owned(),
        changes: empty_changes(),
        project_bootstrap: Some(CaseProjectBootstrap {
            title: "Conflicting project id".to_owned(),
            case_type: "civil".to_owned(),
            opened_on: None,
            summary: String::new(),
        }),
        material_imports: Vec::new(),
    };
    let error = fixture
        .services
        .case_propose_patch(request)
        .expect_err("project id must share the global entity namespace");
    assert_eq!(error.code, "entity_id_conflict");
    assert_eq!(user_count(&fixture.user_path, "projects"), 1);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 0);
}

#[test]
fn service_reserved_snapshot_namespace_is_rejected_before_proposal_creation() {
    let fixture = empty_fixture();
    let source = fixture._root.path().join("materials/reserved.txt");
    fs::write(&source, "reserved namespace test").expect("source");
    let mut material_request = bootstrap_request(&source);
    material_request.material_imports[0].material_id =
        "urn:lawyer-assistance:proposal-snapshot:v1:user-material".to_owned();
    let error = fixture
        .services
        .case_propose_patch(material_request)
        .expect_err("reserved material id must fail during propose");
    assert_eq!(error.code, "invalid_request");
    assert_eq!(user_count(&fixture.user_path, "projects"), 0);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 0);

    let mut source_request = bootstrap_request(&source);
    source_request.material_imports.clear();
    source_request.changes.facts[0].source_refs =
        vec!["urn:lawyer-assistance:proposal-snapshot:v1:user-source".to_owned()];
    let error = fixture
        .services
        .case_propose_patch(source_request)
        .expect_err("reserved source ref must fail during propose");
    assert_eq!(error.code, "invalid_request");
    assert_eq!(user_count(&fixture.user_path, "projects"), 0);
    assert_eq!(user_count(&fixture.user_path, "operation_audit"), 0);
}

#[test]
fn bootstrap_only_and_existing_project_material_only_are_valid_reviewed_changes() {
    let bootstrap_fixture = empty_fixture();
    let bootstrap = CaseProposePatchRequest {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: "bootstrap-only".to_owned(),
        base_revision: ABSENT_CASE_REVISION.to_owned(),
        changes: empty_changes(),
        project_bootstrap: Some(CaseProjectBootstrap {
            title: "Empty reviewed case".to_owned(),
            case_type: "civil".to_owned(),
            opened_on: None,
            summary: String::new(),
        }),
        material_imports: Vec::new(),
    };
    let proposal = bootstrap_fixture
        .services
        .case_propose_patch(bootstrap)
        .expect("bootstrap-only proposal");
    bootstrap_fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "bootstrap-only".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: ABSENT_CASE_REVISION.to_owned(),
            confirmed: true,
            idempotency_key: "bootstrap-only-apply".to_owned(),
        })
        .expect("bootstrap-only apply");
    assert_eq!(user_count(&bootstrap_fixture.user_path, "projects"), 1);
    assert_eq!(user_count(&bootstrap_fixture.user_path, "attachments"), 0);

    let material_fixture = fixture();
    let source = material_fixture._root.path().join("material-only.txt");
    fs::write(&source, "material-only source").expect("material source");
    let revision = current_revision(&material_fixture);
    let proposal = material_fixture
        .services
        .case_propose_patch(CaseProposePatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            base_revision: revision.clone(),
            changes: empty_changes(),
            project_bootstrap: None,
            material_imports: vec![CaseMaterialImportRequest {
                material_id: "material-only".to_owned(),
                path: source.to_string_lossy().into_owned(),
                title: "Material only".to_owned(),
            }],
        })
        .expect("material-only proposal");
    material_fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-1".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: revision,
            confirmed: true,
            idempotency_key: "material-only-apply".to_owned(),
        })
        .expect("material-only apply");
    assert_eq!(user_count(&material_fixture.user_path, "attachments"), 1);
    assert_eq!(user_count(&material_fixture.user_path, "case_files"), 1);
}

#[test]
fn changed_material_invalidates_bootstrap_without_partial_database_writes() {
    let fixture = empty_fixture();
    let source = fixture._root.path().join("materials/contract.txt");
    fs::write(&source, "reviewed bytes").expect("write reviewed material");
    let proposal = fixture
        .services
        .case_propose_patch(bootstrap_request(&source))
        .expect("proposal");
    fs::write(&source, "changed after review").expect("mutate material");
    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-bootstrap".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: ABSENT_CASE_REVISION.to_owned(),
            confirmed: true,
            idempotency_key: "bootstrap-drift".to_owned(),
        })
        .expect_err("material drift must fail");
    assert_eq!(error.code, "material_snapshot_drift");
    for table in [
        "projects",
        "attachments",
        "case_files",
        "case_facts",
        "operation_audit",
    ] {
        assert_eq!(user_count(&fixture.user_path, table), 0, "{table}");
    }
}

#[test]
fn apply_rejects_material_replaced_by_outside_hardlink_without_business_writes() {
    let fixture = empty_fixture();
    let source = fixture
        ._root
        .path()
        .join("materials/apply-hardlink/contract.txt");
    fs::create_dir(source.parent().expect("material parent")).expect("create material directory");
    fs::write(&source, "reviewed bytes").expect("write reviewed material");
    let proposal = fixture
        .services
        .case_propose_patch(bootstrap_request(&source))
        .expect("proposal succeeds before filesystem replacement");
    let database_before_apply =
        fs::read(&fixture.user_path).expect("read user database before apply");

    let outside = fixture._root.path().join("outside-hardlink-source.txt");
    fs::write(&outside, "reviewed bytes").expect("write outside hardlink source");
    fs::remove_file(&source).expect("remove reviewed material before replacement");
    fs::hard_link(&outside, &source).expect("replace material with outside hardlink");

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-bootstrap".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: ABSENT_CASE_REVISION.to_owned(),
            confirmed: true,
            idempotency_key: "bootstrap-apply-hardlink-replacement".to_owned(),
        })
        .expect_err("apply must reject a multiply-linked replacement");

    assert_eq!(error.code, "filesystem_hardlink_rejected");
    assert!(!error
        .to_string()
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    assert_bootstrap_apply_wrote_nothing(&fixture, &database_before_apply);
}

#[cfg(any(unix, windows))]
#[test]
fn apply_rejects_material_parent_replaced_by_reparse_without_business_writes() {
    let fixture = empty_fixture();
    let material_parent = fixture._root.path().join("materials/apply-reparse");
    fs::create_dir(&material_parent).expect("create material directory");
    let source = material_parent.join("contract.txt");
    fs::write(&source, "reviewed bytes").expect("write reviewed material");
    let proposal = fixture
        .services
        .case_propose_patch(bootstrap_request(&source))
        .expect("proposal succeeds before directory replacement");
    let database_before_apply =
        fs::read(&fixture.user_path).expect("read user database before apply");

    let outside = fixture._root.path().join("outside-reparse-apply-target");
    fs::create_dir(&outside).expect("create outside directory");
    fs::write(outside.join("contract.txt"), "reviewed bytes")
        .expect("write same-byte outside material");
    fs::remove_file(&source).expect("remove reviewed material before replacement");
    fs::remove_dir(&material_parent).expect("remove reviewed material parent");
    create_directory_symlink(&outside, &material_parent)
        .expect("replace material parent with symlink or Windows junction");

    let error = fixture
        .services
        .case_apply_patch(CaseApplyPatchRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: "case-bootstrap".to_owned(),
            canonical_proposal: proposal.canonical_proposal,
            proposal_hash: proposal.proposal_hash,
            expected_revision: ABSENT_CASE_REVISION.to_owned(),
            confirmed: true,
            idempotency_key: "bootstrap-apply-reparse-replacement".to_owned(),
        })
        .expect_err("apply must reject a reparse-point parent replacement");

    assert_eq!(error.code, "material_path_rejected");
    assert!(!error
        .to_string()
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    assert_bootstrap_apply_wrote_nothing(&fixture, &database_before_apply);
}

#[test]
fn material_paths_outside_allowed_root_are_rejected_without_path_disclosure() {
    let fixture = empty_fixture();
    let outside = fixture._root.path().join("outside.txt");
    fs::write(&outside, "outside").expect("outside material");
    let error = fixture
        .services
        .case_propose_patch(bootstrap_request(&outside))
        .expect_err("outside path rejected");
    assert_eq!(error.code, "material_path_rejected");
    assert!(!error
        .to_string()
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    assert_eq!(user_count(&fixture.user_path, "projects"), 0);

    let traversal = fixture
        ._root
        .path()
        .join("materials")
        .join("..")
        .join("outside.txt");
    let error = fixture
        .services
        .case_propose_patch(bootstrap_request(&traversal))
        .expect_err("traversal outside root rejected");
    assert_eq!(error.code, "material_path_rejected");
}

fn assert_bootstrap_propose_wrote_nothing(fixture: &Fixture, before_database: &[u8]) {
    for table in [
        "projects",
        "attachments",
        "case_files",
        "case_facts",
        "operation_audit",
    ] {
        assert_eq!(user_count(&fixture.user_path, table), 0, "{table}");
    }
    assert_eq!(
        fs::read(&fixture.user_path).expect("read user database after rejected proposal"),
        before_database,
        "case_propose_patch must remain byte-for-byte read-only on a rejected material path"
    );
}

fn assert_bootstrap_apply_wrote_nothing(fixture: &Fixture, before_database: &[u8]) {
    for table in [
        "projects",
        "attachments",
        "case_files",
        "case_facts",
        "operation_audit",
    ] {
        assert_eq!(user_count(&fixture.user_path, table), 0, "{table}");
    }
    assert_eq!(
        fs::read(&fixture.user_path).expect("read user database after rejected apply"),
        before_database,
        "case_apply_patch must not persist business writes for a rejected material replacement"
    );
}

#[test]
fn hardlinked_material_cannot_alias_an_outside_file_into_an_allowed_root() {
    let fixture = empty_fixture();
    let outside = fixture._root.path().join("outside-hardlink-source.txt");
    fs::write(&outside, "outside hardlink source").expect("write outside source");
    let nested = fixture._root.path().join("materials/nested-hardlink");
    fs::create_dir(&nested).expect("create nested material directory");
    let alias = nested.join("aliased.txt");
    fs::hard_link(&outside, &alias).expect("create cross-boundary hard link");
    let before_database = fs::read(&fixture.user_path).expect("read user database before propose");

    let error = fixture
        .services
        .case_propose_patch(bootstrap_request(&alias))
        .expect_err("multiply-linked material must be rejected");

    assert_eq!(error.code, "filesystem_hardlink_rejected");
    assert!(!error
        .to_string()
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    assert_bootstrap_propose_wrote_nothing(&fixture, &before_database);
}

#[test]
fn nested_directory_reparse_cannot_escape_the_allowed_material_root() {
    let fixture = empty_fixture();
    let outside = fixture._root.path().join("outside-reparse-target");
    fs::create_dir(&outside).expect("create outside directory");
    fs::write(outside.join("outside.txt"), "outside reparse source").expect("write outside source");
    let nested = fixture._root.path().join("materials/nested-reparse");
    fs::create_dir(&nested).expect("create nested material directory");
    let reparse = nested.join("redirected");
    create_directory_symlink(&outside, &reparse)
        .expect("create nested directory symlink or Windows junction");
    let escaped = reparse.join("outside.txt");
    let before_database = fs::read(&fixture.user_path).expect("read user database before propose");

    let error = fixture
        .services
        .case_propose_patch(bootstrap_request(&escaped))
        .expect_err("nested reparse escape must be rejected");

    assert_eq!(error.code, "material_path_rejected");
    assert!(!error
        .to_string()
        .contains(&fixture._root.path().to_string_lossy().to_string()));
    assert_bootstrap_propose_wrote_nothing(&fixture, &before_database);
}

#[test]
fn legacy_existing_project_request_without_new_json_fields_remains_compatible() {
    let fixture = fixture();
    let revision = current_revision(&fixture);
    let request_json = serde_json::json!({
        "schemaVersion": SERVICE_SCHEMA_VERSION,
        "projectId": "case-1",
        "baseRevision": revision,
        "changes": empty_changes(),
    });
    let request: CaseProposePatchRequest =
        serde_json::from_value(request_json).expect("legacy request decodes");
    assert!(request.project_bootstrap.is_none());
    assert!(request.material_imports.is_empty());
    let error = fixture
        .services
        .case_propose_patch(request)
        .expect_err("truly empty existing-project patch remains invalid");
    assert_eq!(error.code, "invalid_proposal");
}
