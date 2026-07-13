PRAGMA foreign_keys = OFF;

BEGIN;

DROP TABLE IF EXISTS law_articles_fts;
DROP TABLE IF EXISTS citation_metadata;
DROP TABLE IF EXISTS document_templates;
DROP TABLE IF EXISTS guiding_cases;
DROP TABLE IF EXISTS article_topics;
DROP TABLE IF EXISTS legal_topics;
DROP TABLE IF EXISTS legal_attachments;
DROP TABLE IF EXISTS law_aliases;
DROP TABLE IF EXISTS law_relations;
DROP TABLE IF EXISTS law_articles;
DROP TABLE IF EXISTS law_versions;
DROP TABLE IF EXISTS law_documents;
DROP TABLE IF EXISTS issuing_authorities;
DROP TABLE IF EXISTS coverage_audit;
DROP TABLE IF EXISTS history_version_exceptions;
DROP TABLE IF EXISTS ingestion_audit;
DROP TABLE IF EXISTS source_categories;
DROP TABLE IF EXISTS source_records;
DROP TABLE IF EXISTS source_systems;
DROP TABLE IF EXISTS database_metadata;

CREATE TABLE database_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE source_systems (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  official_scope TEXT NOT NULL,
  maintainer TEXT NOT NULL,
  retrieved_at TEXT,
  notes TEXT NOT NULL
);

CREATE TABLE source_records (
  id TEXT PRIMARY KEY,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id) ON DELETE CASCADE,
  external_id TEXT NOT NULL,
  record_type TEXT NOT NULL,
  source_url TEXT,
  retrieved_at TEXT NOT NULL,
  checksum TEXT NOT NULL,
  raw_json TEXT,
  raw_text TEXT,
  UNIQUE(source_system_id, external_id, record_type)
);

CREATE TABLE source_categories (
  id TEXT PRIMARY KEY,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES source_categories(id) ON DELETE CASCADE,
  external_code TEXT,
  name TEXT NOT NULL,
  category_type TEXT NOT NULL,
  level INTEGER NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE TABLE coverage_audit (
  id TEXT PRIMARY KEY,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expected_total INTEGER,
  fetched_total INTEGER NOT NULL,
  detail_fetched_total INTEGER NOT NULL,
  text_fetched_total INTEGER NOT NULL,
  status TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  notes TEXT NOT NULL
);

CREATE TABLE history_version_exceptions (
  id TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  document_ids_json TEXT NOT NULL,
  effective_dates_json TEXT NOT NULL,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id),
  source_reference TEXT NOT NULL,
  checked_at TEXT NOT NULL
);

CREATE TABLE ingestion_audit (
  id TEXT PRIMARY KEY,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id) ON DELETE CASCADE,
  external_id TEXT NOT NULL,
  source_scope TEXT NOT NULL,
  source_url TEXT,
  index_status TEXT NOT NULL,
  detail_status TEXT NOT NULL,
  text_status TEXT NOT NULL,
  article_status TEXT NOT NULL,
  relation_status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  checksum TEXT,
  last_error TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE(source_system_id, external_id)
);

CREATE TABLE issuing_authorities (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  authority_type TEXT NOT NULL,
  country_region TEXT NOT NULL
);

CREATE TABLE law_documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  title_pinyin TEXT,
  document_type TEXT NOT NULL,
  authority_id TEXT NOT NULL REFERENCES issuing_authorities(id),
  jurisdiction TEXT NOT NULL,
  effectiveness_level TEXT NOT NULL,
  status TEXT NOT NULL,
  promulgated_on TEXT,
  source_url TEXT,
  summary TEXT NOT NULL,
  source_system_id TEXT REFERENCES source_systems(id),
  source_external_id TEXT,
  source_record_id TEXT REFERENCES source_records(id),
  raw_status TEXT,
  raw_category_code TEXT,
  raw_category_name TEXT
);

CREATE TABLE law_versions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  version_label TEXT NOT NULL,
  status TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  published_on TEXT,
  source_reference TEXT NOT NULL
);

CREATE TABLE law_articles (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  version_id TEXT NOT NULL REFERENCES law_versions(id) ON DELETE CASCADE,
  article_number TEXT NOT NULL,
  article_order INTEGER NOT NULL,
  title TEXT,
  content TEXT NOT NULL,
  updated_on TEXT,
  UNIQUE(version_id, article_number)
);

CREATE TABLE law_relations (
  id TEXT PRIMARY KEY,
  from_document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  to_document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  relation_type TEXT NOT NULL,
  description TEXT NOT NULL,
  source_reference TEXT NOT NULL
);

CREATE TABLE law_aliases (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  normalized_alias TEXT NOT NULL
);

CREATE TABLE legal_attachments (
  id TEXT PRIMARY KEY,
  document_id TEXT REFERENCES law_documents(id) ON DELETE CASCADE,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id) ON DELETE CASCADE,
  external_id TEXT NOT NULL,
  title TEXT NOT NULL,
  attachment_type TEXT NOT NULL,
  file_type TEXT,
  source_url TEXT,
  storage_path TEXT,
  raw_json TEXT NOT NULL,
  UNIQUE(source_system_id, external_id, attachment_type)
);

CREATE TABLE legal_topics (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  parent_topic_id TEXT REFERENCES legal_topics(id)
);

CREATE TABLE article_topics (
  article_id TEXT NOT NULL REFERENCES law_articles(id) ON DELETE CASCADE,
  topic_id TEXT NOT NULL REFERENCES legal_topics(id) ON DELETE CASCADE,
  PRIMARY KEY (article_id, topic_id)
);

CREATE TABLE guiding_cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  case_type TEXT NOT NULL,
  case_number TEXT,
  court TEXT,
  decided_on TEXT,
  published_on TEXT,
  summary TEXT NOT NULL,
  content TEXT NOT NULL,
  related_article_id TEXT REFERENCES law_articles(id),
  source_system_id TEXT NOT NULL REFERENCES source_systems(id),
  source_external_id TEXT NOT NULL,
  source_record_id TEXT NOT NULL REFERENCES source_records(id),
  source_url TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  UNIQUE(source_system_id, source_external_id, case_type)
);

CREATE TABLE document_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  template_type TEXT NOT NULL,
  content TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  published_on TEXT,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id),
  source_external_id TEXT NOT NULL,
  source_record_id TEXT NOT NULL REFERENCES source_records(id),
  source_url TEXT NOT NULL,
  UNIQUE(source_system_id, source_external_id)
);

CREATE TABLE citation_metadata (
  id TEXT PRIMARY KEY,
  article_id TEXT NOT NULL REFERENCES law_articles(id) ON DELETE CASCADE,
  citation_id TEXT NOT NULL UNIQUE,
  canonical_label TEXT NOT NULL
);

CREATE VIRTUAL TABLE law_articles_fts USING fts5(
  article_id UNINDEXED,
  document_id UNINDEXED,
  version_id UNINDEXED,
  document_title,
  article_number,
  article_title,
  content,
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE INDEX idx_source_records_external ON source_records(source_system_id, external_id);
CREATE INDEX idx_source_categories_source ON source_categories(source_system_id, category_type);
CREATE INDEX idx_coverage_audit_source ON coverage_audit(source_system_id, scope);
CREATE INDEX idx_history_version_exceptions_reason ON history_version_exceptions(reason);
CREATE INDEX idx_ingestion_audit_source ON ingestion_audit(source_system_id, source_scope);
CREATE INDEX idx_ingestion_audit_status ON ingestion_audit(detail_status, text_status, article_status, relation_status);
CREATE INDEX idx_law_documents_title ON law_documents(title);
CREATE INDEX idx_law_documents_status ON law_documents(status);
CREATE INDEX idx_law_documents_source ON law_documents(source_system_id, source_external_id);
CREATE INDEX idx_law_versions_document ON law_versions(document_id, effective_from, effective_to);
CREATE INDEX idx_law_articles_document ON law_articles(document_id, article_order);
CREATE INDEX idx_law_articles_version ON law_articles(version_id, article_order);
CREATE INDEX idx_law_relations_from ON law_relations(from_document_id);
CREATE INDEX idx_law_relations_to ON law_relations(to_document_id);
CREATE INDEX idx_law_aliases_document ON law_aliases(document_id);
CREATE INDEX idx_law_aliases_normalized ON law_aliases(normalized_alias);
CREATE INDEX idx_legal_attachments_document ON legal_attachments(document_id);
CREATE INDEX idx_citation_metadata_article ON citation_metadata(article_id);
CREATE INDEX idx_guiding_cases_type ON guiding_cases(case_type, published_on);
CREATE INDEX idx_guiding_cases_source ON guiding_cases(source_system_id, source_external_id);
CREATE INDEX idx_document_templates_type ON document_templates(template_type, published_on);
CREATE INDEX idx_document_templates_source ON document_templates(source_system_id, source_external_id);

INSERT INTO database_metadata (key, value, updated_at) VALUES
  ('schema_version', '4', '2026-07-11T00:00:00Z'),
  ('dataset_name', 'official-china-legal-core', '2026-07-02T00:00:00Z'),
  ('dataset_notice', 'Schema only. Production data must be generated from official sources with coverage audit records.', '2026-07-02T00:00:00Z');

COMMIT;

PRAGMA foreign_keys = ON;
