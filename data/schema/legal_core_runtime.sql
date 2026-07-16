PRAGMA page_size = 8192;
PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE database_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE source_systems (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  official_scope TEXT NOT NULL,
  maintainer TEXT NOT NULL,
  retrieved_at TEXT,
  notes TEXT NOT NULL
) WITHOUT ROWID;

-- Runtime distributions retain stable provenance and checksums, but omit the
-- archival raw_json/raw_text payload after the full database passes audit.
CREATE TABLE source_records (
  id TEXT PRIMARY KEY,
  source_system_id TEXT NOT NULL REFERENCES source_systems(id),
  external_id TEXT NOT NULL,
  record_type TEXT NOT NULL,
  source_url TEXT,
  retrieved_at TEXT NOT NULL,
  checksum TEXT NOT NULL,
  UNIQUE(source_system_id, external_id, record_type)
) WITHOUT ROWID;

CREATE TABLE issuing_authorities (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  authority_type TEXT NOT NULL,
  country_region TEXT NOT NULL
) WITHOUT ROWID;

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
) WITHOUT ROWID;

CREATE TABLE law_versions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  version_label TEXT NOT NULL,
  status TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  published_on TEXT,
  source_reference TEXT NOT NULL
) WITHOUT ROWID;

-- Exact article text is stored once.  article_rowid preserves the audited
-- source rowid so the contentless FTS table can map hits without storing ids.
CREATE TABLE law_article_contents (
  content_id INTEGER PRIMARY KEY,
  content TEXT NOT NULL
);

CREATE TABLE law_article_rows (
  article_rowid INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  version_id TEXT NOT NULL REFERENCES law_versions(id) ON DELETE CASCADE,
  article_number TEXT NOT NULL,
  article_order INTEGER NOT NULL,
  title TEXT,
  content_id INTEGER NOT NULL REFERENCES law_article_contents(content_id),
  updated_on TEXT,
  UNIQUE(version_id, article_number)
);

CREATE VIEW law_articles AS
SELECT
  rows.article_rowid AS rowid,
  rows.id,
  rows.document_id,
  rows.version_id,
  rows.article_number,
  rows.article_order,
  rows.title,
  contents.content,
  rows.updated_on
FROM law_article_rows AS rows
JOIN law_article_contents AS contents ON contents.content_id = rows.content_id;

CREATE TABLE law_relations (
  id TEXT PRIMARY KEY,
  from_document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  to_document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  relation_type TEXT NOT NULL,
  description TEXT NOT NULL,
  source_reference TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE law_aliases (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES law_documents(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  normalized_alias TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE legal_topics (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  parent_topic_id TEXT REFERENCES legal_topics(id)
) WITHOUT ROWID;

CREATE TABLE article_topics (
  article_id TEXT NOT NULL REFERENCES law_article_rows(id) ON DELETE CASCADE,
  topic_id TEXT NOT NULL REFERENCES legal_topics(id) ON DELETE CASCADE,
  PRIMARY KEY (article_id, topic_id)
) WITHOUT ROWID;

-- The archival-only surrogate id is omitted.  The article id is the natural
-- runtime key and citation_id keeps its unique lookup index.
CREATE TABLE citation_metadata (
  article_id TEXT PRIMARY KEY REFERENCES law_article_rows(id) ON DELETE CASCADE,
  citation_id TEXT NOT NULL UNIQUE,
  canonical_label TEXT NOT NULL
) WITHOUT ROWID;

-- content='' keeps only the inverted index and per-row token sizes.  Runtime
-- queries join by rowid and load authoritative text from law_articles.
CREATE VIRTUAL TABLE law_articles_fts USING fts5(
  article_id UNINDEXED,
  document_id UNINDEXED,
  version_id UNINDEXED,
  document_title,
  article_number,
  article_title,
  content,
  content = '',
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE INDEX idx_law_documents_title ON law_documents(title);
CREATE INDEX idx_law_documents_status ON law_documents(status);
CREATE INDEX idx_law_documents_source ON law_documents(source_system_id, source_external_id);
CREATE INDEX idx_law_versions_document ON law_versions(document_id, effective_from, effective_to);
CREATE INDEX idx_law_article_rows_document ON law_article_rows(document_id, article_order);
CREATE INDEX idx_law_article_rows_version ON law_article_rows(version_id, article_order);
CREATE INDEX idx_law_relations_from ON law_relations(from_document_id);
CREATE INDEX idx_law_relations_to ON law_relations(to_document_id);
CREATE INDEX idx_law_aliases_document ON law_aliases(document_id);
CREATE INDEX idx_law_aliases_normalized ON law_aliases(normalized_alias);

COMMIT;

PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;
