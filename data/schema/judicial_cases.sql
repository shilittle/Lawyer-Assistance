PRAGMA page_size = 4096;
PRAGMA foreign_keys = ON;

BEGIN;

-- The judicial corpus is a replaceable, read-only sidecar.  It deliberately
-- has no foreign keys into legal_core.sqlite: the two databases may be
-- updated independently and the statutory database must remain untouched.
CREATE TABLE database_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE judicial_cases (
  case_id TEXT PRIMARY KEY,
  case_type TEXT NOT NULL CHECK (case_type IN ('guiding', 'reference', 'typical')),
  guiding_number INTEGER,
  reference_number TEXT,
  title TEXT NOT NULL,
  keywords_json TEXT NOT NULL CHECK (json_valid(keywords_json)),
  publication_date TEXT,
  court TEXT,
  case_number TEXT,
  status TEXT NOT NULL CHECK (status IN ('published', 'withdrawn', 'unknown')),
  source_url TEXT NOT NULL,
  search_text TEXT NOT NULL,
  key_points_json TEXT NOT NULL CHECK (json_valid(key_points_json)),
  basic_facts TEXT NOT NULL,
  judgment_result TEXT NOT NULL,
  reasoning TEXT NOT NULL,
  related_laws_json TEXT NOT NULL CHECK (json_valid(related_laws_json)),
  full_text TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
  CHECK (
    (case_type = 'guiding' AND guiding_number IS NOT NULL AND reference_number IS NULL)
    OR
    (case_type = 'reference' AND guiding_number IS NULL AND reference_number IS NOT NULL)
    OR
    (case_type = 'typical' AND guiding_number IS NULL AND reference_number IS NULL)
  )
) WITHOUT ROWID;

-- Every TXT candidate is retained here, including API/PDF duplicates and the
-- status notice.  A notice has a NULL case_id deliberately: it is provenance
-- evidence for withdrawn cases, never a searchable judicial case.
CREATE TABLE judicial_case_sources (
  source_id TEXT PRIMARY KEY,
  case_id TEXT REFERENCES judicial_cases(case_id) ON DELETE SET NULL,
  normalized_case_id TEXT NOT NULL,
  csv_id TEXT NOT NULL,
  csv_type TEXT NOT NULL CHECK (csv_type IN ('guiding', 'api_guiding', 'reference', 'typical', 'pdf', 'notices')),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('guiding', 'api_guiding', 'reference', 'typical', 'pdf', 'notice')),
  title TEXT NOT NULL,
  source_url TEXT NOT NULL,
  official_urls_json TEXT NOT NULL CHECK (json_valid(official_urls_json)),
  archive_path TEXT NOT NULL UNIQUE,
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  text_sha256 TEXT NOT NULL CHECK (length(text_sha256) = 64),
  text_hash_mode TEXT NOT NULL CHECK (text_hash_mode IN ('raw_bytes', 'utf8_text', 'utf8_text_lf')),
  source_host TEXT,
  source_role TEXT,
  source_authority TEXT,
  publication_date TEXT,
  fetched_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('published', 'withdrawn', 'unknown')),
  is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
  source_header TEXT NOT NULL,
  source_text TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_judicial_cases_type_number
  ON judicial_cases(case_type, guiding_number, reference_number);
CREATE INDEX idx_judicial_cases_publication_date
  ON judicial_cases(publication_date);
CREATE INDEX idx_judicial_cases_status
  ON judicial_cases(status);
CREATE INDEX idx_judicial_cases_reference_number
  ON judicial_cases(reference_number);
CREATE INDEX idx_judicial_case_sources_case_id
  ON judicial_case_sources(case_id, is_primary);
CREATE INDEX idx_judicial_case_sources_normalized_id
  ON judicial_case_sources(normalized_case_id);
CREATE INDEX idx_judicial_case_sources_kind
  ON judicial_case_sources(source_kind);
CREATE INDEX idx_judicial_case_sources_sha256
  ON judicial_case_sources(source_sha256);

COMMIT;

PRAGMA user_version = 1;
