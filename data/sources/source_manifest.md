# Source Manifest

The canonical source manifest for the bundled legal database is stored inside
`apps/desktop/src-tauri/resources/legal_core.sqlite`.

Tables:

- `source_systems`: official source names, base URLs, maintainers, and scope notes.
- `source_records`: fetched official records with external ids, source URLs, checksums, and raw JSON/text where available.
- `source_categories`: official category trees.
- `coverage_audit`: source-level expected totals, fetched totals, detail counts, text counts, and status.

This avoids maintaining a separate 40000+ row manifest file that can drift from
the SQLite artifact. The checked-in `legal_core_build_report.json` is the
historical Stage 1B pre-normalization build summary; use the Stage 1C history,
corpora, strict-audit, and distribution reports for the current schema-v4
snapshot, and query `source_records` for the per-record manifest.

The deterministic SHA-256 over the ordered `source_records` manifest is stored
in `database_metadata.source_manifest_sha256`. The exact distributed SQLite
file size and SHA-256 are stored outside the database in
`data/generated/legal_core_distribution_manifest.json`; this avoids the
self-referential and unverifiable practice of embedding a file's own hash in
that same file.
