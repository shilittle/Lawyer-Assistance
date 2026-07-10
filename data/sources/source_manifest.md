# Source Manifest

The canonical source manifest for the bundled legal database is stored inside
`apps/desktop/src-tauri/resources/legal_core.sqlite`.

Tables:

- `source_systems`: official source names, base URLs, maintainers, and scope notes.
- `source_records`: fetched official records with external ids, source URLs, checksums, and raw JSON/text where available.
- `source_categories`: official category trees.
- `coverage_audit`: source-level expected totals, fetched totals, detail counts, text counts, and status.

This avoids maintaining a separate 40000+ row manifest file that can drift from
the SQLite artifact. Use `data/generated/legal_core_build_report.json` for the
build summary and query `source_records` for the per-record manifest.
