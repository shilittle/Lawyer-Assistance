# Data and result versions (v1.1.0)

The v1.1.0 Web release treats `legal_core.sqlite` and the sibling `judicial_cases.sqlite` as independent read-only public resources. The statute database keeps the v1.0.0 identity and schema. The case manifest binds its filename, size, SHA-256, schema version, record counts, and official source; SQLite integrity and schema checks run before packaging. A missing or incompatible database does not expose paths or diagnostics: statute calls or case calls report their own availability failure while the other corpus remains independent.

`legal_search_cases` and `legal_get_case` return a service schema version of `1`, a case database version from `database_metadata.dataset_version`, and source URL fields stored in the sidecar. The package manifest and `data/runtime/judicial_cases_manifest.json` are metadata about the same immutable file; they do not replace the official source note.

Private workspace records, originals, mappings, and encrypted content are owned by the local application service under the new Web workspace directory. MCP has no database path, mapping, or original-content API. `privacy_workspace.read_result` returns only the current published result ID supplied by the backend. Revoked, stale, failed, or review-required results are rejected by that backend.
