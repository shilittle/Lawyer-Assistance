# Packaging and migration (v1.1.0)

The v1.1.0 Windows x86_64 portable package contains the MCP binary, documentation, integration examples, the verified `legal_core.sqlite` runtime resource, and the verified `judicial_cases.sqlite` sidecar. It also contains `CASE_DATA_SOURCES.md` and `data/runtime/judicial_cases_manifest.json`. The package contains no private workspace database, original, mapping, token, credential, cache, or cloud configuration.

Packaging fails closed if the case sidecar or its generated manifest is missing, if the filename/size/SHA-256 differs, if schema version or `judicial_cases` columns do not match, if declared counts differ from SQLite rows, or if the declared source is not the official Supreme People's Court corpus. The sidecar is copied from `data/runtime` and the generated manifest is copied into the package; no cache or fetched source payload is copied.

Use a new workspace data directory. The MCP public profile does not migrate or modify old user data. Existing public launchers that pass `--config`, `--user-db`, `--allowed-root`, or `--output-dir` continue to parse, but only the legal database setting is used.

Move privacy clients to `privacy_workspace`. Remove configurations for `approved_case_workspace`, `redacted_case`, and `diagram_authoring`; they intentionally fail with `profile_disabled` and are not capability aliases.
