# Packaging and migration (v1.0.0)

The v1.0.0 Windows x86_64 portable package contains the MCP binary, documentation, integration examples, and the verified runtime legal database resource. It contains no private workspace database, original, mapping, token, credential, or cloud configuration.

Use a new workspace data directory. The MCP public profile does not migrate or modify old user data. Existing public launchers that pass `--config`, `--user-db`, `--allowed-root`, or `--output-dir` continue to parse, but only the legal database setting is used.

Move privacy clients to `privacy_workspace`. Remove configurations for `approved_case_workspace`, `redacted_case`, and `diagram_authoring`; they intentionally fail with `profile_disabled` and are not capability aliases.
