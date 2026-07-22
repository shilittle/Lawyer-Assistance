# Installation and preflight

## Install

- For stdio, copy `assets/config.stdio.toml`, replace absolute paths, and retain `--privacy-profile public_law_only` plus the exact five-tool `enabled_tools` list.
- For Streamable HTTP, copy `assets/config.http.toml`. Start the service on `127.0.0.1` with `public_law_only`; provide the Bearer token only through `LAWYER_ASSISTANCE_MCP_TOKEN`.
- For production network ingress, use a controlled TLS reverse proxy. Never package or enable `--dangerously-allow-insecure-non-loopback-http`, `dangerously_allow_insecure_non_loopback_http`, or `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`; those diagnostic escape hatches do not replace TLS.
- Merge `assets/config.privacy-hardening.toml`, then install the complete Skill directory.

## Preflight every task

1. Before reading user content, decide whether it may contain client, case, attachment, path, or derived facts. If so, stop under `RAW_DATA_ALREADY_DISCLOSED_TO_HOST` and call no tool.
2. Run `codex mcp list` and inspect the connection. Require exactly `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`.
3. Call `system_status`; require a ready public legal database, compatible schema, and `public_law_only` profile.
4. Allow only public law names, public article identifiers, public jurisdictions, and public research dates into tool arguments.

`CASE_RAW`, `CASE_REDACTED_PENDING`, pending-review content, label-only `CASE_REDACTED_APPROVED` content, and App artifacts themselves are forbidden in this public-only Codex package. Every case workflow remains disabled here by design. A separate approved package requires a new clean opaque-ID-only task and a current App-issued session; never move text between the packages.