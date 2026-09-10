# Tool contracts (v1.1.0)

The Rust registry is authoritative at `crates/legal-mcp/src/registry.rs`.

| Profile | Tools |
|---|---|
| `public_law_only` | exactly seven tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations`, `legal_search_cases`, `legal_get_case` |
| `privacy_workspace` | exactly ten tools: the seven public tools plus `privacy_workspace.submit`, `privacy_workspace.status`, `privacy_workspace.read_result` |
| `approved_case_workspace`, `redacted_case`, `diagram_authoring` | disabled at startup (`profile_disabled`) |

The original five public-law tools retain their v1.0.0 names and input/output contracts. `legal_search_cases` takes `schema_version`, a non-empty `query`, and optional `case_type`, `limit`, `offset`, and `include_withdrawn`; it searches `judicial_cases.sqlite` locally. `legal_get_case` takes `schema_version` and an opaque `case_id`; it returns the selected public case and its official source metadata. Neither tool calls a model or the public internet.

`privacy_workspace.submit` takes an idempotency `request_id` and 1–100 configured inbox-relative TXT/DOCX paths. `privacy_workspace.status` takes `task_id`. `privacy_workspace.read_result` takes `result_id` and an optional cursor. Successful private responses are backend-provided safe JSON. Failures use `{ "error": { "code": "…", "retryable": false } }`.
