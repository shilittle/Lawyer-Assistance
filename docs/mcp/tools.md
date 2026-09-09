# Tool contracts (v1.0.0)

The Rust registry is authoritative at `crates/legal-mcp/src/registry.rs`.

| Profile | Tools |
|---|---|
| `public_law_only` | `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations` |
| `privacy_workspace` | exactly eight tools: the five public tools plus `privacy_workspace.submit`, `privacy_workspace.status`, `privacy_workspace.read_result` |
| `approved_case_workspace`, `redacted_case`, `diagram_authoring` | disabled at startup (`profile_disabled`) |

`privacy_workspace.submit` takes an idempotency `request_id` and 1–100 configured inbox-relative TXT/DOCX paths. `privacy_workspace.status` takes `task_id`. `privacy_workspace.read_result` takes `result_id` and an optional cursor. Successful private responses are backend-provided safe JSON. Failures use `{ "error": { "code": "…", "retryable": false } }`.
