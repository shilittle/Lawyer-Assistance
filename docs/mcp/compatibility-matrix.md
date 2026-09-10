# Compatibility matrix

| Surface | Contract |
|---|---|
| Release | v1.1.0 Web case-retrieval add-on |
| MCP protocol | `2025-11-25` |
| `public_law_only` | exact seven public legal tools, including two local case tools |
| `privacy_workspace` | exact ten tools: seven public tools plus three workspace tools |
| legacy profiles | startup error `profile_disabled` |
| legal data | `data/runtime/legal_core.sqlite` by default, or `LEGAL_DB`; case sidecar is `judicial_cases.sqlite` beside it |
| private data | never opened by public MCP |

The first five tool names and input schemas are frozen for existing public integrations. The two case tools are additive and read only the sibling `judicial_cases.sqlite`; their manifest and source note are shipped with the portable package. Deprecated CLI fields such as `--user-db`, `--allowed-root`, and `--output-dir` are accepted only so existing public launcher files continue to start; public MCP ignores them.
