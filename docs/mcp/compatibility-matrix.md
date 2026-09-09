# Compatibility matrix

| Surface | Contract |
|---|---|
| Release | v1.0.0 Web major release |
| MCP protocol | `2025-11-25` |
| `public_law_only` | exact five public legal tools |
| `privacy_workspace` | exact eight tools: five public tools plus three workspace tools |
| legacy profiles | startup error `profile_disabled` |
| legal data | `data/runtime/legal_core.sqlite` by default, or `LEGAL_DB` |
| private data | never opened by public MCP |

The first five tool names and input schemas are frozen for existing public integrations. Deprecated CLI fields such as `--user-db`, `--allowed-root`, and `--output-dir` are accepted only so existing public launcher files continue to start; public MCP ignores them.
