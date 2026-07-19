# Public-law tool routing

The active profile is `public_law_only`. Its allowlist is exact and ordered:

| Tool | Purpose |
|---|---|
| `system_status` | Check the local public-law database, schema, and profile status |
| `legal_search` | Search public law by public terms, jurisdiction, and date |
| `legal_get_article` | Read a provision from a selected public-law version |
| `legal_get_versions` | Read public-law version and effective-date intervals |
| `legal_get_relations` | Read public references, replacements, and relations between provisions |

All five tools are read-only, non-destructive, idempotent, and closed-world. Every call includes `schema_version: 1`. For historical search, `case_date` means a public research reference date; it must not be derived from a real case supplied to the host.

Reject the server if any other tool appears. The App→MCP citation receipt positive path does not exist yet, so case material, case state, case-specific citation validation, document generation, writes, and exports are unavailable. Do not recreate them with shell, filesystem, browser, network, Provider, connector, or subagent capabilities.