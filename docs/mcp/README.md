# Lawyer Assistance MCP v1.0.0

Lawyer Assistance v1.0.0 provides local legal research and published-redaction access through MCP protocol version `2025-11-25`.

`public_law_only` is the default profile and exposes exactly five offline tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`.

`privacy_workspace` exposes eight tools in total: those five tools plus `privacy_workspace.submit`, `privacy_workspace.status`, and `privacy_workspace.read_result`. Its three workspace calls use the current MCP client's bearer token only to reach the local backend. They never return originals, mappings, source names, or disk paths.

The former `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are disabled. Selecting one exits with `profile_disabled`.

See [installation](installation.md), [tools](tools.md), and [security](security-and-privacy.md).
