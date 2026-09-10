# Lawyer Assistance MCP v1.1.0

Lawyer Assistance v1.1.0 provides local statute and Supreme People's Court case research plus published-redaction access through MCP protocol version `2025-11-25`.

`public_law_only` is the default profile and exposes exactly seven offline tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations`, `legal_search_cases`, and `legal_get_case`.

`privacy_workspace` exposes ten tools in total: those seven tools plus `privacy_workspace.submit`, `privacy_workspace.status`, and `privacy_workspace.read_result`. Its three workspace calls use the current MCP client's bearer token only to reach the local backend. They never return originals, mappings, source names, or disk paths.

`legal_search_cases` and `legal_get_case` read the sibling `judicial_cases.sqlite` sidecar and return only source-traceable public case data. The sidecar manifest declares the schema, counts, and Supreme People's Court source. An explicit WebUI case-understanding request may use an existing Provider to derive search terms; MCP case tools always search the local corpus directly and never ask a model to invent a case.

The former `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are disabled. Selecting one exits with `profile_disabled`.

See [installation](installation.md), [tools](tools.md), and [security](security-and-privacy.md).
