# OpenCode integration: public law only

Both examples disable sharing and deny the `lawyer_assistance_*` wildcard before allowing exactly five read-only public-law tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`.

- `opencode.local.json` explicitly starts the binary with `--privacy-profile public_law_only`.
- `opencode.remote.json` must connect only to a loopback server started with that profile. Reject the connection unless `tools/list` is an exact five-item match.
- Keep the wildcard permission set to `deny`; changing it to `ask` or `allow` would reopen tools outside this reviewed surface.
- Copy `agents/lawyer-assistance.md` to `.opencode/agents/lawyer-assistance.md`. Merge `AGENTS.md.example` into existing project instructions without overwriting unrelated rules.

OpenCode may use this integration only for public legal research containing no client, case, material, attachment, path, or derived fact. `CASE_RAW`, `CASE_REDACTED_PENDING`, pending review, and label-only or verbally claimed `CASE_REDACTED_APPROVED` content must not reach the host, filesystem, network, MCP, Provider, connector, memory, or another agent.

The App→MCP citation receipt positive path is not implemented, so all case-material, case-state, case-citation validation, document generation, write, and export workflows are disabled—even for locally approved App artifacts.

If content was pasted or attached before the agent rules loaded, the host or selected Provider may already have received it. These rules cannot prevent or retract that disclosure and must not claim the content was never uploaded, sent, logged, retained, deleted, or recalled.