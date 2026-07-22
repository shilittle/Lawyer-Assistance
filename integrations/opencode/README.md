# OpenCode integration: public law only

Both examples disable sharing and deny the `lawyer_assistance_*` wildcard before allowing exactly five read-only public-law tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`.

The separate examples in [APPROVED_WORKSPACE.md](APPROVED_WORKSPACE.md) remain disabled and qualification-gated. They do not relax this default; unqualified `approved_case_workspace` execution must return `PROFILE_NOT_QUALIFIED`.

- `opencode.local.json` explicitly starts the binary with `--privacy-profile public_law_only`.
- `opencode.remote.json` must connect only to a loopback server started with that profile. Reject the connection unless `tools/list` is an exact five-item match.
- Keep the wildcard permission set to `deny`; changing it to `ask` or `allow` would reopen tools outside this reviewed surface.
- Copy `agents/lawyer-assistance.md` to `.opencode/agents/lawyer-assistance.md`. Merge `AGENTS.md.example` into existing project instructions without overwriting unrelated rules.

OpenCode may use this integration only for public legal research containing no client, case, material, attachment, path, or derived fact. `CASE_RAW`, `CASE_REDACTED_PENDING`, pending review, and label-only or verbally claimed `CASE_REDACTED_APPROVED` content must not reach the host, filesystem, network, MCP, Provider, connector, memory, or another agent.

This public-only package intentionally loads no approved session, so case-material, case-state, case-specific citation, write, and export workflows are disabled here—even for locally approved App generations. The separate approved package may be used only in a new clean opaque-ID-only task with a current App-issued `srv_…` session; never attach, paste, or host-read the text.

If content was pasted or attached before the agent rules loaded, the host or selected Provider may already have received it. These rules cannot prevent or retract that disclosure and must not claim the content was never uploaded, sent, logged, retained, deleted, or recalled.