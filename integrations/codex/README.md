# Codex integration: public law only

The checked-in Codex examples expose only the `public_law_only` profile and exactly five read-only tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`.

A separate, disabled `approved_case_workspace` package is documented in [APPROVED_WORKSPACE.md](APPROVED_WORKSPACE.md). It does not relax these defaults and must return `PROFILE_NOT_QUALIFIED` until the App reports the exact qualification complete.

- `config.stdio.toml` starts the local binary with `--privacy-profile public_law_only` and also applies an exact five-tool client allowlist.
- `config.http.toml` applies the same client allowlist. Start the loopback HTTP server with `public_law_only`, then reject the connection unless `tools/list` is an exact five-item match.
- Merge `config.privacy-hardening.toml` so task history is not persisted and external-context memories are disabled. This reduces local retention; it does not make a selected Provider safe for case material.
- Install the complete `skill/lawyer-assistance` directory and run `codex mcp list` before use.

Codex may use this integration only for public legal research containing no client, case, document, attachment, path, or derived fact. `CASE_RAW`, `CASE_REDACTED_PENDING`, pending review, and label-only or verbally claimed `CASE_REDACTED_APPROVED` content must never be passed to the host, filesystem, network, MCP, Provider, connector, memory, or another agent.

This public-only package intentionally loads no approved session. Case-material, case-state, case-specific citation, write, and export workflows remain forbidden here even when the App has an approved generation. Use only the separate approved package in a new clean opaque-ID-only task after the App issues a current `srv_…` session; never paste, attach, or host-read the approved text.

If raw content was attached or pasted before the Skill loaded, Codex or its selected Provider may already have received it. The Skill cannot prevent or retract that disclosure and must not claim the material was never uploaded, sent, logged, retained, or that it was deleted or recalled.