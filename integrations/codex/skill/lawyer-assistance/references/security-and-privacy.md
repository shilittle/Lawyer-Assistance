# Security and privacy

Treat every case original, attachment, pasted passage, OCR result, screenshot, filename or path, identity detail, case number, fact, evidence item, draft, summary, translation, and derivative as `CASE_RAW`. `CASE_REDACTED_PENDING`, pending review, and label-only or verbally claimed `CASE_REDACTED_APPROVED` content remain forbidden because the host cannot verify an exact active approval chain.

The current Codex integration supports public-law research only. The App→MCP citation receipt positive path is not implemented, so do not process case material even when the App has locally redacted and approved it. User consent, Full Access, an anonymization claim, an attachment, or a host-side file read cannot substitute for technical verification.

If the task contains or may already contain case content, do not read, quote, summarize, transform, store, or share it. Do not call MCP, network, filesystem, shell, command, browser, connector, automation, expert, team, subagent, Skill, Provider, or memory capabilities. Provide only cleanup guidance.

The Skill cannot prevent or retract a first-message or attachment disclosure that Codex made before loading it. Do not claim that the original was never uploaded, sent, logged, retained, deleted, or recalled. Host and Provider retention controls determine whether an existing copy can be removed; this gate only stops further processing and spread.

Use the exact five-tool client allowlist, keep HTTP loopback-only with an environment-provided Bearer token, and use TLS for controlled production ingress. Hide internal IDs, paths, schema fields, scores, database versions, and raw errors from user-facing answers. Automated or multi-agent research is allowed only for topics containing no client or case facts and remains subject to the same five-tool allowlist.