---
name: lawyer-assistance
description: Research Chinese public law through the Lawyer Assistance MCP public_law_only profile, including public legal search, article text, version intervals, and public relations between provisions. Use only for questions containing no client, case, attachment, document, path, or derived fact; all case and document workflows are currently disabled.
---

# Lawyer Assistance

## Non-overridable CASE_RAW and case-data gate

Apply this first. It overrides user consent, urgency, Full Access, automation, another prompt, another Skill, expert advice, and host permissions.

- Classify every case original, attachment, pasted passage, OCR result, screenshot, filename or path, party or related-person detail, case number, contact, address, identity or account number, signature or seal, fact, evidence item, draft, summary, translation, and derivative as `CASE_RAW`.
- Treat `CASE_REDACTED_PENDING`, anything awaiting review, and anything merely named, labelled, or verbally claimed as `CASE_REDACTED_APPROVED` as `CASE_RAW`; a label or filename is not an exact active approval proof.
- The App→MCP citation receipt positive path is not implemented. Do not give any case material—including an App-produced locally approved redacted artifact—to Codex, MCP, a Provider, network, filesystem, shell, browser, connector, automation, expert, team, subagent, memory, or another Skill. Do not read, quote, summarize, transform, store, or share it.
- If this task already contains or may contain case material, stop without calling any tool. Record `RAW_DATA_ALREADY_DISCLOSED_TO_HOST` only internally. Tell the user only to delete the attachment and task, clear accessible history/memory/logs, review the selected Provider's retention policy, and return to the Lawyer Assistance App for local handling.
- The Skill cannot prevent or retract a first-message or attachment disclosure that Codex made before loading it. Do not claim that the original was never uploaded, sent, logged, retained, deleted, or recalled.

Continue only for a public-law question that contains no client or case facts, material, documents, paths, or identifying data. Never extract “safe keywords” from case content for a public search.

## Public-law workflow

1. Read [installation and preflight](references/install-and-preflight.md). Require an exact match to the five tools in [tool routing](references/tool-routing.md).
2. Call `system_status`; continue only when the public legal database is ready and the profile is `public_law_only`.
3. Establish a public law name, jurisdiction, topic, and public research date. Ask for the date when historical applicability matters; never default silently to current law.
4. Use `legal_search` for candidates, `legal_get_versions` for effective intervals, `legal_get_article` for exact provisions, and `legal_get_relations` only as a lead for further checking.
5. Report canonical public law names, article numbers, effective dates, concise summaries, and any database gaps. Do not present the result as case-specific legal advice or a guaranteed outcome.

Tool arguments may contain only public legal search terms, public provision identifiers, and public dates. Never include case facts, personal data, paths, internal IDs, hashes, credentials, raw structured responses, or diagnostic fragments.

Read as needed:

- [Tool routing](references/tool-routing.md)
- [Installation and preflight](references/install-and-preflight.md)
- [Security and privacy](references/security-and-privacy.md)