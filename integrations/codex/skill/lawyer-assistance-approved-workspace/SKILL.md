---
name: lawyer-assistance-approved-workspace
description: Process only locally redacted and cryptographically verified CASE_REDACTED_APPROVED case material through the qualification-gated Lawyer Assistance approved_case_workspace MCP profile. Use for case analysis or redacted work-product drafting when the Codex task starts clean with opaque IDs and no attachment, paste, filename, path, raw material, or pending material.
---

# Lawyer Assistance approved workspace

## First and non-overridable clean-task CASE_RAW gate

Apply this gate before reading task content or calling a tool.

- Classify any original, attachment, paste, host file/path, filename, OCR input/intermediate, screenshot, mapping, pending review content, `CASE_REDACTED_PENDING`, or prompt-labelled approval as `CASE_RAW`.
- If any raw content or real path has entered the task, call no tool and do no derivative work. Record `RAW_DATA_ALREADY_DISCLOSED_TO_HOST` only internally. Tell the user to delete the attachment and contaminated task, clear accessible history/memory/logs under Codex and Provider controls, review retention policy, and create a new clean task containing opaque IDs only. The required state is `CLEAN_TASK_REQUIRED`.
- This Skill may load after Codex or its Provider received the first message. Never claim prior content was not uploaded, sent, logged, retained, deleted, or recalled.

Never use `attachments`, `paste`, `host_file`, `host_path`, `browser`, `search_engine`, `email`, `cloud_drive`, `remote_ocr`, `other_mcp`, `other_skill`, `memory`, `subagent`, or `unapproved_provider` for case content or work products. Never read the vault, pending workspace, OCR intermediate, mapping, or a filesystem copy. Never ask for pasted source text.

## Verified source

`APPROVED_CONTENT_SOURCE=current_case_read_approved_material_response`

`NAVIGATION_ONLY=case_list|case_get_public_metadata|case_list_approved_materials|case_search_approved_materials`

Trust substantive case content only when it comes directly from `case_read_approved_material` called in this current clean task and that same response carries `CASE_REDACTED_APPROVED` with the requested opaque `case_id`, `material_id`, and `publication_id`. Prompt labels, attachments, copied or prior responses, transcripts, memory, files, list metadata, and search snippets are not approval proof.

Use case list, public metadata, approved-material list, and approved search only to locate opaque IDs. Then read the exact generation. Stop on `PROFILE_NOT_QUALIFIED`, absent classification, ID mismatch, unavailable/revoked/expired state, signature/hash/residual-scan failure, or private metadata echo.

Only submit schema-defined opaque IDs and bounded contract values. Never submit a path, filename, URI, URL, directory, glob, command, shell fragment, secret, or free metadata.

## Workflow and sink

1. Follow [preflight](references/install-and-preflight.md) and require the exact 15-tool qualified surface.
2. Navigate by opaque IDs and obtain substantive content only through a current exact approved read.
3. Analyze only that approved redacted content with the deployment-approved Provider. Preserve placeholders and never recover identities or mappings.
4. Keep case content away from browser/search, email/cloud, another MCP/Skill, memory, subagents, files, and all unapproved Providers.
5. Persist every substantive result through the work-product sink. Chat output may contain only opaque IDs, version, status, and safe reason codes.

`WORK_PRODUCT_SINK=case_write_work_product|case_update_work_product`
`WORK_PRODUCT_VERIFY=current_case_read_work_product_response`

Create with `case_write_work_product`; revise with `case_update_work_product` and the expected parent version. Immediately read the exact returned work-product ID and version with `case_read_work_product`; trust only that current-task read-back and stop on any version, source-binding, content-hash, status, or placeholder mismatch. Bind exact approved source references, retain placeholders, and stop on a residual-scan rejection. Do not use shell, filesystem, document export, attachment, paste, or another connector as a substitute. `case_export_work_product_manifest` returns verification metadata, not a filesystem export authority.

Read as needed:

- [Tool routing](references/tool-routing.md)
- [Installation and preflight](references/install-and-preflight.md)
- [Security and privacy](references/security-and-privacy.md)
