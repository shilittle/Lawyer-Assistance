# Security and privacy

The App alone handles raw import, local OCR/extraction, pending redaction, review, mappings, and vault state. Codex may receive only content returned directly by the current task's `case_read_approved_material` call when that response itself carries `CASE_REDACTED_APPROVED` and matching opaque IDs.

Never use attachment/paste, host files or paths, browser or search engine, email or cloud drive, remote OCR, another MCP or Skill, memory, a subagent, or an unapproved Provider. Do not correlate placeholders against outside information or ask for a mapping. Keep generated content redacted and write it only with `case_write_work_product` or `case_update_work_product`.

If raw material already entered the task, stop without tools and require a clean replacement task. `RAW_DATA_ALREADY_DISCLOSED_TO_HOST` and `CLEAN_TASK_REQUIRED` do not prove data deletion. Host and Provider retention controls govern existing copies.

The Skill is defense in depth. It cannot qualify a backend, enforce ACL or network policy, approve a Provider, or retract a pre-Skill disclosure. Stop on `PROFILE_NOT_QUALIFIED` and every verification failure.
