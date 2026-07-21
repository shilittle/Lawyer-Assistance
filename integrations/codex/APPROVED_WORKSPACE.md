# Codex integration: approved case workspace

This is a separate, explicit, qualification-gated `approved_case_workspace` integration. It does not change the production-default public-only Skill or configs. The backend currently returns `PROFILE_NOT_QUALIFIED`, so the example configs are disabled and must remain disabled until the App reports the exact isolation, manifest-trust, Provider, and model qualifications complete.

- Choose `config.approved-workspace.stdio.toml` or `config.approved-workspace.http.toml`.
- Merge `config.privacy-hardening.toml`.
- Install the complete `skill/lawyer-assistance-approved-workspace` package and invoke it explicitly.
- Require an exact 15-tool match with `../tool-catalog.approved-case-workspace.json`.

Start a new clean task containing opaque IDs only. Never attach or paste a case document, disclose a filename/path, or ask Codex to read a host file. Only a direct current-task `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED` is a substantive source. Save substantive results only through `case_write_work_product` or `case_update_work_product`.

If raw material entered the task before the Skill loaded, stop all case work, delete the contaminated task and attachment, follow host/Provider retention cleanup, and start another clean task. The Skill cannot retract an earlier disclosure or substitute for backend verification, ACLs, network isolation, or Provider governance.
