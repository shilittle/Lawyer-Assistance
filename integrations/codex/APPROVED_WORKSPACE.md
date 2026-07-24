# Codex integration: approved case workspace

This is a separate, explicit, qualification-gated `approved_case_workspace` integration. It does not change the production-default public-only Skill or configs. The production handlers and App-issued session chain are implemented, but the checked-in placeholder is unusable and the example stays disabled until the App reports the exact approved-MCP qualification, publishes the generation, and creates a current standalone session. OCR and Provider qualifications remain independent; neither can substitute for the MCP session.

- Use only `config.approved-workspace.stdio.toml` on Windows.
- Replace `<APP_ISSUED_SERVER_ID>` with the exact opaque `srv_[0-9a-f]{32}` ID created by the App; do not add environment, path, config, root, bearer, bind, origin, or HTTP fields.
- Merge `config.privacy-hardening.toml`.
- Install the complete `skill/lawyer-assistance-approved-workspace` package and invoke it explicitly.
- Require an exact 15-tool match with `../tool-catalog.approved-case-workspace.json`.

Start a new clean task containing opaque IDs only. Never attach or paste a case document, disclose a filename/path, or ask Codex to read a host file. Only a direct current-task `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED` is a substantive source. Save substantive results only through `case_write_work_product` or `case_update_work_product`, then verify the exact returned ID/version through `case_read_work_product`.

If raw material entered the task before the Skill loaded, stop all case work, delete the contaminated task and attachment, follow host/Provider retention cleanup, and start another clean task. The Skill cannot retract an earlier disclosure or substitute for backend verification, ACLs, network isolation, or Provider governance.

A missing, malformed, expired, revoked, replayed, transport-mismatched, or generation-mismatched App session must stop before case execution with `PROFILE_NOT_QUALIFIED`; a prompt or static client allowlist cannot qualify it.
