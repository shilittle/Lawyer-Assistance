# OpenCode integration: approved case workspace

The `approved_case_workspace` examples are separate from the public-only production defaults. They remain disabled because the exact backend and deployment qualification is not established; unqualified case execution must return `PROFILE_NOT_QUALIFIED`.

- Choose `opencode.approved-workspace.local.json` or `opencode.approved-workspace.remote.json` only after qualification.
- Copy `agents/lawyer-assistance-approved-workspace.md` into `.opencode/agents/` and merge `AGENTS.approved-workspace.md.example` into project rules.
- Keep sharing disabled, wildcard permissions denied, and require the exact 15-tool catalog.

Begin with a clean task that contains opaque IDs only. Do not attach/paste materials or let OpenCode read a host path. Case content is usable only from a direct current-task `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED`; generated case content is persisted only through `case_write_work_product` or `case_update_work_product`.

If raw content already reached the task, stop without tools, remove the contaminated task/attachment, follow retention cleanup, and create a new clean task. Agent rules cannot retract an earlier host or Provider disclosure and do not replace backend checks, ACLs, network isolation, or Provider governance.
