# OpenCode integration: approved case workspace

The `approved_case_workspace` example is separate from the public-only production defaults. Its handlers and App-issued session chain are implemented, while the static example remains disabled with an intentionally unusable placeholder. Only a current App-qualified standalone session executes case tools; missing or stale state returns `PROFILE_NOT_QUALIFIED`.

- Use only `opencode.approved-workspace.local.json` on Windows after qualification.
- Replace `<APP_ISSUED_SERVER_ID>` with the exact opaque `srv_[0-9a-f]{32}` ID created by the App. Do not add environment variables, database/root/config paths, bearer tokens, bind/origin settings, or remote/HTTP transport.
- Copy `agents/lawyer-assistance-approved-workspace.md` into `.opencode/agents/` and merge `AGENTS.approved-workspace.md.example` into project rules.
- Keep sharing disabled, wildcard permissions denied, and require the exact 15-tool catalog.

Begin with a clean task that contains opaque IDs only. Do not attach/paste materials or let OpenCode read a host path. Case content is usable only from a direct current-task `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED`; generated case content is persisted only through `case_write_work_product` or `case_update_work_product` and verified immediately through exact-version `case_read_work_product`.

If raw content already reached the task, stop without tools, remove the contaminated task/attachment, follow retention cleanup, and create a new clean task. Agent rules cannot retract an earlier host or Provider disclosure and do not replace backend checks, ACLs, network isolation, or Provider governance.
