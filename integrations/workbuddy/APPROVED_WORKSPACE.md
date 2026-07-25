# WorkBuddy approved case workspace

The approved handlers and App-issued session chain are implemented, but this package remains disabled with an unusable checked-in placeholder. Use it only after the Lawyer Assistance App reports the exact current `approved_case_workspace` qualification, publishes the approved generation, and creates a live standalone session. Missing or stale state fails closed with `PROFILE_NOT_QUALIFIED`; this document and the placeholder grant no authorization.

Import only `connectors/approved-case-workspace/stdio.windows.json`, replace `<APP_ISSUED_SERVER_ID>` with the exact opaque `srv_[0-9a-f]{32}` ID created by the App, then upload the complete `skill/lawyer-assistance-approved-workspace` directory. Do not add environment variables, database/root/config paths, bearer tokens, bind/origin settings, or an HTTP connector. Do not combine this Skill with the public-only Skill in one case task. Require an exact 21-tool `tools/list` match against `../tool-catalog.approved-case-workspace.json`; call-time authority still comes only from the session's selected grant groups.

Never attach or paste case material into WorkBuddy. Start a clean task with opaque IDs only. The Skill accepts case content solely from the current task's direct `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED`; it persists generated content solely through `case_write_work_product` or `case_update_work_product` and immediately verifies the exact returned version through `case_read_work_product`.

This Skill is a defense in depth. It does not create OS isolation, stop a same-user process from reading an accessible path, approve a Provider, or retract data disclosed before the Skill loaded.
