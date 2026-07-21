# WorkBuddy approved case workspace

Use this package only after the Lawyer Assistance App reports that the exact `approved_case_workspace` qualification is complete. The checked-in backend currently fails closed with `PROFILE_NOT_QUALIFIED`; this document does not claim production authorization.

Import one connector from `connectors/approved-case-workspace`, then upload the complete `skill/lawyer-assistance-approved-workspace` directory. Do not combine it with the public-only Skill in one case task. Require an exact 15-item `tools/list` match against `../tool-catalog.approved-case-workspace.json`.

Never attach or paste case material into WorkBuddy. Start a clean task with opaque IDs only. The Skill accepts case content solely from the current task's direct `case_read_approved_material` response carrying `CASE_REDACTED_APPROVED`, and persists generated content solely through `case_write_work_product` or `case_update_work_product`.

This Skill is a defense in depth. It does not create OS isolation, stop a same-user process from reading an accessible path, approve a Provider, or retract data disclosed before the Skill loaded.
