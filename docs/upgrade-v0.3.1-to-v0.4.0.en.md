# Upgrade from v0.3.1 to v0.4.0

This guide applies only to a local workspace produced by the official `v0.3.1` data model and still preserving the exact User schema 10 and Privacy schema 1 profile. The upgrader authenticates the complete schema, business data, and provenance. It fails closed on an ambiguous database, a hand-edited schema, a mixed-version directory, or an incomplete recovery state; it never guesses provenance or continues writing.

The repository contains the stable `0.4.0` source candidate. Treat downloaded artifacts as the stable release only after the official Release provides the frozen signed asset set and every signing, CI, server-readback, clean-machine, and final MinerU gate has completed.

## Before upgrading

1. Exit v0.3.1 completely and confirm that no Lawyer Assistance or MCP process remains active.
2. Preserve the whole v0.3.1 application-data directory. Do not copy, edit, or replace individual SQLite, Privacy, or recovery files.
3. Start v0.4.0 as the same Windows user. Recovery evidence is protected for Windows CurrentUser and cannot be generated or applied by another account.
4. Do not pre-create the Vault, approved workspace, or work-products directories. These three target components must be authentically absent from an exact v0.3.1 profile.

## First upgrade

Before ordinary application startup, v0.4.0 identifies the exact v0.3.1 profile. Before any source write it creates and authenticates a five-slot original-state recovery point: User v10 and Privacy v1 are present; Vault, Approved, and WorkProducts are absent. It then creates the target components, migrates Privacy, creates the audited one-to-one `ProjectId ↔ PrivacyCaseId` binding, migrates materials and projections, and only then upgrades User schema 10 to 11 in the final transaction.

Do not terminate the process or copy/edit the data directory during the upgrade. If the process ends unexpectedly, start the same v0.4.0 again. Startup arbitration uses authenticated receipts and the actual five-slot state to resume or recover from the sole safe phase. It never performs a SQL down-migration or restores only one database.

After completion, verify that:

- the original projects, conversations, messages, and Privacy reviews remain readable;
- the backend persists project-to-Privacy-case bindings, while the frontend never displays, generates, or infers an authoritative Privacy CaseId;
- Vault, approved workspace, and work-products use their target schemas; and
- another restart creates no duplicate binding, material, generation, or terminal receipt.

An exact v0.3.1 local review may not contain a recoverable source display name or Privacy CaseId. Such a material remains explicitly unassigned until the user assigns it. The application may show an authenticated “legacy name unavailable” placeholder; it does not fabricate the old filename or infer a binding from hashes.

## Explicitly restore v0.3.1

Full recovery is a maintenance operation, not an ordinary `.lavbackup` restore. It is available only after a completed upgrade and re-authentication of the current five slots. In the v0.4.0 maintenance view, choose recovery and type exactly:

```text
恢复到 v0.3.1 并退出当前应用
```

The frontend sends only this phrase—never a path, lineage, Privacy CaseId, credential, or backup bytes. The backend creates a current-v0.4.0 five-component Safety backup and a four-credential archive, closes new MCP/standalone admission, drains current work, revokes active standalone sessions, and completes a final proof inside all write barriers. After the formal recovery marker is installed, the process requests a controlled restart and never reopens business writes in that session.

The next launch is recovery-only: ordinary managers, UI, maintenance, and background work do not initialize. The recovery engine swaps all five physical slots in a fixed order. Before commit, a failure follows authenticated abort intent to restore the complete v0.4.0 state; after commit, it may only continue cleanup and cannot expose a mixed state. Once the completion report is installed and authenticated, the application exits successfully.

User is then restored to the exact schema-10 bytes and Privacy to the exact schema-1 bytes from the original bundle. Vault, Approved, WorkProducts, and the four v0.4.0 credentials are absent. The original V2 bundle, current Safety V3, credential archive, commit/abort/report records, and migration reports remain in the audit namespace; none is a later-upgrade terminal marker.

## Reopen and upgrade again

1. Explicitly start v0.3.1, verify the original project, conversation, message, and Privacy review data, then exit normally.
2. To return to v0.4.0, explicitly start the same v0.4.0. It identifies the exact v0.3.1 profile again, creates a new lineage, and performs the full upgrade.
3. Restart v0.4.0 once more and confirm that the terminal state is idempotent.

Never pass a migration-only original-state bundle to ordinary V3 restore. Ordinary restore must reject old schemas and migration-only identity. Do not move, rename, edit, or delete pending, incoming, rollback, cleanup, or audit files. If startup reports a recovery or provenance-authentication error, preserve the entire data directory and the anonymous error code, stop all writes, and follow the controlled support process. Do not bypass fail-closed behavior by editing a database or deleting a marker.
