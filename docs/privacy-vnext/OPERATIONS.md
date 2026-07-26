# Privacy vNext operations guide

Updated: 2026-07-22
Applies to: Lawyer Assistance `0.4.0-beta.2` on Windows x86_64

This guide describes the implemented production paths. It does not grant qualification by itself. The App's current backend status, signed evidence, current-machine remeasurement, revocation state, and exact purpose/session binding are authoritative. All acceptance fixtures must be synthetic. Never use a real client file to prove a release, and never send raw or pending material to a browser, search engine, remote OCR service, external MCP, Skill, memory, subagent, log, or test service.

## 1. State and trust boundaries

The privacy workflow separates these states:

- `CASE_RAW`: source bytes, native extraction, OCR, filenames, paths, private metadata, and any unreviewed derivative. Local App only.
- `CASE_REDACTED_PENDING`: automatically detected or manually edited text before final residual scan and human approval. Local App only.
- `CASE_REDACTED_APPROVED`: one immutable approved generation whose content, policy, provenance, purpose, destination, expiry, and revocation epoch are cryptographically bound. It is not a general permission to paste or upload the text.
- Approved MCP and Provider authorization: a separate, short-lived, exact authorization derived from an active approved generation. It cannot be replaced by a prompt label, consent, broad host permission, a filename, or copied text.

The frontend exchanges opaque IDs and bounded enums. Rust restores protected content and credentials, verifies every binding immediately before use, and never returns signing keys, session secrets, receipt tokens, database paths, or raw OCR to the browser layer.

## 2. Local MinerU OCR qualification

### Prerequisites

For final deployment, use only an App-managed v4 component imported from its
explicitly approved and signed offline set. No final v4 set or final v4 hash is
published yet: it must be rebuilt deterministically, reviewed, signed, installed
under a short root, remeasured and GPU-probed before App qualification.
Historical candidates are permanently excluded from publication and must not be
substituted. Download only the complete catalog/signature/descriptor/parts set
from an official Release and import it locally; never place a GitHub token in
catalog, configuration, or case metadata. Component download is distinct from
OCR: it accepts no case material or arbitrary URL and never sends a case
identifier, path or content. The OCR flow has no HTTP OCR, SSH OCR, cloud OCR or
remote fallback. Worker, tools configuration, runtime executables, model tree
and Windows Firewall state must all be ordinary local objects: UNC paths, cloud
placeholders, reparse points, symlinks and disallowed hard links fail closed.
Every final installed component path must be at most 259 UTF-16 code units.

### App sequence

1. Open **隐私与本地处理** and run **发现本机安装**. Discovery only inspects fixed local candidates and creates a minimal offline configuration; it does not run OCR or authorize production.
2. Select the OCR routing policy and save:
   - `disabled`: visual OCR is unavailable.
   - `auto_local`: only pages that fail the reliable native-text threshold route to the qualified local worker.
   - `force_local`: every PDF page routes to the qualified local worker.
3. Review the local worker path, tools JSON, model root, explicitly listed runtime executables, language, GPU/device, timeout, and page limit. Save before qualification.
4. Select **1. 建立当前安装信任**. The App inventories and hashes the worker, tools configuration, every declared runtime executable, and the complete model file set, then persists signed local trust evidence. Extra, missing, replaced, linked, or changed files invalidate trust.
5. Select **2. 安装并复核网络隔离**. The App invokes the fixed Windows Firewall helper, installs outbound-block rules for the exact process set, then re-reads the ActiveStore. A cancelled elevation, disabled firewall profile, missing rule, path/hash drift, or verification mismatch leaves network isolation unqualified and rolls back the requested rule set.
6. Set an explicit qualification lifetime and check the production-case authorization box. This is a deliberate user action; it does not auto-approve a document.
7. Select **3. 运行 canary 并签发资格**. The App runs only the fixed synthetic canary through the local worker, verifies the bounded output, binds the result to the current app/policy/worker/config/runtime/model/firewall measurements, signs it with the local protected key, and persists it.
8. Refresh status. Continue only if the backend reports the required individual gates as qualified. A green discovery result alone is insufficient.

`auto_local` and `force_local` have real ingestion behavior only while the complete qualification remains current. If it is absent or becomes invalid, a PDF that needs visual OCR fails closed; it never silently falls back to native low-quality text or a remote service.

### Release qualification boundary

Package/catalog provenance binds the source commit, build-script SHA-256,
worker-source-tree SHA-256, selected runtime distributions and exact model
revisions. A final v4 package has not been published, so this guide intentionally
records no final v4 artifact hash. A release still requires deterministic
rebuild, explicit provenance approval, signing, short-root installation,
installed-tree remeasurement, GPU probe, and the complete App-owned Windows
Firewall/Job Object/canary/restart qualification.

For the final signed-component install/remeasure gate, set the package SHA from
the independently measured packager result (not by blindly copying an
unsigned catalog field), then verify that the detached-signed catalog and
descriptor bind the same value:

```powershell
$env:LA_REAL_MINERU_COMPONENT_RELEASE_DIRECTORY = 'C:\path\to\signed-release'
$env:LA_REAL_MINERU_COMPONENT_OFFLINE_SET_DIRECTORY = 'C:\path\to\offline-set'
$env:LA_REAL_MINERU_COMPONENT_STATE_DIRECTORY = 'C:\short\component-state'
$env:LA_REAL_MINERU_COMPONENT_EXPECTED_PACKAGE_SHA256 = '<64-lowercase-hex-from-independent-build-record>'
cargo test --locked --offline -p lawyer-assistance-desktop `
  mineru_components::tests::real_signed_sharded_release_imports_installs_and_remeasures `
  -- --ignored --exact --nocapture --test-threads=1
```

The test rejects a missing, uppercase, padded, malformed, or stale expected
hash. It also revalidates the signed catalog, dynamic part inventory, package
manifest binding, installed tree, and activation state; no historical v3/v5
hash may be supplied.

Historical diagnostics did not run inside that complete production chain. The
259 UTF-16 preflight gate rejects an unsafe long-path component layout before
extraction. Do not process a real scanned case unless the App currently reports
every required production qualification gate as valid.

### Automatic invalidation

Qualification is reloaded at startup and remeasured before use. It becomes unusable on expiry, explicit revocation, application or policy-version mismatch, worker/config/runtime/model path or hash change, model inventory change, firewall rule/profile change, signed-evidence tampering, environment mismatch, or a failed pre/post-launch identity check. Revocation advances the local epoch so previously derived OCR, MCP, or Provider authorization cannot revive it.

### Document processing

After qualification, select a local PDF/DOCX/TXT/Markdown file in the App. The backend chooses reliable native extraction or qualified OCR, validates page count, order, dimensions, bounding boxes, confidence, output file count/size, and provenance, then creates a unified local review document. Missing pages, malformed geometry, low confidence, unexpected output, timeout, cancellation, process escape, hash drift, or isolation loss fail closed.

OCR is preparation, not approval. Review every page in the side-by-side workbench, add explicit subject terms where needed, resolve page warnings, run the residual-risk check, and approve the exact generation manually.

## 3. Safe approval and exports

Approval binds the exact reviewed content and its source/extraction/OCR/policy/finding/mapping provenance. Later edits create a new generation; a stale receipt cannot approve changed bytes.

From an active approved generation, export through the native save dialog by selecting one of:

- reconstructed text PDF;
- DOCX rebuilt from approved text;
- UTF-8 TXT;
- Markdown.

The frontend sends only `{ redactionId, format }`. Rust reloads the approved payload and receipt, builds a new file, validates the destination, refuses overwrite/reparse/cloud/hardlink targets, reopens the installed file, re-extracts or parses it, compares content/hash, reruns residual scanning, and records an export audit bound to the generation. DOCX output does not carry source comments, tracked revisions, custom XML, external relationships, embedded objects, or source metadata. These are reconstructed safe formats, not a claim of pixel-perfect source-layout preservation.

Revoking the approval makes subsequent export, MCP publication, Provider dispatch, and protected output access fail closed. It does not delete the user's original source file or a separately saved export.

## 4. Approved MCP workflow

The default MCP remains `public_law_only`. Approved case work is a separate flow:

1. In the App, publish the active approved generation to the approved workspace for the exact case/material scope and permitted purpose.
2. Run the App's approved-MCP qualification canary. A formal build first hashes the exact paired MCP sibling and compiles that SHA-256 trust anchor into the same App; an unbound development App, a substituted binary, or a binary that only copies the expected name/version/canary behavior cannot qualify. Qualification and session state are then signed, persisted, bound to the current app/workspace/server binary identity/transport and revocation epoch, and reverified at use.
3. Create a policy-v2 standalone session with only the required grants: `read` authorizes the original eight case-read tools, `write` the original two case write/update tools, `diagram_read` four diagram list/schema/validate/export tools, and `diagram_write` two diagram render/update tools. Existing `read` / `write` grants never include diagram access. The UI displays only an opaque server ID matching `srv_[0-9a-f]{32}`; it never displays the DPAPI-protected descriptor, Credential Manager secret, bearer, database path, workspace path, or ticket.
4. Put only that server ID into the host's disabled Windows stdio template and retain the exact command:

   ```text
   lawyer-assistance-mcp --privacy-profile approved_case_workspace --approved-session-id <APP_ISSUED_SERVER_ID> stdio
   ```

   Do not add config, database, root, path, environment, bearer, bind, origin, HTTP, or escape-hatch options.
5. Start a new clean host task containing opaque IDs only. Require the exact 21-tool catalog: five public-law tools, ten approved workspace tools, and six approved-diagram tools.
6. Use list/search/public metadata only to navigate opaque IDs. Trust substantive material only from the current task's direct `case_read_approved_material` response for the exact generation and carrying `CASE_REDACTED_APPROVED`.
7. Create or update ordinary work only with `case_write_work_product` or `case_update_work_product`. For a real approved-case diagram, use only this profile's `diagram.validate`, `diagram.render`, `diagram.update`, and `diagram.export`: render/update publish encrypted protected `text/html` work-product versions; export returns verified descriptor metadata only, never HTML, a path, or a URI. Immediately reread the returned exact ID/version. Work products are immutable versions with optimistic concurrency, idempotency, journal recovery, residual scan, and exact approved-source binding.
8. Revoke the generation or standalone session in the App when done.

The separate `diagram_authoring` profile is permanently synthetic/public and writes a plaintext local HTML bundle. Never use it as a fallback for a real, pending, or approved case. Every approved call uses a short-lived App-issued ticket bound to the server instance, transport, tool, schema, purpose, canonical request bytes, destination, target IDs/generation, nonce, expiry, and revocation epoch. Consumption is persisted before execution to prevent replay. Missing qualification/session/ticket, mismatch, expiry, revocation, replay, manifest/signature/hash failure, or residual output failure returns an anonymous error and no case content. Both MCP result channels are scanned independently.

### Policy v2 / replay-journal V2 migration and recovery

Approved-MCP policy v2 and replay-journal V2 are breaking standalone-session boundaries. Before using this version, stop all older approved MCP host processes, revoke every old standalone session in the App, and create fresh policy-v2 sessions with explicit grants. V1 Credential Manager state and `standalone-wire-replay-v1.sqlite` are deliberately never read, authenticated as V2, auto-migrated, rolled back, renamed, or replayed. Explicit revocation best-effort deletes the exact V1 and V2 credential targets and the exact fixed local V1/V2 replay files. If any target is a link, is busy, cannot be verified, or cannot be removed, revocation reports failure and the session remains unusable; resolve the local filesystem condition and revoke again before reprovisioning.

For each new wire reservation, the sibling first writes an authenticated pending transition to Windows Credential Manager, then commits the one expected SQLite tail row, then compare-and-swap advances the authenticated credential head, and finally compare-and-swap clears the pending transition. The pending record binds the server, session, database ID, revocation epoch, old and new count/head, exact expected tail MAC, wire/ticket-request digests, and a random nonce. It contains no case body, raw request body, access ticket, signing key, bearer, or other ticket secret.

Restart recovery completes only an authenticated pending transition whose database is the exact single next valid tail. A crash after the pending write but before the database commit remains fail closed; the pending record is not silently cleared. A missing pending record with an advanced database, a missing row, more than one added row, fork, rollback, old/new-head mismatch, session/epoch mismatch, invalid MAC, or any ambiguous state also remains fail closed. Do not edit or copy either store. Revoke and reprovision the session. Revocation/reconfiguration cannot be undone by a stale sibling because every credential update is an exact compare-and-swap under the cross-process credential-store lock.

Streamable HTTP is brokered by the App for controlled acceptance and is not distributed as a static host credential. Static WorkBuddy, Codex, and OpenCode approved assets are Windows stdio only.

## 5. Approved Provider workflow

Ordinary case-bearing `ChatRequest` values remain blocked before serialization. The approved path is separate:

1. Save the Provider profile and credential using the normal Provider settings. The credential remains in Windows Credential Manager.
2. In **已批准案件 Provider 正链**, select the saved profile and one fixed task. Free-form purposes are not accepted. Supported fixed tasks cover summary, legal analysis, chronology, document outline, structured extraction, assistant response, case organization, case legal Q&A, relationship graph, document generation, regenerate, and repair.
3. Run and persist Provider qualification. The canary binds the exact Provider kind, endpoint origin, model, adapter behavior, app/policy version, and current revocation epoch; restart reload and remeasurement are mandatory.
4. Select an active approved redaction generation, the exact fixed task, expiry and output limit; check the explicit per-generation confirmation; then sign the precise Provider/purpose approval.
5. Dispatch using only the opaque redaction ID, saved Provider ID, fixed task enum, and output limit. Rust restores the protected payload and receipt and revalidates content hash, generation, Provider, endpoint, model, purpose, policy, detector/OCR provenance, expiry, and revocation immediately before transport.
6. The response is bounded, residual-scanned, and stored as a protected approved output bound to the request/workflow. List, open, or revoke it from the same panel.

Any naked case request or mismatch fails before network serialization, so the rejected path sends zero HTTP requests. Provider qualification is independent of OCR and approved MCP qualification; passing one never authorizes another.

## 6. Lifecycle, mapping, retention and backup

Open **隐私生命周期、映射与加密备份** to manage:

- separate retention periods for review payloads, mappings, approved content/work products, and backups;
- per-redaction legal hold, which pauses expiry cleanup but grants no read or egress permission;
- retention sweeps with verified hash-chain/journal recovery;
- one-time mapping reveal after the exact confirmation phrase; UI state is cleared on hide, blur, navigation, or page visibility loss;
- mapping revocation, mapping-key rotation, and selected retired-key cryptographic destruction;
- approved generation/work-product revocation and expired OCR-intermediate cleanup.

Logical deletion and cryptographic key destruction are claimed only at those layers. The product does not claim forensic erasure of SSD cells, filesystem history, external backups, host caches, or already disclosed copies. `SQLite secure_delete=ON` is not represented as forensic deletion.

For ordinary disaster recovery, use **完整应用加密备份** (`.lavbackup`) V3. A new backup snapshots and binds five components as one authenticated outer set:

1. `user.sqlite`;
2. the encrypted privacy bundle;
3. a canonical ciphertext-only archive of the encrypted case Vault, created without decrypting source objects;
4. an approved-workspace archive containing committed active generations only; and
5. an encrypted work-products archive containing committed active versions only.

A fresh AES-256-GCM outer key is wrapped with Windows DPAPI CurrentUser; every component has independent 8 MiB chunk AAD. Backup ID, workspace, app/schema versions, timestamps, all five component hashes/sizes/chunk counts, and the Vault, approved-workspace and work-products manifest hashes are authenticated. Ticket/session/qualification state, logs, temporary/staging state and rollback residue are excluded. The UI never receives a filesystem path.

- **导出完整加密备份** creates a new local fixed-drive file and rereads it.
- **选择并验证完整备份** authenticates all five V3 components without modifying live stores. A V2 bundle is recognized only for read/restore compatibility and has its historical three-component shape.
- **选择完整备份并暂存恢复** requires the exact confirmation phrase and returns `restart_required=true`. It stages the databases, Vault, approved workspace and encrypted work products in fixed local paths and never hot-overwrites live state.
- On restart, all components are reverified. Every staged Vault object and work-product generation is authenticated under its own store contract before commit; plaintext verification buffers are zeroized. The two databases, Vault, approved workspace and encrypted work-product store then advance as one recoverable five-component transaction. Incoming, rollback, swap and recovery slots cover all five components. An interruption resumes safely; any failure rolls back all five.
- A successful V3 restore rotates the MCP ticket key and qualification revocation epoch and revokes authenticated standalone sessions. Restored content never revives prior egress authorization.

The `.lavprivacy` bundle is the privacy-database-only maintenance format. Prefer newly created `.lavbackup` V3 for complete application recovery. V2 three-component bundles remain read/restore-compatible only; legacy `.lavbackup` V1 fails closed. Pending legacy single-database, V2 and V3 restore states cannot coexist. All accepted formats reject tamper, wrong user/machine/workspace/app/schema binding, expiry, revocation, duplicates, overwrite, UNC/cloud/reparse/hardlink targets, and partial restore state. Vault, approved-workspace and work-product export/staging additionally enforce canonical strict path allowlists, file-count/size bounds, regular-file/single-link identities and committed-active-state checks.

## 7. WorkBuddy, Codex and OpenCode

Public-only and approved packages are intentionally separate. Never combine both Skills/Agents in one case task. The approved package does not permit attachments, paste, host file reads, browser/search, cloud storage, remote OCR, another MCP/Skill/connector, shell reconstruction, memory, subagent, team, or unapproved Provider. It starts with opaque IDs and receives approved text only from the direct current MCP response.

If raw/pending material, a filename/path, attachment, pasted source, or copied old response has already entered the task, stop every case tool and derivative action. Delete the contaminated task/attachment where the host permits, clear accessible history/memory/logs, review host and Provider retention policy, and start a new clean task. A Skill cannot prevent or retract disclosure that happened before it loaded.

Validate packages before release:

```powershell
python integrations\validate_examples.py
python -m unittest integrations.test_validate_examples
python integrations\validate_approved_workspace_examples.py
python -m unittest integrations.test_validate_approved_workspace_examples
```

## 8. Release acceptance boundary

Run only repository-generated synthetic documents and canaries. Record machine qualification separately from code test results. A release statement must distinguish `CODE_COMPLETE`, `E2E_COMPLETE`, `EXTERNAL_CREDENTIAL_BLOCKED`, and final `COMPLETE`; it must not convert a schema, fail-closed negative test, historical single-page canary, or packaging success into a positive business-flow claim.

From a clean final commit, build and verify the credential-free Windows artifacts independently:

```powershell
pnpm --filter @lawyer-assistance/desktop release:portable
pnpm --filter @lawyer-assistance/desktop release:installer:unsigned
cargo build --release --locked --offline -p legal-mcp --bin lawyer-assistance-mcp
python scripts\package_mcp_release.py --target x86_64-pc-windows-msvc --binary target\release\lawyer-assistance-mcp.exe
```

The unsigned NSIS command emits the explicitly named
`Lawyer.Assistance_<version>_windows-x86_64-unsigned-setup.exe`, adjacent
`.sha256`, and `.manifest.json`. It refuses updater-signing secrets, verifies
the executable and installer are `NotSigned`, records `signed=false` and
`updaterArtifactGenerated=false`, and does not generate `latest.json` or an
updater `.sig`.

The stable signed-release workflow is documented in
`docs/development/release-signing.md`; its executable preflight is
`scripts/release/release_preflight.ps1`. Signing and updater secrets are
external release credentials and are never stored in the repository. Their
absence does not block privacy feature development or explicitly unsigned
technical artifacts.
