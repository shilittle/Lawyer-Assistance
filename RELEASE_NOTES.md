# Lawyer Assistance 0.4.0

## 中文概览

这是 Lawyer Assistance `0.4.0` 稳定版本目标的发行说明。当前仓库已固定稳定源码与发布契约；只有 exact final `main`、签名资产、服务端回读、Windows 10/11 干净机和最终 MinerU 门禁全部取得真实证据后，对应 GitHub Release 才能提升为 stable/latest。在此之前不得把源码候选或未签名产物称为正式发布。

默认 MCP 表面仍只开放只读公共法律检索，但应用内三种执行模式各自使用独立边界：普通聊天无需案件或资格授权，只向所选 BYOK Provider 发送用户主动输入和本次显式选择的普通附件；案件助理只使用当前案件本次显式选择的 approved/current generation 和最小已确认数据；只有 approved automation/MCP 继续要求完整 qualification、grant、ticket 与受保护成果链。

- 安装包和便携包内置 runtime-slim 法律数据库，可直接完成公共法律检索；完整归档数据库不随桌面发行版分发。
- 本地 MinerU OCR 已接入资格校验流程；生产级 OCR 资格仍要求独立 component Release 的最终批准资产、签名链、GPU/driver 与当前机器资格证据。
- 正式 App Release 只接受 Authenticode/RFC3161 已验证的 installer、App 与 paired MCP，并要求 updater `.sig` 精确绑定已签名 installer bytes。仓库内不保存这些私钥。
- 仓库验收只使用合成数据。真实或待审核案件材料不得进入 GitHub、浏览器/搜索引擎、远程 OCR、云存储或任何未经批准的 Provider、MCP 与自动化上下文。
- 请通过发布页提供的 SHA-256 文件核对下载完整性，并阅读[发布状态](docs/release-status.md)与[入门指南](docs/getting-started.md)了解支持边界和安装步骤。

> **Stable `0.4.0` release contract.** The repository has frozen the stable source and asset contract, but a GitHub Release may be promoted to stable/latest only after exact-final-main CI, real signing, server readback, clean-machine, and final MinerU evidence exist. This release separates `interactive_chat`, `interactive_case_work`, and `approved_automation`. Ordinary chat needs a configured BYOK Provider but no case, redaction approval, MCP grant, or OCR qualification. Case Assistant restores only the current request's explicitly selected approved generations and revalidates their project binding and revocation before transport; it does not reuse automation grants or tickets. Approved Provider automation and approved MCP retain exact qualification, publication, destination/purpose, grant, ticket, expiry, revocation, and protected-output gates.

> **Acceptance uses synthetic data only.** Repository tests and machine canaries must never contain real client or case material. Raw or pending material must not enter GitHub, WorkBuddy, Codex, OpenCode, a browser/search engine, remote OCR, cloud storage, another MCP/Skill, memory, subagent, screenshot, terminal output, or log.

## What changed

- Phase 7 completes the planned information-architecture cutover: the product now has four top-level areas—Assistant, Cases, Legal Library, and Settings—and no longer exposes the legacy Privacy aggregate page or compatibility redirects.
- Ordinary chat, approved-only Case Assistant, and approved automation now have separate execution contracts. Ordinary chat does not require a case and can send only the explicitly selected ordinary attachments; Case Assistant sends only the current request's explicitly selected approved generations and confirmed case data; approved automation remains behind qualification, grants, exact tickets, and protected outputs.
- Settings now has four explicit owners: Provider services and credentials; Local processing environment and OCR components; MCP and automation; and Version, backup, and diagnostics. Case material text and human redaction review remain only under Cases → Materials & Redaction.
- The audited `ProjectId ↔ PrivacyCaseId` relationship is a persistent, immutable one-to-one backend binding. Project IDs and Privacy/Vault IDs retain their distinct formats and responsibilities; conflicts and ambiguous historical associations fail closed instead of deriving or rebinding identities.
- Legacy `assistant-case-handoff`, `approvedProviderTaskRequest`, compatibility-only buttons, the hidden `settings:privacy` route, and the fail-closed `start_assistant_run` execution graph have been physically removed while historical display/recovery types and all approved Provider/MCP security capabilities remain intact.
- Local MinerU is connected to App ingestion. `auto_local` routes only PDFs/pages needing visual OCR and `force_local` routes all PDF pages, but only while the signed current-machine qualification remains valid.
- The App builds and signs a complete worker/tools/runtime/model inventory, installs and remeasures exact Windows Firewall outbound-block rules, runs the fixed synthetic canary, persists qualification, reloads it on restart, and invalidates it on expiry, revocation or environment/hash/version drift.
- Approved material publication and all 16 non-public `approved_case_workspace` handlers execute against immutable signed generations or fixed public template/schema data. The profile now lists exactly 21 tools: five public-law, ten approved material/work-product, and six approved-diagram tools. Work products use immutable versions, optimistic concurrency, idempotency, journal recovery, exact source binding, and residual scanning.
- Every work-product version persists exactly `content.envelope.json`, `manifest.json`, and `commit.json`. Content is encrypted with a fresh per-generation AES-256-GCM key and nonce; Windows DPAPI CurrentUser wraps the key, and authenticated data binds workspace/case/work-product/version, signed-manifest hash, content hash/size/media type. Only the scoped `WorkProductService` may authenticate and decrypt it after source, revocation, filesystem, manifest, commit, hash, and residual checks. A legacy plaintext `content.bin` or any extra/missing file fails closed.
- Formal packaging first builds the paired MCP sibling, measures its SHA-256, and compiles that value into the App. Approved-MCP qualification requires this trust anchor in addition to sibling path/file identity, version and behavior; an unbound development App or substituted same-name binary fails closed. Every packaged release sibling must still be measured and rerun because its hash is artifact-specific.
- App-issued MCP tickets bind the server instance, transport, tool, schema, purpose, canonical request bytes, destination, target IDs/generation, nonce, expiry and revocation epoch. Consumption is persistent and replay protected.
- The standalone approved-MCP wire replay journal is now V2. Each reservation persists an authenticated, session/server/epoch-bound pending transition in Windows Credential Manager before the SQLite commit, advances the authenticated head only for the exact expected next tail, and then clears the pending record. Recovery accepts only the exact one-step committed tail; a pre-database crash, missing pending record, multi-step advance, fork, rollback, binding mismatch or tamper remains fail closed and requires revocation plus reprovisioning. The pending record contains hashes/MACs and a nonce, never case text or ticket secrets.
- Standalone approved hosts receive only an opaque App-issued `srv_…` ID. Session descriptors are DPAPI-protected and session secrets remain in Windows Credential Manager; static host assets contain no database/root/config path, environment secret, bearer or HTTP credential. Approved-MCP policy v2 defines four explicit grant groups: `read` authorizes the original eight read case tools, `write` the original two write case tools, `diagram_read` four diagram read/validate/export tools, and `diagram_write` two diagram render/update tools. The original groups never silently expand, and every pre-v2 session must be revoked and recreated.
- `diagram_authoring` remains a permanently synthetic/public profile whose HTML bundle is plaintext and addressed as a local artifact. It is not an approved-case path. Real approved-case diagrams use only `approved_case_workspace`: render/update publish encrypted protected HTML work-product versions and export returns verified descriptor metadata without path, URI, or HTML.
- Approved Provider dispatch is a separate backend-restored type. It revalidates exact content/generation/Provider/endpoint/model/purpose/policy/detector/OCR/expiry/revocation immediately before transport. Naked case requests still fail before serialization and send zero network requests.
- Safe reconstructed PDF, DOCX, TXT and Markdown exports reload the protected approval server-side, refuse unsafe/overwrite/link/cloud destinations, reread the installed file, compare content/hash, rescan residual risk, and append a generation-bound audit.
- Privacy lifecycle UI covers retention, legal holds, expiry sweeps, protected output/work-product lifecycle, mapping reveal/revoke, mapping-key rotation/destruction, and crash recovery. It does not claim forensic media erasure.
- `.lavbackup` V3 authenticates and encrypts five components as one DPAPI-current-user set: the `user.sqlite` snapshot, encrypted privacy bundle, ciphertext-only case Vault archive, approved-workspace archive, and encrypted work-products archive. Every component uses independent chunk AAD under the same fresh backup key. Restore is staged, reverified on restart, installed as one transaction and rolls back all five components on any failure. V2 three-component bundles are accepted only for read/restore compatibility; new complete backups are V3. V1 fails closed. `.lavprivacy` remains a privacy-only maintenance format.
- An exact v0.3.1 profile is authenticated before any source write. The upgrader installs a five-slot original-state recovery point, migrates Privacy and the audited one-to-one `ProjectId ↔ PrivacyCaseId` binding, and commits User schema 10→11 only in the last transaction. An exact legacy review without a recoverable CaseId/display name remains unassigned and uses an authenticated unknown-name presentation; no name or binding is fabricated from hashes.
- Explicit v0.3.1 recovery creates a current five-component Safety backup and credential archive, drains MCP admission and writes, then enters a recovery-only `apply-and-exit` startup. It atomically restores all five original slots, exits successfully, permits a real v0.3.1 reopen, and supports a new, idempotent v0.4.0 upgrade lineage. It never performs SQL down-migration or single-database rollback.
- WorkBuddy, Codex and OpenCode keep separate public and approved packages. Approved packages are Windows stdio only, begin with opaque IDs, stop on contaminated context, and explicitly forbid attachments, paste, host files, browser/search, remote OCR, another MCP/Skill, memory, subagents and unapproved Providers.

The public release status and supported boundaries are maintained in the [release status](docs/release-status.md). Packaging success does not qualify production OCR, establish a trusted Windows publisher, or replace clean-machine acceptance.

## Phase 7 synthetic UI evidence

All images below were captured on 2026-08-01 from production UI components with synthetic data and blocked external transports. They contain no real case material, local path, credential, Bearer token, ticket, receipt, hash, or authoritative Privacy CaseId.

- [Ordinary chat](docs/screenshots/2026-08-01-phase-7-ordinary-chat.png)
- [Explicit ordinary attachment and cancellation](docs/screenshots/2026-08-01-phase-7-ordinary-attachment.png)
- [Case materials and redaction](docs/screenshots/2026-08-01-phase-7-case-materials-and-redaction.png)
- [Approved-only Case Assistant](docs/screenshots/2026-08-01-phase-7-case-assistant-approved.png)
- [Revoked generation fail-closed state](docs/screenshots/2026-08-01-phase-7-case-assistant-revoked.png)
- [Local processing environment and OCR components](docs/screenshots/2026-08-01-phase-7-local-processing.png)
- [MCP and automation](docs/screenshots/2026-08-01-phase-7-mcp-and-automation.png)
- [Version, backup, and diagnostics](docs/screenshots/2026-08-01-phase-7-maintenance.png)

## Compatibility contract

| Item | `0.4.0` value |
|---|---|
| Binary release | `0.4.0` |
| MCP protocol metadata | `2025-11-25` |
| Public service schema | `1` |
| Legal archive schema | `4` |
| Legal runtime schema | `1` when present |
| User database schema | `11` |
| Default profile | `public_law_only` |
| Default tools | 5 read-only public-law tools |
| Experimental profile | `redacted_case`: public five plus receipt-gated `citation_validate`; it remains separate from approved workspace sessions |
| Qualified profile | `approved_case_workspace`: public five + ten approved material/work-product + six approved-diagram tools = 21 |
| Approved session policy | v2; 16 non-public grants split as `read` 8, `write` 2, `diagram_read` 4, `diagram_write` 2; older sessions must be recreated |
| Synthetic diagram profile | `diagram_authoring`: public/synthetic data only; plaintext local HTML bundle; never approved case material |
| Approved static transport | Windows stdio with an App-issued opaque standalone session ID |
| Hidden legacy case tools | unavailable in every profile |

`public_law_only` still exposes exactly, in order:

1. `system_status`
2. `legal_search`
3. `legal_get_article`
4. `legal_get_versions`
5. `legal_get_relations`

The approved profile adds exactly 16 non-public tools.

Case material/work-product tools:

1. `case_list`
2. `case_get_public_metadata`
3. `case_list_approved_materials`
4. `case_read_approved_material`
5. `case_search_approved_materials`
6. `case_list_work_products`
7. `case_read_work_product`
8. `case_write_work_product`
9. `case_update_work_product`
10. `case_export_work_product_manifest`

Approved-diagram tools:

1. `diagram.list_templates`
2. `diagram.get_schema`
3. `diagram.validate`
4. `diagram.render`
5. `diagram.update`
6. `diagram.export`

No approved request accepts a path, filename, URI, URL, directory, glob, command, shell fragment, raw OCR, pending review content, private mapping, secret, bearer, or free metadata object. Approved `diagram.render`/`diagram.update` persist only encrypted protected `text/html`; approved `diagram.export` returns descriptor metadata only and never returns HTML, a path, or an artifact URI. Both MCP result channels are independently privacy scanned.

## Qualification and operating contract

Discovery is not qualification. Qualification is not document approval. Document approval is not general egress permission. MCP and Provider each require an additional exact destination/purpose authorization.

The App is authoritative for these independent gates:

- synthetic canary compatibility;
- local processing-chain integrity;
- Windows network isolation;
- model/runtime trust;
- production scan authorization;
- App automatic routing authorization (never automatic approval);
- approved MCP qualification/session;
- approved Provider qualification and exact dispatch approval.

Every gate has its own evidence, expiry/revocation/invalidation condition and anonymous reason code. Missing or changed evidence fails closed. There is no HTTP/SSH/cloud/remote MinerU or model-download fallback.

### MinerU qualification boundary

- Historical component candidates and direct-worker diagnostics are permanently excluded from publication and cannot be reused as release assets.
- A production component must bind its source commit, build script, worker source tree, selected runtime distributions and exact model revisions. It must be rebuilt deterministically, explicitly approved, signed, installed under a short root, remeasured, GPU-probed and qualified through the App-owned Firewall/Job/canary/restart path.
- The component installer rejects any final component path over 259 UTF-16 code units with `component_runtime_path_too_long`.
- Component installation, signature verification or synthetic diagnostics do not authorize production-case OCR. Continue only when the App currently reports every production qualification gate as valid.
- Download component assets only as a complete signed set from an official Release. URL availability is not integrity or qualification evidence, and GitHub credentials must never enter component or case metadata.

See the [privacy operations guide](docs/privacy-vnext/OPERATIONS.md) for the end-user sequence and [`docs/mcp/approved-case-workspace.md`](docs/mcp/approved-case-workspace.md) for the host contract.

## Install and migration

### Desktop

1. Verify the downloaded artifact, its adjacent SHA-256 where specified, and every applicable embedded manifest.
2. For the formal installer, require the exact GitHub filename `Lawyer.Assistance_0.4.0_x64-setup.exe`, its canonical checksum and detached updater signature. Verify Windows publisher identity, Authenticode policy, RFC3161 timestamp, and the updater signature over the exact installer bytes before execution.
3. Install or unpack under the current Windows user. Do not copy a real `user.sqlite`, privacy store, `.lavbackup`, `.lavprivacy`, case material, Provider credential or session descriptor into the installation tree.
4. On first start, let the App migrate the local databases and initialize the encrypted case Vault, approved workspace, and encrypted work-product store. Create a new five-component `.lavbackup` V3 before relying on restart restore. V2 three-component bundles remain read/restore-compatible but are not newly emitted as the complete format; legacy single-database and V1 bundles fail closed.
5. Use **设置 → 本地处理环境与 OCR 组件** to discover, save, trust, isolate and qualify the local OCR installation. Do not process a visual case PDF until all required backend gates are current.

### Public-law MCP

1. Obtain a separately licensed compatible `legal_core.sqlite` and verify it independently.
2. Explicitly create/migrate the fixed-name user database:

   ```text
   lawyer-assistance-mcp --user-db /absolute/path/user.sqlite init-user-db
   ```

3. Start `--privacy-profile public_law_only` over stdio or loopback HTTP and require the exact five-tool catalog.
4. Call `system_status` and continue only on `ready`. Use public legal names, provisions and dates only.

### Approved MCP

1. **Breaking policy-v2 and replay-journal migration:** stop every older approved MCP host, revoke each old standalone session in the App, and create a fresh policy-v2 session. V1 Credential Manager state and `standalone-wire-replay-v1.sqlite` are never authenticated, migrated, rolled back or replayed as V2. Explicit revocation best-effort deletes the exact V1/V2 credential targets and fixed local replay files; any cleanup failure remains fail closed. Do not copy, rename, edit or reuse an old replay database or credential.
2. Complete local App review and manual approval, publish the exact generation, and run approved-MCP qualification.
3. Create a standalone session in the App and copy only its opaque `srv_…` ID into the disabled Windows stdio template:

   ```text
   lawyer-assistance-mcp --privacy-profile approved_case_workspace --approved-session-id <APP_ISSUED_SERVER_ID> stdio
   ```

4. Select only the required v2 grant groups: `read` (8 case reads), `write` (2 case writes), `diagram_read` (4 diagram reads/validate/export), and/or `diagram_write` (2 diagram render/update). The old `read`/`write` groups do not include diagram access.
5. Do not add config/database/root/path/env/bearer/bind/origin/HTTP options. Require exactly 21 tools and start a clean host task with opaque IDs only. Use diagram tools for real cases only through this profile; render/update create encrypted protected HTML, and export returns metadata only.
6. Stop on `PROFILE_NOT_QUALIFIED`, mismatch, expiry, revocation, replay, integrity or residual-scan errors. Never downgrade to `diagram_authoring`, a file, browser, another tool, remote OCR or copied text.

## Release assets and acceptance checklist

The App Release custom-asset allowlist is exactly these 12 names (GitHub-generated source archives are not counted):

- `Lawyer.Assistance_0.4.0_x64-setup.exe`
- `Lawyer.Assistance_0.4.0_x64-setup.exe.sha256`
- `Lawyer.Assistance_0.4.0_x64-setup.exe.sig`
- `latest.json`
- `Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip`
- `Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256`
- `lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip`
- `lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256`
- `lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz`
- `lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256`
- `lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz`
- `lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256`

Tauri produces the local installer as `Lawyer Assistance_0.4.0_x64-setup.exe`; the release staging process makes and re-verifies the independent dot-name copy above. The `.sha256`, `.sig`, `latest.json` URL/signature, and dot-name installer must all bind the same bytes.

The separate `mineru-components-v0.4.0` Release contains only `mineru-component-catalog.json`, `mineru-component-catalog.json.minisig`, `mineru-component-provenance.json`, `mineru-component-provenance.json.minisig`, the catalog-selected single `.laocrparts` descriptor, and every descriptor-ordered `.partNNNN-of-NNNN`. It must not contain an unsharded `.laocrpkg`, historical candidate, placeholder/synthetic model, or unapproved runtime/model/license/provenance.

Before upload:

- verify every adjacent checksum and embedded/archive manifest;
- reject traversal, duplicate, database, secret, session, credential, case-content and stale-member entries;
- confirm the portable and installer executable ProductVersion is `0.4.0`;
- verify Authenticode and RFC3161 for the installer, portable App, and paired MCP, and require the same publisher identity;
- verify the updater `.sig` and `latest.json` signature against the exact signed installer bytes, filename, version, and canonical URL;
- install/start the installer and portable build, run local health/privacy smoke tests, and run the actual MCP binary stdio/HTTP canaries;
- download the GitHub Release into a fresh directory, compare exact names, count, size, and SHA-256, then rerun the Authenticode/updater, portable, three-platform MCP, and MinerU catalog/provenance/parts validators.

MCP archives contain no legal/user/privacy database, case material, exported document, token, Provider credential, App-issued session descriptor, secret, or machine-local configuration.

## External signing requirements

Release secrets are intentionally outside the repository. A formal build requires an Authenticode certificate with a readable private key and trusted RFC3161 timestamp capability, plus the Tauri updater private key/password matching the embedded public key. The final installer `.sig` and `latest.json` must bind the exact final Authenticode-signed installer.

Missing signing credentials block the complete 12-asset App set, trusted publisher, updater outputs, draft readback, and any stable/latest promotion. They do not invalidate the implemented privacy code or credential-free tests, but no unsigned artifact may be renamed to a formal asset or presented as the stable release. The signed workflow is documented in the [release-signing guide](docs/development/release-signing.md).

## Known limits

- A host may upload the first message or attachment before a Skill/Agent rule loads. MCP cannot prevent, retract or prove deletion of that earlier disclosure. If a task is contaminated, stop and create a clean opaque-ID-only task after following host/Provider retention cleanup.
- Only reconstructed safe PDF/DOCX/TXT/Markdown is claimed. Pixel-perfect layout-preserving redaction is not claimed.
- Mapping/key destruction and logical cleanup are not forensic erasure of SSD cells, filesystem history, external backups, host caches or previously disclosed copies.
- Qualification is machine/user/install specific. Copying a report, session ID, database or model tree to another environment does not transfer qualification.
- Public-law host packages remain intentionally case-free even though the separate approved-session implementation exists.
- Real client material is excluded from release acceptance. Synthetic positive E2E proves the implemented chain, not legal accuracy for every handwriting, stamp, scan quality or jurisdictional document form; low confidence and unsupported cases must fail closed and receive human review.
- Authenticode validity does not by itself establish SmartScreen reputation or clean-machine compatibility. Windows 10/11 publisher, timestamp, install/upgrade/recovery/portable/updater/interruption/uninstall and AV/EDR evidence remains a release-operations gate, not a privacy feature claim.
