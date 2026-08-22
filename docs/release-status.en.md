# Current Release Status

## Version conclusion

The current target version is `0.4.0`, with this release classification:

> `SOURCE_COMPLETE_CANDIDATE` — the repository is aligned to the stable version and the planned product, migration, recovery, and release-control paths are implemented. It is not a `PUBLISHED_STABLE` Release.

Stable-version source identity is not stable-publication evidence. Final local candidate validation, exact-main CI, Authenticode and updater credentials, signed assets, service-side readback, Windows 10/11 clean-machine acceptance, and final MinerU/GPU qualification must each have recorded evidence before the same `v0.4.0` Release can be promoted to stable/latest.

The GitHub repository is public. Repository visibility and the ability to download a file are distribution facts only; they do not establish a trusted publisher, updater readiness, OCR qualification, clean-machine acceptance, or stable-release status.

## 2026-08-14 to 2026-08-22 evaluation release and local validation

The [main CI](https://github.com/shilittle/Lawyer-Assistance/actions/runs/31762817709) and [MCP server CI](https://github.com/shilittle/Lawyer-Assistance/actions/runs/31762817760) succeeded for exact `main@4fd0d88caef5bca6d874e7f1bc290d604e9b172b`; the MCP run covered Windows, Linux, and macOS. This evidence is bound only to that exact SHA, so any later commit merged into `main` requires fresh matching CI evidence.

The project published the public, non-draft, non-latest [`v0.4.0-unsigned-evaluation.1`](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v0.4.0-unsigned-evaluation.1) prerelease. It contains only an unsigned installer, its manifest, and a SHA-256 sidecar. It is not the formal `v0.4.0` Release and does not satisfy the frozen 12-item App/MCP allowlist.

The installer was applied locally as version `0.4.0`. Both the App and paired MCP are `NotSigned`, and MCP `--version` reports `0.4.0`. The App encountered the existing mixed prerelease profile (User schema 10, Privacy schema 4, and existing Vault/Approved state), failed closed with exit code 101, and created no window. Post-run auditing detected no persistent profile write, credential-entry count change, Windows crash report, or residual process. Because complete pre-launch file-hash baselines were not recorded, this is not described as byte-for-byte before/after identity.

See the [development and release audit log](development/development-log-2026-08-22.md) for exact hashes, evidence, and limitations.

## Implemented source-candidate capabilities

| Capability | Status |
|---|---|
| Windows x86_64 desktop application | Implemented in the `0.4.0` source candidate; published-stable acceptance remains pending |
| Four-area information architecture | Implemented as Assistant, Cases, Legal Library, and Settings |
| Ordinary Assistant chat | Implemented without a case prerequisite; uses the selected BYOK Provider and keeps the Provider-server warning visible |
| Explicit ordinary attachments | Implemented; only attachments selected for the current send contribute locally extracted text, and they do not become case materials automatically |
| `runtime-slim-v1` legal database | Used as an application resource for current query and citation workflows |
| Local case, evidence, issue, and legal-authority management | Implemented |
| Local PDF, DOCX, UTF-8 TXT, and Markdown import | Implemented; visual pages remain subject to OCR qualification |
| Cases → Materials & Redaction | Implemented for import, text-layer extraction, redaction review, immutable approval, revocation, and version history; OCR remains gated and currently unqualified for production |
| Approved-only Case Assistant | Implemented under Case Work; each request explicitly selects current approved generations and excludes raw files and Vault objects |
| Audited `ProjectId ↔ PrivacyCaseId` binding | Implemented as a persistent, immutable one-to-one backend binding; the frontend does not derive or receive the authoritative Privacy identity |
| Protected work products and safe derived files | Implemented |
| Five-component authenticated and encrypted `.lavbackup` | Implemented |
| Exact v0.3.1 upgrade and recovery-only downgrade | Implemented with exact-source validation, an authenticated five-slot original-state recovery point, monotonic receipts, five-slot `apply-and-exit`, v0.3.1 reopen, and idempotent re-upgrade harness coverage |
| BYOK Providers | Implemented; `interactive_chat`, `interactive_case_work`, and `approved_automation` are separate channels |
| Four Settings owners | Provider services and credentials; Local processing environment and OCR components; MCP and automation; Version, backup, and diagnostics |
| `public_law_only` | Default five-tool read-only public-law MCP surface |
| `approved_case_workspace` | Exactly 21 tools; disabled by default and constrained by App qualification, session, grants, and tickets |
| `diagram_authoring` | Exactly 11 tools; permanently limited to synthetic or public data |
| Approved-case diagrams | Stored through the approved workspace as encrypted protected HTML work products |
| Release controls | Stable-version gate, exact asset allowlists, signed preflight, publication/readback verification, and fail-closed promotion controls are implemented in source |

## Upgrade and recovery boundary

The automatic upgrade accepts only the immutable exact v0.3.1 profile: user schema 10 and Privacy schema 1 are present, while Vault, Approved, and WorkProducts are authenticated as absent. Unknown, modified, mixed, linked, incomplete, or ambiguous source state fails closed.

Before any source write, v0.4.0 creates and rereads an authenticated original-state recovery point for all five logical slots. Privacy, the audited binding, materials, and approved projection migrate before user schema 10 advances to 11 in its final transaction. The source user database remains read-only throughout the earlier stages. A restart follows only the unique authenticated receipt tail; it does not guess, repair a marker, or run a partial SQL downgrade.

The explicit downgrade is a recovery-only maintenance operation. After the exact confirmation, the App first protects the current v0.4.0 five-slot state and credentials, drains operations, stages the original images, and exits into controlled recovery. The next launch initializes no ordinary manager, UI, maintenance, or background task. It either restores the exact v0.3.1 five-slot state and exits successfully or restores the complete current v0.4.0 state before commit; it never exposes a mixed state. The retained audit evidence does not prevent a later explicit, complete re-upgrade.

Read [Upgrade from v0.3.1 to v0.4.0](upgrade-v0.3.1-to-v0.4.0.en.md) before opening an existing v0.3.1 workspace. Do not give a migration-only recovery bundle to ordinary V3 restore, and do not edit pending, incoming, rollback, cleanup, receipt, or audit files.

## Current workflow boundaries

- `interactive_chat` supports ordinary case-free messages and explicit ordinary attachments. It cannot read the case workspace, Privacy store, Vault, approved generations, or MCP authorization state.
- `interactive_case_work` supports the in-App Case Assistant with only the current case's explicitly selected approved/current generations and confirmed case data. Revoked, stale, raw, pending, foreign-case, and unselected sources fail closed.
- `approved_automation` retains the separate external-host boundary: opaque IDs, clean-task controls, qualification, approved source references, grants, exact tickets, destination/purpose binding, revocation checks, and protected work-product sinks.

These modes are not interchangeable, and no blocked mode falls back to another one. Case text and human review remain in **Cases → Materials & Redaction**; Settings contains only its four configuration and maintenance owners.

## Gates that remain before published stable

### Authenticode and updater credentials

The repository does not contain the Authenticode certificate/private key, trusted timestamp capability, or the updater private key/password matching the embedded public key. Until those external credentials are supplied and verification succeeds, no installer is an accepted stable asset and no installer-bound updater `.sig` or `latest.json` may be treated as live.

### Exact assets and service readback

The App/MCP Release must contain exactly the frozen 12 custom assets: the signed installer, installer checksum and updater signature, `latest.json`, portable archive and checksum, and three platform MCP archives with their checksums. The MinerU component Release is separate and may contain only its detached-signed catalog/provenance pair, one descriptor, and every ordered part it declares. Historical candidates, placeholders, empty models, unsigned metadata, renamed files, or replacement uploads are forbidden.

Both annotated tags must point to the exact final `main` commit. Draft upload is followed by a fresh-directory download and byte/hash/signature/manifest verification of every asset. A mismatch remains draft; it is never overwritten or promoted.

### Production OCR

The local MinerU code path, component management, and qualification gates are implemented, but this release candidate has no recorded evidence that a final approved and signed v4 runtime/model set has been published and qualified. Scanned and visual PDFs must remain fail closed unless the exact current component and machine pass signature-chain, short-root installation, installed-tree remeasurement, Windows Firewall, process-tree, synthetic canary, restart, drift, expiry, revocation, and target-GPU checks. Cloud OCR, remote OCR, SSH, a historical component, or user consent cannot substitute for qualification.

### Full archival database

The desktop application uses the `runtime-slim-v1` projection. The full archival `legal_core_full.sqlite` database is not part of the desktop package and cannot be replaced by a fixture, the runtime projection, or a same-named file. Work requiring full-coverage rebuilds and strict archival/provenance audit must use a separately verified formal archival resource.

### CI and clean-machine acceptance

The eventual exact final `main` commit must pass main CI and MCP Linux/Windows/macOS CI. Commit `4fd0d88…` has successful evidence, but any later final `main` SHA must close the gate again. Windows 10 and Windows 11 clean machines must then cover new install, publisher/timestamp inspection, first launch, exact v0.3.1 upgrade, complete recovery, real v0.3.1 reopen, re-upgrade, portable mode, updater, interrupted installation, uninstall, and SmartScreen/AV/EDR behavior. The final target GPU environment must separately complete MinerU acceptance.

## Publication sequence

1. Finish local candidate validation and merge the same clean commit to synchronized `main`.
2. Record green main and three-platform MCP CI for that exact commit.
3. Build, sign, and locally verify all App/MCP/MinerU assets.
4. Create immutable annotated `mineru-components-v0.4.0` and `v0.4.0` tags at that same commit; leave `v0.3.1` unchanged.
5. Create both Releases as drafts, upload only their exact allowlists, and complete fresh-download service readback.
6. Promote the same Releases to prerelease and complete public-URL clean-machine, upgrade/recovery, updater, and MinerU qualification.
7. Confirm the MinerU Release first, then promote the same App Release to stable/latest without moving a tag or replacing an asset.
8. Reread the public latest endpoint and verify `latest.json`, URL, exact installer bytes, and signature. On failure, return the same App Release to prerelease and stop the stable announcement.

## How this version may be described

Acceptable now:

- “Lawyer Assistance `0.4.0` source-complete candidate”;
- “the repository is aligned to stable version `0.4.0`, while stable publication is externally gated”;
- “the Lawyer Assistance source repository is public”;
- “provides local public-law research, case organization, privacy approval, protected work products, and controlled MCP”;
- “implements exact v0.3.1 upgrade, authenticated original-state recovery, v0.3.1 reopen, and re-upgrade paths”; and
- “production OCR and stable updater use remain blocked until their exact qualification/publication gates pass.”

Do not describe it as:

- a published stable/latest Release, complete production edition, or fully release-accepted build;
- production-qualified for scanned-document OCR;
- Authenticode-signed or backed by a trusted Windows publisher without verifying the exact asset;
- currently supporting a stable automatic-update chain;
- including the full archival database;
- accepted across clean Windows 10/11 machines or the target GPU without their evidence; or
- signed, updater-ready, OCR-qualified, or release-accepted merely because the version is stable-shaped or the repository/file is public.

## User guidance

Do not install a supposed stable package until the project reports that the `v0.4.0` stable promotion and latest-endpoint readback succeeded. Before then, use only project-supplied, verifiable technical artifacts in an isolated evaluation environment with synthetic data. After publication, real-case use must still follow the approval, outbound-data, and host boundaries in [Security and Privacy](security-and-privacy.en.md), and scanned material must not enter OCR unless the App reports every current production qualification gate as valid.
