# Lawyer Assistance MCP 0.4.0-beta.1

> **Privacy vNext prerelease.** This release implements the encrypted local-redaction architecture, approved-workspace contracts and host guardrails requested after v0.3.1. It is a controlled-testing prerelease, not production qualification for real client material.

> **Current qualification is intentionally fail-closed.** `networkIsolationEnforced=false`, `modelManifestTrustEstablished=false`, `appAutoEnableAuthorized=false` and `productionCaseOcrAuthorized=false`. Real scanned case OCR, automatic approval and approved-case MCP execution stay disabled until those gates are independently qualified.

## Privacy vNext scope

- Encrypted local vault primitives, Windows DPAPI key wrapping, AES-256-GCM chunk storage, nonce reservation, encrypted source metadata and fail-closed tamper/truncation checks are implemented in the privacy crate.
- Local OCR worker protocol `la-mineru-worker-v1` is defined and validated for host-to-worker hello, health, OCR, progress, cancel and shutdown messages. Remote MinerU, SSH OCR and cloud OCR remain forbidden for production case material.
- Finding and risk engines now use opaque IDs, private value references, deterministic aliases, integer confidence, detector/model provenance hashes, page/document risk and the exact hard-gate model.
- Approved material and work-product workspaces are immutable, signed, atomic, journaled and user-boundary scoped. Work products can only be written from verified approved material references and are blocked by residual sensitive-content scans.
- Desktop privacy settings expose local-worker/GPU preferences and the blocked capability matrix. These settings do not authorize production OCR or auto approval while qualification flags are false.
- The new `approved_case_workspace` MCP profile and host assets are discoverable but unqualified. Tool execution fails closed and returns anonymous qualification errors rather than raw case content.
- WorkBuddy, Codex and OpenCode approved-workspace instructions explicitly forbid attachments, paste, browser/search, cloud storage, other MCP servers, remote OCR, memory or subagents for unapproved case material.

## Compatibility contract

| Item | Current value |
|---|---|
| Binary release | `0.4.0-beta.1` |
| MCP protocol metadata | `2025-11-25` |
| Public service schema | `1` |
| Legal archive schema | `4` |
| Legal runtime schema | `1` when present |
| User database schema | `10` |
| Production profile | `public_law_only` |
| Production tools | `5`, all read-only |
| Experimental profile | `redacted_case`, `6` tools; no App production signing path |
| Designed but unqualified profile | `approved_case_workspace`, public five plus ten approved-workspace tools; execution blocked |
| Case/material/document raw tools | Hidden and unavailable |

Production MCP still exposes exactly `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions` and `legal_get_relations` under `public_law_only`. Stdio and HTTP must expose the same production tool names, order and schemas.

## Install and migration

1. Obtain a separately licensed compatible `legal_core.sqlite`.
2. Back up `user.sqlite` and its SQLite auxiliary files, then verify archive/binary checksums.
3. Create or migrate the fixed-name user database explicitly:

   ```text
   lawyer-assistance-mcp --user-db /absolute/path/user.sqlite init-user-db
   ```

4. Start stdio or loopback HTTP with `--privacy-profile public_law_only` and dedicated empty input/output roots.
5. Verify `tools/list` is exactly the five public-law tools, then call `system_status` with `schema_version: 1` and continue only on `ready`.
6. Smoke-test only with public legal names, provisions and dates. Never attach, paste or import client/case material into hosts.

The approved-case-workspace host examples are packaging and integration artifacts for controlled testing. They are not permission to process raw or merely pending case material.

## Release asset and updater limits

- The GitHub repository is private and this Release is marked prerelease. Anonymous asset download and the `/releases/latest` updater route are therefore not qualified.
- The Windows installer may be unsigned by Authenticode on this machine. Minisign/Tauri updater signatures prove updater payload integrity but do not prove Windows publisher identity.
- MCP archives contain no legal database, user database, case material, exported document, token, Provider credential or machine-local configuration.

## Known limits

A host may send a first message or attachment before Skill/Agent rules load. MCP cannot prevent, retract or prove deletion of that prior disclosure. If raw case material enters a host context, the approved-workspace instructions require a clean task and zero further tool use.

Reliable text-layer PDFs can still be processed locally through the existing reviewed redaction path. Scanned, handwritten, stamped or image-only case PDFs must fail closed until local OCR isolation, model-manifest trust and production authorization are qualified. There is no remote MinerU, SSH or cloud OCR fallback.

The new privacy vault and approved-workspace modules are Windows-oriented where platform cryptography and filesystem isolation rely on Windows APIs. Cross-platform MCP packaging remains public-law-only unless separately qualified.