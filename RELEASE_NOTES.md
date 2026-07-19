# Lawyer Assistance MCP 0.3.1

> **Supersedes v0.3.0.** The v0.3.0 Windows assets passed local and remote byte verification, but its Linux/macOS MCP Clippy jobs exposed a Windows-only DPAPI constant without a platform guard. v0.3.1 adds the guard and is the first candidate eligible for the complete remote matrix.

> **Windows privacy-hardening prerelease.** This build is published for controlled testing. The NSIS installer is protected by the repository's Tauri/Minisign updater signature but is not Authenticode-signed because no trusted Windows code-signing certificate is available on the release machine. Windows can therefore display an unknown-publisher or SmartScreen warning. Do not treat this prerelease as production qualification for real client material.

## Desktop privacy and redaction

- PDF, DOCX, TXT and Markdown materials can be ingested locally for automatic detection, manual review, exact receipt issuance and reconstructed text-PDF export.
- Safe PDFs embed a hash-pinned Chinese font, reject unsupported glyphs and are reopened for text, object-graph, hash and canary verification before installation.
- Review payloads and receipts can be revoked and deleted through an exact source/extraction-hash-bound lifecycle command while hash-only audit remains.
- Reliable text-layer PDFs are supported. Scanned, handwritten, stamped or otherwise visual PDFs fail closed because the qualified App-to-MinerU production chain is not enabled.
- Case-bearing Provider requests remain blocked before transport. Production MCP and bundled host integrations expose exactly five public-law read-only tools.
- WorkBuddy/Codex/OpenCode rules prohibit case material and unverified derivatives from entering models, networks, connectors, memory or subagents. A host can still pre-read an attachment before these rules load, so no case attachment may be uploaded to such hosts.

## Release asset and updater limits

- The GitHub repository is private and this Release is marked prerelease. Anonymous asset download and the `/releases/latest` updater route are therefore not qualified.
- The installer, SHA-256 file, Tauri/Minisign signature and `latest.json` are published as one version-bound set. Minisign authenticity is not Authenticode publisher identity.
- The independent Windows MCP archive contains no legal database, user database, case material, exported document, token or Provider credential.


> **Privacy hardening breaking change — 2026-07-19.** The current production contract replaces the earlier fixed 12-tool surface with `public_law_only`, exactly five public-law read-only tools. Earlier new-case, material-import, apply/get-state, document-generation and export instructions are legacy and unavailable. Do not use historical release or acceptance text to re-enable them.

This is the first separately packaged MCP server release for Lawyer Assistance. Archives are platform-specific and contain the binary, license/third-party notices, `docs/mcp/`, public-only host integration assets and `MANIFEST.sha256`. They contain no legal database, user database, client material, exported document, token, Provider credential or machine-local configuration.

## Compatibility contract

| Item | Current value |
|---|---|
| Binary release | `0.3.1` |
| MCP protocol metadata | `2025-11-25` |
| Public service schema | `1` |
| Legal archive schema | `4` |
| Legal runtime schema | `1` when present |
| User database schema | `10` |
| Production profile | `public_law_only` |
| Production tools | `5`, all read-only |
| Experimental profile | `redacted_case`, `6` tools; no App production signing path |
| Case/material/document tools | Hidden and unavailable |

The release workflow targets Windows x86-64, Linux x86-64 and macOS Apple silicon. A successful remote three-platform matrix and real-host public-only acceptance remain publication gates; this target is not a certification claim for every OS or host version.

## Install and migration

1. Obtain a separately licensed compatible `legal_core.sqlite`.
2. Back up `user.sqlite` and its SQLite auxiliary files, then verify archive/binary checksums.
3. Create or migrate the fixed-name user database explicitly:

   ```text
   lawyer-assistance-mcp --user-db /absolute/path/user.sqlite init-user-db
   ```

   `stdio` and `serve` never create or migrate it implicitly.
4. Start stdio or loopback HTTP with `--privacy-profile public_law_only` and dedicated empty input/output roots.
5. Verify `tools/list` is exactly `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations`; then call `system_status` with `schema_version: 1` and continue only on `ready`.
6. Smoke-test only with public legal names, provisions and dates. Never attach or paste client/case material.

The former step that created a case with a 64-zero revision, bootstrap/import proposal, confirmed apply and state verification is an old-version instruction. Every tool used by that step is hidden in the current profiles; the step must not be run.

## Profile and egress changes

- All five production tools have `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true` and `openWorldHint: false`.
- stdio and HTTP expose the same five names, order and schemas. Host configs add an exact client allowlist where supported.
- `redacted_case` adds only receipt-gated `citation_validate`. Its ticket must bind exact request bytes, fixed MCP destination/purpose, provenance, key version and short TTL, and remain active/not revoked. The App cannot currently sign this purpose, so production must not enable the profile.
- Case reads/writes, material import, gap analysis, document generation and export are hidden in both profiles.
- Provider transport accepts only explicitly public classifications before serialization. No App-to-Provider case receipt chain is connected; legacy case requests fail closed.

## PDF and OCR limit

Reliable text-layer PDFs can be extracted, reviewed and redacted locally. The safe text-PDF path now embeds a hash-pinned Noto Sans Hans font, rejects unsupported glyphs before approval/export, reopens and re-extracts output, and never copies the original image/object graph. Users can explicitly revoke every receipt and delete the App's protected review payload; source files, separately saved PDFs and hash-only audit remain.

A fixed synthetic page passed MinerU 3.4.3 GPU OCR on the local RTX 5090, but evidence explicitly records no OS network isolation and no trusted model manifest. The App therefore continues to pass no runner (`None`). Scanned, handwritten and image-text PDFs fail closed; there is no remote MinerU, SSH or cloud OCR fallback.

## Known limits

A host may send a first message or attachment before Skill/Agent rules load. MCP cannot prevent, retract or prove deletion of that prior disclosure. The integration rules stop further processing but do not guarantee recall from host/Provider logs.

The built-in HTTP listener rejects non-loopback cleartext binding by default even with Bearer authentication. Production remote access keeps MCP on loopback and uses a controlled TLS reverse proxy. Packaged examples never enable `--dangerously-allow-insecure-non-loopback-http`, `dangerously_allow_insecure_non_loopback_http` or `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`.

## Historical note

Pre-hardening 0.2.0 drafts and historical WorkBuddy acceptance recorded 12 visible tools and case proposal/write/export behavior. Those records describe the system at that time; they are preserved as history but superseded by this breaking privacy contract. Current deployment and testing accept only the five-tool public profile.