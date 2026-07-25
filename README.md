# Lawyer Assistance

Rust-first legal-assistance platform with a cross-platform-targeted MCP server and an optional Windows Tauri 2 professional review station. WorkBuddy, Codex, and OpenCode share the same public-law MCP contract.

Production defaults and the ordinary checked-in host integrations use `public_law_only`:

```text
lawyer-assistance-mcp --privacy-profile public_law_only stdio
lawyer-assistance-mcp --privacy-profile public_law_only serve --bind 127.0.0.1:8787
```

Its exact surface is five read-only tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`. stdio and HTTP must expose the same names and order.

The experimental `redacted_case` profile still adds only receipt-gated `citation_validate` (six tools total) and remains separate from case-workspace authorization. The App does not issue that legacy citation-purpose receipt. Case reads/writes, material import, gap analysis, document generation, and path export remain hidden in both profiles; shared `legal-services` implementations are not external MCP capabilities.

`approved_case_workspace` is a separate, disabled-by-default Windows stdio integration. Its `tools/list` is exactly 21 tools: five public-law tools, ten opaque-ID-only material/work-product tools, and six legal-diagram tools. After the App locally redacts and manually approves an immutable generation, current-machine qualification and an App-issued standalone session can authorize the 16 non-public tools through four explicit grant groups: `read` (8), `write` (2), `diagram_read` (4), and `diagram_write` (2). Existing `read`/`write` grants do not silently gain diagram access. Approved-MCP policy v2 is a breaking authorization boundary, so every older standalone session must be revoked and recreated. A formal App build also carries the SHA-256 of its exact paired MCP sibling as a compile-time trust anchor; an ordinary unbound development build or a substituted same-name binary cannot qualify. Work-product content is never stored as plaintext `content.bin`: each immutable version has exactly `content.envelope.json`, `manifest.json`, and `commit.json`; a fresh AES-256-GCM key/nonce protects the content, DPAPI CurrentUser wraps the key, and only the scoped `WorkProductService` may authenticate/decrypt after all source, revocation, manifest, filesystem, hash, and residual checks. Missing, stale, revoked, mismatched or replayed state, legacy plaintext, or an unexpected generation file fails closed; no prompt or client allowlist bypasses it.

The separate `diagram_authoring` profile is permanently limited to synthetic or public data. Its rendered HTML bundle is plaintext and uses local artifact references, so it must never receive approved case content. Real approved-case diagrams use only `approved_case_workspace`: `diagram.render` and `diagram.update` publish encrypted protected `text/html` work-product versions, while `diagram.export` returns verified descriptor metadata only—never a path, URI, or HTML body.

Provider transport has a separate approved positive path. Rust restores the protected generation and receipt, binds exact Provider/endpoint/model/purpose/provenance/expiry/revocation, rechecks immediately before transport, scans the response, and persists it as protected output. A naked or legacy case-bearing `ChatRequest` remains `CASE_RAW`, fails before serialization and sends zero requests. Local approval alone is never general MCP or Provider permission.

MCP and repository prompts cannot prevent or retract a first message or attachment that a host sent before loading its Skill/Agent rules. Do not put client or case material into WorkBuddy, Codex, OpenCode, or another external model task.

For local material preparation, PDF/DOCX/TXT/Markdown enter the App's bounded local extraction/OCR, automated finding/aliasing, side-by-side human review, residual scan and exact approval workflow. Approved content can be rebuilt as safe PDF, DOCX, UTF-8 TXT or Markdown; each file is re-read, hash/content checked and residual-scanned. Lifecycle actions revoke or logically/cryptographically delete protected state while preserving payload-free hash audit; they never delete a user-selected source or separately saved export.

Local MinerU is connected to App ingestion through `auto_local` and `force_local`. It runs only after the App has signed a complete worker/config/runtime/model inventory, installed and remeasured exact Windows Firewall outbound blocks, completed the fixed synthetic canary, persisted qualification, and revalidated the current environment. Page/order/size/bbox/confidence/output limits, timeout/cancel, pre/post identity checks and process-tree containment fail closed. There is no model download, SSH/cloud/remote OCR or silent fallback.


HTTP remains loopback-only by default. A non-loopback cleartext bind is rejected even with Bearer authentication; production remote access terminates TLS at a trusted reverse proxy connected to the loopback listener.

## Current Scope

As of 2026-07-22, the historical engineering scope of Stages 0–8 remains available for local desktop use. Privacy vNext adds a qualification-gated local OCR chain, independent approved MCP and Provider positive paths, four reconstructed safe export formats, encrypted mapping/lifecycle administration, encrypted-at-rest work products, and a five-component application backup V3 covering the user database, encrypted privacy bundle, ciphertext-only case Vault archive, approved-workspace archive, and encrypted work-products archive. V2 three-component bundles remain read/restore-compatible; V1 fails closed. The public MCP default remains five-tool and case-free. Every case path is conditional on current signed backend evidence and exact purpose authorization; absence or drift fails closed. The updater key/password are available and detached catalog signature verification has succeeded, while final updater artifacts still await the clean signed build. The only currently evidenced external signing blocker is the missing usable Authenticode certificate; clean-machine Windows 10/11 reputation remains release acceptance work, not a privacy feature substitute:

- Tauri 2 desktop shell for Windows x86_64
- React, TypeScript, and Vite frontend
- pnpm workspace and Rust Cargo workspace
- Rust crates split into `domain`, `database`, `retrieval`, `providers`, `citations`, `assistant`, `file-ingest`, `legal-services`, and `legal-mcp`
- Versioned `legal_core.sqlite` schema in `data/schema/legal_core.sql`
- Bundled read-only `legal_core.sqlite` official-source legal metadata index
- Writable `user.sqlite` created under the app's LocalAppData directory with transaction-based migrations, one-time canonical schema repair, and project-ownership constraints
- Strongly typed `health_check` Tauri command with matching Rust and TypeScript types
- Strongly typed offline retrieval commands:
  - `search_laws`
  - `search_articles`
  - `get_article`
  - `get_law_versions`
  - `get_law_relations`
- React offline search workspace with law results, article results, article details, versions, and relations
- Conversation-first Assistant workspace with unbound or case-bound local conversations, bounded history, typed run events and cancellation; legacy case-bearing Provider calls fail before serialization, while the separate privacy-approved path restores and verifies exact protected payloads in Rust
- Rust-side PDF, DOCX, UTF-8 TXT and Markdown privacy import with format checks and hard limits; reliable text layers use native extraction, qualified visual pages use the pinned local MinerU worker, and approved generations export as reconstructed PDF/DOCX/TXT/Markdown
- Versioned Research, Document and Map Artifacts with source/provider/citation audit, safe Markdown, Rust-generated DOCX/JSON, fixed Cytoscape mapping, append-only edits and regeneration
- Pending case-change proposals with case digest/CAS checks, explicit apply or reject, and no model-direct writes to confirmed case records
- Provider profile CRUD with DeepSeek as the only default/top-level preset;
  Qwen / Alibaba Cloud Model Studio, SiliconFlow, and Volcengine Ark remain
  available in a collapsed secondary menu, and existing profiles for all four
  built-in kinds remain compatible
- Custom OpenAI-compatible provider profiles with user-supplied display name, model ID, and HTTPS Base URL
- Windows Credential Manager API key storage with masked status only returned to the frontend
- Provider credentials bound to provider kind/account/HTTPS origin, with cross-process lifecycle serialization between SQLite and Credential Manager
- Shared OpenAI-compatible provider adapter with provider-specific option mapping and in-process mock transport tests
- Streaming response parser foundation for OpenAI-compatible SSE chunks
- Provider settings page with a single DeepSeek quick-create action, collapsed optional/custom provider creation, model ID, Base URL, extension options, masked key status, and connection test results
- Source-bounded legal answer context assembly from the local legal database
- Citation parser and Rust-side validator for `[SRC:...]` source ids
- Citation-grounded public-law answer command using BYOK Provider profiles; case-bearing tasks use only the separate exact-approved Provider workflow, never the public command
- Legal answer records persisted with verified citation reports, not trusted raw model citations
- React citation Q&A workspace with candidate sources, clickable verified inline citations, explicit invalid/duplicate marker styling, citation validation status, and local source text
- Case project CRUD persisted in `user.sqlite`
- MCP privacy profiles with a default `public_law_only` five-tool surface; experimental `redacted_case` adds one legacy receipt-gated citation tool; permanently synthetic/public `diagram_authoring` adds six plaintext-bundle diagram tools; separately qualified `approved_case_workspace` exposes 21 tools total and gates its 16 non-public case/diagram tools through App-issued sessions
- Case workspace data model for files, parties, facts, evidence, legal issues, validated legal basis records, and explicit project-scoped fact-evidence/fact-issue links; composite database constraints reject cross-case relationships
- Rust-side case gap analysis for timeline conflicts, party name inconsistencies, missing evidence support, missing source/date metadata, invalid evidence references, and open legal issues without validated legal basis
- Case legal basis binding through local `[SRC:...]` source ids with Rust-side citation/effectiveness validation and read-only lookups against `legal_core.sqlite`
- Structured case extraction JSON parser with strict Rust deserialization and one repair-attempt path
- React case workspace with project list, editable persisted case files/parties/facts/evidence/issues, fact timeline, evidence catalog, legal basis panel, explicit fact-evidence and fact-issue link editors, gap panel, and extraction review panel
- Six reviewed legal-document templates for local desktop workflows, with structured validation, local citation traceability, rendered Markdown/source preview, and pure-Rust PDF export; local approval/export does not grant MCP or Provider egress
- Case and formal-law graph workspaces with namespaced identities, confirmed nodes, persisted fact-evidence/fact-issue/issue-citation edges, formal `law_relations`, provenance, filtering, search, layout controls, details and exact source jumps
- Version information, authenticated five-component `.lavbackup` V3 for `user.sqlite`, the encrypted privacy bundle, ciphertext-only encrypted case Vault archive, approved-workspace archive and encrypted work-products archive; V2 three-component read/restore compatibility; staged restart restore with all-component rollback; privacy-only maintenance bundle; payload-free crash/maintenance events; and redacted diagnostic export
- A signed-update protocol with strict GitHub URL policy, semantic-version checks, streaming download, Minisign verification, trusted-filename binding, NSIS handoff and stale-installer cleanup
- Reproducible release scripts for an explicitly named unsigned NSIS technical artifact, Authenticode-signed NSIS, updater `latest.json`, deterministic portable ZIP, MCP archive, legal-resource identity verification and complete third-party notices
- Rust unit tests, Vitest, ESLint, and Windows GitHub Actions CI

The complete archival database is generated from official public sources and is
not a sample dataset. Its declared statutory-source coverage state is
`complete`: strict audit passes with schema version 4, full-text article rows
and FTS rows aligned, and zero placeholder article rows. Stage 1C normalizes
4,481 official FLK history families into real multi-version laws with
non-overlapping effective intervals and records 1,121 unresolved official-date
families in a machine-readable exception table. The archival database also
contains the complete declared 2026-07-11 Supreme People's Court website
snapshot: 278 individually published guiding cases, 15 guiding-case batch
notices, 412 typical-case release collections with 597 stable per-case records,
and 752 official court-document templates, all with per-record provenance and
checksums.

The app bundles a separately verified `runtime-slim-v1` projection. It preserves
every law document/version identity, FTS row, citation id, relation and source
record needed by application commands, while omitting raw article duplication,
fetch/audit payloads and the case/template corpora that the current UI does not
query. The archival database and its strict-audit reports remain the coverage
and rebuild authority.

Stage 3 implements compatibility legal-answer Tauri Channel streaming,
cancellation, local citation validation and verified persistence for public,
non-case questions. Stage 4 and Stage 8 retain local case/evidence persistence
and bounded local file extraction, but their historical naked-case Provider and
Assistant routes are now fail-closed before transport. Case facts may leave the
local privacy workflow only as a current, explicitly approved redacted
generation whose receipt is rebound to the exact Provider or approved MCP
destination, purpose, model, request and expiry. Selecting a case material,
showing a scope, or extracting text never constitutes network authorization.
Embeddings and silent local/remote model fallbacks remain outside the product
architecture.

The 2026-07-13 hardening pass adds bounded IPC text/array/response inputs,
strict Gregorian `YYYY-MM-DD` validation, UUID v4 answer record ids, correct
current-law selection that excludes future and fully expired versions, and
database-enforced project ownership for evidence links and legal-basis issue
links. It also repairs unmarked or legacy `user.sqlite` v6 shapes through one
atomic canonical rebuild, serializes read-then-write transactions with
`BEGIN IMMEDIATE`, rejects stale case-workspace responses, preserves finalized
Q&A context across page changes, locks extraction navigation correctly, and
supports editing persisted case child records. Privacy-vNext delivery status is
schema, negative-only gate or package build is not treated as a completed
positive workflow. Native MCP, packaged-app GUI, clean-machine, signing,
SmartScreen, AV/EDR and Windows-version evidence are reported separately so
external qualification is never confused with implemented product behavior.

## Repository Data Policy

The official-source databases are generated local/release artifacts, not Git
blobs:

- Archival/audit authority: `data/generated/legal_core_full.sqlite`,
  4,512,894,976 bytes, SHA-256
  `31cf1995cc09f0e3e00f70bfcf20cf67548f1a6362706ccc11d1fd3b2ebc26ac`.
- Bundled runtime projection: `apps/desktop/src-tauri/resources/legal_core.sqlite`,
  1,775,419,392 bytes, SHA-256
  `86574bba91950b194c6530586eebbae31c689a5bd2a485877b3eed6b611f7d3c`.

Both are intentionally excluded from source control because they exceed
GitHub's ordinary Git object limits. The runtime distribution manifest records
the archival SHA-256 as `archival_source_sha256`, so the smaller application
resource remains tied to the audited full snapshot. Build/runtime state under
`data/build/state/` is also excluded because it can contain cookies, job
databases, and process state.

GitHub Actions creates a clearly marked CI-only fixture database solely for the
Tauri packaging smoke test. CI compacts the full-schema fixture into the actual
runtime schema and runs Rust archive/runtime differential queries. The fixture
is not a product database and must never be uploaded as a release artifact.
Every formal Tauri build runs the read-only resource gate before compilation.

## Architecture Constraints

- The Tauri review station is Windows x86_64. The standalone MCP binary has
  local Windows build/test and WorkBuddy evidence; repository workflow
  definitions target Linux x86_64 and macOS Apple silicon as well, but their
  first successful remote matrix run is still required before publication.
- The Windows desktop exposes an opt-in MCP control page under Settings. It can
  start the same Streamable HTTP implementation in-process on IPv4 loopback;
  startup is manual unless the user explicitly saves `autoStart`. The desktop
  never launches an MCP sidecar or enables a Tauri shell capability.
- The MCP server is pure Rust and does not add a Node or Python runtime.
- The packaged app must not introduce a local LLM, embedding model, Python runtime, or Node runtime.
- The frontend is UI-only and calls Rust through typed Tauri commands.
- SQLite queries, model API requests, and credential access must run in Rust.
- The frontend must never execute arbitrary SQL.
- `legal_core.sqlite` is bundled as an app resource and treated as read-only.
- `user.sqlite` is created as the writable user database under LocalAppData.
- Case and evidence business data is stored through Rust-managed `user.sqlite` tables, not frontend storage.
- API keys and the desktop MCP Bearer must not be written to ordinary config
  files, frontend storage, logs, or SQLite. The `providers` crate stores them
  through Windows Credential Manager and returns only configured/masked status
  to the frontend.
- Every IPC request and response must have explicit Rust and TypeScript types.

## Project Documents

- [MCP architecture, tools, installation and host integrations](docs/mcp/README.md)
- [Privacy vNext operations guide](docs/privacy-vnext/OPERATIONS.md)
- [MCP security and privacy](docs/mcp/security-and-privacy.md)
- [v0.4.0-beta.2 Privacy vNext prerelease notes and MCP compatibility](RELEASE_NOTES.md)
- [WorkBuddy integration package](integrations/workbuddy/README.md)
- [Codex integration package](integrations/codex/README.md)
- [OpenCode integration package](integrations/opencode/README.md)
- [引用 ID 规则](docs/citation-ids.md)

## Development Commands

Build the standalone portable MCP binary on the current platform:

```powershell
cargo build --locked -p legal-mcp --bin lawyer-assistance-mcp
cargo test --locked -p legal-services -p legal-mcp
python integrations\validate_examples.py
```

The databases remain external files. Set their paths and the filesystem
boundaries with CLI flags, a config file, or the documented
`LAWYER_ASSISTANCE_*` environment variables; never package a real `user.sqlite`
or the multi-gigabyte legal database into a Skill or source archive.

Install dependencies:

```powershell
pnpm install
```

Run all required checks:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features --offline -- -D warnings
cargo test --locked --workspace --offline
pnpm lint
pnpm test
pnpm build
python -W error::ResourceWarning -m unittest discover -s data/build -p "test_*.py"
python data/build/audit_provider_security.py
python -m unittest discover -s workers/mineru/tests -t workers/mineru -p "test_*.py" -v
python -m unittest scripts.test_build_production_mineru_worker scripts.test_build_mineru_component_package
python -m unittest integrations.test_validate_examples integrations.test_validate_approved_workspace_examples
python integrations/validate_examples.py
python integrations/validate_approved_workspace_examples.py
python apps/desktop/scripts/verify_legal_resource.py
python -m unittest scripts.test_generate_third_party_notices
python scripts/generate_third_party_notices.py --check
python -m unittest scripts.test_package_mcp_release
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test_qualify_local_mineru.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-standalone-approved-mcp.ps1
```

Run the repeatable Provider secret/logging audit:

```powershell
python data\build\audit_provider_security.py
```

Run the audit's own regression tests:

```powershell
python -m unittest data.build.test_audit_provider_security
```

Run the formal-database integration gates explicitly. The current suite contains
six citation tests, six retrieval/relationship-graph tests, and one Stage 5
document-citation test. They are ignored by ordinary CI so a fixture cannot
masquerade as the product corpus:

```powershell
$env:LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE = (Resolve-Path apps\desktop\src-tauri\resources\legal_core.sqlite)
cargo test --locked --offline -p citations --test formal_legal_core -- --ignored
cargo test --locked --offline -p retrieval --test formal_legal_core -- --ignored
cargo test --locked --offline -p lawyer-assistance-desktop commands::document::tests::acceptance_workspace_citations_match_the_formal_legal_database -- --ignored --exact
Remove-Item Env:LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE
```

Build only the frontend:

```powershell
pnpm build
```

Build an unsigned technical packaging artifact for compilation/resource smoke
testing only; this is not a formal release:

```powershell
pnpm tauri build --config src-tauri/tauri.ci.conf.json
```

Build a fresh deterministic portable ZIP from a clean commit:

```powershell
pnpm --filter @lawyer-assistance/desktop release:portable
```

Build the explicitly unsigned NSIS technical prerelease from a clean commit:

```powershell
pnpm --filter @lawyer-assistance/desktop release:installer:unsigned
```

It emits `Lawyer.Assistance_<version>_windows-x86_64-unsigned-setup.exe`,
its `.sha256`, and `.manifest.json`. The script verifies `signed=false`,
`updaterArtifactGenerated=false`, and refuses signing secrets. It does not
generate `latest.json` or an updater `.sig`; never rename this artifact to look
signed.

Build the formal Authenticode-signed NSIS, updater signature, `latest.json`, and
signed portable ZIP. The updater key password must come from the release secret
store and the certificate must be trusted and contain its private key:

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = '<from-secret-store>'
pnpm --filter @lawyer-assistance/desktop release:signed -- -CodeSigningThumbprint <trusted-thumbprint>
```

The local Tauri build requires the compact, audited runtime database at
`apps/desktop/src-tauri/resources/legal_core.sqlite`. A fresh source checkout
does not contain this generated resource. The complete archival/audit database
is kept separately at `data/generated/legal_core_full.sqlite` and is never
bundled into the app. The current runtime is 1,775,419,392 bytes and is bound by
its distribution manifest to the 4,512,894,976-byte archival source.

Regenerate the complete archival official-source legal database:

```powershell
python data\build\build_legal_core.py --stage all --source all --resume --workers 1 --min-delay 3 --max-delay 8 --stop-on-waf --strict --output data\generated\legal_core_full.sqlite --report data\generated\legal_core_build_report.json
```

Audit the complete archival database without rebuilding:

```powershell
python data\build\build_legal_core.py --stage audit --strict --output data\generated\legal_core_full.sqlite --report data\generated\legal_core_strict_audit_report.json
```

Normalize official FLK history families after a full Stage 1B build:

```powershell
python data\build\stage_1c_history.py --strict
```

This command works on a same-directory safety copy, runs interval/FTS/foreign
key/integrity audits, writes the exact archival hash to
`data/generated/legal_core_full_manifest.json`, and replaces the full database
only after strict acceptance succeeds.

Build the official case/template corpora and finalize schema v4:

```powershell
python data\build\stage_1c_corpora.py --strict --workers 6 --min-delay 0.08
```

After the full database passes strict audit, generate the read-only runtime
projection that is actually bundled with the app:

```powershell
python data\build\compact_legal_core.py
python data\build\verify_legal_core_distribution.py --verify-only --source apps\desktop\src-tauri\resources\legal_core.sqlite
cargo run -p retrieval --example benchmark_legal_core -- data\generated\legal_core_full.sqlite apps\desktop\src-tauri\resources\legal_core.sqlite 30 data\generated\legal_core_performance_report.json --strict
```

The runtime projection preserves every document, version, article identity,
stable citation id and source checksum. It stores exact duplicate article text
once, uses a contentless FTS5 index, and omits raw fetch payloads and audit-only
corpora that no application command reads. The strict audit report and full
database remain the rebuild/provenance authority.

Verify and atomically install an externally distributed database:

```powershell
python data\build\verify_legal_core_distribution.py --manifest <manifest-url-or-path> --source <database-url-or-path>
```

For an HTTP(S) manifest, also pass its externally published SHA-256 using
`--manifest-sha256`. The database is installed only after the manifest trust
root, artifact hash, formal identity, exact row counts, SQLite integrity,
runtime object shape, and archival-source binding all pass.

There is intentionally no `pnpm dev` script in this phase because the project must not rely on a Vite localhost development server.
