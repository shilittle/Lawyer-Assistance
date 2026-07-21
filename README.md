# Lawyer Assistance

Rust-first legal-assistance platform with a cross-platform-targeted MCP server and an optional Windows Tauri 2 professional review station. WorkBuddy, Codex, and OpenCode share the same public-law MCP contract.

Production MCP and all checked-in host integrations use `public_law_only`:

```text
lawyer-assistance-mcp --privacy-profile public_law_only stdio
lawyer-assistance-mcp --privacy-profile public_law_only serve --bind 127.0.0.1:8787
```

Its exact surface is five read-only tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`. stdio and HTTP must expose the same names and order.

The experimental `redacted_case` profile adds only receipt-gated `citation_validate` (six tools total). The App cannot yet issue a receipt bound to that MCP purpose, destination, and exact request bytes, so production remains on the public five. Case reads/writes, material import, gap analysis, document generation, and export are hidden in both profiles. Shared case/document implementations in `crates/legal-services` are not an external MCP capability.

Provider transport also lacks an App-to-Provider case receipt path. It accepts only explicitly public legal/product classifications before serialization; legacy case-bearing requests are `CASE_RAW` and fail closed. Local App review and approval do not automatically authorize MCP or Provider egress.

MCP and repository prompts cannot prevent or retract a first message or attachment that a host sent before loading its Skill/Agent rules. Do not put client or case material into WorkBuddy, Codex, OpenCode, or another external model task.

For local material preparation, PDF/DOCX/TXT/Markdown can enter the App's local extraction, automated redaction, human review, exact receipt and safe text-PDF workflow. The reconstructed PDF embeds a hash-pinned common CJK font; unsupported glyphs fail closed instead of rendering tofu. A confirmed lifecycle action deletes the App's protected review payload and every associated receipt while preserving hash-only audit; it never deletes the user-selected source or separately saved PDF.


HTTP remains loopback-only by default. A non-loopback cleartext bind is rejected even with Bearer authentication; production remote access terminates TLS at a trusted reverse proxy connected to the loopback listener.

## Current Scope

As of 2026-07-19, the historical engineering scope of Stages 0–7 remains implemented for local desktop use: offline legal retrieval, provider configuration, citation-grounded public-law answers, local case/evidence work, six local legal-document workflows, case/law graphs, and the Windows release/update/backup lifecycle. Stage 8 adds an assistant-first product layer and a local privacy/redaction workflow. The 2026-07-19 privacy hardening is a current constraint over those historical outcomes: case-bearing Provider requests fail closed, external MCP hosts receive only the public-law five-tool profile, and scanned/visual PDF processing remains blocked until local OCR is authenticated end to end. Authenticode certification and clean-machine Windows 10/11 qualification remain external release-operations gates:

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
- Conversation-first Assistant workspace with unbound or case-bound local conversations, bounded history, typed run events and cancellation; Provider transport is public-only and rejects case-bearing runs before serialization
- Rust-side PDF, DOCX, UTF-8 TXT and Markdown privacy import with format checks and hard limits; reliable text-layer PDFs can be reviewed and exported as a font-embedded safe text PDF, protected review state can be explicitly revoked/deleted, while the MinerU runner is not connected by the App and scanned/visual PDFs fail closed
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
- Citation-grounded public-law answer command using BYOK provider profiles and in-process mock-provider tests; no case-bearing Provider egress path is enabled
- Legal answer records persisted with verified citation reports, not trusted raw model citations
- React citation Q&A workspace with candidate sources, clickable verified inline citations, explicit invalid/duplicate marker styling, citation validation status, and local source text
- Case project CRUD persisted in `user.sqlite`
- MCP privacy profiles with a production `public_law_only` five-tool surface; experimental `redacted_case` adds one receipt-gated citation tool but has no App signing path, and all case/material/document tools remain hidden
- Case workspace data model for files, parties, facts, evidence, legal issues, validated legal basis records, and explicit project-scoped fact-evidence/fact-issue links; composite database constraints reject cross-case relationships
- Rust-side case gap analysis for timeline conflicts, party name inconsistencies, missing evidence support, missing source/date metadata, invalid evidence references, and open legal issues without validated legal basis
- Case legal basis binding through local `[SRC:...]` source ids with Rust-side citation/effectiveness validation and read-only lookups against `legal_core.sqlite`
- Structured case extraction JSON parser with strict Rust deserialization and one repair-attempt path
- React case workspace with project list, editable persisted case files/parties/facts/evidence/issues, fact timeline, evidence catalog, legal basis panel, explicit fact-evidence and fact-issue link editors, gap panel, and extraction review panel
- Six reviewed legal-document templates for local desktop workflows, with structured validation, local citation traceability, rendered Markdown/source preview, and pure-Rust PDF export; local approval/export does not grant MCP or Provider egress
- Case and formal-law graph workspaces with namespaced identities, confirmed nodes, persisted fact-evidence/fact-issue/issue-citation edges, formal `law_relations`, provenance, filtering, search, layout controls, details and exact source jumps
- Version information, atomic backup, validated restart-time restore, payload-free crash/maintenance events and redacted diagnostic export
- A signed-update protocol with strict GitHub URL policy, semantic-version checks, streaming download, Minisign verification, trusted-filename binding, NSIS handoff and stale-installer cleanup
- Reproducible release scripts for Authenticode-signed NSIS, updater `latest.json`, deterministic portable ZIP, legal-resource identity verification and complete third-party notices
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

Stage 3 implements the compatibility legal-answer Tauri Channel streaming, cancellation, local citation
validation and verified persistence. Stage 4 implements local case/evidence
persistence, legal-basis binding, provider-driven structured extraction, one
automatic repair, bounded review state, user confirmation and atomic
persistence. Its legacy case-extraction flow still sends selected case-material
summaries. Stage 8 separately imports the actual bytes of up to two selected
PDF/DOCX/TXT/Markdown files through Rust and can expose their bounded extracted
text to an Assistant run after the UI shows the exact scope. Embeddings and
local-model workflows remain explicitly outside the product architecture.

The 2026-07-13 hardening pass adds bounded IPC text/array/response inputs,
strict Gregorian `YYYY-MM-DD` validation, UUID v4 answer record ids, correct
current-law selection that excludes future and fully expired versions, and
database-enforced project ownership for evidence links and legal-basis issue
links. It also repairs unmarked or legacy `user.sqlite` v6 shapes through one
atomic canonical rebuild, serializes read-then-write transactions with
`BEGIN IMMEDIATE`, rejects stale case-workspace responses, preserves finalized
Q&A context across page changes, locks extraction navigation correctly, and
supports editing persisted case child records. The declared engineering scope
is complete. The native MCP control page has a local Windows release-app
start/auth/stop/auto-start acceptance record; broader hands-on GUI,
clean-machine, signing, SmartScreen, AV/EDR, and Windows 10/11 qualification
remain required release-operations evidence and do not reopen completed
application development.

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
- [MCP security and privacy](docs/mcp/security-and-privacy.md)
- [v0.4.0-beta.1 Privacy vNext prerelease notes and MCP compatibility](RELEASE_NOTES.md)
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
python apps/desktop/scripts/verify_legal_resource.py
python -m unittest scripts.test_generate_third_party_notices
python scripts/generate_third_party_notices.py --check
python -m unittest scripts.test_package_mcp_release
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
