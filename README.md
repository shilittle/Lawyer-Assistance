# Lawyer Assistance

Windows-first Tauri 2 desktop application for legal assistance workflows.

## Current Scope

As of 2026-07-16, the engineering scope of Stages 0–7 is implemented: offline
legal retrieval, provider configuration, citation-grounded answers, local
case/evidence work, six legal-document workflows, case/law graphs, and the
Windows release/update/backup lifecycle. Automated gates use the formal legal
resource where product identity matters. Authenticode certification and
clean-machine Windows 10/11 qualification are external release-operations
gates, not unfinished application development:

- Tauri 2 desktop shell for Windows x86_64
- React, TypeScript, and Vite frontend
- pnpm workspace and Rust Cargo workspace
- Rust crates split into `domain`, `database`, `retrieval`, `providers`, and `citations`
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
- Citation-grounded legal answer command using BYOK provider profiles and in-process mock-provider tests
- Legal answer records persisted with verified citation reports, not trusted raw model citations
- React citation Q&A workspace with candidate sources, clickable verified inline citations, explicit invalid/duplicate marker styling, citation validation status, and local source text
- Case project CRUD persisted in `user.sqlite`
- Case workspace data model for files, parties, facts, evidence, legal issues, validated legal basis records, and explicit project-scoped fact-evidence/fact-issue links; composite database constraints reject cross-case relationships
- Rust-side case gap analysis for timeline conflicts, party name inconsistencies, missing evidence support, missing source/date metadata, invalid evidence references, and open legal issues without validated legal basis
- Case legal basis binding through local `[SRC:...]` source ids with Rust-side citation/effectiveness validation and read-only lookups against `legal_core.sqlite`
- Structured case extraction JSON parser with strict Rust deserialization and one repair-attempt path
- React case workspace with project list, editable persisted case files/parties/facts/evidence/issues, fact timeline, evidence catalog, legal basis panel, explicit fact-evidence and fact-issue link editors, gap panel, and extraction review panel
- Six reviewed legal-document templates with structured validation, confirmed-data-only assembly, local citation traceability, Markdown preview, pure-Rust DOCX generation, crash-safe export and persisted generation audit records
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

Stage 3 implements Tauri Channel streaming, cancellation, local citation
validation and verified persistence. Stage 4 implements local case/evidence
persistence, legal-basis binding, provider-driven structured extraction, one
automatic repair, bounded review state, user confirmation and atomic
persistence. The current extraction scope intentionally sends selected material
summaries rather than reading original files. Embeddings and local-model
workflows remain explicitly outside the product architecture.

The 2026-07-13 hardening pass adds bounded IPC text/array/response inputs,
strict Gregorian `YYYY-MM-DD` validation, UUID v4 answer record ids, correct
current-law selection that excludes future and fully expired versions, and
database-enforced project ownership for evidence links and legal-basis issue
links. It also repairs unmarked or legacy `user.sqlite` v6 shapes through one
atomic canonical rebuild, serializes read-then-write transactions with
`BEGIN IMMEDIATE`, rejects stale case-workspace responses, preserves finalized
Q&A context across page changes, locks extraction navigation correctly, and
supports editing persisted case child records. The declared engineering scope
is complete; optional hands-on GUI observations remain release-qualification
evidence and do not reopen completed development.

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

- Windows x86_64 is the only supported target in the current phase.
- The app must not create an HTTP server, FastAPI service, Express service, localhost service, or sidecar process.
- The packaged app must not introduce a local LLM, embedding model, Python runtime, or Node runtime.
- The frontend is UI-only and calls Rust through typed Tauri commands.
- SQLite queries, model API requests, and credential access must run in Rust.
- The frontend must never execute arbitrary SQL.
- `legal_core.sqlite` is bundled as an app resource and treated as read-only.
- `user.sqlite` is created as the writable user database under LocalAppData.
- Case and evidence business data is stored through Rust-managed `user.sqlite` tables, not frontend storage.
- API keys must not be written to ordinary config files, frontend storage, logs, or SQLite. The `providers` crate stores API keys through Windows Credential Manager and returns only configured/masked status to the frontend.
- Every IPC request and response must have explicit Rust and TypeScript types.

## Project Documents

- [引用 ID 规则](docs/citation-ids.md)

## Development Commands

Install dependencies:

```powershell
pnpm install
```

Run all required checks:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --offline -- -D warnings
cargo test --locked --workspace --offline
pnpm lint
pnpm test
pnpm build
python -W error::ResourceWarning -m unittest discover -s data/build -p "test_*.py"
python data/build/audit_provider_security.py
python apps/desktop/scripts/verify_legal_resource.py
python scripts/generate_third_party_notices.py --check
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
six citation tests, five retrieval/relationship-graph tests, and one Stage 5
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
