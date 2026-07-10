# Lawyer Assistance

Windows-first Tauri 2 desktop application for legal assistance workflows.

## Current Scope

This repository contains the Stage 0 foundation and the current implementation
baseline for Stages 1 through 4: offline legal retrieval, provider
configuration, citation-grounded answers, and the local case/evidence
workspace. A 2026-07-10 review found that Stages 1 through 4 still have data,
workflow, or manual-acceptance gaps, so they are no longer described as fully
accepted:

- Tauri 2 desktop shell for Windows x86_64
- React, TypeScript, and Vite frontend
- pnpm workspace and Rust Cargo workspace
- Rust crates split into `domain`, `database`, `retrieval`, `providers`, and `citations`
- Versioned `legal_core.sqlite` schema in `data/schema/legal_core.sql`
- Bundled read-only `legal_core.sqlite` official-source legal metadata index
- Writable `user.sqlite` created under the app's LocalAppData directory with transaction-based migrations
- Strongly typed `health_check` Tauri command with matching Rust and TypeScript types
- Strongly typed offline retrieval commands:
  - `search_laws`
  - `search_articles`
  - `get_article`
  - `get_law_versions`
  - `get_law_relations`
- React offline search workspace with law results, article results, article details, versions, and relations
- Provider profile CRUD for DeepSeek, Qwen / Alibaba Cloud Model Studio, SiliconFlow, and Volcengine Ark
- Windows Credential Manager API key storage with masked status only returned to the frontend
- Shared OpenAI-compatible provider adapter with provider-specific option mapping and in-process mock transport tests
- Streaming response parser foundation for OpenAI-compatible SSE chunks
- Provider settings page with model ID, Base URL, extension options, masked key status, and connection test results
- Source-bounded legal answer context assembly from the local legal database
- Citation parser and Rust-side validator for `[SRC:...]` source ids
- Citation-grounded legal answer command using BYOK provider profiles and in-process mock-provider tests
- Legal answer records persisted with verified citation reports, not trusted raw model citations
- React citation Q&A workspace with candidate sources, answer panel, citation validation status, and local source text
- Case project CRUD persisted in `user.sqlite`
- Case workspace data model for files, parties, facts, evidence, fact-evidence links, legal issues, and validated legal basis records
- Rust-side case gap analysis for timeline conflicts, party name inconsistencies, missing evidence support, missing source/date metadata, invalid evidence references, and open legal issues without validated legal basis
- Case legal basis binding through local `[SRC:...]` source ids with Rust-side citation/effectiveness validation and read-only lookups against `legal_core.sqlite`
- Structured case extraction JSON parser with strict Rust deserialization and one repair-attempt path
- React case workspace with project list, case files, parties, fact timeline, evidence catalog, issue list, legal basis panel, link editor, gap panel, and extraction parser panel
- Rust unit tests, Vitest, ESLint, and Windows GitHub Actions CI

The local `legal_core.sqlite` is generated from official public sources and is
not a sample dataset. Its declared statutory-source coverage state is
`complete`: strict audit passes with schema version 3, full-text article rows
and FTS rows aligned, and zero placeholder article rows. It does not yet include
the separately sourced guiding-case, typical-case, or document-template corpora
required by the full MVP plan, and it currently contains no document with more
than one historical version. Stage 3 implements synchronous source-bounded
answers with local citation validation; true frontend-visible streaming remains
to be implemented. Stage 4 implements local case/evidence persistence, legal
basis binding, manual entry, structured extraction parsing, and deterministic
gap checks; provider-driven extraction, automatic repair, review, and confirmed
persistence remain to be completed. The project still does not implement
document generation, graph workflows, embeddings, or local model workflows.

## Repository Data Policy

The official-source database is a generated local/release artifact, not a Git
blob. The audited 2026-07-10 snapshot is 3,962,118,144 bytes with SHA-256
`9f6cb72534064938b56e1803daf477ade98f33de73ec0ea27076c51366a290d7`.
It is intentionally excluded from source control because it exceeds GitHub's
ordinary Git object limits. Build/runtime state under `data/build/state/` is
also excluded because it can contain cookies, job databases, and process state.

GitHub Actions creates a clearly marked CI-only fixture database solely for the
Tauri packaging smoke test. That fixture is not a product database and must
never be uploaded as a release artifact. A versioned external distribution and
hash-verification workflow for the official database is a Stage 7 prerequisite.

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
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm lint
pnpm test
pnpm build
pnpm tauri build
```

Build only the frontend:

```powershell
pnpm build
```

Build the Tauri desktop binary:

```powershell
pnpm tauri build
```

The local Tauri build requires the audited official database at
`apps/desktop/src-tauri/resources/legal_core.sqlite`. A fresh source checkout
does not contain that generated 3.69 GiB resource.

Regenerate the bundled official-source legal database:

```powershell
python data\build\build_legal_core.py --stage all --source all --resume --workers 1 --min-delay 3 --max-delay 8 --stop-on-waf --strict --output apps\desktop\src-tauri\resources\legal_core.sqlite --report data\generated\legal_core_build_report.json
```

Audit the bundled database without rebuilding:

```powershell
python data\build\build_legal_core.py --stage audit --strict --output apps\desktop\src-tauri\resources\legal_core.sqlite --report data\generated\legal_core_strict_audit_report.json
```

There is intentionally no `pnpm dev` script in this phase because the project must not rely on a Vite localhost development server.
