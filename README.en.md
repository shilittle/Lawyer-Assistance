# Lawyer Assistance

[中文](README.md)

Lawyer Assistance is a Windows single-user legal tool built around one Rust backend, a plain HTML WebUI, and an independently callable MCP program. This release focuses on material redaction and local legal research.

The current release is `1.2.1`. It retains model-assisted redaction, legal retrieval, document writing, and conversations while repairing task/version binding, encrypted drafts, search consistency, resource limits, PDF isolation, citation evidence, and context budgets. See the [independent-retest follow-up record](docs/web/retest-1.2.1.md) and the release validation summary. The [previous report](docs/web/audit-1.2.1.md) remains historical evidence. Download it from the [v1.2.1 release page](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v1.2.1-r1).

TXT, DOCX, PDF, PNG, JPEG and WebP inputs produce plain UTF-8 redacted TXT. Document writing renders one shared Markdown structure to safe preview HTML, plain TXT, structured DOCX and default A4 PDF. Provider presets discover available models using the supplied key and support separate chat, redaction, writing and OCR defaults. Trusted domestic official endpoints may receive explicitly selected originals; other providers require valid redacted references. User data remains protected by the local Windows service.

The existing seven public MCP tools and ten privacy-workspace tools remain compatible. The official SPC sidecar contains 759 primary cases/articles: 279 guiding cases, 61 reference cases, and 419 typical-case collections, with 834 retained TXT source entries. Typical collections may contain multiple cases and are retrieved as one article; Guiding Case 45 retains its official Luoyang Intermediate People's Court repost. See the [upgrade guide](docs/web/ai-upgrade.md), [AI validation report](docs/web/ai-validation.md), and the source manifests.

## Portable Windows package

The local builder `scripts/package_portable.py` produces `Lawyer-Assistance_1.2.1_windows-x86_64-portable.zip`. Release filenames also carry the date and source commit. Assets include the ZIP, its adjacent `.zip.sha256`, and the JSON manifests. The Windows x86_64 portable ZIP contains two release executables, `legal_core.sqlite`, the sibling `judicial_cases.sqlite` sidecar, its source note and distribution manifest, the derived retrieval index, licenses/notices, current documentation and MCP examples, `Lawyer-Assistance.vbs`, and `Stop-Lawyer-Assistance.vbs`. Extract it and double-click a launcher; it invokes `wscript.exe` with a hidden window:

```powershell
lawyer-assistance.exe serve --open --port 8877 --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" --legal-db "<package>\data\runtime\legal_core.sqlite"
```

User data is stored under `%LOCALAPPDATA%\LawyerAssistanceWeb`; the package does not migrate or overwrite the old Tauri workspace. The browser opens at `http://127.0.0.1:8877`. If a service is already running, `lawyer-assistance.exe login` opens its saved local session.

To stop the service, double-click `Stop-Lawyer-Assistance.vbs` or run `lawyer-assistance.exe stop`. The command reads the current user's encrypted connection descriptor and sends an authenticated loopback session/CSRF shutdown request to the matching server process; it never kills an arbitrary process.

After receiving the ZIP, verify the adjacent `.zip.sha256`, then inspect `MANIFEST.sha256` and `portable.manifest.json` inside the archive. The portable manifest must include size, SHA-256, schema, count, and official-source identity for both databases. The v1.2.1 artifact is an unsigned Windows portable package; it has no installer, signature file, or updater file.

## Development

Use a stable/MSVC Rust toolchain, Node.js `>=24`, pnpm `>=11`, and Python 3. The WebUI is embedded into the Rust binary from `apps/web`; it does not require a frontend development server:

```powershell
pnpm install
pnpm check
pnpm test
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
pnpm build
```

Run the backend directly with an absolute legal-database path. Without `--data-dir`, the service uses `%LOCALAPPDATA%\LawyerAssistanceWeb`:

```powershell
cargo run --release --locked -p lawyer-assistance-server --bin lawyer-assistance -- serve `
  --open --port 8877 `
  --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" `
  --legal-db "$pwd\data\runtime\legal_core.sqlite"
```

Build the portable package (this builds both release executables):

```powershell
python scripts/package_portable.py
```

When release executables already exist, validate resources and package them with:

```powershell
python scripts/package_portable.py --skip-build
```

The script only creates a ZIP, SHA-256 sidecar, and JSON manifest. It does not upload to GitHub or create an installer, signature, `.sig`, `latest.json`, or updater file.

## MCP

The public MCP uses the runtime legal database and never opens the private workspace:

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

The fixed public profile contains seven tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations`, `legal_search_cases`, and `legal_get_case`. The `privacy_workspace` profile contains ten tools in total, adding `privacy_workspace.submit`, `privacy_workspace.status`, and `privacy_workspace.read_result`. The original five legal tool names and I/O contracts remain unchanged; a missing case sidecar is reported as unavailable while the statute database identity remains unchanged.

`privacy_workspace` uses a client token created by the WebUI and proxies requests to a running local backend. It accepts only relative paths below the configured inbox, returns task status, and pages through published redacted text. It never returns original text, mappings, original filenames, or disk paths. The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are disabled and are not silently mapped to the new profile.

See the [MCP documentation](docs/mcp/README.md) for the protocol and tool contracts.

## Documentation

- [Getting started](docs/getting-started.en.md)
- [Security and privacy](docs/security-and-privacy.en.md)
- [Legal data and runtime database](docs/data/legal-corpus.md)
- [MCP documentation](docs/mcp/README.md)
- [Web core and operating boundaries](docs/web/README.md)
- [AI incremental validation report](docs/web/ai-validation.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [v1.2.1 release notes](RELEASE_NOTES.md)

Legal data supports research and lawyer review; it does not replace checking current official text, facts, or professional advice.

## License

Source code is MIT licensed. Runtime legal-data provenance, licensing, and third-party notices are shipped under `data/runtime/` and documented in [legal-data sources](data/runtime/DATA_SOURCES.md), [case sources](data/runtime/CASE_DATA_SOURCES.md), and the [legal-data guide](docs/data/legal-corpus.md).
