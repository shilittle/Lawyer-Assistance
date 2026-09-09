# Lawyer Assistance

[中文](README.md)

Lawyer Assistance is a Windows single-user legal tool built around one Rust backend, a plain HTML WebUI, and an independently callable MCP program. This release focuses on material redaction and local legal research.

The current release is `1.0.0`, the public Web major release after the Tauri refactor. Windows artifacts are unsigned portable packages; there is no installer or automatic updater.

## Product boundary

- **Material redaction:** import TXT and DOCX, extract body text and tables, detect common names, organizations, contact details, identity numbers, case numbers, and account identifiers, replace them with stable group aliases, and run a residual scan before publishing a result.
- **Review and export:** add sensitive terms, edit aliases, resolve difficult findings, or revoke a result in the WebUI. Export TXT, Markdown, reconstructed DOCX, or a batch ZIP.
- **Legal research:** query the read-only `legal_core.sqlite` runtime database for laws, articles, versions, effective dates, relations, and bookmarks.
- **Small utilities:** six fixed document templates and a simple Provider conversation whose context can include explicitly selected legal articles and valid redacted results. Real Provider integration has not been completed for this public release; validation uses a controllable simulation service.
- **MCP:** `public_law_only` exposes five read-only public-law tools. `privacy_workspace` exposes eight tools in total: those five public tools plus submit, status, and paged result-reading.

PDF/image input, scanned-document OCR, original-layout preservation, complex case management, legal graphs, and autonomous legal workflows are outside v1.0.0. OCR is only an extension boundary; no OCR runtime is installed or published. Cloud assistance is validated with a controllable simulation service; synthetic-material pass, false-positive, and missed-detection reports are regression evidence, not a real-case accuracy guarantee.

## Portable Windows package

Download `Lawyer-Assistance_1.0.0_windows-x86_64-portable.zip`. The Windows x86_64 portable ZIP contains two release executables, the runtime legal database, licenses/notices, current documentation and MCP examples, `Lawyer-Assistance.vbs`, and `Stop-Lawyer-Assistance.vbs`. Extract it and double-click a launcher; it invokes `wscript.exe` with a hidden window:

```powershell
lawyer-assistance.exe serve --open --port 8877 --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" --legal-db "<package>\data\runtime\legal_core.sqlite"
```

User data is stored under `%LOCALAPPDATA%\LawyerAssistanceWeb`; the package does not migrate or overwrite the old Tauri workspace. The browser opens at `http://127.0.0.1:8877`. If a service is already running, `lawyer-assistance.exe login` opens its saved local session.

To stop the service, double-click `Stop-Lawyer-Assistance.vbs` or run `lawyer-assistance.exe stop`. The command reads the current user's encrypted connection descriptor and sends an authenticated loopback session/CSRF shutdown request to the matching server process; it never kills an arbitrary process.

Verify the adjacent `.zip.sha256`, then inspect `MANIFEST.sha256` and `portable.manifest.json` inside the archive. The v1.0.0 public artifact is an unsigned local portable package; it has no installer, signature file, or updater file.

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

The fixed public profile contains five tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`. The `privacy_workspace` profile contains eight tools in total, adding `privacy_workspace.submit`, `privacy_workspace.status`, and `privacy_workspace.read_result`.

`privacy_workspace` uses a client token created by the WebUI and proxies requests to a running local backend. It accepts only relative paths below the configured inbox, returns task status, and pages through published redacted text. It never returns original text, mappings, original filenames, or disk paths. The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are disabled and are not silently mapped to the new profile.

See the [MCP documentation](docs/mcp/README.md) for the protocol and tool contracts.

## Documentation

- [Getting started](docs/getting-started.en.md)
- [Security and privacy](docs/security-and-privacy.en.md)
- [Legal data and runtime database](docs/data/legal-corpus.md)
- [MCP documentation](docs/mcp/README.md)
- [Web core and operating boundaries](docs/web/README.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [v1.0.0 release notes](RELEASE_NOTES.md)

Legal data supports research and lawyer review; it does not replace checking current official text, facts, or professional advice.

## License

Source code is MIT licensed. Runtime legal-data provenance, licensing, and third-party notices are shipped under `data/runtime/` and documented in [DATA_SOURCES.md](data/runtime/DATA_SOURCES.md) and the [legal-data guide](docs/data/legal-corpus.md).
