# Getting started

## Run the portable package

1. Download and extract the GitHub Release asset `Lawyer-Assistance_1.0.0_windows-x86_64-portable.zip` on Windows x86_64.
2. Verify the adjacent `.zip.sha256`, then inspect `MANIFEST.sha256` and `portable.manifest.json` inside the ZIP.
3. Double-click `Lawyer-Assistance.vbs`. It invokes `wscript.exe` with a hidden window and runs `lawyer-assistance.exe serve --open --port 8877`.
4. Open `http://127.0.0.1:8877`. User data defaults to `%LOCALAPPDATA%\LawyerAssistanceWeb`. The portable package is unsigned and includes no installer or automatic updater.

To stop the service, double-click `Stop-Lawyer-Assistance.vbs` or run `lawyer-assistance.exe stop`. The command verifies the current user's encrypted connection descriptor and uses an authenticated loopback session plus CSRF check; it never calls `taskkill`.

If a service is already running, run `lawyer-assistance.exe login`. The old Tauri data directory is never read, migrated, or overwritten.

## Run from source

```powershell
pnpm install
cargo run --release --locked -p lawyer-assistance-server --bin lawyer-assistance -- serve `
  --open --port 8877 `
  --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" `
  --legal-db "$pwd\data\runtime\legal_core.sqlite"
```

Without `--legal-db`, the server checks `data/runtime/legal_core.sqlite` beside the executable and then the same path below the current directory. A missing legal database blocks legal research only; it does not rewrite the user workspace.

## Redact material

1. Create a material group in **Material redaction** and maintain its group dictionary.
2. Select TXT or DOCX files and submit an import task. If TXT encoding is ambiguous, choose an encoding and retry; invalid bytes are never silently replaced. DOCX body text and tables are extracted, while images, embedded objects, revisions, or unsupported structures are reported explicitly.
3. Review detected names, organizations, addresses, phones, email addresses, identity numbers, case numbers, and account identifiers. Same-group entities receive stable aliases, then local replacement and residual scanning run.
4. Add dictionary entries, edit aliases, mark false positives, or explicitly authorize one cloud-assistance request for the exact material version, Provider, model, and purpose. Only extracted text is sent; returned candidates are locally verified before replacement.
5. A complete, conflict-free, alias-consistent, residual-clean task produces an immutable usable result. Failed or pending-review results cannot be read through MCP.
6. Export TXT, Markdown, reconstructed DOCX, or a ZIP of usable results. Export rereads and validates generated files.

## Legal research, templates, and chat

Legal research supports keyword search, law/article details, versions, effective dates, and relations. Results can be bookmarked and copied as citations. Fixed templates provide form-based previews and TXT/Markdown/DOCX export. Provider chat sends only user input and explicitly selected legal articles and valid redacted results; it never reads original material automatically. Real Provider integration has not been completed for this public release; related validation uses a controllable simulation service.

## MCP

The public profile uses the standalone program:

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

It exposes five fixed read-only public-law tools. The `privacy_workspace` profile exposes eight tools in total: those five plus submit/status/read_result. It requires a client token created in **Settings** and calls the running loopback server. Configure an inbox and material group, then send only relative paths below that inbox. The profile never returns original text, mappings, original filenames, or disk paths.

## Limits

PDF/image input, scanned-document OCR, and original-layout preservation are not supported. OCR is only an extension boundary. Cloud assistance is validated with a controllable simulation service; synthetic-material pass, false-positive, and missed-detection reports are not a real-case accuracy guarantee. Do not describe the portable ZIP or a source build as a signed installer, a live updater, or an OCR-qualified asset.
