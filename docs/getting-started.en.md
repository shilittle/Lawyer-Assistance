# Getting started

This page describes v1.2.0. It builds on the V1.0.0 Web workspace with model-led material redaction, complete paged legal research, AI legal research, document writing, and AI conversations with legal tools. See the [upgrade guide](web/ai-upgrade.md) for migration details and the [AI incremental validation report](web/ai-validation.md) for executed commands, model calls, case retrieval checks, and limits. Delivery is a local Windows portable ZIP with a SHA-256 sidecar and JSON manifests; this page does not claim that a GitHub Release has been published.

## Run the portable package

1. Build or obtain `Lawyer-Assistance_1.2.0_windows-x86_64-portable.zip` with `scripts/package_portable.py`, then extract it on Windows x86_64.
2. Verify the adjacent `.zip.sha256`, then inspect `MANIFEST.sha256` and `portable.manifest.json` inside the ZIP.
3. Double-click `Lawyer-Assistance.vbs`. It invokes `wscript.exe` with a hidden window and runs `lawyer-assistance.exe serve --open --port 8877`.
4. Open `http://127.0.0.1:8877`. User data defaults to `%LOCALAPPDATA%\LawyerAssistanceWeb`. The portable package is unsigned and includes no installer or automatic updater.

The package includes `legal_core.sqlite`, the sibling Supreme People's Court case sidecar `judicial_cases.sqlite`, a derived retrieval index, case provenance and distribution manifests, Pdfium, Typst, Chinese fonts, and MCP examples. The sidecar contains 759 primary cases/articles: 279 guiding cases, 61 reference cases, and 419 typical-case collections; its source inventory keeps 834 TXT source entries. A typical collection may contain multiple cases and remains one `typical` article for retrieval. Guiding Case 45 retains the official Luoyang Intermediate People's Court repost. See `CASE_DATA_SOURCES.md` and `judicial_cases_manifest.json` for provenance and hashes.

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

Without `--legal-db`, the server checks `data/runtime/legal_core.sqlite` beside the executable and then the same path below the current directory. After finding the statute database, it discovers `judicial_cases.sqlite` automatically in the same `data/runtime` directory. A missing statute database blocks statute research; a missing case sidecar makes case research unavailable; neither changes the user workspace.

## Redact material

1. Create a material group in **Material redaction** and maintain its group dictionary.
2. Select TXT, DOCX, PDF, PNG, JPEG, or WebP files and submit an import task. PDF, image, and embedded DOCX images go through the configured cloud visual OCR model; TXT and DOCX body text is extracted locally first. With no model configured, TXT/DOCX retain the local path and the task reports the processing mode explicitly.
3. With a redaction model configured, processing follows “extraction or visual OCR → local pre-scan → LLM localization → local verification and replacement → LLM residual check → local residual scan.” Review names, organizations, addresses, phones, email addresses, identity numbers, case numbers, and account identifiers; same-group entities receive stable aliases.
4. Add dictionary entries, edit aliases, or mark false positives. Cloud assistance must be bound to the exact material version, Provider, model, and purpose. Trusted domestic official presets allow selected originals by default; custom endpoints require confirmation, and untrusted providers may receive only valid redacted references.
5. Only a complete, conflict-free, alias-consistent task with a clean residual scan produces an immutable usable result. Failed, pending-review, or revoked results cannot be read through MCP.
6. Redacted material is stored as UTF-8 plain TXT; batch operations may export a ZIP. Original formats and layout are not redaction output formats, and exports are reread and validated.

## Legal research, AI research, document writing, and chat

Legal research defaults to grouped laws and also offers a flat article view. It counts the complete match set before paging instead of truncating at 20 results. Filters cover type, effectiveness level, jurisdiction, status, and case date; sorting covers relevance, effectiveness, publication date, and effective date. History and related regulations are on by default, and historical-version articles can be read page by page. Statute research uses the local read-only runtime database.

Case mode searches the local sidecar by keyword, guiding/reference/typical type, and guiding number, and opens case details and official sources. The corpus covers only the Supreme People's Court cases declared by its source manifest, not every national judgment. Typical collections are stored as articles and are not counted as single cases.

AI legal research can use a user description, an attachment, or a graphical selection of an existing redacted material. The model structures the facts, refines keywords, and searches local statutes, versions, and Supreme People's Court cases over multiple rounds; it does not perform internet legal research. Database validation checks citation identifiers and verbatim quotations, and the run is saved to history.

**Document writing** uses the case description, document type, and user requirements to compose the document and can call the same local legal tools. Generation is saved to history automatically. The preview renders the document body instead of showing Markdown source. TXT is plain text, DOCX is a structured document, and the default export is a rendered Chinese A4 PDF.

The first complete AI conversation response receives an automatic title, which can then be edited manually. Users can select materials graphically and upload attachments; the conversation AI can call local statute and case tools. Accepted background tasks are independent of the browser lifecycle, so closing the page does not cancel them; users can cancel explicitly.

## MCP

The public profile uses the standalone program:

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

It exposes seven fixed read-only public-law tools: `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, `legal_get_relations`, `legal_search_cases`, and `legal_get_case`. The two case tools read the Supreme People's Court sidecar in the same directory. The `privacy_workspace` profile has ten tools in total, adding `privacy_workspace.submit`, `privacy_workspace.status`, and `privacy_workspace.read_result`; create a client token in **Settings** and call the running loopback server. The original five legal tool I/O contracts remain unchanged. Public MCP never opens original text, mappings, original filenames, or disk paths.

## Limits

- PDF, image, and scanned-material OCR requires a configured cloud visual model; provider, model, or request failures do not produce fabricated OCR or publish a result.
- The local case corpus scope, sources, and statuses are defined by `judicial_cases_manifest.json` and `CASE_DATA_SOURCES.md`; it is not a complete national judgment corpus.
- AI research, document writing, and chat use only explicitly selected material that satisfies the applicable send policy. Test materials are independently generated fictional content; test metrics are not real-case accuracy guarantees.
- Portable ZIPs and source builds are unsigned technical artifacts. The final portable package still requires packaging and manifest validation before delivery and must not be described as a published GitHub installer, formal updater, or signed asset.
