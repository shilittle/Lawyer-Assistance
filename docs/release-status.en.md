# Current release status

This page describes v1.2.1. The [release page](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v1.2.1-r1) provides the complete Windows portable package, source and SHA-256 checksums; asset names include the date and commit. See the [retest record](web/retest-1.2.1.md) for changes and validation limits, and the release attachment `release-validation.json` for build identity and packaged verification.

## Version and delivery

The source version is `1.2.1`. It builds on the V1.0.0 Web workspace and uses a Rust server, plain HTML WebUI, and MCP. The local builder `scripts/package_portable.py` produces:

```text
Lawyer-Assistance_1.2.1_windows-x86_64-portable.zip
Lawyer-Assistance_1.2.1_windows-x86_64-portable.zip.sha256
Lawyer-Assistance_1.2.1_windows-x86_64-portable.manifest.json
```

The ZIP contains two release executables, `data/runtime/legal_core.sqlite`, the sibling `judicial_cases.sqlite`, a derived retrieval index, `CASE_DATA_SOURCES.md`, `judicial_cases_manifest.json`, Pdfium, Typst, Chinese fonts, license and third-party notices, current documentation, MCP examples, `Lawyer-Assistance.vbs`, and `Stop-Lawyer-Assistance.vbs`. The packager checks both databases and their manifests for size, SHA-256, schema, counts, and official-source identity.

Portable packages and source builds are unsigned technical artifacts. They contain no installer, signature file, `.sig`, `latest.json`, or automatic updater. The ZIP, its `.zip.sha256`, and JSON manifests are provided together as release assets.

## Available capabilities

| Capability | Status |
| --- | --- |
| Local server and loopback WebUI | Implemented; defaults to `127.0.0.1:8877` |
| Model-led material redaction | Local pre-scan, LLM localization, local verification and replacement, LLM residual check, and local residual scan |
| PDF, image, and embedded DOCX images | Text pages are extracted locally in an isolated worker; scanned and mixed pages use configured visual OCR as needed, with page/paragraph selection |
| Redaction output | Stored as UTF-8 plain TXT; batch operations may export a ZIP |
| Local legal research | Complete-match counting, grouped-law/flat-article views, filters, relevance/date sorting, and paging |
| Historical versions and related regulations | Defaults to currently effective versions when no date is given; historical scope is explicit and articles are paginated |
| AI legal research | Searches local statutes, versions, and Supreme People's Court cases from descriptions, attachments, or selected materials, with history saved |
| Document writing | Model-written documents with local legal tools, rendered preview, version history, plain TXT/structured DOCX/default PDF export |
| AI conversation | Automatic title, manual rename, graphical material selection, attachments, and local legal tools; background tasks continue independently |
| Model settings | Common provider presets, online model-list discovery, multi-select enablement, and separate chat/redaction/writing/OCR defaults |
| `public_law_only` | Exactly seven public-law tools, including two case tools |
| `privacy_workspace` | Seven public tools plus three redaction tools, ten total, with an independent client token |

## Case data

`judicial_cases.sqlite` is an independent read-only Supreme People's Court case sidecar. It currently contains 759 primary cases/articles: 279 guiding cases, 61 reference cases, and 419 typical-case collections; the source inventory retains 834 TXT source entries. A typical collection may contain multiple cases and is retrieved as one `case_type=typical` article. It is not folded into the reference corpus, and 834 source entries must not be reported as 834 cases. Guiding Case 45 retains its official Luoyang Intermediate People's Court repost URL, source role, and authority. See `data/runtime/CASE_DATA_SOURCES.md` and `data/generated/judicial_cases_manifest.json` for sources, hashes, statuses, and versions.

## Upgrade and compatibility

Stop the old service, build or obtain the v1.2.1 portable ZIP, and double-click `Lawyer-Assistance.vbs`. When an existing Web workspace is opened for the first time, the backend creates and verifies a backup before upgrading transactionally; groups, originals, dictionaries, bookmarks, results, and conversations are retained. The old Tauri workspace is not migrated.

To stop the service, double-click `Stop-Lawyer-Assistance.vbs` or run `lawyer-assistance.exe stop`. The request verifies the current user's encrypted connection descriptor and uses an authenticated loopback session plus CSRF check; it does not terminate arbitrary processes. Closing the browser does not cancel accepted background AI tasks; unknown cloud requests require an explicit continuation.

The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` MCP profiles return a disabled error and are not mapped to `privacy_workspace`. The original five legal tool names and I/O contracts remain unchanged.

## Operating boundaries

- Cloud visual OCR, LLM redaction, AI research, document writing, and chat require a configured Provider, model, and send policy. Failed, revoked, or pending-review states are not published automatically.
- Trusted domestic official presets allow selected originals by default; custom endpoints require confirmation, and untrusted providers may receive only valid redacted references. Originals, mappings, private history, and checkpoints remain protected by the local backend.
- AI legal research uses only local statutes, versions, and Supreme People's Court cases; it does not perform internet legal research. The case sidecar is not a complete national judgment corpus.
- Validation uses independently generated fictional material; test metrics are not real-case accuracy guarantees. The final portable package is governed by its packaged manifests and validation results.
