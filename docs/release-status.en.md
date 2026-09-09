# Current release status

## Version

The source version remains `0.4.0` while the project moves from the Tauri desktop workspace to a Rust server, plain HTML WebUI, and MCP. This version is for local technical validation and reproducible portable packaging; it is not a signed Windows stable release.

The portable builder `scripts/package_portable.py` produces:

```text
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256
Lawyer-Assistance_0.4.0_windows-x86_64-portable.manifest.json
```

The ZIP contains the two release executables, `data/runtime/legal_core.sqlite`, `DATA_SOURCES.md`, `LICENSE.txt`, `THIRD_PARTY_NOTICES.txt`, README files, `Lawyer-Assistance.vbs`, `Stop-Lawyer-Assistance.vbs`, `MANIFEST.sha256`, and `portable.manifest.json`. Before packaging, the builder compares database size, SHA-256, and the SQLite `source_manifest_sha256` with `data/generated/legal_core_distribution_manifest.json`.

## Available capabilities

| Capability | Status |
| --- | --- |
| Local server and loopback WebUI | Implemented; defaults to `127.0.0.1:8877` |
| TXT/DOCX redaction | Local extraction, detection, replacement, review, residual scan, and result versions |
| TXT/Markdown/DOCX/ZIP export | Implemented with reread validation |
| Local legal research | Uses the read-only runtime database |
| `public_law_only` | Exactly five public-law tools |
| `privacy_workspace` | Three redaction tools with an independent client token |
| Provider assistance/simple chat | Requires explicit binding; sends only allowed extracted/redacted text |
| PDF/image/scanned-document OCR | Not in the first release; extension boundary only |
| Tauri, installers, signing, updaters, GitHub publication | Removed from the current release path |

## Data and compatibility

The new data directory is `%LOCALAPPDATA%\LawyerAssistanceWeb`. The old Tauri directory, cases, mappings, and authorization are left untouched and are never migrated or opened automatically. A missing legal database affects legal research only; redaction tasks do not depend on it.

The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` MCP profiles return an explicit disabled error and are not mapped to `privacy_workspace`.

## Limits

- Portable packages and local release builds are unsigned technical artifacts.
- There is no installer, Authenticode/RFC3161 chain, `.sig`, `latest.json`, or automatic updater.
- No production OCR runtime, GPU qualification, or cloud-OCR fallback is shipped.
- Real case material must not enter the repository, tests, logs, screenshots, or an unauthorized Provider/MCP context.
