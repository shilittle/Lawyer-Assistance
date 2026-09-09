# Lawyer Assistance documentation

Version `0.4.0` is the local Web refactor: a Rust server owns business and HTTP/MCP boundaries, while `apps/web` supplies plain HTML/CSS/JavaScript with no build step. The first release focuses on TXT/DOCX redaction and local legal research.

## User documentation

- [Getting started](getting-started.en.md)
- [Security and privacy](security-and-privacy.en.md)
- [Legal data and runtime database](data/legal-corpus.md)
- [Web API](web/README.md), when generated
- [MCP documentation](mcp/README.md)
- [Repository layout](development/repository-layout.md)
- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)

## Supported boundary

The first Web release supports TXT/DOCX, public legal research, simple templates, Provider chat, and the declared MCP tools. PDF/image/scanned-document OCR, original-layout preservation, complex case workspaces, legal graphs, and autonomous workflows are out of scope. There is no Tauri installer, signing/updater chain, or OCR runtime.

## Data and licensing

The read-only runtime legal database and notices live under `data/runtime/`. Source and audit tools remain under `data/sources/` and `data/build/`; they must not write user data while the application is running.
