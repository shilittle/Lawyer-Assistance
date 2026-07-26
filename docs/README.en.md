# Lawyer Assistance Documentation

Lawyer Assistance is a local legal-assistance application for Windows x86_64. It provides offline public-law research, case-material organization, controlled AI-assisted workflows, legal diagrams, work-product management, and encrypted backup. Local processing is the default data boundary; every Provider or host integration requires explicit configuration and its corresponding authorization chain.

The current version is `0.4.0-beta.2`, an unsigned technical prerelease. It is not a formal release that has completed Authenticode signing, automatic-update, production OCR, and full archival-data delivery acceptance. Read the [current release status](release-status.en.md) before use.

## User documentation

- [Getting started](getting-started.en.md): installation, first launch, public-law research, case workspaces, BYOK Providers, MCP, and backup.
- [Security and privacy](security-and-privacy.en.md): local data, outbound authorization, OCR, host integrations, and backup boundaries.
- [Current release status](release-status.en.md): implemented `0.4.0-beta.2` capabilities, disabled-by-default features, and formal-release gates.
- [中文文档](README.md)

## Functional reference

- [MCP overview](mcp/README.md)
- [MCP installation and operation](mcp/installation.md)
- [MCP tools and profile contract](mcp/tools.md)
- [Approved case workspace](mcp/approved-case-workspace.md)
- [Diagram architecture](diagrams/architecture.md)
- [Diagram security model](diagrams/security-model.md)
- [Privacy workspace and MCP boundary](privacy-vnext/WORKSPACE_AND_MCP.md)
- [Privacy operations](privacy-vnext/OPERATIONS.md)
- [Legal corpus and runtime database](data/legal-corpus.md)
- [Repository layout](development/repository-layout.md)
- [Windows release signing](development/release-signing.md)

## Host integrations

The repository includes functional integration examples for WorkBuddy, Codex, and OpenCode. Their default integrations are fixed to the case-free `public_law_only` profile. Approved case workspaces use separate, disabled-by-default configurations that require current authorization from the App.

- [WorkBuddy](../integrations/workbuddy/README.md)
- [Codex](../integrations/codex/README.md)
- [OpenCode](../integrations/opencode/README.md)

## Legal and data notice

Application content supports research and lawyer review; it does not replace verification of current official texts, case facts, or professional judgment. Application packages use the verified `runtime-slim-v1` legal database. The full archival database is not included in the technical prerelease package. Data provenance and version identity are governed by the repository source manifest, distribution manifest, and in-App version information.

- [Data-source manifest](../data/sources/source_manifest.md)
- [Release notes](../RELEASE_NOTES.md)
- [License](../LICENSE)
