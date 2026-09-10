# Security and privacy

This page describes the v1.2.0 boundaries. The [upgrade guide](web/ai-upgrade.md) explains the workflow changes, and the [AI incremental validation report](web/ai-validation.md) records the checks that were actually run. The local portable package is delivered with SHA-256 and JSON manifests; this page does not claim a GitHub publication.

## Data layers

- **Public legal data:** `data/runtime/legal_core.sqlite` and its sibling `judicial_cases.sqlite` are opened read-only. Statute and case research use their respective databases. The case sidecar has 759 primary cases/articles (279 guiding, 61 reference, and 419 typical-case collections) and 834 retained TXT source entries; its scope and provenance are defined by `CASE_DATA_SOURCES.md` and `judicial_cases_manifest.json`.
- **User workspace:** defaults to `%LOCALAPPDATA%\LawyerAssistanceWeb` and stores groups, tasks, extracted text, redaction versions, dictionaries, Provider state, bookmarks, and sessions. The old Tauri data directory is not migrated.
- **Original/private material:** originals, mappings, and unpublished text remain protected by the backend workspace. Logs, errors, and MCP responses do not return them.
- **Browser sessions:** the bootstrap token is used only for the first local login. Subsequent requests use an HttpOnly session cookie and CSRF token. Responses are `no-store`, and Host/Origin mismatches are rejected.

## Redaction and AI egress

TXT/DOCX extraction and local pre-scanning remain local. PDF, image, and embedded-DOCX-image inputs use the configured cloud visual OCR model. With a redaction model configured, the backend sends only the requested extracted/OCR text for LLM span localization or residual checking; local verification, replacement, stable aliases, and residual scanning determine the saved result. The model cannot directly rewrite the material into a redacted result.

Cloud assistance must be explicitly bound to the exact material version, Provider, model, and purpose. Trusted domestic official presets allow selected originals by default; custom endpoints require confirmation, and untrusted providers may receive only valid redacted material references. Missing consent, revocation, version drift, path escape, incomplete extraction, invalid model output, or a failed residual scan blocks transport or publication. Redacted material is stored as UTF-8 plain TXT.

AI legal research, document writing, and conversation use only user-selected materials or attachments that pass the current send policy. The model may call local read-only statute, version, relation, and Supreme People's Court case search; it cannot write to either public database, and AI legal research does not perform internet legal research. Citation identifiers and verbatim quotations are checked against the local databases.

Provider chat never reads original material automatically. Materials in a request are rechecked for provider, version, result validity, and send policy; revocation or source changes block a later send. A request already sent to a provider cannot be recalled. Instructions inside a document are content only and do not gain tool, configuration, file-write, or network permissions.

## MCP boundary

- `public_law_only` has exactly seven read-only public-law tools. `legal_search_cases` and `legal_get_case` read only the verified Supreme People's Court case sidecar and never open the private workspace database.
- `privacy_workspace` uses the same backend business service with a separate client bearer token. The client is bound to a selected material group and inbox.
- `privacy_workspace.submit` accepts only relative paths below the inbox and rechecks symlinks, path escape, source changes, and idempotency.
- `privacy_workspace.status` returns task state and anonymous security reason codes. `read_result` pages only through a currently valid redacted result.
- Pending-review, failed, cancelled, revoked, and expired results are unreadable. No tool returns originals, mappings, original filenames, disk paths, human approval, or cloud authorization.
- The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are explicitly disabled.

## Runtime and reports

The local portable package writes only to `%LOCALAPPDATA%\LawyerAssistanceWeb`; its launchers start or stop the server through hidden `wscript.exe`. The stop launcher calls only the session/CSRF-authenticated loopback endpoint and never kills an arbitrary process. The package contains no user data, credentials, signing keys, or updater. Verify the embedded `MANIFEST.sha256`, the `.zip.sha256`, the legal distribution manifest, and the judicial case distribution manifest before use.

Cloud OCR and model features require configured providers and models. A provider failure does not produce a result by assumption. The case sidecar is an official-source subset, not a complete national judgment corpus. Validation uses independently generated fictional material; its metrics are not real-case accuracy guarantees. Final portable ZIP packaging and manifest validation remain delivery steps.

Use synthetic data when reporting security issues. Do not upload real material, mappings, credentials, identifying paths, or raw logs; see the repository [security policy](../SECURITY.md).
