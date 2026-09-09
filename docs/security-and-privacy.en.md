# Security and privacy

## Data layers

- **Public legal data:** `data/runtime/legal_core.sqlite` is opened read-only. The public MCP and legal-research WebUI access only this database.
- **User workspace:** defaults to `%LOCALAPPDATA%\LawyerAssistanceWeb` and stores groups, tasks, extracted text, redaction versions, dictionaries, Provider state, bookmarks, and sessions. The old Tauri data directory is not migrated.
- **Original/private material:** originals, mappings, and unpublished text remain protected by the backend workspace. Logs, errors, and MCP responses do not return them.
- **Browser sessions:** the bootstrap token is used only for the first local login. Subsequent requests use an HttpOnly session cookie and CSRF token. Responses are `no-store`, and Host/Origin mismatches are rejected.

## Redaction egress boundary

TXT/DOCX extraction, detection, replacement, residual scanning, and export are local by default. Cloud assistance must be explicitly bound to the material version, Provider, model, and purpose. The request contains extracted text; the model returns candidate spans, and the backend replaces only candidates that it verifies in the source. Missing consent, revocation, version drift, path escape, incomplete extraction, or a failed residual scan blocks transport or publication.

Provider chat never reads original material automatically. It may use the current user message and explicitly selected valid redacted results. Do not paste original case text into ordinary chat, a browser, a search engine, or another MCP.

## MCP boundary

- `public_law_only` has exactly five read-only public-law tools and never opens the private workspace database.
- `privacy_workspace` uses the same backend business service but a separate client bearer token; the client is bound to a selected material group and inbox.
- `privacy_workspace.submit` accepts only relative paths below the inbox and rechecks symlinks, path escape, source changes, and idempotency.
- `privacy_workspace.status` returns task state and anonymous security reason codes. `read_result` pages only through a currently valid redacted result.
- Pending-review, failed, cancelled, revoked, and expired results are unreadable. No tool returns originals, mappings, original filenames, disk paths, human approval, or cloud authorization.
- The old `approved_case_workspace`, `redacted_case`, and `diagram_authoring` profiles are explicitly disabled.

## Runtime and reports

The portable package writes only to `%LOCALAPPDATA%\LawyerAssistanceWeb`; its launchers start or stop the server through hidden `wscript.exe`. The stop launcher calls only the session/CSRF-authenticated loopback endpoint and never kills an arbitrary process. It contains no user data, credentials, signing keys, or updater. Verify the embedded `MANIFEST.sha256`, the `.zip.sha256`, and the legal distribution manifest.

Use synthetic data when reporting security issues. Do not upload real material, mappings, credentials, identifying paths, or raw logs; see the repository [security policy](../SECURITY.md).
