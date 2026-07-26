# Getting Started

## 1. Before you begin

`0.4.0-beta.2` targets Windows x86_64 and is currently an unsigned technical prerelease:

- The installer has no verified Windows publisher identity and may trigger SmartScreen or security-software warnings.
- There is no active automatic-update release chain. Upgrade only with a complete new package supplied and verified by the project.
- Production scanned-document OCR is not qualified. Do not use it for scanned or visual PDFs unless every current qualification gate is shown as passed in the App.
- The technical prerelease uses the `runtime-slim-v1` legal database and does not include the full archival database.

When downloading or receiving a package, verify its version, filename, SHA-256, and bundled manifest. Do not treat a CI fixture, debug executable, or historical OCR component as a product asset.

## 2. First launch

1. Start Lawyer Assistance and confirm that the displayed version is `0.4.0-beta.2`.
2. Open the health or version information and confirm that the runtime legal database is loaded.
3. Read the privacy notice and confirm that the application's retention and outbound-data boundaries fit the intended work.
4. To use a model Provider, create your own Provider configuration and save its API key. Windows Credential Manager stores the key; the frontend displays masked status only.
5. Before using case, Provider, MCP, or OCR capabilities, check the corresponding qualification and authorization state separately. Passing one capability never enables another automatically.

## 3. Public-law research

Public-law research reads the runtime legal database offline and can:

- search laws and articles;
- show version and effectiveness information;
- show legal relations and source citations; and
- prepare sourced research material for public-law questions.

A lawyer must verify results against current official texts and the relevant facts. The runtime projection serves application queries and does not replace the full archival audit database.

## 4. Case workspaces

Case workspaces organize cases, parties, facts, evidence, issues, legal authorities, and work products locally. Use this sequence:

1. Create a case and enter only the necessary structured information.
2. Import PDF, DOCX, UTF-8 TXT, or Markdown.
3. Review local extraction, sensitive-data findings, and alias mappings.
4. Manually review the redaction scope and approve only the immutable generation needed for later work.
5. Use approved material through controlled in-App workflows.
6. Save final output as a protected work product and read back the stored version in the App.

Local approval does not authorize pasting text into a chat, attaching it to a task, opening it in a browser, sending it to another MCP, or using it with an arbitrary Provider. Authorization must match the exact generation, destination, purpose, and current state.

## 5. BYOK Providers

Lawyer Assistance connects to compatible Providers with BYOK (bring your own key):

- the user supplies the Provider account and API key;
- API keys are not written to ordinary configuration, logs, or database content;
- ordinary public-law Q&A sends only the minimum context prepared for that request;
- case content uses the separate approved Provider workflow; and
- the Provider, endpoint, model, purpose, approved generation, and expiry must be checked before dispatch.

A Provider is an external service. Review its retention, access-control, regional, and billing policies before use. Local approval is not general permission for every Provider.

## 6. MCP and host integrations

Lawyer Assistance defines four distinct MCP profiles:

| Profile | Tools | Purpose |
|---|---:|---|
| `public_law_only` | 5 | Default read-only public-law research with no case data |
| `redacted_case` | 6 | Compatibility experiment; the current App does not issue its positive-purpose ticket |
| `diagram_authoring` | 11 | Synthetic or public data only; produces a local plaintext diagram bundle |
| `approved_case_workspace` | 21 | Approved case workspace constrained by App qualification, session, grants, and per-call tickets |

The default WorkBuddy, Codex, and OpenCode examples use `public_law_only`. Approved-case configurations are separate, disabled-by-default Windows stdio configurations. For an approved workspace:

1. Create a current standalone session in the App.
2. Start a new clean host task containing opaque IDs only.
3. Do not paste, attach, or host-read case text.
4. Trust substantive material only from the direct current-task `case_read_approved_material` response.
5. Save output only through controlled work-product or approved-diagram tools, then read back the exact stored version.

## 7. Legal diagrams

- `diagram_authoring` accepts synthetic or public legal data only. Its HTML is a local plaintext artifact and must never contain real case material.
- Real approved-case diagrams must use `approved_case_workspace`.
- Approved `diagram.render` and `diagram.update` store encrypted protected HTML work products.
- `diagram.export` returns verified descriptor metadata only, never HTML, a file path, or a URI.

## 8. OCR

Reliable native text layers can be handled by local parsers. A scanned or visual PDF may enter local MinerU only when the App shows that the current worker, models, component integrity, Windows Firewall isolation, synthetic canary, and environment remeasurement have all passed.

The current technical prerelease is not production-OCR-qualified. Historical components, GPU diagnostics, user consent, or remote OCR cannot replace qualification. Failure must block processing rather than silently upload or fall back to a remote service.

## 9. Backup and restore

The App provides a local authenticated and encrypted `.lavbackup` that covers the user database, privacy state, encrypted Vault, approved workspace, and encrypted work products. A separate `.lavprivacy` format supports privacy maintenance.

- Finish active writes and use the App's export action before backup.
- Store backups in a controlled location; do not upload them to an unapproved cloud drive, chat, or ticket.
- After restore, verify cases, Vault data, approved generations, work products, and authorization state.
- Backup and logical deletion do not imply forensic erasure of SSD cells, external copies, host caches, or cloud history.

## 10. When a workflow is blocked

`PROFILE_NOT_QUALIFIED`, expiry, revocation, replay, integrity, or residual-scan errors mean that the workflow must stop. Do not downgrade to paste, attachment, file paths, a browser, remote OCR, another MCP, or another Provider.

See [Security and Privacy](security-and-privacy.en.md) and [Current Release Status](release-status.en.md) for more information.
