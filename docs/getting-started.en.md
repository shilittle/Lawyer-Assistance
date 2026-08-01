# Getting Started

## 1. Before you begin

`0.4.0-beta.2` targets Windows x86_64 and is currently an unsigned technical prerelease:

- The installer has no verified Windows publisher identity and may trigger SmartScreen or security-software warnings.
- There is no active automatic-update release chain. Upgrade only with a complete new package supplied and verified by the project.
- Production scanned-document OCR is not qualified. Do not use it for scanned or visual PDFs unless every current qualification gate is shown as passed in the App.
- The technical prerelease uses the `runtime-slim-v1` legal database and does not include the full archival database.

When downloading or receiving a package, verify its version, filename, SHA-256, and bundled manifest. Do not treat a CI fixture, debug executable, or historical OCR component as a product asset.

The source repository is public, but public visibility or downloadability is not a substitute for Authenticode signing, updater metadata, OCR qualification, or clean-machine release acceptance.

## 2. Product map

The top-level navigation has four product areas:

| Area | Owner |
|---|---|
| **Assistant** | Ordinary, case-free Provider conversations and explicit ordinary attachments |
| **Cases** | Overview, Materials & Redaction, Case Work, and Outputs |
| **Legal Library** | Offline laws, articles, versions, effectiveness, relations, and source review |
| **Settings** | Provider services and credentials; Local processing environment and OCR components; MCP and automation; Version, backup, and diagnostics |

Case material, redacted text, and human review stay under **Cases → Materials & Redaction**. They are not configuration content and do not appear in Settings.

## 3. First launch

1. Start Lawyer Assistance and confirm that the displayed version is `0.4.0-beta.2`.
2. Open **Settings → Version, backup, and diagnostics** and confirm that the runtime legal database is loaded.
3. Read the privacy notice and confirm that the application's retention and outbound-data boundaries fit the intended work.
4. Under **Settings → Provider services and credentials**, create your own Provider configuration and save its API key. Windows Credential Manager stores the key; the frontend displays masked status only.
5. Before using case, Provider, MCP, or OCR capabilities, check the corresponding qualification and authorization state separately. Passing one capability never enables another automatically.

## 4. Ordinary Assistant chat and attachments

Ordinary chat is available after a Provider is configured. It does not require a case, a case-file upload, redaction approval, a Provider task receipt, reviewer metadata, or an automation ticket.

1. Open **Assistant** and create an independent conversation.
2. Choose the Provider and enter a message.
3. Keep the disclosure beside the composer in view: the message will be sent through the selected Provider API, and unredacted case material must not be entered or uploaded.
4. Send the message. The App uses the `interactive_chat` boundary and does not read the case workspace, Vault, case materials, redaction generations, or MCP services.

To include an ordinary attachment:

1. Import the file into the current ordinary conversation.
2. Explicitly select it for this send. The disclosure names each selected attachment and shows its detected type and size.
3. Confirm that locally extracted text will be sent to the selected Provider. The local path is not sent.
4. Deselect or cancel the attachment if it should not be included.

Only explicitly selected attachments are included in the request. Unselected and cross-conversation attachments are not enumerated or sent, and an ordinary attachment is not automatically registered as a case material. If a file contains case information, stop and use **Cases → Materials & Redaction** instead.

## 5. Public-law research

Public-law research reads the runtime legal database offline and can:

- search laws and articles;
- show version and effectiveness information;
- show legal relations and source citations; and
- prepare sourced research material for public-law questions.

A lawyer must verify results against current official texts and the relevant facts. The runtime projection serves application queries and does not replace the full archival audit database.

## 6. Case workspaces

Case workspaces organize cases, parties, facts, evidence, issues, legal authorities, and work products locally. Their fixed sections are **Overview**, **Materials & Redaction**, **Case Work**, and **Outputs**. Use this sequence:

1. Create a case and enter only the necessary structured information.
2. Open **Materials & Redaction** and import PDF, DOCX, UTF-8 TXT, or Markdown.
3. Review local extraction, sensitive-data findings, alias mappings, and the redaction draft. OCR may run only if the current local qualification is valid.
4. Manually review the redaction scope and approve only the immutable generation needed for later work. This page also owns approved-generation history and revocation.
5. Open **Case Work → Case Assistant**, create or select a dedicated `case_work` conversation, and explicitly select approved/current generations from the current case for this request.
6. Choose the Provider, output type, and **Select and send**. The backend revalidates the project binding, every selected generation, confirmed case context, Provider, model, purpose, expiry, and revocation immediately before transport.
7. Review the scanned pending response. Applying case analysis or binding a document or diagram to Outputs is a separate explicit confirmation.
8. Save final output as a protected work product and read back the stored version in the App.

Local approval does not authorize pasting text into a chat, attaching it to a task, opening it in a browser, sending it to another MCP, or using it with an arbitrary Provider. Authorization must match the exact generation, destination, purpose, and current state.

The Case Assistant never reads raw case files, pending redaction drafts, original Vault objects, file paths, ordinary-chat attachments, or generations from another case. If a selected generation is revoked or becomes stale, the retry must fail before Provider transport, the invalid selection is cleared, and the user must select current material again.

## 7. BYOK Providers

Lawyer Assistance connects to compatible Providers with BYOK (bring your own key):

- the user supplies the Provider account and API key;
- API keys are not written to ordinary configuration, logs, or database content;
- ordinary Assistant chat sends only the entered message, eligible ordinary-chat history, and attachment bodies explicitly selected for that send;
- case content uses the separate approved-only Case Assistant workflow; and
- the Provider, endpoint, model, purpose, approved generation, and expiry must be checked before dispatch.

A Provider is an external service. Review its retention, access-control, regional, and billing policies before use. Local approval is not general permission for every Provider.

## 8. Three non-interchangeable execution modes

| Mode | Used by | Boundary |
|---|---|---|
| `interactive_chat` | Ordinary Assistant | User-entered text, eligible ordinary-chat history, and explicitly selected ordinary attachments. It cannot access case services and cannot target an external MCP host. |
| `interactive_case_work` | Case Assistant in Case Work | Explicit approved/current generations from the current case plus a minimum of confirmed case data and current local legal sources. Raw, pending, revoked, foreign-case, or unselected sources are forbidden. |
| `approved_automation` | MCP, WorkBuddy, Codex, OpenCode, and other hosts | Opaque IDs, approved source references, clean-task controls, current qualification, grants, exact tickets, destination and purpose binding, and protected work-product sinks. |

These modes do not authorize one another. Do not fall back from a blocked case or automation request to ordinary chat, pasted content, a file attachment, another MCP, or another Provider.

## 9. Settings owners

- **Provider services and credentials:** Provider profiles, endpoint and model configuration, connection tests, and Credential Manager-backed API-key status.
- **Local processing environment and OCR components:** privacy mode, OCR configuration and discovery, component installation and trust, firewall isolation, status, qualification, and revocation. This page contains no case review body.
- **MCP and automation:** local MCP service configuration, controlled Provider automation approvals and history, and approved-workspace MCP qualification, publication, host sessions, and revocation.
- **Version, backup, and diagnostics:** application version and update checks, content-free diagnostic export, retention and mapping-key maintenance, cleanup, and five-component backup and restore.

## 10. MCP and host integrations

Lawyer Assistance defines four distinct MCP profiles:

| Profile | Tools | Purpose |
|---|---:|---|
| `public_law_only` | 5 | Default read-only public-law research with no case data |
| `redacted_case` | 6 | Compatibility experiment; the current App does not issue its positive-purpose ticket |
| `diagram_authoring` | 11 | Synthetic or public data only; produces a local plaintext diagram bundle |
| `approved_case_workspace` | 21 | Approved case workspace constrained by App qualification, session, grants, and per-call tickets |

The default WorkBuddy, Codex, and OpenCode examples use `public_law_only`. Approved-case configurations are separate, disabled-by-default Windows stdio configurations and belong to `approved_automation`, not ordinary chat or the in-App Case Assistant. For an approved workspace:

1. Create a current standalone session in the App.
2. Start a new clean host task containing opaque IDs only.
3. Do not paste, attach, or host-read case text.
4. Trust substantive material only from the direct current-task `case_read_approved_material` response.
5. Save output only through controlled work-product or approved-diagram tools, then read back the exact stored version.

## 11. Legal diagrams

- `diagram_authoring` accepts synthetic or public legal data only. Its HTML is a local plaintext artifact and must never contain real case material.
- Real approved-case diagrams must use `approved_case_workspace`.
- Approved `diagram.render` and `diagram.update` store encrypted protected HTML work products.
- `diagram.export` returns verified descriptor metadata only, never HTML, a file path, or a URI.

## 12. OCR

Reliable native text layers can be handled by local parsers. A scanned or visual PDF may enter local MinerU only when the App shows that the current worker, models, component integrity, Windows Firewall isolation, synthetic canary, and environment remeasurement have all passed.

Manage this boundary under **Settings → Local processing environment and OCR components**. The current technical prerelease is not production-OCR-qualified. Historical components, GPU diagnostics, user consent, or remote OCR cannot replace qualification. Failure must block processing rather than silently upload or fall back to a remote service.

## 13. Backup and restore

Under **Settings → Version, backup, and diagnostics**, the App provides a local authenticated and encrypted `.lavbackup` that covers the user database, privacy state, encrypted Vault, approved workspace, and encrypted work products. A separate `.lavprivacy` format supports privacy maintenance.

- Finish active writes and use the App's export action before backup.
- Store backups in a controlled location; do not upload them to an unapproved cloud drive, chat, or ticket.
- After restore, verify cases, Vault data, approved generations, work products, and authorization state.
- Backup and logical deletion do not imply forensic erasure of SSD cells, external copies, host caches, or cloud history.

## 14. When a workflow is blocked

`PROFILE_NOT_QUALIFIED`, expiry, revocation, replay, integrity, or residual-scan errors mean that the affected case or automation workflow must stop. Do not downgrade it to ordinary chat, an ordinary attachment, pasted content, file paths, a browser, remote OCR, another MCP, or another Provider. Ordinary chat's own non-case content does not require MCP qualification, but it must never be used to bypass the case-material boundary.

See [Security and Privacy](security-and-privacy.en.md) and [Current Release Status](release-status.en.md) for more information.
