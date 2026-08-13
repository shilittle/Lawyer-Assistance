# Security and Privacy

## Security model overview

Lawyer Assistance processes the legal database, case material, redaction state, work products, and backups locally by default. It treats “content is local,” “content was manually approved,” and “content may be sent to a destination” as three different facts. User consent, a prompt, host permissions, or a filename cannot replace backend qualification, signed state, authorization scope, and replay protection.

This model reduces accidental disclosure and unauthorized access. It does not replace lawyer review, organizational controls, endpoint security, Provider contracts, or backup management.

## Product ownership boundaries

The four top-level areas have distinct responsibilities:

- **Assistant** owns ordinary, case-free Provider conversations and explicitly selected ordinary attachments. Its persistent disclosure states that selected content is sent to the Provider server and warns against entering or uploading unredacted case material.
- **Cases** owns Overview, **Materials & Redaction**, Case Work, and Outputs. Case material, extracted text, redaction drafts, human review, approved generations, revocation, and version history remain under Materials & Redaction.
- **Legal Library** owns offline public-law search, versions, effectiveness, relations, and source review.
- **Settings** is limited to four owners: **Provider services and credentials**; **Local processing environment and OCR components**; **MCP and automation**; and **Version, backup, and diagnostics**. It does not display case-file bodies or the human redaction workbench.

## Data classes

- **Public legal data:** may enter the default public-law research workflow.
- **Interactive user-provided content:** text entered by the user in ordinary chat, plus non-case attachment bodies that belong to the current ordinary conversation, were extracted locally, and were explicitly selected for this send. It may be sent to the selected Provider, but it is not public data and cannot access case-material services.
- **Raw case data:** client, case, material, attachment, OCR text, and identifying derived facts; local-only by default.
- **Pending redaction:** not yet precisely reviewed and therefore handled as raw case data.
- **Approved generation:** immutable content, scope, and provenance signed by the App after manual review; it still has no general outbound permission.
- **Protected work product:** a work product or approved-case diagram created and stored through a controlled workflow.

## Local storage

The application uses a read-only runtime legal database and locally writable user data. Rust backend services manage cases, approvals, Vault data, mappings, and work products; the frontend cannot perform arbitrary database reads. API keys use Windows Credential Manager. Ordinary configuration, logs, and frontend state contain only necessary non-secret information or masked status.

Protected work products use authenticated encryption, versioned manifests, and authenticated completion records. Legacy plaintext content, an unexpected file set, hash mismatch, revoked provenance, or residual files fail closed.

Application `ProjectId` and authoritative Privacy/Vault `PrivacyCaseId` values remain different identity domains. The trusted backend maintains an audited, persistent, immutable one-to-one binding; it does not derive the relationship with string replacement, hashing, truncation, or a predictable counter. The frontend never generates, guesses, caches as authoritative, or receives the authoritative `PrivacyCaseId`. Ambiguous historical identity recovery fails closed, and project deletion preserves the binding and audit history so that a retired `ProjectId` cannot be rebound to another Privacy case. See [ADR-0001](adr/0001-project-privacy-case-binding.md).

## Execution modes do not mix

| Mode | Authorized use | Forbidden crossover |
|---|---|---|
| `interactive_chat` | Ordinary Assistant messages, eligible history from that ordinary conversation, and attachment bodies explicitly selected for the current send | No case workspace, CaseMaterial, Privacy, Vault, approved generation, receipt, grant, ticket, or external MCP destination |
| `interactive_case_work` | The current case's explicitly selected approved/current generations, minimum confirmed case data, and current local legal sources | No raw or pending material, revoked or foreign-case generations, ordinary-chat attachments or history, automation grants, or MCP tickets |
| `approved_automation` | Approved MCP and external-host work through opaque IDs, approved source references, current qualification, grants, exact tickets, and protected sinks | No arbitrary paths, pasted case text, implicit source expansion, or fallback to either interactive mode |

Consent or approval in one mode never authorizes another. A blocked case or automation request must not be retried by pasting it into ordinary chat or moving it to another Provider, MCP, browser, or host.

## Provider dispatch

Lawyer Assistance uses BYOK Providers. Ordinary chat and approved-case Provider dispatch are separate data channels:

- Ordinary Assistant chat does not require a case or redaction approval. It sends only the user's message, eligible successful `interactive_chat` history from that conversation, and locally extracted attachment bodies explicitly selected for the current send. It does not send a local path and does not register an ordinary attachment as case material.
- Ordinary chat uses the separate `InteractiveUserProvided` classification and interactive authority. That pairing permits the selected external or verified-local Provider transport but grants no access to case services and cannot target an external MCP host.
- The Provider-server disclosure remains visible beside the ordinary composer, identifies the selected Provider, names the selected attachments with type and size, and warns against unredacted case material.
- The in-App Case Assistant accepts only approved/current generations explicitly selected from the current case plus a minimum of confirmed case data. It excludes raw files, pending drafts, Vault objects, paths, ordinary-chat attachments, and unselected history.
- A case request binds the exact project/Privacy binding snapshot, generations, Provider, endpoint, model, purpose, policy, expiry, and revocation state. The backend rechecks immediately before transport, fully buffers and scans the response, and stores only a scanned pending output.
- Applying a Case Assistant analysis, document, or diagram is a separate explicit confirmation. If a generation is revoked or becomes stale, a retry fails before transport and requires a new material selection.
- Ordinary or legacy case-bearing requests fail before serialization and network dispatch.

Providers can have their own logging, training, retention, personnel-access, and regional policies. The deployment owner must review them before use. The App cannot retract data already received by an external service.

## MCP profile isolation

- `public_law_only` is fixed to five read-only public-law tools and cannot read cases, Vault data, approved material, or work products.
- `diagram_authoring` accepts synthetic or public data only and produces local plaintext HTML. It is never a fallback channel for a real case.
- `approved_case_workspace` advertises exactly 21 tools, but discovery is not authorization. Its 16 non-public tools also require current App qualification, a standalone session, explicit grants, and an exact per-call ticket. This is the `approved_automation` boundary and is not reused by ordinary chat or the in-App Case Assistant.
- Case read/write grants and diagram read/write grants are separate. An old session never gains diagram access silently.

The approved profile accepts no arbitrary path, filename, URI, attachment, pasted source, command, shell fragment, or raw OCR. Case output is stored only through controlled work-product and approved-diagram interfaces.

`CaseRaw` and `CaseRedactedPending` content is rejected before an external MCP transport is called. Content-free audit records may retain the classification, hashes, byte counts, and rejection reason, but not the payload or destination identifier in plaintext.

## WorkBuddy, Codex, and OpenCode

Default host packages support `public_law_only` only. An approved-case package is installed separately, remains disabled by default, and starts in a new task containing opaque IDs only.

A Skill or Agent rule may load after a host sends the first message or attachment. If case content entered the task before the rule loaded, the host or its selected Provider may already have received it. Stop all calls, remove the contaminated task and attachment, clean accessible history, memory, and logs using host and Provider controls, and create a new clean task. Neither the App nor a Skill can prove that an external copy was deleted.

## File import and OCR

PDF, DOCX, UTF-8 TXT, and Markdown receive local format, size, structure, and content checks. Reliable text layers can be parsed locally. Visual pages may enter local MinerU only after current qualification is complete.

Production OCR qualification requires an exact component, worker, configuration, model, and runtime inventory; Windows Firewall outbound isolation; process-tree containment; a fixed synthetic canary; restart validation; and expiry, revocation, and drift invalidation. These controls belong under **Settings → Local processing environment and OCR components**. The `0.4.0` source candidate implements this validation chain, but production qualification cannot be claimed until final MinerU assets, signatures, GPU/driver, and clean-machine evidence exist. There is no SSH, cloud OCR, remote model download, or silent fallback.

## Diagram security

Diagram input uses a closed schema, fixed templates, and deterministic local rendering. The renderer rejects arbitrary scripts, external resources, unsafe HTML, location disclosure, and oversized graphs. Approved-case diagrams bind source lineage, specification hash, HTML hash, and an encrypted work-product manifest. Export returns descriptor metadata only.

## Backup, deletion, and logging

Under **Settings → Version, backup, and diagnostics**, `.lavbackup` uses authenticated encryption across the user database, privacy state, encrypted Vault, approved workspace, and encrypted work products. Retention, mapping and key maintenance, cleanup, and backup/restore are global maintenance functions; they do not move case review content into Settings. A backup file is still sensitive and must remain in an access-controlled location.

The application aims to log only stable error codes, versions, and content-free diagnostics. Do not place source content, keys, paths, mappings, or session information in logs, screenshots, or support tickets. Revocation, logical deletion, and key destruction do not guarantee forensic erasure of SSD cells, operating-system history, external backups, host caches, or previously disclosed cloud copies.

## Legal and operational limits

- The legal database and model output support research and review; they are not legal advice.
- A professional must verify citations, versions, effectiveness, case facts, and final documents.
- Only the exact installer from an official Release that passes Authenticode, RFC3161, and server readback has a verified Windows publisher identity; a source candidate or unsigned artifact does not.
- The source repository is public, but public source or downloadable assets do not prove Authenticode signing, updater readiness, OCR qualification, or clean-machine release acceptance.
- Updater code and verification are implemented, but automatic update is unavailable until the installer-bound signature, `latest.json`, Release promotion, and final endpoint revalidation complete.
- The full archival database is not included in the desktop App Release.
- Final production-OCR qualification still requires real assets and machine evidence; scanned or visual PDFs must remain blocked whenever current qualification is invalid.

See [Current Release Status](release-status.en.md) for current limitations and release gates.
