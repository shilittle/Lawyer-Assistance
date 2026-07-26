# Security and Privacy

## Security model overview

Lawyer Assistance processes the legal database, case material, redaction state, work products, and backups locally by default. It treats “content is local,” “content was manually approved,” and “content may be sent to a destination” as three different facts. User consent, a prompt, host permissions, or a filename cannot replace backend qualification, signed state, authorization scope, and replay protection.

This model reduces accidental disclosure and unauthorized access. It does not replace lawyer review, organizational controls, endpoint security, Provider contracts, or backup management.

## Data classes

- **Public legal data:** may enter the default public-law research workflow.
- **Raw case data:** client, case, material, attachment, OCR text, and identifying derived facts; local-only by default.
- **Pending redaction:** not yet precisely reviewed and therefore handled as raw case data.
- **Approved generation:** immutable content, scope, and provenance signed by the App after manual review; it still has no general outbound permission.
- **Protected work product:** a work product or approved-case diagram created and stored through a controlled workflow.

## Local storage

The application uses a read-only runtime legal database and locally writable user data. Rust backend services manage cases, approvals, Vault data, mappings, and work products; the frontend cannot perform arbitrary database reads. API keys use Windows Credential Manager. Ordinary configuration, logs, and frontend state contain only necessary non-secret information or masked status.

Protected work products use authenticated encryption, versioned manifests, and authenticated completion records. Legacy plaintext content, an unexpected file set, hash mismatch, revoked provenance, or residual files fail closed.

## Provider dispatch

Lawyer Assistance uses BYOK Providers. Public-law Q&A and approved-case Provider dispatch are separate data channels:

- Public-law Q&A must contain no client or case facts.
- An approved-case request restores content from a protected generation and binds the exact Provider, endpoint, model, purpose, policy, expiry, and revocation state.
- The backend rechecks immediately before transport, scans the response, and persists it as protected output.
- Ordinary or legacy case-bearing requests fail before serialization and network dispatch.

Providers can have their own logging, training, retention, personnel-access, and regional policies. The deployment owner must review them before use. The App cannot retract data already received by an external service.

## MCP profile isolation

- `public_law_only` is fixed to five read-only public-law tools and cannot read cases, Vault data, approved material, or work products.
- `diagram_authoring` accepts synthetic or public data only and produces local plaintext HTML. It is never a fallback channel for a real case.
- `approved_case_workspace` advertises exactly 21 tools, but discovery is not authorization. Its 16 non-public tools also require current App qualification, a standalone session, explicit grants, and an exact per-call ticket.
- Case read/write grants and diagram read/write grants are separate. An old session never gains diagram access silently.

The approved profile accepts no arbitrary path, filename, URI, attachment, pasted source, command, shell fragment, or raw OCR. Case output is stored only through controlled work-product and approved-diagram interfaces.

## WorkBuddy, Codex, and OpenCode

Default host packages support `public_law_only` only. An approved-case package is installed separately, remains disabled by default, and starts in a new task containing opaque IDs only.

A Skill or Agent rule may load after a host sends the first message or attachment. If case content entered the task before the rule loaded, the host or its selected Provider may already have received it. Stop all calls, remove the contaminated task and attachment, clean accessible history, memory, and logs using host and Provider controls, and create a new clean task. Neither the App nor a Skill can prove that an external copy was deleted.

## File import and OCR

PDF, DOCX, UTF-8 TXT, and Markdown receive local format, size, structure, and content checks. Reliable text layers can be parsed locally. Visual pages may enter local MinerU only after current qualification is complete.

Production OCR qualification requires an exact component, worker, configuration, model, and runtime inventory; Windows Firewall outbound isolation; process-tree containment; a fixed synthetic canary; restart validation; and expiry, revocation, and drift invalidation. The current technical prerelease has not achieved this qualification and provides no SSH, cloud OCR, remote model download, or silent fallback.

## Diagram security

Diagram input uses a closed schema, fixed templates, and deterministic local rendering. The renderer rejects arbitrary scripts, external resources, unsafe HTML, location disclosure, and oversized graphs. Approved-case diagrams bind source lineage, specification hash, HTML hash, and an encrypted work-product manifest. Export returns descriptor metadata only.

## Backup, deletion, and logging

`.lavbackup` uses authenticated encryption across the user database, privacy state, encrypted Vault, approved workspace, and encrypted work products. A backup file is still sensitive and must remain in an access-controlled location.

The application aims to log only stable error codes, versions, and content-free diagnostics. Do not place source content, keys, paths, mappings, or session information in logs, screenshots, or support tickets. Revocation, logical deletion, and key destruction do not guarantee forensic erasure of SSD cells, operating-system history, external backups, host caches, or previously disclosed cloud copies.

## Legal and operational limits

- The legal database and model output support research and review; they are not legal advice.
- A professional must verify citations, versions, effectiveness, case facts, and final documents.
- The unsigned technical prerelease has no trusted Windows publisher identity.
- There is currently no automatic-update release chain.
- The full archival database is not included in the technical prerelease package.
- Production OCR is not qualified; scanned and visual PDFs must remain blocked.

See [Current Release Status](release-status.en.md) for current limitations and release gates.
