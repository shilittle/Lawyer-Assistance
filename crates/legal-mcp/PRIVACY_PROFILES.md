# MCP privacy profiles

This crate defaults to `public_law_only`. The `redacted_case` profile must be
selected explicitly.

`public_law_only` remains cross-platform. Production `redacted_case` receipt
loading and persisted-token protection currently require Windows Credential
Manager and DPAPI. On other platforms the profile can be listed for contract
inspection, but `citation_validate` always fails closed; no Keychain or
`libsecret` fallback is implemented.

## Tool matrix

| Tool | `public_law_only` | `redacted_case` |
| --- | --- | --- |
| `system_status` | visible, read-only | visible, read-only |
| `legal_search` | visible, read-only | visible, read-only |
| `legal_get_article` | visible, read-only | visible, read-only |
| `legal_get_versions` | visible, read-only | visible, read-only |
| `legal_get_relations` | visible, read-only | visible, read-only |
| `citation_validate` | hidden | visible, receipt-gated, read-only |

The following tools are hidden and uncallable in both profiles:

- `case_get_state`
- `case_propose_patch`
- `case_apply_patch`
- `case_analyze_gaps`
- `document_generate`
- `document_export`

Consequently, integrations that still require a twelve-tool case editing,
generation, or export workflow are incompatible with this server and must
remain disabled until their profile contract is updated.

## `redacted_case` receipt contract

`citation_validate` accepts only two wrapper fields:

- `approved_payload_json`: the exact UTF-8 JSON bytes of one
  `CitationValidateRequest`.
- `redaction_receipt`: the exact persisted `rct_v1` token.

A call is rejected before legal-services runs unless all of these conditions
hold:

1. The token is signed by the App key loaded from the fixed Windows Credential
   Manager target `LawyerAssistancePrivacy/redaction-receipt-signing/v1`.
   MCP never creates a signing key and does not accept one from arguments,
   files, environment variables, or normal configuration.
2. The exact token is present in the fixed sibling database
   `privacy/privacy-workflow.sqlite`, remains active, and its DPAPI-protected
   stored bytes exactly match the submitted token.
3. The persisted review is approved, outbound-ready, has no unresolved
   high-risk findings, and its source, extraction, redacted-content, approved
   payload, policy, and detector provenance matches the signed claims.
4. The destination is `ExternalMcpHost` with identifier
   `lawyer-assistance-mcp:redacted_case`.
5. The purpose is exactly `mcp.citation_validate.v1`, the key version is
   `1`, and the finite receipt lifetime is at most five minutes.
6. The receipt binds the exact `approved_payload_json` bytes. Reformatting,
   reordering JSON fields, or changing one byte invalidates it.
7. The shared residual-sensitive-content scan passes, and the exact bytes then
   decode as a closed `CitationValidateRequest`.

Missing credentials or receipt state do not remove the tool from an explicitly
selected `redacted_case` list. Calls fail closed with generic JSON-RPC
`-32602`; token, payload, file paths, and validation details are not returned.
Only the parsed business request reaches legal-services. Both MCP result
channels, `content` and `structuredContent`, pass the final privacy gate.

## Current integration boundary

The existing App workflow signs `local.safe_pdf` page-material payloads. Those
receipts are deliberately incompatible with `mcp.citation_validate.v1`.
The production App-to-MCP positive signing flow is therefore **not integrated
yet**. The positive HTTP and stdio tests use the trusted in-process constructor
and the same persisted-receipt/DPAPI verification path to qualify the protocol
and cryptographic boundary; that constructor is not a production credential
bypass.

The fixed destination identifies this local MCP profile, not an individual
WorkBuddy, Codex, or other connector instance. Any separately authorized client
connected to the same local service could replay an active token during its
five-minute lifetime. Receipts are revocable but are not one-time-consumed.
Do not describe the current design as connector-instance-bound or replay-proof.

Raw PDFs, OCR output, local paths, case state, writes, document generation, and
exports do not cross this MCP boundary. Local PDF/OCR/redaction belongs in the
App's trusted local IPC workflow. A host such as WorkBuddy must also carry an
explicit policy that forbids uploading, browsing, searching, logging, or
sending any case material before local redaction and approval. MCP can restrict
its own tools and outputs, but it cannot control unrelated network actions
taken by the host.
