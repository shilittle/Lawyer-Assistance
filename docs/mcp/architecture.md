# Architecture (v1.0.0)

A single loopback application service owns the private workspace in the v1.0.0 Web release. `legal-mcp` is a protocol adapter: it opens only the read-only legal database through `LegalServices::new_public` and forwards privacy workspace requests to `http://127.0.0.1:8877` by default.

The public legal tools need no user database. `privacy_workspace` creates a request-scoped backend adapter from each incoming `Authorization: Bearer` header. The adapter accepts only literal loopback HTTP origins, disables redirects, applies connection/request/response limits, and converts failures to `{ "error": { "code", "retryable" } }`.

The HTTP MCP router accepts no bearer or a configured public bearer as the five-tool public scope. A syntactically valid non-public bearer may see the privacy scope; the backend validates that client's authorization and material group for every workspace operation.
