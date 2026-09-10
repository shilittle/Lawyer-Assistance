# Architecture (v1.1.0)

A single loopback application service owns the private workspace in the v1.1.0 Web release. `legal-mcp` is a protocol adapter: it opens the read-only statute database and its sibling case sidecar through the public legal service, then forwards privacy workspace requests to `http://127.0.0.1:8877` by default.

The public legal tools need no user database. `legal_search` and the original article tools continue to use `legal_core.sqlite`; `legal_search_cases` and `legal_get_case` discover `judicial_cases.sqlite` in the same directory and keep it read-only. A missing or incompatible case sidecar produces a bounded availability result without changing the statute database. `privacy_workspace` creates a request-scoped backend adapter from each incoming `Authorization: Bearer` header. The adapter accepts only literal loopback HTTP origins, disables redirects, applies connection/request/response limits, and converts failures to `{ "error": { "code", "retryable" } }`.

The HTTP MCP router accepts no bearer or a configured public bearer as the seven-tool public scope. A syntactically valid non-public bearer may see the privacy scope; the backend validates that client's authorization and material group for every workspace operation.
