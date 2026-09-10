# Security and privacy (v1.1.0)

Public MCP tools accept and return only public legal research data. They do not open a user workspace database. The two case tools read only the verified, read-only `judicial_cases.sqlite` sidecar beside `legal_core.sqlite`; results carry official source URLs and bounded public fields.

Case understanding is an explicit WebUI operation. After the user chooses an existing Provider, only the current input is sent to that Provider to derive a bounded query and issue list. The returned cases always come from the local sidecar; model output cannot add a case, source URL, full text, or holding.

The privacy MCP surface has three narrow operations: submit configured inbox-relative paths, inspect task status, and read paged published redacted results. It has no original reader, mapping reader, approval operation, cloud authorization operation, or arbitrary file path parameter.

The local adapter allows only literal loopback HTTP, no redirects, bounded requests and responses, and a current bearer header. Backend errors are reduced to a safe code and retryability flag; they must not include source text, mappings, original names, disk paths, stack traces, or diagnostics. HTTP responses use `Cache-Control: no-store` and validate Host and Origin.
