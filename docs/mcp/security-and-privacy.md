# Security and privacy (v1.0.0)

Public MCP tools accept and return only public legal research data. They do not open a user workspace database.

The privacy MCP surface has three narrow operations: submit configured inbox-relative paths, inspect task status, and read paged published redacted results. It has no original reader, mapping reader, approval operation, cloud authorization operation, or arbitrary file path parameter.

The local adapter allows only literal loopback HTTP, no redirects, bounded requests and responses, and a current bearer header. Backend errors are reduced to a safe code and retryability flag; they must not include source text, mappings, original names, disk paths, stack traces, or diagnostics. HTTP responses use `Cache-Control: no-store` and validate Host and Origin.
