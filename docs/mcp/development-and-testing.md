# Development and testing

Run the focused MCP checks for the v1.1.0 Web release and after protocol changes:

```text
cargo fmt --all -- --check
cargo test -p legal-mcp -p legal-services
python integrations/validate_examples.py
python -m unittest integrations/test_validate_examples.py
```

Regression coverage verifies exact public and privacy tool lists (7/10), the two additive case tool names and schemas, disabled legacy profiles, stdio-only JSON-RPC output, loopback daemon failure redaction, and Streamable HTTP authorization/timeout boundaries. The separate case smoke uses the real official sidecar with a local mock Provider for the explicit understanding route; it does not send case text to a model beyond the current input. Cloud-assistance checks use a controllable simulation service; v1.1.0 does not claim production Provider accuracy. Do not use real cloud credentials or private case materials in these tests.
