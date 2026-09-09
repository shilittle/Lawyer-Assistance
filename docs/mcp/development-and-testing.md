# Development and testing

Run the focused MCP checks for the v1.0.0 Web release and after protocol changes:

```text
cargo fmt --all -- --check
cargo test -p legal-mcp -p legal-services
python integrations/validate_examples.py
python -m unittest integrations/test_validate_examples.py
```

Regression coverage verifies exact public and privacy tool lists, disabled legacy profiles, stdio-only JSON-RPC output, loopback daemon failure redaction, and Streamable HTTP authorization/timeout boundaries. Cloud-assistance checks use a controllable simulation service; v1.0.0 does not claim a real Provider integration. Do not use real cloud credentials or case materials in these tests.
