# Installation and run (v1.1.0)

The public stdio server can run without a private workspace database:

```text
lawyer-assistance-mcp --legal-db /absolute/path/legal_core.sqlite --privacy-profile public_law_only stdio
```

Without `--legal-db`, the server uses `LEGAL_DB` then `data/runtime/legal_core.sqlite`. It then discovers `judicial_cases.sqlite` in the same directory for `legal_search_cases` and `legal_get_case`; no second public path argument is needed. `--config` may still provide `legal_db` for existing launchers. Legacy user-workspace options are ignored by the public profile.

For a v1.1.0 `privacy_workspace` stdio connection, the application backend must already be running on loopback and the client token comes from a file or `MCP_TOKEN`:

```text
lawyer-assistance-mcp --privacy-profile privacy_workspace --daemon-url http://127.0.0.1:8877 --client-token-file /absolute/path/client-token.txt stdio
```

Never pass a bearer token as a command-line argument. The standalone HTTP listener defaults to `127.0.0.1:8787/mcp`; an application can embed `build_proxy_router` in its own loopback server.
