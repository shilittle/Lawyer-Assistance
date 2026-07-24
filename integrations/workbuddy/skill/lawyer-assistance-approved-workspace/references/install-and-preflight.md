# Installation and preflight

1. Do not import this package until the App reports the exact approved-workspace qualification complete. A missing, malformed, expired, revoked, or mismatched session must return `PROFILE_NOT_QUALIFIED`.
2. Import only `assets/connectors/stdio.windows.json`. In the App, create a standalone stdio session, copy only its opaque `srv_[0-9a-f]{32}` server ID, and replace `<APP_ISSUED_SERVER_ID>` exactly once.
3. Require the exact command tail `--privacy-profile approved_case_workspace --approved-session-id <srv_id> stdio`. Refuse any database/root/config path, environment field, bearer token, bind/origin value, HTTP transport, or dangerous switch. The host never receives the DPAPI descriptor path or any key/token.
4. Require `tools/list` to match all 15 entries in [tool-catalog](tool-catalog.md), in order. An extra, missing, renamed, or reordered tool is a deployment failure.
5. Start every case task with opaque IDs only and no attachment, paste, filename, path, copied case text, or old tool response.
6. Stop before processing on `PROFILE_NOT_QUALIFIED`, unavailable isolation, unapproved Provider, missing manifest trust, revocation, expiry, response mismatch, or any raw disclosure.

Do not weaken wildcard denial or history/memory controls to make the profile work. A client allowlist cannot qualify the backend. Approved HTTP is App-broker-only and has no static host asset.
