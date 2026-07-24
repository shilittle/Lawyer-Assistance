# Installation and preflight

1. Keep the approved config disabled until the App reports the exact qualification complete. A missing, malformed, expired, revoked, or mismatched session must return `PROFILE_NOT_QUALIFIED`.
2. Use only the Windows stdio asset. In the App, create a standalone stdio session, copy only its opaque `srv_[0-9a-f]{32}` server ID, and replace `<APP_ISSUED_SERVER_ID>` exactly once.
3. Require the exact command tail `--privacy-profile approved_case_workspace --approved-session-id <srv_id> stdio`. Refuse every environment field, database/root/config path, bearer token, bind/origin value, HTTP transport, or dangerous switch. The host never receives the DPAPI descriptor path or a key/token.
4. Require an exact ordered 15-tool list. Keep wildcard denial/default write confirmation and merge `config.privacy-hardening.toml`.
5. Invoke the Skill explicitly in a new clean task with opaque IDs only. Do not attach, paste, name, or path-reference case material.
6. Stop if qualification, Provider approval, isolation, manifest trust, revocation/expiry state, or response verification is unavailable.

Approved HTTP is App-broker-only and has no static Codex asset.
