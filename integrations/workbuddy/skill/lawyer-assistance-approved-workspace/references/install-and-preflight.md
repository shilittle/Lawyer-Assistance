# Installation and preflight

1. Do not import this package until the App reports the exact approved-workspace qualification complete. The present unqualified backend must answer case execution with `PROFILE_NOT_QUALIFIED`.
2. Import one connector from `assets/connectors`; replace executable/database locations only. The stdio command must retain `--privacy-profile approved_case_workspace`. Never grant a vault, case-source, pending, or approved filesystem root to WorkBuddy.
3. For HTTP, use only `127.0.0.1`, source the Bearer token from `LAWYER_ASSISTANCE_MCP_TOKEN`, and require the server itself to run `approved_case_workspace`.
4. Require `tools/list` to match all 15 entries in [tool-catalog](tool-catalog.md), in order. An extra, missing, renamed, or reordered tool is a deployment failure.
5. Start every case task with opaque IDs only and no attachment, paste, filename, path, copied case text, or old tool response.
6. Stop before processing on `PROFILE_NOT_QUALIFIED`, unavailable isolation, unapproved Provider, missing manifest trust, or any raw disclosure.

Do not weaken wildcard denial or history/memory controls to make the profile work. A client allowlist cannot qualify the backend.
