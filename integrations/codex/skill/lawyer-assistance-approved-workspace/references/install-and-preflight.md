# Installation and preflight

1. Keep the approved config disabled until the App reports the exact qualification complete. Current unqualified execution must return `PROFILE_NOT_QUALIFIED`.
2. Select the stdio or HTTP asset. Stdio must pin `--privacy-profile approved_case_workspace`; HTTP must stay loopback-only with an environment-provided Bearer token and a server started under the same profile.
3. Never grant the MCP host a vault, source-case, pending, or approved directory. The legacy allowed root in the template points to a dedicated empty input directory; work products are reachable only through business methods.
4. Require an exact ordered 15-tool list. Keep wildcard denial/default write confirmation and merge `config.privacy-hardening.toml`.
5. Invoke the Skill explicitly in a new clean task with opaque IDs only. Do not attach, paste, name, or path-reference case material.
6. Stop if qualification, Provider approval, isolation, manifest trust, revocation state, or response verification is unavailable.
