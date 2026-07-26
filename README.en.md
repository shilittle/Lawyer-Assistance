# Lawyer Assistance

[简体中文](README.md)

Lawyer Assistance is a local-first legal assistance workstation for Windows x86_64. It brings public-law research, case organization, citation verification, document and diagram work products, privacy approval, and controlled MCP/model access into one desktop application.

Current version: `0.4.0-beta.2`

> [!WARNING]
> This version is a technical prerelease. The current Windows installer is not Authenticode-signed and has no trusted publisher identity. Production OCR and automatic updates are not enabled. Download files only from the project Releases page, and verify the SHA-256 checksum and manifest before installation.

## Highlights

- **Local legal research**: a bundled read-only legal database supports laws, articles, historical versions, effective periods, and legal relations without requiring a model.
- **Case workspace**: locally manage matters, materials, parties, facts, evidence, issues, legal authorities, and their relationships, with timeline, gap-analysis, research, document, and graph workspaces.
- **Privacy approval chain**: materials are extracted, detected, aliased, and reviewed in the App. Only an immutable, explicitly approved generation can enter a designated workflow, with purpose, destination, model, expiry, and revocation checked again at use time.
- **21-tool approved MCP**: the separate `approved_case_workspace` profile contains exactly 5 public-law tools, 10 opaque-ID-only case/work-product tools, and 6 approved-diagram tools. It is disabled by default and opens only with current App qualification plus short-lived, least-privilege sessions and tickets.
- **Synthetic/public diagrams**: the `diagram_authoring` profile provides 5 public-law tools and 6 diagram tools for synthetic or public data only. Its local HTML bundle is plaintext and must never contain real case data. Approved-case diagrams use the encrypted work-product path instead.
- **Bring your own key (BYOK)**: configure your own Provider API key. The App supports DeepSeek, Qwen, SiliconFlow, Volcengine Ark, and custom OpenAI-compatible endpoints. Keys are stored in Windows Credential Manager, not ordinary configuration files.
- **Host integrations**: public-only integrations are included for WorkBuddy, Codex, and OpenCode, alongside separate disabled-by-default, qualification-gated approved-workspace integrations.

## Release status

| Area | `0.4.0-beta.2` status |
| --- | --- |
| Windows x86_64 desktop App | Technical prerelease |
| Installer | NSIS, currently unsigned |
| Local legal research and case workspace | Available |
| BYOK public-law Q&A | Available; calls the selected Provider over the network |
| Privacy approval and approved MCP | Implemented; disabled by default and qualification-gated |
| `diagram_authoring` | Synthetic/public data only |
| Production OCR | Not enabled; scanned/image-only PDFs should not be treated as supported |
| Automatic updates | Not enabled; check Releases manually |

This project is not a substitute for a lawyer and does not guarantee that search results, model output, or generated documents are suitable for a particular matter. Important conclusions should be checked by a qualified professional against authoritative text, current legal effect, and the actual case record.

## Download and install

### Requirements

- Windows x86_64
- Sufficient disk space for the App, bundled legal database, and local workspace data
- Network access when using a BYOK Provider; local legal search does not require one

### Download

Open [GitHub Releases](https://github.com/shilittle/Lawyer-Assistance/releases) and download the following assets for `0.4.0-beta.2`:

- `Lawyer.Assistance_0.4.0-beta.2_windows-x86_64-unsigned-setup.exe`
- The adjacent `.sha256` file
- The adjacent `.manifest.json` file

Do not use a renamed installer or one obtained from another source. If these exact assets are not present, no supported public installer is available there. This prerelease does not produce a usable updater `.sig` or `latest.json`.

### Verify

Calculate the installer hash in PowerShell:

```powershell
Get-FileHash `
  .\Lawyer.Assistance_0.4.0-beta.2_windows-x86_64-unsigned-setup.exe `
  -Algorithm SHA256
```

Compare the result with the `.sha256` file and confirm that the manifest reports:

- `version` is `0.4.0-beta.2`
- `signed` is `false`
- `updaterArtifactGenerated` is `false`

After verification, run the installer. It uses current-user installation mode. Because the installer is unsigned, Windows may show an unknown-publisher warning. Confirm the exact filename, source, and checksum first, and never bypass a warning for an installer of unknown origin.

## Quick start

1. Launch Lawyer Assistance and search for a law, keyword, or article number.
2. Open an article to review its source, version, effective period, and related authorities.
3. To organize a matter, create a local case workspace and enter materials, facts, evidence, and issues. Reliable text layers can be extracted locally; do not rely on production OCR for scans in this prerelease.
4. To use a model, create a BYOK Provider under Settings and select it only for a defined task. Public-law Q&A uses local candidate sources and validates `[SRC:...]` citations.
5. For public-law access from an external host, start the default `public_law_only` MCP:

```text
lawyer-assistance-mcp --privacy-profile public_law_only stdio
```

The profile must expose exactly these 5 read-only tools:

```text
system_status
legal_search
legal_get_article
legal_get_versions
legal_get_relations
```

Never send case data through the public-only integration. `approved_case_workspace` may be issued only after in-App material approval, current qualification, and least-privilege authorization. Host tasks use opaque IDs only and must not paste or attach case text.

## Documentation

- [User documentation home](docs/README.en.md)
- [Full getting-started guide](docs/getting-started.en.md)
- [Current release status](docs/release-status.en.md)
- [User security and privacy guide](docs/security-and-privacy.en.md)
- [Legal corpus and runtime database](docs/data/legal-corpus.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release notes](RELEASE_NOTES.md)
- [MCP overview](docs/mcp/README.md)
- [MCP installation and operation](docs/mcp/installation.md)
- [Approved case workspace](docs/mcp/approved-case-workspace.md)
- [MCP security and privacy boundary](docs/mcp/security-and-privacy.md)
- [Compatibility matrix](docs/mcp/compatibility-matrix.md)
- [Diagram architecture](docs/diagrams/architecture.md)
- [Diagram examples](docs/diagrams/examples.md)
- [WorkBuddy integration](integrations/workbuddy/README.md)
- [Codex integration](integrations/codex/README.md)
- [OpenCode integration](integrations/opencode/README.md)
- [Repository guide](docs/development/repository-layout.md)

## Development and build

### Toolchain

- Windows with the MSVC Rust toolchain
- Node.js `>=24`
- pnpm `>=11` (the repository declares `pnpm@11.7.0`)
- Python 3

Install dependencies:

```powershell
pnpm install
```

Run the common checks and frontend build:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features --offline -- -D warnings
cargo test --locked --workspace --offline
pnpm lint
pnpm test
pnpm build
```

Build the standalone MCP binary:

```powershell
cargo build --locked -p legal-mcp --bin lawyer-assistance-mcp
```

Build an explicitly unsigned Windows technical installer:

```powershell
pnpm --filter @lawyer-assistance/desktop release:installer:unsigned
```

A formal desktop build requires these generated and verified resources:

```text
apps/desktop/src-tauri/resources/legal_core.sqlite
data/generated/legal_core_distribution_manifest.json
```

The large legal databases are generated/release resources rather than ordinary Git blobs. The build also verifies licenses, third-party notices, frontend output, and the hash binding between the packaged MCP sibling and the App. See the [repository guide](docs/development/repository-layout.md) and [MCP development documentation](docs/mcp/development-and-testing.md) for the full constraints.

## Security and privacy

- **Local-first does not mean network-free**: legal research, case storage, and most workspace functions are local. BYOK Provider requests are sent to the third party selected by the user.
- **Approval is not blanket authorization**: even locally approved material remains bound to an exact destination, purpose, model, generation, expiry, and revocation state.
- **Public MCP has no case capabilities**: the default profile contains only 5 read-only public-law tools.
- **Approved MCP uses least privilege**: the non-public tools in the 21-tool profile are divided into `read`, `write`, `diagram_read`, and `diagram_write`. Missing, expired, revoked, or mismatched state fails closed.
- **Do not paste raw case material into an external host**: WorkBuddy, Codex, OpenCode, or another model host may process an attachment or first message before integration rules load. Rules cannot retract a disclosure that has already occurred.
- **Credential protection**: Provider keys are stored in Windows Credential Manager; the frontend receives only configured or masked status.
- **Network boundary**: MCP HTTP is loopback-only by default. Do not use cleartext non-loopback listening as a production endpoint.
- **Local protection is machine/user-bound**: some encrypted state uses Windows DPAPI CurrentUser. Copying files does not transfer qualification or authorization.

When reporting a security issue, do not attach real case data, credentials, databases, or raw logs to a public issue. Provide only the minimum redacted information needed to reproduce the problem.

## License

The source code is available under the [MIT License](LICENSE).

Bundled third-party components, legal data, and source materials may have their own licenses, terms, and attribution requirements. See:

- [Third-party notices](apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt)
- [Data sources](apps/desktop/src-tauri/resources/DATA_SOURCES.md)
