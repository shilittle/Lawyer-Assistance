# Lawyer Assistance

[简体中文](README.md)

Lawyer Assistance is a local-first legal assistance workstation for Windows x86_64. It brings public-law research, case organization, citation verification, document and diagram work products, privacy approval, and controlled MCP/model access into one desktop application.

Current version: `0.4.0`

> [!WARNING]
> The repository carries the stable-version `0.4.0` source candidate, but the stable Release is not published until exact-main CI, external signing, server readback, Windows 10/11 clean-machine, updater, and final MinerU qualification gates all have recorded evidence. Do not treat a locally built, CI, historical, or prerelease asset as the published stable package.
>
> The source repository is public. Public access to source code or downloadable files does not make an installer signed, activate the updater, qualify OCR, or satisfy stable-release acceptance.

## Highlights

- **Local legal research**: a bundled read-only legal database supports laws, articles, historical versions, effective periods, and legal relations without requiring a model.
- **Ordinary Assistant chat**: start a conversation after configuring a Provider without first creating a case, importing a case file, or completing redaction approval. The composer keeps the Provider-server warning visible and sends only the message, eligible ordinary-chat history, and attachments explicitly selected for that send.
- **Case workspace**: locally manage matters through Overview, Materials & Redaction, Case Work, and Outputs. Materials & Redaction owns import, local extraction or qualified OCR, redaction review, immutable approval, revocation, and version history.
- **Approved-only Case Assistant**: Case Work can use only the current case's explicitly selected approved/current redaction generations plus confirmed case data. It never reads raw case files or Vault objects, and a revoked source must be reselected before another request.
- **Privacy approval chain**: materials are extracted, detected, aliased, and reviewed in the App. Only an immutable, explicitly approved generation can enter a designated workflow, with purpose, destination, model, expiry, and revocation checked again at use time.
- **21-tool approved MCP**: the separate `approved_case_workspace` profile contains exactly 5 public-law tools, 10 opaque-ID-only case/work-product tools, and 6 approved-diagram tools. It is disabled by default and opens only with current App qualification plus short-lived, least-privilege sessions and tickets.
- **Synthetic/public diagrams**: the `diagram_authoring` profile provides 5 public-law tools and 6 diagram tools for synthetic or public data only. Its local HTML bundle is plaintext and must never contain real case data. Approved-case diagrams use the encrypted work-product path instead.
- **Bring your own key (BYOK)**: configure your own Provider API key. The App supports DeepSeek, Qwen, SiliconFlow, Volcengine Ark, and custom OpenAI-compatible endpoints. Keys are stored in Windows Credential Manager, not ordinary configuration files.
- **Host integrations**: public-only integrations are included for WorkBuddy, Codex, and OpenCode, alongside separate disabled-by-default, qualification-gated approved-workspace integrations.

## Release status

| Area | `0.4.0` source-candidate status |
| --- | --- |
| Windows x86_64 desktop App | Implemented in source; published-stable acceptance remains pending |
| Installer | NSIS release path implemented; no stable asset is accepted until Authenticode and RFC 3161 verification pass |
| Local legal research and case workspace | Available |
| Ordinary Assistant chat and explicit attachments | Available with BYOK; no case is required, and selected content is sent to the Provider over the network |
| Approved-only Case Assistant | Implemented under Case Work; source and Provider authorization are rechecked before transport |
| Privacy approval and approved MCP | Implemented; disabled by default and qualification-gated |
| `diagram_authoring` | Synthetic/public data only |
| Production OCR | Not qualified; scanned/image-only PDFs remain blocked unless every current qualification gate passes |
| Automatic updates | Release path implemented; no active stable update chain exists before signed `latest.json` publication and readback |

This project is not a substitute for a lawyer and does not guarantee that search results, model output, or generated documents are suitable for a particular matter. Important conclusions should be checked by a qualified professional against authoritative text, current legal effect, and the actual case record.

## Download and install

### Requirements

- Windows x86_64
- Sufficient disk space for the App, bundled legal database, and local workspace data
- Network access when using a BYOK Provider; local legal search does not require one

### Download

The stable `v0.4.0` package must not be treated as available merely because the repository or an individual file is public. When the project reports that the stable Release has passed every gate, open [GitHub Releases](https://github.com/shilittle/Lawyer-Assistance/releases) and require this exact 12-asset App/MCP allowlist (GitHub-generated source archives do not count):

```text
Lawyer.Assistance_0.4.0_x64-setup.exe
Lawyer.Assistance_0.4.0_x64-setup.exe.sha256
Lawyer.Assistance_0.4.0_x64-setup.exe.sig
latest.json
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256
lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip
lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256
lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz
lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256
```

Do not use a renamed installer or one obtained from another source. The official publication process rereads every asset from the service before promotion. If the exact set is incomplete, the Release is still a draft/prerelease, or the project has not reported final readback success, no supported stable installer is available there. Never substitute an unsigned technical build or an older beta.

### Verify

After stable publication, calculate the installer hash and inspect its Windows signature in PowerShell:

```powershell
Get-FileHash `
  .\Lawyer.Assistance_0.4.0_x64-setup.exe `
  -Algorithm SHA256

Get-AuthenticodeSignature `
  .\Lawyer.Assistance_0.4.0_x64-setup.exe | `
  Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

Compare the digest with `Lawyer.Assistance_0.4.0_x64-setup.exe.sha256`. Continue only when the signature status is `Valid`, the expected publisher identity is present, and a trusted timestamp is shown. The Release verifier also binds `latest.json` and its updater signature to these exact installer bytes; do not edit or rename any asset.

After verification, run the installer. It uses current-user installation mode. Stop if Windows reports an unknown publisher, an invalid or missing signature, an unexpected signer, or an untrusted timestamp; those results do not match the stable asset contract.

## Quick start

1. Under **Settings → Provider services and credentials**, create a BYOK Provider and store its API key.
2. Open **Assistant**, create an independent conversation, choose the Provider, and send an ordinary message. No case, case upload, redaction review, or task-specific approval form is required.
3. To include an ordinary attachment, import it into that conversation and explicitly select it for the current send. The App shows its name, type, and size and states that locally extracted text will be sent; cancelling or leaving it unselected sends no attachment body or local path. Ordinary attachments do not become case materials automatically.
4. Keep the Provider disclosure beside the composer in view: ordinary chat is sent through the selected Provider API and must not contain unredacted case material.
5. Use **Legal Library** for offline laws, versions, effective periods, relations, and source review.
6. For a real matter, create a case and open **Cases → Materials & Redaction**. Import the material, complete local text extraction, review the redaction, and approve an immutable generation. Do not rely on production OCR until the exact final component and current machine both pass every qualification gate.
7. Open **Cases → Case Work → Case Assistant**, explicitly select approved/current generations for that request, and choose **Select and send**. Only those approved projections and confirmed case data may be used. Applying analysis, document, or diagram output remains a separate confirmation step.
8. For public-law access from an external host, start the default `public_law_only` MCP:

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

## Information architecture and execution modes

The top-level product areas are fixed to **Assistant**, **Cases**, **Legal Library**, and **Settings**. Settings has four owners: **Provider services and credentials**, **Local processing environment and OCR components**, **MCP and automation**, and **Version, backup, and diagnostics**. Case material, redacted text, and human review remain under **Cases → Materials & Redaction**, not Settings.

The three execution modes are intentionally separate:

| Mode | Product use | Allowed source boundary |
| --- | --- | --- |
| `interactive_chat` | Ordinary Assistant chat | User-entered text, eligible ordinary-chat history, and attachments explicitly selected for that send; never the case workspace or Vault |
| `interactive_case_work` | Case Assistant inside Case Work | Explicit approved/current generations from the current case plus confirmed case data; never raw or pending material |
| `approved_automation` | MCP and external hosts | Opaque IDs, approved source references, current qualification, grants, exact tickets, and protected work-product sinks |

Approval in one mode never authorizes another mode or provides a fallback route.

## Documentation

- [User documentation home](docs/README.en.md)
- [Full getting-started guide](docs/getting-started.en.md)
- [Current release status](docs/release-status.en.md)
- [Upgrade from v0.3.1 to v0.4.0](docs/upgrade-v0.3.1-to-v0.4.0.en.md)
- [User security and privacy guide](docs/security-and-privacy.en.md)
- [Legal corpus and runtime database](docs/data/legal-corpus.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
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

Build an explicitly unsigned Windows technical artifact for local validation only:

```powershell
pnpm --filter @lawyer-assistance/desktop release:installer:unsigned
```

This command does not create a stable installer, updater metadata, or publication evidence. The stable workflow requires external Authenticode and updater credentials, exact asset allowlists, signature verification, service-side readback, and the remaining release gates described in [Current release status](docs/release-status.en.md).

A formal desktop build requires these generated and verified resources:

```text
apps/desktop/src-tauri/resources/legal_core.sqlite
data/generated/legal_core_distribution_manifest.json
```

The large legal databases are generated/release resources rather than ordinary Git blobs. The build also verifies licenses, third-party notices, frontend output, and the hash binding between the packaged MCP sibling and the App. See the [repository guide](docs/development/repository-layout.md) and [MCP development documentation](docs/mcp/development-and-testing.md) for the full constraints.

## Security and privacy

- **Local-first does not mean network-free**: legal research, case storage, and most workspace functions are local. BYOK Provider requests are sent to the third party selected by the user.
- **Ordinary chat is case-free, not automatically public**: its explicit `interactive_chat` authority permits the user-selected Provider request but never grants access to case services. The App continuously warns against entering or attaching unredacted case material.
- **Approval is not blanket authorization**: even locally approved material remains bound to an exact destination, purpose, model, generation, expiry, and revocation state.
- **Case Assistant is approved-only**: each send revalidates the current case and only the generations explicitly selected for that request. Raw files, pending redactions, Vault objects, paths, and ordinary-chat attachments are excluded.
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
