# Current Release Status

## Version conclusion

The current target version is `0.4.0-beta.2`, with this release classification:

> Unsigned technical prerelease; it has not met the release gates for a formal production or complete edition.

This conclusion does not negate the implemented local legal research, case workspace, privacy approval, protected work-product, MCP, and backup capabilities. It means that signing, automatic update, production OCR, full archival resources, and final-environment acceptance remain incomplete.

## Currently available capabilities

| Capability | Status |
|---|---|
| Windows x86_64 desktop application | Implemented; the technical prerelease has no trusted publisher identity |
| `runtime-slim-v1` legal database | Used as an application resource for current query and citation workflows |
| Local case, evidence, issue, and legal-authority management | Implemented |
| Local PDF, DOCX, UTF-8 TXT, and Markdown import | Implemented; visual pages remain subject to OCR qualification |
| Redaction review, immutable approved generations, Vault, and mappings | Implemented |
| Protected work products and safe derived files | Implemented |
| Five-component authenticated and encrypted `.lavbackup` | Implemented |
| BYOK Providers | Implemented; public-law and approved-case channels are separate |
| `public_law_only` | Default five-tool read-only public-law MCP surface |
| `approved_case_workspace` | Exactly 21 tools; disabled by default and constrained by App qualification, session, grants, and tickets |
| `diagram_authoring` | Exactly 11 tools; permanently limited to synthetic or public data |
| Approved-case diagrams | Stored through the approved workspace as encrypted protected HTML work products |

## Not delivered or not qualified

### Authenticode and installers

The current version has not completed formal Authenticode signing or trusted Windows publisher acceptance. An unsigned installer may trigger SmartScreen, AV, or EDR warnings and must not be labeled as signed or as a formal production installer.

### Automatic update

No publishable installer-bound updater `.sig` or `latest.json` is currently available. The technical prerelease must not publish updater metadata that points to an unsigned installer. Upgrade by obtaining and verifying a complete replacement package.

### Production OCR

The local MinerU code path, component management, and qualification gates are implemented, but the current version has no final publishable component or production qualification. Scanned and visual PDFs must remain fail-closed. Do not substitute cloud OCR, remote OCR, SSH, or silent upload.

### Full archival database

The application uses the `runtime-slim-v1` projection. The full archival `legal_core_full.sqlite` database is not part of the technical prerelease package and cannot be replaced by a fixture, the runtime projection, or a same-named file. Work requiring full-coverage rebuilds and strict archival/provenance audit must use a separately verified formal archival resource.

### Final-environment acceptance

A formal release still requires:

- generation and verification of final portable, installer, and MCP assets from clean release source;
- Windows 10/11 clean-machine install, launch, upgrade, rollback, and uninstall coverage;
- exact Authenticode, timestamp, SmartScreen, AV/EDR, and updater-asset verification;
- deterministic build, approval, signing, short-root installation, remeasurement, and GPU probe of the final MinerU component;
- all App OCR isolation, canary, restart, drift, revocation, and expiry gates; and
- remeasurement and synthetic E2E of the final release App and its paired MCP binary.

## How this version may be described

Acceptable descriptions:

- “Lawyer Assistance `0.4.0-beta.2` unsigned technical prerelease”
- “Provides local public-law research, case organization, privacy approval, protected work products, and controlled MCP”
- “Production OCR is blocked by default”
- “Uses a runtime legal database; the full archival database is not included”

Do not describe it as:

- a “formal release,” “complete production edition,” or fully release-accepted build;
- production-qualified for scanned-document OCR;
- Authenticode-signed or backed by a trusted Windows publisher;
- currently supporting automatic updates;
- including the full archival database; or
- fully accepted across clean Windows 10/11 machines.

## User guidance

Use the technical prerelease only with project-supplied, verifiable assets and preferably in an isolated evaluation environment with synthetic or properly authorized data. Real-case use must follow the approval, outbound-data, and host boundaries in [Security and Privacy](security-and-privacy.en.md). Scanned material must not enter OCR until production qualification is complete.
