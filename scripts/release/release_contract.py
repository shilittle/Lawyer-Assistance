"""Canonical v0.4.0 repository and release-contract validation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib
from typing import Any, NoReturn


FORMAL_VERSION = "0.4.0"
FORMAL_APP_TAG = "v0.4.0"
FORMAL_MINERU_TAG = "mineru-components-v0.4.0"
REPOSITORY = {
    "owner": "shilittle",
    "name": "Lawyer-Assistance",
    "httpsUrl": "https://github.com/shilittle/Lawyer-Assistance.git",
}
WORKSPACE_PACKAGES = [
    "assistant",
    "citations",
    "database",
    "diagrams",
    "domain",
    "file-ingest",
    "lawyer-assistance-desktop",
    "legal-mcp",
    "legal-services",
    "material-processing",
    "privacy",
    "providers",
    "retrieval",
]
VERSION_SOURCES = [
    {"path": "package.json", "kind": "json", "key": "version"},
    {"path": "apps/desktop/package.json", "kind": "json", "key": "version"},
    {
        "path": "apps/desktop/src-tauri/tauri.conf.json",
        "kind": "json",
        "key": "version",
    },
    {"path": "Cargo.toml", "kind": "toml", "key": "workspace.package.version"},
    {
        "path": "crates/assistant/Cargo.toml",
        "kind": "toml",
        "key": "package.version",
    },
    {
        "path": "crates/legal-mcp/Cargo.toml",
        "kind": "toml",
        "key": "package.version",
    },
]
CURRENT_DOCS = [
    {"path": "README.md", "versionMarkerTemplate": "当前版本：`{version}`"},
    {
        "path": "README.en.md",
        "versionMarkerTemplate": "Current version: `{version}`",
    },
    {
        "path": "docs/README.md",
        "versionMarkerTemplate": "当前版本为 `{version}`",
    },
    {
        "path": "docs/README.en.md",
        "versionMarkerTemplate": "The current version is `{version}`",
    },
    {
        "path": "docs/release-status.md",
        "versionMarkerTemplate": "当前目标版本为 `{version}`",
    },
    {
        "path": "docs/release-status.en.md",
        "versionMarkerTemplate": "The current target version is `{version}`",
    },
    {
        "path": "docs/getting-started.md",
        "versionMarkerTemplate": "`{version}` 面向 Windows x86_64",
    },
    {
        "path": "docs/getting-started.en.md",
        "versionMarkerTemplate": "`{version}` targets Windows x86_64",
    },
    {
        "path": "docs/privacy-vnext/OPERATIONS.md",
        "versionMarkerTemplate": (
            "Applies to: Lawyer Assistance `{version}` on Windows x86_64"
        ),
    },
]
APP_ASSETS = [
    "Lawyer.Assistance_0.4.0_x64-setup.exe",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sha256",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sig",
    "latest.json",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256",
    "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip",
    "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256",
    "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz",
    "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz",
    "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256",
]
MINERU_FILENAME = (
    "lawyer-assistance-mineru-0.4.0-windows-x86_64.laocrpkg.laocrparts"
)
IMMUTABLE_V031 = {
    "tagObject": "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc",
    "peeledCommit": "0970f1c614b1bec1856869c68065162339849468",
}
COMPATIBILITY_ROWS = [
    "| MCP protocol metadata | `2025-11-25` |",
    "| Public service schema | `1` |",
    "| Legal archive schema | `4` |",
    "| Legal runtime schema | `1` when present |",
    "| User database schema | `11` |",
    "| Approved session policy | v2;",
]

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class ContractLoadError(Exception):
    """The requested contract could not be parsed safely."""


class ContractError(Exception):
    """A stable, fail-closed contract validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidationResult:
    mode: str
    version: str


def _duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractLoadError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_utf8(path: Path, code: str) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ContractError(code, f"required file is unavailable: {path.name}") from error
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractError(code, f"UTF-8 BOM is not allowed: {path.name}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(code, f"required file is not UTF-8: {path.name}") from error


def _load_json_file(path: Path, code: str) -> Any:
    text = _read_utf8(path, code)
    try:
        return json.loads(text, object_pairs_hook=_duplicate_key)
    except ContractLoadError:
        raise
    except json.JSONDecodeError as error:
        raise ContractError(code, f"invalid JSON: {path.name}") from error


def load_contract(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ContractLoadError("contract file is unavailable") from error
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractLoadError("contract must be UTF-8 without BOM")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_duplicate_key)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractLoadError("contract is not canonical UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ContractLoadError("contract root must be an object")
    return value


def _fail(code: str, message: str) -> NoReturn:
    raise ContractError(code, message)


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("SCHEMA", f"{label} keys do not match the frozen schema")
    return value


def _canonical_contract(contract: dict[str, Any]) -> None:
    top = {
        "schemaVersion",
        "repository",
        "release",
        "versions",
        "workspacePackages",
        "versionSources",
        "mcpVersionProbe",
        "releaseNotes",
        "compatibilityContract",
        "currentDocs",
        "minerU",
        "appAssets",
        "immutableTags",
    }
    _closed(contract, top, "contract")
    if contract["schemaVersion"] != 1:
        _fail("SCHEMA", "schemaVersion must be 1")
    repository = _closed(contract["repository"], set(REPOSITORY), "repository")
    if repository != REPOSITORY:
        _fail("REPOSITORY", "repository identity differs from the frozen repository")
    release = _closed(
        contract["release"], {"formalVersion", "appTag", "minerUTag"}, "release"
    )
    if release != {
        "formalVersion": FORMAL_VERSION,
        "appTag": FORMAL_APP_TAG,
        "minerUTag": FORMAL_MINERU_TAG,
    }:
        _fail("FORMAL_IDENTITY", "formal version or release tag drifted")
    versions = _closed(contract["versions"], {"currentSource", "formal"}, "versions")
    current_source = _closed(
        versions["currentSource"], {"path", "kind", "key"}, "versions.currentSource"
    )
    if current_source != VERSION_SOURCES[0] or versions["formal"] != FORMAL_VERSION:
        _fail("FORMAL_IDENTITY", "version authority differs from the frozen contract")
    if contract["workspacePackages"] != WORKSPACE_PACKAGES:
        _fail("WORKSPACE_SET", "workspace package set/order must be the frozen 13")
    if contract["versionSources"] != VERSION_SOURCES:
        _fail("VERSION_SOURCES", "version source set/order drifted")

    probe = _closed(
        contract["mcpVersionProbe"],
        {
            "package",
            "binary",
            "expectedStdoutTemplate",
            "sourcePath",
            "sourceMarkers",
        },
        "mcpVersionProbe",
    )
    if probe != {
        "package": "legal-mcp",
        "binary": "lawyer-assistance-mcp",
        "expectedStdoutTemplate": "lawyer-assistance-mcp {version}",
        "sourcePath": "crates/legal-mcp/src/config.rs",
        "sourceMarkers": ['name = "lawyer-assistance-mcp"', "version,"],
    }:
        _fail("MCP_CONTRACT", "MCP version probe drifted")

    notes = _closed(contract["releaseNotes"], {"path", "titleTemplate"}, "releaseNotes")
    if notes != {
        "path": "RELEASE_NOTES.md",
        "titleTemplate": "# Lawyer Assistance {version}",
    }:
        _fail("RELEASE_NOTES", "release-notes contract drifted")
    compatibility = _closed(
        contract["compatibilityContract"],
        {"path", "heading", "versionRowTemplate", "requiredRows"},
        "compatibilityContract",
    )
    if compatibility != {
        "path": "RELEASE_NOTES.md",
        "heading": "## Compatibility contract",
        "versionRowTemplate": "| Binary release | `{version}` |",
        "requiredRows": COMPATIBILITY_ROWS,
    }:
        _fail("COMPATIBILITY", "compatibility contract drifted")
    if contract["currentDocs"] != CURRENT_DOCS:
        _fail("CURRENT_DOCS", "current-document set/order drifted")
    mineru = _closed(
        contract["minerU"], {"formalFilenameFixturePath", "formalFilename"}, "minerU"
    )
    if mineru != {
        "formalFilenameFixturePath": (
            "scripts/release/fixtures/mineru-formal-filename-v0.4.0.txt"
        ),
        "formalFilename": MINERU_FILENAME,
    }:
        _fail("MINERU_FILENAME", "formal MinerU filename contract drifted")
    if contract["appAssets"] != APP_ASSETS:
        _fail("APP_ASSETS", "App asset allowlist must be the frozen ordered 12")
    tags = _closed(contract["immutableTags"], {"v0.3.1"}, "immutableTags")
    tag = _closed(tags["v0.3.1"], {"tagObject", "peeledCommit"}, "immutableTags.v0.3.1")
    if tag != IMMUTABLE_V031:
        _fail("IMMUTABLE_TAG", "v0.3.1 immutable provenance drifted")


def _repo_path(root: Path, relative: str, code: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        _fail(code, "contract path is not a normalized repository-relative path")
    candidate = root.joinpath(*posix.parts)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            _fail(code, f"required ordinary file is unavailable: {relative}")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _fail(code, f"required file escapes the repository: {relative}")
    return resolved


def _toml(path: Path, code: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(_read_utf8(path, code))
    except tomllib.TOMLDecodeError as error:
        raise ContractError(code, f"invalid TOML: {path.name}") from error
    return value


def _key(value: Any, dotted_key: str, code: str) -> Any:
    current = value
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            _fail(code, f"missing version key: {dotted_key}")
        current = current[part]
    return current


def _source_value(root: Path, source: dict[str, str]) -> str:
    path = _repo_path(root, source["path"], "VERSION_SOURCE")
    if source["kind"] == "json":
        value = _key(_load_json_file(path, "VERSION_SOURCE"), source["key"], "VERSION_SOURCE")
    elif source["kind"] == "toml":
        value = _key(_toml(path, "VERSION_SOURCE"), source["key"], "VERSION_SOURCE")
    else:
        _fail("VERSION_SOURCE", "unsupported version source kind")
    if not isinstance(value, str):
        _fail("VERSION_SOURCE", f"version is not a string: {source['path']}")
    return value


def _validate_semver(version: str, code: str) -> re.Match[str]:
    match = _SEMVER.fullmatch(version)
    if match is None:
        _fail(code, f"invalid semantic version: {version}")
    return match


def _validate_workspace(root: Path, expected_version: str) -> None:
    root_manifest = _toml(_repo_path(root, "Cargo.toml", "WORKSPACE"), "WORKSPACE")
    members = _key(root_manifest, "workspace.members", "WORKSPACE")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        _fail("WORKSPACE", "workspace.members is invalid")
    product_names: list[str] = []
    for member in members:
        relative = PurePosixPath(member)
        manifest = _toml(
            _repo_path(root, f"{relative.as_posix()}/Cargo.toml", "WORKSPACE"),
            "WORKSPACE",
        )
        package = manifest.get("package")
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            _fail("WORKSPACE", f"workspace package metadata is invalid: {member}")
        if relative.parts[0] == "vendor":
            continue
        product_names.append(package["name"])
        declared = package.get("version")
        if declared != {"workspace": True} and declared != expected_version:
            _fail("WORKSPACE_VERSION", f"workspace manifest version drifted: {member}")
    if sorted(product_names) != sorted(WORKSPACE_PACKAGES) or len(product_names) != 13:
        _fail("WORKSPACE_SET", "Cargo workspace product packages differ from the frozen 13")

    lock = _toml(_repo_path(root, "Cargo.lock", "CARGO_LOCK"), "CARGO_LOCK")
    packages = lock.get("package")
    if not isinstance(packages, list):
        _fail("CARGO_LOCK", "Cargo.lock package list is invalid")
    for name in WORKSPACE_PACKAGES:
        matches = [
            item
            for item in packages
            if isinstance(item, dict) and item.get("name") == name and "source" not in item
        ]
        if len(matches) != 1:
            _fail("CARGO_LOCK", f"Cargo.lock must contain one local package: {name}")
        if matches[0].get("version") != expected_version:
            _fail("CARGO_LOCK_VERSION", f"Cargo.lock version drifted: {name}")


def _validate_mcp(root: Path, contract: dict[str, Any], version: str, binary: Path | None) -> None:
    probe = contract["mcpVersionProbe"]
    expected = probe["expectedStdoutTemplate"].format(version=version)
    source = _read_utf8(_repo_path(root, probe["sourcePath"], "MCP_CONTRACT"), "MCP_CONTRACT")
    for marker in probe["sourceMarkers"]:
        if source.count(marker) != 1:
            _fail("MCP_CONTRACT", "MCP source version contract is missing or ambiguous")
    if binary is None:
        return
    binary_path = binary if binary.is_absolute() else root / binary
    try:
        binary_path = binary_path.resolve(strict=True)
        if binary_path.is_symlink() or not binary_path.is_file():
            _fail("MCP_BINARY", "MCP binary is not an ordinary file")
        completed = subprocess.run(
            [str(binary_path), "--version"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContractError("MCP_BINARY", "MCP --version probe failed") from error
    if completed.returncode != 0:
        _fail("MCP_BINARY", "MCP --version returned a nonzero status")
    if completed.stderr != b"":
        _fail("MCP_STDERR", "MCP --version must emit no stderr")
    if completed.stdout not in {
        (expected + "\n").encode("utf-8"),
        (expected + "\r\n").encode("utf-8"),
    }:
        _fail("MCP_STDOUT", "MCP --version stdout is not the unique expected line")


def _validate_release_notes(root: Path, contract: dict[str, Any], version: str) -> None:
    notes_contract = contract["releaseNotes"]
    notes = _read_utf8(
        _repo_path(root, notes_contract["path"], "RELEASE_NOTES"), "RELEASE_NOTES"
    )
    lines = notes.splitlines()
    title = notes_contract["titleTemplate"].format(version=version)
    if not lines or lines[0] != title or lines.count(title) != 1:
        _fail("RELEASE_NOTES_TITLE", "Release Notes title does not match the version")
    compatibility = contract["compatibilityContract"]
    heading = compatibility["heading"]
    if lines.count(heading) != 1:
        _fail("COMPATIBILITY", "compatibility heading is missing or ambiguous")
    start = lines.index(heading) + 1
    end = next((index for index in range(start, len(lines)) if lines[index].startswith("## ")), len(lines))
    section = lines[start:end]
    version_row = compatibility["versionRowTemplate"].format(version=version)
    if section.count(version_row) != 1 or sum("| Binary release |" in line for line in section) != 1:
        _fail("COMPATIBILITY_VERSION", "compatibility binary version row drifted")
    for required in compatibility["requiredRows"]:
        count = sum(line == required or line.startswith(required) for line in section)
        if count != 1:
            _fail("COMPATIBILITY", f"compatibility row is missing or ambiguous: {required}")


def _validate_docs_and_mineru(root: Path, contract: dict[str, Any], version: str) -> None:
    for document in contract["currentDocs"]:
        text = _read_utf8(
            _repo_path(root, document["path"], "CURRENT_DOCS"), "CURRENT_DOCS"
        )
        marker = document["versionMarkerTemplate"].format(version=version)
        if text.count(marker) != 1:
            _fail("CURRENT_DOCS", f"current version marker drifted: {document['path']}")
    mineru = contract["minerU"]
    fixture = _repo_path(root, mineru["formalFilenameFixturePath"], "MINERU_FILENAME")
    expected = mineru["formalFilename"] + "\n"
    if _read_utf8(fixture, "MINERU_FILENAME") != expected:
        _fail("MINERU_FILENAME", "formal MinerU filename fixture drifted")


def validate_repository(
    root: Path,
    contract: dict[str, Any],
    mode: str,
    mcp_binary: Path | None = None,
) -> ValidationResult:
    if mode not in {"current", "formal"}:
        _fail("MODE", "mode must be current or formal")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise ContractError("ROOT", "repository root is unavailable") from error
    if not root.is_dir():
        _fail("ROOT", "repository root is not a directory")
    _canonical_contract(contract)

    current_source = contract["versions"]["currentSource"]
    current_version = _source_value(root, current_source)
    current_match = _validate_semver(current_version, "CURRENT_VERSION")
    expected_version = current_version
    if mode == "formal":
        if current_version != FORMAL_VERSION or current_match.group(4) or current_match.group(5):
            _fail("FORMAL_VERSION", "formal mode requires exact 0.4.0 without metadata")
        expected_version = FORMAL_VERSION
    for source in contract["versionSources"]:
        value = _source_value(root, source)
        _validate_semver(value, "VERSION_SOURCE")
        if value != expected_version:
            _fail("VERSION_DRIFT", f"version source drifted: {source['path']}")

    _validate_workspace(root, expected_version)
    _validate_mcp(root, contract, expected_version, mcp_binary)
    _validate_release_notes(root, contract, expected_version)
    _validate_docs_and_mineru(root, contract, expected_version)
    return ValidationResult(mode=mode, version=expected_version)
