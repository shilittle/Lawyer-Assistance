"""Build the unsigned Windows portable package for the Web server.

The package is intentionally small and boring: the Rust Web server, the
standalone public/privacy MCP binary, the provided runtime legal database,
the notices/licence files, current operating documentation, safe MCP examples,
and ``wscript`` launchers.  No user workspace, credentials, Tauri bundle,
updater metadata, or installer is ever copied.

Use ``--skip-build`` when release binaries already exist.  This is useful for
local packaging checks and keeps the packaging step independent from a slow
Rust build.  The script does not publish artifacts or sign them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = "x86_64-pc-windows-msvc"
SERVER_BINARY = "lawyer-assistance.exe"
MCP_BINARY = "lawyer-assistance-mcp.exe"
RUNTIME_FILES = (
    Path("legal_core.sqlite"),
    Path("DATA_SOURCES.md"),
    Path("LICENSE.txt"),
    Path("THIRD_PARTY_NOTICES.txt"),
)
PORTABLE_FILES = (
    # Root documentation linked by README.md/README.en.md.
    (Path("README.md"), Path("README.md")),
    (Path("README.en.md"), Path("README.en.md")),
    (Path("LICENSE"), Path("LICENSE")),
    (Path("CONTRIBUTING.md"), Path("CONTRIBUTING.md")),
    (Path("SECURITY.md"), Path("SECURITY.md")),
    (Path("CHANGELOG.md"), Path("CHANGELOG.md")),
    (Path("RELEASE_NOTES.md"), Path("RELEASE_NOTES.md")),
    # Current user-facing Web and MCP documentation.  The legal-corpus guide
    # intentionally remains a source guide; archival audit inputs are not
    # copied into a user package.
    (Path("docs/getting-started.md"), Path("docs/getting-started.md")),
    (Path("docs/getting-started.en.md"), Path("docs/getting-started.en.md")),
    (Path("docs/security-and-privacy.md"), Path("docs/security-and-privacy.md")),
    (Path("docs/security-and-privacy.en.md"), Path("docs/security-and-privacy.en.md")),
    (Path("docs/data/legal-corpus.md"), Path("docs/data/legal-corpus.md")),
    (Path("docs/mcp/README.md"), Path("docs/mcp/README.md")),
    (Path("docs/mcp/architecture.md"), Path("docs/mcp/architecture.md")),
    (Path("docs/mcp/compatibility-matrix.md"), Path("docs/mcp/compatibility-matrix.md")),
    (Path("docs/mcp/database-and-versioning.md"), Path("docs/mcp/database-and-versioning.md")),
    (Path("docs/mcp/development-and-testing.md"), Path("docs/mcp/development-and-testing.md")),
    (Path("docs/mcp/installation.md"), Path("docs/mcp/installation.md")),
    (Path("docs/mcp/packaging-and-migration.md"), Path("docs/mcp/packaging-and-migration.md")),
    (Path("docs/mcp/security-and-privacy.md"), Path("docs/mcp/security-and-privacy.md")),
    (Path("docs/mcp/tools.md"), Path("docs/mcp/tools.md")),
    (Path("docs/web/README.md"), Path("docs/web/README.md")),
    (Path("docs/web/redaction-quality.md"), Path("docs/web/redaction-quality.md")),
    (Path("docs/web/validation.md"), Path("docs/web/validation.md")),
    # Existing public/privacy configuration examples contain placeholders only.
    (Path("integrations/codex/config.stdio.toml"), Path("examples/mcp/codex/config.stdio.toml")),
    (
        Path("integrations/codex/config.privacy-workspace.stdio.toml"),
        Path("examples/mcp/codex/config.privacy-workspace.stdio.toml"),
    ),
    (
        Path("integrations/workbuddy/connectors/stdio.windows.json"),
        Path("examples/mcp/workbuddy/stdio.windows.json"),
    ),
    (
        Path("integrations/workbuddy/connectors/privacy-workspace/stdio.windows.json"),
        Path("examples/mcp/workbuddy/privacy-workspace.stdio.windows.json"),
    ),
)
LEGAL_DISTRIBUTION_MANIFEST = Path("data/generated/legal_core_distribution_manifest.json")
MAX_MANIFEST_FILE_BYTES = 8 * 1024 * 1024


class PackageError(RuntimeError):
    """A deterministic, user-facing packaging failure."""


@dataclass(frozen=True)
class PackagedFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PackageResult:
    archive: Path
    checksum: Path
    manifest: Path
    package_root: str
    files: tuple[PackagedFile, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise PackageError(f"unable to read {path}") from error
    return digest.hexdigest()


def workspace_version(root: Path) -> str:
    try:
        document = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        value = document["workspace"]["package"]["version"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise PackageError("workspace version could not be read") from error
    if not isinstance(value, str) or not value or any(c not in "0123456789.+-" for c in value):
        raise PackageError("workspace version is invalid")
    return value


def _run(command: list[str], root: Path) -> None:
    try:
        result = subprocess.run(command, cwd=root, check=False)
    except OSError as error:
        raise PackageError(f"command could not run: {command[0]}") from error
    if result.returncode != 0:
        raise PackageError(f"command failed ({result.returncode}): {' '.join(command)}")


def build_release_binaries(root: Path, target: str) -> None:
    """Build exactly the two binaries that belong in the portable package."""
    for package, binary in (
        ("lawyer-assistance-server", "lawyer-assistance"),
        ("legal-mcp", "lawyer-assistance-mcp"),
    ):
        _run(
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "-j",
                "1",
                "--target",
                target,
                "-p",
                package,
                "--bin",
                binary,
            ],
            root,
        )


def release_binary_path(root: Path, target: str, filename: str) -> Path:
    if not target or any(part in target for part in ("/", "\\", "..")):
        raise PackageError("target must be a plain Rust target triple")
    candidates = (
        root / "target" / target / "release" / filename,
        # A developer may have built the current Windows host without an
        # explicit --target.  Accept that Cargo layout as a convenience when
        # --skip-build is used; a fresh package build always uses the target
        # specific directory above.
        root / "target" / "release" / filename,
    )
    for path in candidates:
        if path.is_file() and not path.is_symlink():
            return path
    raise PackageError(f"release binary is missing: {candidates[0]}")


def _read_distribution_manifest(root: Path) -> dict[str, object]:
    path = root / LEGAL_DISTRIBUTION_MANIFEST
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PackageError("legal distribution manifest could not be read") from error
    if not isinstance(value, dict):
        raise PackageError("legal distribution manifest must be an object")
    return value


def verify_legal_runtime(root: Path) -> tuple[Path, dict[str, object]]:
    runtime = root / "data" / "runtime"
    database = runtime / "legal_core.sqlite"
    if not database.is_file() or database.is_symlink():
        raise PackageError(f"runtime legal database is missing: {database}")
    expected = _read_distribution_manifest(root)
    if expected.get("filename") != "legal_core.sqlite":
        raise PackageError("legal distribution manifest names an unexpected file")
    try:
        expected_size = int(expected["size_bytes"])
        expected_hash = str(expected["sha256"]).lower()
        expected_source_hash = str(expected["source_manifest_sha256"]).lower()
    except (KeyError, TypeError, ValueError) as error:
        raise PackageError("legal distribution manifest is incomplete") from error
    if len(expected_hash) != 64 or len(expected_source_hash) != 64:
        raise PackageError("legal distribution manifest has an invalid hash")
    actual_size = database.stat().st_size
    if actual_size != expected_size:
        raise PackageError(f"legal database size does not match manifest: {actual_size} != {expected_size}")
    actual_hash = sha256_file(database)
    if actual_hash != expected_hash:
        raise PackageError("legal database SHA-256 does not match distribution manifest")
    try:
        connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            row = connection.execute(
                "SELECT value FROM database_metadata WHERE key = 'source_manifest_sha256'"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise PackageError("legal database metadata could not be read") from error
    if row is None or str(row[0]).lower() != expected_source_hash:
        raise PackageError("legal database source manifest hash does not match distribution manifest")
    return database, expected


def _ensure_regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"{label} is missing or is a symlink: {path}")
    if path.stat().st_size > MAX_MANIFEST_FILE_BYTES and path.suffix.lower() != ".sqlite":
        raise PackageError(f"{label} is unexpectedly large: {path}")


def _quote_vbs(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def launcher_text() -> str:
    # WScript.Shell.Run with window style 0 is used instead of cmd.exe or a
    # PowerShell console.  The data directory remains under LOCALAPPDATA so a
    # portable package never writes user state beside the executable.
    return '''Option Explicit

Dim fso, shell, root, exe, legalDb, dataDir, command
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fso.GetParentFolderName(WScript.ScriptFullName)
exe = fso.BuildPath(root, "lawyer-assistance.exe")
legalDb = fso.BuildPath(root, "data\\runtime\\legal_core.sqlite")
dataDir = fso.BuildPath(shell.ExpandEnvironmentStrings("%LOCALAPPDATA%"), "LawyerAssistanceWeb")
If Not fso.FileExists(exe) Then
  MsgBox "lawyer-assistance.exe is missing from the portable package.", 16, "Lawyer Assistance"
  WScript.Quit 1
End If
command = _
  """" & exe & """" & " serve --open --port 8877 --data-dir " & _
  """" & dataDir & """" & " --legal-db " & """" & legalDb & """"
shell.CurrentDirectory = root
shell.Run command, 0, False
'''


def stop_launcher_text() -> str:
    """Return a no-console launcher for the authenticated ``stop`` command."""
    return '''Option Explicit

Dim fso, shell, root, exe, command
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fso.GetParentFolderName(WScript.ScriptFullName)
exe = fso.BuildPath(root, "lawyer-assistance.exe")
If Not fso.FileExists(exe) Then
  MsgBox "lawyer-assistance.exe is missing from the portable package.", 16, "Lawyer Assistance"
  WScript.Quit 1
End If
command = """" & exe & """ stop"
shell.CurrentDirectory = root
shell.Run command, 0, False
'''


def _copy_payload(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(source, destination)
    except OSError as error:
        raise PackageError(f"unable to copy package resource: {source}") from error


def _manifest_entries(stage: Path) -> tuple[PackagedFile, ...]:
    entries: list[PackagedFile] = []
    for path in sorted(stage.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == "MANIFEST.sha256":
            continue
        if path.is_symlink():
            raise PackageError(f"portable package contains a symlink: {relative}")
        entries.append(PackagedFile(relative, path.stat().st_size, sha256_file(path)))
    return tuple(entries)


def _write_embedded_manifest(stage: Path, entries: tuple[PackagedFile, ...]) -> Path:
    path = stage / "MANIFEST.sha256"
    lines = [
        "# SHA-256 and byte length for every portable package file except this manifest",
        *(f"{entry.sha256}  {entry.size:>12}  {entry.path}" for entry in entries),
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return path


def _write_json_manifest(stage: Path, version: str, expected_legal: dict[str, object], entries: tuple[PackagedFile, ...]) -> Path:
    path = stage / "portable.manifest.json"
    payload = {
        "format_version": 1,
        "product": "Lawyer Assistance",
        "version": version,
        "artifact": "unsigned-windows-portable",
        "target": DEFAULT_TARGET,
        "signed": False,
        "tauri": False,
        "updater": False,
        "legal_database": {
            "filename": "data/runtime/legal_core.sqlite",
            "size_bytes": expected_legal["size_bytes"],
            "sha256": expected_legal["sha256"],
            "source_manifest_sha256": expected_legal["source_manifest_sha256"],
        },
        "files": [{"path": item.path, "size": item.size, "sha256": item.sha256} for item in entries],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def _zip_tree(stage: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for path in sorted(stage.rglob("*")):
            if not path.is_file():
                continue
            relative = PurePosixPath(stage.name, path.relative_to(stage).as_posix())
            info = zipfile.ZipInfo(str(relative), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            with path.open("rb") as source, package.open(info, "w") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)


def build_package(
    root: Path = ROOT,
    output_dir: Path | None = None,
    *,
    target: str = DEFAULT_TARGET,
    skip_build: bool = False,
) -> PackageResult:
    root = root.resolve()
    output_dir = (output_dir or root / "dist").resolve()
    if target != DEFAULT_TARGET:
        raise PackageError(f"portable packaging only supports {DEFAULT_TARGET}")
    version = workspace_version(root)
    if not skip_build:
        build_release_binaries(root, target)
    server = release_binary_path(root, target, SERVER_BINARY)
    mcp = release_binary_path(root, target, MCP_BINARY)
    legal, expected_legal = verify_legal_runtime(root)
    for relative in RUNTIME_FILES[1:]:
        _ensure_regular_file(root / "data" / "runtime" / relative, f"runtime resource {relative}")
    for source, _destination in PORTABLE_FILES:
        _ensure_regular_file(root / source, f"portable document or example {source}")

    package_root = f"Lawyer-Assistance_{version}_windows-x86_64-portable"
    archive = output_dir / f"{package_root}.zip"
    checksum = output_dir / f"{package_root}.zip.sha256"
    manifest = output_dir / f"{package_root}.manifest.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in (archive, checksum, manifest):
        if path.exists():
            path.unlink()
    with tempfile.TemporaryDirectory(prefix="lawyer-assistance-portable-", dir=output_dir) as temporary:
        stage = Path(temporary) / package_root
        stage.mkdir()
        _copy_payload(server, stage / SERVER_BINARY)
        _copy_payload(mcp, stage / MCP_BINARY)
        for source, destination in PORTABLE_FILES:
            _copy_payload(root / source, stage / destination)
        for relative in RUNTIME_FILES:
            _copy_payload(root / "data" / "runtime" / relative, stage / "data" / "runtime" / relative)
        (stage / "Lawyer-Assistance.vbs").write_text(launcher_text(), encoding="utf-8", newline="\r\n")
        (stage / "Stop-Lawyer-Assistance.vbs").write_text(
            stop_launcher_text(), encoding="utf-8", newline="\r\n"
        )
        entries = _manifest_entries(stage)
        _write_embedded_manifest(stage, entries)
        _write_json_manifest(stage, version, expected_legal, entries)
        # The JSON manifest itself is part of the hash manifest.  Rebuild the
        # hash list after writing it; the JSON's own files list intentionally
        # excludes its self-referential hash, while MANIFEST.sha256 covers it.
        entries = _manifest_entries(stage)
        _write_embedded_manifest(stage, entries)
        _zip_tree(stage, archive)
    archive_hash = sha256_file(archive)
    checksum.write_text(f"{archive_hash}  {archive.name}\n", encoding="ascii", newline="\n")
    # Keep the external JSON manifest beside the archive without adding another
    # non-deterministic file to the zip.  It is generated from the embedded
    # manifest below so callers can inspect the same byte inventory.
    manifest_payload = {
        "format_version": 1,
        "product": "Lawyer Assistance",
        "version": version,
        "artifact": "unsigned-windows-portable",
        "target": target,
        "signed": False,
        "tauri": False,
        "updater": False,
        "archive": archive.name,
        "archive_sha256": archive_hash,
        "legal_database": {
            "filename": "data/runtime/legal_core.sqlite",
            "size_bytes": expected_legal["size_bytes"],
            "sha256": expected_legal["sha256"],
            "source_manifest_sha256": expected_legal["source_manifest_sha256"],
        },
        "files": [
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256}
            for entry in entries
        ],
    }
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return PackageResult(archive, checksum, manifest, package_root, entries)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--skip-build", action="store_true", help="use existing release binaries")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_package(
            args.root,
            args.output_dir,
            target=args.target,
            skip_build=args.skip_build,
        )
    except PackageError as error:
        print(f"portable packaging failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "archive": str(result.archive),
                "checksum": str(result.checksum),
                "manifest": str(result.manifest),
                "files": len(result.files),
                "package_root": result.package_root,
                "signed": False,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
