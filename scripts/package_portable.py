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
from datetime import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse
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
CASE_RUNTIME_FILES = (
    Path("judicial_cases.sqlite"),
    Path("CASE_DATA_SOURCES.md"),
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
    (Path("docs/web/retest-1.2.1.md"), Path("docs/web/retest-1.2.1.md")),
    (Path("docs/web/ai-upgrade.md"), Path("docs/web/ai-upgrade.md")),
    (Path("docs/web/ai-validation.md"), Path("docs/web/ai-validation.md")),
    (Path("docs/web/audit-1.2.1.md"), Path("docs/web/audit-1.2.1.md")),
    (Path("docs/web/audit-1.2.1-contracts.md"), Path("docs/web/audit-1.2.1-contracts.md")),
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
CASE_DISTRIBUTION_MANIFEST = Path("data/generated/judicial_cases_manifest.json")
CASE_MANIFEST_DESTINATION = Path("judicial_cases_manifest.json")
MAX_MANIFEST_FILE_BYTES = 8 * 1024 * 1024
MAX_AI_BINARY_FILE_BYTES = 128 * 1024 * 1024
AI_TOOL_FILES = (
    "typst.exe", "pdfium.dll", "fonts/SourceHanSerifSC-Regular.otf",
    "fonts/SourceHanSerifSC-Bold.otf", "Typst-LICENSE.txt",
    "SourceHanSerif-LICENSE.txt", "pdfium-LICENSE.txt",
    "document-runtime.json", "pdfium.version.json",
)


def verify_ai_runtime(root: Path, corpus: Path | None = None) -> tuple[Path, ...]:
    tools = root / "output/runtime-tools"
    if _has_symlink_component(tools, root) or not tools.is_dir():
        raise PackageError(f"AI runtime resource directory is missing or is a symlink: {tools}")
    paths = tuple(tools / name for name in AI_TOOL_FILES)
    for item in paths:
        _ensure_regular_file(
            item, "AI runtime resource", tools,
            max_bytes=MAX_AI_BINARY_FILE_BYTES if item.suffix.lower() in {".exe", ".dll", ".otf"} else MAX_MANIFEST_FILE_BYTES,
        )
        if (
            _has_symlink_component(item, tools)
            or not item.is_file()
            or item.is_symlink()
            or item.stat().st_size == 0
        ):
            raise PackageError(f"required AI runtime resource missing: {item}")
    try:
        document = json.loads((tools / "document-runtime.json").read_text(encoding="utf-8"))
        expected_paths = {"typst.exe", "fonts/SourceHanSerifSC-Regular.otf", "fonts/SourceHanSerifSC-Bold.otf"}
        if {entry["path"] for entry in document} != expected_paths:
            raise PackageError("document runtime manifest file set invalid")
        for entry in document:
            relative = _safe_relative_path(entry["path"], "document runtime manifest")
            runtime_file = tools / Path(*relative.parts)
            _ensure_regular_file(runtime_file, "document runtime resource", tools, max_bytes=MAX_AI_BINARY_FILE_BYTES)
            if sha256_file(runtime_file) != entry["sha256"]:
                raise PackageError("document runtime checksum mismatch")
        pdfium = json.loads((tools / "pdfium.version.json").read_text(encoding="utf-8"))
        if sha256_file(tools / "pdfium.dll") != pdfium["dll_sha256"]:
            raise PackageError("Pdfium runtime checksum mismatch")
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise PackageError("AI runtime manifest invalid") from error
    layout = resolve_corpus(root, corpus)
    index = layout.runtime / "legal_search_index.sqlite"
    index_manifest = layout.generated / "legal_search_index_manifest.json"
    if (
        _has_symlink_component(index, layout.runtime)
        or _has_symlink_component(index_manifest, layout.generated)
        or not index.is_file()
        or index.is_symlink()
        or not index_manifest.is_file()
        or index_manifest.is_symlink()
    ):
        raise PackageError("derived legal search index missing; run scripts/build_search_index.py")
    connection = sqlite3.connect(f"file:{index.resolve().as_posix()}?mode=ro", uri=True)
    try:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise PackageError("derived legal search index integrity check failed")
        metadata = dict(connection.execute("SELECT key,value FROM search_index_metadata"))
    finally:
        connection.close()
    distribution_manifest = layout.generated / "legal_core_distribution_manifest.json"
    _ensure_regular_file(distribution_manifest, "legal distribution manifest", layout.generated)
    expected = json.loads(distribution_manifest.read_text(encoding="utf-8"))
    if metadata.get("source_manifest_sha256") != expected["source_manifest_sha256"]:
        raise PackageError("derived legal search index belongs to a different legal database")
    return paths


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
    source_commit: str = "unknown"
    label: str | None = None


@dataclass(frozen=True)
class CorpusLayout:
    runtime: Path
    generated: Path


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Return whether ``path`` or a child component is a symlink."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def _safe_relative_path(value: object, description: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PackageError(f"{description} contains an invalid path")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        raise PackageError(f"{description} contains a dangerous path")
    return path


def resolve_corpus(root: Path, corpus: Path | None = None) -> CorpusLayout:
    """Resolve an independent corpus copy without changing the source tree."""

    root = root.resolve()
    selected_input = corpus or root / "data"
    if selected_input.is_symlink():
        raise PackageError("--corpus must name an existing independent directory")
    selected = selected_input.resolve()
    if selected == root or not selected.is_dir() or selected.is_symlink():
        raise PackageError("--corpus must name an existing independent directory")
    nested_runtime = selected / "runtime"
    nested_generated = selected / "generated"
    if nested_runtime.is_dir():
        runtime = nested_runtime
        generated = nested_generated
    elif (selected / "data" / "runtime").is_dir():
        runtime = selected / "data" / "runtime"
        generated = selected / "data" / "generated"
    else:
        runtime = selected
        generated = selected
    for path in (runtime, generated):
        if path.is_symlink() or _has_symlink_component(path, selected):
            raise PackageError(f"corpus path is a symlink: {path}")
    return CorpusLayout(runtime, generated)


def source_commit(root: Path) -> str:
    try:
        value = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, stderr=subprocess.STDOUT
        ).decode("ascii", "replace").strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else "unknown"


def validate_label(label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", label):
        raise PackageError("label must contain only letters, digits, '.', '_' or '-'")
    return label


def default_label(root: Path) -> str:
    revision = source_commit(root)
    suffix = revision[:12] if revision != "unknown" else "unknown"
    return f"{datetime.now().strftime('%Y%m%d')}-{suffix}"


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


def verify_default_server_binary(server: Path) -> None:
    """Ensure the package server was built without the QA-only fault feature.

    The hidden ``document-worker-fault`` subcommand exists only in the
    test-feature binary.  Asking the production binary to parse that unknown
    command stops in Clap before the server or a worker can start.  This also
    catches a ``--skip-build`` invocation that accidentally points at the
    fault-feature executable.
    """

    try:
        result = subprocess.run(
            [str(server), "document-worker-fault"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except subprocess.TimeoutExpired as error:
        raise PackageError("release server fault-feature probe timed out") from error
    except OSError as error:
        raise PackageError("release server fault-feature probe could not run") from error
    output = result.stdout or ""
    lowered = output.lower()
    if result.returncode != 2 or "unrecognized subcommand" not in lowered or "document-worker-fault" not in lowered:
        raise PackageError("release server binary exposes the document-worker-fault test feature")


def _read_distribution_manifest(root: Path, corpus: Path | None = None) -> dict[str, object]:
    path = resolve_corpus(root, corpus).generated / LEGAL_DISTRIBUTION_MANIFEST.name
    if path.is_symlink() or not path.is_file():
        raise PackageError(f"legal distribution manifest is missing or is a symlink: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PackageError("legal distribution manifest could not be read") from error
    if not isinstance(value, dict):
        raise PackageError("legal distribution manifest must be an object")
    return value


def verify_legal_runtime(root: Path, corpus: Path | None = None) -> tuple[Path, dict[str, object]]:
    layout = resolve_corpus(root, corpus)
    runtime = layout.runtime
    database = runtime / "legal_core.sqlite"
    if not database.is_file() or database.is_symlink():
        raise PackageError(f"runtime legal database is missing: {database}")
    expected = _read_distribution_manifest(root, corpus)
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


_CASE_COLUMNS = (
    "case_id",
    "title",
    "case_type",
    "guiding_number",
    "reference_number",
    "keywords_json",
    "publication_date",
    "court",
    "case_number",
    "status",
    "source_url",
    "search_text",
    "key_points_json",
    "basic_facts",
    "judgment_result",
    "reasoning",
    "related_laws_json",
    "full_text",
    "fetched_at",
    "content_sha256",
)
_CASE_SCHEMA_VERSION = "1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _case_manifest_path(root: Path, corpus: Path | None = None) -> Path:
    path = resolve_corpus(root, corpus).generated / CASE_DISTRIBUTION_MANIFEST.name
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"judicial case distribution manifest is missing: {path}")
    return path


def _case_manifest_schema_version(manifest: dict[str, object]) -> str:
    value: object = manifest.get("schema_version")
    if value != _CASE_SCHEMA_VERSION:
        raise PackageError("judicial case manifest has an unsupported schema version")
    return _CASE_SCHEMA_VERSION


def _case_manifest_count(manifest: dict[str, object]) -> tuple[int, dict[str, int]]:
    row_count = manifest.get("row_count")
    if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count <= 0:
        raise PackageError("judicial case manifest has no valid row_count")
    raw_counts = manifest.get("counts")
    if not isinstance(raw_counts, dict) or set(("guiding", "reference", "total")) - raw_counts.keys():
        raise PackageError("judicial case manifest counts are incomplete")
    counts: dict[str, int] = {}
    for key in ("guiding", "reference", "typical", "total"):
        value = raw_counts.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PackageError("judicial case manifest has an invalid case count")
        counts[key] = value
    if counts["total"] != row_count or counts["guiding"] + counts["reference"] + counts["typical"] != row_count:
        raise PackageError("judicial case manifest counts do not add up to row_count")
    if counts["guiding"] <= 0:
        raise PackageError("judicial case manifest must contain at least one guiding case")
    return row_count, {key: counts[key] for key in ("guiding", "reference", "typical") if key != "typical" or "typical" in raw_counts}


def _case_manifest_source(manifest: dict[str, object]) -> list[dict[str, object]]:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise PackageError("judicial case manifest sources are missing")
    sources: list[dict[str, object]] = []
    for item in raw_sources:
        if not isinstance(item, dict):
            raise PackageError("judicial case manifest source entry is invalid")
        url = item.get("url")
        if not isinstance(url, str):
            raise PackageError("judicial case manifest source URL is missing")
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise PackageError("judicial case manifest source URL is malformed") from error
        if (
            parsed.scheme != "https"
            or hostname not in {"court.gov.cn", "www.court.gov.cn", "gongbao.court.gov.cn", "rmfyalk.court.gov.cn", "ipc.court.gov.cn", "hnlyzy.hncourt.gov.cn"}
            or parsed.username
            or parsed.password
            or port is not None
        ):
            raise PackageError("judicial case manifest source URL is not an official Supreme People's Court URL")
        source_hash = item.get("sha256")
        if not isinstance(source_hash, str) or not _HEX_64.fullmatch(source_hash):
            raise PackageError("judicial case manifest source entry has an invalid hash")
        fetched_at = item.get("fetched_at")
        if not isinstance(fetched_at, str) or not fetched_at.strip():
            raise PackageError("judicial case manifest source entry has no fetched_at")
        sources.append(item)
    return sources


def _case_manifest_hash(manifest: dict[str, object], key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise PackageError(f"judicial case manifest has an invalid {key}")
    return value.lower()


def _case_schema_tables(manifest: dict[str, object]) -> tuple[str, ...]:
    schema = manifest.get("schema")
    if not isinstance(schema, dict):
        return ()
    tables = schema.get("tables")
    if tables is None:
        return ()
    if not isinstance(tables, list) or any(not isinstance(table, str) or not table for table in tables):
        raise PackageError("judicial case manifest schema tables are invalid")
    return tuple(tables)


def verify_case_runtime(root: Path, corpus: Path | None = None) -> tuple[Path, dict[str, object]]:
    """Validate the official Supreme People's Court case sidecar before packaging."""
    layout = resolve_corpus(root, corpus)
    runtime = layout.runtime
    database = runtime / "judicial_cases.sqlite"
    if not database.is_file() or database.is_symlink():
        raise PackageError(f"runtime judicial case database is missing: {database}")
    manifest_path = _case_manifest_path(root, corpus)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PackageError("judicial case distribution manifest could not be read") from error
    if not isinstance(manifest, dict):
        raise PackageError("judicial case distribution manifest must be an object")
    if manifest.get("filename") != "judicial_cases.sqlite":
        raise PackageError("judicial case distribution manifest names an unexpected file")
    try:
        expected_size = manifest["size_bytes"]
    except KeyError as error:
        raise PackageError("judicial case manifest is missing size_bytes") from error
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size <= 0:
        raise PackageError("judicial case manifest has an invalid size_bytes")
    expected_hash = _case_manifest_hash(manifest, "sha256")
    schema_version = _case_manifest_schema_version(manifest)
    expected_count, expected_categories = _case_manifest_count(manifest)
    sources = _case_manifest_source(manifest)
    source_hash = manifest.get("source_manifest_sha256")
    if not isinstance(source_hash, str) or not _HEX_64.fullmatch(source_hash):
        raise PackageError("judicial case manifest has an invalid source_manifest_sha256")
    coverage_status = manifest.get("coverage_status")
    if not isinstance(coverage_status, str) or not coverage_status.strip():
        raise PackageError("judicial case manifest coverage_status is missing")
    if coverage_status == "limited_build" or "synthetic" in coverage_status.lower():
        raise PackageError("judicial case manifest is a limited or synthetic build")
    for key in ("dataset_name", "dataset_version"):
        value = manifest.get(key)
        if isinstance(value, str) and "synthetic" in value.lower():
            raise PackageError("judicial case manifest is a synthetic build")
    actual_size = database.stat().st_size
    if actual_size != expected_size:
        raise PackageError(f"judicial case database size does not match manifest: {actual_size} != {expected_size}")
    if sha256_file(database) != expected_hash:
        raise PackageError("judicial case database SHA-256 does not match manifest")
    try:
        connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or str(integrity[0]).lower() != "ok":
                raise PackageError("judicial case database integrity check failed")
            metadata_exists = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_metadata')"
            ).fetchone()
            if not metadata_exists or not bool(metadata_exists[0]):
                raise PackageError("judicial case database metadata table is missing")
            metadata = dict(connection.execute("SELECT key, value FROM database_metadata").fetchall())
            if str(metadata.get("schema_version", "")) != schema_version:
                raise PackageError("judicial case database schema does not match manifest")
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if user_version is None or int(user_version[0]) != int(schema_version):
                raise PackageError("judicial case database PRAGMA user_version does not match manifest")
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(judicial_cases)").fetchall()
            }
            if set(_CASE_COLUMNS) - columns:
                raise PackageError("judicial case database schema is missing required columns")
            for table in _case_schema_tables(manifest):
                exists = connection.execute(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
                    (table,),
                ).fetchone()
                if not exists or not bool(exists[0]):
                    raise PackageError(f"judicial case database schema is missing table: {table}")
            actual_count = int(connection.execute("SELECT COUNT(*) FROM judicial_cases").fetchone()[0])
            if actual_count != expected_count:
                raise PackageError(f"judicial case count does not match manifest: {actual_count} != {expected_count}")
            for category, expected in expected_categories.items():
                actual = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM judicial_cases WHERE case_type = ?",
                        (category,),
                    ).fetchone()[0]
                )
                if actual != expected:
                    raise PackageError(
                        f"judicial case {category} count does not match manifest: {actual} != {expected}"
                    )
            db_source_hash = metadata.get("source_manifest_sha256")
            if db_source_hash is None or str(db_source_hash).lower() != str(source_hash).lower():
                raise PackageError("judicial case source manifest hash does not match database metadata")
        finally:
            connection.close()
    except PackageError:
        raise
    except (OSError, sqlite3.Error, ValueError) as error:
        raise PackageError("judicial case database schema or count could not be read") from error
    manifest = dict(manifest)
    manifest["sources"] = sources
    manifest["schema_version"] = schema_version
    manifest["counts"] = dict(manifest["counts"])
    return database, manifest


def _case_portable_identity(expected_case: dict[str, object]) -> dict[str, object]:
    return {
        "filename": "data/runtime/judicial_cases.sqlite",
        "manifest": "data/runtime/judicial_cases_manifest.json",
        "size_bytes": expected_case["size_bytes"],
        "sha256": expected_case["sha256"],
        "schema_version": expected_case["schema_version"],
        "row_count": expected_case["row_count"],
        "counts": expected_case["counts"],
        "coverage_status": expected_case["coverage_status"],
        "sources": expected_case["sources"],
        "source_manifest_sha256": expected_case["source_manifest_sha256"],
    }


def _ensure_regular_file(path: Path, label: str, boundary: Path | None = None, *, max_bytes: int = MAX_MANIFEST_FILE_BYTES) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or (boundary is not None and _has_symlink_component(path, boundary))
    ):
        raise PackageError(f"{label} is missing or is a symlink: {path}")
    if path.stat().st_size > max_bytes and path.suffix.lower() != ".sqlite":
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


def _write_json_manifest(
    stage: Path,
    version: str,
    source_revision: str,
    label: str | None,
    expected_legal: dict[str, object],
    expected_case: dict[str, object],
    entries: tuple[PackagedFile, ...],
) -> Path:
    path = stage / "portable.manifest.json"
    payload = {
        "format_version": 1,
        "product": "Lawyer Assistance",
        "version": version,
        "candidate": "1.2.1",
        "source_commit": source_revision,
        "label": label,
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
        "judicial_cases_database": _case_portable_identity(expected_case),
        "files": [{"path": item.path, "size": item.size, "sha256": item.sha256} for item in entries],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def _zip_tree(stage: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as package:
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
    label: str | None = None,
    corpus: Path | None = None,
) -> PackageResult:
    root = root.resolve()
    output_dir = (output_dir or root / "dist").resolve()
    if target != DEFAULT_TARGET:
        raise PackageError(f"portable packaging only supports {DEFAULT_TARGET}")
    version = workspace_version(root)
    selected_label = validate_label(label) if label else None
    revision = source_commit(root)
    corpus_layout = resolve_corpus(root, corpus)
    package_suffix = f"_{selected_label}" if selected_label else ""
    package_root = f"Lawyer-Assistance_{version}_windows-x86_64-portable{package_suffix}"
    archive = output_dir / f"{package_root}.zip"
    checksum = output_dir / f"{package_root}.zip.sha256"
    manifest = output_dir / f"{package_root}.manifest.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in (archive, checksum, manifest):
        if path.exists() or path.is_symlink():
            raise PackageError(f"refusing to overwrite existing artifact: {path}")
    if not skip_build:
        build_release_binaries(root, target)
    server = release_binary_path(root, target, SERVER_BINARY)
    verify_default_server_binary(server)
    mcp = release_binary_path(root, target, MCP_BINARY)
    legal, expected_legal = verify_legal_runtime(root, corpus)
    _case_database, expected_case = verify_case_runtime(root, corpus)
    ai_tools = verify_ai_runtime(root, corpus)
    for relative in RUNTIME_FILES[1:]:
        _ensure_regular_file(
            corpus_layout.runtime / relative,
            f"runtime resource {relative}",
            corpus_layout.runtime,
        )
    for relative in CASE_RUNTIME_FILES[1:]:
        _ensure_regular_file(
            corpus_layout.runtime / relative,
            f"runtime case resource {relative}",
            corpus_layout.runtime,
        )
    _ensure_regular_file(
        corpus_layout.generated / CASE_DISTRIBUTION_MANIFEST.name,
        "judicial case distribution manifest",
        corpus_layout.generated,
    )
    for source, _destination in PORTABLE_FILES:
        _ensure_regular_file(root / source, f"portable document or example {source}", root)
    with tempfile.TemporaryDirectory(prefix="lawyer-assistance-portable-", dir=output_dir) as temporary:
        stage = Path(temporary) / package_root
        stage.mkdir()
        _copy_payload(server, stage / SERVER_BINARY)
        _copy_payload(mcp, stage / MCP_BINARY)
        for resource in ai_tools:
            _copy_payload(resource, stage / "tools" / resource.relative_to(root / "output/runtime-tools"))
        _copy_payload(corpus_layout.runtime / "legal_search_index.sqlite", stage / "data/runtime/legal_search_index.sqlite")
        _copy_payload(corpus_layout.generated / "legal_search_index_manifest.json", stage / "data/runtime/legal_search_index_manifest.json")
        for source, destination in PORTABLE_FILES:
            _copy_payload(root / source, stage / destination)
        for relative in RUNTIME_FILES:
            _copy_payload(corpus_layout.runtime / relative, stage / "data" / "runtime" / relative)
        for relative in CASE_RUNTIME_FILES:
            _copy_payload(corpus_layout.runtime / relative, stage / "data" / "runtime" / relative)
        _copy_payload(
            corpus_layout.generated / CASE_DISTRIBUTION_MANIFEST.name,
            stage / "data" / "runtime" / CASE_MANIFEST_DESTINATION,
        )
        (stage / "Lawyer-Assistance.vbs").write_text(launcher_text(), encoding="utf-8", newline="\r\n")
        (stage / "Stop-Lawyer-Assistance.vbs").write_text(
            stop_launcher_text(), encoding="utf-8", newline="\r\n"
        )
        entries = _manifest_entries(stage)
        _write_embedded_manifest(stage, entries)
        _write_json_manifest(
            stage,
            version,
            revision,
            selected_label,
            expected_legal,
            expected_case,
            entries,
        )
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
        "candidate": "1.2.1",
        "source_commit": revision,
        "label": selected_label,
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
        "judicial_cases_database": _case_portable_identity(expected_case),
        "files": [
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256}
            for entry in entries
        ],
    }
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return PackageResult(archive, checksum, manifest, package_root, entries, revision, selected_label)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--label", default=None, help="safe artifact label, e.g. 20260911-01cf195")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="independent corpus directory (data/runtime plus data/generated, or a flat corpus root)",
    )
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
            label=args.label,
            corpus=args.corpus,
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
                "source_commit": result.source_commit,
                "label": result.label,
                "signed": False,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
