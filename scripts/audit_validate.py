"""Run local validation gates with explicit, reviewable evidence.

The preflight phase only reads repository/resource files and asks installed
tools for versions.  It never builds, starts the service, opens a browser, or
changes repository state.  Validation commands are selected by ``--phase`` or
``--only`` and every planned check is recorded, including filtered
``not_run`` checks and checks blocked by a failed prerequisite.

The default output is ``work/retest-121`` so historical ``work/audit-repair``
evidence remains untouched.  No command in this runner contacts a network or
reads provider credentials.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Sequence


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = "x86_64-pc-windows-msvc"
SERVER_BINARY = "lawyer-assistance.exe"
MCP_BINARY = "lawyer-assistance-mcp.exe"

PYTHON_TEST_ROOTS = (Path("data/build"), Path("integrations"), Path("scripts"))
MANIFEST_FILES = (
    Path("data/generated/legal_core_full_manifest.json"),
    Path("data/generated/legal_core_distribution_manifest.json"),
    Path("data/generated/legal_core_runtime_report.json"),
    Path("data/generated/judicial_cases_manifest.json"),
)
RUNTIME_FILES = (
    Path("data/runtime/legal_core.sqlite"),
    Path("data/runtime/judicial_cases.sqlite"),
    Path("data/runtime/legal_search_index.sqlite"),
)
AI_RUNTIME_FILES = (
    Path("typst.exe"),
    Path("pdfium.dll"),
    Path("fonts/SourceHanSerifSC-Regular.otf"),
    Path("fonts/SourceHanSerifSC-Bold.otf"),
    Path("Typst-LICENSE.txt"),
    Path("SourceHanSerif-LICENSE.txt"),
    Path("pdfium-LICENSE.txt"),
    Path("document-runtime.json"),
    Path("pdfium.version.json"),
)
NATIVE_SCRIPTS = (
    "audit_native_smoke",
    "audit_draft_retest_native",
    "audit_editor_export_native",
    "audit_search_native",
    "audit_capacity_native",
    "audit_ai_capacity_native",
    "audit_index_equivalence",
    "audit_document_worker_native",
    "audit_context_citations_native",
    "audit_context_ranges_native",
    "audit_model_capabilities_native",
)
NATIVE_SCRIPT_CHECK_IDS = tuple(f"native-{name.removeprefix('audit_')}" for name in NATIVE_SCRIPTS)
SOURCE_MANIFEST_NAME = "source-manifest.json"
SOURCE_EXCLUDED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "output",
    "target",
    "work",
}
SOURCE_BINARY_SUFFIXES = {
    ".7z",
    ".a",
    ".bin",
    ".cab",
    ".db",
    ".dylib",
    ".dll",
    ".exe",
    ".gz",
    ".lib",
    ".msi",
    ".o",
    ".obj",
    ".p12",
    ".pdb",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".rar",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".zip",
}
SOURCE_PRIVATE_BASENAMES = {
    ".env",
    "credentials",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "secrets",
    "token",
}


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    phase: str
    command: tuple[str, ...]
    log_name: str
    requires: tuple[str, ...] = ()
    assertions: tuple[str, ...] = ("exit_code == 0",)


@dataclass(frozen=True)
class AuditContext:
    root: Path
    resources: Path
    output: Path
    server_exe: Path
    mcp_exe: Path
    target: str = DEFAULT_TARGET


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_path(value: Path, root: Path) -> Path:
    return value.resolve() if value.is_absolute() else (root / value).resolve()


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def safe_log_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "check"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_evidence_log(ctx: AuditContext, check_id: str, payload: Any) -> str:
    """Write a UTF-8 evidence log and return its output-relative path."""

    path = ctx.output / "logs" / (safe_log_name(check_id) + ".log")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
    return display_path(path, ctx.output)


def make_record(check_id: str, phase: str, kind: str, assertions: Iterable[str]) -> dict[str, Any]:
    return {
        "id": check_id,
        "phase": phase,
        "kind": kind,
        "status": "not_run",
        "assertions": list(assertions),
        "command": None,
        "log": None,
    }


def set_timing(record: dict[str, Any], started_at: str, started: float) -> None:
    record["started_at"] = started_at
    record["finished_at"] = utc_now()
    record["elapsed_seconds"] = round(time.monotonic() - started, 3)


def resolve_command(command: Sequence[str]) -> tuple[str, ...]:
    """Resolve Windows ``.cmd`` shims before CreateProcess is called.

    PowerShell resolves ``pnpm`` through its command extensions, while
    ``subprocess.run`` may reject the same bare name on Windows.  Recording
    the resolved path makes the evidence reproducible and preserves a launch
    exception when no executable can be found.
    """

    if not command:
        return ()
    first = str(command[0])
    if Path(first).is_absolute() or any(separator in first for separator in ("/", "\\")):
        return tuple(str(item) for item in command)
    resolved = shutil.which(first)
    if resolved:
        return (resolved, *(str(item) for item in command[1:]))
    return tuple(str(item) for item in command)


def run_capture(command: Sequence[str], cwd: Path) -> dict[str, Any]:
    """Run a read-only probe and retain launch exceptions as evidence."""

    started_at = utc_now()
    started = time.monotonic()
    requested_command = [str(item) for item in command]
    resolved_command = list(resolve_command(command))
    result: dict[str, Any] = {
        "command": resolved_command,
        "requested_command": requested_command,
        "started_at": started_at,
    }
    try:
        completed = subprocess.run(
            resolved_command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        result.update(
            {
                "finished_at": utc_now(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "exit_code": None,
                "launch_exception": {"type": type(error).__name__, "message": str(error)},
            }
        )
        return result
    result.update(
        {
            "finished_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "exit_code": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
        }
    )
    return result


def run_tool_check(
    check_id: str,
    command: Sequence[str],
    ctx: AuditContext,
    assertions: Sequence[str],
    parser: Callable[[str, str, int], tuple[bool, dict[str, Any]]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    record = make_record(check_id, "preflight", "tool", assertions)
    probe = run_capture(command, ctx.root)
    record.update(
        {
            "command": probe["command"],
            "requested_command": probe.get("requested_command", list(command)),
            "started_at": probe["started_at"],
            "finished_at": probe["finished_at"],
            "elapsed_seconds": probe["elapsed_seconds"],
            "exit_code": probe["exit_code"],
        }
    )
    if "launch_exception" in probe:
        missing = probe["launch_exception"].get("type") == "FileNotFoundError"
        record["status"] = "blocked" if missing else "failed"
        record["launch_exception"] = probe["launch_exception"]
        observed: dict[str, Any] = {"launch_exception": probe["launch_exception"]}
        if missing:
            record.update(
                {
                    "reason": "required_tool_missing",
                    "missing": str(command[0]),
                    "how_to_obtain": f"Install or expose {command[0]} on PATH before running this gate.",
                }
            )
    else:
        stdout = str(probe.get("stdout", ""))
        stderr = str(probe.get("stderr", ""))
        record["stdout"] = stdout
        record["stderr"] = stderr
        try:
            passed, observed = parser(stdout, stderr, int(probe["exit_code"]))
        except (TypeError, ValueError, RuntimeError) as error:
            passed = False
            observed = {"parser_exception": f"{type(error).__name__}: {error}"}
        record["status"] = "passed" if passed else "failed"
    record["observed"] = observed
    tool_entry = {
        "id": check_id,
        "command": probe["command"],
        "requested_command": probe.get("requested_command", list(command)),
        "exit_code": probe["exit_code"],
        "started_at": probe["started_at"],
        "finished_at": probe["finished_at"],
        "elapsed_seconds": probe["elapsed_seconds"],
        "status": record["status"],
        "assertions": list(assertions),
        "observed": observed,
    }
    if "launch_exception" in probe:
        tool_entry["launch_exception"] = probe["launch_exception"]
    for key in ("reason", "missing", "how_to_obtain", "affected_checks"):
        if key in record:
            tool_entry[key] = record[key]
    record["log"] = write_evidence_log(
        ctx,
        check_id,
        {"probe": probe, "record": {key: value for key, value in record.items() if key != "log"}},
    )
    tool_entry["log"] = record["log"]
    evidence.setdefault("tools", []).append(tool_entry)
    return record


def parse_node_version(stdout: str, stderr: str, exit_code: int) -> tuple[bool, dict[str, Any]]:
    text = "\n".join(part for part in (stdout, stderr) if part)
    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", text)
    version = tuple(int(item) for item in match.groups()) if match else None
    passed = exit_code == 0 and version is not None and version[0] >= 24
    return passed, {"version": ".".join(str(item) for item in version) if version else None}


def parse_pnpm_version(stdout: str, stderr: str, exit_code: int) -> tuple[bool, dict[str, Any]]:
    text = "\n".join(part for part in (stdout, stderr) if part)
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    version = tuple(int(item) for item in match.groups()) if match else None
    passed = exit_code == 0 and version is not None and version >= (11, 7, 0)
    return passed, {"version": ".".join(str(item) for item in version) if version else None}


def parse_rustc_version(stdout: str, stderr: str, exit_code: int) -> tuple[bool, dict[str, Any]]:
    text = "\n".join(part for part in (stdout, stderr) if part)
    release = re.search(r"^release:\s*(\S+)", text, re.MULTILINE)
    host = re.search(r"^host:\s*(\S+)", text, re.MULTILINE)
    observed = {"release": release.group(1) if release else None, "host": host.group(1) if host else None}
    return (
        exit_code == 0 and observed["release"] == "1.98.0" and observed["host"] == DEFAULT_TARGET,
        observed,
    )


def parse_cargo_version(stdout: str, stderr: str, exit_code: int) -> tuple[bool, dict[str, Any]]:
    text = "\n".join(part for part in (stdout, stderr) if part)
    match = re.search(r"cargo\s+(\d+\.\d+\.\d+)", text, re.IGNORECASE)
    version = match.group(1) if match else None
    return exit_code == 0 and version == "1.98.0", {"version": version}


def parse_python_version(stdout: str, stderr: str, exit_code: int) -> tuple[bool, dict[str, Any]]:
    text = "\n".join(part for part in (stdout, stderr) if part)
    match = re.search(r"Python\s+(\d+)\.(\d+)\.(\d+)", text, re.IGNORECASE)
    version = tuple(int(item) for item in match.groups()) if match else None
    passed = exit_code == 0 and version is not None and version[0] >= 3
    return passed, {"version": ".".join(str(item) for item in version) if version else None}


def find_vswhere() -> Path | None:
    candidates: list[Path] = []
    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    found = shutil.which("vswhere.exe") or shutil.which("vswhere")
    if found:
        candidates.append(Path(found))
    return next((path for path in candidates if path.is_file()), None)


def find_msvc_cl(installation: Path | None) -> Path | None:
    candidates: list[Path] = []
    for name in ("cl.exe", "cl"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    if installation:
        candidates.extend(sorted(installation.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"), reverse=True))
    return next((path for path in candidates if path.is_file()), None)


def find_windows_sdk() -> tuple[Path | None, Path | None]:
    roots: list[Path] = []
    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value) / "Windows Kits" / "10")
    rc_candidates: list[Path] = []
    include_candidates: list[Path] = []
    for root in roots:
        rc_candidates.extend(root.glob("bin/*/x64/rc.exe"))
        include_candidates.extend(root.glob("Include/*"))
    rc = next((path for path in sorted(rc_candidates, reverse=True) if path.is_file()), None)
    include = next((path for path in sorted(include_candidates, reverse=True) if path.is_dir()), None)
    if rc is None:
        found = shutil.which("rc.exe") or shutil.which("rc")
        if found:
            rc = Path(found)
    return rc, include


def find_browsers() -> dict[str, Path]:
    roots = [
        Path(value)
        for value in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA"))
        if value
    ]
    candidates = {
        "chrome": tuple(
            root / relative
            for root in roots
            for relative in (
                Path("Google/Chrome/Application/chrome.exe"),
                Path("Google/Chrome SxS/Application/chrome.exe"),
            )
        ),
        "edge": tuple(root / "Microsoft/Edge/Application/msedge.exe" for root in roots),
    }
    found: dict[str, Path] = {}
    for name, paths in candidates.items():
        path = next((candidate for candidate in paths if candidate.is_file()), None)
        if path is None:
            executable = shutil.which("chrome.exe" if name == "chrome" else "msedge.exe")
            if executable:
                path = Path(executable)
        if path is not None:
            found[name] = path.resolve()
    return found


def hash_entry(
    path: Path,
    root: Path,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "path": display_path(path, root),
        "absolute_path": str(path),
        "required": True,
        "status": "failed",
    }
    if path.is_symlink():
        entry["reason"] = "symlink_not_allowed"
        return entry
    if not path.is_file():
        entry["reason"] = "missing"
        return entry
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        entry["reason"] = f"read_error:{type(error).__name__}:{error}"
        return entry
    failures: list[str] = []
    if size <= 0:
        failures.append("empty")
    if expected_size is not None and size != expected_size:
        failures.append(f"size:{size}!={expected_size}")
    if expected_sha256 is not None and digest.lower() != expected_sha256.lower():
        failures.append(f"sha256:{digest}!={expected_sha256}")
    entry.update({"size_bytes": size, "sha256": digest})
    entry["status"] = "passed" if not failures else "failed"
    if failures:
        entry["failures"] = failures
    if expected_sha256 is not None:
        entry["expected_sha256"] = expected_sha256
    if expected_size is not None:
        entry["expected_size_bytes"] = expected_size
    return entry


def parse_json_bytes(path: Path) -> tuple[Any | None, str | None, str | None]:
    try:
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        return json.loads(payload.decode("utf-8")), digest, None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, None, f"{type(error).__name__}: {error}"


def run_git_listing(command: Sequence[str], cwd: Path) -> dict[str, Any]:
    """Run a NUL-delimited Git listing while retaining raw output metadata."""

    started_at = utc_now()
    started = time.monotonic()
    requested_command = [str(item) for item in command]
    resolved_command = list(resolve_command(command))
    result: dict[str, Any] = {
        "command": resolved_command,
        "requested_command": requested_command,
        "started_at": started_at,
    }
    try:
        completed = subprocess.run(
            resolved_command,
            cwd=cwd,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        result.update(
            {
                "finished_at": utc_now(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "exit_code": None,
                "launch_exception": {"type": type(error).__name__, "message": str(error)},
            }
        )
        return result
    stdout = completed.stdout if isinstance(completed.stdout, bytes) else bytes(completed.stdout or "", "utf-8")
    stderr = completed.stderr if isinstance(completed.stderr, bytes) else str(completed.stderr or "").encode("utf-8", "replace")
    result.update(
        {
            "finished_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "exit_code": completed.returncode,
            "stdout_bytes": stdout,
            "stdout_bytes_count": len(stdout),
            "stderr": stderr.decode("utf-8", "replace"),
        }
    )
    return result


def public_git_probe(probe: dict[str, Any]) -> dict[str, Any]:
    """Remove raw NUL output before a probe is embedded in JSON evidence."""

    return {key: value for key, value in probe.items() if key != "stdout_bytes"}


def parse_git_listing(probe: dict[str, Any]) -> tuple[list[str], str | None]:
    if "launch_exception" in probe:
        return [], f"launch_exception:{probe['launch_exception']}"
    if probe.get("exit_code") != 0:
        return [], f"exit_code:{probe.get('exit_code')}:{probe.get('stderr', '').strip()}"
    raw = probe.get("stdout_bytes", b"")
    if not isinstance(raw, bytes):
        return [], "stdout_not_bytes"
    paths: list[str] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            path = item.decode("utf-8")
        except UnicodeDecodeError as error:
            return [], f"path_decode:{type(error).__name__}:{error}"
        paths.append(path)
    return paths, None


def source_exclusion_reason(relative: PurePosixPath, ctx: AuditContext) -> str | None:
    """Return a reason before reading a non-source or sensitive path."""

    parts = tuple(part.lower() for part in relative.parts)
    if any(part in SOURCE_EXCLUDED_DIRECTORIES for part in parts):
        return "generated_or_build_directory"
    try:
        output_relative = PurePosixPath(ctx.output.resolve().relative_to(ctx.root.resolve()).as_posix())
    except ValueError:
        output_relative = None
    if ctx.output.resolve() == ctx.root.resolve() and relative == PurePosixPath(SOURCE_MANIFEST_NAME):
        return "audit_output"
    if output_relative and (
        relative == output_relative
        or output_relative in relative.parents
    ):
        return "audit_output"
    basename = relative.name.lower()
    if basename.startswith(".env") or basename in SOURCE_PRIVATE_BASENAMES:
        return "private_material"
    if relative.suffix.lower() in SOURCE_BINARY_SUFFIXES:
        return "binary_or_build_artifact"
    return None


def hash_source_entry(path: Path, relative: PurePosixPath, tracked: bool | None) -> dict[str, Any]:
    """Hash source bytes exactly as stored, preserving CRLF/LF differences."""

    entry: dict[str, Any] = {
        "path": relative.as_posix(),
        "tracked": tracked,
        "status": "failed",
    }
    try:
        if path.is_symlink():
            entry["error"] = {"type": "SymlinkNotAllowed", "message": "source symlinks are not hashed"}
            return entry
        if not path.is_file():
            entry["error"] = {"type": "FileNotFoundError", "message": "source file is missing or not a regular file"}
            return entry
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        entry["error"] = {"type": type(error).__name__, "message": str(error)}
        return entry
    entry.update({"size_bytes": size, "sha256": digest, "status": "passed"})
    return entry


def source_summary_sha256(entries: Sequence[dict[str, Any]]) -> str:
    """Hash a deterministic path/status/size/byte-digest ledger."""

    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: str(item.get("path", ""))):
        canonical = {
            "path": entry.get("path"),
            "tracked": entry.get("tracked"),
            "status": entry.get("status"),
            "size_bytes": entry.get("size_bytes"),
            "sha256": entry.get("sha256"),
            "error": entry.get("error"),
        }
        digest.update(json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def source_manifest_record(ctx: AuditContext) -> dict[str, Any]:
    """Build the source-byte manifest from Git's tracked/nonignored list."""

    canonical_command = ("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    cached_command = ("git", "ls-files", "-z", "--cached")
    canonical_probe = run_git_listing(canonical_command, ctx.root)
    cached_probe = run_git_listing(cached_command, ctx.root)
    paths, canonical_error = parse_git_listing(canonical_probe)
    tracked_paths, cached_error = parse_git_listing(cached_probe)
    tracked_keys = {PurePosixPath(item.replace("\\", "/")).as_posix() for item in tracked_paths}
    failures: list[str] = []
    if canonical_error:
        failures.append(f"canonical_listing:{canonical_error}")
    if cached_error:
        failures.append(f"cached_listing:{cached_error}")
    entries: list[dict[str, Any]] = []
    excluded_counts: dict[str, int] = {}
    seen: set[str] = set()
    normalized_listed_paths = {
        PurePosixPath(item.replace("\\", "/")).as_posix()
        for item in paths
        if item
    }
    untracked_count = sum(item not in tracked_keys for item in normalized_listed_paths)
    if not canonical_error and not cached_error:
        for raw_path in paths:
            normalized = raw_path.replace("\\", "/")
            try:
                relative = PurePosixPath(normalized)
                if not normalized or relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                    raise ValueError("path must be a normalized relative path")
                relative_key = relative.as_posix()
                if relative_key in seen:
                    failures.append(f"duplicate_path:{relative_key}")
                    continue
                seen.add(relative_key)
            except ValueError as error:
                failures.append(f"invalid_path:{raw_path}:{error}")
                continue
            exclusion = source_exclusion_reason(relative, ctx)
            if exclusion:
                excluded_counts[exclusion] = excluded_counts.get(exclusion, 0) + 1
                continue
            entry = hash_source_entry(ctx.root / Path(*relative.parts), relative, relative_key in tracked_keys)
            entries.append(entry)
            if entry.get("status") != "passed":
                failures.append(f"read:{relative_key}:{entry.get('error')}")
    entries.sort(key=lambda item: str(item["path"]))
    summary_hash = source_summary_sha256(entries)
    status = "blocked" if any("launch_exception" in failure for failure in failures) else ("failed" if failures else "passed")
    artifact_path = ctx.output / SOURCE_MANIFEST_NAME
    payload: dict[str, Any] = {
        "schema_version": 1,
        "status": status,
        "summary_algorithm": "sha256(canonical JSON ledger per source entry, sorted by path)",
        "summary_sha256": summary_hash,
        "git_list_command": list(canonical_command),
        "tracked_list_command": list(cached_command),
        "listed_count": len(paths),
        "included_count": len(entries),
        "untracked_count": untracked_count,
        "included_untracked_count": sum(entry.get("tracked") is False for entry in entries),
        "excluded_counts": dict(sorted(excluded_counts.items())),
        "files": entries,
    }
    if failures:
        payload["failures"] = failures
    artifact_error: str | None = None
    try:
        write_json(artifact_path, payload)
        artifact = hash_entry(artifact_path, ctx.output)
    except OSError as error:
        artifact_error = f"{type(error).__name__}: {error}"
        artifact = {
            "path": SOURCE_MANIFEST_NAME,
            "absolute_path": str(artifact_path),
            "required": True,
            "status": "failed",
            "reason": "write_error",
        }
    if artifact_error or artifact.get("status") != "passed":
        if artifact_error is None:
            artifact_error = f"artifact_hash:{artifact.get('reason', artifact.get('failures'))}"
        failures.append(f"artifact:{artifact_error}")
        status = "failed"
        payload["status"] = status
        payload["failures"] = failures
        try:
            write_json(artifact_path, payload)
            artifact = hash_entry(artifact_path, ctx.output)
        except OSError:
            pass
    return {
        "status": status,
        "artifact": artifact,
        "summary_sha256": summary_hash,
        "summary_algorithm": payload["summary_algorithm"],
        "listed_count": len(paths),
        "included_count": len(entries),
        "untracked_count": payload["untracked_count"],
        "included_untracked_count": payload["included_untracked_count"],
        "excluded_counts": payload["excluded_counts"],
        "files": entries,
        "commands": [public_git_probe(canonical_probe), public_git_probe(cached_probe)],
        "failures": failures,
    }


def check_commit(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:commit",
        "preflight",
        "environment",
        (
            "HEAD resolves to a full commit hash",
            "repository identity is recorded",
            "all tracked and nonignored source bytes are bound by a raw hash/size manifest",
        ),
    )
    source_manifest = source_manifest_record(ctx)
    evidence["source_manifest"] = source_manifest
    if not (ctx.root / ".git").exists():
        record.update(
            {
                "status": "failed",
                "reason": "git_metadata_missing",
                "source_manifest": source_manifest,
            }
        )
        evidence["commit"] = {
            "status": "failed",
            "reason": "git_metadata_missing",
            "source_manifest": source_manifest,
        }
        return record
    probe = run_capture(("git", "rev-parse", "HEAD"), ctx.root)
    record.update(
        {
            "command": probe["command"],
            "started_at": probe["started_at"],
            "finished_at": probe["finished_at"],
            "elapsed_seconds": probe["elapsed_seconds"],
            "exit_code": probe["exit_code"],
        }
    )
    if "launch_exception" in probe:
        missing = probe["launch_exception"].get("type") == "FileNotFoundError"
        record.update(
            {
                "status": "blocked" if missing else "failed",
                "launch_exception": probe["launch_exception"],
                "reason": "git_missing" if missing else "git_launch_failed",
                "source_manifest": source_manifest,
            }
        )
        if missing:
            record.update(
                {
                    "missing": "git",
                    "how_to_obtain": "Install Git or expose git.exe on PATH before running this gate.",
                }
            )
        evidence["commit"] = {
            "status": record["status"],
            "launch_exception": probe["launch_exception"],
            "reason": record["reason"],
            "source_manifest": source_manifest,
        }
        return record
    commit = str(probe.get("stdout", "")).strip()
    branch_probe = run_capture(("git", "branch", "--show-current"), ctx.root)
    dirty_probe = run_capture(("git", "status", "--porcelain", "--untracked-files=no"), ctx.root)
    record["commands"] = [probe, branch_probe, dirty_probe]
    command_launch_failures = [
        item.get("launch_exception")
        for item in (probe, branch_probe, dirty_probe)
        if "launch_exception" in item
    ]
    tracked_dirty = bool(str(dirty_probe.get("stdout", "")).strip())
    source_untracked = int(source_manifest.get("untracked_count", 0))
    valid_commit = probe["exit_code"] == 0 and bool(re.fullmatch(r"[0-9a-f]{40}", commit))
    observed = {
        "commit": commit or None,
        "branch": str(branch_probe.get("stdout", "")).strip() or None,
        "tracked_dirty": tracked_dirty,
        "untracked_source_count": source_untracked,
        "dirty": tracked_dirty or source_untracked > 0,
        "clean": valid_commit and source_manifest["status"] == "passed" and not command_launch_failures and not tracked_dirty and source_untracked == 0,
        "valid_commit": valid_commit,
        "source_manifest_status": source_manifest["status"],
    }
    valid = valid_commit
    if source_manifest["status"] == "blocked" or command_launch_failures:
        status = "blocked"
    elif not valid or source_manifest["status"] != "passed":
        status = "failed"
    else:
        status = "passed"
    record.update(
        {
            "status": status,
            "observed": observed,
            "source_manifest": source_manifest,
        }
    )
    if command_launch_failures:
        record["launch_exceptions"] = command_launch_failures
    evidence["commit"] = {"status": record["status"], **observed, "source_manifest": source_manifest}
    return record


def check_msvc(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:msvc",
        "preflight",
        "environment",
        ("MSVC cl.exe is installed", "the compiler can be located without changing the environment"),
    )
    vswhere = find_vswhere()
    installation: Path | None = None
    commands: list[dict[str, Any]] = []
    if vswhere:
        probe = run_capture(
            (
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ),
            ctx.root,
        )
        commands.append(probe)
        if probe.get("exit_code") == 0:
            values = str(probe.get("stdout", "")).strip().splitlines()
            if values and Path(values[0].strip()).is_dir():
                installation = Path(values[0].strip())
    compiler = find_msvc_cl(installation)
    if compiler is None:
        record.update({"status": "failed", "reason": "cl.exe_not_found", "commands": commands})
        evidence["msvc"] = {"status": "failed", "commands": commands}
        return record
    compiler_probe = run_capture((str(compiler), "/Bv"), ctx.root)
    commands.append(compiler_probe)
    compiler_output = "\n".join((str(compiler_probe.get("stdout", "")), str(compiler_probe.get("stderr", ""))))
    identified = "Microsoft" in compiler_output and "C/C++" in compiler_output
    observed = {
        "compiler": hash_entry(compiler, ctx.root),
        "installation": str(installation) if installation else None,
        "identified_as_msvc": identified,
    }
    record.update({"status": "passed" if identified and "launch_exception" not in compiler_probe else "failed", "commands": commands, "observed": observed})
    evidence["msvc"] = {"status": record["status"], "commands": commands, **observed}
    return record


def check_sdk(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:sdk",
        "preflight",
        "environment",
        ("Windows SDK rc.exe is installed", "a Windows SDK include directory is present"),
    )
    rc, include = find_windows_sdk()
    observed = {"rc": hash_entry(rc, ctx.root) if rc else None, "include": str(include) if include else None}
    passed = rc is not None and include is not None
    record.update({"status": "passed" if passed else "failed", "observed": observed})
    if not passed:
        record["reason"] = "windows_sdk_not_found"
    evidence["sdk"] = {"status": record["status"], **observed}
    return record


def check_browser(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:browser",
        "preflight",
        "environment",
        ("at least one supported local browser executable is present", "browser discovery does not launch a browser"),
    )
    browsers = {name: hash_entry(path, ctx.root) for name, path in find_browsers().items()}
    passed = bool(browsers) and all(entry.get("status") == "passed" for entry in browsers.values())
    record.update({"status": "passed" if passed else "failed", "observed": browsers})
    if not passed:
        record["reason"] = "chrome_or_edge_not_found"
    evidence["browsers"] = {"status": record["status"], "executables": browsers}
    return record


def check_manifests(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:manifests",
        "preflight",
        "resource",
        (
            "manifest bytes are hashed without newline normalization",
            "archival manifest hash agrees with distribution and runtime evidence",
            "case manifest is present and parseable",
        ),
    )
    entries: list[dict[str, Any]] = []
    payloads: dict[str, Any] = {}
    hashes: dict[str, str] = {}
    failures: list[str] = []
    for relative in MANIFEST_FILES:
        path = ctx.root / relative
        entry = hash_entry(path, ctx.root)
        entries.append(entry)
        if entry["status"] != "passed":
            failures.append(f"{relative.as_posix()}:{entry.get('reason', entry.get('failures'))}")
            continue
        payload, digest, error = parse_json_bytes(path)
        if error or not isinstance(payload, dict) or digest is None:
            failures.append(f"{relative.as_posix()}:invalid_json:{error or 'object_required'}")
            continue
        payloads[relative.as_posix()] = payload
        hashes[relative.as_posix()] = digest
    full_key = "data/generated/legal_core_full_manifest.json"
    distribution_key = "data/generated/legal_core_distribution_manifest.json"
    report_key = "data/generated/legal_core_runtime_report.json"
    case_key = "data/generated/judicial_cases_manifest.json"
    full_hash = hashes.get(full_key)
    distribution = payloads.get(distribution_key)
    report = payloads.get(report_key)
    case_manifest = payloads.get(case_key)
    if full_hash and isinstance(distribution, dict):
        if distribution.get("archival_manifest_sha256") != full_hash:
            failures.append("distribution_archival_manifest_sha256_mismatch")
        if distribution.get("archival_manifest_filename") != Path(full_key).name:
            failures.append("distribution_archival_manifest_filename_mismatch")
    if full_hash and isinstance(report, dict):
        archival = report.get("archival_manifest")
        if not isinstance(archival, dict) or archival.get("sha256") != full_hash:
            failures.append("runtime_report_archival_manifest_sha256_mismatch")
    record.update({"status": "passed" if not failures else "failed", "observed": {"entries": entries}})
    if failures:
        record["failures"] = failures
    evidence["manifests"] = {
        "status": record["status"],
        "files": entries,
        "sha256": hashes,
        "archival_manifest_sha256": full_hash,
        "case_manifest_present": isinstance(case_manifest, dict),
    }
    evidence["manifest_payloads"] = payloads
    return record


def check_runtime_resources(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:runtime-resources",
        "preflight",
        "resource",
        (
            "runtime databases and AI native resources exist and are non-empty",
            "declared runtime resource hashes and sizes match their manifests",
            "AI runtime manifests bind Typst, fonts, and Pdfium bytes",
        ),
    )
    payloads = evidence.get("manifest_payloads", {})
    distribution = payloads.get("data/generated/legal_core_distribution_manifest.json", {})
    case_manifest = payloads.get("data/generated/judicial_cases_manifest.json", {})
    entries: list[dict[str, Any]] = []
    failures: list[str] = []
    runtime_expectations = {
        Path("data/runtime/legal_core.sqlite"): (distribution.get("sha256"), distribution.get("size_bytes")),
        Path("data/runtime/judicial_cases.sqlite"): (case_manifest.get("sha256"), case_manifest.get("size_bytes")),
        Path("data/runtime/legal_search_index.sqlite"): (None, None),
    }
    for relative, (expected_hash, expected_size) in runtime_expectations.items():
        entries.append(
            hash_entry(
                ctx.root / relative,
                ctx.root,
                str(expected_hash) if isinstance(expected_hash, str) else None,
                int(expected_size) if isinstance(expected_size, int) else None,
            )
        )
    for relative in AI_RUNTIME_FILES:
        entries.append(hash_entry(ctx.resources / relative, ctx.root))
    document_path = ctx.resources / "document-runtime.json"
    document_manifest, _, document_error = parse_json_bytes(document_path) if document_path.is_file() else (None, None, "missing")
    if document_error or not isinstance(document_manifest, list):
        failures.append(f"document-runtime.json:invalid:{document_error or 'list_required'}")
    elif isinstance(document_manifest, list):
        expected_paths = {
            item["path"]: item["sha256"]
            for item in document_manifest
            if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str)
        }
        for relative in (Path("typst.exe"), Path("fonts/SourceHanSerifSC-Regular.otf"), Path("fonts/SourceHanSerifSC-Bold.otf")):
            entry = next((item for item in entries if item["absolute_path"] == str(ctx.resources / relative)), None)
            expected = expected_paths.get(relative.as_posix())
            if expected is None:
                failures.append(f"document-runtime.json:missing:{relative.as_posix()}")
            elif entry and entry.get("sha256") != expected:
                failures.append(f"document-runtime.json:sha256:{relative.as_posix()}")
    pdfium_path = ctx.resources / "pdfium.version.json"
    pdfium_manifest, _, pdfium_error = parse_json_bytes(pdfium_path) if pdfium_path.is_file() else (None, None, "missing")
    if pdfium_error or not isinstance(pdfium_manifest, dict):
        failures.append(f"pdfium.version.json:invalid:{pdfium_error or 'object_required'}")
    else:
        pdfium_entry = next((item for item in entries if item["absolute_path"] == str(ctx.resources / "pdfium.dll")), None)
        if pdfium_entry and pdfium_entry.get("sha256") != pdfium_manifest.get("dll_sha256"):
            failures.append("pdfium.version.json:dll_sha256_mismatch")
    for entry in entries:
        if entry.get("status") != "passed":
            failures.append(f"{entry['path']}:{entry.get('reason', entry.get('failures'))}")
    record.update({"status": "passed" if not failures else "failed", "observed": {"entries": entries}})
    if failures:
        record["failures"] = failures
    evidence["resources"] = entries
    return record


def check_executables(ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    record = make_record(
        "preflight:release-executables",
        "preflight",
        "resource",
        ("the server and MCP release executables exist", "release executable bytes are recorded before native checks"),
    )
    entries = [hash_entry(ctx.server_exe, ctx.root), hash_entry(ctx.mcp_exe, ctx.root)]
    failures = [entry["path"] for entry in entries if entry.get("status") != "passed"]
    record.update({"status": "passed" if not failures else "failed", "observed": {"entries": entries}})
    if failures:
        record["failures"] = failures
    evidence["executables"] = entries
    return record


def run_preflight_check(check_id: str, ctx: AuditContext, evidence: dict[str, Any]) -> dict[str, Any]:
    if check_id == "preflight:rustc":
        return run_tool_check(check_id, ("rustc", "+1.98.0", "-vV"), ctx, ("release == 1.98.0", "host == x86_64-pc-windows-msvc"), parse_rustc_version, evidence)
    if check_id == "preflight:cargo":
        return run_tool_check(check_id, ("cargo", "+1.98.0", "--version"), ctx, ("cargo version == 1.98.0",), parse_cargo_version, evidence)
    if check_id == "preflight:node":
        return run_tool_check(check_id, ("node", "--version"), ctx, ("Node.js major version >= 24",), parse_node_version, evidence)
    if check_id == "preflight:pnpm":
        return run_tool_check(check_id, ("pnpm", "--version"), ctx, ("pnpm version >= 11.7.0",), parse_pnpm_version, evidence)
    if check_id == "preflight:python":
        return run_tool_check(check_id, (sys.executable, "--version"), ctx, ("Python major version >= 3",), parse_python_version, evidence)
    if check_id == "preflight:commit":
        return check_commit(ctx, evidence)
    if check_id == "preflight:msvc":
        return check_msvc(ctx, evidence)
    if check_id == "preflight:sdk":
        return check_sdk(ctx, evidence)
    if check_id == "preflight:browser":
        return check_browser(ctx, evidence)
    if check_id == "preflight:manifests":
        return check_manifests(ctx, evidence)
    if check_id == "preflight:runtime-resources":
        return check_runtime_resources(ctx, evidence)
    if check_id == "preflight:release-executables":
        return check_executables(ctx, evidence)
    raise ValueError(f"unknown preflight check: {check_id}")


def discover_python_tests(root: Path) -> tuple[str, ...]:
    """Discover all repository Python test modules, including new runner tests."""

    modules: list[str] = []
    for relative_root in PYTHON_TEST_ROOTS:
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in directory.rglob("test_*.py"):
            if path.is_file() and not path.name.startswith("__"):
                modules.append(".".join(path.relative_to(root).with_suffix("").parts))
    return tuple(sorted(set(modules)))


def build_command_specs(ctx: AuditContext, python_modules: Sequence[str]) -> tuple[CheckSpec, ...]:
    python_command = (sys.executable, "-m", "unittest", *python_modules, "-v")
    specs: list[CheckSpec] = [
        CheckSpec("rust-fmt", "rust", ("cargo", "+1.98.0", "fmt", "--all", "--check"), "rust-fmt.log", ("preflight:rustc", "preflight:cargo")),
        CheckSpec("rust-tests", "rust", ("cargo", "+1.98.0", "test", "--locked", "--offline", "--workspace", "--all-targets", "--all-features"), "rust-tests.log", ("preflight:rustc", "preflight:cargo")),
        CheckSpec("rust-clippy", "rust", ("cargo", "+1.98.0", "clippy", "--locked", "--offline", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"), "rust-clippy.log", ("preflight:rustc", "preflight:cargo")),
        CheckSpec("web-syntax-app", "web", ("node", "--check", "apps/web/app.js"), "web.log", ("preflight:node",)),
        CheckSpec("web-syntax-api", "web", ("node", "--check", "apps/web/api.js"), "web.log", ("preflight:node",)),
        CheckSpec("web-tests", "web", ("node", "--test", "apps/web/app.test.js"), "web.log", ("preflight:node",)),
        CheckSpec("editor-retest", "web", ("node", "scripts/audit_editor_retest.mjs", "--postfix", "--output", str(ctx.output / "editor-retest")), "web.log", ("preflight:node", "preflight:browser")),
        CheckSpec("contract-retest", "web", ("node", "scripts/audit_contract_retest.mjs", "--source", str(ctx.root), "--output", str(ctx.output / "contract-retest")), "web.log", ("preflight:node", "preflight:browser")),
        CheckSpec("context-ranges-web", "web", ("node", "scripts/audit_context_ranges_web.mjs", "--root", str(ctx.root), "--output", str(ctx.output / "context-ranges-web")), "web.log", ("preflight:node", "preflight:browser")),
        CheckSpec("python-tests", "python", python_command, "python.log", ("preflight:python",)),
        CheckSpec("native-pdfium", "native", ("cargo", "+1.98.0", "test", "--locked", "--offline", "-p", "file-ingest", "--lib", "--", "--ignored"), "native-pdfium.log", ("preflight:rustc", "preflight:cargo", "preflight:msvc", "preflight:sdk", "preflight:manifests", "preflight:runtime-resources")),
        CheckSpec("formal-tests", "native", ("cargo", "+1.98.0", "test", "--locked", "--offline", "-p", "citations", "-p", "retrieval", "--test", "formal_legal_core", "--", "--ignored"), "formal-tests.log", ("preflight:rustc", "preflight:cargo", "preflight:manifests", "preflight:runtime-resources")),
        CheckSpec("notices", "packaging", (sys.executable, "scripts/generate_third_party_notices.py", "--check"), "notices.log", ("preflight:python",)),
        CheckSpec("server-build", "native", ("cargo", "+1.98.0", "build", "--locked", "--offline", "--release", "-j", "1", "-p", "lawyer-assistance-server", "--bin", "lawyer-assistance"), "build.log", ("preflight:rustc", "preflight:cargo", "preflight:msvc", "preflight:sdk")),
        CheckSpec("mcp-build", "native", ("cargo", "+1.98.0", "build", "--locked", "--offline", "--release", "-j", "1", "-p", "legal-mcp", "--bin", "lawyer-assistance-mcp"), "build.log", ("preflight:rustc", "preflight:cargo", "preflight:msvc", "preflight:sdk")),
        CheckSpec("ui-regression", "native", ("node", "scripts/audit_ui_regression.mjs"), "native-suite.log", ("preflight:node", "preflight:browser")),
    ]
    for name in NATIVE_SCRIPTS:
        specs.append(
            CheckSpec(
                f"native-{name.removeprefix('audit_')}",
                "native",
                ("node", f"scripts/{name}.mjs", str(ctx.server_exe)),
                "native-suite.log",
                ("preflight:node", "preflight:browser", "preflight:release-executables", "preflight:manifests", "preflight:runtime-resources", "server-build"),
            )
        )
    return tuple(specs)


PREFLIGHT_IDS = (
    "preflight:rustc",
    "preflight:cargo",
    "preflight:node",
    "preflight:pnpm",
    "preflight:python",
    "preflight:commit",
    "preflight:msvc",
    "preflight:sdk",
    "preflight:browser",
    "preflight:manifests",
    "preflight:runtime-resources",
    "preflight:release-executables",
)


def phase_alias(value: str) -> str:
    # Stage names belong to the surrounding retest plan.  Only stage0 has a
    # one-to-one meaning here; later stages combine several subsystems and
    # must be selected with an explicit subsystem or check id.
    return {"stage0": "preflight"}.get(value.strip().lower(), value.strip().lower())


def selection_for(
    phase: str,
    only: Sequence[str],
    preflight_ids: Sequence[str],
    command_specs: Sequence[CheckSpec],
) -> set[str]:
    all_ids = set(preflight_ids) | {spec.check_id for spec in command_specs}
    aliases: dict[str, set[str]] = {"all": set(all_ids), "preflight": set(preflight_ids)}
    for candidate in ("rust", "web", "python", "native", "packaging"):
        aliases[candidate] = {spec.check_id for spec in command_specs if spec.phase == candidate}
    if only:
        selected: set[str] = set()
        for raw in only:
            for token in raw.split(","):
                token = phase_alias(token)
                if not token:
                    continue
                if token in aliases:
                    selected.update(aliases[token])
                elif token in all_ids:
                    selected.add(token)
                else:
                    raise ValueError(f"unknown check or phase for --only: {token}")
    else:
        normalized = phase_alias(phase)
        if normalized not in aliases:
            raise ValueError(f"unknown --phase: {normalized}")
        selected = set(aliases[normalized])
    by_id = {spec.check_id: spec for spec in command_specs}
    preflight_requires = {"preflight:runtime-resources": ("preflight:manifests",)}
    changed = True
    while changed:
        changed = False
        for check_id in tuple(selected):
            spec = by_id.get(check_id)
            requirements = spec.requires if spec else preflight_requires.get(check_id, ())
            for requirement in requirements:
                if requirement not in selected:
                    selected.add(requirement)
                    changed = True
    return selected


def execution_executable_entries(spec: CheckSpec, ctx: AuditContext) -> list[dict[str, Any]]:
    """Hash binaries after a command that builds or executes them.

    Native scripts receive ``server_exe`` as their positional argument, so
    their post-command record must describe that exact path.  Build records
    also capture the resulting bytes because a build may replace a binary
    whose preflight hash was captured earlier.
    """

    paths: list[Path] = []
    if spec.check_id == "server-build" or spec.check_id in NATIVE_SCRIPT_CHECK_IDS:
        paths.append(ctx.server_exe)
    if spec.check_id == "mcp-build":
        paths.append(ctx.mcp_exe)
    return [hash_entry(path, ctx.root) for path in paths]


def run_command_check(
    spec: CheckSpec,
    ctx: AuditContext,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = make_record(spec.check_id, spec.phase, "command", spec.assertions)
    log_path = ctx.output / "logs" / (safe_log_name(spec.check_id) + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    started = time.monotonic()
    resolved_command = resolve_command(spec.command)
    record["command"] = list(resolved_command)
    record["requested_command"] = list(spec.command)
    record["log"] = display_path(log_path, ctx.output)
    environment = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    environment["LAWYER_AUDIT_OUTPUT"] = str(ctx.output)
    environment["LAWYER_ASSISTANCE_PDFIUM"] = str(ctx.resources / "pdfium.dll")
    environment["LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"] = str(ctx.root / "data/runtime/legal_core.sqlite")
    try:
        with log_path.open("wb") as log:
            log.write(("$ " + subprocess.list2cmdline(list(resolved_command)) + "\n").encode("utf-8"))
            log.flush()
            completed = subprocess.run(
                list(resolved_command),
                cwd=ctx.root,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
    except OSError as error:
        record.update({"status": "failed", "exit_code": None, "launch_exception": {"type": type(error).__name__, "message": str(error)}})
    else:
        record.update({"status": "passed" if completed.returncode == 0 else "failed", "exit_code": completed.returncode})
    executable_entries = execution_executable_entries(spec, ctx)
    if executable_entries:
        record["execution_executable_hashes"] = executable_entries
        if evidence is not None:
            evidence.setdefault("execution_executables", {})[spec.check_id] = executable_entries
    set_timing(record, started_at, started)
    return record


def blocked_record(spec: CheckSpec, records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    record = make_record(spec.check_id, spec.phase, "command", spec.assertions)
    blocked_by = [requirement for requirement in spec.requires if records.get(requirement, {}).get("status") != "passed"]
    record.update(
        {
            "status": "blocked",
            "blocked_by": blocked_by,
            "reason": "prerequisite_not_passed",
            "command": list(spec.command),
            "requested_command": list(spec.command),
        }
    )
    return record


def make_report(
    ctx: AuditContext,
    phase: str,
    only: Sequence[str],
    records: Sequence[dict[str, Any]],
    selected: set[str],
    evidence: dict[str, Any],
    python_modules: Sequence[str],
    started_at: str,
    started: float,
) -> dict[str, Any]:
    counts = {status: sum(record.get("status") == status for record in records) for status in ("passed", "failed", "blocked", "not_run")}
    selected_records = [record for record in records if record.get("id") in selected]
    if any(record.get("status") == "failed" for record in selected_records):
        status = "failed"
    elif any(record.get("status") == "blocked" for record in selected_records):
        status = "blocked"
    elif any(record.get("status") == "not_run" for record in selected_records):
        status = "not_run"
    else:
        status = "passed"
    all_check_ids = {record.get("id") for record in records}
    selected_ids = [record["id"] for record in records if record.get("id") in selected]
    omitted_ids = [record["id"] for record in records if record.get("id") not in selected]
    scope = {
        "phase": phase_alias(phase),
        "only": list(only),
        "selected_check_ids": selected_ids,
        "omitted_check_ids": omitted_ids,
        "selected_count": len(selected_ids),
        "omitted_count": len(omitted_ids),
        "full_suite": selected == all_check_ids,
        "preflight_only": bool(selected_ids) and all(
            record.get("kind") != "command" for record in records if record.get("id") in selected
        ),
        "selected_status": status,
    }
    report = {
        "schema_version": 2,
        "status": status,
        "passed": status == "passed",
        "phase": phase_alias(phase),
        "only": list(only),
        "started_at": started_at,
        "finished_at": utc_now(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "root": str(ctx.root),
        "resources_root": str(ctx.resources),
        "output": str(ctx.output),
        "target": ctx.target,
        "python_tests": {"modules": list(python_modules), "count": len(python_modules)},
        "summary": {"counts": counts, "selected_count": len(selected_records), "total_checks": len(records)},
        "scope": scope,
        "evidence": evidence,
        "commit": evidence.get("commit"),
        "source_manifest": evidence.get("source_manifest"),
        "tools": evidence.get("tools", []),
        "execution_executables": evidence.get("execution_executables", {}),
        "executables": evidence.get("executables", []),
        "resources": evidence.get("resources", []),
        "manifests": evidence.get("manifests", {}),
        "preflight": [record for record in records if record.get("kind") != "command"],
        "commands": [record for record in records if record.get("kind") == "command"],
        "checks": list(records),
    }
    return report


def affected_command_checks(check_id: str, command_specs: Sequence[CheckSpec]) -> list[str]:
    """Return all command checks that depend on a missing preflight input."""

    affected = {spec.check_id for spec in command_specs if check_id in spec.requires}
    changed = True
    while changed:
        changed = False
        for spec in command_specs:
            if spec.check_id in affected:
                continue
            if any(requirement in affected for requirement in spec.requires):
                affected.add(spec.check_id)
                changed = True
    return [spec.check_id for spec in command_specs if spec.check_id in affected]


def run_audit(ctx: AuditContext, phase: str = "all", only: Sequence[str] = ()) -> dict[str, Any]:
    ctx.output.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    started = time.monotonic()
    python_modules = discover_python_tests(ctx.root)
    command_specs = build_command_specs(ctx, python_modules)
    selected = selection_for(phase, only, PREFLIGHT_IDS, command_specs)
    evidence: dict[str, Any] = {
        "commit": None,
        "source_manifest": None,
        "tools": [],
        "executables": [],
        "execution_executables": {},
        "resources": [],
        "manifests": {},
        "preflight_logs": {},
    }
    records: list[dict[str, Any]] = []
    record_map: dict[str, dict[str, Any]] = {}
    for check_id in PREFLIGHT_IDS:
        if check_id in selected:
            record = run_preflight_check(check_id, ctx, evidence)
            if record.get("status") == "blocked":
                affected = affected_command_checks(check_id, command_specs)
                if affected:
                    record["affected_checks"] = affected
                    for tool in evidence.get("tools", []):
                        if tool.get("id") == check_id:
                            tool["affected_checks"] = affected
            if record.get("log") is None:
                payload = dict(record)
                payload.pop("log", None)
                record["log"] = write_evidence_log(ctx, check_id, payload)
            evidence["preflight_logs"][check_id] = record["log"]
            for tool in evidence.get("tools", []):
                if tool.get("id") == check_id:
                    tool["log"] = record["log"]
        else:
            record = make_record(check_id, "preflight", "environment", ("preflight selected explicitly or by dependency",))
            record["reason"] = "selection_filter"
        records.append(record)
        record_map[check_id] = record
    # Manifest payloads are an internal bridge between the manifest and
    # runtime-resource checks.  The report retains their raw byte hashes and
    # assertions, rather than copying the potentially large case inventory.
    evidence.pop("manifest_payloads", None)
    for spec in command_specs:
        if spec.check_id not in selected:
            record = make_record(spec.check_id, spec.phase, "command", spec.assertions)
            record.update(
                {
                    "reason": "selection_filter",
                    "command": list(spec.command),
                    "requested_command": list(spec.command),
                }
            )
        elif any(record_map.get(requirement, {}).get("status") != "passed" for requirement in spec.requires):
            record = blocked_record(spec, record_map)
        else:
            record = run_command_check(spec, ctx, evidence)
        records.append(record)
        record_map[spec.check_id] = record
    report = make_report(ctx, phase, only, records, selected, evidence, python_modules, started_at, started)
    write_json(ctx.output / "final-command-results.json", report)
    write_json(
        ctx.output / "preflight-evidence.json",
        {
            key: report[key]
            for key in (
                "schema_version",
                "status",
                "passed",
                "phase",
                "only",
                "root",
                "resources_root",
                "output",
                "scope",
                "commit",
                "source_manifest",
                "tools",
                "executables",
                "resources",
                "manifests",
                "preflight",
                "summary",
            )
        },
    )
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="repository root; relative paths resolve here")
    parser.add_argument("--resources", type=Path, default=None, help="native runtime resource directory; defaults to <root>/output/runtime-tools")
    parser.add_argument("--output", type=Path, default=None, help="evidence directory; defaults to <root>/work/retest-121")
    parser.add_argument("--exe-dir", type=Path, default=None, help="release executable directory; defaults to <root>/target/x86_64-pc-windows-msvc/release")
    parser.add_argument("--phase", default="all", help="all, preflight, rust, web, python, native, packaging, or stage0 (preflight) alias")
    parser.add_argument("--only", action="append", default=[], help="comma-separated check ids or phase aliases; repeatable")
    parser.add_argument("--preflight-only", action="store_true", help="run only non-mutating preflight checks")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    root = arguments.root.resolve()
    resources = resolve_path(arguments.resources, root) if arguments.resources else (root / "output" / "runtime-tools").resolve()
    output = resolve_path(arguments.output, root) if arguments.output else (root / "work" / "retest-121").resolve()
    exe_dir = resolve_path(arguments.exe_dir, root) if arguments.exe_dir else (root / "target" / DEFAULT_TARGET / "release").resolve()
    phase = "preflight" if arguments.preflight_only else arguments.phase
    ctx = AuditContext(
        root=root,
        resources=resources,
        output=output,
        server_exe=exe_dir / SERVER_BINARY,
        mcp_exe=exe_dir / MCP_BINARY,
    )
    try:
        report = run_audit(ctx, phase=phase, only=arguments.only)
    except (OSError, ValueError) as error:
        print(f"audit runner failed before report generation: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": report["output"], "summary": report["summary"]}, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
