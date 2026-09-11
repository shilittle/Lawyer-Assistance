"""Build one independently staged diagnostic EXE/PDB pair.

This helper keeps release optimisation while requiring the repository's
``[profile.diagnostic]`` profile (``inherits = "release"`` and ``debug = 2``)
to be present.  Cargo builds into a fresh temporary target directory, then
the matching executable and PDB are copied together to a new output
directory.  The manifest binds revision, dirty state, tool versions,
dependency snapshot, binary hashes, and the PE CodeView/PDB GUID+age pair.

The script never reuses a PDB from another build and never records the PDB's
embedded source path.  It does not modify Cargo profiles or product source.
No network is used: Cargo is invoked with ``--locked --offline``.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = "x86_64-pc-windows-msvc"
DEFAULT_TOOLCHAIN = "1.98.0"
DEFAULT_PACKAGE = "lawyer-assistance-server"
DEFAULT_BINARY = "lawyer-assistance"
PROFILE = "diagnostic"
PROFILE_DEBUG = 2
MAX_COMMAND_SECONDS = 1_800
HEX_REVISION = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class DiagnosticBuildError(RuntimeError):
    def __init__(self, category: str, *, blocked: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.blocked = blocked


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_name(value: str, label: str) -> str:
    if not SAFE_NAME.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def run_capture(
    command: Sequence[str],
    cwd: Path,
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = MAX_COMMAND_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DiagnosticBuildError("command_timeout", blocked=True) from error
    except FileNotFoundError as error:
        raise DiagnosticBuildError("required_tool_missing", blocked=True) from error
    except OSError as error:
        raise DiagnosticBuildError("command_unavailable", blocked=True) from error


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def run_logged(
    command: Sequence[str],
    cwd: Path,
    log_dir: Path,
    log_name: str,
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = MAX_COMMAND_SECONDS,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a bounded command and persist its complete result before returning."""

    started_at = utc_now()
    started = time.monotonic()
    record: dict[str, Any] = {
        "command": [str(item) for item in command],
        "started_at": started_at,
    }
    execute = runner or subprocess.run
    try:
        completed = execute(
            list(command),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        record.update({"finished_at": utc_now(), "elapsed_seconds": round(time.monotonic() - started, 3), "exit_code": None, "error_category": "command_timeout", "stdout": "", "stderr": ""})
        write_json(log_dir / log_name, record)
        raise DiagnosticBuildError("command_timeout", blocked=True)
    except FileNotFoundError:
        record.update({"finished_at": utc_now(), "elapsed_seconds": round(time.monotonic() - started, 3), "exit_code": None, "error_category": "required_tool_missing", "stdout": "", "stderr": ""})
        write_json(log_dir / log_name, record)
        raise DiagnosticBuildError("required_tool_missing", blocked=True)
    except OSError:
        record.update({"finished_at": utc_now(), "elapsed_seconds": round(time.monotonic() - started, 3), "exit_code": None, "error_category": "command_unavailable", "stdout": "", "stderr": ""})
        write_json(log_dir / log_name, record)
        raise DiagnosticBuildError("command_unavailable", blocked=True)
    record.update(
        {
            "finished_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "exit_code": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
        }
    )
    write_json(log_dir / log_name, record)
    return completed


def parse_cargo_version(text: str) -> str | None:
    match = re.search(r"\bcargo\s+(\d+\.\d+\.\d+)\b", text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def parse_rustc_version(text: str) -> dict[str, str | None]:
    release = re.search(r"^release:\s*(\S+)", text, flags=re.MULTILINE)
    host = re.search(r"^host:\s*(\S+)", text, flags=re.MULTILINE)
    return {
        "release": release.group(1) if release else None,
        "host": host.group(1) if host else None,
    }


def git_identity(root: Path) -> dict[str, Any]:
    revision_probe = run_capture(("git", "rev-parse", "HEAD"), root, timeout=30)
    revision = revision_probe.stdout.strip().splitlines()[0] if revision_probe.stdout.strip() else ""
    if revision_probe.returncode != 0 or not HEX_REVISION.fullmatch(revision):
        raise DiagnosticBuildError("git_revision_unavailable", blocked=True)
    status_probe = run_capture(("git", "status", "--porcelain", "--untracked-files=all"), root, timeout=30)
    if status_probe.returncode != 0:
        raise DiagnosticBuildError("git_status_unavailable", blocked=True)
    # Do not persist status output: it can contain user paths.  A boolean is
    # enough to bind the source state used by this diagnostic build.
    return {"revision": revision, "dirty": bool(status_probe.stdout.strip())}


def verify_profile_contract(root: Path) -> dict[str, Any]:
    path = root / "Cargo.toml"
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except FileNotFoundError as error:
        raise DiagnosticBuildError("cargo_manifest_missing", blocked=True) from error
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DiagnosticBuildError("cargo_manifest_invalid") from error
    profile = document.get("profile", {}).get(PROFILE)
    if not isinstance(profile, dict):
        raise DiagnosticBuildError("diagnostic_profile_missing", blocked=True)
    if profile.get("inherits") != "release":
        raise DiagnosticBuildError("diagnostic_profile_must_inherit_release")
    # Cargo accepts the equivalent spellings ``2``, ``true`` and ``"full"``
    # for a fully debuggable artifact.  Normalize them to the numeric value in
    # the manifest so the profile contract stays deterministic while matching
    # the repository's TOML representation.
    debug_value = profile.get("debug")
    if debug_value is True or debug_value == PROFILE_DEBUG or debug_value == "full":
        normalized_debug = PROFILE_DEBUG
    else:
        raise DiagnosticBuildError("diagnostic_profile_debug_must_be_2")
    return {
        "name": PROFILE,
        "inherits": "release",
        "debug": normalized_debug,
        "optimisation_source": "release",
    }


def _read_exact(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise DiagnosticBuildError("binary_debug_record_truncated")
    return data[offset : offset + size]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack("<H", _read_exact(data, offset, 2))[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack("<I", _read_exact(data, offset, 4))[0]


def _rva_to_file_offset(data: bytes, rva: int, section_offset: int, section_count: int, optional_end: int) -> int:
    for index in range(section_count):
        offset = section_offset + index * 40
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_pointer = _u32(data, offset + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            file_offset = raw_pointer + (rva - virtual_address)
            if file_offset <= len(data):
                return file_offset
    # Debug data can be addressed by a raw pointer even when malformed section
    # metadata makes the RVA unavailable.  This fallback stays within bytes
    # and still fails closed if no valid directory is found.
    if optional_end <= rva < len(data):
        return rva
    raise DiagnosticBuildError("pe_debug_rva_unmapped")


def pe_codeview_identity(path: Path) -> dict[str, Any]:
    """Extract only the CodeView GUID and age; discard its embedded PDB path."""

    data = path.read_bytes()
    if _read_exact(data, 0, 2) != b"MZ":
        raise DiagnosticBuildError("exe_not_pe")
    pe_offset = _u32(data, 0x3C)
    if _read_exact(data, pe_offset, 4) != b"PE\0\0":
        raise DiagnosticBuildError("exe_pe_header_invalid")
    file_header = pe_offset + 4
    section_count = _u16(data, file_header + 2)
    optional_size = _u16(data, file_header + 16)
    optional = file_header + 20
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B):
        raise DiagnosticBuildError("exe_optional_header_invalid")
    data_directory = optional + (96 if magic == 0x10B else 112)
    debug_directory = data_directory + 6 * 8
    debug_rva = _u32(data, debug_directory)
    debug_size = _u32(data, debug_directory + 4)
    if not debug_rva or debug_size < 28:
        raise DiagnosticBuildError("exe_codeview_missing")
    section_offset = optional + optional_size
    debug_offset = _rva_to_file_offset(data, debug_rva, section_offset, section_count, section_offset)
    for index in range(debug_size // 28):
        entry = debug_offset + index * 28
        if entry + 28 > len(data):
            break
        debug_type = _u32(data, entry + 12)
        size_of_data = _u32(data, entry + 16)
        raw_pointer = _u32(data, entry + 24)
        if debug_type != 2 or size_of_data < 24 or raw_pointer + size_of_data > len(data):
            continue
        codeview = _read_exact(data, raw_pointer, size_of_data)
        if codeview[:4] != b"RSDS":
            continue
        guid = codeview[4:20].hex()
        age = _u32(codeview, 20)
        return {"signature": "RSDS", "guid": guid, "age": age}
    raise DiagnosticBuildError("exe_codeview_missing")


def _pdb_streams(data: bytes) -> list[bytes | None]:
    signature = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    if not data.startswith(signature):
        raise DiagnosticBuildError("pdb_msf_signature_invalid")
    block_size = _u32(data, 32)
    directory_bytes = _u32(data, 44)
    block_map_address = _u32(data, 52)
    if block_size < 512 or block_size > 65_536 or directory_bytes > 64 * 1024 * 1024:
        raise DiagnosticBuildError("pdb_directory_invalid")
    num_directory_blocks = (directory_bytes + block_size - 1) // block_size
    block_map_offset = block_map_address * block_size
    block_numbers = [
        _u32(data, block_map_offset + index * 4) for index in range(num_directory_blocks)
    ]
    directory = bytearray()
    for block_number in block_numbers:
        start = block_number * block_size
        directory.extend(_read_exact(data, start, block_size))
    directory = directory[:directory_bytes]
    if len(directory) < 4:
        raise DiagnosticBuildError("pdb_directory_invalid")
    stream_count = _u32(directory, 0)
    if stream_count > 65_536:
        raise DiagnosticBuildError("pdb_stream_count_invalid")
    sizes_offset = 4
    if sizes_offset + stream_count * 4 > len(directory):
        raise DiagnosticBuildError("pdb_stream_sizes_truncated")
    sizes = [_u32(directory, sizes_offset + index * 4) for index in range(stream_count)]
    block_lists_offset = sizes_offset + stream_count * 4
    streams: list[bytes | None] = []
    for size in sizes:
        if size == 0xFFFFFFFF:
            streams.append(None)
            continue
        block_count = (size + block_size - 1) // block_size
        end = block_lists_offset + block_count * 4
        if end > len(directory):
            raise DiagnosticBuildError("pdb_stream_blocks_truncated")
        stream_data = bytearray()
        for block_index in range(block_count):
            block_number = _u32(directory, block_lists_offset + block_index * 4)
            stream_data.extend(_read_exact(data, block_number * block_size, block_size))
        streams.append(bytes(stream_data[:size]))
        block_lists_offset = end
    return streams


def pdb_info_identity(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    streams = _pdb_streams(data)
    if len(streams) <= 1 or streams[1] is None or len(streams[1]) < 28:
        raise DiagnosticBuildError("pdb_info_stream_missing")
    info = streams[1]
    return {
        "guid": info[12:28].hex(),
        "age": _u32(info, 8),
    }


def pair_debug_identities(exe: Path, pdb: Path) -> dict[str, Any]:
    codeview = pe_codeview_identity(exe)
    pdb_info = pdb_info_identity(pdb)
    matched = codeview.get("guid") == pdb_info.get("guid") and codeview.get("age") == pdb_info.get("age")
    return {
        "codeview": codeview,
        "pdb_info": pdb_info,
        "matched": matched,
        "assertion": "PE CodeView RSDS GUID and age equal PDB Info GUID and age",
    }


def locate_artifacts(target_dir: Path, target: str, binary: str) -> tuple[Path, Path]:
    profile_dir = target_dir / target / PROFILE
    exe = profile_dir / f"{binary}.exe"
    if not exe.is_file():
        raise DiagnosticBuildError("diagnostic_exe_missing")
    # MSVC/rustc emits underscores for the PDB basename even when Cargo's
    # binary name contains hyphens (e.g. lawyer-assistance.exe versus
    # lawyer_assistance.pdb).  Accept only this deterministic alternate stem,
    # never an arbitrary neighbouring PDB.
    pdb_candidates = [profile_dir / f"{binary}.pdb"]
    underscored = binary.replace("-", "_")
    if underscored != binary:
        pdb_candidates.append(profile_dir / f"{underscored}.pdb")
    pdb = next((candidate for candidate in pdb_candidates if candidate.is_file()), None)
    if pdb is None:
        raise DiagnosticBuildError("diagnostic_pdb_missing")
    return exe, pdb


def diagnostic_build_command(toolchain: str, target: str, package: str, binary: str) -> list[str]:
    """Return the fixed, serial Cargo invocation used for diagnostic builds."""

    return [
        "cargo",
        f"+{toolchain}",
        "build",
        "--locked",
        "--offline",
        "--target",
        target,
        "--profile",
        PROFILE,
        "-j",
        "1",
        "-p",
        package,
        "--bin",
        binary,
    ]


def diagnostic_metadata_command(toolchain: str, target: str) -> list[str]:
    """Return a locked, offline dependency query scoped to the build target."""

    return [
        "cargo",
        f"+{toolchain}",
        "metadata",
        "--locked",
        "--offline",
        "--filter-platform",
        target,
        "--format-version",
        "1",
    ]


def _tool_versions(
    root: Path,
    toolchain: str,
    log_dir: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    cargo = run_logged(("cargo", f"+{toolchain}", "--version"), root, log_dir, "tool-cargo.log.json", timeout=60, runner=runner)
    cargo_version = parse_cargo_version((cargo.stdout or "") + "\n" + (cargo.stderr or ""))
    if cargo.returncode != 0 or cargo_version != toolchain:
        raise DiagnosticBuildError("cargo_version_mismatch")
    rustc = run_logged(("rustc", f"+{toolchain}", "-vV"), root, log_dir, "tool-rustc.log.json", timeout=60, runner=runner)
    rustc_info = parse_rustc_version((rustc.stdout or "") + "\n" + (rustc.stderr or ""))
    if rustc.returncode != 0 or rustc_info.get("release") != toolchain:
        raise DiagnosticBuildError("rustc_version_mismatch")
    return {"cargo": cargo_version, "rustc": rustc_info}


def build_diagnostic(
    root: Path,
    output: Path,
    *,
    target: str = DEFAULT_TARGET,
    target_dir: Path | None = None,
    toolchain: str = DEFAULT_TOOLCHAIN,
    package: str = DEFAULT_PACKAGE,
    binary: str = DEFAULT_BINARY,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    """Build and stage a pair; ``runner`` exists for deterministic unit tests."""

    root = root.resolve()
    output = output.resolve()
    validate_name(package, "package")
    validate_name(binary, "binary")
    if output.exists():
        raise FileExistsError(f"diagnostic output already exists: {output.name}")
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    logs.mkdir()
    started = time.monotonic()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "kind": "diagnostic-build",
        "created_at": utc_now(),
        "target": target,
        "profile": PROFILE,
        "package": package,
        "binary": binary,
        "logs": {
            "tool_cargo": "logs/tool-cargo.log.json",
            "tool_rustc": "logs/tool-rustc.log.json",
            "cargo_metadata": "logs/cargo-metadata.log.json",
            "cargo_build": "logs/cargo-build.log.json",
        },
    }
    try:
        profile = verify_profile_contract(root)
        manifest["profile"] = profile
        source = git_identity(root)
        manifest["source"] = source
        lockfile = root / "Cargo.lock"
        if not lockfile.is_file():
            raise DiagnosticBuildError("cargo_lock_missing", blocked=True)
        lock_hash = sha256_file(lockfile)
        manifest["dependency"] = {"cargo_lock_sha256": lock_hash}
        tools = _tool_versions(root, toolchain, logs, runner=runner)
        manifest["toolchain"] = tools
        cargo_runner = runner or subprocess.run
        build_target_dir = (target_dir.resolve() if target_dir is not None else root / "target").resolve()
        try:
            output.relative_to(build_target_dir)
        except ValueError:
            pass
        else:
            raise DiagnosticBuildError("target_dir_must_not_contain_output")
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = str(build_target_dir)
        metadata_command = diagnostic_metadata_command(toolchain, target)
        metadata = run_logged(
            metadata_command,
            root,
            logs,
            "cargo-metadata.log.json",
            env=env,
            timeout=MAX_COMMAND_SECONDS,
            runner=cargo_runner,
        )
        if metadata.returncode != 0:
            raise DiagnosticBuildError("cargo_metadata_failed")
        metadata_text = metadata.stdout or ""
        try:
            metadata_document = json.loads(metadata_text)
        except json.JSONDecodeError as error:
            raise DiagnosticBuildError("cargo_metadata_invalid") from error
        if not isinstance(metadata_document, dict) or not isinstance(metadata_document.get("packages"), list):
            raise DiagnosticBuildError("cargo_metadata_invalid")
        manifest["dependency"].update(
            {
                "cargo_metadata_sha256": sha256_bytes(metadata_text.encode("utf-8")),
                "package_count": len(metadata_document["packages"]),
            }
        )
        build_command = diagnostic_build_command(toolchain, target, package, binary)
        built = run_logged(
            build_command,
            root,
            logs,
            "cargo-build.log.json",
            env=env,
            timeout=MAX_COMMAND_SECONDS,
            runner=cargo_runner,
        )
        if built.returncode != 0:
            raise DiagnosticBuildError("cargo_build_failed")
        source_exe, source_pdb = locate_artifacts(build_target_dir, target, binary)
        pair = pair_debug_identities(source_exe, source_pdb)
        if not pair["matched"]:
            raise DiagnosticBuildError("exe_pdb_identity_mismatch")
        staged_exe = output / source_exe.name
        staged_pdb = output / source_pdb.name
        shutil.copyfile(source_exe, staged_exe)
        shutil.copyfile(source_pdb, staged_pdb)
        staged_pair = pair_debug_identities(staged_exe, staged_pdb)
        if not staged_pair["matched"]:
            raise DiagnosticBuildError("staged_exe_pdb_identity_mismatch")
        artifact = {
            "exe": {"file": staged_exe.name, "bytes": staged_exe.stat().st_size, "sha256": sha256_file(staged_exe)},
            "pdb": {"file": staged_pdb.name, "bytes": staged_pdb.stat().st_size, "sha256": sha256_file(staged_pdb)},
        }
        pair_id = sha256_bytes((artifact["exe"]["sha256"] + "\n" + artifact["pdb"]["sha256"]).encode("ascii"))
        manifest.update(
            {
                "status": "passed",
                "artifact": artifact,
                "debug_identity": staged_pair,
                "pair_id": pair_id,
                "pair_assertion": "staged EXE and PDB hashes and CodeView/PDB GUID+age were checked together",
            }
        )
    except DiagnosticBuildError as error:
        manifest["status"] = "blocked" if error.blocked else "failed"
        manifest["reason"] = error.category
    except OSError as error:
        # Keep a reviewable failure manifest even when an artifact/hash copy
        # or a later filesystem operation fails after source/tool metadata
        # has already been collected.  Do not persist the OS message because
        # it may contain a local path.
        manifest["status"] = "failed"
        manifest["reason"] = "diagnostic_artifact_io_failed"
        manifest["error_category"] = type(error).__name__
    manifest["elapsed_seconds"] = round(time.monotonic() - started, 3)
    manifest_path = output / "diagnostic-build.json"
    with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True, help="new directory for the matched EXE/PDB and manifest")
    parser.add_argument("--target-dir", type=Path, default=None, help="Cargo target directory; defaults to <root>/target")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--toolchain", default=DEFAULT_TOOLCHAIN)
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--bin", dest="binary", default=DEFAULT_BINARY)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        manifest = build_diagnostic(
            args.root,
            args.output,
            target=args.target,
            target_dir=args.target_dir,
            toolchain=args.toolchain,
            package=args.package,
            binary=args.binary,
        )
    except (ValueError, FileExistsError, OSError) as error:
        manifest = {"schema_version": 1, "status": "failed", "kind": "diagnostic-build", "reason": type(error).__name__}
    print(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))
    return 0 if manifest.get("status") == "passed" else 2 if manifest.get("status") == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
