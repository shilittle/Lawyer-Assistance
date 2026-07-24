#!/usr/bin/env python3
"""Build a deterministic, unsigned local MinerU component release.

This tool packages executable/runtime/model bytes only. It never accepts case
material and never performs network access. The emitted catalog must be signed
offline with the release Minisign key before the desktop application will trust
it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Sequence


PACKAGE_MAGIC = b"LAOCPK1\0"
SCHEMA_VERSION = 1
SHARDED_CATALOG_SCHEMA_VERSION = 2
PART_SET_SCHEMA_VERSION = 1
PROTOCOL_VERSION = "la-mineru-worker-v1"
PLATFORM = "windows-x86_64"
MAX_PACKAGE_BYTES = 64 * 1024 * 1024 * 1024
# A pinned MinerU 3.4.3 + CUDA runtime has roughly forty thousand files.  Its
# canonical per-file inventory is about 7 MiB, so the old 4 MiB limit rejected
# the real production component even though every payload remained bounded.
# Keep the parser bounded, but align the package envelope with the 16 MiB
# support-manifest ceiling enforced by the OCR runtime verifier.
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 150_000
MAX_PARTS = 128
GITHUB_RELEASE_ASSET_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_PART_SIZE_BYTES = 1900 * 1024 * 1024
BUFFER_BYTES = 1024 * 1024
RESERVED_OUTPUTS = {
    "manifest.json",
    "config/lawyer-assistance-mineru.json",
}
PROVENANCE_RELATIVE = "licenses/mineru-component-provenance.json"
PROVENANCE_FILENAME = "mineru-component-provenance.json"
PROVENANCE_VERSION = "lawyer-assistance-mineru-component-provenance-v1"
MAX_PROVENANCE_BYTES = 16 * 1024 * 1024
ALLOWED_TOP_LEVEL = {"worker", "python", "runtime", "models", "licenses"}
EXECUTABLE_TOP_LEVEL = {"worker", "python", "runtime"}
WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])?$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
UNSAFE_FILE_ATTRIBUTES = 0x00000400 | 0x00001000 | 0x00040000 | 0x00400000


class PackageBuildError(RuntimeError):
    """A stable, non-sensitive component packaging rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SourceFile:
    relative_path: str
    absolute_path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class PackagePart:
    number: int
    file_name: str
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class BuildResult:
    package_path: Path
    catalog_path: Path
    package_size_bytes: int
    package_sha256: str
    manifest_sha256: str
    catalog_sha256: str
    signing_command: str
    provenance_path: Path
    provenance_sha256: str
    provenance_signing_command: str
    sharded: bool = False
    part_manifest_path: Path | None = None
    part_manifest_sha256: str | None = None
    part_paths: tuple[Path, ...] = ()


def reject(code: str, message: str) -> PackageBuildError:
    return PackageBuildError(code, message)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(BUFFER_BYTES):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_semver(value: str) -> None:
    match = SEMVER.fullmatch(value)
    if match is None:
        raise reject("version_invalid", "Component version must be strict SemVer.")
    prerelease = match.group(4)
    if prerelease and any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease.split(".")
    ):
        raise reject("version_invalid", "Numeric prerelease identifiers cannot contain leading zeros.")


def validate_identifier(value: str, label: str) -> None:
    if IDENTIFIER.fullmatch(value) is None:
        raise reject("identifier_invalid", f"{label} is not a valid release identifier.")


def normalized_relative(value: str) -> str:
    if not value or "\\" in value or value.startswith("/") or value.endswith("/"):
        raise reject("path_invalid", "Component paths must be canonical relative POSIX paths.")
    path = PurePosixPath(value)
    if str(path) != value or len(value) > 240 or len(path.parts) > 32:
        raise reject("path_invalid", "Component path is not canonical or exceeds the limit.")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise reject("path_invalid", "Component path traversal is forbidden.")
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if (
            part.endswith((".", " "))
            or ":" in part
            or stem in WINDOWS_RESERVED_STEMS
            or any(ord(character) < 32 for character in part)
        ):
            raise reject("path_invalid", "Component path is invalid on Windows.")
    if path.parts[0].casefold() not in ALLOWED_TOP_LEVEL:
        raise reject("path_not_allowlisted", "Component file is outside the release allowlist.")
    return value


def validate_relative_paths(paths: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    folded: set[str] = set()
    for value in paths:
        value = normalized_relative(value)
        key = value.casefold()
        if key in folded or key in RESERVED_OUTPUTS:
            raise reject("path_duplicate", "Duplicate or reserved component path was rejected.")
        folded.add(key)
        normalized.append(value)
    return tuple(normalized)


def file_attributes(metadata: os.stat_result) -> int:
    return int(getattr(metadata, "st_file_attributes", 0))


def validate_metadata(metadata: os.stat_result, *, directory: bool) -> None:
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected or file_attributes(metadata) & UNSAFE_FILE_ATTRIBUTES:
        raise reject("filesystem_rejected", "Reparse, cloud, offline, or non-ordinary files are forbidden.")
    if not directory and metadata.st_nlink != 1:
        raise reject("filesystem_rejected", "Hard-linked component files are forbidden.")


def validate_fixed_windows_path(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    if os.name == "nt":
        import ctypes

        drive = absolute.drive
        if not drive or ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") != 3:
            raise reject("filesystem_rejected", "Component source and outputs require a fixed local drive.")
    if not absolute.exists():
        raise reject("filesystem_rejected", "Required local path does not exist.")
    validate_metadata(absolute.lstat(), directory=directory)
    current = absolute
    while current.parent != current:
        validate_metadata(current.lstat(), directory=current.is_dir())
        current = current.parent
    return absolute


def ensure_output_parent(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    validate_fixed_windows_path(parent, directory=True)
    if absolute.exists():
        raise reject("output_exists", "Release output is create-new and already exists.")
    return absolute


def path_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def collect_source_files(source: Path) -> list[SourceFile]:
    source = validate_fixed_windows_path(source, directory=True)
    relative_paths: list[str] = []
    absolute_paths: list[Path] = []

    def visit(directory: Path) -> None:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        for entry in entries:
            entry_path = Path(entry.path)
            metadata = entry_path.stat(follow_symlinks=False)
            if entry.is_dir(follow_symlinks=False):
                validate_metadata(metadata, directory=True)
                visit(entry_path)
            elif entry.is_file(follow_symlinks=False):
                validate_metadata(metadata, directory=False)
                relative_paths.append(entry_path.relative_to(source).as_posix())
                absolute_paths.append(entry_path)
            else:
                raise reject("filesystem_rejected", "Only ordinary directories and files are allowed.")

    visit(source)
    validated = validate_relative_paths(relative_paths)
    if not validated or len(validated) > MAX_FILES:
        raise reject("file_count_invalid", "Component file count is outside the supported limit.")

    files: list[SourceFile] = []
    for relative, absolute in zip(validated, absolute_paths, strict=True):
        digest, measured_size = sha256_file(absolute)
        metadata = absolute.stat(follow_symlinks=False)
        validate_metadata(metadata, directory=False)
        if measured_size == 0 or measured_size != metadata.st_size:
            raise reject("file_changed", "Component file changed or is empty during measurement.")
        files.append(SourceFile(relative, absolute, measured_size, digest))
    return files


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise reject("provenance_invalid", "Provenance JSON contains a duplicate field.")
        value[key] = item
    return value


def validate_component_provenance(files: Sequence[SourceFile]) -> tuple[bytes, str]:
    matches = [entry for entry in files if entry.relative_path == PROVENANCE_RELATIVE]
    if len(matches) != 1 or matches[0].size_bytes > MAX_PROVENANCE_BYTES:
        raise reject("provenance_missing", "Exactly one bounded component provenance file is required.")
    raw = matches[0].absolute_path.read_bytes()
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                reject("provenance_invalid", "Provenance JSON constant is invalid.")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise reject("provenance_invalid", "Component provenance JSON is invalid.") from error
    required = {
        "schemaVersion",
        "provenanceVersion",
        "provenanceInputSha256",
        "approval",
        "source",
        "cpython",
        "runtimeProfile",
        "distributions",
        "excludedDistributions",
        "models",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schemaVersion") != 1
        or value.get("provenanceVersion") != PROVENANCE_VERSION
        or json_bytes(value) != raw
    ):
        raise reject("provenance_invalid", "Component provenance shape is invalid.")
    approval = value.get("approval")
    distributions = value.get("distributions")
    models = value.get("models")
    if (
        not isinstance(approval, dict)
        or approval.get("approvedForRedistribution") is not True
        or not isinstance(approval.get("reviewer"), str)
        or not approval.get("reviewer", "").strip()
        or not isinstance(distributions, list)
        or not distributions
        or not isinstance(models, list)
        or len(models) != 2
    ):
        raise reject("provenance_unapproved", "Component provenance is not approved for redistribution.")

    def reject_unknown_license(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if key == "license" and (
                    not isinstance(nested, str)
                    or nested.strip().casefold()
                    in {"", "noassertion", "none", "unknown", "n/a", "not specified"}
                ):
                    raise reject("license_unresolved", "Unknown licenses cannot enter a release.")
                reject_unknown_license(nested)
        elif isinstance(item, list):
            for nested in item:
                reject_unknown_license(nested)

    reject_unknown_license(value)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != matches[0].sha256:
        raise reject("provenance_changed", "Component provenance changed during measurement.")
    return raw, digest


def ensure_declared_runtime(
    files: Sequence[SourceFile], worker: str, runtime_executables: Sequence[str]
) -> tuple[str, tuple[str, ...]]:
    worker = normalized_relative(worker)
    runtimes = validate_relative_paths(runtime_executables)
    if len(runtimes) > 32 or len(set(path.casefold() for path in runtimes)) != len(runtimes):
        raise reject("runtime_invalid", "Zero to 32 unique additional runtime executables are allowed.")
    declared = {worker.casefold(), *(path.casefold() for path in runtimes)}
    available = {entry.relative_path.casefold(): entry for entry in files}
    if worker.casefold() not in available:
        raise reject("worker_missing", "Declared MinerU worker is not in the package source.")
    for executable in (worker, *runtimes):
        path = PurePosixPath(executable)
        if path.suffix != ".exe" or path.parts[0].casefold() not in EXECUTABLE_TOP_LEVEL:
            raise reject("runtime_invalid", "Runtime entries must be allowlisted lowercase .exe paths.")
        entry = available.get(executable.casefold())
        if entry is None:
            raise reject("runtime_missing", "Declared runtime executable is missing.")
        with entry.absolute_path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                raise reject("runtime_invalid", "Worker and runtime executables must have an MZ header.")
    extras = [
        entry.relative_path
        for entry in files
        if PurePosixPath(entry.relative_path).suffix.casefold() == ".exe"
        and entry.relative_path.casefold() not in declared
    ]
    if extras:
        raise reject("runtime_omitted", "Every packaged executable must be declared for isolation.")
    return worker, runtimes


def ensure_model_directory(files: Sequence[SourceFile], value: str) -> str:
    value = normalized_relative(value)
    path = PurePosixPath(value)
    if not path.parts or path.parts[0].casefold() != "models":
        raise reject("model_directory_invalid", "Model directories must be inside models/.")
    prefix = f"{value.casefold()}/"
    if not any(entry.relative_path.casefold().startswith(prefix) for entry in files):
        raise reject("model_directory_empty", "Declared model directory has no package files.")
    return value


def atomic_create_new(path: Path, writer) -> None:
    path = ensure_output_parent(path)
    incoming = path.parent / f".{path.name}.incoming-{uuid.uuid4()}"
    try:
        with incoming.open("xb") as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(incoming, path)
    except Exception:
        try:
            incoming.unlink()
        except FileNotFoundError:
            pass
        raise


def write_package(
    output: Path,
    manifest_bytes: bytes,
    files: Sequence[SourceFile],
    *,
    max_package_bytes: int = MAX_PACKAGE_BYTES,
) -> tuple[str, int]:
    payload_size = sum(entry.size_bytes for entry in files)
    expected_size = len(PACKAGE_MAGIC) + 4 + len(manifest_bytes) + payload_size
    if len(manifest_bytes) == 0 or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise reject("manifest_size_invalid", "Package manifest exceeds the supported limit.")
    if expected_size > max_package_bytes:
        raise reject("package_size_invalid", "Package exceeds the supported size limit.")
    digest = hashlib.sha256()

    def write(handle: BinaryIO) -> None:
        header = PACKAGE_MAGIC + struct.pack("<I", len(manifest_bytes)) + manifest_bytes
        handle.write(header)
        digest.update(header)
        for entry in files:
            measured = hashlib.sha256()
            total = 0
            with entry.absolute_path.open("rb") as source:
                while chunk := source.read(BUFFER_BYTES):
                    handle.write(chunk)
                    digest.update(chunk)
                    measured.update(chunk)
                    total += len(chunk)
            if total != entry.size_bytes or measured.hexdigest() != entry.sha256:
                raise reject("file_changed", "Component file changed after manifest measurement.")

    atomic_create_new(output, write)
    package_hash, actual_size = sha256_file(output)
    if actual_size != expected_size or package_hash != digest.hexdigest():
        output.unlink(missing_ok=True)
        raise reject("package_verify_failed", "New package failed its final size or hash check.")
    return package_hash, actual_size


def write_sharded_package(
    output: Path,
    manifest_bytes: bytes,
    files: Sequence[SourceFile],
    *,
    package_id: str,
    component_version: str,
    manifest_sha256: str,
    part_size_bytes: int,
    max_package_bytes: int = MAX_PACKAGE_BYTES,
) -> tuple[str, int, Path, str, tuple[PackagePart, ...]]:
    payload_size = sum(entry.size_bytes for entry in files)
    expected_size = len(PACKAGE_MAGIC) + 4 + len(manifest_bytes) + payload_size
    if len(manifest_bytes) == 0 or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise reject("manifest_size_invalid", "Package manifest exceeds the supported limit.")
    if expected_size > max_package_bytes:
        raise reject("package_size_invalid", "Package exceeds the supported size limit.")
    if not 16 <= part_size_bytes < GITHUB_RELEASE_ASSET_LIMIT_BYTES:
        raise reject(
            "part_size_invalid",
            "Every release part must be non-empty and strictly smaller than 2 GiB.",
        )
    part_count = (expected_size + part_size_bytes - 1) // part_size_bytes
    if part_count == 0 or part_count > MAX_PARTS:
        raise reject("part_count_invalid", "The sharded package requires too many parts.")

    output = Path(os.path.abspath(output))
    ensure_output_parent(output)
    descriptor_path = output.with_name(f"{output.name}.laocrparts")
    final_paths = tuple(
        output.with_name(f"{output.name}.part{number:04d}-of-{part_count:04d}")
        for number in range(1, part_count + 1)
    )
    for path in (*final_paths, descriptor_path):
        ensure_output_parent(path)

    token = uuid.uuid4()
    incoming_paths = tuple(
        path.with_name(f".{path.name}.incoming-{token}") for path in final_paths
    )
    published: list[Path] = []
    handle: BinaryIO | None = None
    try:
        overall = hashlib.sha256()
        parts: list[PackagePart] = []
        current_number = 0
        current_size = 0
        current_hash = hashlib.sha256()
        total = 0

        def open_next() -> BinaryIO:
            nonlocal current_number, current_size, current_hash
            current_number += 1
            current_size = 0
            current_hash = hashlib.sha256()
            return incoming_paths[current_number - 1].open("xb")

        def finish_current() -> None:
            nonlocal handle
            if handle is None:
                return
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            handle = None
            final = final_paths[current_number - 1]
            parts.append(
                PackagePart(
                    number=current_number,
                    file_name=final.name,
                    path=final,
                    size_bytes=current_size,
                    sha256=current_hash.hexdigest(),
                )
            )

        def consume(chunk: bytes) -> None:
            nonlocal handle, current_size, total
            offset = 0
            while offset < len(chunk):
                if handle is None:
                    handle = open_next()
                available = part_size_bytes - current_size
                take = min(available, len(chunk) - offset)
                segment = chunk[offset : offset + take]
                handle.write(segment)
                current_hash.update(segment)
                overall.update(segment)
                current_size += take
                total += take
                offset += take
                if current_size == part_size_bytes:
                    finish_current()

        consume(PACKAGE_MAGIC + struct.pack("<I", len(manifest_bytes)) + manifest_bytes)
        for entry in files:
            measured = hashlib.sha256()
            measured_size = 0
            with entry.absolute_path.open("rb") as source:
                while chunk := source.read(BUFFER_BYTES):
                    measured.update(chunk)
                    measured_size += len(chunk)
                    consume(chunk)
            if measured_size != entry.size_bytes or measured.hexdigest() != entry.sha256:
                raise reject("file_changed", "Component file changed after manifest measurement.")
        finish_current()
        if total != expected_size or len(parts) != part_count:
            raise reject("package_verify_failed", "Sharded package byte count is invalid.")

        for incoming, final in zip(incoming_paths, final_paths, strict=True):
            os.rename(incoming, final)
            published.append(final)

        descriptor = {
            "schemaVersion": PART_SET_SCHEMA_VERSION,
            "packageId": package_id,
            "componentVersion": component_version,
            "packageFilename": output.name,
            "packageSizeBytes": expected_size,
            "packageSha256": overall.hexdigest(),
            "packageManifestSha256": manifest_sha256,
            "partCount": part_count,
            "parts": [
                {
                    "number": part.number,
                    "fileName": part.file_name,
                    "sizeBytes": part.size_bytes,
                    "sha256": part.sha256,
                }
                for part in parts
            ],
        }
        descriptor_bytes = json_bytes(descriptor)
        atomic_create_new(descriptor_path, lambda target: target.write(descriptor_bytes))

        reread_overall = hashlib.sha256()
        for part in parts:
            digest, size = sha256_file(part.path)
            if digest != part.sha256 or size != part.size_bytes:
                raise reject("package_verify_failed", "A release part changed after publication.")
            with part.path.open("rb") as source:
                while chunk := source.read(BUFFER_BYTES):
                    reread_overall.update(chunk)
        if reread_overall.hexdigest() != overall.hexdigest():
            raise reject("package_verify_failed", "The logical package hash is invalid.")
        return (
            overall.hexdigest(),
            expected_size,
            descriptor_path,
            hashlib.sha256(descriptor_bytes).hexdigest(),
            tuple(parts),
        )
    except Exception:
        if handle is not None:
            handle.close()
        for path in (*incoming_paths, *published, descriptor_path):
            path.unlink(missing_ok=True)
        raise


class PartReader:
    def __init__(self, paths: Sequence[Path]) -> None:
        self._paths = iter(paths)
        self._handle: BinaryIO | None = None

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        output = bytearray()
        while size < 0 or len(output) < size:
            if self._handle is None:
                try:
                    self._handle = next(self._paths).open("rb")
                except StopIteration:
                    break
            remaining = -1 if size < 0 else size - len(output)
            chunk = self._handle.read(remaining)
            if chunk:
                output.extend(chunk)
                continue
            self._handle.close()
            self._handle = None
        return bytes(output)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "PartReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def verify_sharded_package(logical_output: Path, catalog_path: Path) -> None:
    catalog, _ = strict_catalog(catalog_path)
    entries = catalog.get("entries")
    if (
        catalog.get("schemaVersion") != SHARDED_CATALOG_SCHEMA_VERSION
        or not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0], dict)
    ):
        raise reject("catalog_invalid", "Generated sharded catalog is invalid.")
    entry = entries[0]
    descriptor_path = logical_output.with_name(f"{logical_output.name}.laocrparts")
    descriptor_hash, descriptor_size = sha256_file(descriptor_path)
    if (
        entry.get("partSetManifestSha256") != descriptor_hash
        or entry.get("partSetManifestSizeBytes") != descriptor_size
    ):
        raise reject("part_manifest_tampered", "Part-set manifest is not catalog-bound.")
    descriptor_bytes = descriptor_path.read_bytes()
    try:
        descriptor = json.loads(descriptor_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as failure:
        raise reject("part_manifest_invalid", "Part-set manifest is invalid JSON.") from failure
    expected_descriptor_keys = {
        "schemaVersion",
        "packageId",
        "componentVersion",
        "packageFilename",
        "packageSizeBytes",
        "packageSha256",
        "packageManifestSha256",
        "partCount",
        "parts",
    }
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != expected_descriptor_keys
        or json_bytes(descriptor) != descriptor_bytes
        or descriptor.get("schemaVersion") != PART_SET_SCHEMA_VERSION
        or descriptor.get("packageId") != entry.get("packageId")
        or descriptor.get("componentVersion") != entry.get("componentVersion")
        or descriptor.get("packageFilename") != logical_output.name
        or descriptor.get("packageSizeBytes") != entry.get("packageSizeBytes")
        or descriptor.get("packageSha256") != entry.get("packageSha256")
        or descriptor.get("packageManifestSha256")
        != entry.get("packageManifestSha256")
    ):
        raise reject("part_manifest_invalid", "Part-set manifest binding is invalid.")
    descriptor_parts = descriptor.get("parts")
    catalog_parts = entry.get("parts")
    part_count = descriptor.get("partCount")
    if (
        not isinstance(part_count, int)
        or not 1 <= part_count <= MAX_PARTS
        or not isinstance(descriptor_parts, list)
        or len(descriptor_parts) != part_count
        or not isinstance(catalog_parts, list)
        or len(catalog_parts) != part_count
    ):
        raise reject("part_manifest_invalid", "Part-set inventory is invalid.")

    paths: list[Path] = []
    total = 0
    overall = hashlib.sha256()
    for index, (part, catalog_part) in enumerate(
        zip(descriptor_parts, catalog_parts, strict=True), start=1
    ):
        if (
            not isinstance(part, dict)
            or set(part) != {"number", "fileName", "sizeBytes", "sha256"}
            or not isinstance(catalog_part, dict)
            or set(catalog_part)
            != {"number", "fileName", "sizeBytes", "sha256", "downloadUrl"}
        ):
            raise reject("part_manifest_invalid", "Part entry schema is invalid.")
        expected_name = (
            f"{logical_output.name}.part{index:04d}-of-{part_count:04d}"
        )
        if (
            part.get("number") != index
            or part.get("fileName") != expected_name
            or catalog_part.get("number") != index
            or catalog_part.get("fileName") != expected_name
            or catalog_part.get("sizeBytes") != part.get("sizeBytes")
            or catalog_part.get("sha256") != part.get("sha256")
            or not isinstance(part.get("sizeBytes"), int)
            or not 0 < part["sizeBytes"] < GITHUB_RELEASE_ASSET_LIMIT_BYTES
            or not isinstance(part.get("sha256"), str)
            or len(part["sha256"]) != 64
        ):
            raise reject("part_manifest_invalid", "Part entry binding is invalid.")
        path = descriptor_path.parent / expected_name
        digest, size = sha256_file(path)
        if digest != part["sha256"] or size != part["sizeBytes"]:
            raise reject("part_tampered", "A package part failed size or hash verification.")
        paths.append(path)
        total += size
        with path.open("rb") as source:
            while chunk := source.read(BUFFER_BYTES):
                overall.update(chunk)
    if total != entry.get("packageSizeBytes") or overall.hexdigest() != entry.get(
        "packageSha256"
    ):
        raise reject("package_tampered", "The logical package failed whole-hash verification.")

    with PartReader(paths) as handle:
        if handle.read(8) != PACKAGE_MAGIC:
            raise reject("package_invalid", "Logical package magic is invalid.")
        length_bytes = handle.read(4)
        if len(length_bytes) != 4:
            raise reject("package_invalid", "Logical package manifest length is missing.")
        manifest_length = struct.unpack("<I", length_bytes)[0]
        if manifest_length == 0 or manifest_length > MAX_MANIFEST_BYTES:
            raise reject("package_invalid", "Logical package manifest length is invalid.")
        manifest_bytes = handle.read(manifest_length)
        if (
            len(manifest_bytes) != manifest_length
            or hashlib.sha256(manifest_bytes).hexdigest()
            != entry.get("packageManifestSha256")
        ):
            raise reject("manifest_tampered", "Logical package manifest is not trusted.")
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as failure:
            raise reject("package_invalid", "Logical package manifest JSON is invalid.") from failure
        validate_provenance_bindings(manifest, entry, catalog_path.parent)
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, list) or not files:
            raise reject("package_invalid", "Logical package inventory is missing.")
        paths_in_manifest: list[str] = []
        for file_entry in files:
            if (
                not isinstance(file_entry, dict)
                or set(file_entry) != {"relativePath", "sizeBytes", "sha256"}
            ):
                raise reject("package_invalid", "Logical package inventory is invalid.")
            relative = file_entry.get("relativePath")
            size = file_entry.get("sizeBytes")
            expected_hash = file_entry.get("sha256")
            if (
                not isinstance(relative, str)
                or not isinstance(size, int)
                or size <= 0
                or not isinstance(expected_hash, str)
            ):
                raise reject("package_invalid", "Logical package inventory value is invalid.")
            paths_in_manifest.append(relative)
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = handle.read(min(BUFFER_BYTES, remaining))
                if not chunk:
                    raise reject("package_invalid", "Logical package payload is truncated.")
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.hexdigest() != expected_hash:
                raise reject("payload_tampered", "Logical package payload hash is invalid.")
        validate_relative_paths(paths_in_manifest)
        if handle.read(1):
            raise reject("package_invalid", "Logical package contains trailing data.")


def strict_catalog(path: Path) -> tuple[dict[str, object], bytes]:
    bytes_value = path.read_bytes()
    try:
        value = json.loads(bytes_value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise reject("catalog_invalid", "Previous catalog is not strict JSON.") from error
    expected = {"schemaVersion", "catalogId", "issuedAtUnix", "expiresAtUnix", "entries"}
    if not isinstance(value, dict) or set(value) != expected:
        raise reject("catalog_invalid", "Previous catalog schema is not accepted.")
    return value, bytes_value


def validate_catalog_epoch(catalog_bytes: bytes, issued_at: int, previous_catalog: Path | None) -> None:
    if previous_catalog is None:
        return
    previous, previous_bytes = strict_catalog(previous_catalog)
    previous_issued = previous.get("issuedAtUnix")
    if not isinstance(previous_issued, int) or previous_issued <= 0:
        raise reject("catalog_invalid", "Previous catalog epoch is invalid.")
    if issued_at < previous_issued:
        raise reject("catalog_rollback_rejected", "Catalog issuedAt cannot move backwards.")
    if issued_at == previous_issued and catalog_bytes != previous_bytes:
        raise reject("catalog_equivocation_rejected", "Same-epoch catalog content cannot change.")


def powershell_quote(path: Path) -> str:
    return '"' + str(path).replace('"', '`"') + '"'


def signing_command(path: Path, issued_at: int) -> str:
    signature = path.with_name(f"{path.name}.minisig")
    trusted = f"timestamp:{issued_at}`tfile:{path.name}"
    return (
        'minisign.exe -S -s "$env:LAWYER_ASSISTANCE_MINISIGN_SECRET_KEY" '
        f"-m {powershell_quote(path)} -x {powershell_quote(signature)} "
        f'-t "{trusted}"'
    )


def validate_provenance_bindings(
    manifest: object, entry: object, release_directory: Path
) -> None:
    if not isinstance(manifest, dict) or not isinstance(entry, dict):
        raise reject("provenance_binding_invalid", "Provenance binding is missing.")
    manifest_keys = {
        "schemaVersion",
        "packageId",
        "componentVersion",
        "mineruVersion",
        "protocolVersion",
        "platform",
        "worker",
        "runtimeExecutables",
        "pipelineModelDirectory",
        "vlmModelDirectory",
        "provenanceRelativePath",
        "provenanceSizeBytes",
        "provenanceSha256",
        "files",
    }
    if set(manifest) != manifest_keys:
        raise reject("package_invalid", "Package manifest schema is not exact.")
    provenance_size = manifest.get("provenanceSizeBytes")
    provenance_hash = manifest.get("provenanceSha256")
    files = manifest.get("files")
    matching = (
        [
            file
            for file in files
            if isinstance(file, dict) and file.get("relativePath") == PROVENANCE_RELATIVE
        ]
        if isinstance(files, list)
        else []
    )
    if (
        manifest.get("provenanceRelativePath") != PROVENANCE_RELATIVE
        or not isinstance(provenance_size, int)
        or not 0 < provenance_size <= MAX_PROVENANCE_BYTES
        or not isinstance(provenance_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", provenance_hash) is None
        or len(matching) != 1
        or matching[0].get("sizeBytes") != provenance_size
        or matching[0].get("sha256") != provenance_hash
        or entry.get("provenanceFileName") != PROVENANCE_FILENAME
        or entry.get("provenanceSizeBytes") != provenance_size
        or entry.get("provenanceSha256") != provenance_hash
    ):
        raise reject("provenance_binding_invalid", "Package/catalog provenance binding is invalid.")
    expected_url = (
        "https://github.com/shilittle/Lawyer-Assistance/releases/download/"
        f"mineru-components-v{manifest.get('componentVersion')}/{PROVENANCE_FILENAME}"
    )
    if entry.get("provenanceDownloadUrl") != expected_url:
        raise reject("provenance_binding_invalid", "Provenance release URL is not exact.")
    provenance_path = release_directory / PROVENANCE_FILENAME
    digest, size = sha256_file(provenance_path)
    if digest != provenance_hash or size != provenance_size:
        raise reject("provenance_asset_tampered", "Standalone provenance asset is not catalog-bound.")


def verify_package(package_path: Path, catalog_path: Path) -> None:
    catalog, _ = strict_catalog(catalog_path)
    entries = catalog.get("entries")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise reject("catalog_invalid", "Generated catalog must contain exactly one component entry.")
    entry = entries[0]
    package_hash, package_size = sha256_file(package_path)
    if entry.get("packageSha256") != package_hash or entry.get("packageSizeBytes") != package_size:
        raise reject("package_tampered", "Package bytes no longer match the unsigned catalog.")
    with package_path.open("rb") as handle:
        if handle.read(8) != PACKAGE_MAGIC:
            raise reject("package_invalid", "Package magic is invalid.")
        length_bytes = handle.read(4)
        if len(length_bytes) != 4:
            raise reject("package_invalid", "Package manifest length is missing.")
        manifest_length = struct.unpack("<I", length_bytes)[0]
        if manifest_length == 0 or manifest_length > MAX_MANIFEST_BYTES:
            raise reject("package_invalid", "Package manifest length is invalid.")
        manifest_bytes = handle.read(manifest_length)
        if len(manifest_bytes) != manifest_length:
            raise reject("package_invalid", "Package manifest is truncated.")
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise reject("package_invalid", "Package manifest is invalid JSON.") from error
        if entry.get("packageManifestSha256") != hashlib.sha256(manifest_bytes).hexdigest():
            raise reject("manifest_tampered", "Package manifest hash no longer matches the catalog.")
        validate_provenance_bindings(manifest, entry, catalog_path.parent)
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, list) or not files:
            raise reject("package_invalid", "Package manifest file inventory is missing.")
        paths: list[str] = []
        for file_entry in files:
            if not isinstance(file_entry, dict) or set(file_entry) != {"relativePath", "sizeBytes", "sha256"}:
                raise reject("package_invalid", "Package file inventory schema is invalid.")
            relative = file_entry.get("relativePath")
            size = file_entry.get("sizeBytes")
            expected_hash = file_entry.get("sha256")
            if not isinstance(relative, str) or not isinstance(size, int) or size <= 0:
                raise reject("package_invalid", "Package file inventory value is invalid.")
            paths.append(relative)
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = handle.read(min(BUFFER_BYTES, remaining))
                if not chunk:
                    raise reject("package_invalid", "Package payload is truncated.")
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.hexdigest() != expected_hash:
                raise reject("payload_tampered", "Package payload hash is invalid.")
        validate_relative_paths(paths)
        if handle.read(1):
            raise reject("package_invalid", "Package contains trailing data.")


def build_release(
    *,
    source: Path,
    output: Path,
    catalog_output: Path,
    package_id: str,
    catalog_id: str,
    component_version: str,
    mineru_version: str,
    worker: str,
    runtime_executables: Sequence[str],
    pipeline_model_directory: str,
    vlm_model_directory: str,
    issued_at: int,
    expires_at: int,
    previous_catalog: Path | None = None,
    max_package_bytes: int = MAX_PACKAGE_BYTES,
    part_size_bytes: int | None = None,
) -> BuildResult:
    validate_identifier(package_id, "packageId")
    validate_identifier(catalog_id, "catalogId")
    validate_semver(component_version)
    if not mineru_version or len(mineru_version) > 64:
        raise reject("mineru_version_invalid", "MinerU version is required and length-limited.")
    now = int(time.time())
    if issued_at <= 0 or issued_at > now + 300 or expires_at <= max(issued_at, now):
        raise reject("catalog_epoch_invalid", "Catalog issuedAt/expiresAt is invalid for current time.")

    source = validate_fixed_windows_path(source, directory=True)
    output = Path(os.path.abspath(output))
    catalog_output = Path(os.path.abspath(catalog_output))
    expected_name = f"lawyer-assistance-mineru-{component_version}-windows-x86_64.laocrpkg"
    if output.name != expected_name:
        raise reject("package_filename_invalid", f"Package filename must be {expected_name}.")
    if path_within(output, source) or path_within(catalog_output, source):
        raise reject("output_inside_source", "Release outputs cannot be placed inside the package source.")
    ensure_output_parent(output)
    ensure_output_parent(catalog_output)

    files = collect_source_files(source)
    provenance_bytes, provenance_hash = validate_component_provenance(files)
    provenance_output = catalog_output.with_name(PROVENANCE_FILENAME)
    if path_within(provenance_output, source):
        raise reject("output_inside_source", "Provenance output cannot be placed inside the source.")
    ensure_output_parent(provenance_output)
    worker, runtimes = ensure_declared_runtime(files, worker, runtime_executables)
    pipeline = ensure_model_directory(files, pipeline_model_directory)
    vlm = ensure_model_directory(files, vlm_model_directory)
    if pipeline.casefold() == vlm.casefold():
        raise reject("model_directory_invalid", "Pipeline and VLM model directories must be distinct.")

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "packageId": package_id,
        "componentVersion": component_version,
        "mineruVersion": mineru_version,
        "protocolVersion": PROTOCOL_VERSION,
        "platform": PLATFORM,
        "worker": worker,
        "runtimeExecutables": list(runtimes),
        "pipelineModelDirectory": pipeline,
        "vlmModelDirectory": vlm,
        "provenanceRelativePath": PROVENANCE_RELATIVE,
        "provenanceSizeBytes": len(provenance_bytes),
        "provenanceSha256": provenance_hash,
        "files": [
            {
                "relativePath": entry.relative_path,
                "sizeBytes": entry.size_bytes,
                "sha256": entry.sha256,
            }
            for entry in files
        ],
    }
    manifest_bytes = json_bytes(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    release_base_url = (
        "https://github.com/shilittle/Lawyer-Assistance/releases/download/"
        f"mineru-components-v{component_version}/"
    )
    provenance_download_url = f"{release_base_url}{PROVENANCE_FILENAME}"
    part_manifest_path: Path | None = None
    part_manifest_hash: str | None = None
    parts: tuple[PackagePart, ...] = ()
    if part_size_bytes is None:
        package_hash, package_size = write_package(
            output,
            manifest_bytes,
            files,
            max_package_bytes=max_package_bytes,
        )
        download_url = f"{release_base_url}{expected_name}"
        catalog_entry = {
            "packageId": package_id,
            "componentVersion": component_version,
            "mineruVersion": mineru_version,
            "protocolVersion": PROTOCOL_VERSION,
            "platform": PLATFORM,
            "packageSizeBytes": package_size,
            "packageSha256": package_hash,
            "packageManifestSha256": manifest_hash,
            "provenanceFileName": PROVENANCE_FILENAME,
            "provenanceSizeBytes": len(provenance_bytes),
            "provenanceSha256": provenance_hash,
            "provenanceDownloadUrl": provenance_download_url,
            "downloadUrl": download_url,
            "revoked": False,
        }
        catalog_schema = SCHEMA_VERSION
    else:
        (
            package_hash,
            package_size,
            part_manifest_path,
            part_manifest_hash,
            parts,
        ) = write_sharded_package(
            output,
            manifest_bytes,
            files,
            package_id=package_id,
            component_version=component_version,
            manifest_sha256=manifest_hash,
            part_size_bytes=part_size_bytes,
            max_package_bytes=max_package_bytes,
        )
        download_url = f"{release_base_url}{part_manifest_path.name}"
        catalog_entry = {
            "packageId": package_id,
            "componentVersion": component_version,
            "mineruVersion": mineru_version,
            "protocolVersion": PROTOCOL_VERSION,
            "platform": PLATFORM,
            "packageSizeBytes": package_size,
            "packageSha256": package_hash,
            "packageManifestSha256": manifest_hash,
            "provenanceFileName": PROVENANCE_FILENAME,
            "provenanceSizeBytes": len(provenance_bytes),
            "provenanceSha256": provenance_hash,
            "provenanceDownloadUrl": provenance_download_url,
            "downloadUrl": download_url,
            "partSetManifestSizeBytes": part_manifest_path.stat().st_size,
            "partSetManifestSha256": part_manifest_hash,
            "parts": [
                {
                    "number": part.number,
                    "fileName": part.file_name,
                    "sizeBytes": part.size_bytes,
                    "sha256": part.sha256,
                    "downloadUrl": f"{release_base_url}{part.file_name}",
                }
                for part in parts
            ],
            "revoked": False,
        }
        catalog_schema = SHARDED_CATALOG_SCHEMA_VERSION
    catalog = {
        "schemaVersion": catalog_schema,
        "catalogId": catalog_id,
        "issuedAtUnix": issued_at,
        "expiresAtUnix": expires_at,
        "entries": [catalog_entry],
    }
    catalog_bytes = json_bytes(catalog)
    try:
        validate_catalog_epoch(catalog_bytes, issued_at, previous_catalog)
        atomic_create_new(catalog_output, lambda handle: handle.write(catalog_bytes))
        atomic_create_new(
            provenance_output, lambda handle: handle.write(provenance_bytes)
        )
        copied_provenance_hash, copied_provenance_size = sha256_file(provenance_output)
        if (
            copied_provenance_hash != provenance_hash
            or copied_provenance_size != len(provenance_bytes)
        ):
            raise reject("provenance_copy_failed", "Standalone provenance copy failed verification.")
        if parts:
            verify_sharded_package(output, catalog_output)
        else:
            verify_package(output, catalog_output)
    except Exception:
        output.unlink(missing_ok=True)
        if part_manifest_path is not None:
            part_manifest_path.unlink(missing_ok=True)
        for part in parts:
            part.path.unlink(missing_ok=True)
        catalog_output.unlink(missing_ok=True)
        provenance_output.unlink(missing_ok=True)
        raise
    catalog_hash = hashlib.sha256(catalog_bytes).hexdigest()
    return BuildResult(
        package_path=output,
        catalog_path=catalog_output,
        package_size_bytes=package_size,
        package_sha256=package_hash,
        manifest_sha256=manifest_hash,
        catalog_sha256=catalog_hash,
        signing_command=signing_command(catalog_output, issued_at),
        provenance_path=provenance_output,
        provenance_sha256=provenance_hash,
        provenance_signing_command=signing_command(provenance_output, issued_at),
        sharded=bool(parts),
        part_manifest_path=part_manifest_path,
        part_manifest_sha256=part_manifest_hash,
        part_paths=tuple(part.path for part in parts),
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--catalog-output", type=Path, required=True)
    value.add_argument("--package-id", required=True)
    value.add_argument("--catalog-id", required=True)
    value.add_argument("--component-version", required=True)
    value.add_argument("--mineru-version", required=True)
    value.add_argument("--worker", required=True)
    value.add_argument("--runtime-executable", action="append", default=[])
    value.add_argument("--pipeline-model-directory", required=True)
    value.add_argument("--vlm-model-directory", required=True)
    value.add_argument("--issued-at", type=int, required=True)
    value.add_argument("--expires-at", type=int, required=True)
    value.add_argument("--previous-catalog", type=Path)
    value.add_argument("--part-size-bytes", type=int)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        result = build_release(
            source=arguments.source,
            output=arguments.output,
            catalog_output=arguments.catalog_output,
            package_id=arguments.package_id,
            catalog_id=arguments.catalog_id,
            component_version=arguments.component_version,
            mineru_version=arguments.mineru_version,
            worker=arguments.worker,
            runtime_executables=arguments.runtime_executable,
            pipeline_model_directory=arguments.pipeline_model_directory,
            vlm_model_directory=arguments.vlm_model_directory,
            issued_at=arguments.issued_at,
            expires_at=arguments.expires_at,
            previous_catalog=arguments.previous_catalog,
            part_size_bytes=arguments.part_size_bytes,
        )
    except PackageBuildError as error:
        print(json.dumps({"ok": False, "code": error.code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "package": str(result.package_path),
                "catalog": str(result.catalog_path),
                "packageSizeBytes": result.package_size_bytes,
                "packageSha256": result.package_sha256,
                "packageManifestSha256": result.manifest_sha256,
                "catalogSha256": result.catalog_sha256,
                "provenance": str(result.provenance_path),
                "provenanceSha256": result.provenance_sha256,
                "sharded": result.sharded,
                "partManifest": str(result.part_manifest_path) if result.part_manifest_path else None,
                "parts": [str(path) for path in result.part_paths],
                "signed": False,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    print("UNSIGNED_CATALOG_AND_PROVENANCE_REQUIRE_OFFLINE_MINISIGN=1")
    print(result.signing_command)
    print(result.provenance_signing_command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
