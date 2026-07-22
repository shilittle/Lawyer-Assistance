"""Strict verification of the self-contained production support tree."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Final


SCHEMA_VERSION: Final = 1
MANIFEST_VERSION: Final = "lawyer-assistance-mineru-support-v1"
PROTOCOL_VERSION: Final = "la-mineru-worker-v1"
WORKER_VERSION: Final = "1.0.0"
PYTHON_VERSION: Final = "3.12.13"
MINERU_VERSION: Final = "3.4.3"
PYTORCH_VERSION: Final = "2.8.0+cu128"
MAX_MANIFEST_BYTES: Final = 16 * 1024 * 1024
MAX_FILES: Final = 150_000
HASH_RE: Final = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_TOP: Final = {"worker", "python", "runtime"}
CRITICAL_FILES: Final = (
    "worker/lawyer_assistance_mineru_worker/__init__.py",
    "worker/lawyer_assistance_mineru_worker/main.py",
    "worker/lawyer_assistance_mineru_worker/output_document.py",
    "worker/lawyer_assistance_mineru_worker/protocol.py",
    "worker/lawyer_assistance_mineru_worker/runtime.py",
    "worker/lawyer_assistance_mineru_worker/single_process.py",
    "worker/lawyer_assistance_mineru_worker/support_manifest.py",
    "worker/mineru-worker._pth",
    "worker/python312._pth",
    "worker/python312.dll",
    "worker/sitecustomize.py",
    "python/Lib/os.py",
    "python/Lib/site.py",
    "runtime/site-packages/mineru/__init__.py",
    "runtime/site-packages/pypdfium2/__init__.py",
    "runtime/site-packages/torch/__init__.py",
)
EXPECTED_FIELDS: Final = {
    "schemaVersion",
    "manifestVersion",
    "selfContained",
    "protocolVersion",
    "workerVersion",
    "pythonVersion",
    "mineruVersion",
    "pytorchVersion",
    "supportTreeSha256",
    "supportIdentitySha256",
    "criticalFiles",
    "files",
}


class SupportManifestFailure(RuntimeError):
    """Stable support-tree rejection without paths or document material."""


def _sha256_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    import hashlib

    digest = hashlib.sha256()
    size = 0
    with path.open("rb", buffering=0) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SupportManifestFailure("support_manifest_duplicate_field")
        result[key] = value
    return result


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise SupportManifestFailure("support_manifest_path_invalid")
    path = PurePosixPath(value)
    if (
        str(path) != value
        or len(value) > 240
        or len(path.parts) > 32
        or not path.parts
        or path.parts[0] not in ALLOWED_TOP
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise SupportManifestFailure("support_manifest_path_invalid")
    return value


def _tree_hash(files: list[tuple[str, int, str]]) -> str:
    canonical = bytearray(b"la-mineru-support-tree-v1\n")
    for relative, size, digest in files:
        canonical.extend(relative.encode("utf-8"))
        canonical.extend(b"\n")
        canonical.extend(str(size).encode("ascii"))
        canonical.extend(b"\n")
        canonical.extend(digest.encode("ascii"))
        canonical.extend(b"\n")
    return _sha256_bytes(bytes(canonical))


def _identity_hash(tree_hash: str) -> str:
    return _sha256_bytes(
        (
            "la-mineru-support-identity-v1\n"
            f"{PROTOCOL_VERSION}\n{WORKER_VERSION}\n{PYTHON_VERSION}\n"
            f"{MINERU_VERSION}\n{PYTORCH_VERSION}\n{tree_hash}\n"
        ).encode("utf-8")
    )


def validate_support_manifest(
    manifest_path: Path,
    expected_manifest_sha256: str,
    executable: Path,
    *,
    full: bool = False,
) -> tuple[str, str]:
    """Return ``(support identity, tree hash)`` after strict local checks."""
    if not HASH_RE.fullmatch(expected_manifest_sha256):
        raise SupportManifestFailure("support_manifest_hash_invalid")
    try:
        manifest_path = manifest_path.resolve(strict=True)
        executable = executable.resolve(strict=True)
    except OSError as error:
        raise SupportManifestFailure("support_manifest_unavailable") from error
    if (
        not manifest_path.is_file()
        or manifest_path.name != "mineru-worker.support-manifest.json"
        or manifest_path.parent != executable.parent
        or executable.name.casefold() != "mineru-worker.exe"
    ):
        raise SupportManifestFailure("support_manifest_location_invalid")
    manifest_hash, manifest_size = _sha256_file(manifest_path)
    if (
        manifest_hash != expected_manifest_sha256
        or not 1 <= manifest_size <= MAX_MANIFEST_BYTES
    ):
        raise SupportManifestFailure("support_manifest_integrity_failed")
    try:
        value = json.loads(
            manifest_path.read_bytes(),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                SupportManifestFailure("support_manifest_number_invalid")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SupportManifestFailure("support_manifest_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != EXPECTED_FIELDS
        or value["schemaVersion"] != SCHEMA_VERSION
        or value["manifestVersion"] != MANIFEST_VERSION
        or value["selfContained"] is not True
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["workerVersion"] != WORKER_VERSION
        or value["pythonVersion"] != PYTHON_VERSION
        or value["mineruVersion"] != MINERU_VERSION
        or value["pytorchVersion"] != PYTORCH_VERSION
        or value["criticalFiles"] != list(CRITICAL_FILES)
        or not isinstance(value["files"], list)
        or not 1 <= len(value["files"]) <= MAX_FILES
    ):
        raise SupportManifestFailure("support_manifest_invalid")
    files: list[tuple[str, int, str]] = []
    previous: str | None = None
    folded: set[str] = set()
    by_path: dict[str, tuple[int, str]] = {}
    for entry in value["files"]:
        if not isinstance(entry, dict) or set(entry) != {"relativePath", "sizeBytes", "sha256"}:
            raise SupportManifestFailure("support_manifest_entry_invalid")
        relative = _relative(entry.get("relativePath"))
        size = entry.get("sizeBytes")
        digest = entry.get("sha256")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(digest, str)
            or not HASH_RE.fullmatch(digest)
            or (previous is not None and previous >= relative)
            or relative.casefold() in folded
        ):
            raise SupportManifestFailure("support_manifest_entry_invalid")
        previous = relative
        folded.add(relative.casefold())
        files.append((relative, size, digest))
        by_path[relative] = (size, digest)
    tree_hash = _tree_hash(files)
    if value["supportTreeSha256"] != tree_hash or value["supportIdentitySha256"] != _identity_hash(tree_hash):
        raise SupportManifestFailure("support_manifest_identity_invalid")
    component_root = manifest_path.parent.parent
    targets = tuple(relative for relative, _size, _digest in files) if full else CRITICAL_FILES
    for relative in targets:
        expected = by_path.get(relative)
        if expected is None:
            raise SupportManifestFailure("critical_support_missing")
        candidate = component_root.joinpath(*PurePosixPath(relative).parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(component_root)
        except (OSError, ValueError) as error:
            raise SupportManifestFailure("support_path_escape") from error
        if not resolved.is_file() or resolved.is_symlink():
            raise SupportManifestFailure("support_file_invalid")
        actual_hash, actual_size = _sha256_file(resolved)
        if (actual_size, actual_hash) != expected:
            raise SupportManifestFailure("support_file_integrity_failed")
    return str(value["supportIdentitySha256"]), tree_hash
