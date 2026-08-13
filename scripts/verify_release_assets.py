#!/usr/bin/env python3
"""Verify the exact, already-downloaded v0.4.0 release asset sets.

The verifier is deliberately read-only.  It is used both before upload and
after downloading a draft release into a fresh directory.  Asset names are
derived from the checked-in release contract (and, for MinerU, from an
authenticated catalog); callers cannot supply an alternate allowlist.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_mineru_component_package as mineru_packager  # noqa: E402
import package_mcp_release as mcp_packager  # noqa: E402
from release import release_contract as canonical_release_contract  # noqa: E402


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_PORTABLE_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_PORTABLE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_PORTABLE_MEMBERS = 16_384
MINERU_CATALOG = "mineru-component-catalog.json"
MINERU_PROVENANCE = "mineru-component-provenance.json"
MINERU_PUBLIC_KEY = ROOT / "apps" / "desktop" / "src-tauri" / "updater-public.key"
MINISIGN_SIGNATURE_COMMENT = "untrusted comment: signature from minisign secret key"
TAURI_SIGNATURE_COMMENT = "untrusted comment: signature from tauri secret key"


class VerificationError(RuntimeError):
    """Stable, non-sensitive release verification rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Contract:
    version: str
    app_tag: str
    mineru_tag: str
    app_assets: tuple[str, ...]


@dataclass(frozen=True)
class VerificationReport:
    kind: str
    version: str
    expected_commit: str
    asset_names: tuple[str, ...]
    portable_members: tuple[str, ...] = ()
    authenticode_files: tuple[str, ...] = ()

    def json_value(self) -> dict[str, object]:
        return {
            "ok": True,
            "kind": self.kind,
            "version": self.version,
            "expectedCommit": self.expected_commit,
            "assetCount": len(self.asset_names),
            "assetNames": list(self.asset_names),
            "portableMembers": list(self.portable_members),
            "authenticodeFiles": list(self.authenticode_files),
        }


def reject(code: str, message: str) -> VerificationError:
    return VerificationError(code, message)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise reject("json_duplicate_field", "JSON contains a duplicate field.")
        result[key] = value
    return result


def strict_json_bytes(raw: bytes, *, code: str) -> object:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise reject(code, "JSON is empty or exceeds the bounded release limit.")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                reject(code, "JSON contains a non-finite number.")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise reject(code, "JSON is not valid strict UTF-8 JSON.") from error


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _ordinary_metadata(path: Path, *, directory: bool = False) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise reject("path_unavailable", f"Required release path is unavailable: {path.name}") from error
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected or stat.S_ISLNK(metadata.st_mode) or _has_reparse_attribute(metadata):
        kind = "directory" if directory else "file"
        raise reject("path_not_ordinary", f"Release {kind} must be ordinary and non-linked: {path.name}")
    if not directory and metadata.st_size <= 0:
        raise reject("asset_empty", f"Release asset must be nonempty: {path.name}")
    return metadata


def _read_ordinary(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    before = _ordinary_metadata(path)
    if before.st_size > max_bytes:
        raise reject("asset_too_large", f"Release asset exceeds its verification bound: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise reject("path_not_ordinary", f"Release file is not ordinary: {path.name}")
            raw = handle.read(max_bytes + 1)
    except OSError as error:
        raise reject("asset_read_failed", f"Release asset could not be read: {path.name}") from error
    after = _ordinary_metadata(path)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_opened or identity_before != identity_after or len(raw) != before.st_size:
        raise reject("asset_changed", f"Release asset changed while it was read: {path.name}")
    if len(raw) > max_bytes:
        raise reject("asset_too_large", f"Release asset exceeds its verification bound: {path.name}")
    return raw


def _sha256_file(path: Path) -> tuple[str, int]:
    before = _ordinary_metadata(path)
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise reject("asset_read_failed", f"Release asset could not be hashed: {path.name}") from error
    after = _ordinary_metadata(path)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or size != before.st_size
    ):
        raise reject("asset_changed", f"Release asset changed while it was hashed: {path.name}")
    return digest.hexdigest(), size


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def expected_app_assets(version: str) -> tuple[str, ...]:
    return (
        f"Lawyer.Assistance_{version}_x64-setup.exe",
        f"Lawyer.Assistance_{version}_x64-setup.exe.sha256",
        f"Lawyer.Assistance_{version}_x64-setup.exe.sig",
        "latest.json",
        f"Lawyer-Assistance_{version}_windows-x86_64-portable.zip",
        f"Lawyer-Assistance_{version}_windows-x86_64-portable.zip.sha256",
        f"lawyer-assistance-mcp-v{version}-x86_64-pc-windows-msvc.zip",
        f"lawyer-assistance-mcp-v{version}-x86_64-pc-windows-msvc.zip.sha256",
        f"lawyer-assistance-mcp-v{version}-x86_64-unknown-linux-gnu.tar.gz",
        f"lawyer-assistance-mcp-v{version}-x86_64-unknown-linux-gnu.tar.gz.sha256",
        f"lawyer-assistance-mcp-v{version}-aarch64-apple-darwin.tar.gz",
        f"lawyer-assistance-mcp-v{version}-aarch64-apple-darwin.tar.gz.sha256",
    )


def load_contract(path: Path) -> Contract:
    _ordinary_metadata(path)
    try:
        value = canonical_release_contract.load_contract(path)
        canonical_release_contract._canonical_contract(value)  # noqa: SLF001
    except (
        canonical_release_contract.ContractLoadError,
        canonical_release_contract.ContractError,
    ) as error:
        raise reject("contract_invalid", "Release contract is not the frozen canonical v0.4.0 contract.") from error
    release = value["release"]
    assets = tuple(value["appAssets"])
    return Contract(
        canonical_release_contract.FORMAL_VERSION,
        release["appTag"],
        release["minerUTag"],
        assets,
    )


def validate_expected_commit(value: str) -> str:
    normalized = value.strip().lower()
    if COMMIT.fullmatch(normalized) is None:
        raise reject("commit_invalid", "Expected release commit must be a full lowercase 40-character SHA.")
    return normalized


def _directory_names(directory: Path) -> tuple[str, ...]:
    _ordinary_metadata(directory, directory=True)
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        raise reject("directory_read_failed", "Release directory could not be enumerated.") from error
    names: list[str] = []
    folded: set[str] = set()
    for entry in entries:
        _ordinary_metadata(entry)
        if entry.name.casefold() in folded:
            raise reject("asset_case_alias", "Release directory contains a case-aliased asset.")
        folded.add(entry.name.casefold())
        names.append(entry.name)
    return tuple(names)


def _assert_exact_names(directory: Path, expected: Iterable[str]) -> None:
    expected_tuple = tuple(expected)
    actual = _directory_names(directory)
    if set(actual) != set(expected_tuple) or len(actual) != len(expected_tuple):
        missing = sorted(set(expected_tuple) - set(actual))
        extra = sorted(set(actual) - set(expected_tuple))
        raise reject(
            "asset_set_mismatch",
            f"Release asset set is not exact (missing={missing}, extra={extra}).",
        )


def verify_canonical_checksum(directory: Path, filename: str) -> None:
    asset = directory / filename
    checksum = directory / f"{filename}.sha256"
    digest, _ = _sha256_file(asset)
    expected = f"{digest}  {filename}\n".encode("ascii")
    if _read_ordinary(checksum, max_bytes=1024) != expected:
        raise reject("checksum_noncanonical", f"Checksum is not canonical or does not match: {checksum.name}")


# Minimal dependency-free Ed25519 verification.  Minisign signs a 64-byte
# BLAKE2b prehash for its primary signature, then signs
# primary_signature || trusted_comment for its global signature.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1, 1, 0)


def _x_recover(y: int) -> int:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(x2, (_Q + 3) // 8, _Q)
    if (x * x - x2) % _Q:
        x = x * _I % _Q
    if (x * x - x2) % _Q:
        raise reject("minisign_invalid", "Minisign point encoding is invalid.")
    return x


def _decode_point(raw: bytes) -> tuple[int, int, int, int]:
    if len(raw) != 32:
        raise reject("minisign_invalid", "Minisign point length is invalid.")
    encoded = int.from_bytes(raw, "little")
    sign_bit = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _Q:
        raise reject("minisign_invalid", "Minisign point is not canonical.")
    x = _x_recover(y)
    if (x & 1) != sign_bit:
        x = _Q - x
    if x == 0 and sign_bit:
        raise reject("minisign_invalid", "Minisign point sign is not canonical.")
    return (x, y, 1, x * y % _Q)


def _point_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = 2 * _D * t1 * t2 % _Q
    d = 2 * z1 * z2 % _Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _point_double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _t = point
    a, b, c = x * x % _Q, y * y % _Q, 2 * z * z % _Q
    d = -a % _Q
    e = ((x + y) * (x + y) - a - b) % _Q
    g, f, h = (d + b) % _Q, (d + b - c) % _Q, (d - b) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalar_mult(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


_BASE_Y = 4 * pow(5, _Q - 2, _Q) % _Q
_BASE_X = _x_recover(_BASE_Y)
if _BASE_X & 1:
    _BASE_X = _Q - _BASE_X
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _Q)


def _point_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return (left[0] * right[2] - right[0] * left[2]) % _Q == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % _Q == 0


def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise reject("minisign_invalid", "Minisign key or signature length is invalid.")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        raise reject("minisign_invalid", "Minisign scalar is not canonical.")
    public = _decode_point(public_key)
    encoded_r = signature[:32]
    point_r = _decode_point(encoded_r)
    if (
        _point_equal(public, _IDENTITY)
        or _point_equal(point_r, _IDENTITY)
        or not _point_equal(_scalar_mult(_L, public), _IDENTITY)
        or not _point_equal(_scalar_mult(_L, point_r), _IDENTITY)
    ):
        raise reject("minisign_invalid", "Minisign point is not in the prime-order subgroup.")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % _L
    if not _point_equal(
        _scalar_mult(scalar, _BASE), _point_add(point_r, _scalar_mult(challenge, public))
    ):
        raise reject("minisign_invalid", "Minisign signature verification failed.")


def _decode_base64(value: str, *, code: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise reject(code, "Minisign material is not canonical Base64.") from error


def load_minisign_public_key(path: Path) -> tuple[bytes, bytes]:
    encoded = _read_ordinary(path, max_bytes=16 * 1024).strip()
    try:
        text = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError) as error:
        raise reject("minisign_key_invalid", "Embedded Minisign public key is invalid.") from error
    lines = text.splitlines()
    if len(lines) != 2 or not lines[0].startswith("untrusted comment: minisign public key "):
        raise reject("minisign_key_invalid", "Embedded Minisign public key envelope is invalid.")
    blob = _decode_base64(lines[1], code="minisign_key_invalid")
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise reject("minisign_key_invalid", "Embedded Minisign public key payload is invalid.")
    return blob[2:10], blob[10:]


def verify_minisign(
    content: bytes,
    signature_bytes: bytes,
    *,
    expected_filename: str,
    public_key_path: Path,
    expected_untrusted_comment: str = MINISIGN_SIGNATURE_COMMENT,
) -> int:
    if b"\r" in signature_bytes:
        raise reject("minisign_invalid", "Minisign signature must use LF text.")
    try:
        lines = signature_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise reject("minisign_invalid", "Minisign signature is not UTF-8.") from error
    if len(lines) != 4 or lines[0] != expected_untrusted_comment:
        raise reject("minisign_invalid", "Minisign signature envelope is invalid.")
    marker = "trusted comment: timestamp:"
    if not lines[2].startswith(marker) or "\tfile:" not in lines[2]:
        raise reject("minisign_invalid", "Minisign trusted comment is invalid.")
    timestamp_text, filename = lines[2][len(marker) :].split("\tfile:", 1)
    if not timestamp_text.isdigit() or filename != expected_filename:
        raise reject("minisign_invalid", "Minisign trusted filename or timestamp is invalid.")
    key_id, public_key = load_minisign_public_key(public_key_path)
    primary = _decode_base64(lines[1], code="minisign_invalid")
    global_signature = _decode_base64(lines[3], code="minisign_invalid")
    if len(primary) != 74 or primary[:2] != b"ED" or primary[2:10] != key_id:
        raise reject("minisign_invalid", "Minisign signature does not match the trusted key id.")
    _ed25519_verify(
        public_key,
        primary[10:],
        hashlib.blake2b(content, digest_size=64).digest(),
    )
    _ed25519_verify(
        public_key,
        global_signature,
        primary[10:] + lines[2][len("trusted comment: ") :].encode("utf-8"),
    )
    return int(timestamp_text)


def decode_tauri_signature_envelope(signature_bytes: bytes) -> bytes:
    if b"\r" in signature_bytes:
        raise reject("latest_invalid", "Tauri updater signature must use canonical LF text.")
    try:
        encoded = signature_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise reject("latest_invalid", "Tauri updater signature is not ASCII Base64.") from error
    if not encoded or encoded != encoded.strip():
        raise reject("latest_invalid", "Tauri updater signature Base64 is not canonical.")
    decoded = _decode_base64(encoded, code="latest_invalid")
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise reject("latest_invalid", "Tauri updater signature Base64 is not canonical.")
    return decoded


def _validate_github_url(value: object, expected_path: str, *, code: str) -> None:
    if not isinstance(value, str):
        raise reject(code, "Release URL is missing.")
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
        or "%" in parsed.path
        or "\\" in parsed.path
    ):
        raise reject(code, "Release URL is not the exact official asset URL.")


def verify_latest_json(
    directory: Path, contract: Contract, public_key_path: Path
) -> bytes:
    value = strict_json_bytes(_read_ordinary(directory / "latest.json"), code="latest_invalid")
    if not isinstance(value, dict) or set(value) != {"version", "notes", "pub_date", "platforms"}:
        raise reject("latest_invalid", "latest.json schema is not exact.")
    platforms = value.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != {"windows-x86_64"}:
        raise reject("latest_invalid", "latest.json platform set is not exact.")
    windows = platforms["windows-x86_64"]
    if not isinstance(windows, dict) or set(windows) != {"signature", "url"}:
        raise reject("latest_invalid", "latest.json Windows entry is not exact.")
    if value.get("version") != contract.version or value.get("notes") != f"Lawyer Assistance {contract.version}":
        raise reject("latest_invalid", "latest.json version or notes do not match the contract.")
    try:
        parsed_date = dt.datetime.fromisoformat(str(value.get("pub_date")).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise reject("latest_invalid", "latest.json pub_date is invalid.") from error
    if parsed_date.tzinfo is None:
        raise reject("latest_invalid", "latest.json pub_date must include a timezone.")
    installer = contract.app_assets[0]
    _validate_github_url(
        windows.get("url"),
        f"/shilittle/Lawyer-Assistance/releases/download/{contract.app_tag}/{installer}",
        code="latest_invalid",
    )
    if not isinstance(windows.get("signature"), str):
        raise reject("latest_invalid", "latest.json updater signature is missing.")
    detached_envelope = _read_ordinary(directory / f"{installer}.sig", max_bytes=64 * 1024)
    if windows["signature"] != detached_envelope.decode("ascii"):
        raise reject("latest_signature_mismatch", "latest.json and detached updater signatures differ.")
    signature = decode_tauri_signature_envelope(detached_envelope)
    local_filename = f"Lawyer Assistance_{contract.version}_x64-setup.exe"
    installer_bytes = _read_ordinary(
        directory / installer, max_bytes=MAX_PORTABLE_MEMBER_BYTES
    )
    verify_minisign(
        installer_bytes,
        signature,
        expected_filename=local_filename,
        public_key_path=public_key_path,
        expected_untrusted_comment=TAURI_SIGNATURE_COMMENT,
    )
    return installer_bytes


def _safe_portable_name(name: str, seen: set[str]) -> PurePosixPath:
    if (
        not name
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise reject("portable_member_unsafe", "Portable archive contains an unsafe member name.")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in path.parts):
        raise reject("portable_member_unsafe", f"Portable archive member is unsafe: {name}")
    folded = name.casefold()
    if folded in seen:
        raise reject("portable_member_alias", "Portable archive contains a duplicate or case alias.")
    seen.add(folded)
    return path


def read_portable_archive(path: Path) -> dict[str, bytes]:
    _ordinary_metadata(path)
    members: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for count, info in enumerate(archive.infolist(), start=1):
                if count > MAX_PORTABLE_MEMBERS:
                    raise reject("portable_too_many_members", "Portable archive has too many members.")
                _safe_portable_name(info.filename, seen)
                unix_type = (info.external_attr >> 16) & 0o170000
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or unix_type not in {0, 0o100000}
                    or info.file_size <= 0
                    or info.file_size > MAX_PORTABLE_MEMBER_BYTES
                ):
                    raise reject("portable_member_invalid", "Portable archive contains a non-ordinary member.")
                total += info.file_size
                if total > MAX_PORTABLE_TOTAL_BYTES:
                    raise reject("portable_too_large", "Portable archive exceeds the aggregate limit.")
                raw = archive.read(info)
                if len(raw) != info.file_size:
                    raise reject("portable_member_changed", "Portable member size differs from its header.")
                members[info.filename] = raw
    except zipfile.BadZipFile as error:
        raise reject("portable_invalid", "Portable release is not a valid ZIP archive.") from error
    return members


def _require_exact_object(value: object, keys: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise reject(code, "Release manifest object schema is not exact.")
    return value


def verify_portable(
    path: Path, *, version: str, expected_commit: str, public_key_path: Path
) -> tuple[tuple[str, ...], dict[str, bytes]]:
    members = read_portable_archive(path)
    manifest_raw = members.get("release-manifest.json")
    if manifest_raw is None:
        raise reject("portable_manifest_missing", "Portable archive is missing release-manifest.json.")
    manifest = _require_exact_object(
        strict_json_bytes(manifest_raw, code="portable_manifest_invalid"),
        {
            "manifestVersion",
            "manifestScope",
            "version",
            "commit",
            "architecture",
            "buildMode",
            "generatedAt",
            "buildProvenance",
            "mcpBinary",
            "toolchain",
            "lockfiles",
            "legalDatabase",
            "updaterPublicKey",
            "files",
        },
        "portable_manifest_invalid",
    )
    if (
        manifest["manifestVersion"] != 1
        or manifest["manifestScope"]
        != "all packaged files except release-manifest.json and the external .sha256 checksum"
        or manifest["version"] != version
        or manifest["commit"] != expected_commit
        or manifest["architecture"] != "x86_64-pc-windows-msvc"
        or manifest["buildMode"] != "signed-build-provenance"
    ):
        raise reject("portable_manifest_identity", "Portable release manifest identity is invalid.")
    try:
        generated = dt.datetime.fromisoformat(str(manifest["generatedAt"]).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise reject("portable_manifest_invalid", "Portable generatedAt is invalid.") from error
    if generated.tzinfo is None:
        raise reject("portable_manifest_invalid", "Portable generatedAt must include a timezone.")
    build = _require_exact_object(
        manifest["buildProvenance"],
        {
            "sourceCommit",
            "sourceDateEpoch",
            "executablePath",
            "executableSha256",
            "mcpBinaryPath",
            "mcpBinarySha256",
        },
        "portable_manifest_invalid",
    )
    mcp = _require_exact_object(
        manifest["mcpBinary"],
        {"siblingPath", "version", "size", "sha256", "qualificationBinding"},
        "portable_manifest_invalid",
    )
    _require_exact_object(manifest["toolchain"], {"rustc", "node", "tauriCli"}, "portable_manifest_invalid")
    lockfiles = _require_exact_object(manifest["lockfiles"], {"cargoSha256", "pnpmSha256"}, "portable_manifest_invalid")
    legal = _require_exact_object(
        manifest["legalDatabase"],
        {"version", "scope", "size", "sha256", "sourceManifestSha256"},
        "portable_manifest_invalid",
    )
    app_bytes = members.get("lawyer-assistance.exe")
    mcp_bytes = members.get("lawyer-assistance-mcp.exe")
    if app_bytes is None or mcp_bytes is None:
        raise reject("portable_binary_missing", "Portable archive is missing an App or MCP binary.")
    app_hash = hashlib.sha256(app_bytes).hexdigest()
    mcp_hash = hashlib.sha256(mcp_bytes).hexdigest()
    if (
        build.get("sourceCommit") != expected_commit
        or not isinstance(build.get("sourceDateEpoch"), int)
        or isinstance(build.get("sourceDateEpoch"), bool)
        or build["sourceDateEpoch"] <= 0
        or build.get("executablePath") != "target/x86_64-pc-windows-msvc/release/lawyer-assistance.exe"
        or build.get("executableSha256") != app_hash
        or build.get("mcpBinaryPath")
        != "target/x86_64-pc-windows-msvc/release/lawyer-assistance-mcp.exe"
        or build.get("mcpBinarySha256") != mcp_hash
        or mcp
        != {
            "siblingPath": "lawyer-assistance-mcp.exe",
            "version": version,
            "size": len(mcp_bytes),
            "sha256": mcp_hash,
            "qualificationBinding": "compiled-release-sha256+canonical-path-identity+file-identity+sha256+version",
        }
    ):
        raise reject("portable_mcp_trust_anchor", "Portable App/MCP trust anchor is invalid.")
    if any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in lockfiles.values()):
        raise reject("portable_manifest_invalid", "Portable lockfile hashes are invalid.")
    if (
        not isinstance(legal.get("size"), int)
        or isinstance(legal.get("size"), bool)
        or legal["size"] <= 0
        or not isinstance(legal.get("sha256"), str)
        or SHA256.fullmatch(legal["sha256"]) is None
        or not isinstance(legal.get("sourceManifestSha256"), str)
        or SHA256.fullmatch(legal["sourceManifestSha256"]) is None
    ):
        raise reject("portable_manifest_invalid", "Portable legal resource evidence is invalid.")
    encoded_key = _read_ordinary(public_key_path, max_bytes=16 * 1024).decode("ascii").strip()
    if manifest.get("updaterPublicKey") != encoded_key:
        raise reject("portable_public_key_drift", "Portable updater public key differs from the trust anchor.")
    declared = manifest.get("files")
    if not isinstance(declared, list) or not declared:
        raise reject("portable_manifest_invalid", "Portable manifest file inventory is missing.")
    inventory: dict[str, tuple[int, str]] = {}
    previous: tuple[str, str] | None = None
    for item in declared:
        record = _require_exact_object(item, {"path", "size", "sha256"}, "portable_manifest_invalid")
        relative = record.get("path")
        size = record.get("size")
        digest = record.get("sha256")
        if (
            not isinstance(relative, str)
            or relative == "release-manifest.json"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise reject("portable_manifest_invalid", "Portable manifest contains an invalid file entry.")
        _safe_portable_name(relative, {name.casefold() for name in inventory})
        key = (relative.casefold(), relative)
        if previous is not None and key <= previous:
            raise reject("portable_manifest_order", "Portable file inventory is not canonically ordered.")
        previous = key
        inventory[relative] = (size, digest)
    actual = {name: raw for name, raw in members.items() if name != "release-manifest.json"}
    if set(inventory) != set(actual):
        raise reject("portable_manifest_coverage", "Portable manifest does not cover the archive exactly.")
    for name, raw in actual.items():
        if inventory[name] != (len(raw), hashlib.sha256(raw).hexdigest()):
            raise reject("portable_manifest_hash", f"Portable manifest hash or size failed: {name}")
    return (
        tuple(sorted(members, key=lambda name: (name.casefold(), name))),
        {
            "portable-lawyer-assistance.exe": app_bytes,
            "portable-lawyer-assistance-mcp.exe": mcp_bytes,
        },
    )


def verify_mcp_archive(
    directory: Path, filename: str, *, version: str, target: str, expected_commit: str
) -> bytes:
    archive = directory / filename
    package_root = f"lawyer-assistance-mcp-v{version}-{target}"
    try:
        members = mcp_packager._read_archive(archive)  # noqa: SLF001 - intentional verifier reuse
        mcp_packager.verify_embedded_manifest(members, package_root)
    except (OSError, mcp_packager.PackageError, zipfile.BadZipFile) as error:
        raise reject("mcp_archive_invalid", f"MCP archive verification failed: {filename}") from error
    provenance_name = f"{package_root}/PACKAGE-PROVENANCE.json"
    binary_name = "lawyer-assistance-mcp.exe" if "windows" in target else "lawyer-assistance-mcp"
    binary_path = f"{package_root}/{binary_name}"
    if provenance_name not in members or binary_path not in members:
        raise reject("mcp_provenance_missing", "MCP archive is missing binary provenance.")
    provenance_raw = members[provenance_name]
    provenance = _require_exact_object(
        strict_json_bytes(provenance_raw, code="mcp_provenance_invalid"),
        {
            "schemaVersion",
            "sourceCommit",
            "sourceCommitTimestamp",
            "sourceClean",
            "binarySha256",
            "binarySize",
            "binaryVersion",
            "binaryFresh",
            "releaseReady",
            "target",
        },
        "mcp_provenance_invalid",
    )
    binary = members[binary_path]
    expected = {
        "schemaVersion": 1,
        "sourceCommit": expected_commit,
        "sourceCommitTimestamp": provenance.get("sourceCommitTimestamp"),
        "sourceClean": True,
        "binarySha256": hashlib.sha256(binary).hexdigest(),
        "binarySize": len(binary),
        "binaryVersion": version,
        "binaryFresh": True,
        "releaseReady": True,
        "target": target,
    }
    if (
        not isinstance(provenance.get("sourceCommitTimestamp"), int)
        or isinstance(provenance.get("sourceCommitTimestamp"), bool)
        or provenance["sourceCommitTimestamp"] <= 0
        or provenance != expected
        or provenance_raw != canonical_json(provenance) + b"\n"
    ):
        raise reject("mcp_provenance_invalid", "MCP provenance is not exact release-ready HEAD evidence.")
    return binary


def _verification_output(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    _ordinary_metadata(parent, directory=True)
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise reject("verification_output_invalid", "Verification output parent is unavailable.") from error
    if os.path.normcase(str(parent)) != os.path.normcase(str(resolved_parent)):
        raise reject("verification_output_invalid", "Verification output parent must not traverse a link.")
    if absolute.exists():
        _ordinary_metadata(absolute, directory=True)
        try:
            if any(absolute.iterdir()):
                raise reject("verification_output_not_empty", "Verification output directory must be empty.")
        except OSError as error:
            raise reject("verification_output_invalid", "Verification output directory could not be read.") from error
    else:
        try:
            absolute.mkdir(mode=0o700)
        except OSError as error:
            raise reject("verification_output_invalid", "Verification output directory could not be created.") from error
        _ordinary_metadata(absolute, directory=True)
    return absolute


def write_verified_authenticode_files(
    output: Path, files: dict[str, bytes]
) -> tuple[str, ...]:
    if not files or len(files) != len({name.casefold() for name in files}):
        raise reject("verification_output_invalid", "Authenticode output inventory is invalid.")
    output = _verification_output(output)
    written: list[str] = []
    for name, raw in files.items():
        if PurePosixPath(name).name != name or not name.endswith(".exe") or not raw:
            raise reject("verification_output_invalid", "Authenticode output name or bytes are invalid.")
        destination = output / name
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(destination, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise reject("verification_output_write_failed", f"Verified executable could not be created: {name}") from error
        digest, size = _sha256_file(destination)
        if size != len(raw) or digest != hashlib.sha256(raw).hexdigest():
            raise reject("verification_output_write_failed", f"Verified executable reread failed: {name}")
        written.append(str(destination))
    return tuple(written)


def verify_app_release(
    directory: Path,
    contract: Contract,
    expected_commit: str,
    *,
    public_key_path: Path = MINERU_PUBLIC_KEY,
    verification_output: Path | None = None,
) -> VerificationReport:
    _assert_exact_names(directory, contract.app_assets)
    for filename in contract.app_assets:
        if filename.endswith(".sha256"):
            continue
        if f"{filename}.sha256" in contract.app_assets:
            verify_canonical_checksum(directory, filename)
    installer_bytes = verify_latest_json(directory, contract, public_key_path)
    portable_name = f"Lawyer-Assistance_{contract.version}_windows-x86_64-portable.zip"
    portable_members, authenticode_bytes = verify_portable(
        directory / portable_name,
        version=contract.version,
        expected_commit=expected_commit,
        public_key_path=public_key_path,
    )
    authenticode_bytes = {
        f"Lawyer.Assistance_{contract.version}_x64-setup.exe": installer_bytes,
        **authenticode_bytes,
    }
    targets = (
        ("x86_64-pc-windows-msvc", ".zip"),
        ("x86_64-unknown-linux-gnu", ".tar.gz"),
        ("aarch64-apple-darwin", ".tar.gz"),
    )
    for target, suffix in targets:
        name = f"lawyer-assistance-mcp-v{contract.version}-{target}{suffix}"
        binary = verify_mcp_archive(
            directory,
            name,
            version=contract.version,
            target=target,
            expected_commit=expected_commit,
        )
    authenticode_files = (
        write_verified_authenticode_files(verification_output, authenticode_bytes)
        if verification_output is not None
        else ()
    )
    return VerificationReport(
        "app",
        contract.version,
        expected_commit,
        contract.app_assets,
        portable_members,
        authenticode_files,
    )


def _official_mineru_path(tag: str, filename: str) -> str:
    return f"/shilittle/Lawyer-Assistance/releases/download/{tag}/{filename}"


def _catalog_entry(catalog: object, contract: Contract) -> tuple[dict[str, object], int, int]:
    value = _require_exact_object(
        catalog,
        {"schemaVersion", "catalogId", "issuedAtUnix", "expiresAtUnix", "entries"},
        "mineru_catalog_invalid",
    )
    issued = value.get("issuedAtUnix")
    expires = value.get("expiresAtUnix")
    entries = value.get("entries")
    if (
        value.get("schemaVersion") != 2
        or not isinstance(value.get("catalogId"), str)
        or not value["catalogId"]
        or not isinstance(issued, int)
        or isinstance(issued, bool)
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or issued <= 0
        or issued > int(time.time()) + 300
        or expires <= int(time.time())
        or expires <= issued
        or not isinstance(entries, list)
        or len(entries) != 1
    ):
        raise reject("mineru_catalog_invalid", "MinerU catalog identity or epoch is invalid.")
    entry = _require_exact_object(
        entries[0],
        {
            "packageId",
            "componentVersion",
            "mineruVersion",
            "protocolVersion",
            "platform",
            "packageSizeBytes",
            "packageSha256",
            "packageManifestSha256",
            "provenanceFileName",
            "provenanceSizeBytes",
            "provenanceSha256",
            "provenanceDownloadUrl",
            "downloadUrl",
            "partSetManifestSizeBytes",
            "partSetManifestSha256",
            "parts",
            "revoked",
        },
        "mineru_catalog_invalid",
    )
    if (
        entry.get("componentVersion") != contract.version
        or entry.get("protocolVersion") != mineru_packager.PROTOCOL_VERSION
        or entry.get("platform") != mineru_packager.PLATFORM
        or entry.get("provenanceFileName") != MINERU_PROVENANCE
        or entry.get("revoked") is not False
        or not isinstance(entry.get("packageSizeBytes"), int)
        or isinstance(entry.get("packageSizeBytes"), bool)
        or entry["packageSizeBytes"] <= 0
        or any(
            not isinstance(entry.get(field), str) or SHA256.fullmatch(entry[field]) is None
            for field in ("packageSha256", "packageManifestSha256", "provenanceSha256", "partSetManifestSha256")
        )
        or not isinstance(entry.get("provenanceSizeBytes"), int)
        or isinstance(entry.get("provenanceSizeBytes"), bool)
        or entry["provenanceSizeBytes"] <= 0
        or not isinstance(entry.get("partSetManifestSizeBytes"), int)
        or isinstance(entry.get("partSetManifestSizeBytes"), bool)
        or entry["partSetManifestSizeBytes"] <= 0
    ):
        raise reject("mineru_catalog_invalid", "MinerU catalog entry is not a final sharded component.")
    _validate_github_url(
        entry.get("provenanceDownloadUrl"),
        _official_mineru_path(contract.mineru_tag, MINERU_PROVENANCE),
        code="mineru_catalog_invalid",
    )
    return entry, issued, expires


def derive_mineru_assets(
    directory: Path,
    contract: Contract,
    *,
    public_key_path: Path = MINERU_PUBLIC_KEY,
) -> tuple[tuple[str, ...], dict[str, object], int]:
    catalog_path = directory / MINERU_CATALOG
    catalog_raw = _read_ordinary(catalog_path, max_bytes=2 * 1024 * 1024)
    catalog_signature = _read_ordinary(directory / f"{MINERU_CATALOG}.minisig", max_bytes=64 * 1024)
    signature_epoch = verify_minisign(
        catalog_raw,
        catalog_signature,
        expected_filename=MINERU_CATALOG,
        public_key_path=public_key_path,
    )
    catalog = strict_json_bytes(catalog_raw, code="mineru_catalog_invalid")
    if catalog_raw != canonical_json(catalog):
        raise reject("mineru_catalog_noncanonical", "MinerU catalog is not canonical JSON.")
    entry, issued, _expires = _catalog_entry(catalog, contract)
    if signature_epoch != issued:
        raise reject("mineru_signature_epoch", "MinerU catalog signature epoch differs from issuedAtUnix.")
    descriptor_url = entry.get("downloadUrl")
    if not isinstance(descriptor_url, str):
        raise reject("mineru_catalog_invalid", "MinerU descriptor URL is missing.")
    descriptor = descriptor_url.rsplit("/", 1)[-1]
    logical = f"lawyer-assistance-mineru-{contract.version}-windows-x86_64.laocrpkg"
    if descriptor != f"{logical}.laocrparts":
        raise reject("mineru_catalog_invalid", "MinerU catalog does not name the unique formal descriptor.")
    _validate_github_url(
        descriptor_url,
        _official_mineru_path(contract.mineru_tag, descriptor),
        code="mineru_catalog_invalid",
    )
    parts = entry.get("parts")
    if not isinstance(parts, list) or not 1 <= len(parts) <= mineru_packager.MAX_PARTS:
        raise reject("mineru_catalog_invalid", "MinerU catalog has no bounded ordered parts.")
    names: list[str] = [
        MINERU_CATALOG,
        f"{MINERU_CATALOG}.minisig",
        MINERU_PROVENANCE,
        f"{MINERU_PROVENANCE}.minisig",
        descriptor,
    ]
    total = 0
    for number, part_value in enumerate(parts, start=1):
        part = _require_exact_object(
            part_value,
            {"number", "fileName", "sizeBytes", "sha256", "downloadUrl"},
            "mineru_catalog_invalid",
        )
        expected_name = f"{logical}.part{number:04d}-of-{len(parts):04d}"
        if (
            part.get("number") != number
            or part.get("fileName") != expected_name
            or not isinstance(part.get("sizeBytes"), int)
            or isinstance(part.get("sizeBytes"), bool)
            or not 0 < part["sizeBytes"] < mineru_packager.GITHUB_RELEASE_ASSET_LIMIT_BYTES
            or not isinstance(part.get("sha256"), str)
            or SHA256.fullmatch(part["sha256"]) is None
        ):
            raise reject("mineru_catalog_invalid", "MinerU catalog part order or identity is invalid.")
        _validate_github_url(
            part.get("downloadUrl"),
            _official_mineru_path(contract.mineru_tag, expected_name),
            code="mineru_catalog_invalid",
        )
        total += part["sizeBytes"]
        names.append(expected_name)
    if total != entry.get("packageSizeBytes"):
        raise reject("mineru_catalog_invalid", "MinerU catalog part total differs from package size.")
    if len(set(names)) != len(names) or len({name.casefold() for name in names}) != len(names):
        raise reject("mineru_catalog_invalid", "MinerU catalog derives duplicate or aliased assets.")
    return tuple(names), entry, issued


def verify_mineru_release(
    directory: Path,
    contract: Contract,
    expected_commit: str,
    *,
    public_key_path: Path = MINERU_PUBLIC_KEY,
) -> VerificationReport:
    expected, entry, issued = derive_mineru_assets(directory, contract, public_key_path=public_key_path)
    _assert_exact_names(directory, expected)
    if any(name.endswith(".laocrpkg") for name in _directory_names(directory)):
        raise reject("mineru_unsharded_forbidden", "Unsharded .laocrpkg assets are forbidden in a sharded release.")
    provenance_path = directory / MINERU_PROVENANCE
    provenance_raw = _read_ordinary(provenance_path, max_bytes=mineru_packager.MAX_PROVENANCE_BYTES)
    provenance_signature = _read_ordinary(directory / f"{MINERU_PROVENANCE}.minisig", max_bytes=64 * 1024)
    if verify_minisign(
        provenance_raw,
        provenance_signature,
        expected_filename=MINERU_PROVENANCE,
        public_key_path=public_key_path,
    ) != issued:
        raise reject("mineru_signature_epoch", "MinerU provenance signature epoch differs from the catalog.")
    provenance = strict_json_bytes(provenance_raw, code="mineru_provenance_invalid")
    if provenance_raw != canonical_json(provenance):
        raise reject("mineru_provenance_noncanonical", "MinerU provenance is not canonical JSON.")
    source_value = provenance.get("source") if isinstance(provenance, dict) else None
    if not isinstance(source_value, dict) or source_value.get("repositoryCommit") != expected_commit:
        raise reject("mineru_provenance_commit", "MinerU provenance does not bind the exact release HEAD.")
    digest, size = _sha256_file(provenance_path)
    if digest != entry.get("provenanceSha256") or size != entry.get("provenanceSizeBytes"):
        raise reject("mineru_provenance_binding", "MinerU provenance is not catalog-bound.")
    source = mineru_packager.SourceFile(
        mineru_packager.PROVENANCE_RELATIVE, provenance_path, size, digest
    )
    try:
        mineru_packager.validate_component_provenance((source,))
        logical = directory / f"lawyer-assistance-mineru-{contract.version}-windows-x86_64.laocrpkg"
        mineru_packager.verify_sharded_package(logical, directory / MINERU_CATALOG)
    except (OSError, mineru_packager.PackageBuildError) as error:
        code = error.code if isinstance(error, mineru_packager.PackageBuildError) else "io_failure"
        raise reject("mineru_chain_invalid", f"MinerU package chain failed closed ({code}).") from error
    return VerificationReport("mineru", contract.version, expected_commit, expected)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify exact App or MinerU release assets")
    parser.add_argument("--kind", required=True, choices=("app", "mineru"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--public-key", type=Path, default=MINERU_PUBLIC_KEY)
    parser.add_argument(
        "--verification-output",
        type=Path,
        help="fresh empty output directory for already-verified Authenticode executables",
    )
    parser.add_argument(
        "--list-asset-names",
        action="store_true",
        help="print only the verified, ordered asset-name JSON array",
    )
    arguments = parser.parse_args()
    try:
        contract = load_contract(arguments.contract)
        expected_commit = validate_expected_commit(arguments.expected_commit)
        if arguments.kind == "app":
            report = verify_app_release(
                arguments.directory,
                contract,
                expected_commit,
                public_key_path=arguments.public_key,
                verification_output=arguments.verification_output,
            )
        else:
            if arguments.verification_output is not None:
                raise reject(
                    "verification_output_invalid",
                    "--verification-output applies only to the App release.",
                )
            report = verify_mineru_release(
                arguments.directory,
                contract,
                expected_commit,
                public_key_path=arguments.public_key,
            )
    except (OSError, VerificationError) as error:
        code = error.code if isinstance(error, VerificationError) else "io_failure"
        print(f"release asset verification failed [{code}]: {error}", file=sys.stderr)
        return 1
    value: object = list(report.asset_names) if arguments.list_asset_names else report.json_value()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
