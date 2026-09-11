"""Package an explicitly selected, byte-verified QA evidence inventory.

The inventory is intentionally required.  This prevents a validation archive
from silently reusing the retired ``work/audit-repair`` directory.  Each
selected file is checked before it is copied, and the archive contains the
same byte hashes plus the baseline and source revisions used for the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
EXECUTABLE_SUFFIXES = {
    ".7z",
    ".a",
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".bin",
    ".cab",
    ".class",
    ".dylib",
    ".dll",
    ".exe",
    ".jar",
    ".lib",
    ".msi",
    ".o",
    ".obj",
    ".pdb",
    ".ps1",
    ".pyc",
    ".pyo",
    ".rar",
    ".scr",
    ".so",
    ".sys",
    ".wasm",
    ".vbs",
}
# The explicit baseline archive is a source checkout.  PowerShell/batch/VBS
# files in that checkout are source text; compiled payloads remain forbidden.
BASELINE_EXECUTABLE_SUFFIXES = EXECUTABLE_SUFFIXES - {".bat", ".cmd", ".ps1", ".vbs"}
DATABASE_SUFFIXES = {
    ".accdb",
    ".db",
    ".mdb",
    ".sqlite",
    ".sqlite3",
    ".sqlite-shm",
    ".sqlite-wal",
}
PRIVATE_BINARY_SUFFIXES = {".dpapi", ".key", ".pem", ".pfx"}
PRIVATE_NAMES = {
    ".env",
    "apikey.txt",
    "credentials",
    "cookies",
    "cookies-journal",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "login data",
    "passwords",
    "secrets",
    "token",
}
PRIVATE_PARTS = {
    ".config",
    ".credentials",
    "credentials",
    "secrets",
    "user data",
}
PROFILE_PARTS = {
    "audit_repair",
    "browser-profile",
    "browser_profile",
    "chrome-profile",
    "edge-profile",
    "firefox-profile",
    "user-workspace",
    "workspace",
}
PROFILE_PREFIXES = (
    "browser-profile-",
    "browser-profile_",
    "browser_profile-",
    "browser_profile_",
    "user-workspace-",
    "user-workspace_",
    "workspace-",
    "workspace_",
)
BASELINE_SOURCE_ZIP = PurePosixPath("work/retest-121/baseline-source.zip")


class ValidationPackageError(RuntimeError):
    """A deterministic, user-facing validation packaging failure."""


@dataclass(frozen=True)
class InventoryEntry:
    source_path: Path
    archive_path: str
    expected_bytes: int
    expected_sha256: str
    kind: str | None = None


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise ValidationPackageError(f"unable to read inventory file: {path}") from error


def git_revision(root: Path, revision: str) -> str:
    try:
        value = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
            cwd=root,
            stderr=subprocess.STDOUT,
        ).decode("ascii", "replace").strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValidationPackageError(f"git revision could not be resolved: {revision}") from error
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValidationPackageError(f"git revision is not a commit: {revision}")
    return value


def workspace_version(root: Path) -> str:
    try:
        value = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise ValidationPackageError("workspace version could not be read") from error
    if not isinstance(value, str) or not value or any(c not in "0123456789.+-" for c in value):
        raise ValidationPackageError("workspace version is invalid")
    return value


def validate_label(label: str) -> str:
    if not LABEL_PATTERN.fullmatch(label) or len(label) > 96:
        raise ValidationPackageError("label must contain only letters, digits, '.', '_' or '-'")
    return label


def _inventory_items(document: object) -> list[object]:
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        raise ValidationPackageError("inventory must be a JSON list or an object containing files")
    for key in ("files", "entries", "paths"):
        value = document.get(key)
        if isinstance(value, list):
            return value
    raise ValidationPackageError("inventory has no files list")


def _expected_size(item: dict[str, object]) -> int | None:
    for key in ("bytes", "size_bytes", "size"):
        if key in item:
            value = item[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValidationPackageError("inventory entry has an invalid byte length")
            return value
    return None


def _expected_hash(item: dict[str, object]) -> str | None:
    value = item.get("sha256")
    if value is None:
        return None
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValidationPackageError("inventory entry has an invalid SHA-256")
    return value.lower()


def _normal_path(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        raise ValidationPackageError(f"dangerous inventory path: {value}")
    return path


def _is_baseline_source_zip(path: PurePosixPath) -> bool:
    return path == BASELINE_SOURCE_ZIP


def _inventory_kind(raw: dict[str, object]) -> str | None:
    value = raw.get("kind")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationPackageError("inventory entry kind is invalid")
    return value.strip().lower()


def _reject_sensitive_path(path: PurePosixPath) -> None:
    lowered = tuple(part.lower() for part in path.parts)
    basename = lowered[-1]
    if "audit-repair" in lowered or "audit_repair" in lowered:
        raise ValidationPackageError("retired work/audit-repair evidence is not accepted")
    source_service = len(lowered) >= 2 and lowered[:2] == ("crates", "workspace-service")
    if not source_service and (
        any(part in PROFILE_PARTS for part in lowered[:-1])
        or any(part.startswith(prefix) for part in lowered[:-1] for prefix in PROFILE_PREFIXES)
        or ("browser" in lowered[:-1] and "profile" in lowered[:-1])
    ):
        raise ValidationPackageError(f"workspace or browser profile is not accepted: {path}")
    suffix = path.suffix.lower()
    if suffix in EXECUTABLE_SUFFIXES:
        raise ValidationPackageError(f"executable is not accepted: {path}")
    if suffix in DATABASE_SUFFIXES:
        raise ValidationPackageError(f"database is not accepted: {path}")
    if basename.endswith("-journal") or basename.endswith("-shm") or basename.endswith("-wal"):
        raise ValidationPackageError(f"database sidecar is not accepted: {path}")
    if suffix in PRIVATE_BINARY_SUFFIXES:
        raise ValidationPackageError(f"private credential material is not accepted: {path}")
    if (
        any(part in PRIVATE_PARTS for part in lowered)
        or basename in PRIVATE_NAMES
        or basename.startswith(".env")
        or basename.startswith(("credential.", "credentials.", "secret.", "secrets.", "token."))
    ):
        raise ValidationPackageError(f"private credential or browser data is not accepted: {path}")
    if suffix == ".zip" and not _is_baseline_source_zip(path):
        raise ValidationPackageError(f"archive is not accepted unless it is the explicit baseline source zip: {path}")


def _has_symlink_component(path: Path, root: Path) -> bool:
    current = root
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def read_inventory(path: Path, root: Path = ROOT) -> tuple[InventoryEntry, ...]:
    if path.is_symlink() or not path.is_file():
        raise ValidationPackageError(f"inventory is missing or is a symlink: {path}")
    path = path.resolve()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationPackageError("inventory JSON could not be read") from error
    entries: list[InventoryEntry] = []
    seen: set[str] = set()
    root = root.resolve()
    for raw in _inventory_items(document):
        if isinstance(raw, str):
            item: dict[str, object] = {"path": raw}
        elif isinstance(raw, dict):
            item = raw
        else:
            raise ValidationPackageError("inventory entry must be a path string or object")
        value = item.get("path")
        if not isinstance(value, str):
            raise ValidationPackageError("inventory entry has no path")
        relative = _normal_path(value)
        _reject_sensitive_path(relative)
        kind = _inventory_kind(item)
        # A path-only inventory is itself an explicit selection.  Preserve an
        # explicit kind when supplied, while treating the one exact rebuilt
        # baseline path as a source archive for the legacy path-list form.
        if _is_baseline_source_zip(relative) and kind is None:
            kind = "source_archive"
        if _is_baseline_source_zip(relative) and kind != "source_archive":
            raise ValidationPackageError("baseline source zip kind must be source_archive")
        if kind == "source_archive" and not _is_baseline_source_zip(relative):
            raise ValidationPackageError("source_archive kind is only allowed for the baseline source zip")
        source = root / Path(*relative.parts)
        if _has_symlink_component(source, root) or not source.is_file() or source.is_symlink():
            raise ValidationPackageError(f"inventory file is missing or is a symlink: {value}")
        try:
            source = source.resolve(strict=True)
        except OSError as error:
            raise ValidationPackageError(f"inventory file could not be resolved: {value}") from error
        if not source.is_relative_to(root):
            raise ValidationPackageError(f"inventory file escapes repository root: {value}")
        archive_value = item.get("archive_path", value.replace("\\", "/"))
        if not isinstance(archive_value, str):
            raise ValidationPackageError("inventory archive_path is invalid")
        archive_relative = _normal_path(archive_value)
        _reject_sensitive_path(archive_relative)
        if _is_baseline_source_zip(archive_relative) and not _is_baseline_source_zip(relative):
            raise ValidationPackageError("baseline source zip archive_path must select the baseline source zip")
        if _is_baseline_source_zip(archive_relative) and kind is None:
            kind = "source_archive"
        if _is_baseline_source_zip(archive_relative) and kind != "source_archive":
            raise ValidationPackageError("baseline source zip archive kind must be source_archive")
        if kind == "source_archive" and not _is_baseline_source_zip(archive_relative):
            raise ValidationPackageError("source_archive archive_path must be the baseline source zip")
        archive_path = archive_relative.as_posix()
        if archive_path.lower() == "evidence_manifest.json":
            raise ValidationPackageError("inventory archive_path is reserved for the generated manifest")
        if archive_path in seen:
            raise ValidationPackageError(f"inventory contains a duplicate path: {archive_path}")
        seen.add(archive_path)
        expected_bytes = _expected_size(item)
        expected_sha256 = _expected_hash(item)
        actual_bytes = source.stat().st_size
        if expected_bytes is not None and actual_bytes != expected_bytes:
            raise ValidationPackageError(f"inventory byte length mismatch: {value}")
        actual_sha256 = sha256_file(source)
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise ValidationPackageError(f"inventory SHA-256 mismatch: {value}")
        entries.append(
            InventoryEntry(
                source,
                archive_path,
                actual_bytes if expected_bytes is None else expected_bytes,
                actual_sha256 if expected_sha256 is None else expected_sha256,
                kind,
            )
        )
    if not entries:
        raise ValidationPackageError("inventory is empty")
    return tuple(entries)


def _reject_baseline_member(path: PurePosixPath) -> None:
    """Apply the evidence archive's path policy to a source ZIP member."""

    if not path.parts or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValidationPackageError("baseline source zip contains a dangerous member path")
    lowered = tuple(part.lower() for part in path.parts)
    basename = lowered[-1]
    # The rebuilt baseline is itself a repository archive and legitimately has
    # paths such as ``crates/workspace-service``.  Reject only the retired
    # evidence/profile roots, plus a top-level user workspace directory.
    source_service = len(lowered) >= 2 and lowered[:2] == ("crates", "workspace-service")
    if not source_service and (
        any(part in PROFILE_PARTS for part in lowered[:-1])
        or any(part.startswith(prefix) for part in lowered[:-1] for prefix in PROFILE_PREFIXES)
        or ("browser" in lowered[:-1] and "profile" in lowered[:-1])
    ):
        raise ValidationPackageError("baseline source zip contains a workspace or browser profile")
    if (
        any(part in PRIVATE_PARTS for part in lowered)
        or basename in PRIVATE_NAMES
        or basename.startswith(".env")
    ):
        raise ValidationPackageError("baseline source zip contains private credential or browser data")
    suffix = path.suffix.lower()
    if suffix in BASELINE_EXECUTABLE_SUFFIXES:
        raise ValidationPackageError("baseline source zip contains an executable")
    if suffix in DATABASE_SUFFIXES or basename.endswith(("-journal", "-shm", "-wal")):
        raise ValidationPackageError("baseline source zip contains a database or sidecar")
    if suffix in PRIVATE_BINARY_SUFFIXES:
        raise ValidationPackageError("baseline source zip contains private credential material")


def _zip_baseline_source_is_safe(content: bytes) -> None:
    """Reject traversal, links, and protected payloads in the allowed source ZIP."""

    import io

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as source_zip:
            for item in source_zip.infolist():
                if "\x00" in item.filename:
                    raise ValidationPackageError("baseline source zip contains a NUL member path")
                member = PurePosixPath(item.filename.replace("\\", "/"))
                _reject_baseline_member(member)
                mode = (item.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ValidationPackageError("baseline source zip contains a symlink member")
    except zipfile.BadZipFile as error:
        raise ValidationPackageError("baseline source zip is not a valid ZIP") from error


def package_validation(
    inventory: Path,
    *,
    base: str,
    label: str,
    output_dir: Path | None = None,
    root: Path = ROOT,
) -> dict[str, object]:
    root = root.resolve()
    output_dir = (output_dir or root / "dist").resolve()
    selected_label = validate_label(label)
    base_revision = git_revision(root, base)
    source_revision = git_revision(root, "HEAD")
    version = workspace_version(root)
    inventory_path = inventory if inventory.is_absolute() else root / inventory
    inventory_path = inventory_path.resolve()
    entries = read_inventory(inventory_path, root)
    payload: dict[str, bytes] = {}
    manifest_files: list[dict[str, object]] = []
    for entry in entries:
        content = entry.source_path.read_bytes()
        if len(content) != entry.expected_bytes or sha256_bytes(content) != entry.expected_sha256:
            raise ValidationPackageError(f"inventory file changed after verification: {entry.source_path}")
        if entry.archive_path == BASELINE_SOURCE_ZIP.as_posix():
            _zip_baseline_source_is_safe(content)
        payload[entry.archive_path] = content
        manifest_file = {
            "path": entry.archive_path,
            "source_path": entry.source_path.relative_to(root).as_posix(),
            "bytes": entry.expected_bytes,
            "sha256": entry.expected_sha256,
        }
        if entry.kind is not None:
            manifest_file["kind"] = entry.kind
        manifest_files.append(manifest_file)
    manifest = {
        "format_version": 2,
        "product": "Lawyer Assistance",
        "candidate": "1.2.1",
        "version": version,
        "label": selected_label,
        "base_revision": base_revision,
        "source_revision": source_revision,
        "inventory_sha256": sha256_file(inventory_path),
        "files": sorted(manifest_files, key=lambda item: str(item["path"])),
    }
    payload["EVIDENCE_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    name = f"Lawyer-Assistance_{version}_validation_{selected_label}"
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{name}.zip"
    checksum = output_dir / f"{name}.zip.sha256"
    manifest_path = output_dir / f"{name}.manifest.json"
    for path in (archive, checksum, manifest_path):
        if path.exists() or path.is_symlink():
            raise ValidationPackageError(f"refusing to overwrite existing artifact: {path}")
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for relative, content in sorted(payload.items()):
            info = zipfile.ZipInfo(f"{name}/{relative}", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, content)
    archive_hash = sha256_file(archive)
    checksum.write_text(f"{archive_hash}  {archive.name}\n", encoding="ascii", newline="\n")
    external_manifest = dict(manifest)
    external_manifest.update({"archive": archive.name, "archive_sha256": archive_hash})
    manifest_path.write_text(json.dumps(external_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {
        "archive": str(archive),
        "checksum": str(checksum),
        "manifest": str(manifest_path),
        "files": len(payload),
        "bytes": archive.stat().st_size,
        "sha256": archive_hash,
        "base_revision": base_revision,
        "source_revision": source_revision,
        "label": selected_label,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="JSON inventory of selected paths (optional bytes/sha256 are verified when present)",
    )
    parser.add_argument("--base", required=True, help="baseline commit recorded in the evidence manifest")
    parser.add_argument("--label", required=True, help="safe artifact label, e.g. 20260911-01cf195")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=ROOT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = package_validation(
            args.inventory,
            base=args.base,
            label=args.label,
            output_dir=args.output_dir,
            root=args.root,
        )
    except ValidationPackageError as error:
        print(f"validation packaging failed: {error}")
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
