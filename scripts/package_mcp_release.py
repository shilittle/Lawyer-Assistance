from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "lawyer-assistance-mcp"
MAX_SUPPORT_FILE_BYTES = 8 * 1024 * 1024
MAX_SUPPORT_TOTAL_BYTES = 32 * 1024 * 1024
FORBIDDEN_SUFFIXES = {
    ".db",
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_NAMES = {
    "apikey.txt",
    "credentials.json",
    "token.txt",
    "user.sqlite-shm",
    "user.sqlite-wal",
}
IGNORED_SUPPORT_NAMES = {".ds_store", "thumbs.db"}
IGNORED_SUPPORT_SUFFIXES = {".pyc", ".pyo"}
IGNORED_SUPPORT_DIRECTORIES = {"__pycache__"}


class PackageError(RuntimeError):
    pass


@dataclass(frozen=True)
class Payload:
    path: str
    data: bytes
    executable: bool = False


@dataclass(frozen=True)
class PackageResult:
    archive: Path
    checksum: Path
    sha256: str
    package_root: str
    files: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def workspace_version(root: Path) -> str:
    manifest = root / "Cargo.toml"
    try:
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        version = parsed["workspace"]["package"]["version"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise PackageError("workspace version could not be read") from error
    if not isinstance(version, str) or not version or any(character.isspace() for character in version):
        raise PackageError("workspace version is invalid")
    return version


def _forbidden(relative: PurePosixPath) -> bool:
    name = relative.name.casefold()
    return name in FORBIDDEN_NAMES or relative.suffix.casefold() in FORBIDDEN_SUFFIXES


def _read_support_file(source: Path, relative: PurePosixPath) -> Payload:
    if source.is_symlink() or not source.is_file():
        raise PackageError(f"release support path is not a regular file: {relative}")
    if _forbidden(relative):
        raise PackageError(f"forbidden database or secret-like file in release inputs: {relative}")
    size = source.stat().st_size
    if size > MAX_SUPPORT_FILE_BYTES:
        raise PackageError(f"release support file exceeds 8 MiB: {relative}")
    return Payload(relative.as_posix(), source.read_bytes())


def _tree_payloads(source_root: Path, archive_root: PurePosixPath) -> list[Payload]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise PackageError(f"release support directory is unavailable: {archive_root}")
    payloads: list[Payload] = []
    for source in sorted(source_root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if source.is_symlink():
            raise PackageError(f"symlink is not allowed in release inputs: {source.name}")
        source_relative = source.relative_to(source_root)
        if (
            any(part.casefold() in IGNORED_SUPPORT_DIRECTORIES for part in source_relative.parts)
            or source.name.casefold() in IGNORED_SUPPORT_NAMES
            or source.suffix.casefold() in IGNORED_SUPPORT_SUFFIXES
        ):
            continue
        if source.is_dir():
            continue
        relative = archive_root / PurePosixPath(source_relative.as_posix())
        payloads.append(_read_support_file(source, relative))
    return payloads


def _release_notes_payload(root: Path, version: str) -> Payload:
    relative = PurePosixPath("RELEASE_NOTES.md")
    payload = _read_support_file(root / relative, relative)
    try:
        text = payload.data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageError("RELEASE_NOTES.md must be valid UTF-8") from error
    required_markers = (
        f"# Lawyer Assistance MCP {version}",
        "## Compatibility contract",
        "MCP protocol metadata",
        "Public service schema",
        "Legal archive schema",
        "User database schema",
        "## Install and migration",
        "## Known limits",
    )
    missing = [marker for marker in required_markers if marker not in text]
    if missing:
        raise PackageError(
            "RELEASE_NOTES.md does not describe this version and its compatibility contract: "
            + ", ".join(missing)
        )
    return payload


def collect_payloads(root: Path, binary: Path, target: str) -> list[Payload]:
    if not target or any(character.isspace() for character in target):
        raise PackageError("target triple is invalid")
    expected_binary_name = f"{PRODUCT}.exe" if "windows" in target else PRODUCT
    if binary.name != expected_binary_name:
        raise PackageError(f"binary must be named {expected_binary_name} for target {target}")
    if binary.is_symlink() or not binary.is_file():
        raise PackageError("release binary is missing or is not a regular file")

    direct_files = [
        (root / "LICENSE", PurePosixPath("LICENSE")),
        (root / "README.md", PurePosixPath("README.md")),
        (
            root / "apps" / "desktop" / "src-tauri" / "resources" / "THIRD_PARTY_NOTICES.txt",
            PurePosixPath("THIRD_PARTY_NOTICES.txt"),
        ),
    ]
    payloads = [Payload(expected_binary_name, binary.read_bytes(), executable=True)]
    payloads.extend(_read_support_file(source, relative) for source, relative in direct_files)
    payloads.append(_release_notes_payload(root, workspace_version(root)))
    payloads.extend(_tree_payloads(root / "docs" / "mcp", PurePosixPath("docs/mcp")))
    payloads.extend(_tree_payloads(root / "integrations", PurePosixPath("integrations")))

    support_size = sum(len(payload.data) for payload in payloads if not payload.executable)
    if support_size > MAX_SUPPORT_TOTAL_BYTES:
        raise PackageError("release support files exceed the 32 MiB aggregate limit")
    paths = [payload.path for payload in payloads]
    if len(paths) != len(set(paths)):
        raise PackageError("release payload contains duplicate paths")
    return sorted(payloads, key=lambda payload: payload.path.casefold())


def manifest_payload(payloads: list[Payload]) -> Payload:
    lines = [
        "# SHA-256 and byte length for every packaged file except this manifest",
        *[
            f"{sha256_bytes(payload.data)}  {len(payload.data)}  {payload.path}"
            for payload in payloads
        ],
    ]
    return Payload("MANIFEST.sha256", ("\n".join(lines) + "\n").encode("utf-8"))


def _write_zip(archive: Path, package_root: str, payloads: list[Payload]) -> None:
    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as package:
        for payload in payloads:
            info = zipfile.ZipInfo(f"{package_root}/{payload.path}", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = ((0o755 if payload.executable else 0o644) & 0xFFFF) << 16
            package.writestr(info, payload.data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _write_tar_gz(archive: Path, package_root: str, payloads: list[Payload]) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as package:
                for payload in payloads:
                    info = tarfile.TarInfo(f"{package_root}/{payload.path}")
                    info.size = len(payload.data)
                    info.mode = 0o755 if payload.executable else 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    package.addfile(info, io.BytesIO(payload.data))


def _read_archive(archive: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for info in package.infolist():
                if info.is_dir() or info.filename in members:
                    raise PackageError("release ZIP contains an invalid or duplicate member")
                members[info.filename] = package.read(info)
    else:
        with tarfile.open(archive, mode="r:gz") as package:
            for info in package.getmembers():
                if not info.isfile() or info.name in members:
                    raise PackageError("release tarball contains a non-file or duplicate member")
                extracted = package.extractfile(info)
                if extracted is None:
                    raise PackageError("release tarball member could not be read")
                members[info.name] = extracted.read()
    return members


def verify_archive(archive: Path, package_root: str, payloads: list[Payload]) -> None:
    members = _read_archive(archive)
    expected = {f"{package_root}/{payload.path}": payload.data for payload in payloads}
    if members != expected:
        raise PackageError("release archive contents differ from the verified payload")
    for member in members:
        path = PurePosixPath(member)
        if path.is_absolute() or ".." in path.parts or _forbidden(path):
            raise PackageError(f"unsafe release archive member: {member}")


def build_package(root: Path, binary: Path, target: str, output_dir: Path) -> PackageResult:
    root = root.resolve(strict=True)
    binary = binary.resolve(strict=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    version = workspace_version(root)
    package_root = f"{PRODUCT}-v{version}-{target}"
    suffix = ".zip" if "windows" in target else ".tar.gz"
    archive = output_dir / f"{package_root}{suffix}"
    payloads = collect_payloads(root, binary, target)
    payloads.append(manifest_payload(payloads))
    payloads.sort(key=lambda payload: payload.path.casefold())
    if suffix == ".zip":
        _write_zip(archive, package_root, payloads)
    else:
        _write_tar_gz(archive, package_root, payloads)
    verify_archive(archive, package_root, payloads)
    digest = sha256_bytes(archive.read_bytes())
    checksum = Path(f"{archive}.sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n")
    return PackageResult(archive, checksum, digest, package_root, len(payloads))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and verify a database-free MCP release archive")
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "mcp")
    arguments = parser.parse_args()
    try:
        result = build_package(ROOT, arguments.binary, arguments.target, arguments.output_dir)
    except (OSError, PackageError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"MCP packaging failed: {error}", file=os.sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "archive": str(result.archive),
                "checksum": str(result.checksum),
                "sha256": result.sha256,
                "package_root": result.package_root,
                "files": result.files,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
