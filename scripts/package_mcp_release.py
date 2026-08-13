from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "lawyer-assistance-mcp"
MAX_SUPPORT_FILE_BYTES = 8 * 1024 * 1024
MAX_SUPPORT_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MANIFEST_HEADER = "# SHA-256 and byte length for every packaged file except this manifest"
FORBIDDEN_SUFFIXES = {
    ".db",
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".lavbackup",
    ".lavprivacy",
    ".credential",
    ".secret",
    ".session",
    ".token",
}
FORBIDDEN_NAMES = {
    "apikey.txt",
    "credentials.json",
    "token.txt",
    "user.sqlite-shm",
    "user.sqlite-wal",
    "approved-session.json",
    "session-descriptor.json",
    "session.json",
    "secrets.json",
}
IGNORED_SUPPORT_NAMES = {".ds_store", "thumbs.db"}
IGNORED_SUPPORT_SUFFIXES = {".pyc", ".pyo"}
IGNORED_SUPPORT_DIRECTORIES = {"__pycache__"}
FORBIDDEN_SUPPORT_DIRECTORIES = {
    ".release-secrets",
    "attachments",
    "canaries",
    "case-fixtures",
    "case-material",
    "credentials",
    "exports",
    "fixtures",
    "secrets",
    "sessions",
    "testdata",
    "vault",
    "workspace",
}
TEXT_SUPPORT_SUFFIXES = {
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.IGNORECASE
)
TOKEN_PREFIX_PATTERN = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b"
)
BEARER_PATTERN = re.compile(
    r"\bBearer\s+(?=[A-Za-z0-9._~+/=-]{12,}(?:$|[\s,;)\]}]))"
    r"(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{12,}",
    re.IGNORECASE,
)
SESSION_ID_PATTERN = re.compile(r"\bsrv_[0-9a-f]{32}\b")
CASE_CANARY_PATTERN = re.compile(
    r"\b(?:raw[_-]?case|case[_-]?material|local)[_-]?canary\b", re.IGNORECASE
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)\b(?:api[_-]?key|access[_-]?token|bearer[_-]?token|client[_-]?secret|"
    r"session[_-]?secret|password)[\"']?\s*[:=]\s*[\"']?([^\s\"',}\]]{4,})"
)
SAFE_SECRET_VALUE_PATTERN = re.compile(
    r"^(?:\$\{|\{env:|<|[A-Z][A-Z0-9_]{5,}$|(?:redacted|placeholder|unset|none|null|"
    r"absent|missing|required)$)",
    re.IGNORECASE,
)


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


@dataclass(frozen=True)
class RepositoryProvenance:
    source_commit: str
    source_commit_timestamp: int
    source_clean: bool
    binary_sha256: str
    binary_size: int
    binary_version: str
    binary_fresh: bool
    release_ready: bool


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def workspace_version(root: Path) -> str:
    manifest = root / "Cargo.toml"
    try:
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        version = parsed["workspace"]["package"]["version"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise PackageError("workspace version could not be read") from error
    if not isinstance(version, str) or SEMVER_PATTERN.fullmatch(version) is None:
        raise PackageError("workspace version is invalid")
    return version


def _run_checked(command: list[str], root: Path) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PackageError("release provenance command could not run") from error
    if completed.returncode != 0:
        raise PackageError("release provenance command returned a nonzero status")
    return completed.stdout.strip()


def run_release_contract_gate(
    root: Path,
    mode: str,
    binary: Path | None = None,
) -> None:
    if mode not in {"current", "formal"}:
        raise PackageError("release contract mode is invalid")
    checker = root / "scripts" / "check_release_contract.py"
    contract = root / "scripts" / "release" / "release-contract-v0.4.0.json"
    command = [
        os.sys.executable,
        str(checker),
        "--root",
        str(root),
        "--contract",
        str(contract),
        "--mode",
        mode,
    ]
    if binary is not None:
        command.extend(("--mcp-binary", str(binary)))
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PackageError("release contract gate could not run") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise PackageError(f"release contract {mode} gate failed{suffix}")
    expected_stdout = f"release contract {mode} OK: {workspace_version(root)}"
    if completed.stderr or completed.stdout.strip() != expected_stdout:
        raise PackageError("release contract gate returned unexpected output")


def inspect_repository_provenance(
    root: Path,
    binary: Path,
    *,
    allow_nonrelease_inputs: bool = False,
    expected_commit: str | None = None,
) -> RepositoryProvenance:
    root = root.resolve(strict=True)
    if binary.is_symlink():
        raise PackageError("release binary must not be a symlink")
    binary = binary.resolve(strict=True)
    repository_root = Path(
        _run_checked(["git", "rev-parse", "--show-toplevel"], root)
    ).resolve(strict=True)
    if repository_root != root:
        raise PackageError("package root is not the current Git worktree")

    source_commit = _run_checked(["git", "rev-parse", "HEAD"], root).lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise PackageError("release source commit is invalid")
    if expected_commit is not None:
        normalized_expected = expected_commit.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", normalized_expected):
            raise PackageError("expected release commit is invalid")
        if source_commit != normalized_expected:
            raise PackageError("release source commit does not match the expected commit")

    timestamp_text = _run_checked(["git", "show", "-s", "--format=%ct", "HEAD"], root)
    if not timestamp_text.isdigit():
        raise PackageError("release source commit timestamp is invalid")
    source_commit_timestamp = int(timestamp_text)
    source_clean = not _run_checked(
        ["git", "status", "--porcelain=v1", "--untracked-files=normal"], root
    )

    stat = binary.stat()
    if binary.is_symlink() or not binary.is_file() or stat.st_size <= 0:
        raise PackageError("release binary must be a nonempty ordinary file")
    binary_fresh = stat.st_mtime + 2 >= source_commit_timestamp
    expected_version = workspace_version(root)
    expected_version_line = f"{PRODUCT} {expected_version}"
    actual_version_line = _run_checked([str(binary), "--version"], root)
    if actual_version_line != expected_version_line:
        raise PackageError("release binary version does not match the workspace version")

    release_ready = source_clean and binary_fresh
    if not release_ready and not allow_nonrelease_inputs:
        if not source_clean:
            raise PackageError("release packages require a clean Git worktree")
        raise PackageError("release binary predates the current source commit")
    return RepositoryProvenance(
        source_commit=source_commit,
        source_commit_timestamp=source_commit_timestamp,
        source_clean=source_clean,
        binary_sha256=sha256_bytes(binary.read_bytes()),
        binary_size=stat.st_size,
        binary_version=expected_version,
        binary_fresh=binary_fresh,
        release_ready=release_ready,
    )


def provenance_payload(provenance: RepositoryProvenance, target: str) -> Payload:
    value = {
        "schemaVersion": 1,
        "sourceCommit": provenance.source_commit,
        "sourceCommitTimestamp": provenance.source_commit_timestamp,
        "sourceClean": provenance.source_clean,
        "binarySha256": provenance.binary_sha256,
        "binarySize": provenance.binary_size,
        "binaryVersion": provenance.binary_version,
        "binaryFresh": provenance.binary_fresh,
        "releaseReady": provenance.release_ready,
        "target": target,
    }
    data = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return Payload("PACKAGE-PROVENANCE.json", data)


def _forbidden(relative: PurePosixPath) -> bool:
    name = relative.name.casefold()
    parts = {part.casefold() for part in relative.parts}
    return (
        name.startswith(".env")
        or name in FORBIDDEN_NAMES
        or relative.suffix.casefold() in FORBIDDEN_SUFFIXES
        or bool(parts & FORBIDDEN_SUPPORT_DIRECTORIES)
    )


def _scan_support_content(relative: PurePosixPath, data: bytes) -> None:
    suffix = relative.suffix.casefold()
    if suffix and suffix not in TEXT_SUPPORT_SUFFIXES:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageError(f"release text support file is not valid UTF-8: {relative}") from error
    if PRIVATE_KEY_PATTERN.search(text):
        raise PackageError(f"private key material is forbidden in release inputs: {relative}")
    if TOKEN_PREFIX_PATTERN.search(text) or BEARER_PATTERN.search(text):
        raise PackageError(f"literal access credential is forbidden in release inputs: {relative}")
    if SESSION_ID_PATTERN.search(text):
        raise PackageError(f"live approved session id is forbidden in release inputs: {relative}")
    if CASE_CANARY_PATTERN.search(text):
        raise PackageError(f"raw case canary content is forbidden in release inputs: {relative}")
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(text):
        value = match.group(1).strip()
        if not SAFE_SECRET_VALUE_PATTERN.match(value):
            raise PackageError(f"literal secret assignment is forbidden in release inputs: {relative}")


def _read_support_file(source: Path, relative: PurePosixPath) -> Payload:
    if source.is_symlink() or not source.is_file():
        raise PackageError(f"release support path is not a regular file: {relative}")
    if _forbidden(relative):
        raise PackageError(f"forbidden database or secret-like file in release inputs: {relative}")
    size = source.stat().st_size
    if size > MAX_SUPPORT_FILE_BYTES:
        raise PackageError(f"release support file exceeds 8 MiB: {relative}")
    data = source.read_bytes()
    _scan_support_content(relative, data)
    return Payload(relative.as_posix(), data)


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
            or (
                source.name.casefold().startswith("test_")
                and source.suffix.casefold() == ".py"
            )
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
    expected_title = f"# Lawyer Assistance {version}"
    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    required_markers = (
        "## Compatibility contract",
        "MCP protocol metadata",
        "Public service schema",
        "Legal archive schema",
        "User database schema",
        "## Install and migration",
        "## Known limits",
    )
    missing = [marker for marker in required_markers if marker not in text]
    if first_line != expected_title:
        missing.insert(0, expected_title)
    if missing:
        raise PackageError(
            "RELEASE_NOTES.md does not describe this version and its compatibility contract: "
            + ", ".join(missing)
        )
    return payload


def collect_payloads(
    root: Path,
    binary: Path,
    target: str,
    provenance: RepositoryProvenance | None = None,
) -> list[Payload]:
    if TARGET_PATTERN.fullmatch(target) is None:
        raise PackageError("target triple is invalid")
    expected_binary_name = f"{PRODUCT}.exe" if "windows" in target else PRODUCT
    if binary.name != expected_binary_name:
        raise PackageError(f"binary must be named {expected_binary_name} for target {target}")
    if (
        binary.is_symlink()
        or not binary.is_file()
        or binary.stat().st_size <= 0
    ):
        raise PackageError("release binary is missing or is not an ordinary file")

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
    if provenance is not None:
        binary_payload = payloads[0]
        if (
            sha256_bytes(binary_payload.data) != provenance.binary_sha256
            or len(binary_payload.data) != provenance.binary_size
            or workspace_version(root) != provenance.binary_version
        ):
            raise PackageError("release binary changed after provenance verification")
        payloads.append(provenance_payload(provenance, target))

    support_size = sum(len(payload.data) for payload in payloads if not payload.executable)
    if support_size > MAX_SUPPORT_TOTAL_BYTES:
        raise PackageError("release support files exceed the 32 MiB aggregate limit")
    paths = [payload.path for payload in payloads]
    if len(paths) != len(set(paths)):
        raise PackageError("release payload contains duplicate paths")
    return sorted(payloads, key=lambda payload: payload.path.casefold())


def manifest_payload(payloads: list[Payload]) -> Payload:
    lines = [
        MANIFEST_HEADER,
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


def _validate_archive_member_name(name: str, seen_casefold: set[str]) -> PurePosixPath:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or ":" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise PackageError("release archive contains an unsafe member name")
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PackageError(f"unsafe release archive member: {name}")
    folded = name.casefold()
    if folded in seen_casefold:
        raise PackageError("release archive contains a duplicate or case-aliased member")
    seen_casefold.add(folded)
    if _forbidden(path):
        raise PackageError(f"unsafe release archive member: {name}")
    return path


def _read_archive(archive: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    seen_casefold: set[str] = set()
    total_size = 0
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member_count, info in enumerate(package.infolist(), start=1):
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise PackageError("release ZIP contains too many members")
                _validate_archive_member_name(info.filename, seen_casefold)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or unix_mode not in {0, 0o100000}
                    or info.file_size > MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise PackageError("release ZIP contains a non-ordinary or oversized member")
                total_size += info.file_size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    raise PackageError("release ZIP exceeds the aggregate size limit")
                data = package.read(info)
                if len(data) != info.file_size:
                    raise PackageError("release ZIP member size differs from its header")
                members[info.filename] = data
    else:
        with tarfile.open(archive, mode="r:gz") as package:
            for member_count, info in enumerate(package, start=1):
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise PackageError("release tarball contains too many members")
                _validate_archive_member_name(info.name, seen_casefold)
                if not info.isfile() or info.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise PackageError("release tarball contains a non-file or oversized member")
                total_size += info.size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    raise PackageError("release tarball exceeds the aggregate size limit")
                extracted = package.extractfile(info)
                if extracted is None:
                    raise PackageError("release tarball member could not be read")
                data = extracted.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(data) != info.size:
                    raise PackageError("release tarball member size differs from its header")
                members[info.name] = data
    return members


def verify_embedded_manifest(members: dict[str, bytes], package_root: str) -> None:
    if (
        not package_root
        or PurePosixPath(package_root).name != package_root
        or any(character in package_root for character in "/\\:")
    ):
        raise PackageError("release package root is invalid")
    manifest_name = f"{package_root}/MANIFEST.sha256"
    if manifest_name not in members:
        raise PackageError("release archive is missing its embedded manifest")
    manifest_data = members[manifest_name]
    if not manifest_data.endswith(b"\n") or b"\r" in manifest_data:
        raise PackageError("release embedded manifest must use canonical LF text")
    try:
        manifest_text = manifest_data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageError("release embedded manifest is not valid UTF-8") from error
    lines = manifest_text.splitlines()
    if not lines or lines[0] != MANIFEST_HEADER:
        raise PackageError("release embedded manifest header is invalid")

    prefix = f"{package_root}/"
    actual_payloads: dict[str, bytes] = {}
    seen_archive_names: set[str] = set()
    for name, data in members.items():
        _validate_archive_member_name(name, seen_archive_names)
        if not name.startswith(prefix):
            raise PackageError("release archive contains a member outside its package root")
        relative_name = name[len(prefix) :]
        relative = PurePosixPath(relative_name)
        if (
            not relative_name
            or relative.is_absolute()
            or relative.as_posix() != relative_name
            or any(part in {"", ".", ".."} for part in relative.parts)
            or _forbidden(relative)
        ):
            raise PackageError(f"unsafe release archive member: {name}")
        if relative_name != "MANIFEST.sha256":
            actual_payloads[relative_name] = data

    declared: dict[str, tuple[str, int]] = {}
    seen_declared_casefold: set[str] = set()
    previous_sort_key: tuple[str, str] | None = None
    entry_pattern = re.compile(r"^([0-9a-f]{64})  ([0-9]+)  (.+)$")
    for line in lines[1:]:
        match = entry_pattern.fullmatch(line)
        if match is None:
            raise PackageError("release embedded manifest contains a malformed entry")
        digest, size_text, relative_name = match.groups()
        relative = PurePosixPath(relative_name)
        if (
            relative_name == "MANIFEST.sha256"
            or relative.is_absolute()
            or relative.as_posix() != relative_name
            or any(part in {"", ".", ".."} for part in relative.parts)
            or ":" in relative_name
            or "\\" in relative_name
            or _forbidden(relative)
        ):
            raise PackageError("release embedded manifest contains an unsafe path")
        if size_text != str(int(size_text)):
            raise PackageError("release embedded manifest contains a noncanonical size")
        folded = relative_name.casefold()
        if folded in seen_declared_casefold:
            raise PackageError("release embedded manifest contains a duplicate path")
        seen_declared_casefold.add(folded)
        sort_key = (folded, relative_name)
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise PackageError("release embedded manifest entries are not canonically sorted")
        previous_sort_key = sort_key
        declared[relative_name] = (digest, int(size_text))

    if set(declared) != set(actual_payloads):
        raise PackageError("release embedded manifest does not cover the archive exactly")
    for relative_name, data in actual_payloads.items():
        digest, size = declared[relative_name]
        if size != len(data) or digest != sha256_bytes(data):
            raise PackageError("release embedded manifest hash or size verification failed")

def verify_archive(archive: Path, package_root: str, payloads: list[Payload]) -> None:
    members = _read_archive(archive)
    verify_embedded_manifest(members, package_root)
    expected = {f"{package_root}/{payload.path}": payload.data for payload in payloads}
    if members != expected:
        raise PackageError("release archive contents differ from the verified payload")


def build_package(
    root: Path,
    binary: Path,
    target: str,
    output_dir: Path,
    provenance: RepositoryProvenance | None = None,
) -> PackageResult:
    root = root.resolve(strict=True)
    if binary.is_symlink():
        raise PackageError("release binary must not be a symlink")
    binary = binary.resolve(strict=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise PackageError("release output directory must be an ordinary directory")
    output_dir = output_dir.resolve(strict=True)
    version = workspace_version(root)
    package_root = f"{PRODUCT}-v{version}-{target}"
    if provenance is not None and not provenance.release_ready:
        package_root += "-NONRELEASE"
    suffix = ".zip" if "windows" in target else ".tar.gz"
    archive = output_dir / f"{package_root}{suffix}"
    checksum = Path(f"{archive}.sha256")
    for destination in (archive, checksum):
        if destination.exists() and (
            destination.is_symlink() or not destination.is_file()
        ):
            raise PackageError("release destination must be absent or an ordinary file")

    payloads = collect_payloads(root, binary, target, provenance)
    payloads.append(manifest_payload(payloads))
    payloads.sort(key=lambda payload: payload.path.casefold())

    archive_temporary: Path | None = None
    checksum_temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output_dir,
            prefix=f".{package_root}.",
            suffix=suffix,
            delete=False,
        ) as temporary:
            archive_temporary = Path(temporary.name)
        if suffix == ".zip":
            _write_zip(archive_temporary, package_root, payloads)
        else:
            _write_tar_gz(archive_temporary, package_root, payloads)
        verify_archive(archive_temporary, package_root, payloads)
        digest = sha256_bytes(archive_temporary.read_bytes())

        with tempfile.NamedTemporaryFile(
            dir=output_dir,
            prefix=f".{package_root}.",
            suffix=".sha256",
            delete=False,
        ) as temporary:
            checksum_temporary = Path(temporary.name)
        checksum_temporary.write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n"
        )
        os.replace(archive_temporary, archive)
        archive_temporary = None
        os.replace(checksum_temporary, checksum)
        checksum_temporary = None
    finally:
        if archive_temporary is not None:
            archive_temporary.unlink(missing_ok=True)
        if checksum_temporary is not None:
            checksum_temporary.unlink(missing_ok=True)

    return PackageResult(archive, checksum, digest, package_root, len(payloads))

def main() -> int:
    parser = argparse.ArgumentParser(description="Build and verify a database-free MCP release archive")
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "mcp")
    parser.add_argument(
        "--expected-commit",
        help="require the full 40-character source commit used for the release",
    )
    parser.add_argument(
        "--allow-nonrelease-inputs",
        action="store_true",
        help="allow dirty or stale inputs only for local preflight; the package is marked releaseReady=false",
    )
    parser.add_argument(
        "--version-gate-mode",
        choices=("current", "formal"),
        default="formal",
        help="use current only for pre-stable CI; direct release packaging defaults to formal",
    )
    arguments = parser.parse_args()
    result: PackageResult | None = None
    try:
        run_release_contract_gate(ROOT, arguments.version_gate_mode)
        provenance = inspect_repository_provenance(
            ROOT,
            arguments.binary,
            allow_nonrelease_inputs=arguments.allow_nonrelease_inputs,
            expected_commit=arguments.expected_commit,
        )
        run_release_contract_gate(
            ROOT,
            arguments.version_gate_mode,
            arguments.binary,
        )
        result = build_package(
            ROOT,
            arguments.binary,
            arguments.target,
            arguments.output_dir,
            provenance,
        )
        provenance_after = inspect_repository_provenance(
            ROOT,
            arguments.binary,
            allow_nonrelease_inputs=arguments.allow_nonrelease_inputs,
            expected_commit=provenance.source_commit,
        )
        if provenance_after != provenance:
            raise PackageError("release source or binary changed while packaging")
    except (OSError, PackageError, tarfile.TarError, zipfile.BadZipFile) as error:
        if result is not None:
            result.archive.unlink(missing_ok=True)
            result.checksum.unlink(missing_ok=True)
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
                "source_commit": provenance.source_commit,
                "source_clean": provenance.source_clean,
                "binary_version": provenance.binary_version,
                "binary_sha256": provenance.binary_sha256,
                "release_ready": provenance.release_ready,
            },
            ensure_ascii=False,
        )
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
