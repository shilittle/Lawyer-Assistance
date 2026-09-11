"""Create a deterministic source snapshot and an explicit baseline increment.

The snapshot is made from the current checkout.  ``--base`` controls the
binary Git patch recorded in the archive, so committed changes after a review
baseline remain visible even when the working tree is clean.  The source
inventory is byte based: no newline conversion or exact-tag lookup is used.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_MAX_BYTES = 16 * 1024 * 1024
EXCLUDED_PARTS = {
    ".git",
    ".release-secrets",
    "dist",
    "node_modules",
    "output",
    "target",
    "work",
}
WORKSPACE_PARTS = {
    "browser-profile",
    "browser_profile",
    "user-workspace",
    "workspace",
}
WORKSPACE_PREFIXES = (
    "browser-profile-",
    "browser-profile_",
    "browser_profile-",
    "browser_profile_",
    "user-workspace-",
    "user-workspace_",
    "workspace-",
    "workspace_",
)
PRIVATE_BASENAMES = {
    ".env",
    "apikey.txt",
    "credentials",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "secrets",
    "token",
}
PRIVATE_SUFFIXES = {".dpapi", ".key", ".pem", ".pfx", ".sqlite", ".sqlite3", ".db"}
LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class SourcePackageError(RuntimeError):
    """A deterministic, user-facing source packaging failure."""


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise SourcePackageError(f"unable to read {path}") from error


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = error.output.decode("utf-8", "replace").strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        raise SourcePackageError(f"git {' '.join(args)} failed: {detail}") from error


def repository_root(root: Path) -> Path:
    """Resolve and require the Git toplevel supplied to the source packager.

    A caller may supply a lexical Windows path alias (for example ``nested/..``
    or a short path). The Git toplevel is the authority instead of comparing a
    normalized path with this module's or another unnormalized alias.
    """

    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise SourcePackageError("source packaging must run from the repository root") from error
    if not root.is_dir():
        raise SourcePackageError("source packaging must run from the repository root")
    try:
        top_level = Path(
            git(root, "rev-parse", "--show-toplevel").decode("utf-8", "strict").strip()
        ).resolve(strict=True)
    except (OSError, UnicodeError, ValueError, SourcePackageError) as error:
        raise SourcePackageError("source packaging must run from the repository root") from error
    if top_level != root:
        raise SourcePackageError("source packaging must run from the repository root")
    return root


def git_revision(root: Path, revision: str) -> str:
    value = git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SourcePackageError(f"git revision is not a commit: {revision}")
    return value


def workspace_version(root: Path) -> str:
    try:
        value = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise SourcePackageError("workspace version could not be read") from error
    if not isinstance(value, str) or not value or any(c not in "0123456789.+-" for c in value):
        raise SourcePackageError("workspace version is invalid")
    return value


def validate_label(label: str) -> str:
    if not LABEL_PATTERN.fullmatch(label) or len(label) > 96 or label in {".", ".."}:
        raise SourcePackageError("label must contain only letters, digits, '.', '_' or '-'")
    return label


def default_label(root: Path) -> str:
    revision = git(root, "rev-parse", "--short=12", "HEAD").decode("ascii", "replace").strip()
    return f"{datetime.now().strftime('%Y%m%d')}-{revision}"


def known_credentials(root: Path) -> tuple[bytes, ...]:
    """Read only known local key values for a private byte scan."""

    values: list[bytes] = []
    for relative in ("apikey.txt", ".env", ".release-secrets"):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            continue
        try:
            for line in path.read_bytes().splitlines():
                value = line.strip()
                if value.startswith((b"#", b";")):
                    continue
                if b"=" in value:
                    value = value.split(b"=", 1)[1].strip().strip(b"'\"")
                if len(value) > 32:
                    values.append(value)
        except OSError as error:
            raise SourcePackageError(f"unable to inspect credential file: {relative}") from error
    return tuple(dict.fromkeys(values))


def source_candidates(root: Path) -> list[str]:
    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SourcePackageError("git source inventory could not be read") from error
    candidates = sorted(set(item for item in raw.decode("utf-8", "strict").split("\0") if item))
    return [item for item in candidates if not is_workspace_path(item)]


def is_workspace_path(relative: str) -> bool:
    """Identify local workspace/profile paths while retaining source crates."""

    parts = tuple(part.lower() for part in relative.replace("\\", "/").split("/"))
    if len(parts) >= 2 and parts[:2] == ("crates", "workspace-service"):
        return False
    if any(part in WORKSPACE_PARTS for part in parts) or ("browser" in parts and "profile" in parts):
        return True
    # Prefix rules target directory roots (for example ``workspace_foo/draft``).
    # A legitimate source filename such as ``workspace_json.rs`` is not a local
    # workspace merely because its basename starts with ``workspace_``.
    return any(part.startswith(prefix) for part in parts[:-1] for prefix in WORKSPACE_PREFIXES)


def _diff_paths(root: Path, base_revision: str) -> tuple[str, ...]:
    """Return both sides of changed/renamed paths, including deleted files."""

    raw = git(root, "diff", "--name-only", "--no-renames", "-z", base_revision)
    return tuple(item for item in raw.decode("utf-8", "strict").split("\0") if item)


def validate_diff_paths(root: Path, base_revision: str) -> None:
    """Reject protected paths before a binary Git patch can copy old blobs."""

    for relative in _diff_paths(root, base_revision):
        normalized = relative.replace("\\", "/")
        parts = tuple(part.lower() for part in normalized.split("/"))
        if not parts or any(part in EXCLUDED_PARTS for part in parts):
            raise SourcePackageError(f"local-only path in source increment: {relative}")
        if is_workspace_path(relative):
            raise SourcePackageError(f"workspace or browser profile in source increment: {relative}")
        basename = parts[-1]
        suffix = Path(normalized).suffix.lower()
        if basename in PRIVATE_BASENAMES or basename.startswith(".env") or suffix in PRIVATE_SUFFIXES:
            raise SourcePackageError(f"private path in source increment: {relative}")


def safe_source_path(
    root: Path,
    relative: str,
    excluded_paths: tuple[Path, ...] = (),
) -> Path:
    path = root / relative
    try:
        normalized = path.relative_to(root)
        resolved = path.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise SourcePackageError(f"unsafe source path: {relative}") from error
    if path.is_symlink() or not path.is_file() or not resolved.is_relative_to(root.resolve()):
        raise SourcePackageError(f"unsafe source path: {relative}")
    lowered_parts = tuple(part.lower() for part in normalized.parts)
    if any(part in EXCLUDED_PARTS for part in lowered_parts):
        raise SourcePackageError(f"local-only path in source inventory: {relative}")
    if is_workspace_path(relative):
        raise SourcePackageError(f"workspace or browser profile in source inventory: {relative}")
    if any(resolved == excluded or resolved.is_relative_to(excluded) for excluded in excluded_paths):
        raise SourcePackageError(f"local-only output path in source inventory: {relative}")
    basename = normalized.name.lower()
    if (
        basename in PRIVATE_BASENAMES
        or basename.startswith(".env")
        or normalized.suffix.lower() in PRIVATE_SUFFIXES
    ):
        raise SourcePackageError(f"private source path: {relative}")
    if path.stat().st_size > SOURCE_MAX_BYTES:
        raise SourcePackageError(f"source file is unexpectedly large: {relative}")
    return path


def build_payload(
    root: Path,
    credentials: tuple[bytes, ...],
    excluded_paths: tuple[Path, ...] = (),
) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    for relative in source_candidates(root):
        candidate = root / relative
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError:
            resolved_candidate = candidate
        if any(
            resolved_candidate == excluded or resolved_candidate.is_relative_to(excluded)
            for excluded in excluded_paths
        ):
            # An output directory may already contain an artifact from a
            # previous failed/independent run.  It is outside the source
            # snapshot by construction, so skip it before the normal path
            # policy reports local-only files.
            continue
        path = safe_source_path(root, relative, excluded_paths)
        content = path.read_bytes()
        if any(secret in content for secret in credentials):
            raise SourcePackageError(f"credential matched source: {relative}")
        payload[relative.replace("\\", "/")] = content
    return payload


def archive_name(version: str, label: str | None) -> str:
    return f"Lawyer-Assistance_{version}_source" + (f"_{label}" if label else "")


def package_source(
    root: Path = ROOT,
    output_dir: Path | None = None,
    *,
    base: str | None = None,
    label: str | None = None,
) -> dict[str, object]:
    root = repository_root(root)
    output_dir = (output_dir or root / "dist").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    version = workspace_version(root)
    selected_label = validate_label(label) if label else default_label(root)
    base_revision = git_revision(root, base) if base else git_revision(root, "HEAD")
    source_revision = git_revision(root, "HEAD")
    credentials = known_credentials(root)
    validate_diff_paths(root, base_revision)
    payload = build_payload(root, credentials, (output_dir,))
    patch = git(root, "diff", "--binary", "--full-index", base_revision)
    if any(secret in patch for secret in credentials):
        raise SourcePackageError("credential matched source increment")
    payload["SOURCE_INCREMENT.patch"] = patch
    payload["SOURCE_HANDOFF.txt"] = (
        f"Lawyer Assistance {version}\n"
        f"label: {selected_label}\n"
        f"base revision: {base_revision}\n"
        f"source revision: {source_revision}\n\n"
        "此包是当前源码快照，SOURCE_INCREMENT.patch 记录相对指定基线的已提交及工作树差异。\n"
        "本包不含密钥、用户工作区、数据库二进制或本地测试材料。\n"
        "便携包、构建及验证方法见 README.md 和 docs/web/retest-1.2.1.md。\n"
    ).encode("utf-8")
    manifest_files = [
        {"path": name, "bytes": len(content), "sha256": sha256_bytes(content)}
        for name, content in sorted(payload.items())
    ]
    manifest = {
        "format_version": 2,
        "product": "Lawyer Assistance",
        "version": version,
        "candidate": "1.2.1",
        "label": selected_label,
        "base_revision": base_revision,
        "source_revision": source_revision,
        "patch": next(item for item in manifest_files if item["path"] == "SOURCE_INCREMENT.patch"),
        "files": manifest_files,
    }
    payload["SOURCE_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    name = archive_name(version, label)
    archive = output_dir / f"{name}.zip"
    checksum = output_dir / f"{name}.zip.sha256"
    for path in (archive, checksum):
        if path.exists() or path.is_symlink():
            raise SourcePackageError(f"refusing to overwrite existing artifact: {path}")
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for relative, content in sorted(payload.items()):
            info = zipfile.ZipInfo(f"{name}/{relative}", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, content)
    digest = sha256_file(archive)
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    return {
        "archive": str(archive),
        "checksum": str(checksum),
        "files": len(payload),
        "bytes": archive.stat().st_size,
        "sha256": digest,
        "manifest_sha256": sha256_bytes(payload["SOURCE_MANIFEST.json"]),
        "patch_sha256": sha256_bytes(patch),
        "base_revision": base_revision,
        "source_revision": source_revision,
        "label": selected_label,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=None, help="baseline commit for SOURCE_INCREMENT.patch")
    parser.add_argument("--label", default=None, help="safe artifact label, e.g. 20260911-01cf195")
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = package_source(output_dir=args.output_dir, base=args.base, label=args.label)
    except SourcePackageError as error:
        print(f"source packaging failed: {error}")
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
