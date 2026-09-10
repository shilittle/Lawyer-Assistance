"""Extract a generated portable archive and verify its entire file inventory."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import zipfile
from contextlib import nullcontext

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--existing", action="store_true", help="verify a previously extracted directory without overwriting files")
    args = parser.parse_args()
    archive = args.archive.resolve()
    destination = args.destination.resolve()
    with archive.open("rb") as source:
        archive_digest = hashlib.file_digest(source, "sha256").hexdigest()
    expected_digest = archive.with_suffix(".zip.sha256").read_text(encoding="ascii").split()[0]
    if archive_digest != expected_digest:
        raise ValueError("archive checksum sidecar mismatch")
    if not destination.is_relative_to(ROOT / "output"):
        raise ValueError("verification destination must be inside this workspace output directory")
    if destination.exists() and any(destination.iterdir()) and not args.existing:
        raise ValueError("verification destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    key_file = ROOT / "apikey.txt"
    keys = [line.strip().encode() for line in key_file.read_text(encoding="utf-8-sig").splitlines() if len(line.strip()) > 32] if key_file.exists() else []
    checked = {}
    top_names = set()
    with zipfile.ZipFile(archive) as package:
        for item in package.infolist():
            relative = PurePosixPath(item.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in item.filename:
                raise ValueError("unsafe archive path")
            target = (destination / item.filename).resolve()
            if not target.is_relative_to(destination) or item.filename in checked:
                raise ValueError("unsafe or duplicate archive entry")
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.suffix == ".dpapi" or target.name in {"apikey.txt", "workspace.sqlite", "workspace.lock"}:
                raise ValueError("private workspace file in archive")
            top_names.add(relative.parts[0])
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            tail = b""
            size = 0
            existing = args.existing and target.is_file()
            with package.open(item) as source, (nullcontext(None) if existing else target.open("xb")) as output:
                while block := source.read(1024 * 1024):
                    joined = tail + block
                    if any(key in joined for key in keys):
                        raise ValueError(f"credential matched package entry: {item.filename}")
                    tail = joined[-512:]
                    if output is not None:
                        output.write(block)
                    digest.update(block)
                    size += len(block)
            checked[item.filename] = {"sha256": digest.hexdigest(), "bytes": size}
            if existing:
                with target.open("rb") as extracted:
                    if hashlib.file_digest(extracted, "sha256").hexdigest() != digest.hexdigest():
                        raise ValueError(f"extracted file differs from archive: {item.filename}")
    if len(top_names) != 1:
        raise ValueError("archive root is ambiguous")
    name = next(iter(top_names))
    package_dir = destination / name
    manifest = json.loads((package_dir / "portable.manifest.json").read_text(encoding="utf-8"))
    for item in manifest["files"]:
        actual = checked[f"{name}/{item['path']}"]
        if actual["sha256"] != item["sha256"] or actual["bytes"] != item["size"]:
            raise ValueError(f"manifest mismatch: {item['path']}")
    hashes = (package_dir / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
    for line in hashes:
        if not line or line.startswith("#"):
            continue
        expected, size, relative = line.split(None, 2)
        if checked[f"{name}/{relative}"]["sha256"] != expected or checked[f"{name}/{relative}"]["bytes"] != int(size):
            raise ValueError(f"embedded checksum mismatch: {relative}")
    report = {"archive": str(archive), "archive_sha256": archive_digest, "package_dir": str(package_dir), "files": len(checked),
              "uncompressed_bytes": sum(x["bytes"] for x in checked.values()),
              "manifest_verified": True, "embedded_checksums_verified": True,
              "credential_patterns_checked": len(keys), "credential_scan_matches": 0, "private_workspace_files": 0}
    (destination / "inventory-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
