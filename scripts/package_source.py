"""Archive the current source tree and its increment from HEAD, without local data or keys."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def main() -> None:
    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    key_file = ROOT / "apikey.txt"
    # Compare privately; report only the offending relative path on a match.
    keys = [line.strip().encode() for line in key_file.read_text(encoding="utf-8-sig").splitlines() if len(line.strip()) > 32] if key_file.exists() else []
    candidates = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")
    payload: dict[str, bytes] = {}
    for relative in sorted(set(candidates)):
        if not relative:
            continue
        path = ROOT / relative
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise RuntimeError(f"Non-regular source: {relative}")
        if any(part in {"output", "target", "dist", "node_modules", ".git", ".release-secrets"} for part in path.relative_to(ROOT).parts):
            raise RuntimeError(f"Local-only path in source inventory: {relative}")
        if path.name == "apikey.txt" or path.suffix in {".sqlite", ".dpapi"} or path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError(f"Private or unexpectedly large source: {relative}")
        content = path.read_bytes()
        if any(key in content for key in keys):
            raise RuntimeError(f"Credential matched source: {relative}")
        payload[relative] = content
    diff = git("diff", "--binary", "HEAD")
    if any(key in diff for key in keys):
        raise RuntimeError("Credential matched source increment")
    payload["SOURCE_INCREMENT.patch"] = diff
    payload["SOURCE_HANDOFF.txt"] = (
        f"Lawyer Assistance {version}\n\n"
        "此包是当前完整源码快照，包含在 V1.0.0 及保留的案例检索增量上完成的修改。\n"
        "SOURCE_INCREMENT.patch 记录已有受控文件相对基线的差异；新增文件已包含在源码树中。\n"
        "本包不含密钥、用户工作区、数据库二进制或本地测试材料。运行库和可执行程序见同版本便携包。\n"
        "构建及验证方法见 README.md、docs/web/ai-upgrade.md 和 docs/web/ai-validation.md。\n"
    ).encode("utf-8")
    manifest = {
        "version": version,
        "base_revision": git("rev-parse", "HEAD").decode().strip(),
        "base_tag": git("describe", "--tags", "--exact-match", "HEAD").decode().strip(),
        "files": [{"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()} for name, content in payload.items()],
    }
    payload["SOURCE_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    out = ROOT / "dist"
    out.mkdir(exist_ok=True)
    name = f"Lawyer-Assistance_{version}_source"
    archive = out / f"{name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for relative, content in sorted(payload.items()):
            info = zipfile.ZipInfo(f"{name}/{relative}", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(json.dumps({"archive": str(archive), "files": len(payload), "bytes": archive.stat().st_size, "sha256": digest}, ensure_ascii=False))


if __name__ == "__main__":
    main()
