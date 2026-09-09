from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.package_portable import (
    DEFAULT_TARGET,
    PORTABLE_FILES,
    PackageError,
    build_package,
    launcher_text,
    stop_launcher_text,
    verify_legal_runtime,
)


class PortablePackageTests(unittest.TestCase):
    def fixture(self, directory: str) -> Path:
        root = Path(directory)
        (root / "data/runtime").mkdir(parents=True)
        (root / "data/generated").mkdir(parents=True)
        (root / "target" / DEFAULT_TARGET / "release").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "0.4.0"\n', encoding="utf-8"
        )
        for source, _destination in PORTABLE_FILES:
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {source.as_posix()}\n", encoding="utf-8")
        for name in ("DATA_SOURCES.md", "LICENSE.txt", "THIRD_PARTY_NOTICES.txt"):
            (root / "data/runtime" / name).write_text(name + "\n", encoding="utf-8")
        database = root / "data/runtime/legal_core.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE database_metadata (key TEXT PRIMARY KEY, value TEXT)")
            source_hash = "a" * 64
            connection.execute(
                "INSERT INTO database_metadata(key, value) VALUES ('source_manifest_sha256', ?)",
                (source_hash,),
            )
            connection.commit()
        finally:
            connection.close()
        digest = hashlib.sha256(database.read_bytes()).hexdigest()
        (root / "data/generated/legal_core_distribution_manifest.json").write_text(
            json.dumps(
                {
                    "filename": "legal_core.sqlite",
                    "size_bytes": database.stat().st_size,
                    "sha256": digest,
                    "source_manifest_sha256": "a" * 64,
                }
            ),
            encoding="utf-8",
        )
        (root / "target" / DEFAULT_TARGET / "release" / "lawyer-assistance.exe").write_bytes(
            b"server-binary"
        )
        (root / "target" / DEFAULT_TARGET / "release" / "lawyer-assistance-mcp.exe").write_bytes(
            b"mcp-binary"
        )
        return root

    def test_skip_build_creates_verified_zip_and_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            result = build_package(root, root / "dist", skip_build=True)
            self.assertTrue(result.archive.is_file())
            self.assertTrue(result.checksum.is_file())
            self.assertTrue(result.manifest.is_file())
            digest = hashlib.sha256(result.archive.read_bytes()).hexdigest()
            self.assertIn(digest, result.checksum.read_text(encoding="ascii"))
            with zipfile.ZipFile(result.archive) as package:
                names = set(package.namelist())
                prefix = result.package_root + "/"
                expected = {
                    prefix + "lawyer-assistance.exe",
                    prefix + "lawyer-assistance-mcp.exe",
                    prefix + "Lawyer-Assistance.vbs",
                    prefix + "Stop-Lawyer-Assistance.vbs",
                    prefix + "data/runtime/legal_core.sqlite",
                    prefix + "data/runtime/DATA_SOURCES.md",
                    prefix + "data/runtime/LICENSE.txt",
                    prefix + "data/runtime/THIRD_PARTY_NOTICES.txt",
                    prefix + "MANIFEST.sha256",
                    prefix + "portable.manifest.json",
                    prefix + "LICENSE",
                    prefix + "docs/getting-started.md",
                    prefix + "docs/mcp/README.md",
                    prefix + "docs/web/README.md",
                    prefix + "examples/mcp/codex/config.stdio.toml",
                    prefix + "examples/mcp/codex/config.privacy-workspace.stdio.toml",
                    prefix + "examples/mcp/workbuddy/stdio.windows.json",
                    prefix + "examples/mcp/workbuddy/privacy-workspace.stdio.windows.json",
                }
                expected.update(prefix + destination.as_posix() for _source, destination in PORTABLE_FILES)
                self.assertTrue(expected.issubset(names))
                manifest = package.read(prefix + "MANIFEST.sha256").decode("utf-8")
                self.assertIn("lawyer-assistance.exe", manifest)
                launcher = package.read(prefix + "Lawyer-Assistance.vbs").decode("utf-8")
                self.assertIn("serve --open --port 8877", launcher)
                self.assertIn("shell.Run command, 0, False", launcher)
                stop_launcher = package.read(prefix + "Stop-Lawyer-Assistance.vbs").decode("utf-8")
                self.assertIn('""" & exe & """ stop', stop_launcher)
                self.assertIn("shell.Run command, 0, False", stop_launcher)

    def test_legal_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manifest = root / "data/generated/legal_core_distribution_manifest.json"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["sha256"] = "f" * 64
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "SHA-256"):
                verify_legal_runtime(root)

    def test_missing_release_binary_fails_without_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "target" / DEFAULT_TARGET / "release" / "lawyer-assistance-mcp.exe").unlink()
            with self.assertRaisesRegex(PackageError, "release binary"):
                build_package(root, root / "dist", skip_build=True)

    def test_launcher_is_hidden_and_uses_local_appdata(self) -> None:
        text = launcher_text()
        self.assertIn("WScript.Shell", text)
        self.assertIn("%LOCALAPPDATA%", text)
        self.assertIn("shell.Run command, 0, False", text)
        self.assertNotIn("cmd.exe", text.lower())
        self.assertNotIn("If Not fso.FileExists(legalDb)", text)

    def test_stop_launcher_is_hidden_and_does_not_taskkill(self) -> None:
        text = stop_launcher_text()
        self.assertIn('""" & exe & """ stop', text)
        self.assertIn("shell.Run command, 0, False", text)
        self.assertNotIn("taskkill", text.lower())
        self.assertNotIn("cmd.exe", text.lower())


if __name__ == "__main__":
    unittest.main()
