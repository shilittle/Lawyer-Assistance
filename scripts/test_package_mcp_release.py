from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.package_mcp_release import (
    PackageError,
    _read_archive,
    build_package,
    collect_payloads,
    sha256_bytes,
)


class McpReleasePackageTests(unittest.TestCase):
    def fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        (root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "9.8.7"\n', encoding="utf-8"
        )
        (root / "LICENSE").write_text("test license\n", encoding="utf-8")
        (root / "README.md").write_text("# test\n", encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text(
            """# Lawyer Assistance MCP 9.8.7

## Compatibility contract

MCP protocol metadata
Public service schema
Legal archive schema
User database schema

## Install and migration

Fixture migration guidance.

## Known limits

Fixture limits.
""",
            encoding="utf-8",
        )
        notices = root / "apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt"
        notices.parent.mkdir(parents=True)
        notices.write_text("test notices\n", encoding="utf-8")
        docs = root / "docs/mcp"
        docs.mkdir(parents=True)
        (docs / "README.md").write_text("MCP docs\n", encoding="utf-8")
        integrations = root / "integrations/workbuddy"
        integrations.mkdir(parents=True)
        (integrations / "connector.json").write_text('{"token":"${TOKEN}"}\n', encoding="utf-8")
        binary = root / "lawyer-assistance-mcp"
        binary.write_bytes(b"test-binary")
        return root, binary

    def test_tarball_is_deterministic_manifested_and_database_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            first = build_package(root, binary, "x86_64-unknown-linux-gnu", root / "out-1")
            second = build_package(root, binary, "x86_64-unknown-linux-gnu", root / "out-2")
            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual(first.sha256, sha256_bytes(first.archive.read_bytes()))
            self.assertTrue(first.checksum.read_text(encoding="utf-8").endswith("\n"))
            self.assertGreaterEqual(first.files, 8)
            members = _read_archive(first.archive)
            release_notes_name = f"{first.package_root}/RELEASE_NOTES.md"
            manifest_name = f"{first.package_root}/MANIFEST.sha256"
            self.assertIn(release_notes_name, members)
            self.assertIn(manifest_name, members)
            self.assertIn(
                b"  RELEASE_NOTES.md\n",
                members[manifest_name],
            )

    def test_windows_zip_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            windows_binary = binary.with_suffix(".exe")
            binary.rename(windows_binary)
            result = build_package(root, windows_binary, "x86_64-pc-windows-msvc", root / "out")
            self.assertEqual(result.archive.suffix, ".zip")
            self.assertTrue(result.archive.is_file())

    def test_database_or_secret_like_support_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            forbidden = root / "integrations" / "user.sqlite"
            forbidden.write_bytes(b"not really sqlite")
            with self.assertRaises(PackageError):
                collect_payloads(root, binary, "x86_64-unknown-linux-gnu")

    def test_release_notes_must_match_workspace_version_and_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            (root / "RELEASE_NOTES.md").write_text(
                "# Lawyer Assistance MCP 9.8.6\n\n## Known limits\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PackageError, "RELEASE_NOTES"):
                collect_payloads(root, binary, "x86_64-unknown-linux-gnu")

    def test_developer_cache_files_do_not_affect_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            cache = root / "integrations" / "__pycache__" / "validator.cpython-313.pyc"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"machine-local-bytecode")
            (root / "integrations" / ".DS_Store").write_bytes(b"machine-local-metadata")
            paths = {
                payload.path
                for payload in collect_payloads(root, binary, "x86_64-unknown-linux-gnu")
            }
            self.assertNotIn("integrations/__pycache__/validator.cpython-313.pyc", paths)
            self.assertNotIn("integrations/.DS_Store", paths)


if __name__ == "__main__":
    unittest.main()
