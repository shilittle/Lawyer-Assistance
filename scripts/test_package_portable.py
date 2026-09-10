from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.package_portable import (
    CASE_DISTRIBUTION_MANIFEST,
    AI_TOOL_FILES,
    DEFAULT_TARGET,
    PORTABLE_FILES,
    PackageError,
    build_package,
    launcher_text,
    stop_launcher_text,
    verify_case_runtime,
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
        case_database = root / "data/runtime/judicial_cases.sqlite"
        connection = sqlite3.connect(case_database)
        try:
            connection.execute("PRAGMA user_version = 1")
            connection.execute("CREATE TABLE database_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            case_source_hash = "b" * 64
            connection.executemany(
                "INSERT INTO database_metadata(key, value) VALUES (?, ?)",
                [("schema_version", "1"), ("dataset_version", "test-cases-v1"), ("source_manifest_sha256", case_source_hash)],
            )
            connection.execute(
                """
                CREATE TABLE judicial_cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    case_type TEXT NOT NULL,
                    guiding_number INTEGER,
                    reference_number TEXT,
                    keywords_json TEXT NOT NULL,
                    publication_date TEXT,
                    court TEXT,
                    case_number TEXT,
                    status TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    key_points_json TEXT,
                    basic_facts TEXT,
                    judgment_result TEXT,
                    reasoning TEXT,
                    related_laws_json TEXT,
                    full_text TEXT,
                    fetched_at TEXT,
                    content_sha256 TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO judicial_cases(
                    case_id, title, case_type, guiding_number, reference_number,
                    keywords_json, publication_date, court, case_number, status,
                    source_url, search_text, key_points_json, basic_facts,
                    judgment_result, reasoning, related_laws_json, full_text, fetched_at,
                    content_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "guiding-1",
                    "测试指导案例",
                    "guiding",
                    1,
                    None,
                    '["劳动关系"]',
                    "2026-01-01",
                    "最高人民法院",
                    "（2026）最高法民再1号",
                    "active",
                    "https://www.court.gov.cn/shenpan/xiangqing/1.html",
                    "测试指导案例 劳动关系",
                    '["劳动关系认定"]',
                    "测试事实",
                    "测试裁判结果",
                    "测试裁判理由",
                    '["民法典"]',
                    "测试正文",
                    "2026-01-01T00:00:00Z",
                    "c" * 64,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        case_digest = hashlib.sha256(case_database.read_bytes()).hexdigest()
        (root / CASE_DISTRIBUTION_MANIFEST).write_text(
            json.dumps(
                {
                    "dataset_name": "test-judicial-cases",
                    "dataset_version": "test-cases-v1",
                    "filename": "judicial_cases.sqlite",
                    "size_bytes": case_database.stat().st_size,
                    "sha256": case_digest,
                    "schema_version": "1",
                    "row_count": 1,
                    "counts": {"total": 1, "guiding": 1, "reference": 0},
                    "coverage_status": "guiding_catalogue_partial_reference_curated",
                    "source_manifest_sha256": "b" * 64,
                    "sources": [{
                        "url": "https://www.court.gov.cn/",
                        "fetched_at": "2026-09-09T00:00:00Z",
                        "sha256": "d" * 64,
                    }],
                }
            ),
            encoding="utf-8",
        )
        (root / "data/runtime/CASE_DATA_SOURCES.md").write_text(
            "本测试案例库仅用于打包测试，不代表真实数据。来源：最高人民法院。\n",
            encoding="utf-8",
        )
        (root / "target" / DEFAULT_TARGET / "release" / "lawyer-assistance.exe").write_bytes(
            b"server-binary"
        )
        (root / "target" / DEFAULT_TARGET / "release" / "lawyer-assistance-mcp.exe").write_bytes(
            b"mcp-binary"
        )
        tools = root / "output/runtime-tools"
        for name in AI_TOOL_FILES:
            target = tools / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"synthetic-runtime")
        (tools / "document-runtime.json").write_text(json.dumps([
            {"path": name, "sha256": hashlib.sha256((tools / name).read_bytes()).hexdigest()}
            for name in ("typst.exe", "fonts/SourceHanSerifSC-Regular.otf", "fonts/SourceHanSerifSC-Bold.otf")
        ]), encoding="utf-8")
        (tools / "pdfium.version.json").write_text(json.dumps({"dll_sha256": hashlib.sha256((tools / "pdfium.dll").read_bytes()).hexdigest()}), encoding="utf-8")
        connection = sqlite3.connect(root / "data/runtime/legal_search_index.sqlite")
        try:
            connection.execute("CREATE TABLE search_index_metadata (key TEXT,value TEXT)")
            connection.execute("INSERT INTO search_index_metadata VALUES ('source_manifest_sha256', ?)", ("a" * 64,))
            connection.commit()
        finally:
            connection.close()
        (root / "data/generated/legal_search_index_manifest.json").write_text("{}", encoding="utf-8")
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
                    prefix + "data/runtime/judicial_cases.sqlite",
                    prefix + "data/runtime/CASE_DATA_SOURCES.md",
                    prefix + "data/runtime/judicial_cases_manifest.json",
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
                portable_manifest = json.loads(package.read(prefix + "portable.manifest.json"))
                self.assertEqual(
                    portable_manifest["judicial_cases_database"]["filename"],
                    "data/runtime/judicial_cases.sqlite",
                )
                self.assertEqual(portable_manifest["judicial_cases_database"]["counts"]["total"], 1)
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

    def test_case_manifest_identity_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            verify_case_runtime(root)
            manifest = root / CASE_DISTRIBUTION_MANIFEST
            original = json.loads(manifest.read_text(encoding="utf-8"))
            for field, value, message in (
                ("sha256", "f" * 64, "SHA-256"),
                ("schema_version", "2", "schema"),
                ("sources", [{"url": "https://untrusted.example/", "fetched_at": "2026-09-09T00:00:00Z", "sha256": "d" * 64}], "source"),
            ):
                with self.subTest(field=field):
                    changed = dict(original)
                    changed[field] = value
                    manifest.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaisesRegex(PackageError, message):
                        verify_case_runtime(root)
                    manifest.write_text(json.dumps(original), encoding="utf-8")
            changed = dict(original)
            changed["counts"] = {"total": 2, "guiding": 2, "reference": 0}
            manifest.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "count"):
                verify_case_runtime(root)

    def test_missing_case_sidecar_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "data/runtime/judicial_cases.sqlite").unlink()
            with self.assertRaisesRegex(PackageError, "judicial case database"):
                build_package(root, root / "dist", skip_build=True)

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
