#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("verify_legal_core_distribution.py")
SPEC = importlib.util.spec_from_file_location("verify_legal_core_distribution", MODULE_PATH)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


class DistributionVerificationTests(unittest.TestCase):
    def create_archive_database(self, path: Path) -> dict[str, object]:
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE database_metadata (
              key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE source_records (
              source_system_id TEXT NOT NULL,
              external_id TEXT NOT NULL,
              record_type TEXT NOT NULL,
              source_url TEXT,
              checksum TEXT NOT NULL
            );
            INSERT INTO database_metadata VALUES ('schema_version', '4', '2026-07-11');
            INSERT INTO database_metadata VALUES ('dataset_version', 'archive-v1', '2026-07-11');
            INSERT INTO source_records VALUES (
              'official', '1', 'detail', 'https://example.test/1', 'abc'
            );
            """
        )
        source_hash = verify.source_manifest_sha256(connection)
        connection.commit()
        connection.close()
        manifest: dict[str, object] = {
            "dataset_version": "archive-v1",
            "schema_version": "4",
            "source_manifest_sha256": source_hash,
            "ci_fixture_allowed": False,
        }
        self.refresh_artifact_fields(path, manifest)
        return manifest

    def create_database(self, path: Path) -> dict[str, object]:
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE database_metadata (
              key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE source_systems (id TEXT PRIMARY KEY);
            CREATE TABLE source_records (
              id TEXT PRIMARY KEY,
              source_system_id TEXT NOT NULL REFERENCES source_systems(id),
              external_id TEXT NOT NULL,
              record_type TEXT NOT NULL,
              source_url TEXT,
              retrieved_at TEXT NOT NULL,
              checksum TEXT NOT NULL
            );
            CREATE TABLE law_documents (id TEXT PRIMARY KEY, title TEXT NOT NULL);
            CREATE TABLE law_versions (
              id TEXT PRIMARY KEY,
              document_id TEXT NOT NULL REFERENCES law_documents(id)
            );
            CREATE TABLE law_relations (
              id TEXT PRIMARY KEY,
              from_document_id TEXT NOT NULL REFERENCES law_documents(id),
              to_document_id TEXT NOT NULL REFERENCES law_documents(id)
            );
            CREATE TABLE law_article_contents (
              content_id INTEGER PRIMARY KEY,
              content TEXT NOT NULL
            );
            CREATE TABLE law_article_rows (
              article_rowid INTEGER PRIMARY KEY,
              id TEXT NOT NULL UNIQUE,
              document_id TEXT NOT NULL REFERENCES law_documents(id),
              version_id TEXT NOT NULL REFERENCES law_versions(id),
              article_number TEXT NOT NULL,
              article_order INTEGER NOT NULL,
              title TEXT,
              content_id INTEGER NOT NULL REFERENCES law_article_contents(content_id),
              updated_on TEXT
            );
            CREATE VIEW law_articles AS
            SELECT rows.article_rowid AS rowid, rows.id, rows.document_id, rows.version_id,
                   rows.article_number, rows.article_order, rows.title, contents.content,
                   rows.updated_on
            FROM law_article_rows AS rows
            JOIN law_article_contents AS contents ON contents.content_id = rows.content_id;
            CREATE TABLE citation_metadata (
              article_id TEXT PRIMARY KEY REFERENCES law_article_rows(id),
              citation_id TEXT NOT NULL UNIQUE,
              canonical_label TEXT NOT NULL
            );
            CREATE VIRTUAL TABLE law_articles_fts USING fts5(
              article_id UNINDEXED,
              document_id UNINDEXED,
              version_id UNINDEXED,
              document_title,
              article_number,
              article_title,
              content,
              content = '',
              tokenize = 'unicode61 remove_diacritics 2'
            );

            INSERT INTO database_metadata VALUES ('schema_version', '4', '2026-07-11');
            INSERT INTO database_metadata VALUES ('dataset_version', 'test-v1', '2026-07-11');
            INSERT INTO database_metadata VALUES (
              'distribution_profile', 'runtime-slim-v1', '2026-07-11'
            );
            INSERT INTO database_metadata VALUES ('runtime_schema_version', '1', '2026-07-11');
            INSERT INTO database_metadata VALUES (
              'dataset_name', 'official-china-legal-core', '2026-07-11'
            );
            INSERT INTO database_metadata VALUES ('coverage_status', 'complete', '2026-07-11');
            INSERT INTO database_metadata VALUES (
              'runtime_source_verification', 'trusted_archival_manifest', '2026-07-11'
            );
            INSERT INTO database_metadata VALUES (
              'runtime_ci_fixture_allowed', 'false', '2026-07-11'
            );
            INSERT INTO database_metadata VALUES (
              'runtime_fts_contentless', 'true', '2026-07-11'
            );
            INSERT INTO database_metadata VALUES (
              'runtime_archival_payload_included', 'false', '2026-07-11'
            );
            INSERT INTO source_systems VALUES ('official');
            INSERT INTO source_records VALUES (
              'source-1', 'official', '1', 'detail', 'https://example.test/1',
              '2026-07-11', 'abc'
            );
            INSERT INTO law_documents VALUES ('document-1', '测试法');
            INSERT INTO law_versions VALUES ('version-1', 'document-1');
            INSERT INTO law_article_contents VALUES (1, '第一条 测试正文');
            INSERT INTO law_article_rows VALUES (
              1, 'article-1', 'document-1', 'version-1', '第一条', 1, NULL, 1,
              '2026-07-11'
            );
            INSERT INTO citation_metadata VALUES ('article-1', 'citation-1', '测试法第一条');
            INSERT INTO law_articles_fts(
              rowid, article_id, document_id, version_id, document_title,
              article_number, article_title, content
            ) VALUES (
              1, 'article-1', 'document-1', 'version-1', '测试法',
              '第一条', '', '第一条 测试正文'
            );
            PRAGMA user_version = 1;
            """
        )
        manifest_hash = verify.source_manifest_sha256(connection)
        connection.commit()
        connection.close()
        manifest: dict[str, object] = {
            "dataset_name": "official-china-legal-core",
            "dataset_version": "test-v1",
            "source_dataset_name": "official-china-legal-core",
            "coverage_status": "complete",
            "source_coverage_status": "complete",
            "schema_version": "4",
            "runtime_profile": "runtime-slim-v1",
            "runtime_schema_version": "1",
            "source_verification": "trusted_archival_manifest",
            "archival_source_sha256": "a" * 64,
            "archival_manifest_sha256": "b" * 64,
            "counts": {
                "documents": 1,
                "versions": 1,
                "articles": 1,
                "article_rows": 1,
                "distinct_article_contents": 1,
                "fts_rows": 1,
                "relations": 0,
                "citations": 1,
                "source_records": 1,
            },
            "source_manifest_sha256": manifest_hash,
            "ci_fixture_allowed": False,
        }
        self.refresh_artifact_fields(path, manifest)
        return manifest

    @staticmethod
    def refresh_artifact_fields(path: Path, manifest: dict[str, object]) -> None:
        manifest["size_bytes"] = path.stat().st_size
        manifest["sha256"] = verify.sha256_file(path)

    @staticmethod
    def update_database(path: Path, sql: str) -> None:
        connection = sqlite3.connect(path)
        connection.executescript(sql)
        connection.commit()
        connection.close()

    def test_verifies_all_distribution_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            result = verify.verify_database(database, manifest)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["foreign_key_errors"], 0)
        self.assertEqual(result["article_count"], 1)
        self.assertEqual(result["distinct_content_count"], 1)
        self.assertEqual(result["citation_count"], 1)
        self.assertEqual(result["source_record_count"], 1)
        self.assertEqual(result["missing_article_content"], 0)

    def test_preserves_non_runtime_archive_manifest_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "archive.sqlite"
            manifest = self.create_archive_database(database)
            result = verify.verify_database(database, manifest)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["runtime_object_types"], {})

    def test_accepts_pre_release_top_level_count_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            counts = manifest.pop("counts")
            assert isinstance(counts, dict)
            for top_level, nested in verify.RUNTIME_COUNT_FIELDS.items():
                manifest[top_level] = counts[nested]
            result = verify.verify_database(database, manifest)
        self.assertEqual(result["status"], "complete")

    def test_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            manifest["sha256"] = "0" * 64
            result = verify.verify_database(database, manifest)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(item.startswith("sha256:") for item in result["failures"]))

    def test_rejects_foreign_key_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(
                database,
                "UPDATE law_article_rows SET document_id = 'missing-document';",
            )
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        self.assertIn("foreign_key_errors:1", result["failures"])

    def test_rejects_missing_article_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(database, "UPDATE law_article_contents SET content = '';")
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        self.assertIn("missing_article_content:1", result["failures"])

    def test_rejects_archival_tables_and_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(
                database,
                """
                CREATE TABLE legal_attachments (id TEXT PRIMARY KEY);
                ALTER TABLE source_records ADD COLUMN raw_json TEXT;
                ALTER TABLE citation_metadata ADD COLUMN id TEXT;
                """,
            )
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        self.assertTrue(
            any(item.startswith("archival_tables_present:") for item in result["failures"])
        )
        self.assertTrue(
            any(item.startswith("archival_columns_present:") for item in result["failures"])
        )

    def test_rejects_runtime_schema_metadata_or_pragma_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(
                database,
                """
                UPDATE database_metadata SET value = '2' WHERE key = 'runtime_schema_version';
                PRAGMA user_version = 2;
                """,
            )
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        self.assertIn("database_runtime_schema_version:2!=1", result["failures"])
        self.assertIn("sqlite_user_version:2!=1", result["failures"])

    def test_rejects_missing_or_wrong_exact_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            counts = manifest["counts"]
            assert isinstance(counts, dict)
            counts.pop("source_records")
            counts["articles"] = 2
            result = verify.verify_database(database, manifest)
        self.assertIn("manifest_missing:counts.source_records", result["failures"])
        self.assertIn("article_count:1!=2", result["failures"])

    def test_rejects_invalid_archival_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            manifest["archival_source_sha256"] = "not-a-sha256"
            manifest["archival_manifest_sha256"] = "also-not-a-sha256"
            result = verify.verify_database(database, manifest)
        self.assertIn(
            "manifest_invalid_sha256:archival_source_sha256",
            result["failures"],
        )
        self.assertIn(
            "manifest_invalid_sha256:archival_manifest_sha256",
            result["failures"],
        )

    def test_removing_runtime_profile_cannot_downgrade_runtime_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            manifest.pop("runtime_profile")
            result = verify.verify_database(database, manifest)
        self.assertIn("runtime_profile:None!=runtime-slim-v1", result["failures"])

    def test_runtime_database_shape_prevents_removing_all_manifest_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            for key in verify.RUNTIME_MANIFEST_MARKERS:
                manifest.pop(key, None)
            result = verify.verify_database(database, manifest)
        self.assertIn("runtime_profile:None!=runtime-slim-v1", result["failures"])
        self.assertIn("manifest_missing:counts.articles", result["failures"])

    def test_rejects_spoofed_formal_runtime_manifest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            manifest.update(
                {
                    "runtime_profile": "runtime-slim-v1-ci-fixture",
                    "runtime_schema_version": "2",
                    "source_verification": "unverified_ci_fixture",
                    "dataset_name": "lookalike-legal-core",
                    "source_dataset_name": "lookalike-legal-core",
                    "coverage_status": "incomplete",
                    "source_coverage_status": "unknown",
                }
            )
            result = verify.verify_database(database, manifest)
        expected_failures = {
            "runtime_profile:runtime-slim-v1-ci-fixture!=runtime-slim-v1",
            "runtime_schema_version:2!=1",
            "source_verification:unverified_ci_fixture!=trusted_archival_manifest",
            "dataset_name:lookalike-legal-core!=official-china-legal-core",
            "source_dataset_name:lookalike-legal-core!=official-china-legal-core",
            "coverage_status:incomplete!=complete",
            "source_coverage_status:unknown!=complete",
        }
        self.assertTrue(expected_failures.issubset(set(result["failures"])))

    def test_rejects_spoofed_runtime_database_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(
                database,
                """
                UPDATE database_metadata SET value = 'runtime-slim-v1-ci-fixture'
                  WHERE key = 'distribution_profile';
                UPDATE database_metadata SET value = 'lookalike-legal-core'
                  WHERE key = 'dataset_name';
                UPDATE database_metadata SET value = 'incomplete'
                  WHERE key = 'coverage_status';
                UPDATE database_metadata SET value = 'unverified_ci_fixture'
                  WHERE key = 'runtime_source_verification';
                UPDATE database_metadata SET value = 'true'
                  WHERE key = 'runtime_ci_fixture_allowed';
                UPDATE database_metadata SET value = 'false'
                  WHERE key = 'runtime_fts_contentless';
                UPDATE database_metadata SET value = 'true'
                  WHERE key = 'runtime_archival_payload_included';
                """,
            )
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        expected_failures = {
            "database_runtime_profile:runtime-slim-v1-ci-fixture!=runtime-slim-v1",
            "database_metadata_dataset_name:lookalike-legal-core!=official-china-legal-core",
            "database_metadata_coverage_status:incomplete!=complete",
            "database_metadata_runtime_source_verification:unverified_ci_fixture!="
            "trusted_archival_manifest",
            "database_metadata_runtime_ci_fixture_allowed:true!=false",
            "database_metadata_runtime_fts_contentless:false!=true",
            "database_metadata_runtime_archival_payload_included:true!=false",
        }
        self.assertTrue(expected_failures.issubset(set(result["failures"])))

    def test_rejects_spoofed_runtime_object_shapes_and_contentful_fts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            self.update_database(
                database,
                """
                DROP VIEW law_articles;
                CREATE TABLE law_articles AS
                SELECT rows.article_rowid AS rowid, rows.id, rows.document_id,
                       rows.version_id, rows.article_number, rows.article_order,
                       rows.title, contents.content, rows.updated_on
                FROM law_article_rows AS rows
                JOIN law_article_contents AS contents ON contents.content_id = rows.content_id;
                DROP TABLE law_articles_fts;
                CREATE VIRTUAL TABLE law_articles_fts USING fts5(
                  article_id UNINDEXED, document_id UNINDEXED, version_id UNINDEXED,
                  document_title, article_number, article_title, content
                );
                INSERT INTO law_articles_fts(
                  rowid, article_id, document_id, version_id, document_title,
                  article_number, article_title, content
                ) VALUES (
                  1, 'article-1', 'document-1', 'version-1', '测试法',
                  '第一条', '', '第一条 测试正文'
                );
                """,
            )
            self.refresh_artifact_fields(database, manifest)
            result = verify.verify_database(database, manifest)
        self.assertIn("runtime_object_type:law_articles:table!=view", result["failures"])
        self.assertIn("runtime_fts_not_contentless", result["failures"])

    def test_rejects_manifest_that_allows_ci_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legal.sqlite"
            manifest = self.create_database(database)
            manifest["ci_fixture_allowed"] = True
            result = verify.verify_database(database, manifest)
        self.assertIn("ci_fixture_allowed_must_be_false", result["failures"])

    def test_remote_manifest_requires_and_verifies_external_hash(self) -> None:
        payload = json.dumps({"value": "trusted"}).encode("utf-8")
        expected = hashlib.sha256(payload).hexdigest()
        with mock.patch.object(verify.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "--manifest-sha256"):
                verify.load_json("https://example.test/manifest.json")
            urlopen.assert_not_called()

            urlopen.return_value = io.BytesIO(payload)
            loaded = verify.load_json(
                "https://example.test/manifest.json",
                expected,
            )
            self.assertEqual(loaded, {"value": "trusted"})

            urlopen.return_value = io.BytesIO(payload)
            with self.assertRaisesRegex(RuntimeError, "manifest SHA-256 mismatch"):
                verify.load_json(
                    "https://example.test/manifest.json",
                    "0" * 64,
                )

    def test_verify_only_reads_target_without_replacing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            database = directory / "legal.sqlite"
            manifest = self.create_database(database)
            manifest_path = directory / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            before_hash = verify.sha256_file(database)
            before_mtime = database.stat().st_mtime_ns
            with contextlib.redirect_stdout(io.StringIO()):
                status = verify.verify_only(str(manifest_path), database)
            self.assertEqual(status, 0)
            self.assertEqual(verify.sha256_file(database), before_hash)
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)

    def test_verify_only_rejects_remote_database_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "only a local path"):
                verify.verify_only(
                    str(manifest_path),
                    "https://example.test/legal.sqlite",
                )

    def test_install_still_atomically_replaces_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = directory / "source.sqlite"
            output = directory / "installed.sqlite"
            manifest = self.create_database(source)
            manifest_path = directory / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            output.write_bytes(b"old database")
            with contextlib.redirect_stdout(io.StringIO()):
                status = verify.install(str(manifest_path), output, str(source))
            self.assertEqual(status, 0)
            self.assertEqual(verify.sha256_file(output), verify.sha256_file(source))

    def test_failed_install_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = directory / "source.sqlite"
            output = directory / "installed.sqlite"
            manifest = self.create_database(source)
            manifest["sha256"] = "0" * 64
            manifest_path = directory / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            original = b"existing verified database"
            output.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, "legal database verification failed"):
                verify.install(str(manifest_path), output, str(source))
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(list(directory.glob("legal_core_download_*.sqlite")), [])

    def test_main_dispatches_verify_only_without_installing(self) -> None:
        manifest_hash = "b" * 64
        with mock.patch.object(verify, "verify_only", return_value=0) as verify_call:
            with mock.patch.object(verify, "install") as install_call:
                status = verify.main(
                    [
                        "--verify-only",
                        "--manifest",
                        "manifest.json",
                        "--manifest-sha256",
                        manifest_hash,
                        "--output",
                        "installed.sqlite",
                    ]
                )
        self.assertEqual(status, 0)
        verify_call.assert_called_once_with(
            "manifest.json",
            Path("installed.sqlite"),
            manifest_hash,
        )
        install_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
