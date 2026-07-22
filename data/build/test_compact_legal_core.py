#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = Path(__file__).with_name("compact_legal_core.py")
SPEC = importlib.util.spec_from_file_location("compact_legal_core", MODULE_PATH)
assert SPEC and SPEC.loader
compact = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compact
SPEC.loader.exec_module(compact)


class CompactLegalCoreTests(unittest.TestCase):
    def create_archival_database(self, path: Path) -> None:
        connection = sqlite3.connect(path)
        connection.executescript((ROOT / "data" / "schema" / "legal_core.sql").read_text(encoding="utf-8"))
        connection.executescript(
            (ROOT / "data" / "fixtures" / "legal_core_retrieval_fixture.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.execute(
            """
            INSERT INTO source_systems (
              id, name, base_url, official_scope, maintainer, retrieved_at, notes
            ) VALUES ('official', 'Official fixture', 'https://example.test', 'fixture', 'test', NULL, '')
            """
        )
        connection.execute(
            """
            INSERT INTO source_records (
              id, source_system_id, external_id, record_type, source_url,
              retrieved_at, checksum, raw_json, raw_text
            ) VALUES (
              'source-1', 'official', '1', 'detail', 'https://example.test/1',
              '2026-07-13T00:00:00Z', 'abc', ?, ?
            )
            """,
            ("x" * 100_000, "相同原始正文" * 20_000),
        )
        connection.execute(
            """
            INSERT INTO legal_attachments (
              id, document_id, source_system_id, external_id, title,
              attachment_type, file_type, source_url, storage_path, raw_json
            ) VALUES (
              'attachment-1', 'cn-civil-code', 'official', '1', 'archive',
              'source', 'json', 'https://example.test/1', 'cache/1.json', '{}'
            )
            """
        )
        timestamp = "2026-07-13T00:00:00Z"
        for key, value in {
            "coverage_status": "complete",
            "dataset_name": "official-china-legal-core",
            "dataset_version": "fixture-runtime-v1",
        }.items():
            connection.execute(
                """
                INSERT INTO database_metadata (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, value, timestamp),
            )
        manifest_hash = compact.source_manifest_sha256(connection)
        connection.execute(
            """
            INSERT INTO database_metadata (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            ("source_manifest_sha256", manifest_hash, timestamp),
        )
        connection.commit()
        connection.close()

    def create_archival_manifest(self, source: Path, path: Path) -> dict[str, object]:
        connection = sqlite3.connect(source)
        try:
            metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
            source_manifest_hash = compact.source_manifest_sha256(connection)
        finally:
            connection.close()
        payload: dict[str, object] = {
            "dataset_version": metadata["dataset_version"],
            "generated_at": "2026-07-13T00:00:00Z",
            "filename": source.name,
            "size_bytes": source.stat().st_size,
            "sha256": compact.sha256_file(source),
            "source_manifest_sha256": source_manifest_hash,
            "schema_version": metadata["schema_version"],
            "distribution_status": "archival_local_snapshot",
            "download_url": None,
            "ci_fixture_allowed": False,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return payload

    def test_checked_in_runtime_evidence_binds_archival_manifest_bytes(self) -> None:
        generated = ROOT / "data" / "generated"
        archival_manifest = generated / "legal_core_full_manifest.json"
        distribution = json.loads(
            (generated / "legal_core_distribution_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        runtime_report = json.loads(
            (generated / "legal_core_runtime_report.json").read_text(encoding="utf-8")
        )
        archival_manifest_sha256 = compact.sha256_file(archival_manifest)

        self.assertEqual(
            distribution["archival_manifest_filename"], archival_manifest.name
        )
        self.assertEqual(
            distribution["archival_manifest_sha256"], archival_manifest_sha256
        )
        self.assertEqual(
            runtime_report["archival_manifest"]["sha256"],
            archival_manifest_sha256,
        )

    def test_builds_verified_contentless_deduplicated_runtime_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "full.sqlite"
            output = root / "runtime.sqlite"
            report = root / "report.json"
            manifest = root / "manifest.json"
            archival_manifest = root / "full_manifest.json"
            self.create_archival_database(source)
            self.create_archival_manifest(source, archival_manifest)

            result = compact.compact(
                source,
                output,
                report,
                manifest,
                archival_manifest_path=archival_manifest,
            )

            connection = sqlite3.connect(output)
            try:
                article_count = connection.execute("SELECT COUNT(*) FROM law_articles").fetchone()[0]
                distinct_count = connection.execute(
                    "SELECT COUNT(*) FROM law_article_contents"
                ).fetchone()[0]
                source_connection = sqlite3.connect(source)
                try:
                    original_distinct = source_connection.execute(
                        "SELECT COUNT(DISTINCT content) FROM law_articles"
                    ).fetchone()[0]
                finally:
                    source_connection.close()
                fts_hits = connection.execute(
                    """
                    SELECT articles.id
                    FROM law_articles_fts
                    JOIN law_articles AS articles ON articles.rowid = law_articles_fts.rowid
                    WHERE law_articles_fts MATCH ?
                    """,
                    ('"违约责任"',),
                ).fetchall()
                source_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(source_records)")
                }
                citation_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(citation_metadata)")
                }
                fts_content_table = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'law_articles_fts_content'"
                ).fetchone()[0]
                attachment_table = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'legal_attachments'"
                ).fetchone()[0]
                runtime_metadata = dict(
                    connection.execute("SELECT key, value FROM database_metadata")
                )
            finally:
                connection.close()

            report_payload = json.loads(report.read_text(encoding="utf-8"))
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))

            self.assertEqual(result["verification"]["status"], "complete")
            self.assertEqual(article_count, 7)
            self.assertEqual(distinct_count, original_distinct)
            self.assertLess(distinct_count, article_count)
            self.assertTrue(fts_hits)
            self.assertNotIn("raw_json", source_columns)
            self.assertNotIn("raw_text", source_columns)
            self.assertNotIn("id", citation_columns)
            self.assertEqual(fts_content_table, 0)
            self.assertEqual(attachment_table, 0)
            self.assertTrue(report.is_file())
            self.assertTrue(manifest.is_file())
            self.assertEqual(runtime_metadata["distribution_profile"], compact.RUNTIME_PROFILE)
            self.assertEqual(
                runtime_metadata["runtime_source_verification"], "trusted_archival_manifest"
            )
            self.assertEqual(manifest_payload["filename"], output.name)
            self.assertIs(manifest_payload["ci_fixture_allowed"], False)
            self.assertEqual(manifest_payload["runtime_profile"], compact.RUNTIME_PROFILE)
            self.assertEqual(
                manifest_payload["runtime_schema_version"], compact.RUNTIME_SCHEMA_VERSION
            )
            self.assertEqual(manifest_payload["archival_source_sha256"], compact.sha256_file(source))
            self.assertEqual(
                manifest_payload["archival_manifest_sha256"],
                compact.sha256_file(archival_manifest),
            )
            self.assertEqual(manifest_payload["counts"], report_payload["counts"])
            self.assertEqual(manifest_payload["counts"]["articles"], article_count)
            self.assertIs(report_payload["ci_fixture_allowed"], False)
            self.assertTrue(report_payload["source_revalidated_after_compaction"])

    def test_rejects_every_archival_manifest_binding_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "full.sqlite"
            archival_manifest = root / "full_manifest.json"
            self.create_archival_database(source)
            base = self.create_archival_manifest(source, archival_manifest)
            mismatches = {
                "filename": "wrong.sqlite",
                "size_bytes": int(base["size_bytes"]) + 1,
                "sha256": "0" * 64,
                "dataset_version": "wrong-version",
                "schema_version": "999",
                "source_manifest_sha256": "f" * 64,
                "ci_fixture_allowed": True,
            }

            for field, bad_value in mismatches.items():
                with self.subTest(field=field):
                    payload = dict(base)
                    payload[field] = bad_value
                    archival_manifest.write_text(
                        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
                    )
                    output = root / f"runtime-{field}.sqlite"
                    report = root / f"report-{field}.json"
                    manifest = root / f"manifest-{field}.json"
                    with self.assertRaisesRegex(RuntimeError, "archival manifest"):
                        compact.compact(
                            source,
                            output,
                            report,
                            manifest,
                            archival_manifest_path=archival_manifest,
                        )
                    self.assertFalse(output.exists())
                    self.assertFalse(report.exists())
                    self.assertFalse(manifest.exists())

    def test_unverified_source_is_forced_to_non_release_fixture_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "unverified.sqlite"
            output = root / "runtime.sqlite"
            report = root / "report.json"
            manifest = root / "manifest.json"
            self.create_archival_database(source)
            connection = sqlite3.connect(source)
            try:
                connection.execute(
                    "UPDATE database_metadata SET value = 'incomplete' WHERE key = 'coverage_status'"
                )
                connection.execute(
                    "UPDATE database_metadata SET value = 'looks-official' WHERE key = 'dataset_name'"
                )
                connection.commit()
            finally:
                connection.close()

            compact.compact(
                source,
                output,
                report,
                manifest,
                allow_unverified_source=True,
                archival_manifest_path=root / "does-not-exist.json",
            )

            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            connection = sqlite3.connect(output)
            try:
                metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
            finally:
                connection.close()
            self.assertIs(manifest_payload["ci_fixture_allowed"], True)
            self.assertEqual(manifest_payload["runtime_profile"], compact.UNVERIFIED_RUNTIME_PROFILE)
            self.assertEqual(manifest_payload["distribution_status"], "ci_fixture_not_for_release")
            self.assertEqual(manifest_payload["dataset_name"], compact.FIXTURE_DATASET_NAME)
            self.assertEqual(manifest_payload["dataset_version"], compact.FIXTURE_DATASET_VERSION)
            self.assertEqual(manifest_payload["source_verification"], "unverified_ci_fixture")
            self.assertIsNone(manifest_payload["archival_manifest_sha256"])
            self.assertEqual(metadata["dataset_name"], compact.FIXTURE_DATASET_NAME)
            self.assertEqual(metadata["dataset_version"], compact.FIXTURE_DATASET_VERSION)
            self.assertEqual(metadata["coverage_status"], "ci_fixture")
            self.assertEqual(metadata["distribution_profile"], compact.UNVERIFIED_RUNTIME_PROFILE)
            self.assertEqual(metadata["runtime_source_dataset_name"], "looks-official")
            self.assertEqual(metadata["runtime_source_verification"], "unverified_ci_fixture")
            self.assertEqual(metadata["runtime_ci_fixture_allowed"], "true")

    def test_source_change_during_compaction_blocks_all_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "full.sqlite"
            output = root / "runtime.sqlite"
            report = root / "report.json"
            manifest = root / "manifest.json"
            archival_manifest = root / "full_manifest.json"
            self.create_archival_database(source)
            self.create_archival_manifest(source, archival_manifest)
            original_sha256_file = compact.sha256_file
            source_hash_calls = 0

            def mutate_before_final_source_hash(path: Path) -> str:
                nonlocal source_hash_calls
                if path.resolve() == source.resolve():
                    source_hash_calls += 1
                    if source_hash_calls == 2:
                        with path.open("ab") as handle:
                            handle.write(b"changed-during-compaction")
                return original_sha256_file(path)

            with mock.patch.object(
                compact, "sha256_file", side_effect=mutate_before_final_source_hash
            ):
                with self.assertRaisesRegex(RuntimeError, "source file changed|source changed"):
                    compact.compact(
                        source,
                        output,
                        report,
                        manifest,
                        archival_manifest_path=archival_manifest,
                    )

            self.assertEqual(source_hash_calls, 2)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())
            self.assertFalse(manifest.exists())
            self.assertFalse(list(root.glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
