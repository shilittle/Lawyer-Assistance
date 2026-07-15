#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("stage_1c_history.py")
SPEC = importlib.util.spec_from_file_location("stage_1c_history", MODULE_PATH)
assert SPEC and SPEC.loader
stage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stage
SPEC.loader.exec_module(stage)


class Stage1CHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        schema = stage.ROOT / "data" / "schema" / "legal_core.sql"
        self.connection.executescript(schema.read_text(encoding="utf-8"))
        self.connection.execute(
            """
            INSERT INTO source_systems (id, name, base_url, official_scope, maintainer, notes)
            VALUES ('flk_npc', '国家法律法规数据库', 'https://flk.npc.gov.cn/', '法律', '全国人大常委会办公厅', 'test')
            """
        )
        self.connection.execute(
            """
            INSERT INTO issuing_authorities (id, name, authority_type, country_region)
            VALUES ('authority', '全国人民代表大会常务委员会', 'state_authority', 'CN')
            """
        )

    def tearDown(self) -> None:
        self.connection.close()

    def add_version(self, suffix: str, effective_from: str) -> None:
        document_id = f"doc-{suffix}"
        version_id = f"version-{suffix}"
        source_id = f"source-{suffix}"
        article_id = f"article-{suffix}"
        self.connection.execute(
            """
            INSERT INTO source_records
              (id, source_system_id, external_id, record_type, source_url, retrieved_at, checksum)
            VALUES (?, 'flk_npc', ?, 'detail', ?, '2026-07-11T00:00:00Z', ?)
            """,
            (source_id, suffix, f"https://flk.npc.gov.cn/detail2.html?ZmY4MDgxODE={suffix}", f"hash-{suffix}"),
        )
        self.connection.execute(
            """
            INSERT INTO law_documents (
              id, title, document_type, authority_id, jurisdiction, effectiveness_level,
              status, promulgated_on, source_url, summary, source_system_id,
              source_external_id, source_record_id
            ) VALUES (?, '中华人民共和国测试法', 'law', 'authority', 'CN', 'national_law',
                      'in_force', ?, ?, 'test', 'flk_npc', ?, ?)
            """,
            (document_id, effective_from, f"https://flk.npc.gov.cn/{suffix}", suffix, source_id),
        )
        self.connection.execute(
            """
            INSERT INTO law_versions
              (id, document_id, version_label, status, effective_from, source_reference)
            VALUES (?, ?, ?, 'in_force', ?, '国家法律法规数据库')
            """,
            (version_id, document_id, f"{effective_from}版本", effective_from),
        )
        self.connection.execute(
            """
            INSERT INTO law_articles
              (id, document_id, version_id, article_number, article_order, content)
            VALUES (?, ?, ?, '第一条', 1, ?)
            """,
            (article_id, document_id, version_id, f"{effective_from}正文"),
        )
        self.connection.execute(
            """
            INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label)
            VALUES (?, ?, ?, '第一条')
            """,
            (f"citation-{suffix}", article_id, f"law:{document_id}:{version_id}:art:1"),
        )

    def add_history_relation(self, left: str, right: str) -> None:
        self.connection.execute(
            """
            INSERT INTO law_relations
              (id, from_document_id, to_document_id, relation_type, description, source_reference)
            VALUES (?, ?, ?, 'history_version', '官方历史沿革', '国家法律法规数据库 lsyg')
            """,
            (f"rel-{left}-{right}", f"doc-{left}", f"doc-{right}"),
        )

    def test_normalize_history_merges_documents_and_bounds_versions(self) -> None:
        self.add_version("old", "2017-06-01")
        self.add_version("middle", "2022-09-01")
        self.add_version("current", "2026-01-01")
        self.add_history_relation("current", "middle")
        self.add_history_relation("middle", "old")

        report = stage.normalize_history(self.connection)
        stage.refresh_fts(self.connection)

        self.assertEqual(report.merged_family_count, 1)
        self.assertEqual(report.removed_document_count, 2)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM law_documents").fetchone()[0], 1
        )
        versions = [
            tuple(row)
            for row in self.connection.execute(
                "SELECT effective_from, effective_to FROM law_versions ORDER BY effective_from"
            ).fetchall()
        ]
        self.assertEqual(
            versions,
            [
                ("2017-06-01", "2022-08-31"),
                ("2022-09-01", "2025-12-31"),
                ("2026-01-01", None),
            ],
        )
        document_ids = {
            row[0] for row in self.connection.execute("SELECT DISTINCT document_id FROM law_articles")
        }
        self.assertEqual(document_ids, {"doc-current"})
        # Citation ids remain stable so previously persisted answers still resolve.
        citation_ids = {
            row[0] for row in self.connection.execute("SELECT citation_id FROM citation_metadata")
        }
        self.assertIn("law:doc-old:version-old:art:1", citation_ids)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM law_articles_fts").fetchone()[0], 3
        )

    def test_duplicate_effective_dates_are_declared_and_not_merged(self) -> None:
        self.add_version("a", "2022-01-01")
        self.add_version("b", "2022-01-01")
        self.add_history_relation("a", "b")

        report = stage.normalize_history(self.connection)

        self.assertEqual(report.merged_family_count, 0)
        self.assertEqual(report.skipped_family_count, 1)
        self.assertEqual(report.skipped_families[0]["reason"], "duplicate_effective_date")
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM law_documents").fetchone()[0], 2
        )

    def test_civil_code_article_1260_bounds_repealed_contract_law(self) -> None:
        self.add_version("contract-law", "1999-10-01")
        self.connection.execute(
            "UPDATE law_documents SET title = '中华人民共和国合同法' WHERE id = 'doc-contract-law'"
        )
        self.connection.execute(
            "UPDATE law_versions SET status = 'repealed', effective_to = NULL "
            "WHERE id = 'version-contract-law'"
        )

        changed = stage.apply_authoritative_terminal_dates(self.connection)

        self.assertEqual(changed, 1)
        self.assertEqual(
            self.connection.execute(
                "SELECT effective_to FROM law_versions WHERE id = 'version-contract-law'"
            ).fetchone()[0],
            "2020-12-31",
        )
        self.assertEqual(stage.apply_authoritative_terminal_dates(self.connection), 0)

        audit = stage.authoritative_terminal_date_audit(self.connection)
        self.assertEqual(audit["title_count"], 1)
        self.assertEqual(audit["version_count"], 1)
        self.assertEqual(audit["violation_count"], 0)
        self.assertEqual(audit["missing_article_count"], 0)

        self.connection.execute(
            "UPDATE law_versions SET effective_to = '2021-01-01' "
            "WHERE id = 'version-contract-law'"
        )
        corrupted = stage.authoritative_terminal_date_audit(self.connection)
        self.assertEqual(corrupted["title_count"], 0)
        self.assertEqual(corrupted["version_count"], 0)
        self.assertEqual(corrupted["violation_count"], 1)


if __name__ == "__main__":
    unittest.main()
