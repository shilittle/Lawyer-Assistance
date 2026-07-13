#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_legal_core.py")
SPEC = importlib.util.spec_from_file_location("build_legal_core", MODULE_PATH)
assert SPEC and SPEC.loader
build = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build
SPEC.loader.exec_module(build)


class LegalCoreBuildTests(unittest.TestCase):
    def test_parse_articles_splits_chinese_article_numbers(self) -> None:
        text = "第一条 为了规范事项，制定本法。\n第二条 本法适用于相关活动。"

        articles = build.parse_articles(text)

        self.assertEqual([item[0] for item in articles], ["第一条", "第二条"])
        self.assertIn("规范事项", articles[0][3])

    def test_parse_articles_keeps_full_text_when_no_article_numbers(self) -> None:
        text = "这是一个没有逐条编号的正式决定全文。决定自公布之日起施行。"

        articles = build.parse_articles(text)

        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0][0], "全文")
        self.assertEqual(articles[0][3], text)

    def test_docx_text_extracts_word_paragraphs(self) -> None:
        namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        document_xml = f"""
        <w:document xmlns:w="{namespace}">
          <w:body>
            <w:p><w:r><w:t>第一条</w:t></w:r><w:r><w:t> 官方正文</w:t></w:r></w:p>
            <w:p><w:r><w:t>第二条 后续正文</w:t></w:r></w:p>
          </w:body>
        </w:document>
        """.encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "law.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("word/document.xml", document_xml)

            text = build.docx_text(path)

        self.assertIn("第一条 官方正文", text)
        self.assertIn("第二条 后续正文", text)

    def test_extract_gov_article_text_prefers_content_container(self) -> None:
        markup = """
        <html><body><script>bad()</script>
        <div id="UCAP-CONTENT"><p>第一条 官方网页正文。</p><p>第二条 后续内容。</p></div></body></html>
        """

        text = build.extract_gov_article_text(markup)

        self.assertIn("第一条 官方网页正文", text)
        self.assertNotIn("bad()", text)

    def test_waf_challenge_detection(self) -> None:
        markup = "<html>Please enable JavaScript and refresh the page<script src='/wzws-waf-cgi/jquery.js'></script></html>"

        self.assertTrue(build.looks_like_waf_challenge(markup))

    def test_amendment_relation_types(self) -> None:
        self.assertEqual(build.amendment_relation_types({"title": "关于修改某法的决定"}), ("amended_by", "amends"))
        self.assertEqual(build.amendment_relation_types({"title": "关于废止某条例的决定"}), ("repealed_by", "repeals"))

    def test_insert_articles_keeps_duplicate_article_numbers(self) -> None:
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript((build.ROOT / "data" / "schema" / "legal_core.sql").read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO source_systems (id, name, base_url, official_scope, maintainer, notes)
            VALUES ('test_source', '测试来源', 'https://example.test', '测试', '测试', '测试')
            """
        )
        connection.execute(
            """
            INSERT INTO issuing_authorities (id, name, authority_type, country_region)
            VALUES ('auth-test', '测试机关', 'test', 'CN')
            """
        )
        connection.execute(
            """
            INSERT INTO law_documents (
              id, title, document_type, authority_id, jurisdiction, effectiveness_level,
              status, summary, source_system_id, source_external_id
            )
            VALUES ('doc-test', '测试法', 'law', 'auth-test', 'CN', 'national_law',
                    'in_force', '测试', 'test_source', 'doc-test')
            """
        )
        connection.execute(
            """
            INSERT INTO law_versions (id, document_id, version_label, status, effective_from, source_reference)
            VALUES ('ver-test', 'doc-test', '测试版本', 'in_force', '2026-01-01', '测试')
            """
        )
        text = "第一条 第一段。\n第一条 第二段。"

        count = build.insert_articles(
            connection,
            document_id="doc-test",
            version_id="ver-test",
            title="测试法",
            text=text,
            updated_on="2026-01-01",
        )

        rows = connection.execute(
            "SELECT article_number, content FROM law_articles ORDER BY article_order, article_number"
        ).fetchall()
        self.assertEqual(count, 2)
        self.assertEqual(rows[0][0], "第一条")
        self.assertEqual(rows[1][0], "第一条-2")


    def test_insert_articles_skips_title_only_preamble(self) -> None:
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript((build.ROOT / "data" / "schema" / "legal_core.sql").read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO source_systems (id, name, base_url, official_scope, maintainer, notes)
            VALUES ('test_source', 'test source', 'https://example.test', 'test', 'test', 'test')
            """
        )
        connection.execute(
            """
            INSERT INTO issuing_authorities (id, name, authority_type, country_region)
            VALUES ('auth-test', 'test authority', 'test', 'CN')
            """
        )
        title = "\u4e2d\u534e\u4eba\u6c11\u5171\u548c\u56fd\u6d4b\u8bd5\u6761\u4f8b"
        connection.execute(
            """
            INSERT INTO law_documents (
              id, title, document_type, authority_id, jurisdiction, effectiveness_level,
              status, summary, source_system_id, source_external_id
            )
            VALUES ('doc-test', ?, 'law', 'auth-test', 'CN', 'national_law',
                    'in_force', 'summary', 'test_source', 'doc-test')
            """,
            (title,),
        )
        connection.execute(
            """
            INSERT INTO law_versions (id, document_id, version_label, status, effective_from, source_reference)
            VALUES ('ver-test', 'doc-test', 'test version', 'in_force', '2026-01-01', 'test')
            """
        )
        text = (
            f"{title}\n"
            "\u7b2c\u4e00\u6761 \u4e3a\u4e86\u89c4\u8303\u4e8b\u9879\uff0c\u5236\u5b9a\u672c\u6761\u4f8b\u3002\n"
            "\u7b2c\u4e8c\u6761 \u672c\u6761\u4f8b\u9002\u7528\u4e8e\u76f8\u5173\u6d3b\u52a8\u3002"
        )

        count = build.insert_articles(
            connection,
            document_id="doc-test",
            version_id="ver-test",
            title=title,
            text=text,
            updated_on="2026-01-01",
        )

        rows = connection.execute(
            "SELECT article_number, content FROM law_articles ORDER BY article_order"
        ).fetchall()
        self.assertEqual(count, 2)
        self.assertEqual([row[0] for row in rows], ["\u7b2c\u4e00\u6761", "\u7b2c\u4e8c\u6761"])
        self.assertNotIn(title, [row[1] for row in rows])

    def test_text_marker_hits_ignores_official_english_terms(self) -> None:
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript((build.ROOT / "data" / "schema" / "legal_core.sql").read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO source_systems (id, name, base_url, official_scope, maintainer, notes)
            VALUES ('test_source', 'test source', 'https://example.test', 'test', 'test', 'test')
            """
        )
        connection.execute(
            """
            INSERT INTO source_records (
              id, source_system_id, external_id, record_type, retrieved_at, checksum, raw_text
            )
            VALUES ('src-official', 'test_source', 'official', 'text',
                    '2026-01-01T00:00:00+00:00', 'checksum',
                    'Official Sample and Democratic Republic are terms in an official appendix.')
            """
        )

        self.assertEqual(build.text_marker_hits(connection), 0)

        connection.execute(
            """
            INSERT INTO source_records (
              id, source_system_id, external_id, record_type, retrieved_at, checksum, raw_text
            )
            VALUES ('src-fixture', 'test_source', 'fixture', 'text',
                    '2026-01-01T00:00:00+00:00', 'checksum2',
                    'sample data fixture_legal placeholder')
            """
        )

        self.assertEqual(build.text_marker_hits(connection), 1)


if __name__ == "__main__":
    unittest.main()
