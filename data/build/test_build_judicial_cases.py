from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_judicial_cases.py")
SPEC = importlib.util.spec_from_file_location("build_judicial_cases", MODULE_PATH)
assert SPEC and SPEC.loader
build = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build
SPEC.loader.exec_module(build)


class _Response:
    def __init__(self, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _Opener:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def open(self, request: object, timeout: int) -> _Response:
        return _Response(self.body)


def _detail_markup(title: str = "指导案例1号：测试案") -> str:
    return f"""
    <html><body>
      <div class="detail"><div class="title">{title}</div>
        <ul class="message"><li class="fl">来源：最高人民法院</li>
          <li class="fl">发布时间：2024-01-02 03:04:05</li></ul>
        <div class="txt_txt" id="zoom">
          <strong>关键词</strong><br/>民事/合同/违约<br/>
          <strong>裁判要点</strong><br/>1.第一项规则。<br/>2.第二项规则。<br/>
          <strong>相关法条</strong><br/>《中华人民共和国民法典》第五百七十七条<br/>
          <strong>基本案情</strong><br/>原告与被告签订合同，后发生争议。<br/>
          <strong>裁判结果</strong><br/>北京市第一中级人民法院作出（2024）京01民终1号判决。<br/>
          <strong>裁判理由</strong><br/>法院认为，违约责任应依法承担。
        </div>
      </div>
    </body></html>
    """


class JudicialCaseBuildTests(unittest.TestCase):
    def test_listing_parser_keeps_official_links_and_total(self) -> None:
        markup = """
        <div class="sec_list"><ul>
          <li><a title="指导案例2号：乙案" href="/shenpan/xiangqing/2.html">乙案</a><i class="date">2024-01-02</i></li>
          <li><a title="发布通知" href="/shenpan/xiangqing/notice.html">通知</a><i class="date">2024-01-03</i></li>
        </ul><div class="count">共<span class="num">2</span>篇文章</div>
        <a href="/shenpan/gengduo/77_2.html">下一页</a></div>
        """

        items, page_urls, total = build.parse_listing_page(markup)

        self.assertEqual(total, 2)
        self.assertEqual(len(items), 2)
        self.assertIn("https://www.court.gov.cn/shenpan/gengduo/77_2.html", page_urls)
        self.assertEqual(items[0].listed_date, "2024-01-02")

    def test_detail_parser_extracts_metadata_and_sections(self) -> None:
        detail = build.parse_detail_page(_detail_markup())

        self.assertEqual(detail["title"], "指导案例1号：测试案")
        self.assertEqual(detail["source"], "最高人民法院")
        self.assertEqual(detail["publication_date"], "2024-01-02")
        sections = build.extract_sections(detail["body"])
        self.assertEqual(build.split_keywords(sections["keywords"]), ["民事", "合同", "违约"])
        self.assertEqual(build.split_key_points(sections["key_points"]), ["第一项规则。", "第二项规则。"])
        self.assertIn("民法典", sections["related_laws"])
        self.assertIn("合同", sections["basic_facts"])

    def test_reference_selection_excludes_commentary_and_ordinary_typical_case(self) -> None:
        self.assertTrue(build.is_reference_candidate_title("入库参考案例：甲案"))
        self.assertTrue(build.is_reference_candidate_title("入库参考案例选介：乙案"))
        self.assertFalse(build.is_reference_candidate_title("入库参考案例解读：甲案"))
        self.assertFalse(build.is_reference_candidate_title("最高人民法院典型案例：甲案"))

    def test_build_record_has_stable_identity_and_source_hash(self) -> None:
        markup = _detail_markup()
        detail = build.parse_detail_page(markup)
        item = build.ListingItem(
            title="指导案例1号：测试案",
            url="https://www.court.gov.cn/shenpan/xiangqing/1.html",
            listed_date="2024-01-02",
        )
        record, reason = build.build_case_record(
            item=item,
            detail=detail,
            raw_body=markup.encode("utf-8"),
            case_type="guiding",
            fetched_at="2024-01-02T03:04:05+00:00",
        )

        self.assertIsNone(reason)
        assert record is not None
        self.assertEqual(record["case_id"], "spc-guiding-1")
        self.assertEqual(record["content_sha256"], build.sha256_bytes(detail["body"].encode("utf-8")))
        self.assertEqual(json.loads(record["key_points_json"]), ["第一项规则。", "第二项规则。"])
        self.assertEqual(record["publication_date"], "2024-01-02")
        self.assertEqual(record["case_number"], "（2024）京01民终1号")

    def test_withdrawn_notice_numbers_are_parsed_without_marking_other_numbers(self) -> None:
        text = "法〔2020〕343号。9号、20号指导性案例不再参照。本通知自2021年1月1日起施行。"

        self.assertEqual(build.extract_withdrawn_guiding_numbers(text), [9, 20])

    def test_challenge_does_not_write_response_cache(self) -> None:
        challenge = b"<html>Please enable JavaScript and refresh the page</html>"
        with tempfile.TemporaryDirectory() as tmp:
            fetcher = build.CachedFetcher(
                Path(tmp),
                refresh=True,
                retries=3,
                pause=0,
                opener=_Opener(challenge),
            )
            with self.assertRaises(build.FetchError):
                fetcher.fetch(build.GUIDING_INDEX_URL)
            self.assertFalse(list(Path(tmp).rglob("*.html")))
            self.assertEqual(fetcher.failures[0].kind, "challenge")

    def test_sqlite_sidecar_schema_and_json_contract(self) -> None:
        markup = _detail_markup()
        detail = build.parse_detail_page(markup)
        record, reason = build.build_case_record(
            item=build.ListingItem(
                title="指导案例1号：测试案",
                url="https://www.court.gov.cn/shenpan/xiangqing/1.html",
                listed_date="2024-01-02",
            ),
            detail=detail,
            raw_body=markup.encode("utf-8"),
            case_type="guiding",
            fetched_at="2024-01-02T03:04:05+00:00",
        )
        assert record is not None and reason is None
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "judicial_cases.sqlite"
            count, digest = build.create_database(
                [record],
                output,
                metadata={
                    "schema_version": "1",
                    "dataset_version": "judicial-cases-v1-test",
                },
            )
            self.assertEqual(count, 1)
            self.assertEqual(len(digest), 64)
            import sqlite3

            connection = sqlite3.connect(output)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertEqual(
                    connection.execute("SELECT value FROM database_metadata WHERE key='schema_version'").fetchone()[0],
                    "1",
                )
                row = connection.execute(
                    "SELECT case_id, case_type, guiding_number, keywords_json, key_points_json FROM judicial_cases"
                ).fetchone()
                self.assertEqual(row[0:3], ("spc-guiding-1", "guiding", 1))
                self.assertEqual(json.loads(row[3]), ["民事", "合同", "违约"])
                self.assertEqual(len(json.loads(row[4])), 2)
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
