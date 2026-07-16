#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("stage_1c_corpora.py")
SPEC = importlib.util.spec_from_file_location("stage_1c_corpora", MODULE_PATH)
assert SPEC and SPEC.loader
corpora = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpora
SPEC.loader.exec_module(corpora)


class Stage1CCorporaTests(unittest.TestCase):
    def test_guiding_listing_parser_keeps_title_date_and_url(self) -> None:
        markup = """
        <li><a title="指导性案例279号：测试案" href="/shenpan/xiangqing/490521.html">测试</a>
        <i class="date">2026-02-28</i></li>
        """
        items = corpora.parse_listing(markup, r"/shenpan/xiangqing/\d+\.html")
        self.assertEqual(
            items,
            [{
                "title": "指导性案例279号：测试案",
                "published_on": "2026-02-28",
                "url": "https://www.court.gov.cn/shenpan/xiangqing/490521.html",
            }],
        )

    def test_content_parser_extracts_only_official_article_container(self) -> None:
        markup = """
        <div>navigation</div><div class="txt_txt"><strong>裁判要点</strong><br />
        第一项。<p>基本案情</p><script>secret()</script></div><div>footer</div>
        """
        content = corpora.parse_content(markup, {"txt_txt"})
        self.assertIn("裁判要点", content)
        self.assertIn("第一项", content)
        self.assertIn("基本案情", content)
        self.assertNotIn("navigation", content)
        self.assertNotIn("secret", content)
        self.assertNotIn("footer", content)

    def test_template_categories_and_pagination_are_deterministic(self) -> None:
        markup = """
        <a href="/susongyangshi/5.html">管辖</a>
        <a href="/susongyangshi/102.html">行政</a>
        <a href="/susongyangshi/5_3.html">尾页</a>
        """
        self.assertEqual(corpora.template_category_paths(markup), ["susongyangshi/5", "susongyangshi/102"])
        self.assertEqual(corpora.discover_last_page(markup, "/susongyangshi/5"), 3)

    def test_template_classifier_uses_stable_product_categories(self) -> None:
        self.assertEqual(corpora.classify_template("民事起诉状"), "complaint")
        self.assertEqual(corpora.classify_template("民事裁定书"), "ruling")
        self.assertEqual(corpora.classify_template("民事管辖协商函"), "other_official_court_document")

    def test_guiding_number_accepts_old_and_new_official_labels(self) -> None:
        self.assertEqual(corpora.guiding_case_number("指导案例45号：测试案"), "45")
        self.assertEqual(corpora.guiding_case_number("指导性案例279号：测试案"), "279")
        self.assertIsNone(corpora.guiding_case_number("最高人民法院关于发布第十批指导性案例的通知"))

    def test_splits_individual_typical_cases_and_ignores_contents_list(self) -> None:
        record = corpora.CorpusRecord(
            external_id="100",
            title="测试典型案例",
            published_on="2026-01-01",
            source_url="https://www.court.gov.cn/zixun/xiangqing/100.html",
            content=(
                "案例一：目录标题一\n案例二：目录标题二\n"
                "【案例一】真实标题一\n【基本案情】\n这是第一件案例的完整案情和处理过程，内容足够长以通过分段要求。"
                "本案经过审理后依法作出处理，并形成可供参考的典型意义。\n"
                "【典型意义】\n第一件案例的典型意义。\n"
                "【案例二】真实标题二\n【基本案情】\n这是第二件案例的完整案情和处理过程，内容足够长以通过分段要求。"
                "本案经过审理后依法作出处理，并形成可供参考的典型意义。\n"
                "【典型意义】\n第二件案例的典型意义。"
            ),
            checksum="abc",
            raw_metadata={},
        )
        cases = corpora.split_typical_cases(record)
        self.assertEqual([case["title"] for case in cases], ["真实标题一", "真实标题二"])
        self.assertIn("第一件案例", cases[0]["content"])
        self.assertNotIn("第二件案例", cases[0]["content"])


if __name__ == "__main__":
    unittest.main()
