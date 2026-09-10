from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("import_spc_txt_corpus.py")
SPEC = importlib.util.spec_from_file_location("import_spc_txt_corpus", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ImportSpcTxtCorpusTests(unittest.TestCase):
    def make_archive(self, directory: Path) -> Path:
        archive = directory / "corpus.zip"
        rows = []
        entries: list[tuple[str, bytes, dict[str, object]]] = []

        def add(
            csv_id: str,
            normalized: str,
            csv_type: str,
            title: str,
            path: str,
            metadata: dict[str, object],
            text: str,
        ) -> None:
            raw = text.encode("utf-8")
            entries.append((path, raw, {"txt_file": path, **metadata}))
            rows.append(
                {
                    "ID": csv_id,
                    "规范案例标识": normalized,
                    "类型": csv_type,
                    "标题": title,
                    "指导编号": str(metadata.get("guiding_number") or ""),
                    "来源": str(metadata.get("source_url") or "https://www.court.gov.cn/a"),
                    "TXT路径": path,
                    "SHA-256": MODULE.sha256_bytes(raw),
                }
            )

        add(
            "guiding-1",
            "guiding:1",
            "guiding",
            "指导性案例1号：劳动关系案",
            "txt/guiding/guiding-0001.txt",
            {"id": "guiding-0001", "guiding_number": 1, "source_url": "https://www.court.gov.cn/a"},
            "指导性案例1号：劳动关系案\n\n裁判要点\n劳动关系应结合事实认定。\n\n基本案情\n甲乙发生争议。\n\n裁判结果\n支持请求。",
        )
        add(
            "api-1",
            "guiding:1",
            "api_guiding",
            "指导性案例1号：劳动关系案",
            "txt/case_library/guiding/api-1.txt",
            {"id": "api-1", "guiding_number": 1, "source_url": "https://rmfyalk.court.gov.cn/a"},
            "指导性案例1号：劳动关系案 API副本",
        )
        add(
            "typical-1",
            "reference:2025-01-1-001-001",
            "typical",
            "执行典型案例合集",
            "txt/typical/typical-1.txt",
            {"id": "typical-1", "reference_number": "2025-01-1-001-001", "source_url": "https://www.court.gov.cn/b"},
            "执行典型案例合集\n\n1. 案件甲\n被执行人拒不履行。",
        )
        add(
            "notice-1",
            "notice:1",
            "notices",
            "部分指导性案例不再参照的通知",
            "txt/notices/notice-1.txt",
            {"id": "notice-1", "source_url": "https://www.court.gov.cn/c"},
            "关于部分指导性案例不再参照的通知\n\n指导性案例9号。",
        )
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zfile:
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=MODULE.CSV_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            zfile.writestr("案例目录.csv", buffer.getvalue().encode("utf-8-sig"))
            zfile.writestr("reports/corpus_manifest.json", json.dumps({"generated_at": "2026-09-09T00:00:00+00:00"}))
            for path, raw, metadata in entries:
                zfile.writestr(path, raw)
                zfile.writestr(f"metadata/{Path(path).stem}.json", json.dumps(metadata, ensure_ascii=False))
        return archive

    def test_load_preserves_variants_and_keeps_typical_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.make_archive(Path(temporary))
            cases, sources, info = MODULE.load_archive(archive)
        self.assertEqual(len(cases), 2)
        self.assertEqual(len(sources), 4)
        self.assertEqual(info["source_counts"]["api_guiding"], 1)
        self.assertEqual(info["source_counts"]["notices"], 1)
        self.assertEqual({case.case_type for case in cases}, {"guiding", "typical"})
        typical = next(case for case in cases if case.case_type == "typical")
        self.assertEqual(typical.case_id, "spc-typical-typical-1")
        notice = next(source for source in sources if source.source_kind == "notice")
        self.assertIsNone(notice.case_id)
        self.assertIn("通知", notice.source_header)
        self.assertTrue(notice.source_text.startswith(notice.source_header))
        self.assertEqual(sum(source.is_primary for source in sources), 2)

    def test_database_writes_source_text_and_foreign_key_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.make_archive(Path(temporary))
            cases, sources, info = MODULE.load_archive(archive)
            output = Path(temporary) / "judicial_cases.sqlite"
            MODULE.create_database(cases, sources, output, MODULE.database_metadata("test", "2026-09-09T00:00:00+00:00", info, cases))
            import sqlite3

            connection = sqlite3.connect(output)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM judicial_cases").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM judicial_case_sources").fetchone()[0], 4)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM judicial_case_sources WHERE case_id IS NULL").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT case_type FROM judicial_cases WHERE case_id = 'spc-typical-typical-1'").fetchone()[0], "typical")
            connection.close()

    def test_digest_mismatch_is_rejected(self) -> None:
        with self.assertRaises(MODULE.ImportError):
            MODULE.verify_row_digest("0" * 64, b"ok", "ok")


if __name__ == "__main__":
    unittest.main()
