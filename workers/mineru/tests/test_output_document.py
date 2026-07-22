import json
import tempfile
import unittest
from pathlib import Path

from lawyer_assistance_mineru_worker.output_document import (
    OutputFailure,
    _load_json,
    _low_resolution,
    _safe_output_files,
    output_tree_sha256,
    parse_content,
    parse_middle,
)


def realistic_middle() -> dict[str, object]:
    return {
        "pdf_info": [
            {
                "page_idx": 0,
                "page_size": [1000, 2000],
                "para_blocks": [
                    {
                        "type": "text",
                        "bbox": [100, 100, 500, 300],
                        "score": 0.96,
                        "lines": [
                            {"spans": [{"content": "合成当事人甲", "score": 0.91}]}
                        ],
                    },
                    {
                        "type": "table_body",
                        "bbox": [100, 400, 900, 900],
                        "score": 0.84,
                        "lines": [
                            {
                                "spans": [
                                    {
                                        "type": "table",
                                        "html": "<table><tr><td>合成金额</td></tr></table>",
                                    }
                                ]
                            }
                        ],
                    },
                    {
                        "type": "image",
                        "bbox": [100, 1000, 900, 1800],
                        "score": 0.73,
                        "lines": [],
                    },
                ],
                "discarded_blocks": [],
            }
        ]
    }


def realistic_content() -> list[dict[str, object]]:
    return [
        {
            "type": "text",
            "text": "合成当事人甲",
            "page_idx": 0,
            "bbox": [100, 50, 500, 150],
        },
        {
            "type": "table",
            "table_body": "<table><tr><td>合成金额</td></tr></table>",
            "page_idx": 0,
            "bbox": [100, 200, 900, 450],
        },
        {"type": "image", "page_idx": 0, "bbox": [100, 500, 900, 900]},
    ]


class OutputParserTests(unittest.TestCase):
    def test_realistic_text_table_image_output_is_fully_associated(self) -> None:
        middle = parse_middle(realistic_middle(), 1)
        parsed = parse_content(realistic_content(), middle)
        blocks, risks = parsed[0]
        self.assertEqual(len(blocks), 3)
        self.assertEqual([block["reading_order"] for block in blocks], [0, 1, 2])
        self.assertEqual([block["block_type"] for block in blocks], ["text", "table", "screenshot"])
        self.assertEqual(blocks[0]["normalized_text"], "合成当事人甲")
        self.assertEqual(blocks[0]["ocr_confidence_ppm"], 910_000)
        self.assertEqual(blocks[1]["layout_confidence_ppm"], 840_000)
        self.assertEqual(blocks[2]["normalized_text"], "")
        self.assertEqual(risks, {"complex_table", "screenshot"})
        self.assertTrue(all(str(block["raw_text_ref"]).startswith("obj_") for block in blocks))

    def test_missing_confidence_bbox_mismatch_and_incomplete_coverage_are_rejected(self) -> None:
        missing = realistic_middle()
        del missing["pdf_info"][0]["para_blocks"][0]["lines"][0]["spans"][0]["score"]
        with self.assertRaisesRegex(OutputFailure, "confidence_missing"):
            parse_middle(missing, 1)

        middle = parse_middle(realistic_middle(), 1)
        mismatch = realistic_content()
        mismatch[0]["bbox"] = [101, 50, 500, 150]
        with self.assertRaisesRegex(OutputFailure, "content_middle_association_invalid"):
            parse_content(mismatch, middle)

        incomplete = realistic_content()
        incomplete.pop(1)
        with self.assertRaisesRegex(OutputFailure, "middle_coverage_incomplete"):
            parse_content(incomplete, middle)

    def test_duplicate_json_and_output_tree_tamper_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_bytes(b'{"pdf_info":[],"pdf_info":[]}')
            with self.assertRaisesRegex(OutputFailure, "duplicate_json_field"):
                _load_json(duplicate, 1024)

            output = root / "output"
            (output / "nested").mkdir(parents=True)
            (output / "a.txt").write_bytes(b"synthetic-a")
            (output / "nested/b.txt").write_bytes(b"synthetic-b")
            first_files = _safe_output_files(output, 1024)
            first = output_tree_sha256(first_files)
            self.assertEqual([item[0] for item in first_files], ["a.txt", "nested/b.txt"])
            (output / "nested/b.txt").write_bytes(b"tampered-b")
            second = output_tree_sha256(_safe_output_files(output, 1024))
            self.assertNotEqual(first, second)

    def test_page_order_dimensions_and_numbers_are_strict(self) -> None:
        wrong_count = realistic_middle()
        with self.assertRaisesRegex(OutputFailure, "middle_page_count_mismatch"):
            parse_middle(wrong_count, 2)
        invalid = realistic_middle()
        invalid["pdf_info"][0]["page_size"][0] = float("nan")
        with self.assertRaisesRegex(OutputFailure, "page_dimension_invalid"):
            parse_middle(invalid, 1)
        invalid = realistic_middle()
        invalid["pdf_info"][0]["para_blocks"][0]["bbox"] = [10, 10, 1001, 20]
        with self.assertRaisesRegex(OutputFailure, "bbox_invalid"):
            parse_middle(invalid, 1)

    def test_low_resolution_signal_distinguishes_blur_from_edges(self) -> None:
        from PIL import Image

        blurred = Image.new("RGB", (128, 128), "white")
        checkerboard = Image.new("RGB", (128, 128), "white")
        pixels = checkerboard.load()
        for y in range(128):
            for x in range(128):
                if (x // 4 + y // 4) % 2:
                    pixels[x, y] = (0, 0, 0)
        self.assertTrue(_low_resolution(blurred))
        self.assertFalse(_low_resolution(checkerboard))


if __name__ == "__main__":
    unittest.main()
