import importlib.util
import io
import threading
import time
import unittest
from pathlib import Path


PROBE_PATH = Path(__file__).parents[1] / "scripts/protocol_probe.py"
SPEC = importlib.util.spec_from_file_location("la_mineru_protocol_probe", PROBE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class _BlockingStream:
    def __init__(self) -> None:
        self.release = threading.Event()

    def readline(self, _limit: int) -> bytes:
        self.release.wait(5)
        return b""


class ProtocolProbeTests(unittest.TestCase):
    def test_three_page_qualification_shape_counts_eight_each_without_returning_text(self) -> None:
        document = {
            "pages": [
                {
                    "blocks": [
                        {"normalized_text": f"synthetic-{page}-{index}"}
                        for index in range(8)
                    ]
                    + [{"normalized_text": ""}, {"normalized_text": "   "}]
                }
                for page in range(3)
            ]
        }
        per_page, total = probe.text_block_counts(document)
        self.assertEqual(per_page, [8, 8, 8])
        self.assertEqual(total, 24)
        summary = {
            "perPageTextBlockCounts": per_page,
            "totalTextBlockCount": total,
        }
        self.assertNotIn("synthetic-", repr(summary))

    def test_quality_summary_contains_metadata_but_never_text(self) -> None:
        document = {
            "pages": [
                {
                    "status": "ok",
                    "rotation_degrees": 90,
                    "coverage_ppm": 123,
                    "minimum_ocr_confidence_ppm": 700_000,
                    "mean_ocr_confidence_ppm": 800_000,
                    "visual_risks": ["handwriting"],
                    "warnings": ["low_resolution"],
                    "blocks": [{"normalized_text": "synthetic-private-marker"}],
                }
            ]
        }
        summary = probe.quality_summary(document)
        self.assertEqual(summary[0]["warnings"], ["low_resolution"])
        self.assertEqual(summary[0]["rotationDegrees"], 90)
        self.assertNotIn("synthetic-private-marker", repr(summary))

    def test_text_count_rejects_missing_or_non_string_normalized_text(self) -> None:
        for block in ({}, {"normalized_text": 3}):
            with self.subTest(block=block), self.assertRaisesRegex(
                RuntimeError, "worker_document_invalid"
            ):
                probe.text_block_counts({"pages": [{"blocks": [block]}]})

    def test_background_reader_enforces_deadline_and_decodes_a_valid_line(self) -> None:
        reader = probe.ResponseReader(io.BytesIO(b'{"message_type":"health"}\n'))
        self.assertEqual(reader.read(time.monotonic() + 1), {"message_type": "health"})
        blocking = _BlockingStream()
        reader = probe.ResponseReader(blocking)
        try:
            with self.assertRaisesRegex(RuntimeError, "worker_timeout"):
                reader.read(time.monotonic() + 0.02)
        finally:
            blocking.release.set()


if __name__ == "__main__":
    unittest.main()
