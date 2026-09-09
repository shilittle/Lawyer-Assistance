from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.prepare_web_smoke_db import (
    ROOT,
    SYNTHETIC_DATASET_NAME,
    SYNTHETIC_DISTRIBUTION_PROFILE,
    FixtureError,
    prepare_fixture,
)


class PrepareWebSmokeDbTests(unittest.TestCase):
    def test_creates_marked_fixture_with_web_smoke_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "web-smoke.sqlite"
            prepared = prepare_fixture(output)
            self.assertEqual(prepared, output.resolve())
            self.assertTrue(prepared.is_file())

            connection = sqlite3.connect(f"file:{prepared.as_posix()}?mode=ro", uri=True)
            try:
                metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
                self.assertEqual(metadata["dataset_name"], SYNTHETIC_DATASET_NAME)
                self.assertEqual(
                    metadata["distribution_profile"], SYNTHETIC_DISTRIBUTION_PROFILE
                )
                self.assertEqual(metadata["coverage_status"], "synthetic")
                self.assertGreater(
                    connection.execute(
                        "SELECT COUNT(*) FROM law_articles WHERE content LIKE '%合同%'"
                    ).fetchone()[0],
                    0,
                )
                self.assertGreater(
                    connection.execute(
                        "SELECT COUNT(*) FROM law_versions WHERE document_id = 'cn-civil-code'"
                    ).fetchone()[0],
                    0,
                )
                self.assertGreater(
                    connection.execute(
                        "SELECT COUNT(*) FROM law_relations WHERE from_document_id = 'cn-civil-code'"
                    ).fetchone()[0],
                    0,
                )
            finally:
                connection.close()

    def test_refuses_runtime_output(self) -> None:
        with self.assertRaisesRegex(FixtureError, "data/runtime"):
            prepare_fixture(ROOT / "data" / "runtime" / "legal_core.sqlite")


if __name__ == "__main__":
    unittest.main()
