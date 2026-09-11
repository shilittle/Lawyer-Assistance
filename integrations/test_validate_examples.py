from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from integrations import validate_examples as validator


class IntegrationExamplesTests(unittest.TestCase):
    def setUp(self) -> None:
        validator.ERRORS.clear()

    def tearDown(self) -> None:
        validator.ERRORS.clear()

    def test_checked_in_examples_match_both_tool_contracts(self) -> None:
        validator.validate_integrations_root()
        validator.validate_rust_registry()
        self.assertEqual([], validator.ERRORS)

    def test_public_catalog_rejects_an_unexpected_extra_tool(self) -> None:
        path = validator.INTEGRATIONS / "tool-catalog.json"
        catalog = json.loads(path.read_text(encoding="utf-8"))
        catalog["tools"].append({"name": "unexpected_extra_tool"})
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "catalog.json"
            copied.write_text(json.dumps(catalog), encoding="utf-8")
            validator.validate_catalog(copied, "public_law_only", validator.PUBLIC_TOOLS)
        self.assertTrue(any("exact tool contract" in error for error in validator.ERRORS))

    def test_legacy_profile_text_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "integrations"
            shutil.copytree(validator.INTEGRATIONS, copied)
            (copied / "example.md").write_text("approved_case_workspace", encoding="utf-8")
            validator.validate_no_legacy_profile_assets(copied)
        self.assertTrue(any("legacy profile" in error for error in validator.ERRORS))


if __name__ == "__main__":
    unittest.main()
