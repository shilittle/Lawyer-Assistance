import subprocess
import tempfile
import unittest
from pathlib import Path

if __package__:
    from scripts.check_utf8_text import (
        MOJIBAKE_MARKERS,
        is_text_path,
        scan_bytes,
        scan_repository,
    )
else:
    from check_utf8_text import (
        MOJIBAKE_MARKERS,
        is_text_path,
        scan_bytes,
        scan_repository,
    )


class Utf8TextGateTests(unittest.TestCase):
    def test_selects_source_document_and_config_text_only(self) -> None:
        for path in (
            "src/main.rs",
            "src/App.tsx",
            "docs/readme.md",
            ".github/workflows/ci.yml",
            "Cargo.lock",
            "LICENSE",
            ".gitignore",
        ):
            with self.subTest(path=path):
                self.assertTrue(is_text_path(path))

        for path in (
            "data/legal_core.sqlite",
            "release/setup.exe",
            "docs/manual.docx",
            "assets/icon.png",
            "dist/archive.zip",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_text_path(path))

    def test_accepts_valid_utf8_and_two_question_marks(self) -> None:
        payload = "\u6cd5\u5f8b\u6587\u4e66 what??\n".encode("utf-8")
        self.assertEqual(scan_bytes("valid.md", payload), [])

    def test_rejects_invalid_utf8(self) -> None:
        issues = scan_bytes("invalid.md", b"valid\n\xff")
        self.assertEqual([issue.rule for issue in issues], ["invalid-utf8"])

    def test_rejects_replacement_and_question_mark_run(self) -> None:
        payload = ("prefix\ufffd " + "?" * 3).encode("utf-8")
        rules = {issue.rule for issue in scan_bytes("broken.md", payload)}
        self.assertEqual(rules, {"replacement-character", "question-mark-run"})

    def test_rejects_every_known_mojibake_marker(self) -> None:
        self.assertGreaterEqual(len(MOJIBAKE_MARKERS), 5)
        for description, marker in MOJIBAKE_MARKERS:
            with self.subTest(description=description):
                issues = scan_bytes("broken.md", marker.encode("utf-8"))
                self.assertIn("chinese-mojibake", {issue.rule for issue in issues})

    def test_repository_scan_uses_git_index_and_skips_binary_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "tracked.md").write_text("\u4e2d\u6587\n", encoding="utf-8")
            (root / "archive.sqlite").write_bytes(b"\xff\xfe\0\0")
            (root / "untracked.ts").write_bytes(b"\xff")
            subprocess.run(
                ["git", "-C", str(root), "add", "tracked.md", "archive.sqlite"],
                check=True,
            )

            paths, issues = scan_repository(root)
            self.assertEqual(paths, ("tracked.md",))
            self.assertEqual(issues, [])

            subprocess.run(
                ["git", "-C", str(root), "add", "untracked.ts"], check=True
            )
            paths, issues = scan_repository(root)
            self.assertEqual(paths, ("tracked.md", "untracked.ts"))
            self.assertEqual([issue.rule for issue in issues], ["invalid-utf8"])

    def test_repository_scan_skips_an_intentionally_deleted_tracked_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            tracked = root / "removed.md"
            tracked.write_text("\u6cd5\u5f8b\u6587\u4e66\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "removed.md"], check=True)
            tracked.unlink()

            paths, issues = scan_repository(root)
            self.assertEqual(paths, ("removed.md",))
            self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
