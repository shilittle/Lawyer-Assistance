import hashlib
import tempfile
import unittest
from pathlib import Path

if __package__:
    from scripts.generate_third_party_notices import (
        CARGO_RELEASE_TARGET_PRODUCTS,
        canonical_text_sha256,
        cargo_components,
        complete_missing_license_texts,
    )
else:
    # Keep the regression test runnable both as a module (the CI entry point)
    # and as a standalone file from the repository root.
    from generate_third_party_notices import (
        CARGO_RELEASE_TARGET_PRODUCTS,
        canonical_text_sha256,
        cargo_components,
        complete_missing_license_texts,
    )

class CanonicalTextSha256Tests(unittest.TestCase):
    def test_line_endings_do_not_change_lockfile_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "lf.lock"
            crlf = root / "crlf.lock"
            lf.write_bytes(b"alpha\nbeta\n")
            crlf.write_bytes(b"alpha\r\nbeta\r\n")

            expected = hashlib.sha256(b"alpha\nbeta\n").hexdigest()
            self.assertEqual(canonical_text_sha256(lf), expected)
            self.assertEqual(canonical_text_sha256(crlf), expected)

    def test_mcp_runtime_dependencies_are_in_the_release_notice_closure(self) -> None:
        self.assertEqual(
            CARGO_RELEASE_TARGET_PRODUCTS,
            (
                ("x86_64-pc-windows-msvc", frozenset({"lawyer-assistance-server", "legal-mcp"})),
                ("x86_64-unknown-linux-gnu", frozenset({"lawyer-assistance-server", "legal-mcp"})),
                ("aarch64-apple-darwin", frozenset({"legal-mcp"})),
            ),
        )
        components = {(component.name, component.version) for component in cargo_components()}
        self.assertIn(("rmcp", "2.2.0"), components)
        self.assertIn(("rmcp-macros", "2.2.0"), components)
        self.assertIn(("signal-hook-registry", "1.4.8"), components)

    def test_current_release_dependencies_have_notice_text(self) -> None:
        components = complete_missing_license_texts(cargo_components())
        self.assertTrue(components)
        self.assertTrue(all(component.texts for component in components))
        self.assertFalse(any(component.name.startswith("tauri") for component in components))


if __name__ == "__main__":
    unittest.main()
