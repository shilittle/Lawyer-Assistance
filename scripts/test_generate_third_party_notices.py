import hashlib
import tempfile
import unittest
from pathlib import Path

if __package__:
    from scripts.generate_third_party_notices import (
        SAFE_EXPORT_FONT_SHA256,
        bundled_asset_components,
        canonical_text_sha256,
        cargo_components,
    )
else:
    # Keep the regression test runnable both as a module (the CI entry point)
    # and as a standalone file from the repository root.
    from generate_third_party_notices import (
        SAFE_EXPORT_FONT_SHA256,
        bundled_asset_components,
        canonical_text_sha256,
        cargo_components,
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

    def test_bundled_safe_export_font_is_hash_pinned_and_noticed(self) -> None:
        components = bundled_asset_components()
        self.assertEqual(len(components), 1)
        component = components[0]
        self.assertEqual(component.name, "Noto Sans S Chinese Regular")
        self.assertEqual(component.version, "1.000")
        self.assertEqual(component.license_expression, "Apache-2.0")
        self.assertIn("7db3c634", SAFE_EXPORT_FONT_SHA256)
        text_names = {name for name, _ in component.texts}
        self.assertIn("LICENSE-APACHE-2.0.txt", text_names)
        self.assertIn("NOTICE-NOTO-SANS-S-CHINESE.txt", text_names)

    def test_mcp_runtime_dependencies_are_in_the_release_notice_closure(self) -> None:
        components = {(component.name, component.version) for component in cargo_components()}
        self.assertIn(("rmcp", "2.2.0"), components)
        self.assertIn(("rmcp-macros", "2.2.0"), components)


if __name__ == "__main__":
    unittest.main()
