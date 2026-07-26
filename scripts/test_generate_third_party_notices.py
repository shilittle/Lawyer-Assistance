import hashlib
import tempfile
import unittest
from pathlib import Path

if __package__:
    from scripts.generate_third_party_notices import (
        CARGO_RELEASE_TARGET_PRODUCTS,
        SAFE_EXPORT_FONT_SHA256,
        bundled_asset_components,
        canonical_text_sha256,
        cargo_components,
        complete_missing_license_texts,
    )
else:
    # Keep the regression test runnable both as a module (the CI entry point)
    # and as a standalone file from the repository root.
    from generate_third_party_notices import (
        CARGO_RELEASE_TARGET_PRODUCTS,
        SAFE_EXPORT_FONT_SHA256,
        bundled_asset_components,
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

    def test_bundled_safe_export_font_is_hash_pinned_and_noticed(self) -> None:
        components = bundled_asset_components()
        self.assertEqual(len(components), 1)
        component = components[0]
        self.assertEqual(component.name, "Noto Sans SC Regular")
        self.assertEqual(component.version, "2.004")
        self.assertEqual(component.license_expression, "OFL-1.1")
        self.assertIn("c7763f45", SAFE_EXPORT_FONT_SHA256)
        text_names = {name for name, _ in component.texts}
        self.assertIn("LICENSE-OFL-1.1.txt", text_names)
        self.assertIn("NOTICE-NOTO-SANS-SC.txt", text_names)

    def test_mcp_runtime_dependencies_are_in_the_release_notice_closure(self) -> None:
        self.assertEqual(
            CARGO_RELEASE_TARGET_PRODUCTS,
            (
                ("x86_64-pc-windows-msvc", frozenset({"lawyer-assistance-desktop", "legal-mcp"})),
                ("x86_64-unknown-linux-gnu", frozenset({"legal-mcp"})),
                ("aarch64-apple-darwin", frozenset({"legal-mcp"})),
            ),
        )
        components = {(component.name, component.version) for component in cargo_components()}
        self.assertIn(("rmcp", "2.2.0"), components)
        self.assertIn(("rmcp-macros", "2.2.0"), components)
        self.assertIn(("signal-hook-registry", "1.4.8"), components)

    def test_jsonschema_regex_uses_same_release_repository_license(self) -> None:
        components = {
            (component.name, component.version): component
            for component in complete_missing_license_texts(cargo_components())
        }
        jsonschema = components[("jsonschema", "0.48.2")]
        regex = components[("jsonschema-regex", "0.48.2")]
        uuid_simd = components[("uuid-simd", "0.8.0")]
        vsimd = components[("vsimd", "0.8.0")]

        self.assertEqual(regex.license_expression, "MIT")
        self.assertEqual(regex.texts[0][0], "UPSTREAM-LICENSE-MIT")
        self.assertEqual(regex.texts[0][1], jsonschema.texts[0][1])
        self.assertEqual(uuid_simd.texts, vsimd.texts)
        self.assertIn("Copyright (c) 2021 Nugine", uuid_simd.texts[0][1])


if __name__ == "__main__":
    unittest.main()
