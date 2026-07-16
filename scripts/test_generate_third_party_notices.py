import hashlib
import tempfile
import unittest
from pathlib import Path

if __package__:
    from scripts.generate_third_party_notices import canonical_text_sha256
else:
    # Keep the regression test runnable both as a module (the CI entry point)
    # and as a standalone file from the repository root.
    from generate_third_party_notices import canonical_text_sha256


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


if __name__ == "__main__":
    unittest.main()
