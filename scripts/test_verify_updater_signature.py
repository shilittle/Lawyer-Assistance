import base64
import tempfile
import unittest
from pathlib import Path

from scripts.test_verify_release_assets import TEST_PUBLIC_KEY, TEST_TAURI_SIGNATURE
from scripts.verify_release_assets import VerificationError
from scripts.verify_updater_signature import verify_updater_signature


class UpdaterSignatureVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "test"
        self.signature = self.root / "test.sig"
        self.public_key = self.root / "updater-public.key"
        self.artifact.write_bytes(b"test")
        self.signature.write_bytes(base64.b64encode(TEST_TAURI_SIGNATURE.encode()))
        self.public_key.write_bytes(base64.b64encode(TEST_PUBLIC_KEY.encode()))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_tauri_signature_and_public_key_pass(self) -> None:
        verify_updater_signature(self.artifact, self.signature, self.public_key, "test")

    def test_wrong_key_password_output_tamper_and_filename_fail_closed(self) -> None:
        originals = {
            self.artifact: self.artifact.read_bytes(),
            self.signature: self.signature.read_bytes(),
            self.public_key: self.public_key.read_bytes(),
        }
        mutations = (
            ("artifact", self.artifact, b"Test"),
            ("signature", self.signature, b"not-base64"),
            ("key", self.public_key, b"not-base64"),
        )
        for label, path, value in mutations:
            with self.subTest(label=label):
                path.write_bytes(value)
                try:
                    with self.assertRaises(VerificationError):
                        verify_updater_signature(
                            self.artifact,
                            self.signature,
                            self.public_key,
                            "test",
                        )
                finally:
                    path.write_bytes(originals[path])
        with self.assertRaises(VerificationError):
            verify_updater_signature(self.artifact, self.signature, self.public_key, "other")


if __name__ == "__main__":
    unittest.main()
