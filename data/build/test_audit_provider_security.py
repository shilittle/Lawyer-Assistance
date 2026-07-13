import unittest
from pathlib import Path

from data.build.audit_provider_security import scan_text


class ProviderSecurityAuditTests(unittest.TestCase):
    def test_rejects_plaintext_credential_files_without_reading_the_value(self) -> None:
        findings = scan_text(Path("apikey.txt"), "opaque-value")

        self.assertEqual(findings[0].rule, "credential_file")
        self.assertNotIn("opaque-value", repr(findings))

    def test_detects_likely_provider_keys_without_printing_the_secret(self) -> None:
        findings = scan_text(
            Path("example.toml"),
            'api_key = "sk-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"',
        )

        self.assertTrue(findings)
        self.assertEqual(findings[0].rule, "provider_key_prefix")
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ", repr(findings))

    def test_allows_explicit_dummy_values_in_contract_tests(self) -> None:
        findings = scan_text(
            Path("example.rs"),
            'let api_key = "not-a-real-provider-secret-1234";',
        )

        self.assertEqual(findings, [])

    def test_rejects_sensitive_logging_even_for_runtime_variables(self) -> None:
        findings = scan_text(
            Path("example.ts"),
            'console.' + 'log("Authorization", apiKey);',
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "sensitive_logging")


if __name__ == "__main__":
    unittest.main()
