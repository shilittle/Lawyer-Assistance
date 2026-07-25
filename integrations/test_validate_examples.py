from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from integrations import validate_examples as validator


class PublicOnlyIntegrationValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        validator.ERRORS.clear()

    def tearDown(self) -> None:
        validator.ERRORS.clear()

    def copy_integrations(self, directory: str) -> Path:
        destination = Path(directory) / "integrations"
        shutil.copytree(validator.INTEGRATIONS, destination)
        return destination

    def test_checked_in_integrations_are_public_only_and_self_contained(self) -> None:
        validator.validate_integrations_root()
        validator.validate_repository_privacy_boundary()
        validator.validate_rust_registry()
        self.assertEqual([], validator.ERRORS)

    def test_case_raw_gate_is_first_operational_section(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "codex" / "skill" / "lawyer-assistance" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace(
                    "# Lawyer Assistance\n\n## Non-overridable CASE_RAW and case-data gate",
                    "# Lawyer Assistance\n\n## Weaker rule first\n\n## Non-overridable CASE_RAW and case-data gate",
                ),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(any("first operational section" in error for error in validator.ERRORS))

    def test_pending_classification_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "workbuddy" / "skill" / "lawyer-assistance" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace("CASE_REDACTED_PENDING", "REMOVED_PENDING"),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(any("CASE_REDACTED_PENDING" in error for error in validator.ERRORS))

    def test_diagram_skill_cannot_drop_subagent_egress_prohibition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "workbuddy" / "skill" / "lawyer-diagrams" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace("subagent", "delegated-worker"),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(any("mandatory privacy marker subagent" in error for error in validator.ERRORS))

    def test_diagram_skill_cannot_route_real_cases_to_raw_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "workbuddy" / "skill" / "lawyer-diagrams" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace(
                    "REAL_CASE_DIAGRAM_ROUTE=approved_case_workspace",
                    "REAL_CASE_DIAGRAM_ROUTE=diagram_authoring",
                ),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(
                any("REAL_CASE_DIAGRAM_ROUTE" in error for error in validator.ERRORS)
            )

    def test_label_only_approved_classification_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            agent = integrations / "opencode" / "agents" / "lawyer-assistance.md"
            agent.write_text(
                agent.read_text(encoding="utf-8").replace("CASE_REDACTED_APPROVED", "REMOVED_APPROVED"),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(any("CASE_REDACTED_APPROVED" in error for error in validator.ERRORS))

    def test_pre_skill_host_disclosure_boundary_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "codex" / "skill" / "lawyer-assistance" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace(
                    "The Skill cannot prevent or retract a first-message or attachment disclosure that Codex made before loading it.",
                    "The host boundary is unspecified.",
                ),
                encoding="utf-8",
            )
            validator.validate_skill_packages(integrations)
            self.assertTrue(any("host pre-Skill disclosure boundary missing" in error for error in validator.ERRORS))

    def test_repository_cannot_permit_host_raw_fact_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            readme.write_text(
                "Facts require host-supplied or explicitly authorized host-read text.\n",
                encoding="utf-8",
            )
            validator.validate_repository_privacy_boundary((readme,))
            self.assertTrue(any("permits CASE_RAW host content" in error for error in validator.ERRORS))

    def test_catalog_rejects_sensitive_sixth_tool(self) -> None:
        catalog = json.loads((validator.INTEGRATIONS / "tool-catalog.json").read_text(encoding="utf-8"))
        catalog["tools"].append(
            {
                "name": "citation_validate",
                "annotations": dict(validator.EXPECTED_ANNOTATIONS),
                "confirmation_required": False,
            }
        )
        validator.validate_catalog(catalog)
        self.assertTrue(any("exactly five" in error for error in validator.ERRORS))

    def test_codex_enabled_tools_reject_sensitive_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "codex" / "config.http.toml"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '  "legal_get_relations",',
                    '  "legal_get_relations",\n  "citation_validate",',
                ),
                encoding="utf-8",
            )
            validator.validate_integrations_root(integrations)
            self.assertTrue(any("enabled_tools must be exact public five" in error for error in validator.ERRORS))
    def test_opencode_wildcard_must_deny(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "opencode" / "opencode.local.json"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '"lawyer_assistance_*": "deny"',
                    '"lawyer_assistance_*": "ask"',
                ),
                encoding="utf-8",
            )
            validator.validate_integrations_root(integrations)
            self.assertTrue(any("wildcard must deny" in error for error in validator.ERRORS))

    def test_stdio_must_pin_public_law_only_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "workbuddy" / "connectors" / "stdio.windows.json"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '["--privacy-profile", "public_law_only", "stdio"]',
                    '["stdio"]',
                ),
                encoding="utf-8",
            )
            validator.validate_integrations_root(integrations)
            self.assertTrue(any("must pin public_law_only" in error for error in validator.ERRORS))

    def test_legacy_case_tool_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            readme = integrations / "workbuddy" / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "\nUse case_get_state for the workflow.\n",
                encoding="utf-8",
            )
            validator.validate_no_legacy_case_workflows(integrations)
            self.assertTrue(any("legacy case workflow marker" in error for error in validator.ERRORS))

    def test_packaged_config_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            asset = integrations / "codex" / "skill" / "lawyer-assistance" / "assets" / "config.http.toml"
            asset.write_text(asset.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            validator.validate_integrations_root(integrations)
            self.assertTrue(any("Codex packaged asset differs" in error for error in validator.ERRORS))

    def test_literal_bearer_secret_is_rejected(self) -> None:
        validator.validate_no_literal_secrets(
            Path("fixture.json"),
            {"Authorization": "Bearer " + "definitely-a-real-secret"},
        )
        self.assertTrue(
            any(
                "hard-coded bearer" in error or "environment placeholder" in error
                for error in validator.ERRORS
            )
        )

    def test_dangerous_non_loopback_flags_are_rejected(self) -> None:
        document = {
            "dangerously_allow_insecure_non_loopback_http": True,
            "args": ["serve", "--dangerously-allow-insecure-non-loopback-http"],
            "env": {
                "LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP": "true"
            },
        }
        validator.validate_no_dangerous_transport_opt_in(Path("fixture.json"), document)
        for opt_in in validator.DANGEROUS_NON_LOOPBACK_OPT_INS:
            self.assertTrue(any(opt_in in error for error in validator.ERRORS))

    def test_public_rust_registry_matches_five_tool_catalog(self) -> None:
        validator.validate_rust_registry()
        self.assertEqual([], validator.ERRORS)

    def test_output_root_cannot_be_reused_as_input_root(self) -> None:
        environment = {
            "LAWYER_ASSISTANCE_ALLOWED_ROOTS": "/srv/lawyer-assistance/cases:/srv/lawyer-assistance/exports",
            "LAWYER_ASSISTANCE_OUTPUT_ROOT": "/srv/lawyer-assistance/exports",
        }
        validator.validate_stdio_path_boundaries(
            Path("fixture.toml"),
            environment,
            "/srv/lawyer-assistance/cases",
            "/srv/lawyer-assistance/exports",
        )
        self.assertTrue(any("default allowed root drift" in error for error in validator.ERRORS))
        self.assertTrue(any("output root must not be an input root" in error for error in validator.ERRORS))


if __name__ == "__main__":
    unittest.main()
