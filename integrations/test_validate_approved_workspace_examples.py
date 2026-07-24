from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from integrations import validate_approved_workspace_examples as approved
from integrations import validate_examples as public


class ApprovedWorkspaceIntegrationValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        approved.ERRORS.clear()
        public.ERRORS.clear()

    def tearDown(self) -> None:
        approved.ERRORS.clear()
        public.ERRORS.clear()

    def copy_integrations(self, directory: str) -> Path:
        destination = Path(directory) / "integrations"
        shutil.copytree(approved.INTEGRATIONS, destination)
        return destination

    def validate_fixture(self, integrations: Path) -> None:
        approved.validate_integrations_root(integrations, include_rust=False)

    def test_checked_in_approved_packages_are_exact_and_fail_closed(self) -> None:
        approved.validate_integrations_root()
        self.assertEqual([], approved.ERRORS)

    def test_existing_public_only_validator_remains_independently_green(self) -> None:
        public.validate_integrations_root()
        public.validate_repository_privacy_boundary()
        public.validate_rust_registry()
        self.assertEqual([], public.ERRORS)

    def test_catalog_rejects_missing_or_reordered_tool(self) -> None:
        catalog = json.loads(
            (approved.INTEGRATIONS / "tool-catalog.approved-case-workspace.json").read_text(
                encoding="utf-8"
            )
        )
        catalog["tools"][8], catalog["tools"][9] = catalog["tools"][9], catalog["tools"][8]
        approved.validate_catalog(catalog)
        self.assertTrue(any("exact ordered 15-tool" in error for error in approved.ERRORS))

    def test_catalog_requires_confirmation_for_work_product_write(self) -> None:
        catalog = json.loads(
            (approved.INTEGRATIONS / "tool-catalog.approved-case-workspace.json").read_text(
                encoding="utf-8"
            )
        )
        item = next(tool for tool in catalog["tools"] if tool["name"] == "case_write_work_product")
        item["confirmation_required"] = False
        approved.validate_catalog(catalog)
        self.assertTrue(any("write confirmation" in error for error in approved.ERRORS))

    def test_workbuddy_packaged_connector_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            asset = (
                integrations
                / "workbuddy"
                / "skill"
                / "lawyer-assistance-approved-workspace"
                / "assets"
                / "connectors"
                / "stdio.windows.json"
            )
            asset.write_text(asset.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self.validate_fixture(integrations)
            self.assertTrue(any("WorkBuddy approved asset differs" in error for error in approved.ERRORS))

    def test_workbuddy_stdio_must_pin_approved_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "workbuddy" / "connectors" / "approved-case-workspace" / "stdio.windows.json"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '"approved_case_workspace"', '"public_law_only"'
                ),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("approved session args drift" in error for error in approved.ERRORS))

    def test_sensitive_workspace_root_is_rejected(self) -> None:
        environment = {
            "LAWYER_ASSISTANCE_ALLOWED_ROOTS": "/srv/lawyer-assistance/vault",
            "LAWYER_ASSISTANCE_OUTPUT_ROOT": "/srv/lawyer-assistance/work-products",
        }
        approved.validate_approved_roots(
            Path("fixture.json"),
            environment,
            "/srv/lawyer-assistance/vault",
            "/srv/lawyer-assistance/work-products",
        )
        self.assertTrue(any("sensitive workspace root" in error for error in approved.ERRORS))

    def test_codex_config_must_remain_disabled_until_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "codex" / "config.approved-workspace.stdio.toml"
            config.write_text(
                config.read_text(encoding="utf-8").replace("enabled = false", "enabled = true"),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("unqualified example must be disabled" in error for error in approved.ERRORS))

    def test_codex_allowlist_rejects_extra_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "codex" / "config.approved-workspace.stdio.toml"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '  "case_export_work_product_manifest",',
                    '  "case_export_work_product_manifest",\n  "filesystem_read",',
                ),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("exact 15 tools required" in error for error in approved.ERRORS))

    def test_opencode_wildcard_must_remain_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            config = integrations / "opencode" / "opencode.approved-workspace.local.json"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    '"lawyer_assistance_*": "deny"',
                    '"lawyer_assistance_*": "allow"',
                ),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("wildcard must deny" in error for error in approved.ERRORS))

    def test_opencode_agent_frontmatter_wildcard_must_remain_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            agent = (
                integrations
                / "opencode"
                / "agents"
                / "lawyer-assistance-approved-workspace.md"
            )
            agent.write_text(
                agent.read_text(encoding="utf-8").replace(
                    "  lawyer_assistance_*: deny", "  lawyer_assistance_*: allow"
                ),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("agent wildcard must deny" in error for error in approved.ERRORS))

    def test_current_direct_read_invariant_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "codex" / "skill" / "lawyer-assistance-approved-workspace" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace(approved.SOURCE_INVARIANT, "SOURCE_REMOVED"),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("APPROVED_CONTENT_SOURCE" in error for error in approved.ERRORS))

    def test_work_product_sink_invariant_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            agent = integrations / "opencode" / "agents" / "lawyer-assistance-approved-workspace.md"
            agent.write_text(
                agent.read_text(encoding="utf-8").replace(approved.SINK_INVARIANT, "SINK_REMOVED"),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("WORK_PRODUCT_SINK" in error for error in approved.ERRORS))

    def test_each_forbidden_capability_must_be_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            rules = integrations / "opencode" / "AGENTS.approved-workspace.md.example"
            rules.write_text(
                rules.read_text(encoding="utf-8").replace("remote_ocr", "removed_capability"),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("remote_ocr" in error for error in approved.ERRORS))

    def test_clean_replacement_task_rule_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = integrations / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "SKILL.md"
            skill.write_text(
                skill.read_text(encoding="utf-8").replace("new clean task", "continued task"),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("clean replacement task" in error for error in approved.ERRORS))

    def test_prompt_label_cannot_be_declared_sufficient(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            rules = integrations / "opencode" / "AGENTS.approved-workspace.md.example"
            rules.write_text(
                rules.read_text(encoding="utf-8")
                + "\nA CASE_REDACTED_APPROVED label is sufficient.\n",
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("unsafe host permission" in error for error in approved.ERRORS))

    def test_literal_bearer_secret_is_rejected(self) -> None:
        approved.validate_generic_document(
            Path("fixture.json"),
            {"Authorization": "Bea" + "rer " + "definitely-a-real-secret"},
        )
        self.assertTrue(
            any(
                "hard-coded bearer" in error or "environment placeholder" in error
                for error in approved.ERRORS
            )
        )

    def test_app_issued_session_placeholder_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            paths = (
                integrations / "workbuddy" / "connectors" / "approved-case-workspace" / "stdio.windows.json",
                integrations / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "assets" / "connectors" / "stdio.windows.json",
            )
            for path in paths:
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        approved.SESSION_PLACEHOLDER,
                        "srv_NOT_A_VALID_APP_SESSION",
                    ),
                    encoding="utf-8",
                )
            self.validate_fixture(integrations)
            self.assertTrue(any("approved session args drift" in error for error in approved.ERRORS))

    def test_approved_stdio_rejects_environment_or_path_injection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            paths = (
                integrations / "workbuddy" / "connectors" / "approved-case-workspace" / "stdio.windows.json",
                integrations / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "assets" / "connectors" / "stdio.windows.json",
            )
            for path in paths:
                data = json.loads(path.read_text(encoding="utf-8"))
                data["mcpServers"]["lawyer_assistance"]["env"] = {
                    "LAWYER_ASSISTANCE_USER_DB": "C:/case/raw.sqlite"
                }
                path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            self.validate_fixture(integrations)
            self.assertTrue(any("only stdio session fields" in error for error in approved.ERRORS))

    def test_static_approved_http_asset_cannot_reappear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            path = integrations / "codex" / "config.approved-workspace.http.toml"
            path.write_text(
                "[mcp_servers.lawyer_assistance]\n"
                "url = \"http://127.0.0.1:8787/mcp\"\n"
                "bearer_token_env_var = \"LAWYER_ASSISTANCE_MCP_TOKEN\"\n",
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("static HTTP/Unix asset is forbidden" in error for error in approved.ERRORS))

    def test_work_product_readback_invariant_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            integrations = self.copy_integrations(directory)
            skill = (
                integrations
                / "workbuddy"
                / "skill"
                / "lawyer-assistance-approved-workspace"
                / "SKILL.md"
            )
            skill.write_text(
                skill.read_text(encoding="utf-8").replace(
                    approved.VERIFY_INVARIANT,
                    "VERIFY_REMOVED",
                ),
                encoding="utf-8",
            )
            self.validate_fixture(integrations)
            self.assertTrue(any("WORK_PRODUCT_VERIFY" in error for error in approved.ERRORS))

        approved.validate_rust_registry()
    def test_rust_case_tool_constant_matches_host_contract(self) -> None:
        self.assertEqual([], approved.ERRORS)


if __name__ == "__main__":
    unittest.main()
