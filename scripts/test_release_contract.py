from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from scripts.release.release_contract import (
    APP_ASSETS,
    COMPATIBILITY_ROWS,
    CURRENT_DOCS,
    IMMUTABLE_V031,
    MINERU_FILENAME,
    VERSION_SOURCES,
    WORKSPACE_PACKAGES,
    ContractError,
    ContractLoadError,
    load_contract,
    validate_repository,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = REPOSITORY_ROOT / "scripts/release/release-contract-v0.4.0.json"


class ReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.contract = load_contract(CONTRACT_PATH)
        self.write_repository("0.4.0-beta.2")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def write_repository(self, version: str) -> None:
        members = [
            "apps/desktop/src-tauri",
            "crates/assistant",
            "crates/citations",
            "crates/database",
            "crates/domain",
            "crates/diagrams",
            "crates/file-ingest",
            "crates/legal-mcp",
            "crates/material-processing",
            "crates/privacy",
            "crates/legal-services",
            "crates/providers",
            "crates/retrieval",
            "vendor/minisign-verify",
        ]
        names = [
            "lawyer-assistance-desktop",
            "assistant",
            "citations",
            "database",
            "domain",
            "diagrams",
            "file-ingest",
            "legal-mcp",
            "material-processing",
            "privacy",
            "legal-services",
            "providers",
            "retrieval",
            "minisign-verify",
        ]
        self.write("package.json", json.dumps({"version": version}) + "\n")
        self.write(
            "apps/desktop/package.json", json.dumps({"version": version}) + "\n"
        )
        self.write(
            "apps/desktop/src-tauri/tauri.conf.json",
            json.dumps({"version": version}) + "\n",
        )
        quoted_members = ",\n  ".join(json.dumps(member) for member in members)
        self.write(
            "Cargo.toml",
            f"[workspace]\nmembers = [\n  {quoted_members}\n]\n"
            f"[workspace.package]\nversion = {json.dumps(version)}\n",
        )
        for member, name in zip(members, names, strict=True):
            declared = "0.2.5" if member.startswith("vendor/") else version
            if name not in {"assistant", "legal-mcp", "minisign-verify"}:
                version_line = "version.workspace = true"
            else:
                version_line = f"version = {json.dumps(declared)}"
            self.write(
                f"{member}/Cargo.toml",
                f"[package]\nname = {json.dumps(name)}\n{version_line}\n",
            )
        lock = [
            "version = 4",
            *[
                f"\n[[package]]\nname = {json.dumps(name)}\nversion = {json.dumps(version)}"
                for name in WORKSPACE_PACKAGES
            ],
            '\n[[package]]\nname = "minisign-verify"\nversion = "0.2.5"',
        ]
        self.write("Cargo.lock", "\n".join(lock) + "\n")
        self.write(
            "crates/legal-mcp/src/config.rs",
            '#[command(\n    name = "lawyer-assistance-mcp",\n    version,\n)]\n',
        )
        compatibility = "\n".join(
            [
                "## Compatibility contract",
                "",
                f"| Binary release | `{version}` |",
                *COMPATIBILITY_ROWS,
            ]
        )
        self.write(
            "RELEASE_NOTES.md",
            f"# Lawyer Assistance {version}\n\n{compatibility}\n\n## Install and migration\n",
        )
        for document in CURRENT_DOCS:
            marker = document["versionMarkerTemplate"].format(version=version)
            self.write(document["path"], marker + "\n")
        self.write(
            "scripts/release/fixtures/mineru-formal-filename-v0.4.0.txt",
            MINERU_FILENAME + "\n",
        )

    def assert_code(self, code: str, callback) -> None:
        with self.assertRaises(ContractError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)

    def validate(self, mode: str = "current", binary: Path | None = None):
        return validate_repository(self.root, self.contract, mode, binary)

    def test_current_repository_and_formal_repository_pass(self) -> None:
        result = self.validate()
        self.assertEqual((result.mode, result.version), ("current", "0.4.0-beta.2"))
        self.write_repository("0.4.0")
        result = self.validate("formal")
        self.assertEqual((result.mode, result.version), ("formal", "0.4.0"))

    def test_formal_rejects_prerelease_build_and_wrong_core(self) -> None:
        self.assert_code("FORMAL_VERSION", lambda: self.validate("formal"))
        for version in ("0.4.0+build.1", "0.4.0-rc.1+build.1", "0.4.1"):
            self.write_repository(version)
            self.assert_code("FORMAL_VERSION", lambda: self.validate("formal"))

    def test_all_six_version_sources_are_exact(self) -> None:
        for source in VERSION_SOURCES[1:]:
            self.write_repository("0.4.0-beta.2")
            path = self.root / source["path"]
            path.write_text(
                path.read_text("utf-8").replace("0.4.0-beta.2", "0.4.0-beta.3"),
                encoding="utf-8",
            )
            self.assert_code("VERSION_DRIFT", self.validate)

    def test_workspace_and_lock_require_exactly_the_thirteen_products(self) -> None:
        manifest = self.root / "crates/retrieval/Cargo.toml"
        manifest.write_text(
            manifest.read_text("utf-8").replace('name = "retrieval"', 'name = "other"'),
            encoding="utf-8",
        )
        self.assert_code("WORKSPACE_SET", self.validate)
        self.write_repository("0.4.0-beta.2")
        lock = self.root / "Cargo.lock"
        lock.write_text(
            lock.read_text("utf-8").replace('name = "privacy"', 'name = "other"'),
            encoding="utf-8",
        )
        self.assert_code("CARGO_LOCK", self.validate)

    def test_lock_rejects_wrong_version_and_duplicate_local_package(self) -> None:
        lock = self.root / "Cargo.lock"
        text = lock.read_text("utf-8")
        lock.write_text(
            text.replace(
                'name = "privacy"\nversion = "0.4.0-beta.2"',
                'name = "privacy"\nversion = "0.4.0-beta.3"',
            ),
            encoding="utf-8",
        )
        self.assert_code("CARGO_LOCK_VERSION", self.validate)
        self.write_repository("0.4.0-beta.2")
        lock.write_text(
            lock.read_text("utf-8")
            + '\n[[package]]\nname = "privacy"\nversion = "0.4.0-beta.2"\n',
            encoding="utf-8",
        )
        self.assert_code("CARGO_LOCK", self.validate)

    def test_mcp_source_and_binary_probe_are_unique_and_quiet(self) -> None:
        binary = self.root / "lawyer-assistance-mcp.exe"
        binary.write_bytes(b"fixture")
        success = subprocess.CompletedProcess(
            [str(binary), "--version"], 0, b"lawyer-assistance-mcp 0.4.0-beta.2\n", b""
        )
        with patch("scripts.release.release_contract.subprocess.run", return_value=success):
            self.validate(binary=binary)
        for completed, code in (
            (subprocess.CompletedProcess([], 1, b"", b""), "MCP_BINARY"),
            (
                subprocess.CompletedProcess(
                    [], 0, b"lawyer-assistance-mcp 0.4.0-beta.2\nextra\n", b""
                ),
                "MCP_STDOUT",
            ),
            (
                subprocess.CompletedProcess(
                    [], 0, b"lawyer-assistance-mcp 0.4.0-beta.2\n", b"warning\n"
                ),
                "MCP_STDERR",
            ),
        ):
            with patch(
                "scripts.release.release_contract.subprocess.run", return_value=completed
            ):
                self.assert_code(code, lambda: self.validate(binary=binary))
        self.write("crates/legal-mcp/src/config.rs", 'name = "different"\n')
        self.assert_code("MCP_CONTRACT", self.validate)

    def test_release_notes_title_and_compatibility_contract_fail_closed(self) -> None:
        notes = self.root / "RELEASE_NOTES.md"
        notes.write_text(
            notes.read_text("utf-8").replace(
                "# Lawyer Assistance 0.4.0-beta.2", "# Lawyer Assistance 0.4.0-beta.3"
            ),
            encoding="utf-8",
        )
        self.assert_code("RELEASE_NOTES_TITLE", self.validate)
        self.write_repository("0.4.0-beta.2")
        notes.write_text(
            notes.read_text("utf-8").replace("| Public service schema | `1` |", ""),
            encoding="utf-8",
        )
        self.assert_code("COMPATIBILITY", self.validate)

    def test_current_docs_and_formal_mineru_fixture_fail_closed(self) -> None:
        self.write("docs/release-status.en.md", "The current target version is `9.9.9`\n")
        self.assert_code("CURRENT_DOCS", self.validate)
        self.write_repository("0.4.0-beta.2")
        self.write(
            "scripts/release/fixtures/mineru-formal-filename-v0.4.0.txt",
            "lawyer-assistance-mineru-0.4.0-windows-x86_64.laocrpkg\n",
        )
        self.assert_code("MINERU_FILENAME", self.validate)

    def test_contract_is_closed_and_machine_facts_are_immutable(self) -> None:
        mutations = []
        extra = copy.deepcopy(self.contract)
        extra["unexpected"] = True
        mutations.append((extra, "SCHEMA"))
        repository = copy.deepcopy(self.contract)
        repository["repository"]["owner"] = "attacker"
        mutations.append((repository, "REPOSITORY"))
        assets = copy.deepcopy(self.contract)
        assets["appAssets"] = APP_ASSETS[:-1]
        mutations.append((assets, "APP_ASSETS"))
        tag = copy.deepcopy(self.contract)
        tag["immutableTags"]["v0.3.1"] = {
            **IMMUTABLE_V031,
            "peeledCommit": "0" * 40,
        }
        mutations.append((tag, "IMMUTABLE_TAG"))
        for contract, code in mutations:
            self.assert_code(
                code,
                lambda contract=contract: validate_repository(
                    self.root, contract, "current"
                ),
            )

    def test_contract_loader_rejects_duplicate_keys_and_bom(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaises(ContractLoadError):
            load_contract(duplicate)
        bom = self.root / "bom.json"
        bom.write_bytes(b"\xef\xbb\xbf{}")
        with self.assertRaises(ContractLoadError):
            load_contract(bom)


class McpCiReleaseContractPathTests(unittest.TestCase):
    @staticmethod
    def workflow_paths(event: str) -> list[str]:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/mcp-ci.yml"
        ).read_text(encoding="utf-8")
        event_header = f"  {event}:"
        lines = workflow.splitlines()
        try:
            event_start = lines.index(event_header)
            paths_start = lines.index("    paths:", event_start + 1)
        except ValueError as error:
            raise AssertionError(f"missing {event} paths filter") from error

        paths: list[str] = []
        for line in lines[paths_start + 1 :]:
            if line.startswith('      - "') and line.endswith('"'):
                paths.append(line[len('      - "') : -1])
                continue
            if line.strip():
                break
        if not paths:
            raise AssertionError(f"empty {event} paths filter")
        return paths

    @staticmethod
    def is_covered(required: str, pattern: str) -> bool:
        if pattern == required:
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            return required.startswith(prefix + "/")
        return False

    def test_push_and_pull_request_cover_every_release_contract_input(self) -> None:
        contract = load_contract(CONTRACT_PATH)
        required = {
            ".github/workflows/mcp-ci.yml",
            "Cargo.lock",
            "scripts/check_release_contract.py",
            "scripts/release/release_contract.py",
            "scripts/verify_release_assets.py",
            "scripts/test_verify_release_assets.py",
            "scripts/verify_updater_signature.py",
            "scripts/test_verify_updater_signature.py",
            CONTRACT_PATH.relative_to(REPOSITORY_ROOT).as_posix(),
            Path(__file__).resolve().relative_to(REPOSITORY_ROOT).as_posix(),
            contract["mcpVersionProbe"]["sourcePath"],
            contract["releaseNotes"]["path"],
            contract["compatibilityContract"]["path"],
            contract["minerU"]["formalFilenameFixturePath"],
        }
        required.update(source["path"] for source in contract["versionSources"])
        required.update(document["path"] for document in contract["currentDocs"])

        workspace = tomllib.loads(
            (REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        )
        required.update(
            f"{member.rstrip('/')}/Cargo.toml"
            for member in workspace["workspace"]["members"]
        )

        for event in ("push", "pull_request"):
            patterns = self.workflow_paths(event)
            uncovered = sorted(
                path
                for path in required
                if not any(self.is_covered(path, pattern) for pattern in patterns)
            )
            self.assertEqual(uncovered, [], f"{event} does not cover contract inputs")

        workflow = (REPOSITORY_ROOT / ".github/workflows/mcp-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "python -m unittest scripts.test_release_contract scripts.test_verify_updater_signature",
            workflow,
        )
        self.assertIn("--expected-commit '${{ github.sha }}'", workflow)


if __name__ == "__main__":
    unittest.main()
