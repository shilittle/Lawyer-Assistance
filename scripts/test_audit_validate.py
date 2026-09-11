from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import audit_validate


ROOT = Path(__file__).resolve().parents[1]


def init_git_fixture(root: Path) -> None:
    subprocess.run(("git", "init", "-q"), cwd=root, check=True, capture_output=True)
    subprocess.run(
        ("git", "add", "."),
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Audit Test",
            "-c",
            "user.email=audit-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ),
        cwd=root,
        check=True,
        capture_output=True,
    )


class AuditValidateTests(unittest.TestCase):
    def test_python_discovery_includes_the_runner_test_module(self) -> None:
        modules = audit_validate.discover_python_tests(ROOT)
        self.assertIn("scripts.test_audit_validate", modules)
        self.assertGreaterEqual(len(modules), 14)

    def test_only_filter_adds_prerequisites_and_leaves_other_subsystems_out(self) -> None:
        context = audit_validate.AuditContext(
            root=ROOT,
            resources=ROOT / "output" / "runtime-tools",
            output=ROOT / "work" / "test-audit-validate",
            server_exe=ROOT / "server.exe",
            mcp_exe=ROOT / "mcp.exe",
        )
        specs = audit_validate.build_command_specs(context, ())
        selected = audit_validate.selection_for(
            "all", ("web-tests",), audit_validate.PREFLIGHT_IDS, specs
        )
        self.assertEqual(
            {"web-tests", "preflight:node"},
            selected,
        )
        self.assertNotIn("rust-tests", selected)
        self.assertNotIn("preflight:rustc", selected)

    def test_runtime_resource_selection_includes_manifest_authority(self) -> None:
        context = audit_validate.AuditContext(
            root=ROOT,
            resources=ROOT / "output" / "runtime-tools",
            output=ROOT / "work" / "test-audit-validate",
            server_exe=ROOT / "server.exe",
            mcp_exe=ROOT / "mcp.exe",
        )
        specs = audit_validate.build_command_specs(context, ())
        selected = audit_validate.selection_for(
            "all", ("preflight:runtime-resources",), audit_validate.PREFLIGHT_IDS, specs
        )
        self.assertEqual(
            {"preflight:runtime-resources", "preflight:manifests"},
            selected,
        )

    def test_preflight_scope_is_explicit_when_report_passes(self) -> None:
        preflight = audit_validate.make_record(
            "preflight:python", "preflight", "tool", ("Python major version >= 3",)
        )
        preflight.update({"status": "passed"})
        command = audit_validate.make_record(
            "python-tests", "python", "command", ("exit_code == 0",)
        )
        report = audit_validate.make_report(
            audit_validate.AuditContext(ROOT, ROOT, ROOT, ROOT / "server.exe", ROOT / "mcp.exe"),
            "preflight",
            (),
            (preflight, command),
            {"preflight:python"},
            {"commit": None, "tools": [], "executables": [], "resources": [], "manifests": {}},
            (),
            "2026-09-11T00:00:00+00:00",
            0.0,
        )
        self.assertTrue(report["passed"])
        self.assertTrue(report["scope"]["preflight_only"])
        self.assertFalse(report["scope"]["full_suite"])
        self.assertIn("python-tests", report["scope"]["omitted_check_ids"])

    def test_raw_hash_keeps_crlf_distinct_from_lf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            raw = b"{\r\n  \"ok\": true\r\n}\r\n"
            path.write_bytes(raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), audit_validate.sha256_file(path))
            self.assertNotEqual(
                audit_validate.sha256_file(path),
                hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
            )

    def test_missing_command_is_recorded_as_launch_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            context = audit_validate.AuditContext(
                root=Path(directory),
                resources=Path(directory),
                output=output,
                server_exe=Path(directory) / "server.exe",
                mcp_exe=Path(directory) / "mcp.exe",
            )
            spec = audit_validate.CheckSpec(
                "missing-probe", "test", ("audit-command-that-does-not-exist",), "probe.log"
            )
            record = audit_validate.run_command_check(spec, context)
            self.assertEqual("failed", record["status"])
            self.assertIsNone(record["exit_code"])
            self.assertEqual("FileNotFoundError", record["launch_exception"]["type"])
            self.assertTrue((output / "logs" / "missing-probe.log").is_file())

    def test_missing_preflight_tool_is_blocked_with_recovery_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            context = audit_validate.AuditContext(
                root=directory_path,
                resources=directory_path,
                output=directory_path / "output",
                server_exe=directory_path / "server.exe",
                mcp_exe=directory_path / "mcp.exe",
            )
            missing_probe = {
                "command": ["node"],
                "requested_command": ["node", "--version"],
                "started_at": "2026-09-11T00:00:00+00:00",
                "finished_at": "2026-09-11T00:00:00+00:00",
                "elapsed_seconds": 0.001,
                "exit_code": None,
                "launch_exception": {
                    "type": "FileNotFoundError",
                    "message": "node was not found",
                },
            }
            evidence: dict[str, object] = {"tools": []}
            with patch.object(audit_validate, "run_capture", return_value=missing_probe):
                record = audit_validate.run_tool_check(
                    "preflight:node",
                    ("node", "--version"),
                    context,
                    ("Node.js major version >= 24",),
                    audit_validate.parse_node_version,
                    evidence,
                )
            self.assertEqual("blocked", record["status"])
            self.assertEqual("node", record["missing"])
            self.assertIn("PATH", record["how_to_obtain"])
            self.assertEqual("blocked", evidence["tools"][0]["status"])

    def test_pnpm_cmd_shim_is_resolved_before_launch(self) -> None:
        with patch.object(audit_validate.shutil, "which", return_value=r"C:\tools\pnpm.cmd"):
            self.assertEqual(
                (r"C:\tools\pnpm.cmd", "--version"),
                audit_validate.resolve_command(("pnpm", "--version")),
            )

    def test_source_manifest_binds_untracked_bytes_and_ignores_non_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repo"
            repository.mkdir()
            (repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            (repository / "tracked.txt").write_bytes(b"tracked\n")
            crlf = b"first\r\nsecond\r\n"
            (repository / "crlf.txt").write_bytes(crlf)
            init_git_fixture(repository)
            (repository / "ignored.txt").write_bytes(b"ignored-v1\n")
            (repository / "new.py").write_bytes(b"print('v1')\r\n")
            (repository / "target").mkdir()
            (repository / "target" / "build.exe").write_bytes(b"generated")
            (repository / "private.pem").write_bytes(b"private")
            context = audit_validate.AuditContext(
                root=repository,
                resources=repository,
                output=parent / "evidence",
                server_exe=repository / "server.exe",
                mcp_exe=repository / "mcp.exe",
            )

            first = audit_validate.source_manifest_record(context)
            self.assertEqual("passed", first["status"])
            self.assertEqual(3, first["untracked_count"])
            self.assertEqual(1, first["included_untracked_count"])
            self.assertEqual(
                ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                first["commands"][0]["requested_command"],
            )
            manifest_path = context.output / audit_validate.SOURCE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            by_path = {entry["path"]: entry for entry in manifest["files"]}
            self.assertIn("new.py", by_path)
            self.assertFalse(by_path["new.py"]["tracked"])
            self.assertEqual(hashlib.sha256(crlf).hexdigest(), by_path["crlf.txt"]["sha256"])
            self.assertNotEqual(
                by_path["crlf.txt"]["sha256"],
                hashlib.sha256(crlf.replace(b"\r\n", b"\n")).hexdigest(),
            )
            for excluded in ("ignored.txt", "target/build.exe", "private.pem"):
                self.assertNotIn(excluded, by_path)
            first_summary = first["summary_sha256"]

            (repository / "new.py").write_bytes(b"print('v2')\r\n")
            second = audit_validate.source_manifest_record(context)
            self.assertNotEqual(first_summary, second["summary_sha256"])
            second_summary = second["summary_sha256"]
            second_artifact_sha256 = second["artifact"]["sha256"]
            (repository / "ignored.txt").write_bytes(b"ignored-v2\n")
            third = audit_validate.source_manifest_record(context)
            self.assertEqual(second_summary, third["summary_sha256"])
            self.assertEqual(second_artifact_sha256, third["artifact"]["sha256"])
            self.assertEqual(
                third["artifact"]["sha256"],
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            )

    def test_source_manifest_reports_read_failure_without_claiming_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repo"
            repository.mkdir()
            (repository / "tracked.txt").write_bytes(b"tracked")
            init_git_fixture(repository)
            context = audit_validate.AuditContext(
                root=repository,
                resources=repository,
                output=parent / "evidence",
                server_exe=repository / "server.exe",
                mcp_exe=repository / "mcp.exe",
            )
            with patch.object(audit_validate, "sha256_file", side_effect=OSError("read denied")):
                result = audit_validate.source_manifest_record(context)
            self.assertEqual("failed", result["status"])
            self.assertTrue(result["failures"])
            entry = next(item for item in result["files"] if item["path"] == "tracked.txt")
            self.assertEqual("OSError", entry["error"]["type"])


if __name__ == "__main__":
    unittest.main()
