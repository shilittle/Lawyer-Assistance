from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import call, patch

from scripts.package_mcp_release import (
    PackageError,
    PackageResult,
    RepositoryProvenance,
    _read_archive,
    _scan_support_content,
    build_package,
    collect_payloads,
    inspect_repository_provenance,
    main,
    run_release_contract_gate,
    sha256_bytes,
    verify_embedded_manifest,
    workspace_version,
)


class McpReleasePackageTests(unittest.TestCase):
    def fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        (root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "9.8.7"\n', encoding="utf-8"
        )
        (root / "LICENSE").write_text("test license\n", encoding="utf-8")
        (root / "README.md").write_text("# test\n", encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text(
            """# Lawyer Assistance 9.8.7

## Compatibility contract

MCP protocol metadata
Public service schema
Legal archive schema
User database schema

## Install and migration

Fixture migration guidance.

## Known limits

Fixture limits.
""",
            encoding="utf-8",
        )
        notices = root / "apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt"
        notices.parent.mkdir(parents=True)
        notices.write_text("test notices\n", encoding="utf-8")
        docs = root / "docs/mcp"
        docs.mkdir(parents=True)
        (docs / "README.md").write_text("MCP docs\n", encoding="utf-8")
        integrations = root / "integrations/workbuddy"
        integrations.mkdir(parents=True)
        (integrations / "connector.json").write_text(
            '{"token":"{env:TOKEN}"}\n', encoding="utf-8"
        )
        binary = root / "lawyer-assistance-mcp"
        binary.write_bytes(b"test-binary")
        return root, binary

    def provenance(self, root: Path, binary: Path) -> RepositoryProvenance:
        data = binary.read_bytes()
        return RepositoryProvenance(
            source_commit="a" * 40,
            source_commit_timestamp=1,
            source_clean=True,
            binary_sha256=sha256_bytes(data),
            binary_size=len(data),
            binary_version="9.8.7",
            binary_fresh=True,
            release_ready=True,
        )

    def test_tarball_is_deterministic_manifested_and_database_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            first = build_package(root, binary, "x86_64-unknown-linux-gnu", root / "out-1")
            second = build_package(root, binary, "x86_64-unknown-linux-gnu", root / "out-2")
            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual(first.sha256, sha256_bytes(first.archive.read_bytes()))
            self.assertTrue(first.checksum.read_text(encoding="utf-8").endswith("\n"))
            self.assertGreaterEqual(first.files, 8)
            members = _read_archive(first.archive)
            release_notes_name = f"{first.package_root}/RELEASE_NOTES.md"
            manifest_name = f"{first.package_root}/MANIFEST.sha256"
            self.assertIn(release_notes_name, members)
            self.assertIn(manifest_name, members)
            self.assertIn(b"  RELEASE_NOTES.md\n", members[manifest_name])
            verify_embedded_manifest(members, first.package_root)

    def test_windows_zip_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            windows_binary = binary.with_suffix(".exe")
            binary.rename(windows_binary)
            result = build_package(
                root, windows_binary, "x86_64-pc-windows-msvc", root / "out"
            )
            self.assertEqual(result.archive.suffix, ".zip")
            self.assertTrue(result.archive.is_file())
            verify_embedded_manifest(_read_archive(result.archive), result.package_root)

    def test_database_secret_or_session_support_path_is_rejected(self) -> None:
        candidates = (
            Path("integrations/user.sqlite"),
            Path("integrations/sessions/descriptor.json"),
            Path("integrations/case-material/intake.txt"),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with tempfile.TemporaryDirectory() as directory:
                    root, binary = self.fixture(directory)
                    forbidden = root / candidate
                    forbidden.parent.mkdir(parents=True, exist_ok=True)
                    forbidden.write_bytes(b"not release material")
                    with self.assertRaises(PackageError):
                        collect_payloads(root, binary, "x86_64-unknown-linux-gnu")

    def test_target_and_workspace_version_cannot_escape_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            with self.assertRaisesRegex(PackageError, "target triple"):
                collect_payloads(root, binary, "../escape")

            (root / "Cargo.toml").write_text(
                '[workspace]\n[workspace.package]\nversion = "../escape"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PackageError, "version is invalid"):
                workspace_version(root)

    def test_nonrelease_provenance_is_visibly_marked_in_archive_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            verified = self.provenance(root, binary)
            preflight = RepositoryProvenance(
                source_commit=verified.source_commit,
                source_commit_timestamp=verified.source_commit_timestamp,
                source_clean=False,
                binary_sha256=verified.binary_sha256,
                binary_size=verified.binary_size,
                binary_version=verified.binary_version,
                binary_fresh=True,
                release_ready=False,
            )
            result = build_package(
                root,
                binary,
                "x86_64-unknown-linux-gnu",
                root / "out",
                preflight,
            )
            self.assertIn("-NONRELEASE.tar.gz", result.archive.name)
            record_name = f"{result.package_root}/PACKAGE-PROVENANCE.json"
            record = json.loads(_read_archive(result.archive)[record_name])
            self.assertFalse(record["releaseReady"])
    def test_release_notes_must_match_workspace_version_and_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            (root / "RELEASE_NOTES.md").write_text(
                "# Lawyer Assistance 9.8.6\n\n## Known limits\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PackageError, "RELEASE_NOTES"):
                collect_payloads(root, binary, "x86_64-unknown-linux-gnu")

    def test_developer_cache_and_validator_tests_do_not_affect_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            cache = root / "integrations" / "__pycache__" / "validator.cpython-313.pyc"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"machine-local-bytecode")
            (root / "integrations" / ".DS_Store").write_bytes(b"machine-local-metadata")
            canary_test = root / "integrations" / "test_release_canary.py"
            canary_test.write_text(
                'SECRET = "Bearer not-a-real-abcdefghijklmnop-1234"\nRAW_CASE_CANARY = True\n',
                encoding="utf-8",
            )
            paths = {
                payload.path
                for payload in collect_payloads(
                    root, binary, "x86_64-unknown-linux-gnu"
                )
            }
            self.assertNotIn(
                "integrations/__pycache__/validator.cpython-313.pyc", paths
            )
            self.assertNotIn("integrations/.DS_Store", paths)
            self.assertNotIn("integrations/test_release_canary.py", paths)

    def test_high_confidence_secret_session_and_case_canary_content_is_rejected(self) -> None:
        samples = {
            "private-key": b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n",
            "bearer": b"Authorization: Bearer not-a-real-abcdefghijklmnop-1234\n",
            "prefixed-token": b"access_token=ghp_1234567890abcdefghijklmnop\n",
            "session": b"session=srv_0123456789abcdef0123456789abcdef\n",
            "case-canary": b"RAW_CASE_CANARY\n",
            "secret-assignment": b"client_secret=not-a-placeholder\n",
        }
        for name, data in samples.items():
            with self.subTest(name=name), self.assertRaises(PackageError):
                _scan_support_content(PurePosixPath(f"{name}.txt"), data)

    def test_documented_secret_placeholders_are_allowed(self) -> None:
        data = b"\n".join(
            (
                b"Authorization: Bearer {env:LAWYER_ASSISTANCE_TOKEN}",
                b"client_secret=<from-secret-store>",
                b"password=REDACTED",
                b"Bearer authentication remains loopback-only.",
            )
        )
        _scan_support_content(PurePosixPath("README.md"), data)

    def test_archive_reader_rejects_traversal_and_case_alias_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traversal = root / "traversal.zip"
            with zipfile.ZipFile(traversal, "w") as package:
                package.writestr("release/../escape.txt", b"escape")
            with self.assertRaises(PackageError):
                _read_archive(traversal)

            case_alias = root / "case-alias.zip"
            with zipfile.ZipFile(case_alias, "w") as package:
                package.writestr("release/README.md", b"one")
                package.writestr("release/readme.md", b"two")
            with self.assertRaises(PackageError):
                _read_archive(case_alias)

    def test_embedded_manifest_detects_member_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            result = build_package(
                root, binary, "x86_64-unknown-linux-gnu", root / "out"
            )
            members = _read_archive(result.archive)
            readme_name = f"{result.package_root}/README.md"
            members[readme_name] += b"tampered"
            with self.assertRaisesRegex(PackageError, "hash or size"):
                verify_embedded_manifest(members, result.package_root)

    def test_package_provenance_is_embedded_and_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            provenance = self.provenance(root, binary)
            result = build_package(
                root,
                binary,
                "x86_64-unknown-linux-gnu",
                root / "out",
                provenance,
            )
            members = _read_archive(result.archive)
            provenance_name = f"{result.package_root}/PACKAGE-PROVENANCE.json"
            manifest_name = f"{result.package_root}/MANIFEST.sha256"
            self.assertIn(provenance_name, members)
            record = json.loads(members[provenance_name])
            self.assertEqual(record["sourceCommit"], "a" * 40)
            self.assertEqual(record["binarySha256"], provenance.binary_sha256)
            self.assertTrue(record["releaseReady"])
            self.assertIn(b"  PACKAGE-PROVENANCE.json\n", members[manifest_name])
            verify_embedded_manifest(members, result.package_root)

    def test_binary_change_after_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            provenance = self.provenance(root, binary)
            binary.write_bytes(b"changed-after-verification")
            with self.assertRaisesRegex(PackageError, "changed after provenance"):
                collect_payloads(
                    root,
                    binary,
                    "x86_64-unknown-linux-gnu",
                    provenance,
                )

    def test_repository_provenance_requires_clean_fresh_matching_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            commit = "b" * 40
            status = ""

            def command_output(command: list[str], command_root: Path) -> str:
                self.assertEqual(command_root, root.resolve())
                if command == ["git", "rev-parse", "--show-toplevel"]:
                    return str(root.resolve())
                if command == ["git", "rev-parse", "HEAD"]:
                    return commit
                if command == ["git", "show", "-s", "--format=%ct", "HEAD"]:
                    return "1"
                if command == [
                    "git",
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=normal",
                ]:
                    return status
                if command == [str(binary.resolve()), "--version"]:
                    return "lawyer-assistance-mcp 9.8.7"
                self.fail(f"unexpected provenance command: {command}")

            with patch(
                "scripts.package_mcp_release._run_checked",
                side_effect=command_output,
            ):
                provenance = inspect_repository_provenance(
                    root, binary, expected_commit=commit
                )
            self.assertTrue(provenance.release_ready)
            self.assertEqual(provenance.source_commit, commit)
            self.assertEqual(provenance.binary_sha256, sha256_bytes(binary.read_bytes()))

            status = " M README.md"
            with patch(
                "scripts.package_mcp_release._run_checked",
                side_effect=command_output,
            ), self.assertRaisesRegex(PackageError, "clean Git worktree"):
                inspect_repository_provenance(root, binary)

            with patch(
                "scripts.package_mcp_release._run_checked",
                side_effect=command_output,
            ):
                preflight = inspect_repository_provenance(
                    root, binary, allow_nonrelease_inputs=True
                )
            self.assertFalse(preflight.source_clean)
            self.assertFalse(preflight.release_ready)

    def test_contract_gate_invokes_formal_checker_with_exact_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\n[workspace.package]\nversion = "0.4.0"\n',
                encoding="utf-8",
            )
            completed = subprocess.CompletedProcess(
                [], 0, "release contract formal OK: 0.4.0\n", ""
            )
            with patch(
                "scripts.package_mcp_release.subprocess.run",
                return_value=completed,
            ) as checker:
                run_release_contract_gate(root, "formal", binary)
            command = checker.call_args.args[0]
            self.assertEqual(command[0], sys.executable)
            self.assertEqual(
                command[-4:],
                ["--mode", "formal", "--mcp-binary", str(binary)],
            )
            self.assertEqual(checker.call_args.kwargs["cwd"], root)

    def test_contract_gate_rejects_formal_beta_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, _binary = self.fixture(directory)
            failed = subprocess.CompletedProcess(
                [],
                1,
                "",
                "RELEASE_CONTRACT_FORMAL_VERSION: formal releases require exact 0.4.0\n",
            )
            with patch(
                "scripts.package_mcp_release.subprocess.run",
                return_value=failed,
            ), self.assertRaisesRegex(PackageError, "FORMAL_VERSION"):
                run_release_contract_gate(root, "formal")

    def test_cli_defaults_to_formal_and_gates_repository_then_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, binary = self.fixture(directory)
            output = root / "out"
            archive = output / "archive.tar.gz"
            checksum = output / "archive.tar.gz.sha256"
            result = PackageResult(archive, checksum, "c" * 64, "package", 9)
            provenance = self.provenance(root, binary)
            arguments = [
                "package_mcp_release.py",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--binary",
                str(binary),
                "--output-dir",
                str(output),
            ]
            with patch("scripts.package_mcp_release.ROOT", root), patch(
                "scripts.package_mcp_release.os.sys.argv", arguments
            ), patch(
                "scripts.package_mcp_release.run_release_contract_gate"
            ) as gate, patch(
                "scripts.package_mcp_release.inspect_repository_provenance",
                side_effect=(provenance, provenance),
            ), patch(
                "scripts.package_mcp_release.build_package", return_value=result
            ):
                self.assertEqual(main(), 0)
            self.assertEqual(
                gate.call_args_list,
                [call(root, "formal"), call(root, "formal", binary)],
            )


if __name__ == "__main__":
    unittest.main()
