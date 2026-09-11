from __future__ import annotations

import struct
import tempfile
import unittest
import json
import subprocess
from pathlib import Path

from scripts import build_diagnostic as diagnostic


def synthetic_pe(guid: bytes, age: int) -> bytes:
    data = bytearray(0x900)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    file_header = 0x84
    struct.pack_into("<H", data, file_header + 0, 0x8664)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 0xF0)
    optional = file_header + 20
    struct.pack_into("<H", data, optional, 0x20B)
    debug_directory = optional + 112 + 6 * 8
    struct.pack_into("<II", data, debug_directory, 0x1400, 28)
    section = optional + 0xF0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x800, 0x1000, 0x800, 0x400)
    debug_entry = 0x800
    struct.pack_into("<I", data, debug_entry + 12, 2)
    struct.pack_into("<I", data, debug_entry + 16, 36)
    struct.pack_into("<I", data, debug_entry + 24, 0x820)
    codeview = 0x820
    data[codeview : codeview + 4] = b"RSDS"
    data[codeview + 4 : codeview + 20] = guid
    struct.pack_into("<I", data, codeview + 20, age)
    data[codeview + 24 : codeview + 36] = b"private.pdb\0"
    return bytes(data)


def synthetic_pdb(guid: bytes, age: int) -> bytes:
    block_size = 512
    data = bytearray(block_size * 4)
    signature = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    data[: len(signature)] = signature
    struct.pack_into("<IIIIII", data, 32, block_size, 1, 4, 16, 0, 1)
    struct.pack_into("<I", data, block_size, 2)
    directory = block_size * 2
    struct.pack_into("<III", data, directory, 2, 0xFFFFFFFF, 28)
    struct.pack_into("<I", data, directory + 12, 3)
    info = block_size * 3
    struct.pack_into("<III", data, info, 20000404, 0, age)
    data[info + 12 : info + 28] = guid
    return bytes(data)


class BuildDiagnosticTests(unittest.TestCase):
    def test_diagnostic_cargo_command_is_serial(self) -> None:
        command = diagnostic.diagnostic_build_command(
            "1.98.0", "x86_64-pc-windows-msvc", "lawyer-assistance-server", "lawyer-assistance"
        )
        self.assertEqual(1, command.count("-j"))
        self.assertEqual("1", command[command.index("-j") + 1])
        self.assertIn("--offline", command)

    def test_metadata_command_filters_the_selected_platform(self) -> None:
        command = diagnostic.diagnostic_metadata_command("1.98.0", "x86_64-pc-windows-msvc")
        self.assertIn("--filter-platform", command)
        self.assertEqual("x86_64-pc-windows-msvc", command[command.index("--filter-platform") + 1])
        self.assertEqual("1", command[command.index("--format-version") + 1])
        self.assertIn("--locked", command)
        self.assertIn("--offline", command)

    def test_each_logged_command_keeps_result_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)

            def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(args[0], 7, stdout="stdout evidence", stderr="stderr evidence")

            result = diagnostic.run_logged(
                ("cargo", "metadata"),
                Path(directory),
                log_dir,
                "cargo-metadata.log.json",
                runner=runner,
            )
            self.assertEqual(7, result.returncode)
            record = json.loads((log_dir / "cargo-metadata.log.json").read_text(encoding="utf-8"))
            self.assertEqual(["cargo", "metadata"], record["command"])
            self.assertEqual(7, record["exit_code"])
            self.assertEqual("stdout evidence", record["stdout"])
            self.assertEqual("stderr evidence", record["stderr"])

    def test_pe_and_pdb_guid_age_pair_is_checked_without_embedded_path(self) -> None:
        guid = bytes(range(16))
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "lawyer-assistance.exe"
            pdb = Path(directory) / "lawyer-assistance.pdb"
            exe.write_bytes(synthetic_pe(guid, 7))
            pdb.write_bytes(synthetic_pdb(guid, 7))
            pair = diagnostic.pair_debug_identities(exe, pdb)
            self.assertTrue(pair["matched"])
            self.assertEqual(guid.hex(), pair["codeview"]["guid"])
            self.assertEqual(7, pair["pdb_info"]["age"])
            self.assertNotIn("private.pdb", str(pair))

    def test_pdb_age_mismatch_fails_pair_assertion(self) -> None:
        guid = bytes(range(16))
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "a.exe"
            pdb = Path(directory) / "a.pdb"
            exe.write_bytes(synthetic_pe(guid, 7))
            pdb.write_bytes(synthetic_pdb(guid, 8))
            pair = diagnostic.pair_debug_identities(exe, pdb)
            self.assertFalse(pair["matched"])

    def test_hyphenated_binary_accepts_rustc_underscored_pdb_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / diagnostic.DEFAULT_TARGET / diagnostic.PROFILE
            target.mkdir(parents=True)
            exe = target / "lawyer-assistance.exe"
            pdb = target / "lawyer_assistance.pdb"
            exe.write_bytes(b"exe")
            pdb.write_bytes(b"pdb")
            found_exe, found_pdb = diagnostic.locate_artifacts(
                Path(directory), diagnostic.DEFAULT_TARGET, "lawyer-assistance"
            )
            self.assertEqual(exe, found_exe)
            self.assertEqual(pdb, found_pdb)

    def test_profile_contract_requires_inherited_release_debug_two(self) -> None:
        for debug_value in ("2", "true", '"full"'):
            with self.subTest(debug_value=debug_value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "Cargo.toml").write_text(
                    "[profile.release]\nopt-level = 2\n\n[profile.diagnostic]\ninherits = \"release\"\ndebug = " + debug_value + "\n",
                    encoding="utf-8",
                )
                profile = diagnostic.verify_profile_contract(root)
                self.assertEqual("diagnostic", profile["name"])
                self.assertEqual("release", profile["inherits"])
                self.assertEqual(2, profile["debug"])

    def test_missing_profile_is_blocked_and_manifest_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
            output = root / "diagnostic"
            manifest = diagnostic.build_diagnostic(root, output)
            self.assertEqual("blocked", manifest["status"])
            self.assertEqual("diagnostic_profile_missing", manifest["reason"])
            self.assertTrue((output / "diagnostic-build.json").is_file())
            self.assertNotIn("C:\\", (output / "diagnostic-build.json").read_text(encoding="utf-8"))

    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[profile.diagnostic]\ninherits = \"release\"\ndebug = 2\n", encoding="utf-8")
            output = root / "diagnostic"
            output.mkdir()
            (output / "sentinel").write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                diagnostic.build_diagnostic(root, output)
            self.assertEqual("keep", (output / "sentinel").read_text(encoding="utf-8"))

    def test_version_parsers_keep_only_tool_identity(self) -> None:
        self.assertEqual("1.98.0", diagnostic.parse_cargo_version("cargo 1.98.0 (abc 2026-01-01)"))
        self.assertEqual(
            {"release": "1.98.0", "host": "x86_64-pc-windows-msvc"},
            diagnostic.parse_rustc_version("release: 1.98.0\nhost: x86_64-pc-windows-msvc\n"),
        )


if __name__ == "__main__":
    unittest.main()
