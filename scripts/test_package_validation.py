from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import package_validation


class ValidationPackageTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    def repository(self, directory: str) -> tuple[Path, str]:
        root = Path(directory)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Validation Package Test"], cwd=root, check=True)
        (root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "1.2.1"\n', encoding="utf-8"
        )
        (root / "README.md").write_text("source\n", encoding="utf-8")
        subprocess.run(["git", "add", "Cargo.toml", "README.md"], cwd=root, check=True)
        subprocess.run(["git", "commit", "--quiet", "-m", "base"], cwd=root, check=True)
        return root, self.git(root, "rev-parse", "HEAD")

    def inventory(self, root: Path, *paths: str) -> Path:
        entries = []
        for value in paths:
            path = root / value
            content = path.read_bytes()
            entry = {
                "path": value,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            if value.replace("\\", "/") == "work/retest-121/baseline-source.zip":
                entry["kind"] = "source_archive"
            entries.append(entry)
        inventory = root / "selected-inventory.json"
        inventory.write_text(json.dumps({"files": entries}, indent=2) + "\n", encoding="utf-8")
        return inventory

    def test_explicit_inventory_is_hashed_and_baseline_source_zip_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            (root / "docs").mkdir()
            (root / "docs/report.md").write_text("report\n", encoding="utf-8")
            (root / "work/retest-121").mkdir(parents=True)
            (root / "work/retest-121/original-review.md").write_text("original\n", encoding="utf-8")
            baseline_zip = root / "work/retest-121/baseline-source.zip"
            with zipfile.ZipFile(baseline_zip, "w") as source_zip:
                source_zip.writestr("baseline/README.md", b"baseline source")
            inventory = self.inventory(
                root,
                "docs/report.md",
                "work/retest-121/original-review.md",
                "work/retest-121/baseline-source.zip",
            )
            result = package_validation.package_validation(
                inventory,
                base=base,
                label="20260911-01cf195",
                output_dir=root / "artifacts",
                root=root,
            )
            archive = Path(result["archive"])
            self.assertTrue(archive.is_file())
            with zipfile.ZipFile(archive) as package:
                prefix = "Lawyer-Assistance_1.2.1_validation_20260911-01cf195/"
                manifest = json.loads(package.read(prefix + "EVIDENCE_MANIFEST.json"))
                names = set(package.namelist())
            self.assertEqual(manifest["base_revision"], base)
            self.assertEqual(manifest["candidate"], "1.2.1")
            self.assertEqual(manifest["inventory_sha256"], hashlib.sha256(inventory.read_bytes()).hexdigest())
            self.assertIn(prefix + "work/retest-121/baseline-source.zip", names)
            self.assertIn(prefix + "work/retest-121/original-review.md", names)
            with self.assertRaisesRegex(package_validation.ValidationPackageError, "overwrite"):
                package_validation.package_validation(
                    inventory,
                    base=base,
                    label="20260911-01cf195",
                    output_dir=root / "artifacts",
                    root=root,
                )

    def test_inventory_hash_and_size_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            (root / "report.json").write_text("{}\n", encoding="utf-8")
            inventory = self.inventory(root, "report.json")
            value = json.loads(inventory.read_text(encoding="utf-8"))
            value["files"][0]["sha256"] = "0" * 64
            inventory.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(package_validation.ValidationPackageError, "SHA-256"):
                package_validation.package_validation(
                    inventory, base=base, label="20260911-01cf195", output_dir=root / "artifacts", root=root
                )

    def test_dangerous_inventory_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, _base = self.repository(directory)
            cases = {
                "work/audit-repair/report.json": "retired",
                "workspace/report.json": "workspace",
                "workspace-ABCD/report.json": "workspace",
                "workspace_foo/draft.txt": "workspace",
                "user-workspace_foo/draft.txt": "workspace",
                "browser-profile_foo/Preferences": "workspace",
                "browser_profile_foo/Preferences": "workspace",
                "captures/Cookies": "private",
                "browser/Profile/Preferences": "workspace",
                "private/credentials.json": "private",
                "private/.env.local": "private",
                "private/session.pem": "private",
                "data/secret.sqlite": "database",
                "bin/result.exe": "executable",
                "other.zip": "archive",
            }
            for relative, expected in cases.items():
                with self.subTest(relative=relative):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"unsafe")
                    inventory = self.inventory(root, relative)
                    with self.assertRaises(package_validation.ValidationPackageError) as context:
                        package_validation.read_inventory(inventory, root)
                    self.assertTrue(expected in str(context.exception) or expected == "retired")

    def test_baseline_source_zip_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            path = root / "work/retest-121/baseline-source.zip"
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as source_zip:
                source_zip.writestr("../escape.txt", b"bad")
            inventory = self.inventory(root, "work/retest-121/baseline-source.zip")
            with self.assertRaisesRegex(package_validation.ValidationPackageError, "dangerous"):
                package_validation.package_validation(
                    inventory,
                    base=base,
                    label="20260911-01cf195",
                    output_dir=root / "artifacts",
                    root=root,
                )

    def test_baseline_source_zip_rejects_inner_protected_payloads(self) -> None:
        cases = {
            "payload.exe": "executable",
            "private/Cookies": "private",
            "private/.env.local": "private",
            "runtime/data.sqlite": "database",
            "private/session.dpapi": "private",
            "private/session.key": "private",
            "private/session.pem": "private",
            "private/session.pfx": "private",
            "workspace_foo/draft.txt": "workspace",
        }
        for member, message in cases.items():
            with self.subTest(member=member):
                with tempfile.TemporaryDirectory() as directory:
                    root, base = self.repository(directory)
                    path = root / "work/retest-121/baseline-source.zip"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(path, "w") as source_zip:
                        source_zip.writestr(member, b"protected")
                    inventory = self.inventory(root, "work/retest-121/baseline-source.zip")
                    with self.assertRaisesRegex(package_validation.ValidationPackageError, message):
                        package_validation.package_validation(
                            inventory,
                            base=base,
                            label="20260911-01cf195",
                            output_dir=root / "artifacts",
                            root=root,
                        )

    def test_path_only_inventory_and_explicit_archive_kind_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            (root / "report.md").write_text("selected\n", encoding="utf-8")
            service_source = root / "crates/workspace-service/src/lib.rs"
            service_source.parent.mkdir(parents=True, exist_ok=True)
            service_source.write_text("pub fn source() {}\n", encoding="utf-8")
            path = root / "work/retest-121/baseline-source.zip"
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as source_zip:
                source_zip.writestr("baseline/README.md", b"source")
            inventory = root / "path-list.json"
            inventory.write_text(
                json.dumps([
                    "report.md",
                    "crates/workspace-service/src/lib.rs",
                    "work/retest-121/baseline-source.zip",
                ]),
                encoding="utf-8",
            )
            result = package_validation.package_validation(
                inventory,
                base=base,
                label="20260911-path-list",
                output_dir=root / "artifacts",
                root=root,
            )
            with zipfile.ZipFile(result["archive"]) as package:
                prefix = "Lawyer-Assistance_1.2.1_validation_20260911-path-list/"
                manifest = json.loads(package.read(prefix + "EVIDENCE_MANIFEST.json"))
            baseline = next(item for item in manifest["files"] if item["path"].endswith("baseline-source.zip"))
            self.assertEqual(baseline["kind"], "source_archive")
            self.assertIn(
                "crates/workspace-service/src/lib.rs",
                {item["path"] for item in manifest["files"]},
            )

    def test_wrong_explicit_archive_kind_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            path = root / "work/retest-121/baseline-source.zip"
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as source_zip:
                source_zip.writestr("baseline/README.md", b"source")
            inventory = self.inventory(root, "work/retest-121/baseline-source.zip")
            value = json.loads(inventory.read_text(encoding="utf-8"))
            value["files"][0]["kind"] = "report"
            inventory.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(package_validation.ValidationPackageError, "source_archive"):
                package_validation.package_validation(
                    inventory,
                    base=base,
                    label="20260911-wrong-kind",
                    output_dir=root / "artifacts",
                    root=root,
                )

    def test_baseline_source_zip_rejects_symlink_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = self.repository(directory)
            path = root / "work/retest-121/baseline-source.zip"
            path.parent.mkdir(parents=True, exist_ok=True)
            link = zipfile.ZipInfo("baseline/link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as source_zip:
                source_zip.writestr(link, b"README.md")
            inventory = self.inventory(root, "work/retest-121/baseline-source.zip")
            with self.assertRaisesRegex(package_validation.ValidationPackageError, "symlink"):
                package_validation.package_validation(
                    inventory,
                    base=base,
                    label="20260911-01cf195",
                    output_dir=root / "artifacts",
                    root=root,
                )


if __name__ == "__main__":
    unittest.main()
