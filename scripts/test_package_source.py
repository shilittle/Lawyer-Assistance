from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import package_source


class SourcePackageTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    def repository(self, directory: str) -> tuple[Path, str, str]:
        root = Path(directory)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Source Package Test"], cwd=root, check=True)
        (root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.package]\nversion = "1.2.1"\n', encoding="utf-8"
        )
        (root / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "add", "Cargo.toml", "README.md"], cwd=root, check=True)
        subprocess.run(["git", "commit", "--quiet", "-m", "base"], cwd=root, check=True)
        base = self.git(root, "rev-parse", "HEAD")
        (root / "README.md").write_text("candidate repair\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
        subprocess.run(["git", "commit", "--quiet", "-m", "candidate"], cwd=root, check=True)
        source = self.git(root, "rev-parse", "HEAD")
        return root, base, source

    def test_explicit_base_records_committed_increment_without_exact_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base, source = self.repository(directory)
            output = root / "artifacts"
            with patch.object(package_source, "ROOT", root):
                result = package_source.package_source(
                    root,
                    output,
                    base=base,
                    label="20260911-01cf195",
                )
                with self.assertRaisesRegex(package_source.SourcePackageError, "overwrite"):
                    package_source.package_source(
                        root,
                        output,
                        base=base,
                        label="20260911-01cf195",
                    )

            archive = Path(result["archive"])
            self.assertEqual(archive.name, "Lawyer-Assistance_1.2.1_source_20260911-01cf195.zip")
            with zipfile.ZipFile(archive) as package:
                prefix = "Lawyer-Assistance_1.2.1_source_20260911-01cf195/"
                manifest = json.loads(package.read(prefix + "SOURCE_MANIFEST.json"))
                patch_bytes = package.read(prefix + "SOURCE_INCREMENT.patch")
            self.assertEqual(manifest["base_revision"], base)
            self.assertEqual(manifest["source_revision"], source)
            self.assertNotIn("base_tag", manifest)
            self.assertIn(b"candidate repair", patch_bytes)
            self.assertEqual(manifest["patch"]["sha256"], package_source.sha256_bytes(patch_bytes))
            self.assertEqual(result["patch_sha256"], package_source.sha256_bytes(patch_bytes))
            self.assertEqual(result["manifest_sha256"], package_source.sha256_bytes(json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"))

    def test_known_credential_match_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base, _source = self.repository(directory)
            secret = "known-test-secret-value-abcdefghijklmnopqrstuvwxyz"
            (root / "apikey.txt").write_text(secret + "\n", encoding="utf-8")
            (root / "README.md").write_text("contains " + secret + "\n", encoding="utf-8")
            with patch.object(package_source, "ROOT", root):
                with self.assertRaisesRegex(package_source.SourcePackageError, "credential"):
                    package_source.package_source(
                        root,
                        root / "artifacts",
                        base=base,
                        label="20260911-01cf195",
                    )

    def test_output_directory_is_not_reintroduced_into_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base, _source = self.repository(directory)
            output = root / "artifacts"
            output.mkdir()
            (output / "unrelated-evidence.txt").write_text("must stay outside\n", encoding="utf-8")
            with patch.object(package_source, "ROOT", root):
                result = package_source.package_source(
                    root,
                    output,
                    base=base,
                    label="20260911-output-isolation",
                )
            with zipfile.ZipFile(result["archive"]) as package:
                names = set(package.namelist())
            self.assertFalse(any("unrelated-evidence" in name for name in names))

    def test_workspace_directory_is_excluded_but_workspace_service_source_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base, _source = self.repository(directory)
            service_source = root / "crates/workspace-service/src/lib.rs"
            service_source.parent.mkdir(parents=True, exist_ok=True)
            service_source.write_text("pub fn source() {}\n", encoding="utf-8")
            workspace_paths = (
                "workspace_foo/draft.txt",
                "user-workspace_foo/draft.txt",
                "browser-profile_foo/draft.txt",
                "browser_profile_foo/draft.txt",
            )
            for relative in workspace_paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("local workspace\n", encoding="utf-8")
            with patch.object(package_source, "ROOT", root):
                payload = package_source.build_payload(root, package_source.known_credentials(root))
            self.assertIn("crates/workspace-service/src/lib.rs", payload)
            workspace_file = root / "workspace-private/secrets.txt"
            workspace_file.parent.mkdir(parents=True, exist_ok=True)
            workspace_file.write_text("local workspace\n", encoding="utf-8")
            with patch.object(package_source, "ROOT", root):
                candidates = package_source.source_candidates(root)
                payload = package_source.build_payload(root, package_source.known_credentials(root))
            for relative in (*workspace_paths, "workspace-private/secrets.txt"):
                self.assertNotIn(relative, candidates)
                self.assertNotIn(relative, payload)

    def test_increment_rejects_deleted_private_path_before_patch_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base, _source = self.repository(directory)
            private_path = root / ".env.local"
            private_path.write_text("SERVICE_TOKEN=private-value\n", encoding="utf-8")
            subprocess.run(["git", "add", ".env.local"], cwd=root, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "private fixture"], cwd=root, check=True)
            deletion_base = self.git(root, "rev-parse", "HEAD")
            private_path.unlink()
            with patch.object(package_source, "ROOT", root):
                with self.assertRaisesRegex(package_source.SourcePackageError, "private path"):
                    package_source.package_source(
                        root,
                        root / "artifacts",
                        base=deletion_base,
                        label="20260911-deleted-private",
                    )

    def test_label_rejects_path_separators(self) -> None:
        with self.assertRaisesRegex(package_source.SourcePackageError, "label"):
            package_source.validate_label("20260911/01cf195")


if __name__ == "__main__":
    unittest.main()
