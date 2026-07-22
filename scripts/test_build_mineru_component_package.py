import hashlib
import json
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))
import build_mineru_component_package as packager  # noqa: E402


class MineruComponentPackagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        for directory in (
            "worker",
            "python",
            "runtime",
            "models/pipeline",
            "models/vlm",
            "licenses",
        ):
            (self.source / directory).mkdir(parents=True, exist_ok=True)
        (self.source / "worker/mineru-worker.exe").write_bytes(b"MZsynthetic-worker")
        (self.source / "python/python.exe").write_bytes(b"MZsynthetic-python")
        (self.source / "runtime/helper.exe").write_bytes(b"MZsynthetic-helper")
        (self.source / "models/pipeline/model.bin").write_bytes(b"synthetic-pipeline")
        (self.source / "models/vlm/model.bin").write_bytes(b"synthetic-vlm")
        (self.source / "licenses/NOTICE.txt").write_text("synthetic only", encoding="utf-8")
        provenance = {
            "schemaVersion": 1,
            "provenanceVersion": packager.PROVENANCE_VERSION,
            "provenanceInputSha256": "1" * 64,
            "approval": {
                "approvedForRedistribution": True,
                "reviewer": "synthetic-test-reviewer",
                "reviewedAtUnix": 1,
            },
            "source": {
                "repositoryCommit": "2" * 40,
                "buildScriptSha256": "3" * 64,
                "workerSourceTreeSha256": "4" * 64,
            },
            "cpython": {
                "version": "3.12.13",
                "sourceUrl": "https://www.python.org/",
                "contentSha256": "5" * 64,
                "license": "PSF-2.0",
                "licenseFileSha256": "6" * 64,
            },
            "runtimeProfile": {
                "platform": "windows-x86_64",
                "rootDistribution": "mineru==3.4.3",
                "extras": ["pipeline", "vlm"],
            },
            "distributions": [
                {
                    "name": "mineru",
                    "version": "3.4.3",
                    "license": "LicenseRef-MinerU-Open-Source-License",
                }
            ],
            "excludedDistributions": [],
            "models": [
                {"root": "pipeline", "license": "Apache-2.0"},
                {"root": "vlm", "license": "Apache-2.0"},
            ],
        }
        (self.source / packager.PROVENANCE_RELATIVE).write_bytes(
            packager.json_bytes(provenance)
        )
        self.issued_at = int(time.time()) - 10
        self.expires_at = self.issued_at + 86_400

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_manifest_ceiling_fits_real_inventory_and_remains_bounded(self) -> None:
        self.assertEqual(packager.MAX_MANIFEST_BYTES, 16 * 1024 * 1024)
        output = self.root / "oversized.laocrpkg"
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.write_package(
                output,
                b"x" * (packager.MAX_MANIFEST_BYTES + 1),
                (),
            )
        self.assertEqual(failure.exception.code, "manifest_size_invalid")
        self.assertFalse(output.exists())

    def build(
        self,
        destination: str,
        *,
        component_version: str = "1.2.3",
        issued_at: int | None = None,
        previous_catalog: Path | None = None,
        max_package_bytes: int | None = None,
        part_size_bytes: int | None = None,
        runtime_executables: tuple[str, ...] = (
            "python/python.exe",
            "runtime/helper.exe",
        ),
    ):
        release = self.root / destination
        output = release / (
            f"lawyer-assistance-mineru-{component_version}-windows-x86_64.laocrpkg"
        )
        arguments = dict(
            source=self.source,
            output=output,
            catalog_output=release / "mineru-component-catalog.json",
            package_id=f"mineru-windows-{component_version.replace('.', '-')}",
            catalog_id="mineru-windows-stable-v1",
            component_version=component_version,
            mineru_version="3.4.3",
            worker="worker/mineru-worker.exe",
            runtime_executables=runtime_executables,
            pipeline_model_directory="models/pipeline",
            vlm_model_directory="models/vlm",
            issued_at=self.issued_at if issued_at is None else issued_at,
            expires_at=self.expires_at,
            previous_catalog=previous_catalog,
        )
        if max_package_bytes is not None:
            arguments["max_package_bytes"] = max_package_bytes
        if part_size_bytes is not None:
            arguments["part_size_bytes"] = part_size_bytes
        return packager.build_release(**arguments)

    def test_deterministic_package_catalog_double_hash_and_offline_signing_command(self) -> None:
        first = self.build("first")
        second = self.build("second", previous_catalog=first.catalog_path)
        self.assertEqual(first.package_path.read_bytes(), second.package_path.read_bytes())
        self.assertEqual(first.catalog_path.read_bytes(), second.catalog_path.read_bytes())
        catalog = json.loads(first.catalog_path.read_bytes())
        entry = catalog["entries"][0]
        self.assertEqual(entry["packageSha256"], first.package_sha256)
        self.assertEqual(entry["packageManifestSha256"], first.manifest_sha256)
        self.assertEqual(entry["packageSizeBytes"], first.package_size_bytes)
        self.assertEqual(
            entry["downloadUrl"],
            "https://github.com/shilittle/Lawyer-Assistance/releases/download/"
            "mineru-components-v1.2.3/"
            "lawyer-assistance-mineru-1.2.3-windows-x86_64.laocrpkg",
        )
        serialized = first.catalog_path.read_text(encoding="utf-8")
        for forbidden in ("casePath", "caseId", "ocrText", "material", "upload"):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("$env:LAWYER_ASSISTANCE_MINISIGN_SECRET_KEY", first.signing_command)
        self.assertIn(
            f"timestamp:{self.issued_at}`tfile:mineru-component-catalog.json",
            first.signing_command,
        )
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertEqual(
            first.provenance_path.read_bytes(),
            (self.source / packager.PROVENANCE_RELATIVE).read_bytes(),
        )
        self.assertEqual(
            first.provenance_sha256,
            hashlib.sha256(first.provenance_path.read_bytes()).hexdigest(),
        )
        self.assertIn("mineru-component-provenance.json", first.provenance_signing_command)
        packager.verify_package(first.package_path, first.catalog_path)

    def test_tampered_outer_manifest_and_payload_are_rejected(self) -> None:
        outer = self.build("outer")
        with outer.package_path.open("r+b") as handle:
            handle.seek(-1, 2)
            byte = handle.read(1)
            handle.seek(-1, 2)
            handle.write(bytes([byte[0] ^ 1]))
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.verify_package(outer.package_path, outer.catalog_path)
        self.assertEqual(failure.exception.code, "package_tampered")

        manifest = self.build("manifest")
        package_bytes = bytearray(manifest.package_path.read_bytes())
        length = struct.unpack("<I", package_bytes[8:12])[0]
        start, end = 12, 12 + length
        manifest_bytes = bytes(package_bytes[start:end])
        self.assertIn(b"3.4.3", manifest_bytes)
        package_bytes[start:end] = manifest_bytes.replace(b"3.4.3", b"3.4.4", 1)
        manifest.package_path.write_bytes(package_bytes)
        catalog = json.loads(manifest.catalog_path.read_bytes())
        catalog["entries"][0]["packageSha256"] = hashlib.sha256(package_bytes).hexdigest()
        manifest.catalog_path.write_bytes(packager.json_bytes(catalog))
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.verify_package(manifest.package_path, manifest.catalog_path)
        self.assertEqual(failure.exception.code, "manifest_tampered")

        payload = self.build("payload")
        package_bytes = bytearray(payload.package_path.read_bytes())
        package_bytes[-1] ^= 1
        payload.package_path.write_bytes(package_bytes)
        catalog = json.loads(payload.catalog_path.read_bytes())
        catalog["entries"][0]["packageSha256"] = hashlib.sha256(package_bytes).hexdigest()
        payload.catalog_path.write_bytes(packager.json_bytes(catalog))
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.verify_package(payload.package_path, payload.catalog_path)
        self.assertEqual(failure.exception.code, "payload_tampered")

    def test_sharded_release_is_canonical_deterministic_and_tamper_evident(self) -> None:
        first = self.build("sharded-first", part_size_bytes=512)
        second = self.build(
            "sharded-second",
            previous_catalog=first.catalog_path,
            part_size_bytes=512,
        )
        self.assertTrue(first.sharded)
        self.assertFalse(first.package_path.exists())
        self.assertIsNotNone(first.part_manifest_path)
        self.assertGreater(len(first.part_paths), 1)
        self.assertEqual(
            [path.read_bytes() for path in first.part_paths],
            [path.read_bytes() for path in second.part_paths],
        )
        first_catalog = json.loads(first.catalog_path.read_bytes())
        self.assertEqual(
            first_catalog["schemaVersion"], packager.SHARDED_CATALOG_SCHEMA_VERSION
        )
        entry = first_catalog["entries"][0]
        self.assertEqual(entry["packageSha256"], first.package_sha256)
        self.assertEqual(entry["partSetManifestSha256"], first.part_manifest_sha256)
        self.assertEqual(len(entry["parts"]), len(first.part_paths))
        self.assertTrue(
            all(
                part["number"] == index
                and 0 < part["sizeBytes"] < packager.GITHUB_RELEASE_ASSET_LIMIT_BYTES
                for index, part in enumerate(entry["parts"], start=1)
            )
        )
        descriptor_bytes = first.part_manifest_path.read_bytes()
        self.assertEqual(descriptor_bytes, packager.json_bytes(json.loads(descriptor_bytes)))
        packager.verify_sharded_package(first.package_path, first.catalog_path)

        tampered = first.part_paths[-1]
        original = tampered.read_bytes()
        tampered.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.verify_sharded_package(first.package_path, first.catalog_path)
        self.assertEqual(failure.exception.code, "part_tampered")

        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build(
                "invalid-part-limit",
                part_size_bytes=packager.GITHUB_RELEASE_ASSET_LIMIT_BYTES,
            )
        self.assertEqual(failure.exception.code, "part_size_invalid")


    def test_worker_only_component_allows_zero_additional_executables(self) -> None:
        (self.source / "python/python.exe").unlink()
        (self.source / "runtime/helper.exe").unlink()
        release = self.build("worker-only", runtime_executables=())
        package_bytes = release.package_path.read_bytes()
        manifest_length = struct.unpack("<I", package_bytes[8:12])[0]
        manifest = json.loads(package_bytes[12 : 12 + manifest_length])
        self.assertEqual(manifest["worker"], "worker/mineru-worker.exe")
        self.assertEqual(manifest["runtimeExecutables"], [])
        self.assertFalse(
            any(
                entry["relativePath"].casefold().endswith(".exe")
                and entry["relativePath"] != manifest["worker"]
                for entry in manifest["files"]
            )
        )
        packager.verify_package(release.package_path, release.catalog_path)

    def test_limits_duplicate_traversal_omission_and_mz_are_fail_closed(self) -> None:
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("oversized", max_package_bytes=64)
        self.assertEqual(failure.exception.code, "package_size_invalid")
        self.assertFalse(any((self.root / "oversized").glob("*.laocrpkg")))

        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.validate_relative_paths(("worker/A.exe", "worker/a.exe"))
        self.assertEqual(failure.exception.code, "path_duplicate")
        for invalid in ("../escape", "worker\\escape.exe", "NUL/file", "other/file"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(packager.PackageBuildError):
                    packager.normalized_relative(invalid)

        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("omitted", runtime_executables=("python/python.exe",))
        self.assertEqual(failure.exception.code, "runtime_omitted")

        (self.source / "worker/mineru-worker.exe").write_bytes(b"not-an-executable")
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("bad-mz")
        self.assertEqual(failure.exception.code, "runtime_invalid")

    def test_catalog_rollback_equivocation_replay_and_create_new(self) -> None:
        previous = self.build("previous")
        replay = self.build("replay", previous_catalog=previous.catalog_path)
        self.assertEqual(previous.catalog_sha256, replay.catalog_sha256)

        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build(
                "rollback",
                issued_at=self.issued_at - 1,
                previous_catalog=previous.catalog_path,
            )
        self.assertEqual(failure.exception.code, "catalog_rollback_rejected")
        self.assertFalse(any((self.root / "rollback").glob("*.laocrpkg")))

        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build(
                "equivocation",
                component_version="1.2.4",
                previous_catalog=previous.catalog_path,
            )
        self.assertEqual(failure.exception.code, "catalog_equivocation_rejected")
        self.assertFalse(any((self.root / "equivocation").glob("*.laocrpkg")))

        original_package = previous.package_path.read_bytes()
        original_catalog = previous.catalog_path.read_bytes()
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("previous")
        self.assertEqual(failure.exception.code, "output_exists")
        self.assertEqual(previous.package_path.read_bytes(), original_package)
        self.assertEqual(previous.catalog_path.read_bytes(), original_catalog)

    def test_missing_model_and_output_inside_source_are_rejected(self) -> None:
        (self.source / "models/vlm/model.bin").unlink()
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("missing-model")
        self.assertEqual(failure.exception.code, "model_directory_empty")

        output = self.source / "worker/lawyer-assistance-mineru-1.2.3-windows-x86_64.laocrpkg"
        with self.assertRaises(packager.PackageBuildError) as failure:
            packager.build_release(
                source=self.source,
                output=output,
                catalog_output=self.root / "catalog.json",
                package_id="mineru-windows-1-2-3",
                catalog_id="mineru-windows-stable-v1",
                component_version="1.2.3",
                mineru_version="3.4.3",
                worker="worker/mineru-worker.exe",
                runtime_executables=("python/python.exe", "runtime/helper.exe"),
                pipeline_model_directory="models/pipeline",
                vlm_model_directory="models/vlm",
                issued_at=self.issued_at,
                expires_at=self.expires_at,
            )
        self.assertEqual(failure.exception.code, "output_inside_source")

    def test_provenance_is_mandatory_approved_canonical_and_license_resolved(self) -> None:
        path = self.source / packager.PROVENANCE_RELATIVE
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("missing-provenance")
        self.assertEqual(failure.exception.code, "provenance_missing")

        value = json.loads(original)
        value["approval"]["approvedForRedistribution"] = False
        path.write_bytes(packager.json_bytes(value))
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("unapproved-provenance")
        self.assertEqual(failure.exception.code, "provenance_unapproved")

        value["approval"]["approvedForRedistribution"] = True
        value["distributions"][0]["license"] = "NOASSERTION"
        path.write_bytes(packager.json_bytes(value))
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("unknown-license")
        self.assertEqual(failure.exception.code, "license_unresolved")

        path.write_bytes(original + b"\n")
        with self.assertRaises(packager.PackageBuildError) as failure:
            self.build("noncanonical-provenance")
        self.assertEqual(failure.exception.code, "provenance_invalid")


if __name__ == "__main__":
    unittest.main()
