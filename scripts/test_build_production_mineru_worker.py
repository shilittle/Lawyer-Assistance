import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).parent))
import build_production_mineru_worker as builder  # noqa: E402


class ProductionMineruBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.python_home = self.root / "cpython"
        self.site_packages = self.root / "environment/Lib/site-packages"
        self.pipeline = self.root / "models/pipeline"
        self.vlm = self.root / "models/vlm"
        self.worker_source = Path(__file__).parents[1] / "workers/mineru"
        self.repository_license = self.root / "LICENSE"
        for directory in (
            self.python_home / "Lib/email/mime",
            self.python_home / "Lib/site-packages",
            self.python_home / "DLLs",
            self.site_packages,
            self.root / "environment/Scripts",
            self.pipeline,
            self.vlm,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        for name in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
            (self.python_home / name).write_bytes(b"MZ" + name.encode("ascii"))
        (self.python_home / "pythonw.exe").write_bytes(b"MZsecondary")
        (self.python_home / "LICENSE.txt").write_text("CPython synthetic license", encoding="utf-8")
        (self.python_home / "Lib/os.py").write_text("name = 'synthetic'\n", encoding="utf-8")
        (self.python_home / "Lib/site.py").write_text("name = 'synthetic'\n", encoding="utf-8")
        (self.python_home / "Lib/email/mime/__init__.py").write_bytes(b"")
        (self.python_home / "Lib/site-packages/not-copied.py").write_text("bad=1\n", encoding="utf-8")
        (self.python_home / "DLLs/_ssl.pyd").write_bytes(b"synthetic-pyd")
        (self.python_home / "DLLs/helper.exe").write_bytes(b"MZsecondary")
        (self.root / "environment/Scripts/mineru.exe").write_bytes(b"MZsecondary")

        for package in ("mineru", "torch", "pypdfium2"):
            directory = self.site_packages / package
            directory.mkdir()
            (directory / "__init__.py").write_text(f"name={package!r}\n", encoding="utf-8")
        (self.site_packages / "torch/bin").mkdir()
        (self.site_packages / "torch/bin/protoc.exe").write_bytes(b"MZsecondary")
        (self.site_packages / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
        (self.site_packages / "empty_package").mkdir()
        (self.site_packages / "empty_package/__init__.py").write_bytes(b"")
        (self.site_packages / "empty_package/__pycache__").mkdir()
        (self.site_packages / "empty_package/__pycache__/bad.pyc").write_bytes(b"bytecode")

        for name, version in builder.REQUIRED_DISTRIBUTIONS.items():
            dist = self.site_packages / f"{name.replace('-', '_')}-{version}.dist-info"
            dist.mkdir()
            requirements = ""
            if name == "mineru":
                requirements = "".join(
                    f"Requires-Dist: {dependency}=={dependency_version}\n"
                    for dependency, dependency_version in builder.REQUIRED_DISTRIBUTIONS.items()
                    if dependency != "mineru"
                )
            license_metadata = (
                f"License-Expression: {builder.MINERU_LICENSE_ID}\n"
                if name == "mineru"
                else "License: Synthetic Test License\n"
            )
            license_name = "LICENSE.md" if name == "mineru" else "LICENSE.txt"
            (dist / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                f"{license_metadata}{requirements}",
                encoding="utf-8",
            )
            (dist / license_name).write_text(f"Synthetic license for {name}\n", encoding="utf-8")
            package = self.site_packages / name.replace("-", "_") / "__init__.py"
            listed_paths = [
                f"{dist.name}/METADATA",
                f"{dist.name}/{license_name}",
            ]
            if package.is_file():
                listed_paths.append(package.relative_to(self.site_packages).as_posix())
            if name == "torch":
                listed_paths.append("torch/bin/protoc.exe")
            listed = []
            for relative in listed_paths:
                payload = (self.site_packages / relative).read_bytes()
                digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
                listed.append(f"{relative},sha256={digest.decode('ascii')},{len(payload)}")
            listed.append(f"{dist.name}/RECORD,,")
            (dist / "RECORD").write_text("\n".join(listed) + "\n", encoding="utf-8")
        for relative in builder.QUALIFIED_MODELS["pipeline"]["files"]:
            path = self.pipeline / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"pipeline:{relative}".encode("utf-8"))
        for relative in builder.QUALIFIED_MODELS["vlm"]["files"]:
            path = self.vlm / relative
            path.write_bytes(f"vlm:{relative}".encode("utf-8"))
        self.repository_license.write_text("Lawyer Assistance synthetic license", encoding="utf-8")
        self.identity = builder.RuntimeIdentity(
            python_version=builder.CPYTHON_VERSION,
            architecture="windows-x86_64",
            distributions=tuple(
                sorted(
                    (builder.canonical_distribution_name(name), version)
                    for name, version in builder.REQUIRED_DISTRIBUTIONS.items()
                )
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_stage(self, name: str = "stage"):
        selected = builder.resolve_runtime_distributions(self.site_packages)
        measurements = tuple(
            builder.measure_distribution(self.site_packages, item) for item in selected
        )
        cpython_hash, cpython_records = builder.measure_cpython(self.python_home)
        commit = "1" * 40
        script_hash, _ = builder.sha256_file(Path(builder.__file__))
        provenance = {
            "schemaVersion": builder.PROVENANCE_SCHEMA_VERSION,
            "provenanceVersion": builder.PROVENANCE_INPUT_VERSION,
            "approval": {
                "approvedForRedistribution": True,
                "reviewer": "synthetic-test-reviewer",
                "reviewedAtUnix": 1,
            },
            "source": {
                "repositoryCommit": commit,
                "buildScriptSha256": script_hash,
                "workerSourceTreeSha256": builder.measure_worker_source(self.worker_source),
            },
            "cpython": {
                "version": builder.CPYTHON_VERSION,
                "sourceUrl": "https://www.python.org/ftp/python/3.12.13/python-3.12.13-embed-amd64.zip",
                "contentSha256": cpython_hash,
                "license": "PSF-2.0",
                "licenseFileSha256": next(
                    item.sha256
                    for item in cpython_records
                    if item.relative_path == "licenses/cpython/LICENSE.txt"
                ),
            },
            "runtimeProfile": {
                "platform": "windows-x86_64",
                "rootDistribution": "mineru==3.4.3",
                "extras": list(builder.MINERU_RUNTIME_EXTRAS),
            },
            "distributions": [
                {
                    "name": item.name,
                    "version": item.version,
                    "contentSha256": item.content_sha256,
                    "sourceUrl": item.source_urls[0],
                    "license": item.license_declaration,
                    "licenseEvidenceKind": item.license_evidence_kind,
                    "licenseFiles": builder._file_records_json(item.license_files),
                    "installationRecord": builder._file_records_json(
                        (item.installation_record,)
                    )[0],
                    "upstreamArtifact": dict(item.upstream_artifact)
                    if item.upstream_artifact is not None
                    else None,
                }
                for item in measurements
            ],
            "models": [
                {
                    "root": root,
                    "name": builder.QUALIFIED_MODELS[root]["name"],
                    "revision": builder.QUALIFIED_MODELS[root]["revision"],
                    "sourceUrl": (
                        f"https://huggingface.co/{builder.QUALIFIED_MODELS[root]['name']}"
                        f"/tree/{builder.QUALIFIED_MODELS[root]['revision']}"
                    ),
                    "license": builder.QUALIFIED_MODELS[root]["license"],
                    "licenseEvidenceUrl": (
                        f"https://huggingface.co/{builder.QUALIFIED_MODELS[root]['name']}"
                        f"/blob/{builder.QUALIFIED_MODELS[root]['revision']}/README.md"
                    ),
                    "licenseEvidenceSha256": builder.QUALIFIED_MODELS[root][
                        "license_evidence_sha256"
                    ],
                    "files": builder._file_records_json(builder.inventory_tree(model)),
                }
                for root, model in (("pipeline", self.pipeline), ("vlm", self.vlm))
            ],
        }
        provenance_input = self.root / f"{name}-provenance-input.json"
        provenance_input.write_bytes(builder.canonical_json(provenance))
        with mock.patch.object(
            builder, "probe_runtime_identity", return_value=self.identity
        ), mock.patch.object(builder, "_repository_identity", return_value=commit):
            return builder.build_self_contained_stage(
                python_home=self.python_home,
                site_packages=self.site_packages,
                pipeline_model=self.pipeline,
                vlm_model=self.vlm,
                worker_source=self.worker_source,
                repository_license=self.repository_license,
                provenance_input=provenance_input,
                repository_root=self.root,
                output=self.root / name,
            )

    def test_self_contained_stage_has_strict_support_sbom_licenses_and_no_secondary_exe(self) -> None:
        result = self.build_stage()
        stage = self.root / "stage"
        self.assertTrue(result["selfContained"])
        self.assertFalse(result["diagnosticOnly"])
        executables = sorted(path.relative_to(stage).as_posix() for path in stage.rglob("*.exe"))
        self.assertEqual(executables, ["worker/mineru-worker.exe"])
        pth = (stage / "worker/mineru-worker._pth").read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), pth)
        self.assertIn("..\\runtime\\site-packages", pth)
        self.assertFalse((stage / "python/Lib/site-packages/not-copied.py").exists())
        self.assertFalse((stage / "runtime/site-packages/_virtualenv.pth").exists())
        self.assertFalse((stage / "runtime/site-packages/empty_package/__pycache__").exists())
        self.assertFalse((stage / "runtime/site-packages/empty_package").exists())

        version = json.loads((stage / "runtime/version-manifest.json").read_bytes())
        excluded = {(entry["sourceScope"], entry["relativePath"]) for entry in version["excludedExecutables"]}
        self.assertIn(("cpython", "pythonw.exe"), excluded)
        self.assertIn(("cpython", "DLLs/helper.exe"), excluded)
        self.assertIn(("site-packages", "torch/bin/protoc.exe"), excluded)
        self.assertIn(("tool-scripts", "mineru.exe"), excluded)
        self.assertEqual(version["mineruVersion"], "3.4.3")
        self.assertTrue((stage / "runtime/sbom-python.json").is_file())
        self.assertTrue((stage / "licenses/python-distributions.json").is_file())
        self.assertTrue((stage / "licenses/cpython/LICENSE.txt").is_file())
        provenance = json.loads(
            (stage / builder.PROVENANCE_OUTPUT_RELATIVE).read_bytes()
        )
        self.assertEqual(
            provenance["provenanceVersion"], builder.PROVENANCE_OUTPUT_VERSION
        )
        self.assertEqual(len(provenance["distributions"]), len(builder.REQUIRED_DISTRIBUTIONS))
        self.assertEqual(provenance["excludedDistributions"], [])
        self.assertTrue((stage / builder.THIRD_PARTY_NOTICES_RELATIVE).is_file())
        self.assertNotIn(
            "NOASSERTION",
            (stage / builder.THIRD_PARTY_NOTICES_RELATIVE).read_text(encoding="utf-8"),
        )

        manifest_path = stage / "worker/mineru-worker.support-manifest.json"
        manifest = builder.verify_support_manifest(manifest_path, stage)
        records = tuple(
            builder.FileRecord(entry["relativePath"], entry["sizeBytes"], entry["sha256"])
            for entry in manifest["files"]
        )
        self.assertEqual(manifest["supportTreeSha256"], builder.support_tree_hash(records))
        self.assertEqual(manifest["criticalFiles"], list(builder.CRITICAL_SUPPORT_PATHS))
        self.assertEqual([record.relative_path for record in records], sorted(record.relative_path for record in records))

    def test_support_manifest_tamper_and_duplicate_json_fail_closed(self) -> None:
        self.build_stage()
        stage = self.root / "stage"
        manifest_path = stage / "worker/mineru-worker.support-manifest.json"
        target = stage / "worker/sitecustomize.py"
        target.write_bytes(target.read_bytes() + b"#tamper\n")
        with self.assertRaises(builder.BuildFailure) as failure:
            builder.verify_support_manifest(manifest_path, stage)
        self.assertEqual(failure.exception.code, "support_file_changed")

        value = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaises(builder.BuildFailure) as failure:
            builder.verify_support_manifest(manifest_path, stage)
        self.assertEqual(failure.exception.code, "support_manifest_duplicate_field")
        manifest_path.write_text(value, encoding="utf-8")
    def test_support_manifest_rejects_undeclared_support_files(self) -> None:
        self.build_stage("extra-stage")
        stage = self.root / "extra-stage"
        manifest_path = stage / "worker/mineru-worker.support-manifest.json"
        (stage / "runtime/undeclared-support.bin").write_bytes(b"undeclared")
        with self.assertRaises(builder.BuildFailure) as failure:
            builder.verify_support_manifest(manifest_path, stage)
        self.assertEqual(failure.exception.code, "support_tree_inventory_changed")


    def test_dev_launcher_is_external_diagnostic_and_binds_final_path(self) -> None:
        output = self.root / "dev"
        with mock.patch.object(builder, "probe_runtime_identity", return_value=self.identity):
            result = builder.build_dev_launcher(
                python_home=self.python_home,
                site_packages=self.site_packages,
                pipeline_model=self.pipeline,
                vlm_model=self.vlm,
                worker_source=self.worker_source,
                output=output,
            )
        self.assertTrue(result["diagnosticOnly"])
        self.assertFalse(result["selfContained"])
        self.assertEqual(Path(result["worker"]), output / "worker/mineru-worker.exe")
        runtime = json.loads((output / "runtime-manifest.json").read_bytes())
        normalized = str(output / "worker/mineru-worker.exe").replace("/", "\\").lower()
        self.assertEqual(runtime["executables"][0]["pathSha256"], builder.sha256_bytes(normalized.encode()))
        self.assertIn(str(self.python_home / "Lib"), (output / "worker/mineru-worker._pth").read_text())

    def test_output_is_create_new_and_failed_stage_is_cleaned(self) -> None:
        self.build_stage("existing")
        with self.assertRaises(builder.BuildFailure) as failure:
            self.build_stage("existing")
        self.assertEqual(failure.exception.code, "output_exists")
        original = builder._copy_tree
        with mock.patch.object(
            builder, "_copy_tree", side_effect=builder.BuildFailure("synthetic_copy_failure")
        ):
            with self.assertRaises(builder.BuildFailure):
                self.build_stage("failed")
        self.assertIsNotNone(original)
        self.assertFalse((self.root / "failed").exists())
        self.assertFalse(any(self.root.glob(".failed.incoming-*")))

    def test_provenance_approval_is_explicit_canonical_and_create_new(self) -> None:
        draft = self.root / "approval-draft.json"
        output = self.root / "approval-input.json"
        value = {
            "schemaVersion": builder.PROVENANCE_SCHEMA_VERSION,
            "provenanceVersion": builder.PROVENANCE_INPUT_VERSION,
            "approval": {
                "approvedForRedistribution": False,
                "reviewer": "",
                "reviewedAtUnix": 0,
            },
            "source": {},
            "cpython": {},
            "runtimeProfile": {},
            "distributions": [],
            "models": [],
        }
        draft.write_bytes(builder.canonical_json(value))
        result = builder.approve_provenance_draft(
            draft=draft,
            reviewer="synthetic-release-owner",
            reviewed_at=1_700_000_000,
            output=output,
        )
        self.assertEqual(result["mode"], "provenance-approve")
        approved = json.loads(output.read_bytes())
        self.assertEqual(
            approved["approval"],
            {
                "approvedForRedistribution": True,
                "reviewer": "synthetic-release-owner",
                "reviewedAtUnix": 1_700_000_000,
            },
        )
        self.assertEqual(output.read_bytes(), builder.canonical_json(approved))
        with self.assertRaisesRegex(builder.BuildFailure, "output_exists"):
            builder.approve_provenance_draft(
                draft=draft,
                reviewer="synthetic-release-owner",
                reviewed_at=1_700_000_000,
                output=output,
            )

    def test_provenance_approval_rejects_reapproval_and_unknown_fields(self) -> None:
        value = {
            "schemaVersion": builder.PROVENANCE_SCHEMA_VERSION,
            "provenanceVersion": builder.PROVENANCE_INPUT_VERSION,
            "approval": {
                "approvedForRedistribution": True,
                "reviewer": "already-approved",
                "reviewedAtUnix": 1,
            },
            "source": {},
            "cpython": {},
            "runtimeProfile": {},
            "distributions": [],
            "models": [],
        }
        draft = self.root / "already-approved.json"
        draft.write_bytes(builder.canonical_json(value))
        with self.assertRaisesRegex(
            builder.BuildFailure, "provenance_approval_state_invalid"
        ):
            builder.approve_provenance_draft(
                draft=draft,
                reviewer="synthetic-release-owner",
                reviewed_at=2,
                output=self.root / "reapproved.json",
            )
        value["approval"] = {
            "approvedForRedistribution": False,
            "reviewer": "",
            "reviewedAtUnix": 0,
            "unexpected": True,
        }
        unknown = self.root / "unknown-approval.json"
        unknown.write_bytes(builder.canonical_json(value))
        with self.assertRaisesRegex(builder.BuildFailure, "provenance_approval_invalid"):
            builder.approve_provenance_draft(
                draft=unknown,
                reviewer="synthetic-release-owner",
                reviewed_at=2,
                output=self.root / "unknown-output.json",
            )


if __name__ == "__main__":
    unittest.main()
