import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
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
        self.repository_root = self.root / "repository"
        (self.repository_root / "scripts").mkdir(parents=True)
        shutil.copyfile(
            Path(builder.__file__),
            self.repository_root / "scripts/build_production_mineru_worker.py",
        )
        shutil.copytree(
            Path(__file__).parents[1] / "workers/mineru",
            self.repository_root / "workers/mineru",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        (self.repository_root / "LICENSE").write_text(
            "Lawyer Assistance synthetic license\n", encoding="utf-8", newline="\n"
        )
        (self.repository_root / ".gitattributes").write_text(
            "* -text\n", encoding="utf-8", newline="\n"
        )
        (self.repository_root / ".gitignore").write_text(
            "*.ignored\n__pycache__/\n*.pyc\n", encoding="utf-8", newline="\n"
        )
        self._git("init", "--quiet")
        self._git("config", "user.name", "Synthetic Builder Test")
        self._git("config", "user.email", "builder-test@example.invalid")
        self._git("add", "--all")
        self._git("commit", "--quiet", "-m", "synthetic source fixture")
        self.fixture_module_name = (
            f"build_production_mineru_worker_fixture_{id(self):x}"
        )
        self.repo_builder = self._load_fixture_builder()
        self.python_home = self.root / "cpython"
        self.site_packages = self.root / "environment/Lib/site-packages"
        self.pipeline = self.root / "models/pipeline"
        self.vlm = self.root / "models/vlm"
        self.worker_source = self.repository_root / "workers/mineru"
        self.repository_license = self.repository_root / "LICENSE"
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

        for name, version in self.repo_builder.REQUIRED_DISTRIBUTIONS.items():
            dist = self.site_packages / f"{name.replace('-', '_')}-{version}.dist-info"
            dist.mkdir()
            requirements = ""
            if name == "mineru":
                requirements = "".join(
                    f"Requires-Dist: {dependency}=={dependency_version}\n"
                    for dependency, dependency_version in self.repo_builder.REQUIRED_DISTRIBUTIONS.items()
                    if dependency != "mineru"
                )
            license_metadata = (
                f"License-Expression: {self.repo_builder.MINERU_LICENSE_ID}\n"
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
        for relative in self.repo_builder.QUALIFIED_MODELS["pipeline"]["files"]:
            path = self.pipeline / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"pipeline:{relative}".encode("utf-8"))
        for relative in self.repo_builder.QUALIFIED_MODELS["vlm"]["files"]:
            path = self.vlm / relative
            path.write_bytes(f"vlm:{relative}".encode("utf-8"))
        self.identity = self.repo_builder.RuntimeIdentity(
            python_version=self.repo_builder.CPYTHON_VERSION,
            architecture="windows-x86_64",
            distributions=tuple(
                sorted(
                    (self.repo_builder.canonical_distribution_name(name), version)
                    for name, version in self.repo_builder.REQUIRED_DISTRIBUTIONS.items()
                )
            ),
        )

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repository_root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()

    def _git_bytes(self, *arguments: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.repository_root), *arguments],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout

    def _load_fixture_builder(self, path: Path | None = None):
        source = path or self.repository_root / "scripts/build_production_mineru_worker.py"
        name = self.fixture_module_name if path is None else f"{self.fixture_module_name}_external"
        spec = importlib.util.spec_from_file_location(name, source)
        if spec is None or spec.loader is None:
            self.fail("could not load the synthetic builder module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def _source_binding(self):
        return self.repo_builder._repository_source_binding(
            self.repository_root,
            self.worker_source,
            self.repository_license,
        )

    def test_runtime_probe_uses_abi_metadata_in_sanitized_environment(self) -> None:
        expected = {
            "implementation": "cpython",
            "python": self.repo_builder.CPYTHON_VERSION,
            "releaseLevel": "final",
            "serial": 0,
            "platform": "win-amd64",
            "pointerBits": 64,
            "maxsize": 9223372036854775807,
        }

        def completed(command, **options):
            environment = options["env"]
            self.assertEqual(
                command,
                [
                    str(self.python_home / "python.exe"),
                    "-I",
                    "-S",
                    "-c",
                    self.repo_builder.RUNTIME_IDENTITY_PROBE,
                ],
            )
            self.assertEqual(
                set(environment),
                {
                    "SystemRoot",
                    "WINDIR",
                    "PATH",
                    "PYTHONNOUSERSITE",
                    "PYTHONSAFEPATH",
                    "PYTHONDONTWRITEBYTECODE",
                    "PIP_NO_INDEX",
                    "HF_HUB_OFFLINE",
                    "TRANSFORMERS_OFFLINE",
                    "NO_PROXY",
                    "no_proxy",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                },
            )
            self.assertEqual(environment["PATH"], str(self.python_home))
            self.assertTrue(options["check"])
            self.assertTrue(options["capture_output"])
            self.assertEqual(options["timeout"], 30)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=self.repo_builder.canonical_json(expected),
                stderr=b"",
            )

        with mock.patch.object(
            self.repo_builder.subprocess, "run", side_effect=completed
        ):
            identity = self.repo_builder.probe_runtime_identity(
                self.python_home, self.site_packages
            )
        self.assertEqual(identity.python_version, self.repo_builder.CPYTHON_VERSION)
        self.assertEqual(identity.architecture, "windows-x86_64")

    def test_runtime_probe_rejects_every_identity_mismatch(self) -> None:
        expected = {
            "implementation": "cpython",
            "python": self.repo_builder.CPYTHON_VERSION,
            "releaseLevel": "final",
            "serial": 0,
            "platform": "win-amd64",
            "pointerBits": 64,
            "maxsize": 9223372036854775807,
        }
        mutations = {
            "implementation": "pypy",
            "python": "3.12.12",
            "releaseLevel": "candidate",
            "serial": 1,
            "platform": "win-arm64",
            "pointerBits": 32,
            "maxsize": 2147483647,
        }
        candidates = []
        for field, value in mutations.items():
            candidate = dict(expected)
            candidate[field] = value
            candidates.append((field, candidate))
        candidates.append(
            (
                "missing_field",
                {
                    key: value
                    for key, value in expected.items()
                    if key != "platform"
                },
            )
        )
        candidates.append(("extra_field", {**expected, "machine": "AMD64"}))
        candidates.append(
            (
                "obsolete_empty_machine_shape",
                {
                    "python": self.repo_builder.CPYTHON_VERSION,
                    "machine": "",
                    "maxsize": 9223372036854775807,
                },
            )
        )

        for label, candidate in candidates:
            with self.subTest(label=label), mock.patch.object(
                self.repo_builder.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["python.exe"],
                    0,
                    stdout=self.repo_builder.canonical_json(candidate),
                    stderr=b"",
                ),
            ):
                with self.assertRaises(self.repo_builder.BuildFailure) as failure:
                    self.repo_builder.probe_runtime_identity(
                        self.python_home, self.site_packages
                    )
                self.assertEqual(failure.exception.code, "python_version_unqualified")

    def tearDown(self) -> None:
        for name in tuple(sys.modules):
            if name.startswith(self.fixture_module_name):
                sys.modules.pop(name, None)
        self.temporary.cleanup()

    def build_stage(self, name: str = "stage"):
        active_builder = self.repo_builder
        selected = active_builder.resolve_runtime_distributions(self.site_packages)
        measurements = tuple(
            active_builder.measure_distribution(self.site_packages, item) for item in selected
        )
        cpython_hash, cpython_records = active_builder.measure_cpython(self.python_home)
        commit = self._git("rev-parse", "HEAD")
        source_binding = active_builder._repository_source_binding(
            self.repository_root, self.worker_source, self.repository_license
        )
        provenance = {
            "schemaVersion": active_builder.PROVENANCE_SCHEMA_VERSION,
            "provenanceVersion": active_builder.PROVENANCE_INPUT_VERSION,
            "approval": {
                "approvedForRedistribution": True,
                "reviewer": "synthetic-test-reviewer",
                "reviewedAtUnix": 1,
            },
            "source": {
                "repositoryCommit": commit,
                "buildScriptSha256": source_binding.build_script_sha256,
                "workerSourceTreeSha256": source_binding.worker_source_tree_sha256,
            },
            "cpython": {
                "version": active_builder.CPYTHON_VERSION,
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
                "extras": list(active_builder.MINERU_RUNTIME_EXTRAS),
            },
            "distributions": [
                {
                    "name": item.name,
                    "version": item.version,
                    "contentSha256": item.content_sha256,
                    "sourceUrl": item.source_urls[0],
                    "license": item.license_declaration,
                    "licenseEvidenceKind": item.license_evidence_kind,
                    "licenseFiles": active_builder._file_records_json(item.license_files),
                    "installationRecord": active_builder._file_records_json(
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
                    "name": active_builder.QUALIFIED_MODELS[root]["name"],
                    "revision": active_builder.QUALIFIED_MODELS[root]["revision"],
                    "sourceUrl": (
                        f"https://huggingface.co/{active_builder.QUALIFIED_MODELS[root]['name']}"
                        f"/tree/{active_builder.QUALIFIED_MODELS[root]['revision']}"
                    ),
                    "license": active_builder.QUALIFIED_MODELS[root]["license"],
                    "licenseEvidenceUrl": (
                        f"https://huggingface.co/{active_builder.QUALIFIED_MODELS[root]['name']}"
                        f"/blob/{active_builder.QUALIFIED_MODELS[root]['revision']}/README.md"
                    ),
                    "licenseEvidenceSha256": active_builder.QUALIFIED_MODELS[root][
                        "license_evidence_sha256"
                    ],
                    "files": active_builder._file_records_json(active_builder.inventory_tree(model)),
                }
                for root, model in (("pipeline", self.pipeline), ("vlm", self.vlm))
            ],
        }
        provenance_input = self.root / f"{name}-provenance-input.json"
        provenance_input.write_bytes(active_builder.canonical_json(provenance))
        with mock.patch.object(
            active_builder, "probe_runtime_identity", return_value=self.identity
        ):
            return active_builder.build_self_contained_stage(
                python_home=self.python_home,
                site_packages=self.site_packages,
                pipeline_model=self.pipeline,
                vlm_model=self.vlm,
                worker_source=self.worker_source,
                repository_license=self.repository_license,
                provenance_input=provenance_input,
                repository_root=self.repository_root,
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
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self.build_stage("existing")
        self.assertEqual(failure.exception.code, "output_exists")
        original = self.repo_builder._copy_tree
        with mock.patch.object(
            self.repo_builder,
            "_copy_tree",
            side_effect=self.repo_builder.BuildFailure("synthetic_copy_failure"),
        ):
            with self.assertRaises(self.repo_builder.BuildFailure):
                self.build_stage("failed")
        self.assertIsNotNone(original)
        self.assertFalse((self.root / "failed").exists())
        self.assertFalse(any(self.root.glob(".failed.incoming-*")))

    def test_repository_source_binding_accepts_only_clean_head_bytes(self) -> None:
        binding = self._source_binding()
        builder_head = self._git_bytes(
            "show", "HEAD:scripts/build_production_mineru_worker.py"
        )
        license_head = self._git_bytes("show", "HEAD:LICENSE")
        self.assertEqual(binding.repository_commit, self._git("rev-parse", "HEAD"))
        self.assertEqual(
            binding.build_script_sha256,
            self.repo_builder.sha256_bytes(builder_head),
        )
        self.assertEqual(
            binding.worker_source_tree_sha256,
            self.repo_builder.measure_worker_source(self.worker_source),
        )
        self.assertEqual(
            binding.repository_license,
            self.repo_builder.FileRecord(
                "licenses/lawyer-assistance/LICENSE.txt",
                len(license_head),
                self.repo_builder.sha256_bytes(license_head),
            ),
        )

    def test_repository_source_binding_rejects_tracked_drift(self) -> None:
        target = self.worker_source / "lawyer_assistance_mineru_worker/main.py"
        target.write_bytes(target.read_bytes() + b"\n# tracked drift\n")
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "repository_not_clean")

    def test_repository_source_binding_checks_head_bytes_after_status_bypass(self) -> None:
        relative = "workers/mineru/lawyer_assistance_mineru_worker/main.py"
        self._git("update-index", "--assume-unchanged", "--", relative)
        target = self.repository_root / relative
        target.write_bytes(target.read_bytes() + b"\n# hidden drift\n")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "repository_source_bytes_changed")

    def test_repository_source_binding_rejects_untracked_and_ignored_extras(self) -> None:
        package = self.worker_source / "lawyer_assistance_mineru_worker"
        untracked = package / "untracked-source.py"
        untracked.write_text("unexpected = True\n", encoding="utf-8", newline="\n")
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "repository_not_clean")
        untracked.unlink()

        ignored = package / "shadow.ignored"
        ignored.write_text("ignored but unsafe\n", encoding="utf-8", newline="\n")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(
            failure.exception.code, "repository_source_inventory_changed"
        )

    def test_repository_source_binding_rejects_outside_worker_and_license(self) -> None:
        outside_worker = self.root / "outside-worker"
        shutil.copytree(self.worker_source, outside_worker)
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self.repo_builder._repository_source_binding(
                self.repository_root,
                outside_worker,
                self.repository_license,
            )
        self.assertEqual(failure.exception.code, "repository_source_path_invalid")

        outside_license = self.root / "outside-LICENSE"
        shutil.copyfile(self.repository_license, outside_license)
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self.repo_builder._repository_source_binding(
                self.repository_root,
                self.worker_source,
                outside_license,
            )
        self.assertEqual(failure.exception.code, "repository_source_path_invalid")

    def test_repository_source_binding_rejects_outside_executing_builder(self) -> None:
        outside_builder = self.root / "external-builder.py"
        shutil.copyfile(
            self.repository_root / "scripts/build_production_mineru_worker.py",
            outside_builder,
        )
        external_module = self._load_fixture_builder(outside_builder)
        with self.assertRaises(external_module.BuildFailure) as failure:
            external_module._repository_source_binding(
                self.repository_root,
                self.worker_source,
                self.repository_license,
            )
        self.assertEqual(failure.exception.code, "repository_source_path_invalid")

    def test_repository_source_binding_rejects_hidden_builder_replacement(self) -> None:
        relative = "scripts/build_production_mineru_worker.py"
        self._git("update-index", "--assume-unchanged", "--", relative)
        target = self.repository_root / relative
        target.write_bytes(target.read_bytes() + b"\n# replacement\n")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "repository_source_bytes_changed")

    def test_repository_source_binding_rejects_hidden_license_replacement(self) -> None:
        self._git("update-index", "--assume-unchanged", "--", "LICENSE")
        self.repository_license.write_bytes(
            self.repository_license.read_bytes() + b"replacement\n"
        )
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "repository_source_bytes_changed")

    def test_repository_source_binding_rejects_ignored_symlink_reparse(self) -> None:
        link = (
            self.worker_source
            / "lawyer_assistance_mineru_worker"
            / "unsafe-link.ignored"
        )
        try:
            os.symlink(self.repository_license, link)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        self.assertEqual(
            self._git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        with self.assertRaises(self.repo_builder.BuildFailure) as failure:
            self._source_binding()
        self.assertEqual(failure.exception.code, "filesystem_rejected")

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
