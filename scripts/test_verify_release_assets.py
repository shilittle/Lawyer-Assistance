import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_mineru_component_package as mineru_packager  # noqa: E402
import verify_release_assets as verifier  # noqa: E402


TEST_PUBLIC_KEY = (
    "untrusted comment: minisign public key E7620F1842B4E81F\n"
    "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
)
TEST_SIGNATURE = (
    "untrusted comment: signature from minisign secret key\n"
    "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/"
    "z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n"
    "trusted comment: timestamp:1556193335\tfile:test\n"
    "y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1"
    "FkZZSNCisQbuQY+bHwhEBg=="
)
TEST_TAURI_SIGNATURE = TEST_SIGNATURE.replace(
    "signature from minisign secret key", "signature from tauri secret key", 1
)


def write_json(path: Path, value: object) -> None:
    path.write_bytes(verifier.canonical_json(value))


def base_contract(version: str = "0.4.0") -> dict[str, object]:
    contract_path = SCRIPTS / "release" / "release-contract-v0.4.0.json"
    value = json.loads(contract_path.read_text(encoding="utf-8"))
    if version != "0.4.0":
        value["release"] = {
            "formalVersion": version,
            "appTag": f"v{version}",
            "minerUTag": f"mineru-components-v{version}",
        }
        value["versions"]["formal"] = version
        value["appAssets"] = list(verifier.expected_app_assets(version))
    return value


def approved_provenance(commit: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "provenanceVersion": mineru_packager.PROVENANCE_VERSION,
        "provenanceInputSha256": "1" * 64,
        "approval": {
            "approvedForRedistribution": True,
            "reviewer": "release-test",
            "reviewedAtUnix": 1,
        },
        "source": {
            "repositoryCommit": commit,
            "buildScriptSha256": "2" * 64,
            "workerSourceTreeSha256": "3" * 64,
        },
        "cpython": {
            "version": "3.12.13",
            "sourceUrl": "https://www.python.org/",
            "contentSha256": "4" * 64,
            "license": "PSF-2.0",
            "licenseFileSha256": "5" * 64,
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


def archive_payloads(version: str, target: str, commit: str) -> tuple[str, dict[str, bytes]]:
    root = f"lawyer-assistance-mcp-v{version}-{target}"
    binary_name = "lawyer-assistance-mcp.exe" if "windows" in target else "lawyer-assistance-mcp"
    binary = f"binary-{target}".encode()
    provenance = {
        "schemaVersion": 1,
        "sourceCommit": commit,
        "sourceCommitTimestamp": 1,
        "sourceClean": True,
        "binarySha256": hashlib.sha256(binary).hexdigest(),
        "binarySize": len(binary),
        "binaryVersion": version,
        "binaryFresh": True,
        "releaseReady": True,
        "target": target,
    }
    payloads = {
        binary_name: binary,
        "PACKAGE-PROVENANCE.json": verifier.canonical_json(provenance) + b"\n",
    }
    lines = [
        verifier.mcp_packager.MANIFEST_HEADER,
        *[
            f"{hashlib.sha256(raw).hexdigest()}  {len(raw)}  {name}"
            for name, raw in sorted(payloads.items(), key=lambda item: item[0].casefold())
        ],
    ]
    payloads["MANIFEST.sha256"] = ("\n".join(lines) + "\n").encode()
    return root, payloads


def write_mcp_archive(path: Path, root: str, payloads: dict[str, bytes]) -> None:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in payloads.items():
                archive.writestr(f"{root}/{name}", raw)
    else:
        with tarfile.open(path, "w:gz") as archive:
            for name, raw in payloads.items():
                info = tarfile.TarInfo(f"{root}/{name}")
                info.size = len(raw)
                archive.addfile(info, BytesIO(raw))


class ContractAndPrimitiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract_path = self.root / "contract.json"
        write_json(self.contract_path, base_contract())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_contract_derives_exact_twelve_and_rejects_drift(self) -> None:
        contract = verifier.load_contract(self.contract_path)
        self.assertEqual(len(contract.app_assets), 12)
        value = base_contract()
        value["appAssets"][0] = "alias.exe"
        write_json(self.contract_path, value)
        with self.assertRaisesRegex(verifier.VerificationError, "frozen canonical") as failure:
            verifier.load_contract(self.contract_path)
        self.assertEqual(failure.exception.code, "contract_invalid")

        for mutation in ("repository", "version", "top-level"):
            value = base_contract()
            if mutation == "repository":
                value["repository"]["owner"] = "attacker"
            elif mutation == "version":
                value = base_contract("0.4.1")
            else:
                value["unexpected"] = True
            write_json(self.contract_path, value)
            with self.assertRaises(verifier.VerificationError):
                verifier.load_contract(self.contract_path)

    def test_asset_set_rejects_extra_case_alias_symlink_and_empty(self) -> None:
        release = self.root / "release"
        release.mkdir()
        (release / "only").write_bytes(b"ok")
        verifier._assert_exact_names(release, ("only",))
        (release / "extra").write_bytes(b"x")
        with self.assertRaises(verifier.VerificationError):
            verifier._assert_exact_names(release, ("only",))
        (release / "extra").unlink()
        with (
            mock.patch.object(verifier, "_directory_names", return_value=("only", "ONLY")),
            self.assertRaises(verifier.VerificationError),
        ):
            verifier._assert_exact_names(release, ("only",))
        (release / "only").write_bytes(b"")
        with self.assertRaisesRegex(verifier.VerificationError, "nonempty"):
            verifier._assert_exact_names(release, ("only",))
        (release / "only").write_bytes(b"ok")
        try:
            os.symlink(release / "only", release / "link")
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(verifier.VerificationError, "non-linked"):
            verifier._assert_exact_names(release, ("only", "link"))

    def test_canonical_checksum_rejects_uppercase_or_alias_filename(self) -> None:
        asset = self.root / "asset.zip"
        asset.write_bytes(b"bytes")
        digest = hashlib.sha256(b"bytes").hexdigest()
        (self.root / "asset.zip.sha256").write_bytes(f"{digest}  asset.zip\n".encode("ascii"))
        verifier.verify_canonical_checksum(self.root, "asset.zip")
        (self.root / "asset.zip.sha256").write_bytes(
            f"{digest.upper()} *asset.zip\n".encode("ascii")
        )
        with self.assertRaisesRegex(verifier.VerificationError, "not canonical"):
            verifier.verify_canonical_checksum(self.root, "asset.zip")

    def test_dependency_free_minisign_verifies_and_rejects_tamper_and_filename(self) -> None:
        key = self.root / "key"
        key.write_bytes(base64.b64encode(TEST_PUBLIC_KEY.encode()))
        self.assertEqual(
            verifier.verify_minisign(
                b"test", TEST_SIGNATURE.encode(), expected_filename="test", public_key_path=key
            ),
            1556193335,
        )
        for content, filename in ((b"Test", "test"), (b"test", "other")):
            with self.assertRaises(verifier.VerificationError):
                verifier.verify_minisign(
                    content,
                    TEST_SIGNATURE.encode(),
                    expected_filename=filename,
                    public_key_path=key,
                )

    def test_tauri_updater_envelope_is_base64_and_has_an_exact_distinct_comment(self) -> None:
        key = self.root / "key"
        key.write_bytes(base64.b64encode(TEST_PUBLIC_KEY.encode()))
        envelope = base64.b64encode(TEST_TAURI_SIGNATURE.encode())
        decoded = verifier.decode_tauri_signature_envelope(envelope)
        self.assertEqual(decoded, TEST_TAURI_SIGNATURE.encode())
        self.assertEqual(
            verifier.verify_minisign(
                b"test",
                decoded,
                expected_filename="test",
                public_key_path=key,
                expected_untrusted_comment=verifier.TAURI_SIGNATURE_COMMENT,
            ),
            1556193335,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_minisign(
                b"test",
                TEST_SIGNATURE.encode(),
                expected_filename="test",
                public_key_path=key,
                expected_untrusted_comment=verifier.TAURI_SIGNATURE_COMMENT,
            )
        for invalid in (envelope + b"\n", envelope[:-1], b"not-base64"):
            with self.assertRaises(verifier.VerificationError):
                verifier.decode_tauri_signature_envelope(invalid)

    def test_verification_output_is_fresh_create_new_and_reread(self) -> None:
        output = self.root / "verified"
        written = verifier.write_verified_authenticode_files(output, {"one.exe": b"MZone"})
        self.assertEqual(Path(written[0]).read_bytes(), b"MZone")
        with self.assertRaisesRegex(verifier.VerificationError, "must be empty"):
            verifier.write_verified_authenticode_files(output, {"one.exe": b"MZone"})


class AppArchiveTests(unittest.TestCase):
    VERSION = "0.4.0"
    COMMIT = "a" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = self.root / "key"
        self.key.write_bytes(base64.b64encode(TEST_PUBLIC_KEY.encode()))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def portable_members(self) -> dict[str, bytes]:
        app = b"MZapp"
        mcp = b"MZmcp"
        files = {
            "lawyer-assistance.exe": app,
            "lawyer-assistance-mcp.exe": mcp,
            "resources/legal_core.sqlite": b"sqlite",
        }
        inventory = [
            {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in sorted(files.items(), key=lambda item: item[0])
        ]
        manifest = {
            "manifestVersion": 1,
            "manifestScope": "all packaged files except release-manifest.json and the external .sha256 checksum",
            "version": self.VERSION,
            "commit": self.COMMIT,
            "architecture": "x86_64-pc-windows-msvc",
            "buildMode": "signed-build-provenance",
            "generatedAt": "2026-01-01T00:00:00+00:00",
            "buildProvenance": {
                "sourceCommit": self.COMMIT,
                "sourceDateEpoch": 1,
                "executablePath": "target/x86_64-pc-windows-msvc/release/lawyer-assistance.exe",
                "executableSha256": hashlib.sha256(app).hexdigest(),
                "mcpBinaryPath": "target/x86_64-pc-windows-msvc/release/lawyer-assistance-mcp.exe",
                "mcpBinarySha256": hashlib.sha256(mcp).hexdigest(),
            },
            "mcpBinary": {
                "siblingPath": "lawyer-assistance-mcp.exe",
                "version": self.VERSION,
                "size": len(mcp),
                "sha256": hashlib.sha256(mcp).hexdigest(),
                "qualificationBinding": "compiled-release-sha256+canonical-path-identity+file-identity+sha256+version",
            },
            "toolchain": {"rustc": "rustc", "node": "node", "tauriCli": "tauri"},
            "lockfiles": {"cargoSha256": "1" * 64, "pnpmSha256": "2" * 64},
            "legalDatabase": {
                "version": "v",
                "scope": "runtime-slim-v1",
                "size": 6,
                "sha256": hashlib.sha256(b"sqlite").hexdigest(),
                "sourceManifestSha256": "3" * 64,
            },
            "updaterPublicKey": self.key.read_text(encoding="ascii"),
            "files": inventory,
        }
        files["release-manifest.json"] = json.dumps(manifest).encode()
        return files

    def write_portable(self, members: dict[str, bytes]) -> Path:
        path = self.root / "portable.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        return path

    def test_portable_exact_manifest_version_commit_and_mcp_anchor(self) -> None:
        path = self.write_portable(self.portable_members())
        names, binaries = verifier.verify_portable(
            path,
            version=self.VERSION,
            expected_commit=self.COMMIT,
            public_key_path=self.key,
        )
        self.assertIn("release-manifest.json", names)
        self.assertEqual(binaries["portable-lawyer-assistance-mcp.exe"], b"MZmcp")

    def test_portable_tamper_matrix_rejects_extra_traversal_alias_hash_commit(self) -> None:
        mutations: list[tuple[str, callable]] = [
            ("extra", lambda members: members.__setitem__("extra.txt", b"x")),
            ("traversal", lambda members: members.__setitem__("../escape", b"x")),
            ("alias", lambda members: members.__setitem__("LAWYER-ASSISTANCE.EXE", b"x")),
            ("payload", lambda members: members.__setitem__("lawyer-assistance.exe", b"tampered")),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                members = self.portable_members()
                mutate(members)
                path = self.write_portable(members)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_portable(
                        path,
                        version=self.VERSION,
                        expected_commit=self.COMMIT,
                        public_key_path=self.key,
                    )
        with self.assertRaisesRegex(verifier.VerificationError, "identity"):
            verifier.verify_portable(
                self.write_portable(self.portable_members()),
                version=self.VERSION,
                expected_commit="b" * 40,
                public_key_path=self.key,
            )

    def test_three_mcp_archives_reuse_manifest_and_require_release_ready_head(self) -> None:
        targets = (
            ("x86_64-pc-windows-msvc", ".zip"),
            ("x86_64-unknown-linux-gnu", ".tar.gz"),
            ("aarch64-apple-darwin", ".tar.gz"),
        )
        for target, suffix in targets:
            name = f"lawyer-assistance-mcp-v{self.VERSION}-{target}{suffix}"
            root, payloads = archive_payloads(self.VERSION, target, self.COMMIT)
            write_mcp_archive(self.root / name, root, payloads)
            binary = verifier.verify_mcp_archive(
                self.root,
                name,
                version=self.VERSION,
                target=target,
                expected_commit=self.COMMIT,
            )
            self.assertTrue(binary)

        target = "x86_64-pc-windows-msvc"
        name = f"lawyer-assistance-mcp-v{self.VERSION}-{target}.zip"
        root, payloads = archive_payloads(self.VERSION, target, self.COMMIT)
        provenance = json.loads(payloads["PACKAGE-PROVENANCE.json"])
        provenance["releaseReady"] = False
        payloads["PACKAGE-PROVENANCE.json"] = verifier.canonical_json(provenance) + b"\n"
        lines = [
            verifier.mcp_packager.MANIFEST_HEADER,
            *[
                f"{hashlib.sha256(raw).hexdigest()}  {len(raw)}  {path}"
                for path, raw in sorted(
                    ((key, value) for key, value in payloads.items() if key != "MANIFEST.sha256"),
                    key=lambda item: item[0].casefold(),
                )
            ],
        ]
        payloads["MANIFEST.sha256"] = ("\n".join(lines) + "\n").encode()
        (self.root / name).unlink()
        write_mcp_archive(self.root / name, root, payloads)
        with self.assertRaisesRegex(verifier.VerificationError, "release-ready"):
            verifier.verify_mcp_archive(
                self.root,
                name,
                version=self.VERSION,
                target=target,
                expected_commit=self.COMMIT,
            )


class MineruAssetTests(unittest.TestCase):
    VERSION = "0.4.0"
    COMMIT = "a" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract_path = self.root / "contract.json"
        write_json(self.contract_path, base_contract())
        self.contract = verifier.load_contract(self.contract_path)
        self.key = self.root / "key"
        self.key.write_bytes(base64.b64encode(TEST_PUBLIC_KEY.encode()))
        self.issued = 1556193335
        self.logical = f"lawyer-assistance-mineru-{self.VERSION}-windows-x86_64.laocrpkg"
        self.descriptor = f"{self.logical}.laocrparts"
        self.part = f"{self.logical}.part0001-of-0001"
        self.provenance = verifier.canonical_json(approved_provenance(self.COMMIT))
        manifest = b"manifest"
        package = b"LAOCPK1\0" + len(manifest).to_bytes(4, "little") + manifest + b"payload"
        self.package = package
        self.descriptor_bytes = verifier.canonical_json(
            {
                "schemaVersion": 1,
                "packageId": "mineru-windows-stable",
                "componentVersion": self.VERSION,
                "packageFilename": self.logical,
                "packageSizeBytes": len(package),
                "packageSha256": hashlib.sha256(package).hexdigest(),
                "packageManifestSha256": hashlib.sha256(manifest).hexdigest(),
                "partCount": 1,
                "parts": [
                    {
                        "number": 1,
                        "fileName": self.part,
                        "sizeBytes": len(package),
                        "sha256": hashlib.sha256(package).hexdigest(),
                    }
                ],
            }
        )
        base = (
            f"https://github.com/shilittle/Lawyer-Assistance/releases/download/"
            f"mineru-components-v{self.VERSION}/"
        )
        self.catalog = {
            "schemaVersion": 2,
            "catalogId": "mineru-windows-stable-v1",
            "issuedAtUnix": self.issued,
            "expiresAtUnix": int(time.time()) + 86_400,
            "entries": [
                {
                    "packageId": "mineru-windows-stable",
                    "componentVersion": self.VERSION,
                    "mineruVersion": "3.4.3",
                    "protocolVersion": mineru_packager.PROTOCOL_VERSION,
                    "platform": mineru_packager.PLATFORM,
                    "packageSizeBytes": len(package),
                    "packageSha256": hashlib.sha256(package).hexdigest(),
                    "packageManifestSha256": hashlib.sha256(manifest).hexdigest(),
                    "provenanceFileName": verifier.MINERU_PROVENANCE,
                    "provenanceSizeBytes": len(self.provenance),
                    "provenanceSha256": hashlib.sha256(self.provenance).hexdigest(),
                    "provenanceDownloadUrl": base + verifier.MINERU_PROVENANCE,
                    "downloadUrl": base + self.descriptor,
                    "partSetManifestSizeBytes": len(self.descriptor_bytes),
                    "partSetManifestSha256": hashlib.sha256(self.descriptor_bytes).hexdigest(),
                    "parts": [
                        {
                            "number": 1,
                            "fileName": self.part,
                            "sizeBytes": len(package),
                            "sha256": hashlib.sha256(package).hexdigest(),
                            "downloadUrl": base + self.part,
                        }
                    ],
                    "revoked": False,
                }
            ],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def materialize(self) -> None:
        (self.root / verifier.MINERU_CATALOG).write_bytes(verifier.canonical_json(self.catalog))
        (self.root / f"{verifier.MINERU_CATALOG}.minisig").write_text(TEST_SIGNATURE, encoding="utf-8")
        (self.root / verifier.MINERU_PROVENANCE).write_bytes(self.provenance)
        (self.root / f"{verifier.MINERU_PROVENANCE}.minisig").write_text(TEST_SIGNATURE, encoding="utf-8")
        (self.root / self.descriptor).write_bytes(self.descriptor_bytes)
        (self.root / self.part).write_bytes(self.package)

    def derive(self) -> tuple[str, ...]:
        def signature(
            _content: bytes,
            _signature: bytes,
            *,
            expected_filename: str,
            public_key_path: Path,
        ) -> int:
            self.assertIn(expected_filename, {verifier.MINERU_CATALOG, verifier.MINERU_PROVENANCE})
            self.assertEqual(public_key_path, self.key)
            return self.issued

        with mock.patch.object(verifier, "verify_minisign", side_effect=signature):
            names, _entry, _issued = verifier.derive_mineru_assets(
                self.root, self.contract, public_key_path=self.key
            )
        return names

    def test_authenticated_catalog_uniquely_derives_descriptor_and_ordered_parts(self) -> None:
        self.materialize()
        self.assertEqual(
            self.derive(),
            (
                verifier.MINERU_CATALOG,
                f"{verifier.MINERU_CATALOG}.minisig",
                verifier.MINERU_PROVENANCE,
                f"{verifier.MINERU_PROVENANCE}.minisig",
                self.descriptor,
                self.part,
            ),
        )

    def test_mineru_asset_set_rejects_extra_missing_laocrpkg_case_alias_and_symlink(self) -> None:
        mutations = ("extra", "missing", "laocrpkg", "alias", "symlink")
        for label in mutations:
            with self.subTest(label=label):
                for item in list(self.root.iterdir()):
                    if item != self.contract_path and item != self.key:
                        item.unlink()
                self.materialize()
                expected = self.derive()
                if label == "extra":
                    (self.root / "extra.bin").write_bytes(b"x")
                elif label == "missing":
                    (self.root / self.part).unlink()
                elif label == "laocrpkg":
                    (self.root / self.logical).write_bytes(b"forbidden")
                elif label == "alias":
                    actual = verifier._directory_names(self.root)
                    with (
                        mock.patch.object(
                            verifier,
                            "_directory_names",
                            return_value=(*actual, self.part.upper()),
                        ),
                        self.assertRaises(verifier.VerificationError),
                    ):
                        verifier._assert_exact_names(
                            self.root, (*expected, "contract.json", "key")
                        )
                    continue
                else:
                    try:
                        os.symlink(self.root / self.part, self.root / "linked")
                    except OSError:
                        continue
                with self.assertRaises(verifier.VerificationError):
                    verifier._assert_exact_names(self.root, (*expected, "contract.json", "key"))

    def test_catalog_tamper_matrix_rejects_order_url_hash_version_and_commit(self) -> None:
        for label in ("number", "name", "url", "hash", "version"):
            with self.subTest(label=label):
                catalog = copy.deepcopy(self.catalog)
                entry = catalog["entries"][0]
                if label == "number":
                    entry["parts"][0]["number"] = 2
                elif label == "name":
                    entry["parts"][0]["fileName"] = "other"
                elif label == "url":
                    entry["parts"][0]["downloadUrl"] = "https://example.com/part"
                elif label == "hash":
                    entry["parts"][0]["sha256"] = "z" * 64
                else:
                    entry["componentVersion"] = "0.4.1"
                self.catalog = catalog
                self.materialize()
                with self.assertRaises(verifier.VerificationError):
                    self.derive()

    def test_full_mineru_chain_delegates_package_verifier_and_rejects_commit(self) -> None:
        self.materialize()
        expected = self.derive()
        # Release verifier requires an exact release-only directory.
        self.contract_path.unlink()
        self.key_bytes = self.key.read_bytes()
        self.key.unlink()

        def signature(*_args: object, **_kwargs: object) -> int:
            return self.issued

        with (
            mock.patch.object(verifier, "verify_minisign", side_effect=signature),
            mock.patch.object(mineru_packager, "verify_sharded_package") as sharded,
        ):
            report = verifier.verify_mineru_release(
                self.root,
                self.contract,
                self.COMMIT,
                public_key_path=Path("ignored"),
            )
            self.assertEqual(report.asset_names, expected)
            sharded.assert_called_once()
            with self.assertRaisesRegex(verifier.VerificationError, "exact release HEAD"):
                verifier.verify_mineru_release(
                    self.root,
                    self.contract,
                    "b" * 40,
                    public_key_path=Path("ignored"),
                )


if __name__ == "__main__":
    unittest.main()
