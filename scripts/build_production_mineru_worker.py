#!/usr/bin/env python3
"""Build the pinned, local-only Lawyer Assistance MinerU worker runtime.

The builder never downloads dependencies and never accepts document material.
It supports a small diagnostic launcher that references an existing local
environment and a production, self-contained component staging tree.  The
production tree is suitable as input to ``build_mineru_component_package.py``;
the package/catalog remains unsigned until the release owner signs it with the
external Minisign key.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import email.message
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Mapping, Sequence

try:
    from packaging.markers import default_environment
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name as packaging_canonicalize_name
except ImportError:  # pragma: no cover - exercised through the stable failure below.
    default_environment = None
    InvalidRequirement = ValueError
    Requirement = None
    packaging_canonicalize_name = None


PROTOCOL_VERSION = "la-mineru-worker-v1"
WORKER_VERSION = "1.0.0"
SUPPORT_MANIFEST_VERSION = "lawyer-assistance-mineru-support-v1"
SUPPORT_SCHEMA_VERSION = 1
CPYTHON_VERSION = "3.12.13"
MODEL_MANIFEST_VERSION = "mineru-model-manifest-v1"
PROVENANCE_INPUT_VERSION = "lawyer-assistance-mineru-provenance-input-v1"
PROVENANCE_OUTPUT_VERSION = "lawyer-assistance-mineru-component-provenance-v1"
PROVENANCE_SCHEMA_VERSION = 1
PROVENANCE_OUTPUT_RELATIVE = "licenses/mineru-component-provenance.json"
THIRD_PARTY_NOTICES_RELATIVE = "licenses/THIRD_PARTY_NOTICES.txt"
MINERU_RUNTIME_EXTRAS = ("pipeline", "vlm")
MINERU_LICENSE_ID = "LicenseRef-MinerU-Open-Source-License"
UNKNOWN_LICENSE_VALUES = {
    "",
    "noassertion",
    "none",
    "unknown",
    "n/a",
    "not specified",
}
OFFICIAL_SOURCE_HOSTS = {
    "download-r2.pytorch.org",
    "download.pytorch.org",
    "pypi.org",
    "files.pythonhosted.org",
    "python.org",
    "www.python.org",
    "huggingface.co",
    "github.com",
    "raw.githubusercontent.com",
}
PYTORCH_WHEEL_ARTIFACTS = {
    ("torch", "2.8.0+cu128"): {
        "fileName": "torch-2.8.0+cu128-cp312-cp312-win_amd64.whl",
        "sourceUrl": "https://download-r2.pytorch.org/whl/cu128/torch-2.8.0%2Bcu128-cp312-cp312-win_amd64.whl",
        "sha256": "0ad925202387f4e7314302a1b4f8860fa824357f9b1466d7992bf276370ebcff",
    },
    ("torchvision", "0.23.0+cu128"): {
        "fileName": "torchvision-0.23.0+cu128-cp312-cp312-win_amd64.whl",
        "sourceUrl": "https://download-r2.pytorch.org/whl/cu128/torchvision-0.23.0%2Bcu128-cp312-cp312-win_amd64.whl",
        "sha256": "20fa9c7362a006776630b00b8a01919fedcf504a202b81358d32c5aef39956fe",
    },
}
REQUIRED_DISTRIBUTIONS = {
    "mineru": "3.4.3",
    "torch": "2.8.0+cu128",
    "pypdfium2": "5.10.1",
    "pillow": "12.2.0",
    "loguru": "0.7.3",
}
MAX_FILES = 150_000
MAX_BYTES = 64 * 1024 * 1024 * 1024
MAX_RELATIVE_PATH = 240
BUFFER_BYTES = 1024 * 1024
UNSAFE_FILE_ATTRIBUTES = 0x00000400 | 0x00001000 | 0x00040000 | 0x00400000
WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
SUPPORT_TOP_LEVEL = {"worker", "python", "runtime"}
CRITICAL_SUPPORT_PATHS = (
    "worker/lawyer_assistance_mineru_worker/__init__.py",
    "worker/lawyer_assistance_mineru_worker/main.py",
    "worker/lawyer_assistance_mineru_worker/output_document.py",
    "worker/lawyer_assistance_mineru_worker/protocol.py",
    "worker/lawyer_assistance_mineru_worker/runtime.py",
    "worker/lawyer_assistance_mineru_worker/single_process.py",
    "worker/lawyer_assistance_mineru_worker/support_manifest.py",
    "worker/mineru-worker._pth",
    "worker/python312._pth",
    "worker/python312.dll",
    "worker/sitecustomize.py",
    "python/Lib/os.py",
    "python/Lib/site.py",
    "runtime/site-packages/mineru/__init__.py",
    "runtime/site-packages/pypdfium2/__init__.py",
    "runtime/site-packages/torch/__init__.py",
)
PIPELINE_REQUIRED = (
    "models/Layout/PP-DocLayoutV2/model.safetensors",
    "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_det_infer.safetensors",
    "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_rec_infer.safetensors",
)
VLM_REQUIRED = ("config.json", "model.safetensors", "tokenizer.json")
QUALIFIED_MODELS = {
    "pipeline": {
        "name": "opendatalab/PDF-Extract-Kit-1.0",
        "revision": "ed6b654c018d742e65a17671e379c5e6ecc87ec9",
        "license": "AGPL-3.0",
        "license_evidence_sha256": "96da5ddde73c3f578b9eab235ac59cbb5f512755090779a14461863767b70f34",
        "files": (
            "models/Layout/PP-DocLayoutV2/config.json",
            "models/Layout/PP-DocLayoutV2/model.safetensors",
            "models/Layout/PP-DocLayoutV2/preprocessor_config.json",
            "models/MFR/unimernet_hf_small_2503/README.md",
            "models/MFR/unimernet_hf_small_2503/config.json",
            "models/MFR/unimernet_hf_small_2503/generation_config.json",
            "models/MFR/unimernet_hf_small_2503/model.safetensors",
            "models/MFR/unimernet_hf_small_2503/special_tokens_map.json",
            "models/MFR/unimernet_hf_small_2503/tokenizer.json",
            "models/MFR/unimernet_hf_small_2503/tokenizer_config.json",
            "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_det_infer.safetensors",
            "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_rec_infer.safetensors",
            "models/TabCls/paddle_table_cls/PP-LCNet_x1_0_table_cls.onnx",
            "models/TabRec/SlanetPlus/slanet-plus.onnx",
            "models/TabRec/UnetStructure/unet.onnx",
        ),
    },
    "vlm": {
        "name": "opendatalab/MinerU2.5-Pro-2605-1.2B",
        "revision": "bff20d4ae2bf202df9f45284b4d43681555a97ed",
        "license": "Apache-2.0",
        "license_evidence_sha256": "8f829b69be518375b02023f795b3898adec98f5ac37208239884ad88e9a21cb7",
        "files": (
            "added_tokens.json",
            "chat_template.jinja",
            "config.json",
            "generation_config.json",
            "merges.txt",
            "model.safetensors",
            "preprocessor_config.json",
            "special_tokens_map.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "vocab.json",
        ),
    },
}


class BuildFailure(RuntimeError):
    """Stable, non-sensitive build failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class ExcludedExecutable:
    source_scope: str
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class RuntimeIdentity:
    python_version: str
    architecture: str
    distributions: tuple[tuple[str, str], ...]

    def version(self, name: str) -> str:
        normalized = canonical_distribution_name(name)
        values = dict(self.distributions)
        if normalized not in values:
            raise BuildFailure("required_distribution_missing")
        return values[normalized]


@dataclass(frozen=True)
class SelectedDistribution:
    name: str
    version: str
    extras: tuple[str, ...]
    distribution: importlib.metadata.Distribution


@dataclass(frozen=True)
class DistributionMeasurement:
    name: str
    version: str
    source_urls: tuple[str, ...]
    license_declaration: str
    license_evidence_kind: str
    files: tuple[FileRecord, ...]
    license_files: tuple[FileRecord, ...]
    installation_record: FileRecord
    upstream_artifact: Mapping[str, str] | None
    content_sha256: str


@dataclass(frozen=True)
class RepositorySourceBinding:
    repository_commit: str
    build_script_sha256: str
    worker_source_tree_sha256: str
    worker_stage_files: tuple[FileRecord, ...]
    repository_license: FileRecord


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=0) as stream:
        while chunk := stream.read(BUFFER_BYTES):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def file_attributes(metadata: os.stat_result) -> int:
    return int(getattr(metadata, "st_file_attributes", 0))


def validate_metadata(metadata: os.stat_result, *, directory: bool) -> None:
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected or file_attributes(metadata) & UNSAFE_FILE_ATTRIBUTES:
        raise BuildFailure("filesystem_rejected")


def validate_local_path(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    if not absolute.exists():
        raise BuildFailure("source_missing")
    if os.name == "nt":
        drive = absolute.drive
        if not drive or ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") != 3:
            raise BuildFailure("filesystem_not_fixed_local")
    current = absolute
    while current.parent != current:
        validate_metadata(current.lstat(), directory=current.is_dir())
        current = current.parent
    validate_metadata(absolute.lstat(), directory=directory)
    return absolute.resolve(strict=True)


def ensure_output(path: Path) -> Path:
    output = Path(os.path.abspath(path))
    if output.exists():
        raise BuildFailure("output_exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    validate_local_path(output.parent, directory=True)
    return output


def validate_relative_path(value: str, allowed_top: set[str]) -> str:
    if not value or "\\" in value or value.startswith("/") or value.endswith("/"):
        raise BuildFailure("relative_path_invalid")
    path = PurePosixPath(value)
    if str(path) != value or len(value) > MAX_RELATIVE_PATH or len(path.parts) > 32:
        raise BuildFailure("relative_path_invalid")
    if not path.parts or path.parts[0] not in allowed_top:
        raise BuildFailure("relative_path_invalid")
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if (
            part in {"", ".", ".."}
            or part.endswith((".", " "))
            or ":" in part
            or stem in WINDOWS_RESERVED_STEMS
            or any(ord(character) < 32 for character in part)
        ):
            raise BuildFailure("relative_path_invalid")
    return value


def canonical_distribution_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if not normalized or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", normalized):
        raise BuildFailure("distribution_name_invalid")
    return normalized


def _distribution_inventory(site_packages: Path) -> tuple[tuple[str, str], ...]:
    observed: dict[str, str] = {}
    for distribution in importlib.metadata.distributions(path=[str(site_packages)]):
        name = distribution.metadata.get("Name")
        if not isinstance(name, str):
            raise BuildFailure("distribution_metadata_invalid")
        normalized = canonical_distribution_name(name)
        version = distribution.version
        if not version or len(version) > 128 or any(ord(char) < 32 for char in version):
            raise BuildFailure("distribution_metadata_invalid")
        if normalized in observed and observed[normalized] != version:
            raise BuildFailure("distribution_duplicate")
        observed[normalized] = version
    return tuple(sorted(observed.items()))


def _distribution_map(site_packages: Path) -> dict[str, importlib.metadata.Distribution]:
    observed: dict[str, importlib.metadata.Distribution] = {}
    for distribution in importlib.metadata.distributions(path=[str(site_packages)]):
        raw_name = distribution.metadata.get("Name")
        if not isinstance(raw_name, str):
            raise BuildFailure("distribution_metadata_invalid")
        name = canonical_distribution_name(raw_name)
        previous = observed.get(name)
        if previous is not None and previous.version != distribution.version:
            raise BuildFailure("distribution_duplicate")
        observed[name] = distribution
    return observed


def resolve_runtime_distributions(site_packages: Path) -> tuple[SelectedDistribution, ...]:
    """Resolve the declared MinerU PDF pipeline+VLM dependency closure.

    This deliberately does not copy every distribution that happens to share a
    Conda/virtualenv.  Optional Gradio, S3, LMDeploy, test and unrelated tools
    are excluded unless they are transitively required by the two approved
    runtime extras.
    """
    if Requirement is None or default_environment is None or packaging_canonicalize_name is None:
        raise BuildFailure("dependency_parser_unavailable")
    distributions = _distribution_map(site_packages)
    root = canonical_distribution_name("mineru")
    if root not in distributions:
        raise BuildFailure("required_distribution_missing")
    selected: dict[str, set[str]] = {root: set(MINERU_RUNTIME_EXTRAS)}
    pending = [root]
    environment = default_environment()
    environment.update(
        {
            "implementation_name": "cpython",
            "os_name": "nt",
            "platform_machine": "AMD64",
            "platform_system": "Windows",
            "python_full_version": CPYTHON_VERSION,
            "python_version": ".".join(CPYTHON_VERSION.split(".")[:2]),
            "sys_platform": "win32",
        }
    )
    while pending:
        name = pending.pop(0)
        distribution = distributions[name]
        for raw_requirement in distribution.requires or ():
            try:
                requirement = Requirement(raw_requirement)
            except InvalidRequirement as error:
                raise BuildFailure("distribution_requirement_invalid") from error
            applies = any(
                requirement.marker is None
                or requirement.marker.evaluate({**environment, "extra": extra})
                for extra in {*selected[name], ""}
            )
            if not applies:
                continue
            dependency = canonical_distribution_name(requirement.name)
            installed = distributions.get(dependency)
            if installed is None:
                raise BuildFailure("runtime_dependency_missing")
            if requirement.specifier and not requirement.specifier.contains(
                installed.version, prereleases=True
            ):
                raise BuildFailure("runtime_dependency_version_invalid")
            requested_extras = {
                canonical_distribution_name(extra) for extra in requirement.extras
            }
            if dependency not in selected:
                selected[dependency] = requested_extras
                pending.append(dependency)
            elif not requested_extras.issubset(selected[dependency]):
                selected[dependency].update(requested_extras)
                pending.append(dependency)
    return tuple(
        SelectedDistribution(
            name=name,
            version=distributions[name].version,
            extras=tuple(sorted(extras)),
            distribution=distributions[name],
        )
        for name, extras in sorted(selected.items())
    )


def _official_source_urls(
    name: str, version: str, metadata: email.message.Message
) -> tuple[str, ...]:
    pypi_release = f"https://pypi.org/project/{name}/{version}/"
    values: set[str] = {pypi_release}
    for raw in metadata.get_all("Project-URL", []) or []:
        if "," in raw:
            _label, raw = raw.split(",", 1)
        values.add(raw.strip())
    home = metadata.get("Home-page")
    if isinstance(home, str):
        values.add(home.strip())
    accepted: list[str] = []
    for value in sorted(values):
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme == "https"
            and host in OFFICIAL_SOURCE_HOSTS
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
        ):
            accepted.append(value)
    if not accepted:
        raise BuildFailure("distribution_source_missing")
    return (pypi_release, *(value for value in accepted if value != pypi_release))


def _declared_license(metadata: email.message.Message) -> tuple[str, str]:
    expression = metadata.get("License-Expression")
    if isinstance(expression, str) and expression.strip().casefold() not in UNKNOWN_LICENSE_VALUES:
        return " ".join(expression.split())[:4096], "metadata-license-expression"
    value = metadata.get("License")
    if isinstance(value, str) and value.strip().casefold() not in UNKNOWN_LICENSE_VALUES:
        return " ".join(value.split())[:4096], "metadata-license"
    classifiers = sorted(
        item.removeprefix("License :: ").strip()
        for item in metadata.get_all("Classifier", []) or []
        if item.startswith("License :: ") and item.removeprefix("License :: ").strip()
    )
    if classifiers:
        return "; ".join(classifiers)[:4096], "metadata-license-classifier"
    raise BuildFailure("distribution_license_missing")


def _distribution_source_files(
    site_packages: Path, selected: SelectedDistribution
) -> tuple[tuple[str, Path], ...]:
    site_packages = validate_local_path(site_packages, directory=True)
    files = selected.distribution.files
    if not files:
        raise BuildFailure("distribution_files_missing")
    observed: dict[str, Path] = {}
    for entry in files:
        candidate = Path(selected.distribution.locate_file(entry))
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(site_packages).as_posix()
        except (OSError, ValueError):
            # Console entry points and installers outside site-packages are not
            # part of the embedded runtime.  They are neither copied nor
            # represented as provenance for the embedded distribution.
            continue
        if not resolved.is_file() or _skip_runtime_file(relative) is not None:
            continue
        validate_relative_path(f"runtime/site-packages/{relative}", {"runtime"})
        previous = observed.get(relative.casefold())
        if previous is not None and previous != resolved:
            raise BuildFailure("distribution_file_collision")
        observed[relative.casefold()] = resolved
    if not observed:
        raise BuildFailure("distribution_files_missing")
    return tuple(
        sorted(
            ((path.relative_to(site_packages).as_posix(), path) for path in observed.values()),
            key=lambda item: item[0],
        )
    )


def _records_hash(domain: str, records: Sequence[FileRecord]) -> str:
    canonical = bytearray(f"{domain}\n".encode("ascii"))
    for record in sorted(records, key=lambda item: item.relative_path):
        canonical.extend(record.relative_path.encode("utf-8"))
        canonical.extend(b"\n")
        canonical.extend(str(record.size_bytes).encode("ascii"))
        canonical.extend(b"\n")
        canonical.extend(record.sha256.encode("ascii"))
        canonical.extend(b"\n")
    return sha256_bytes(bytes(canonical))


def _distribution_installation_record(
    site_packages: Path, selected: SelectedDistribution
) -> FileRecord:
    candidates: list[tuple[str, Path]] = []
    for entry in selected.distribution.files or ():
        if PurePosixPath(str(entry).replace("\\", "/")).name != "RECORD":
            continue
        path = Path(selected.distribution.locate_file(entry)).resolve(strict=True)
        try:
            relative = path.relative_to(site_packages).as_posix()
        except ValueError:
            continue
        parts = PurePosixPath(relative).parts
        if (
            len(parts) != 2
            or not parts[0].casefold().endswith(".dist-info")
            or parts[1] != "RECORD"
        ):
            continue
        candidates.append((relative, path))
    if len(candidates) != 1:
        raise BuildFailure("distribution_installation_record_missing")
    relative, path = candidates[0]
    digest, size = sha256_file(path)
    return FileRecord(relative, size, digest)


def _verify_distribution_record(
    site_packages: Path, selected: SelectedDistribution
) -> None:
    """Verify every packaged, RECORD-declared file before trusting install evidence."""

    for entry in selected.distribution.files or ():
        path = Path(selected.distribution.locate_file(entry))
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(site_packages).as_posix()
        except (OSError, ValueError):
            # Wheel-created console scripts can live outside site-packages and
            # are deliberately excluded from the embedded component.
            continue
        if _skip_runtime_file(relative) is not None:
            continue
        if PurePosixPath(relative).name == "RECORD":
            continue
        declared_hash = getattr(entry, "hash", None)
        if declared_hash is None or declared_hash.mode != "sha256":
            raise BuildFailure("distribution_record_unverifiable")
        digest, size = sha256_file(resolved)
        encoded = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=").decode("ascii")
        if encoded != declared_hash.value:
            raise BuildFailure("distribution_record_changed")
        declared_size = getattr(entry, "size", None)
        if declared_size is not None and int(declared_size) != size:
            raise BuildFailure("distribution_record_changed")


def _upstream_artifact(selected: SelectedDistribution) -> Mapping[str, str] | None:
    key = (selected.name, selected.version)
    artifact = PYTORCH_WHEEL_ARTIFACTS.get(key)
    if selected.name in {"torch", "torchvision"} and artifact is None:
        raise BuildFailure("pytorch_artifact_unqualified")
    if artifact is None:
        return None
    _validate_official_url(artifact["sourceUrl"], "pytorch_artifact_unqualified")
    if (
        not artifact["fileName"].endswith("-cp312-cp312-win_amd64.whl")
        or not _valid_hash(artifact["sha256"])
    ):
        raise BuildFailure("pytorch_artifact_unqualified")
    return dict(artifact)


def measure_distribution(
    site_packages: Path, selected: SelectedDistribution
) -> DistributionMeasurement:
    site_packages = validate_local_path(site_packages, directory=True)
    _verify_distribution_record(site_packages, selected)
    files: list[FileRecord] = []
    licenses: list[FileRecord] = []
    for relative, path in _distribution_source_files(site_packages, selected):
        digest, size = sha256_file(path)
        record = FileRecord(relative, size, digest)
        files.append(record)
        basename = PurePosixPath(relative).name.casefold()
        if basename.startswith(("license", "licence", "copying", "notice", "copyright")) or (
            "/licenses/" in f"/{relative.casefold()}"
        ):
            licenses.append(record)
    declaration, evidence_kind = _declared_license(selected.distribution.metadata)
    if selected.name == "mineru" and (
        declaration != MINERU_LICENSE_ID
        or not any(
            PurePosixPath(record.relative_path).name.casefold() == "license.md"
            for record in licenses
        )
    ):
        raise BuildFailure("mineru_license_unqualified")
    return DistributionMeasurement(
        name=selected.name,
        version=selected.version,
        source_urls=_official_source_urls(
            selected.name, selected.version, selected.distribution.metadata
        ),
        license_declaration=declaration,
        license_evidence_kind=evidence_kind,
        files=tuple(files),
        license_files=tuple(licenses),
        installation_record=_distribution_installation_record(site_packages, selected),
        upstream_artifact=_upstream_artifact(selected),
        content_sha256=_records_hash("la-mineru-distribution-content-v1", files),
    )


def probe_runtime_identity(python_home: Path, site_packages: Path) -> RuntimeIdentity:
    python_home = validate_local_path(python_home, directory=True)
    site_packages = validate_local_path(site_packages, directory=True)
    executable = validate_local_path(python_home / "python.exe", directory=False)
    environment = {
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
        "PATH": str(python_home),
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "socks5://127.0.0.1:9",
    }
    try:
        result = subprocess.run(
            [
                str(executable),
                "-I",
                "-S",
                "-c",
                "import json,platform,sys;print(json.dumps({'python':platform.python_version(),'machine':platform.machine(),'maxsize':sys.maxsize},separators=(',',':')))"
            ],
            check=True,
            capture_output=True,
            env=environment,
            timeout=30,
        )
        value = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError) as error:
        raise BuildFailure("python_probe_failed") from error
    if (
        value != {
            "python": CPYTHON_VERSION,
            "machine": "AMD64",
            "maxsize": 9223372036854775807,
        }
        and value != {
            "python": CPYTHON_VERSION,
            "machine": "x86_64",
            "maxsize": 9223372036854775807,
        }
    ):
        raise BuildFailure("python_version_unqualified")
    identity = RuntimeIdentity(
        python_version=value["python"],
        architecture="windows-x86_64",
        distributions=_distribution_inventory(site_packages),
    )
    for name, expected in REQUIRED_DISTRIBUTIONS.items():
        if identity.version(name) != expected:
            raise BuildFailure("runtime_version_unqualified")
    return identity


def _source_files(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    root = validate_local_path(root, directory=True)

    def visit(directory: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError as error:
            raise BuildFailure("source_enumeration_failed") from error
        for entry in entries:
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if entry.is_dir(follow_symlinks=False):
                validate_metadata(metadata, directory=True)
                yield from visit(path)
            elif entry.is_file(follow_symlinks=False):
                validate_metadata(metadata, directory=False)
                yield path.relative_to(root).as_posix(), path, metadata
            else:
                raise BuildFailure("filesystem_rejected")

    yield from visit(root)


def inventory_tree(root: Path, *, prefix: str = "") -> tuple[FileRecord, ...]:
    records = []
    folded: set[str] = set()
    total = 0
    for relative, path, metadata in _source_files(root):
        logical = f"{prefix}/{relative}" if prefix else relative
        logical = logical.replace("\\", "/")
        if logical.casefold() in folded:
            raise BuildFailure("casefold_collision")
        folded.add(logical.casefold())
        digest, size = sha256_file(path)
        if size != metadata.st_size:
            raise BuildFailure("source_changed")
        total += size
        if len(records) >= MAX_FILES or total > MAX_BYTES:
            raise BuildFailure("source_limit_exceeded")
        records.append(FileRecord(logical, size, digest))
    records.sort(key=lambda item: item.relative_path)
    return tuple(records)


def model_manifest(model_root: Path) -> dict[str, object]:
    records = inventory_tree(model_root)
    if not records:
        raise BuildFailure("model_tree_empty")
    return {
        "version": MODEL_MANIFEST_VERSION,
        "files": [
            {
                "relativePath": item.relative_path,
                "sha256": item.sha256,
                "sizeBytes": item.size_bytes,
            }
            for item in records
        ],
    }


def validate_models(pipeline_model: Path, vlm_model: Path) -> tuple[Path, Path]:
    pipeline = validate_local_path(pipeline_model, directory=True)
    vlm = validate_local_path(vlm_model, directory=True)
    if pipeline == vlm or pipeline in vlm.parents or vlm in pipeline.parents:
        raise BuildFailure("model_roots_overlap")
    for relative in PIPELINE_REQUIRED:
        validate_local_path(pipeline / Path(relative), directory=False)
    for relative in VLM_REQUIRED:
        validate_local_path(vlm / relative, directory=False)
    return pipeline, vlm


def common_model_root(pipeline: Path, vlm: Path) -> Path:
    left = pipeline.parts
    right = vlm.parts
    count = 0
    for a, b in zip(left, right):
        if a.casefold() != b.casefold():
            break
        count += 1
    if count <= 1:
        raise BuildFailure("model_common_root_invalid")
    return validate_local_path(Path(*left[:count]), directory=True)


def _strict_json(path: Path, invalid_code: str) -> tuple[dict[str, object], bytes]:
    path = validate_local_path(path, directory=False)
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw,
            object_pairs_hook=lambda pairs: _strict_json_object(pairs),
            parse_constant=lambda _value: (_ for _ in ()).throw(BuildFailure(invalid_code)),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BuildFailure(invalid_code) from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise BuildFailure(invalid_code)
    return value, raw


def _require_fields(value: object, fields: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BuildFailure(code)
    return value


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_official_url(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise BuildFailure(code)
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() not in OFFICIAL_SOURCE_HOSTS
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise BuildFailure(code)
    return value


def _git_environment() -> dict[str, str]:
    return {
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git_output(root: Path, arguments: Sequence[str]) -> bytes:
    environment = {
        **_git_environment(),
    }
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            timeout=30,
            env=environment,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise BuildFailure("repository_identity_failed") from error


def _repository_identity(repository_root: Path) -> tuple[Path, str]:
    root = validate_local_path(repository_root, directory=True)
    try:
        top = Path(
            os.fsdecode(_git_output(root, ("rev-parse", "--show-toplevel"))).strip()
        ).resolve(strict=True)
        commit = _git_output(root, ("rev-parse", "HEAD")).decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise BuildFailure("repository_identity_invalid") from error
    if top != root or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise BuildFailure("repository_identity_invalid")
    dirty = _git_output(
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    if dirty:
        raise BuildFailure("repository_not_clean")
    return root, commit


def _head_tree(root: Path, pathspec: str) -> dict[str, tuple[str, str]]:
    raw = _git_output(
        root,
        ("ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", pathspec),
    )
    entries: dict[str, tuple[str, str]] = {}
    try:
        records = raw.split(b"\0")
        for record in records:
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            if (
                kind != "blob"
                or mode not in {"100644", "100755"}
                or not re.fullmatch(r"[0-9a-f]{40,64}", object_id)
                or path in entries
            ):
                raise ValueError("invalid tree entry")
            entries[path] = (mode, object_id)
    except (UnicodeError, ValueError) as error:
        raise BuildFailure("repository_source_tree_invalid") from error
    return entries


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _head_file_record(
    root: Path,
    tree: Mapping[str, tuple[str, str]],
    repository_path: str,
    worktree_path: Path,
    logical_path: str,
) -> FileRecord:
    entry = tree.get(repository_path)
    if entry is None:
        raise BuildFailure("repository_source_not_tracked")
    resolved = validate_local_path(worktree_path, directory=False)
    try:
        head_bytes = _git_output(root, ("cat-file", "blob", entry[1]))
        worktree_bytes = resolved.read_bytes()
    except OSError as error:
        raise BuildFailure("repository_source_read_failed") from error
    if worktree_bytes != head_bytes:
        raise BuildFailure("repository_source_bytes_changed")
    return FileRecord(logical_path, len(head_bytes), sha256_bytes(head_bytes))


def _repository_source_binding(
    repository_root: Path,
    worker_source: Path,
    repository_license: Path,
) -> RepositorySourceBinding:
    root, commit = _repository_identity(repository_root)
    expected_worker = validate_local_path(root / "workers" / "mineru", directory=True)
    expected_builder = validate_local_path(
        root / "scripts" / "build_production_mineru_worker.py", directory=False
    )
    expected_license = validate_local_path(root / "LICENSE", directory=False)
    actual_worker = validate_local_path(worker_source, directory=True)
    actual_builder = validate_local_path(Path(__file__), directory=False)
    actual_license = validate_local_path(repository_license, directory=False)
    if (
        not _same_path(actual_worker, expected_worker)
        or not _same_path(actual_builder, expected_builder)
        or not _same_path(actual_license, expected_license)
    ):
        raise BuildFailure("repository_source_path_invalid")

    worker_tree = _head_tree(root, "workers/mineru")
    actual_worker_files: dict[str, Path] = {}
    for relative, path, _metadata in _source_files(actual_worker):
        repository_path = f"workers/mineru/{relative}"
        if repository_path in actual_worker_files:
            raise BuildFailure("repository_source_inventory_changed")
        actual_worker_files[repository_path] = path
    if set(actual_worker_files) != set(worker_tree):
        raise BuildFailure("repository_source_inventory_changed")

    stage_files: list[FileRecord] = []
    launcher_path = "workers/mineru/launcher/sitecustomize.py"
    if launcher_path not in actual_worker_files:
        raise BuildFailure("repository_source_inventory_changed")
    stage_files.append(
        _head_file_record(
            root,
            worker_tree,
            launcher_path,
            actual_worker_files[launcher_path],
            "worker/sitecustomize.py",
        )
    )
    package_prefix = "workers/mineru/lawyer_assistance_mineru_worker/"
    for repository_path in sorted(actual_worker_files):
        if not repository_path.startswith(package_prefix):
            continue
        relative = repository_path.removeprefix(package_prefix)
        if _skip_runtime_file(relative) is not None:
            continue
        stage_files.append(
            _head_file_record(
                root,
                worker_tree,
                repository_path,
                actual_worker_files[repository_path],
                f"worker/lawyer_assistance_mineru_worker/{relative}",
            )
        )
    stage_files.sort(key=lambda item: item.relative_path)

    builder_tree = _head_tree(root, "scripts/build_production_mineru_worker.py")
    builder_record = _head_file_record(
        root,
        builder_tree,
        "scripts/build_production_mineru_worker.py",
        actual_builder,
        "scripts/build_production_mineru_worker.py",
    )
    license_tree = _head_tree(root, "LICENSE")
    license_record = _head_file_record(
        root,
        license_tree,
        "LICENSE",
        actual_license,
        "licenses/lawyer-assistance/LICENSE.txt",
    )
    return RepositorySourceBinding(
        repository_commit=commit,
        build_script_sha256=builder_record.sha256,
        worker_source_tree_sha256=_records_hash(
            "la-mineru-worker-source-v1", stage_files
        ),
        worker_stage_files=tuple(stage_files),
        repository_license=license_record,
    )


def _logical_source_records(
    source: Path, destination_prefix: str, *, skip_base_site_packages: bool = False
) -> tuple[FileRecord, ...]:
    records: list[FileRecord] = []
    for relative, path, _metadata in _source_files(source):
        parts = PurePosixPath(relative).parts
        if skip_base_site_packages and parts and parts[0] == "site-packages":
            continue
        if _skip_runtime_file(relative) is not None:
            continue
        digest, size = sha256_file(path)
        if size == 0:
            digest = sha256_bytes(b"\n")
            size = 1
        records.append(FileRecord(f"{destination_prefix}/{relative}", size, digest))
    return tuple(records)


def measure_cpython(python_home: Path) -> tuple[str, tuple[FileRecord, ...]]:
    records: list[FileRecord] = []
    for name in (
        "python.exe",
        "python3.dll",
        "python312.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
    ):
        path = validate_local_path(python_home / name, directory=False)
        digest, size = sha256_file(path)
        records.append(FileRecord(f"worker/{'mineru-worker.exe' if name == 'python.exe' else name}", size, digest))
    records.extend(
        _logical_source_records(
            validate_local_path(python_home / "Lib", directory=True),
            "python/Lib",
            skip_base_site_packages=True,
        )
    )
    records.extend(
        _logical_source_records(
            validate_local_path(python_home / "DLLs", directory=True), "python/DLLs"
        )
    )
    license_path = validate_local_path(python_home / "LICENSE.txt", directory=False)
    digest, size = sha256_file(license_path)
    records.append(FileRecord("licenses/cpython/LICENSE.txt", size, digest))
    records.sort(key=lambda item: item.relative_path)
    return _records_hash("la-mineru-cpython-content-v1", records), tuple(records)


def measure_worker_source(worker_source: Path) -> str:
    records: list[FileRecord] = []
    launcher = validate_local_path(worker_source / "launcher" / "sitecustomize.py", directory=False)
    digest, size = sha256_file(launcher)
    records.append(FileRecord("worker/sitecustomize.py", size, digest))
    records.extend(
        _logical_source_records(
            validate_local_path(
                worker_source / "lawyer_assistance_mineru_worker", directory=True
            ),
            "worker/lawyer_assistance_mineru_worker",
        )
    )
    return _records_hash("la-mineru-worker-source-v1", records)


def _file_records_json(records: Sequence[FileRecord]) -> list[dict[str, object]]:
    return [
        {
            "relativePath": record.relative_path,
            "sizeBytes": record.size_bytes,
            "sha256": record.sha256,
        }
        for record in sorted(records, key=lambda item: item.relative_path)
    ]


def _model_observation(root: Path) -> tuple[FileRecord, ...]:
    return inventory_tree(root)


def _validate_model_provenance(
    values: object,
    pipeline_records: Sequence[FileRecord],
    vlm_records: Sequence[FileRecord],
) -> list[dict[str, object]]:
    if not isinstance(values, list) or len(values) != 2:
        raise BuildFailure("model_provenance_invalid")
    expected_records = {"pipeline": pipeline_records, "vlm": vlm_records}
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in values:
        value = _require_fields(
            raw,
            {
                "root",
                "name",
                "revision",
                "sourceUrl",
                "license",
                "licenseEvidenceUrl",
                "licenseEvidenceSha256",
                "files",
            },
            "model_provenance_invalid",
        )
        root = value["root"]
        if root not in expected_records or root in seen:
            raise BuildFailure("model_provenance_invalid")
        seen.add(str(root))
        qualified = QUALIFIED_MODELS[str(root)]
        expected_source = (
            f"https://huggingface.co/{qualified['name']}/tree/{qualified['revision']}"
        )
        expected_evidence = (
            f"https://huggingface.co/{qualified['name']}/blob/{qualified['revision']}/README.md"
        )
        if (
            value["name"] != qualified["name"]
            or value["revision"] != qualified["revision"]
            or value["license"] != qualified["license"]
            or value["sourceUrl"] != expected_source
            or value["licenseEvidenceUrl"] != expected_evidence
            or value["licenseEvidenceSha256"]
            != qualified["license_evidence_sha256"]
        ):
            raise BuildFailure("model_provenance_invalid")
        source = _validate_official_url(value["sourceUrl"], "model_provenance_invalid")
        evidence = _validate_official_url(
            value["licenseEvidenceUrl"], "model_provenance_invalid"
        )
        if value["revision"] not in source or value["revision"] not in evidence:
            raise BuildFailure("model_provenance_revision_unbound")
        files = value["files"]
        if not isinstance(files, list) or not files:
            raise BuildFailure("model_provenance_files_changed")
        observed = {
            item.relative_path: item for item in expected_records[str(root)]
        }
        selected_paths: list[str] = []
        previous: str | None = None
        for raw_file in files:
            file_value = _require_fields(
                raw_file,
                {"relativePath", "sizeBytes", "sha256"},
                "model_provenance_files_changed",
            )
            relative = file_value["relativePath"]
            if not isinstance(relative, str) or previous is not None and previous >= relative:
                raise BuildFailure("model_provenance_files_changed")
            previous = relative
            expected = observed.get(relative)
            if expected is None or file_value != {
                "relativePath": expected.relative_path,
                "sizeBytes": expected.size_bytes,
                "sha256": expected.sha256,
            }:
                raise BuildFailure("model_provenance_files_changed")
            selected_paths.append(relative)
        required = PIPELINE_REQUIRED if root == "pipeline" else VLM_REQUIRED
        if not set(required).issubset(selected_paths):
            raise BuildFailure("model_provenance_required_file_missing")
        if selected_paths != list(qualified["files"]):
            raise BuildFailure("model_provenance_files_changed")
        result.append(dict(value))
    if seen != set(expected_records):
        raise BuildFailure("model_provenance_invalid")
    return sorted(result, key=lambda item: str(item["root"]))


def validate_provenance_input(
    *,
    provenance_input: Path,
    repository_root: Path,
    repository_license: Path,
    python_home: Path,
    worker_source: Path,
    distributions: Sequence[DistributionMeasurement],
    pipeline_records: Sequence[FileRecord],
    vlm_records: Sequence[FileRecord],
    source_binding: RepositorySourceBinding | None = None,
) -> dict[str, object]:
    value, raw = _strict_json(provenance_input, "provenance_input_invalid")
    _require_fields(
        value,
        {
            "schemaVersion",
            "provenanceVersion",
            "approval",
            "source",
            "cpython",
            "runtimeProfile",
            "distributions",
            "models",
        },
        "provenance_input_invalid",
    )
    if (
        value["schemaVersion"] != PROVENANCE_SCHEMA_VERSION
        or value["provenanceVersion"] != PROVENANCE_INPUT_VERSION
    ):
        raise BuildFailure("provenance_input_invalid")
    approval = _require_fields(
        value["approval"],
        {"approvedForRedistribution", "reviewer", "reviewedAtUnix"},
        "provenance_approval_invalid",
    )
    if (
        approval["approvedForRedistribution"] is not True
        or not isinstance(approval["reviewer"], str)
        or not approval["reviewer"].strip()
        or len(approval["reviewer"]) > 128
        or not isinstance(approval["reviewedAtUnix"], int)
        or isinstance(approval["reviewedAtUnix"], bool)
        or approval["reviewedAtUnix"] <= 0
    ):
        raise BuildFailure("provenance_approval_invalid")
    binding = source_binding or _repository_source_binding(
        repository_root, worker_source, repository_license
    )
    source = _require_fields(
        value["source"],
        {"repositoryCommit", "buildScriptSha256", "workerSourceTreeSha256"},
        "provenance_source_invalid",
    )
    if source != {
        "repositoryCommit": binding.repository_commit,
        "buildScriptSha256": binding.build_script_sha256,
        "workerSourceTreeSha256": binding.worker_source_tree_sha256,
    }:
        raise BuildFailure("provenance_source_changed")
    cpython_hash, cpython_records = measure_cpython(python_home)
    cpython = _require_fields(
        value["cpython"],
        {
            "version",
            "sourceUrl",
            "contentSha256",
            "license",
            "licenseFileSha256",
        },
        "cpython_provenance_invalid",
    )
    _validate_official_url(cpython["sourceUrl"], "cpython_provenance_invalid")
    cpython_license_hash = next(
        record.sha256
        for record in cpython_records
        if record.relative_path == "licenses/cpython/LICENSE.txt"
    )
    if (
        cpython["version"] != CPYTHON_VERSION
        or cpython["contentSha256"] != cpython_hash
        or cpython["licenseFileSha256"] != cpython_license_hash
        or not isinstance(cpython["license"], str)
        or cpython["license"].strip().casefold() in UNKNOWN_LICENSE_VALUES
    ):
        raise BuildFailure("cpython_provenance_changed")
    profile = _require_fields(
        value["runtimeProfile"],
        {"platform", "rootDistribution", "extras"},
        "runtime_profile_invalid",
    )
    if profile != {
        "platform": "windows-x86_64",
        "rootDistribution": f"mineru=={REQUIRED_DISTRIBUTIONS['mineru']}",
        "extras": list(MINERU_RUNTIME_EXTRAS),
    }:
        raise BuildFailure("runtime_profile_invalid")
    expected_distributions = [
        {
            "name": item.name,
            "version": item.version,
            "contentSha256": item.content_sha256,
            "sourceUrl": item.source_urls[0],
            "license": item.license_declaration,
            "licenseEvidenceKind": item.license_evidence_kind,
            "licenseFiles": _file_records_json(item.license_files),
            "installationRecord": _file_records_json((item.installation_record,))[0],
            "upstreamArtifact": dict(item.upstream_artifact)
            if item.upstream_artifact is not None
            else None,
        }
        for item in distributions
    ]
    if value["distributions"] != expected_distributions:
        raise BuildFailure("distribution_provenance_changed")
    models = _validate_model_provenance(
        value["models"], pipeline_records, vlm_records
    )
    return {
        "schemaVersion": PROVENANCE_SCHEMA_VERSION,
        "provenanceVersion": PROVENANCE_OUTPUT_VERSION,
        "provenanceInputSha256": sha256_bytes(raw),
        "approval": approval,
        "source": source,
        "cpython": cpython,
        "runtimeProfile": profile,
        "distributions": expected_distributions,
        "models": models,
    }


def write_provenance_draft(
    *,
    python_home: Path,
    site_packages: Path,
    pipeline_model: Path,
    vlm_model: Path,
    worker_source: Path,
    repository_root: Path,
    cpython_source_url: str,
    cpython_license: str,
    model_specs: Mapping[str, Mapping[str, str]],
    model_exclusions: Mapping[str, Sequence[str]],
    output: Path,
) -> dict[str, object]:
    python_home = validate_local_path(python_home, directory=True)
    site_packages = validate_local_path(site_packages, directory=True)
    worker_source = validate_local_path(worker_source, directory=True)
    pipeline, vlm = validate_models(pipeline_model, vlm_model)
    identity = probe_runtime_identity(python_home, site_packages)
    selected = resolve_runtime_distributions(site_packages)
    measurements = tuple(measure_distribution(site_packages, item) for item in selected)
    cpython_source_url = _validate_official_url(
        cpython_source_url, "cpython_provenance_invalid"
    )
    if cpython_license.strip().casefold() in UNKNOWN_LICENSE_VALUES:
        raise BuildFailure("cpython_provenance_invalid")
    cpython_hash, cpython_records = measure_cpython(python_home)
    source_binding = _repository_source_binding(
        repository_root, worker_source, Path(repository_root) / "LICENSE"
    )
    model_values: list[dict[str, object]] = []
    model_records = {
        "pipeline": _model_observation(pipeline),
        "vlm": _model_observation(vlm),
    }
    if set(model_specs) != set(model_records) or set(model_exclusions) != set(model_records):
        raise BuildFailure("model_provenance_invalid")
    for root, records in model_records.items():
        exclusions = tuple(model_exclusions.get(root, ()))
        if len(exclusions) != len(set(exclusions)):
            raise BuildFailure("model_provenance_invalid")
        observed_paths = {item.relative_path for item in records}
        if not set(exclusions).issubset(observed_paths):
            raise BuildFailure("model_provenance_invalid")
        approved_records = tuple(
            item for item in records if item.relative_path not in set(exclusions)
        )
        spec = model_specs[root]
        if set(spec) != {
            "name",
            "revision",
            "sourceUrl",
            "license",
            "licenseEvidenceUrl",
        }:
            raise BuildFailure("model_provenance_invalid")
        qualified = QUALIFIED_MODELS[root]
        model_values.append(
            {
                "root": root,
                **dict(spec),
                "licenseEvidenceSha256": qualified["license_evidence_sha256"],
                "files": _file_records_json(approved_records),
            }
        )
    model_values = _validate_model_provenance(
        model_values, model_records["pipeline"], model_records["vlm"]
    )
    value = {
        "schemaVersion": PROVENANCE_SCHEMA_VERSION,
        "provenanceVersion": PROVENANCE_INPUT_VERSION,
        "approval": {
            "approvedForRedistribution": False,
            "reviewer": "",
            "reviewedAtUnix": 0,
        },
        "source": {
            "repositoryCommit": source_binding.repository_commit,
            "buildScriptSha256": source_binding.build_script_sha256,
            "workerSourceTreeSha256": source_binding.worker_source_tree_sha256,
        },
        "cpython": {
            "version": CPYTHON_VERSION,
            "sourceUrl": cpython_source_url,
            "contentSha256": cpython_hash,
            "license": cpython_license,
            "licenseFileSha256": next(
                item.sha256
                for item in cpython_records
                if item.relative_path == "licenses/cpython/LICENSE.txt"
            ),
        },
        "runtimeProfile": {
            "platform": "windows-x86_64",
            "rootDistribution": f"mineru=={identity.version('mineru')}",
            "extras": list(MINERU_RUNTIME_EXTRAS),
        },
        "distributions": [
            {
                "name": item.name,
                "version": item.version,
                "contentSha256": item.content_sha256,
                "sourceUrl": item.source_urls[0],
                "license": item.license_declaration,
                "licenseEvidenceKind": item.license_evidence_kind,
                "licenseFiles": _file_records_json(item.license_files),
                "installationRecord": _file_records_json((item.installation_record,))[0],
                "upstreamArtifact": dict(item.upstream_artifact)
                if item.upstream_artifact is not None
                else None,
            }
            for item in measurements
        ],
        "models": model_values,
    }
    output = ensure_output(output)
    raw = canonical_json(value)
    with output.open("xb", buffering=0) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    selected_names = {item.name for item in selected}
    excluded = [
        {"name": name, "version": version}
        for name, version in identity.distributions
        if name not in selected_names
    ]
    return {
        "ok": True,
        "mode": "provenance-draft",
        "releaseReady": False,
        "reason": "explicit_redistribution_approval_required",
        "output": str(output),
        "sha256": sha256_bytes(raw),
        "selectedDistributionCount": len(selected),
        "excludedDistributionCount": len(excluded),
        "excludedDistributions": excluded,
        "metadataLicenseOnly": [
            item.name for item in measurements if not item.license_files
        ],
    }


def approve_provenance_draft(
    *, draft: Path, reviewer: str, reviewed_at: int, output: Path
) -> dict[str, object]:
    """Record explicit release-owner approval; stage still remeasures every input."""

    value, _raw = _strict_json(draft, "provenance_input_invalid")
    _require_fields(
        value,
        {
            "schemaVersion",
            "provenanceVersion",
            "approval",
            "source",
            "cpython",
            "runtimeProfile",
            "distributions",
            "models",
        },
        "provenance_input_invalid",
    )
    if (
        value["schemaVersion"] != PROVENANCE_SCHEMA_VERSION
        or value["provenanceVersion"] != PROVENANCE_INPUT_VERSION
    ):
        raise BuildFailure("provenance_input_invalid")
    approval = _require_fields(
        value["approval"],
        {"approvedForRedistribution", "reviewer", "reviewedAtUnix"},
        "provenance_approval_invalid",
    )
    if approval != {
        "approvedForRedistribution": False,
        "reviewer": "",
        "reviewedAtUnix": 0,
    }:
        raise BuildFailure("provenance_approval_state_invalid")
    if (
        not isinstance(reviewer, str)
        or reviewer != reviewer.strip()
        or not reviewer
        or len(reviewer) > 128
        or any(ord(char) < 32 for char in reviewer)
        or not isinstance(reviewed_at, int)
        or isinstance(reviewed_at, bool)
        or reviewed_at <= 0
    ):
        raise BuildFailure("provenance_approval_invalid")
    value["approval"] = {
        "approvedForRedistribution": True,
        "reviewer": reviewer,
        "reviewedAtUnix": reviewed_at,
    }
    output = ensure_output(output)
    raw = canonical_json(value)
    with output.open("xb", buffering=0) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "ok": True,
        "mode": "provenance-approve",
        "releaseReady": False,
        "reason": "clean_stage_remeasurement_and_external_signing_required",
        "output": str(output),
        "sha256": sha256_bytes(raw),
        "reviewer": reviewer,
        "reviewedAtUnix": reviewed_at,
    }


def _copy_verified(source: Path, destination: Path, *, materialize_empty: bool = True) -> FileRecord:
    metadata = source.stat(follow_symlinks=False)
    validate_metadata(metadata, directory=False)
    source_hash, source_size = sha256_file(source)
    if source_size != metadata.st_size:
        raise BuildFailure("source_changed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise BuildFailure("stage_collision")
    if source_size == 0:
        if not materialize_empty:
            raise BuildFailure("empty_file_rejected")
        destination.write_bytes(b"\n")
    else:
        with source.open("rb", buffering=0) as input_stream, destination.open("xb", buffering=0) as output:
            shutil.copyfileobj(input_stream, output, BUFFER_BYTES)
            output.flush()
            os.fsync(output.fileno())
    staged_hash, staged_size = sha256_file(destination)
    if source_size != 0 and (staged_hash != source_hash or staged_size != source_size):
        raise BuildFailure("copy_verify_failed")
    return FileRecord(destination.as_posix(), staged_size, staged_hash)


def _logical_copy(
    source: Path,
    stage: Path,
    relative: str,
    *,
    allowed_top: set[str],
) -> FileRecord:
    relative = validate_relative_path(relative, allowed_top)
    copied = _copy_verified(source, stage / PurePosixPath(relative))
    return FileRecord(relative, copied.size_bytes, copied.sha256)


def _verify_staged_repository_sources(
    stage: Path, binding: RepositorySourceBinding
) -> None:
    expected = (*binding.worker_stage_files, binding.repository_license)
    for record in expected:
        path = validate_local_path(stage / PurePosixPath(record.relative_path), directory=False)
        digest, size = sha256_file(path)
        if digest != record.sha256 or size != record.size_bytes:
            raise BuildFailure("repository_source_copy_changed")


def _excluded_executables(
    scopes: Sequence[tuple[str, Path]],
    *,
    exclude: Iterable[Path] = (),
) -> tuple[ExcludedExecutable, ...]:
    omitted = {path.resolve(strict=True) for path in exclude}
    records: list[ExcludedExecutable] = []
    for scope, root in scopes:
        for relative, path, metadata in _source_files(root):
            if path.suffix.casefold() != ".exe" or path.resolve(strict=True) in omitted:
                continue
            digest, size = sha256_file(path)
            if size != metadata.st_size:
                raise BuildFailure("source_changed")
            records.append(ExcludedExecutable(scope, relative, size, digest))
    records.sort(key=lambda item: (item.source_scope, item.relative_path.casefold(), item.relative_path))
    return tuple(records)


def _skip_runtime_file(relative: str) -> str | None:
    path = PurePosixPath(relative)
    if any(part == "__pycache__" for part in path.parts) or path.suffix.casefold() in {".pyc", ".pyo"}:
        return "bytecode_cache"
    if path.suffix.casefold() == ".exe":
        return "secondary_executable"
    if path.suffix.casefold() in {".pth", ".egg-link"}:
        return "path_hook"
    return None


def _copy_tree(
    source: Path,
    stage: Path,
    destination_prefix: str,
    *,
    allowed_top: set[str],
    skip_base_site_packages: bool = False,
) -> tuple[list[FileRecord], dict[str, int]]:
    records: list[FileRecord] = []
    skipped: dict[str, int] = {}
    for relative, path, _metadata in _source_files(source):
        parts = PurePosixPath(relative).parts
        if skip_base_site_packages and parts and parts[0] == "site-packages":
            skipped["base_site_packages"] = skipped.get("base_site_packages", 0) + 1
            continue
        reason = _skip_runtime_file(relative)
        if reason:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        logical = f"{destination_prefix}/{relative}"
        records.append(_logical_copy(path, stage, logical, allowed_top=allowed_top))
    return records, skipped


def _copy_selected_distributions(
    site_packages: Path,
    stage: Path,
    selected: Sequence[SelectedDistribution],
) -> tuple[list[FileRecord], dict[str, str]]:
    copied_by_path: dict[str, FileRecord] = {}
    packaged_by_distribution: dict[str, list[FileRecord]] = {}
    for distribution in selected:
        packaged: list[FileRecord] = []
        for relative, source in _distribution_source_files(site_packages, distribution):
            logical = f"runtime/site-packages/{relative}"
            key = logical.casefold()
            existing = copied_by_path.get(key)
            if existing is None:
                record = _logical_copy(
                    source, stage, logical, allowed_top={"runtime"}
                )
                copied_by_path[key] = record
            else:
                digest, size = sha256_file(source)
                if size == 0:
                    digest, size = sha256_bytes(b"\n"), 1
                if existing.sha256 != digest or existing.size_bytes != size:
                    raise BuildFailure("distribution_file_collision")
                record = existing
            packaged.append(
                FileRecord(relative, record.size_bytes, record.sha256)
            )
        packaged_by_distribution[distribution.name] = packaged
    return (
        sorted(copied_by_path.values(), key=lambda item: item.relative_path),
        {
            name: _records_hash("la-mineru-packaged-distribution-v1", records)
            for name, records in sorted(packaged_by_distribution.items())
        },
    )


def _copy_approved_model(
    source_root: Path,
    stage: Path,
    destination_prefix: str,
    approved_model: Mapping[str, object],
) -> list[FileRecord]:
    records: list[FileRecord] = []
    files = approved_model.get("files")
    if not isinstance(files, list) or not files:
        raise BuildFailure("model_provenance_invalid")
    for raw in files:
        value = _require_fields(
            raw, {"relativePath", "sizeBytes", "sha256"}, "model_provenance_invalid"
        )
        relative = value["relativePath"]
        if not isinstance(relative, str):
            raise BuildFailure("model_provenance_invalid")
        validate_relative_path(f"models/{relative}", {"models"})
        record = _logical_copy(
            source_root / PurePosixPath(relative),
            stage,
            f"{destination_prefix}/{relative}",
            allowed_top={"models"},
        )
        if record.size_bytes != value["sizeBytes"] or record.sha256 != value["sha256"]:
            raise BuildFailure("model_provenance_files_changed")
        records.append(record)
    return records


def _copy_worker_launcher(
    *,
    python_home: Path,
    worker_source: Path,
    stage: Path,
    pth_lines: Sequence[str],
) -> list[FileRecord]:
    records: list[FileRecord] = []
    records.append(
        _logical_copy(
            python_home / "python.exe",
            stage,
            "worker/mineru-worker.exe",
            allowed_top={"worker"},
        )
    )
    for name in ("python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        records.append(
            _logical_copy(
                python_home / name,
                stage,
                f"worker/{name}",
                allowed_top={"worker"},
            )
        )
    for name in ("sitecustomize.py",):
        records.append(
            _logical_copy(
                worker_source / "launcher" / name,
                stage,
                f"worker/{name}",
                allowed_top={"worker"},
            )
        )
    worker_package = worker_source / "lawyer_assistance_mineru_worker"
    copied, _skipped = _copy_tree(
        worker_package,
        stage,
        "worker/lawyer_assistance_mineru_worker",
        allowed_top={"worker"},
    )
    records.extend(copied)
    pth = "\n".join((*pth_lines, "import site", ""))
    for name in ("mineru-worker._pth", "python312._pth"):
        path = stage / "worker" / name
        path.write_text(pth, encoding="utf-8", newline="\n")
        digest, size = sha256_file(path)
        records.append(FileRecord(f"worker/{name}", size, digest))
    manifest = {
        "version": WORKER_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "selfContained": not any(Path(line).is_absolute() for line in pth_lines if line != "."),
    }
    manifest_path = stage / "worker" / "mineru-worker.exe.manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    digest, size = sha256_file(manifest_path)
    records.append(FileRecord("worker/mineru-worker.exe.manifest.json", size, digest))
    return records


def _license_inventory(
    site_packages: Path,
    stage: Path,
    distributions: Sequence[DistributionMeasurement],
) -> tuple[list[FileRecord], dict[str, object]]:
    records: list[FileRecord] = []
    entries: list[dict[str, object]] = []
    for distribution in distributions:
        copied_licenses: list[dict[str, object]] = []
        seen_hashes: set[str] = set()
        for license_record in distribution.license_files:
            if license_record.sha256 in seen_hashes:
                continue
            seen_hashes.add(license_record.sha256)
            candidate = validate_local_path(
                site_packages / PurePosixPath(license_record.relative_path), directory=False
            )
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate.name)[:80] or "LICENSE.txt"
            relative = (
                f"licenses/python/{distribution.name}/"
                f"{license_record.sha256[:16]}-{safe_name}"
            )
            record = _logical_copy(candidate, stage, relative, allowed_top={"licenses"})
            records.append(record)
            copied_licenses.append(
                {"relativePath": relative, "sizeBytes": record.size_bytes, "sha256": record.sha256}
            )
        entries.append(
            {
                "name": distribution.name,
                "version": distribution.version,
                "sourceUrls": list(distribution.source_urls),
                "license": distribution.license_declaration,
                "licenseEvidenceKind": distribution.license_evidence_kind,
                "licenseFiles": copied_licenses,
                "installationRecord": _file_records_json(
                    (distribution.installation_record,)
                )[0],
                "upstreamArtifact": dict(distribution.upstream_artifact)
                if distribution.upstream_artifact is not None
                else None,
            }
        )
    return records, {
        "schemaVersion": 2,
        "noAssertionAllowed": False,
        "distributions": entries,
    }


def third_party_notices(provenance: Mapping[str, object]) -> bytes:
    lines = [
        "Lawyer Assistance MinerU Component - Third-Party Notices",
        "",
        "This file is generated from the approved, hash-bound provenance manifest.",
        "Unknown or absent license declarations are rejected by the production builder.",
        "License text files supplied by upstream distributions are retained under licenses/python/.",
        "",
        "CPython",
        f"  Version: {provenance['cpython']['version']}",
        f"  Source: {provenance['cpython']['sourceUrl']}",
        f"  License: {provenance['cpython']['license']}",
        "  License file: licenses/cpython/LICENSE.txt",
        "",
        "Python distributions",
    ]
    for item in provenance["distributions"]:
        lines.extend(
            [
                f"- {item['name']} {item['version']}",
                f"  Source: {item['sourceUrl']}",
                f"  Declared license: {item['license']}",
                f"  Evidence: {item['licenseEvidenceKind']}",
            ]
        )
        if item["licenseFiles"]:
            for license_file in item["licenseFiles"]:
                lines.append(
                    f"  Upstream license evidence SHA-256: {license_file['sha256']}"
                )
        else:
            lines.append("  Upstream wheel installed no separate license text; declaration is metadata-bound.")
        artifact = item["upstreamArtifact"]
        if artifact is not None:
            lines.extend(
                [
                    f"  Qualified upstream wheel: {artifact['fileName']}",
                    f"  Wheel SHA-256: {artifact['sha256']}",
                    f"  Wheel URL: {artifact['sourceUrl']}",
                ]
            )
    lines.extend(["", "Models"])
    for item in provenance["models"]:
        lines.extend(
            [
                f"- {item['name']} @ {item['revision']}",
                f"  Source: {item['sourceUrl']}",
                f"  Declared license: {item['license']}",
                f"  License evidence: {item['licenseEvidenceUrl']}",
                f"  License evidence SHA-256: {item['licenseEvidenceSha256']}",
            ]
        )
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def component_provenance(
    approved: Mapping[str, object],
    *,
    packaged_hashes: Mapping[str, str],
    all_distributions: Sequence[tuple[str, str]],
) -> dict[str, object]:
    selected = {str(item["name"]) for item in approved["distributions"]}
    distributions = []
    for item in approved["distributions"]:
        enriched = dict(item)
        packaged = packaged_hashes.get(str(item["name"]))
        if not _valid_hash(packaged):
            raise BuildFailure("packaged_distribution_unmeasured")
        enriched["packagedContentSha256"] = packaged
        distributions.append(enriched)
    excluded = [
        {
            "name": name,
            "version": version,
            "reason": "outside-mineru-pipeline-vlm-dependency-closure",
        }
        for name, version in all_distributions
        if name not in selected
    ]
    return {
        "schemaVersion": PROVENANCE_SCHEMA_VERSION,
        "provenanceVersion": PROVENANCE_OUTPUT_VERSION,
        "provenanceInputSha256": approved["provenanceInputSha256"],
        "approval": approved["approval"],
        "source": approved["source"],
        "cpython": approved["cpython"],
        "runtimeProfile": approved["runtimeProfile"],
        "distributions": distributions,
        "excludedDistributions": excluded,
        "models": approved["models"],
    }


def support_tree_hash(records: Sequence[FileRecord]) -> str:
    canonical = bytearray(b"la-mineru-support-tree-v1\n")
    for record in sorted(records, key=lambda item: item.relative_path):
        canonical.extend(record.relative_path.encode("utf-8"))
        canonical.extend(b"\n")
        canonical.extend(str(record.size_bytes).encode("ascii"))
        canonical.extend(b"\n")
        canonical.extend(record.sha256.encode("ascii"))
        canonical.extend(b"\n")
    return sha256_bytes(bytes(canonical))


def support_identity_hash(
    *, identity: RuntimeIdentity, tree_hash: str
) -> str:
    canonical = (
        "la-mineru-support-identity-v1\n"
        f"{PROTOCOL_VERSION}\n{WORKER_VERSION}\n{identity.python_version}\n"
        f"{identity.version('mineru')}\n{identity.version('torch')}\n{tree_hash}\n"
    ).encode("utf-8")
    return sha256_bytes(canonical)


def verify_support_manifest(path: Path, component_root: Path) -> dict[str, object]:
    """Fully remeasure a freshly built support tree and reject drift."""
    path = validate_local_path(path, directory=False)
    component_root = validate_local_path(component_root, directory=True)
    try:
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=lambda pairs: _strict_json_object(pairs),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                BuildFailure("support_manifest_invalid")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BuildFailure("support_manifest_invalid") from error
    expected_fields = {
        "schemaVersion",
        "manifestVersion",
        "selfContained",
        "protocolVersion",
        "workerVersion",
        "pythonVersion",
        "mineruVersion",
        "pytorchVersion",
        "supportTreeSha256",
        "supportIdentitySha256",
        "criticalFiles",
        "files",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value["schemaVersion"] != SUPPORT_SCHEMA_VERSION
        or value["manifestVersion"] != SUPPORT_MANIFEST_VERSION
        or value["selfContained"] is not True
        or value["protocolVersion"] != PROTOCOL_VERSION
        or value["workerVersion"] != WORKER_VERSION
        or value["pythonVersion"] != CPYTHON_VERSION
        or value["mineruVersion"] != REQUIRED_DISTRIBUTIONS["mineru"]
        or value["pytorchVersion"] != REQUIRED_DISTRIBUTIONS["torch"]
        or value["criticalFiles"] != list(CRITICAL_SUPPORT_PATHS)
        or not isinstance(value["files"], list)
        or not value["files"]
        or len(value["files"]) > MAX_FILES
    ):
        raise BuildFailure("support_manifest_invalid")
    records: list[FileRecord] = []
    previous: str | None = None
    folded: set[str] = set()
    for entry in value["files"]:
        if not isinstance(entry, dict) or set(entry) != {"relativePath", "sizeBytes", "sha256"}:
            raise BuildFailure("support_manifest_invalid")
        relative = entry.get("relativePath")
        size = entry.get("sizeBytes")
        digest = entry.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise BuildFailure("support_manifest_invalid")
        validate_relative_path(relative, SUPPORT_TOP_LEVEL)
        if previous is not None and previous >= relative:
            raise BuildFailure("support_manifest_invalid")
        previous = relative
        if relative.casefold() in folded:
            raise BuildFailure("support_manifest_invalid")
        folded.add(relative.casefold())
        candidate = validate_local_path(component_root / PurePosixPath(relative), directory=False)
        try:
            candidate.relative_to(component_root)
        except ValueError as error:
            raise BuildFailure("support_path_escape") from error
        actual_hash, actual_size = sha256_file(candidate)
        if actual_hash != digest or actual_size != size:
            raise BuildFailure("support_file_changed")
        records.append(FileRecord(relative, size, digest))
    expected_inventory = {record.relative_path for record in records}
    exempt = {
        "worker/mineru-worker.exe",
        "worker/mineru-worker.exe.manifest.json",
        "worker/mineru-worker.support-manifest.json",
    }
    actual_inventory: set[str] = set()
    for top in sorted(SUPPORT_TOP_LEVEL):
        for relative, _candidate, _metadata in _source_files(component_root / top):
            logical = f"{top}/{relative}"
            if logical not in exempt:
                actual_inventory.add(logical)
    if actual_inventory != expected_inventory:
        raise BuildFailure("support_tree_inventory_changed")
    tree_hash = support_tree_hash(records)
    if tree_hash != value["supportTreeSha256"]:
        raise BuildFailure("support_tree_hash_invalid")
    identity = RuntimeIdentity(
        python_version=str(value["pythonVersion"]),
        architecture="windows-x86_64",
        distributions=(
            ("mineru", str(value["mineruVersion"])),
            ("torch", str(value["pytorchVersion"])),
        ),
    )
    if support_identity_hash(identity=identity, tree_hash=tree_hash) != value["supportIdentitySha256"]:
        raise BuildFailure("support_identity_invalid")
    if not set(CRITICAL_SUPPORT_PATHS).issubset({item.relative_path for item in records}):
        raise BuildFailure("critical_support_missing")
    return value


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuildFailure("support_manifest_duplicate_field")
        result[key] = value
    return result

def _write_support_manifest(
    stage: Path,
    records: Sequence[FileRecord],
    identity: RuntimeIdentity,
) -> FileRecord:
    support = [
        record
        for record in records
        if PurePosixPath(record.relative_path).parts[0] in SUPPORT_TOP_LEVEL
        and record.relative_path != "worker/mineru-worker.exe"
        and record.relative_path != "worker/mineru-worker.exe.manifest.json"
    ]
    support.sort(key=lambda item: item.relative_path)
    if len({item.relative_path.casefold() for item in support}) != len(support):
        raise BuildFailure("support_path_collision")
    available = {item.relative_path for item in support}
    missing = sorted(set(CRITICAL_SUPPORT_PATHS) - available)
    if missing:
        raise BuildFailure("critical_support_missing")
    tree_hash = support_tree_hash(support)
    manifest = {
        "schemaVersion": SUPPORT_SCHEMA_VERSION,
        "manifestVersion": SUPPORT_MANIFEST_VERSION,
        "selfContained": True,
        "protocolVersion": PROTOCOL_VERSION,
        "workerVersion": WORKER_VERSION,
        "pythonVersion": identity.python_version,
        "mineruVersion": identity.version("mineru"),
        "pytorchVersion": identity.version("torch"),
        "supportTreeSha256": tree_hash,
        "supportIdentitySha256": support_identity_hash(identity=identity, tree_hash=tree_hash),
        "criticalFiles": list(CRITICAL_SUPPORT_PATHS),
        "files": [
            {
                "relativePath": item.relative_path,
                "sizeBytes": item.size_bytes,
                "sha256": item.sha256,
            }
            for item in support
        ],
    }
    path = stage / "worker" / "mineru-worker.support-manifest.json"
    path.write_bytes(canonical_json(manifest))
    digest, size = sha256_file(path)
    return FileRecord("worker/mineru-worker.support-manifest.json", size, digest)


def _atomic_stage(output: Path, builder) -> Path:
    output = ensure_output(output)
    incoming = output.parent / f".{output.name}.incoming-{uuid.uuid4()}"
    incoming.mkdir()
    try:
        builder(incoming)
        os.rename(incoming, output)
    except BaseException:
        shutil.rmtree(incoming, ignore_errors=True)
        raise
    return output


def build_dev_launcher(
    *,
    python_home: Path,
    site_packages: Path,
    pipeline_model: Path,
    vlm_model: Path,
    worker_source: Path,
    output: Path,
) -> dict[str, object]:
    python_home = validate_local_path(python_home, directory=True)
    site_packages = validate_local_path(site_packages, directory=True)
    worker_source = validate_local_path(worker_source, directory=True)
    pipeline, vlm = validate_models(pipeline_model, vlm_model)
    identity = probe_runtime_identity(python_home, site_packages)
    model_root = common_model_root(pipeline, vlm)
    result: dict[str, object] = {}

    def create(stage: Path) -> None:
        pth_lines = (
            ".",
            str(python_home / "Lib"),
            str(python_home / "DLLs"),
            str(site_packages),
        )
        records = _copy_worker_launcher(
            python_home=python_home,
            worker_source=worker_source,
            stage=stage,
            pth_lines=pth_lines,
        )
        config = {"models-dir": {"pipeline": str(pipeline), "vlm": str(vlm)}}
        (stage / "config.json").write_bytes(canonical_json(config))
        (stage / "model-manifest.json").write_bytes(canonical_json(model_manifest(model_root)))
        worker = stage / "worker" / "mineru-worker.exe"
        worker_hash, worker_size = sha256_file(worker)
        final_worker = Path(os.path.abspath(output)) / "worker" / "mineru-worker.exe"
        normalized = str(final_worker).replace("/", "\\").lower()
        runtime = {
            "schemaVersion": 1,
            "version": "lawyer-assistance-mineru-runtime-v1",
            "executables": [
                {
                    "pathSha256": sha256_bytes(normalized.encode("utf-8")),
                    "sha256": worker_hash,
                    "sizeBytes": worker_size,
                    "role": "launcher",
                }
            ],
        }
        (stage / "runtime-manifest.json").write_bytes(canonical_json(runtime))
        result.update(
            {
                "ok": True,
                "mode": "dev-launcher",
                "diagnosticOnly": True,
                "selfContained": False,
                "worker": str(final_worker),
                "workerSha256": worker_hash,
                "pythonVersion": identity.python_version,
                "mineruVersion": identity.version("mineru"),
                "pytorchVersion": identity.version("torch"),
                "modelRoot": str(model_root),
                "fileCount": len(records),
            }
        )

    _atomic_stage(output, create)
    return result


def build_self_contained_stage(
    *,
    python_home: Path,
    site_packages: Path,
    pipeline_model: Path,
    vlm_model: Path,
    worker_source: Path,
    repository_license: Path,
    provenance_input: Path,
    repository_root: Path,
    output: Path,
) -> dict[str, object]:
    python_home = validate_local_path(python_home, directory=True)
    site_packages = validate_local_path(site_packages, directory=True)
    worker_source = validate_local_path(worker_source, directory=True)
    repository_license = validate_local_path(repository_license, directory=False)
    source_binding = _repository_source_binding(
        repository_root, worker_source, repository_license
    )
    pipeline, vlm = validate_models(pipeline_model, vlm_model)
    identity = probe_runtime_identity(python_home, site_packages)
    selected = resolve_runtime_distributions(site_packages)
    measurements = tuple(measure_distribution(site_packages, item) for item in selected)
    pipeline_records_observed = _model_observation(pipeline)
    vlm_records_observed = _model_observation(vlm)
    approved_provenance = validate_provenance_input(
        provenance_input=provenance_input,
        repository_root=repository_root,
        repository_license=repository_license,
        python_home=python_home,
        worker_source=worker_source,
        distributions=measurements,
        pipeline_records=pipeline_records_observed,
        vlm_records=vlm_records_observed,
        source_binding=source_binding,
    )
    approved_models = {
        str(model["root"]): model for model in approved_provenance["models"]
    }
    scopes: list[tuple[str, Path]] = [
        ("cpython", python_home),
        ("site-packages", site_packages),
    ]
    tool_scripts = site_packages.parent.parent / "Scripts"
    if tool_scripts.is_dir():
        scopes.append(("tool-scripts", validate_local_path(tool_scripts, directory=True)))
    excluded = _excluded_executables(
        tuple(scopes),
        exclude=(python_home / "python.exe",),
    )
    result: dict[str, object] = {}

    def create(stage: Path) -> None:
        records = _copy_worker_launcher(
            python_home=python_home,
            worker_source=worker_source,
            stage=stage,
            pth_lines=(".", "..\\python\\Lib", "..\\python\\DLLs", "..\\runtime\\site-packages"),
        )
        base_records, base_skipped = _copy_tree(
            python_home / "Lib",
            stage,
            "python/Lib",
            allowed_top={"python"},
            skip_base_site_packages=True,
        )
        dll_records, dll_skipped = _copy_tree(
            python_home / "DLLs",
            stage,
            "python/DLLs",
            allowed_top={"python"},
        )
        site_records, packaged_hashes = _copy_selected_distributions(
            site_packages, stage, selected
        )
        pipeline_records = _copy_approved_model(
            pipeline,
            stage,
            "models/pipeline",
            approved_models["pipeline"],
        )
        vlm_records = _copy_approved_model(
            vlm,
            stage,
            "models/vlm",
            approved_models["vlm"],
        )
        records.extend(base_records)
        records.extend(dll_records)
        records.extend(site_records)
        records.extend(pipeline_records)
        records.extend(vlm_records)

        license_records, license_inventory = _license_inventory(
            site_packages, stage, measurements
        )
        records.extend(license_records)
        for source, relative in (
            (python_home / "LICENSE.txt", "licenses/cpython/LICENSE.txt"),
            (repository_license, "licenses/lawyer-assistance/LICENSE.txt"),
        ):
            records.append(_logical_copy(source, stage, relative, allowed_top={"licenses"}))
        _verify_staged_repository_sources(stage, source_binding)
        license_manifest = stage / "licenses" / "python-distributions.json"
        license_manifest.write_bytes(canonical_json(license_inventory))
        license_hash, license_size = sha256_file(license_manifest)
        records.append(FileRecord("licenses/python-distributions.json", license_size, license_hash))

        provenance = component_provenance(
            approved_provenance,
            packaged_hashes=packaged_hashes,
            all_distributions=identity.distributions,
        )
        provenance_path = stage / PurePosixPath(PROVENANCE_OUTPUT_RELATIVE)
        provenance_path.write_bytes(canonical_json(provenance))
        provenance_hash, provenance_size = sha256_file(provenance_path)
        records.append(
            FileRecord(PROVENANCE_OUTPUT_RELATIVE, provenance_size, provenance_hash)
        )
        notices_path = stage / PurePosixPath(THIRD_PARTY_NOTICES_RELATIVE)
        notices_path.write_bytes(third_party_notices(provenance))
        notices_hash, notices_size = sha256_file(notices_path)
        records.append(
            FileRecord(THIRD_PARTY_NOTICES_RELATIVE, notices_size, notices_hash)
        )

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "lawyer-assistance-mineru-worker",
                    "version": WORKER_VERSION,
                },
                "properties": [
                    {"name": "lawyer-assistance:offline-only", "value": "true"},
                    {"name": "lawyer-assistance:python", "value": identity.python_version},
                    {"name": "lawyer-assistance:mineru", "value": identity.version("mineru")},
                ],
            },
            "components": [
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                }
                for name, version in ((item.name, item.version) for item in selected)
            ],
        }
        sbom_path = stage / "runtime" / "sbom-python.json"
        sbom_path.write_bytes(canonical_json(sbom))
        sbom_hash, sbom_size = sha256_file(sbom_path)
        records.append(FileRecord("runtime/sbom-python.json", sbom_size, sbom_hash))

        skipped = dict(base_skipped)
        for values in (dll_skipped,):
            for reason, count in values.items():
                skipped[reason] = skipped.get(reason, 0) + count
        skipped["distribution_outside_runtime_closure"] = len(identity.distributions) - len(
            selected
        )
        version_manifest = {
            "schemaVersion": 1,
            "workerVersion": WORKER_VERSION,
            "protocolVersion": PROTOCOL_VERSION,
            "platform": identity.architecture,
            "pythonVersion": identity.python_version,
            "mineruVersion": identity.version("mineru"),
            "pytorchVersion": identity.version("torch"),
            "pypdfium2Version": identity.version("pypdfium2"),
            "pillowVersion": identity.version("pillow"),
            "loguruVersion": identity.version("loguru"),
            "modelDirectories": {"pipeline": "models/pipeline", "vlm": "models/vlm"},
            "provenance": {
                "relativePath": PROVENANCE_OUTPUT_RELATIVE,
                "sha256": provenance_hash,
                "inputSha256": approved_provenance["provenanceInputSha256"],
            },
            "runtimeDistributionProfile": {
                "root": f"mineru=={identity.version('mineru')}",
                "extras": list(MINERU_RUNTIME_EXTRAS),
                "selectedCount": len(selected),
                "excludedCount": len(identity.distributions) - len(selected),
            },
            "excludedExecutables": [
                {
                    "sourceScope": item.source_scope,
                    "relativePath": item.relative_path,
                    "sizeBytes": item.size_bytes,
                    "sha256": item.sha256,
                }
                for item in excluded
            ],
            "skippedFileCounts": dict(sorted(skipped.items())),
            "zeroBytePolicy": "materialized-as-single-lf-and-rehashed",
        }
        version_path = stage / "runtime" / "version-manifest.json"
        version_path.write_bytes(canonical_json(version_manifest))
        version_hash, version_size = sha256_file(version_path)
        records.append(FileRecord("runtime/version-manifest.json", version_size, version_hash))

        support_record = _write_support_manifest(stage, records, identity)
        records.append(support_record)
        folded = [record.relative_path.casefold() for record in records]
        if len(folded) != len(set(folded)) or len(records) > MAX_FILES:
            raise BuildFailure("stage_inventory_invalid")
        for record in records:
            path = stage / PurePosixPath(record.relative_path)
            digest, size = sha256_file(path)
            if digest != record.sha256 or size != record.size_bytes or size == 0:
                raise BuildFailure("stage_verify_failed")
            if path.suffix.casefold() == ".exe" and record.relative_path != "worker/mineru-worker.exe":
                raise BuildFailure("secondary_executable_leaked")
        total = sum(record.size_bytes for record in records)
        if total > MAX_BYTES:
            raise BuildFailure("stage_limit_exceeded")
        support_hash, _ = sha256_file(stage / support_record.relative_path)
        verify_support_manifest(stage / support_record.relative_path, stage)
        result.update(
            {
                "ok": True,
                "mode": "stage",
                "diagnosticOnly": False,
                "selfContained": True,
                "stage": str(output),
                "worker": str(output / "worker" / "mineru-worker.exe"),
                "supportManifest": str(output / support_record.relative_path),
                "supportManifestSha256": support_hash,
                "fileCount": len(records),
                "totalBytes": total,
                "excludedExecutableCount": len(excluded),
                "pythonDistributionCount": len(identity.distributions),
                "packagedPythonDistributionCount": len(selected),
                "excludedPythonDistributionCount": len(identity.distributions) - len(selected),
                "provenance": str(output / PROVENANCE_OUTPUT_RELATIVE),
                "provenanceSha256": provenance_hash,
                "thirdPartyNotices": str(output / THIRD_PARTY_NOTICES_RELATIVE),
                "signed": False,
            }
        )

    _atomic_stage(output, create)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subcommands = value.add_subparsers(dest="command", required=True)
    for name in ("dev-launcher", "stage"):
        command = subcommands.add_parser(name)
        command.add_argument("--python-home", type=Path, required=True)
        command.add_argument("--site-packages", type=Path, required=True)
        command.add_argument("--pipeline-model", type=Path, required=True)
        command.add_argument("--vlm-model", type=Path, required=True)
        command.add_argument("--worker-source", type=Path, default=Path("workers/mineru"))
        command.add_argument("--output", type=Path, required=True)
        if name == "stage":
            command.add_argument("--repository-license", type=Path, default=Path("LICENSE"))
            command.add_argument("--repository-root", type=Path, default=Path("."))
            command.add_argument("--provenance-input", type=Path, required=True)
    draft = subcommands.add_parser("provenance-draft")
    draft.add_argument("--python-home", type=Path, required=True)
    draft.add_argument("--site-packages", type=Path, required=True)
    draft.add_argument("--pipeline-model", type=Path, required=True)
    draft.add_argument("--vlm-model", type=Path, required=True)
    draft.add_argument("--worker-source", type=Path, default=Path("workers/mineru"))
    draft.add_argument("--repository-root", type=Path, default=Path("."))
    draft.add_argument("--cpython-source-url", required=True)
    draft.add_argument("--cpython-license", required=True)
    for model in ("pipeline", "vlm"):
        draft.add_argument(f"--{model}-model-name", required=True)
        draft.add_argument(f"--{model}-model-revision", required=True)
        draft.add_argument(f"--{model}-model-source-url", required=True)
        draft.add_argument(f"--{model}-model-license", required=True)
        draft.add_argument(f"--{model}-model-license-evidence-url", required=True)
        draft.add_argument(
            f"--{model}-model-exclude-relative-path", action="append", default=[]
        )
    draft.add_argument("--output", type=Path, required=True)
    approve = subcommands.add_parser("provenance-approve")
    approve.add_argument("--draft", type=Path, required=True)
    approve.add_argument("--reviewer", required=True)
    approve.add_argument("--reviewed-at", type=int, required=True)
    approve.add_argument("--output", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "provenance-approve":
            result = approve_provenance_draft(
                draft=arguments.draft,
                reviewer=arguments.reviewer,
                reviewed_at=arguments.reviewed_at,
                output=arguments.output,
            )
            print(canonical_json(result).decode("utf-8"))
            return 0
        common = dict(
            python_home=arguments.python_home,
            site_packages=arguments.site_packages,
            pipeline_model=arguments.pipeline_model,
            vlm_model=arguments.vlm_model,
            worker_source=arguments.worker_source,
            output=arguments.output,
        )
        if arguments.command == "dev-launcher":
            result = build_dev_launcher(**common)
        elif arguments.command == "stage":
            result = build_self_contained_stage(
                **common,
                repository_license=arguments.repository_license,
                repository_root=arguments.repository_root,
                provenance_input=arguments.provenance_input,
            )
        else:
            model_specs = {
                model: {
                    "name": getattr(arguments, f"{model}_model_name"),
                    "revision": getattr(arguments, f"{model}_model_revision"),
                    "sourceUrl": getattr(arguments, f"{model}_model_source_url"),
                    "license": getattr(arguments, f"{model}_model_license"),
                    "licenseEvidenceUrl": getattr(
                        arguments, f"{model}_model_license_evidence_url"
                    ),
                }
                for model in ("pipeline", "vlm")
            }
            result = write_provenance_draft(
                **common,
                repository_root=arguments.repository_root,
                cpython_source_url=arguments.cpython_source_url,
                cpython_license=arguments.cpython_license,
                model_specs=model_specs,
                model_exclusions={
                    model: getattr(
                        arguments, f"{model}_model_exclude_relative_path"
                    )
                    for model in ("pipeline", "vlm")
                },
            )
    except (BuildFailure, OSError, UnicodeError, ValueError) as error:
        code = error.code if isinstance(error, BuildFailure) else "build_failed"
        print(canonical_json({"ok": False, "code": code}).decode("utf-8"), file=sys.stderr)
        return 2
    print(canonical_json(result).decode("utf-8"))
    if arguments.command == "stage":
        print("UNSIGNED_STAGE_REQUIRES_COMPONENT_PACKAGING_AND_OFFLINE_MINISIGN=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
