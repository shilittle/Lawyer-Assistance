"""Bound runtime identity and health evidence for the managed MinerU worker."""

from __future__ import annotations

import ctypes
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import PROTOCOL_VERSION
from .support_manifest import (
    SupportManifestFailure,
    validate_support_manifest,
)

WORKER_VERSION: Final = "1.0.0"
MAX_SMALL_FILE_BYTES: Final = 8 * 1024 * 1024
MAX_OUTPUT_BYTES: Final = 512 * 1024 * 1024
HASH_RE: Final = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID_RE: Final = re.compile(r"^[a-z][a-z0-9]{1,15}_[0-9a-f]{32}$")
VERSION_RE: Final = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
OFFLINE_ENV: Final = (
    ("MINERU_MODEL_SOURCE", "local"),
    ("HF_HUB_OFFLINE", "1"),
    ("TRANSFORMERS_OFFLINE", "1"),
    ("HF_DATASETS_OFFLINE", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
    ("PIP_NO_INDEX", "1"),
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONSAFEPATH", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("DO_NOT_TRACK", "1"),
    ("NO_PROXY", "*"),
    ("HTTP_PROXY", "http://127.0.0.1:9"),
    ("HTTPS_PROXY", "http://127.0.0.1:9"),
    ("ALL_PROXY", "socks5://127.0.0.1:9"),
)
OFFLINE_POLICY_V1: Final = (
    "la-mineru-offline-env-v1\n"
    + "".join(f"{key}={value}\n" for key, value in OFFLINE_ENV)
).encode("ascii")
JOB_POLICY_V1: Final = (
    b"la-mineru-windows-job-v1\n"
    b"active-process-limit=1\n"
    b"kill-on-close=true\n"
    b"suspended-before-assign=true\n"
)


class RuntimeFailure(RuntimeError):
    """A non-sensitive, stable failure that must close the worker."""


@dataclass(frozen=True)
class RuntimePaths:
    job_root: Path
    config: Path
    model_root: Path
    model_manifest: Path
    runtime_manifest: Path
    support_manifest: Path | None
    input_pdf: Path
    output: Path
    cache: Path


@dataclass(frozen=True)
class GpuDescriptor:
    index: int
    name: str
    driver: str
    memory_mib: int


class _NvmlMemory(ctypes.Structure):
    _fields_ = [
        ("total", ctypes.c_ulonglong),
        ("free", ctypes.c_ulonglong),
        ("used", ctypes.c_ulonglong),
    ]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, maximum: int | None = None) -> str:
    stat = path.stat()
    if not path.is_file() or stat.st_size <= 0 or (maximum is not None and stat.st_size > maximum):
        raise RuntimeFailure("bound_file_invalid")
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value or value != value.strip() or "\x00" in value:
        raise RuntimeFailure("environment_invalid")
    return value


def require_hash_env(name: str) -> str:
    value = require_env(name)
    if not HASH_RE.fullmatch(value):
        raise RuntimeFailure("environment_hash_invalid")
    return value


def require_opaque_env(name: str) -> str:
    value = require_env(name)
    if not OPAQUE_ID_RE.fullmatch(value):
        raise RuntimeFailure("environment_id_invalid")
    return value


def fixed_path(name: str, *, directory: bool) -> Path:
    raw = require_env(name)
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise RuntimeFailure("bound_path_invalid")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise RuntimeFailure("bound_path_invalid") from error
    if directory != resolved.is_dir():
        raise RuntimeFailure("bound_path_invalid")
    return resolved


def _comparable_path(path: Path) -> str:
    """Normalize an already-resolved path without losing Windows identity."""
    value = str(path)
    if os.name == "nt":
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def path_within_directory(path: Path, directory: Path) -> bool:
    """Compare resolved paths across normal and extended-length Windows spellings."""
    candidate = _comparable_path(path)
    root = _comparable_path(directory)
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False


def ordinary_path(path: Path, *, directory: bool) -> None:
    try:
        stat = path.lstat()
    except OSError as error:
        raise RuntimeFailure("job_path_invalid") from error
    if path.is_symlink() or directory != path.is_dir():
        raise RuntimeFailure("job_path_invalid")
    attributes = getattr(stat, "st_file_attributes", 0)
    if attributes & 0x00000400:
        raise RuntimeFailure("job_path_invalid")
    if not directory and getattr(stat, "st_nlink", 1) != 1:
        raise RuntimeFailure("job_path_invalid")


def _version(distribution: str) -> str:
    try:
        value = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeFailure("runtime_version_missing") from error
    if not VERSION_RE.fullmatch(value) or value != value.strip():
        raise RuntimeFailure("runtime_version_invalid")
    return value


def _nvml_call(function: object, *arguments: object) -> None:
    result = function(*arguments)
    if result != 0:
        raise RuntimeFailure("gpu_runtime_unavailable")


def _measure_nvml(indices: tuple[int, ...]) -> tuple[GpuDescriptor, ...]:
    if os.name != "nt":
        raise RuntimeFailure("gpu_runtime_unavailable")
    try:
        nvml = ctypes.WinDLL("nvml.dll")
    except OSError as error:
        raise RuntimeFailure("gpu_runtime_unavailable") from error
    nvml.nvmlInit_v2.restype = ctypes.c_int
    nvml.nvmlShutdown.restype = ctypes.c_int
    nvml.nvmlDeviceGetHandleByIndex_v2.restype = ctypes.c_int
    nvml.nvmlDeviceGetName.restype = ctypes.c_int
    nvml.nvmlSystemGetDriverVersion.restype = ctypes.c_int
    nvml.nvmlDeviceGetMemoryInfo.restype = ctypes.c_int
    initialized = False
    try:
        _nvml_call(nvml.nvmlInit_v2)
        initialized = True
        driver_buffer = ctypes.create_string_buffer(96)
        _nvml_call(nvml.nvmlSystemGetDriverVersion, driver_buffer, len(driver_buffer))
        driver = driver_buffer.value.decode("ascii", "strict")
        if not VERSION_RE.fullmatch(driver):
            raise RuntimeFailure("gpu_driver_invalid")
        descriptors: list[GpuDescriptor] = []
        for index in indices:
            handle = ctypes.c_void_p()
            _nvml_call(
                nvml.nvmlDeviceGetHandleByIndex_v2,
                ctypes.c_uint(index),
                ctypes.byref(handle),
            )
            name_buffer = ctypes.create_string_buffer(256)
            _nvml_call(nvml.nvmlDeviceGetName, handle, name_buffer, len(name_buffer))
            name = name_buffer.value.decode("utf-8", "strict")
            memory = _NvmlMemory()
            _nvml_call(nvml.nvmlDeviceGetMemoryInfo, handle, ctypes.byref(memory))
            memory_mib = int(memory.total // (1024 * 1024))
            if (
                not 3 <= len(name) <= 128
                or name != name.strip()
                or any(ord(character) < 0x20 for character in name)
                or memory_mib < 1024
            ):
                raise RuntimeFailure("gpu_descriptor_invalid")
            descriptors.append(GpuDescriptor(index, name, driver, memory_mib))
        return tuple(descriptors)
    finally:
        if initialized:
            nvml.nvmlShutdown()


def _requested_indices(value: str) -> tuple[int, ...]:
    if value == "auto":
        return (0,)
    if not value.startswith("cuda:"):
        raise RuntimeFailure("cuda_device_required")
    pieces = value[5:].split(",")
    try:
        indices = tuple(int(piece, 10) for piece in pieces)
    except ValueError as error:
        raise RuntimeFailure("cuda_device_invalid") from error
    if (
        not indices
        or len(indices) > 16
        or len(set(indices)) != len(indices)
        or any(index < 0 or index > 63 for index in indices)
    ):
        raise RuntimeFailure("cuda_device_invalid")
    visible = os.environ.get("CUDA_VISIBLE_DEVICES")
    if visible != ",".join(str(index) for index in indices):
        raise RuntimeFailure("cuda_device_binding_invalid")
    return indices


def _gpu_identity(requested: str) -> tuple[dict[str, object], str, str]:
    indices = _requested_indices(requested)
    descriptors = _measure_nvml(indices)
    try:
        import torch
    except Exception as error:
        raise RuntimeFailure("pytorch_unavailable") from error
    if not torch.cuda.is_available() or torch.cuda.device_count() != len(indices):
        raise RuntimeFailure("cuda_runtime_unavailable")
    for visible_index, descriptor in enumerate(descriptors):
        if torch.cuda.get_device_name(visible_index).strip() != descriptor.name:
            raise RuntimeFailure("cuda_device_binding_invalid")
    cuda_runtime = str(torch.version.cuda or "")
    if not VERSION_RE.fullmatch(cuda_runtime):
        raise RuntimeFailure("cuda_version_invalid")
    canonical = "\n".join(
        f"{item.index}|{item.name}|{item.driver}|{item.memory_mib}" for item in descriptors
    )
    hardware_hash = sha256_hex(canonical.encode("utf-8"))
    device = {
        "kind": "cuda",
        "indices": list(indices),
        "hardware_fingerprint_sha256": hardware_hash,
    }
    return device, descriptors[0].driver, cuda_runtime


class WorkerRuntime:
    def __init__(self) -> None:
        if require_env("LA_MINERU_PROTOCOL_VERSION") != PROTOCOL_VERSION:
            raise RuntimeFailure("protocol_version_invalid")
        for key, expected in OFFLINE_ENV:
            if os.environ.get(key) != expected:
                raise RuntimeFailure("offline_environment_invalid")
        if os.environ.get("no_proxy") != "*":
            raise RuntimeFailure("offline_environment_invalid")

        job_root = Path.cwd().resolve(strict=True)
        ordinary_path(job_root, directory=True)
        for variable in ("TEMP", "TMP", "USERPROFILE", "HOME"):
            if Path(require_env(variable)).resolve(strict=False) != job_root:
                raise RuntimeFailure("job_root_binding_invalid")

        config = fixed_path("LA_MINERU_CONFIG_PATH", directory=False)
        model_root = fixed_path("LA_MINERU_MODEL_ROOT", directory=True)
        model_manifest = fixed_path("LA_MINERU_MODEL_MANIFEST_PATH", directory=False)
        runtime_manifest = fixed_path("LA_MINERU_RUNTIME_MANIFEST_PATH", directory=False)
        diagnostic = os.environ.get("LA_MINERU_DIAGNOSTIC_ONLY")
        if diagnostic not in {None, "1"}:
            raise RuntimeFailure("diagnostic_mode_invalid")
        self.diagnostic_only = diagnostic == "1"
        support_manifest = (
            None
            if self.diagnostic_only
            else fixed_path("LA_MINERU_SUPPORT_MANIFEST_PATH", directory=False)
        )
        self.paths = RuntimePaths(
            job_root=job_root,
            config=config,
            model_root=model_root,
            model_manifest=model_manifest,
            runtime_manifest=runtime_manifest,
            input_pdf=job_root / "input.pdf",
            support_manifest=support_manifest,
            output=job_root / "output",
            cache=job_root / "cache",
        )

        self.worker_sha256 = require_hash_env("LA_MINERU_WORKER_SHA256")
        self.config_sha256 = require_hash_env("LA_MINERU_CONFIG_SHA256")
        self.model_manifest_sha256 = require_hash_env("LA_MINERU_MODEL_MANIFEST_SHA256")
        self.isolation_evidence_id = require_opaque_env("LA_MINERU_ISOLATION_EVIDENCE_ID")
        if self.diagnostic_only:
            self.support_manifest_sha256 = sha256_hex(
                b"la-mineru-diagnostic-support-unqualified-v1\n"
            )
            self.support_identity_sha256 = self.support_manifest_sha256
            self.support_tree_sha256 = self.support_manifest_sha256
        else:
            self.support_manifest_sha256 = require_hash_env("LA_MINERU_SUPPORT_MANIFEST_SHA256")
        self.isolation_evidence_sha256 = require_hash_env(
            "LA_MINERU_ISOLATION_EVIDENCE_SHA256"
        )
        self.qualification_report_id = require_opaque_env(
            "LA_MINERU_QUALIFICATION_REPORT_ID"
        )
        self.job_policy_sha256 = require_hash_env("LA_MINERU_JOB_POLICY_SHA256")
        self.backend = require_env("LA_MINERU_BACKEND")
        self.language = require_env("LA_MINERU_LANGUAGE")
        self.requested_device_value = require_env("LA_MINERU_REQUESTED_DEVICE")
        try:
            self.max_output_bytes = int(require_env("LA_MINERU_MAX_OUTPUT_BYTES"), 10)
        except ValueError as error:
            raise RuntimeFailure("output_limit_invalid") from error
        if not 1 <= self.max_output_bytes <= MAX_OUTPUT_BYTES:
            raise RuntimeFailure("output_limit_invalid")
        if self.backend != "pipeline" or self.language not in {
            "ch",
            "ch_server",
            "korean",
            "ta",
            "te",
            "ka",
            "th",
            "el",
            "arabic",
            "east_slavic",
            "cyrillic",
            "devanagari",
        }:
            raise RuntimeFailure("ocr_mode_invalid")

        if sha256_file(Path(sys.executable)) != self.worker_sha256:
            raise RuntimeFailure("worker_integrity_failed")
        if sha256_file(config, MAX_SMALL_FILE_BYTES) != self.config_sha256:
            raise RuntimeFailure("config_integrity_failed")
        if sha256_file(model_manifest, MAX_SMALL_FILE_BYTES) != self.model_manifest_sha256:
            raise RuntimeFailure("model_integrity_failed")
        sha256_file(runtime_manifest, MAX_SMALL_FILE_BYTES)
        if not self.diagnostic_only:
            expected_identity = require_hash_env("LA_MINERU_SUPPORT_IDENTITY_SHA256")
            try:
                support_identity, support_tree = validate_support_manifest(
                    self.paths.support_manifest,
                    self.support_manifest_sha256,
                    Path(sys.executable),
                    full=False,
                )
            except SupportManifestFailure as error:
                raise RuntimeFailure("support_integrity_failed") from error
            if support_identity != expected_identity:
                raise RuntimeFailure("support_identity_failed")
            self.support_identity_sha256 = support_identity
            self.support_tree_sha256 = support_tree

        try:
            config_value = json.loads(config.read_text(encoding="utf-8"))
            manifest_value = json.loads(model_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeFailure("bound_json_invalid") from error
        if not isinstance(config_value, dict) or not isinstance(
            config_value.get("models-dir"), dict
        ):
            raise RuntimeFailure("config_invalid")
        for raw in config_value["models-dir"].values():
            if not isinstance(raw, str):
                raise RuntimeFailure("config_invalid")
            try:
                bound_model_path = Path(raw).resolve(strict=True)
            except OSError as error:
                raise RuntimeFailure("config_model_path_invalid") from error
            if not path_within_directory(bound_model_path, model_root):
                raise RuntimeFailure("config_model_path_invalid")
        if (
            not isinstance(manifest_value, dict)
            or not isinstance(manifest_value.get("version"), str)
            or not VERSION_RE.fullmatch(manifest_value["version"])
            or not isinstance(manifest_value.get("files"), list)
            or not manifest_value["files"]
        ):
            raise RuntimeFailure("model_manifest_invalid")
        self.model_version = manifest_value["version"]

        self.actual_device, self.gpu_driver_version, self.cuda_runtime_version = _gpu_identity(
            self.requested_device_value
        )
        self.python_version = platform.python_version()
        self.mineru_version = _version("mineru")
        self.pytorch_version = _version("torch")
        if not all(
            VERSION_RE.fullmatch(value)
            for value in (
                WORKER_VERSION,
                self.python_version,
                self.mineru_version,
                self.pytorch_version,
                self.cuda_runtime_version,
                self.gpu_driver_version,
                self.model_version,
            )
        ):
            raise RuntimeFailure("runtime_version_invalid")
        self.case_material_loaded = False

    def identity(self) -> dict[str, object]:
        return {
            "worker_version": WORKER_VERSION,
            "worker_sha256": self.worker_sha256,
            "python_version": self.python_version,
            "mineru_version": self.mineru_version,
            "pytorch_version": self.pytorch_version,
            "cuda_runtime_version": self.cuda_runtime_version,
            "gpu_driver_version": self.gpu_driver_version,
            "actual_device": self.actual_device,
            "model_version": self.model_version,
            "model_manifest_sha256": self.model_manifest_sha256,
            "config_sha256": self.config_sha256,
        }

    def requested_device(self) -> dict[str, object]:
        return dict(self.actual_device)

    def health(self) -> dict[str, object]:
        if self.case_material_loaded:
            raise RuntimeFailure("health_after_material_load")
        runtime_versions = sha256_hex(
            (
                "la-mineru-runtime-versions-v1\n"
                f"{WORKER_VERSION}\n"
                f"{self.python_version}\n"
                f"{self.mineru_version}\n"
                f"{self.pytorch_version}\n"
                f"{self.cuda_runtime_version}\n"
                f"{self.gpu_driver_version}\n"
                f"{self.model_version}\n"
            ).encode("utf-8")
        )
        gpu_hash = str(self.actual_device["hardware_fingerprint_sha256"])
        expected_job_policy = sha256_hex(JOB_POLICY_V1)
        if self.job_policy_sha256 != expected_job_policy:
            raise RuntimeFailure("job_policy_binding_invalid")
        checks = (
            ("worker_integrity", self.worker_sha256),
            ("config_integrity", self.config_sha256),
            ("model_integrity", self.model_manifest_sha256),
            ("runtime_versions", runtime_versions),
            ("support_integrity", self.support_identity_sha256),
            ("gpu_runtime", gpu_hash),
            ("offline_flags", sha256_hex(OFFLINE_POLICY_V1)),
            ("os_network_isolation", self.isolation_evidence_sha256),
            ("job_root_confinement", expected_job_policy),
        )
        return {
            "checked_at_unix": int(time.time()),
            "case_material_loaded": False,
            "checks": [
                {
                    "check_id": check_id,
                    "passed": True,
                    "evidence_sha256": evidence,
                    "reason_codes": [],
                }
                for check_id, evidence in checks
            ],
        }

    def validate_ocr_job_paths(self) -> None:
        allowed = {"input.pdf", "output", "cache"}
        observed = {entry.name for entry in self.paths.job_root.iterdir()}
        if not observed.issubset(allowed) or "input.pdf" not in observed or "output" not in observed:
            raise RuntimeFailure("job_tree_invalid")
        ordinary_path(self.paths.input_pdf, directory=False)
        ordinary_path(self.paths.output, directory=True)
        if self.paths.cache.exists():
            ordinary_path(self.paths.cache, directory=True)
        if any(self.paths.output.iterdir()):
            raise RuntimeFailure("output_not_empty")
