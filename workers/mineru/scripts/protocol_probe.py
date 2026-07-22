#!/usr/bin/env python3
"""Run a diagnostic direct worker probe with fixed synthetic PDFs only.

This does not replace App qualification: it does not install or attest Windows
Firewall rules and does not create the host Windows Job. The production App
performs both controls independently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO, Final

PROTOCOL_VERSION: Final = "la-mineru-worker-v1"
MAX_LINE_BYTES: Final = 128 * 1024 * 1024
ALLOWED_PREFIXES: Final = ("privacy-vnext-ocr-", "qualification-canary")
SAFE_RUNTIME_CODE: Final = re.compile(r"^[a-z][a-z0-9_]{1,95}$")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def opaque(prefix: str, seed: bytes) -> str:
    return f"{prefix}_{digest(seed)[:32]}"


def write_request(stream: BinaryIO, value: dict[str, object]) -> None:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stream.write(encoded + b"\n")
    stream.flush()


def read_response(stream: BinaryIO) -> dict[str, object]:
    line = stream.readline(MAX_LINE_BYTES + 2)
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES + 1:
        raise RuntimeError("worker_response_invalid")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise RuntimeError("worker_response_invalid")
    return value

class ResponseReader:
    """Continuously drain stdout so every protocol wait has a real deadline."""

    def __init__(
        self,
        stream: BinaryIO,
        process: subprocess.Popen[bytes] | None = None,
        stderr: BinaryIO | None = None,
    ) -> None:
        self._responses: queue.Queue[
            tuple[dict[str, object] | None, BaseException | None]
        ] = queue.Queue()

        def consume() -> None:
            try:
                while True:
                    self._responses.put((read_response(stream), None))
            except BaseException as error:
                if process is not None and stderr is not None:
                    exit_code = process.poll()
                    if exit_code is None:
                        try:
                            exit_code = process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            exit_code = None
                    if exit_code is not None:
                        captured = stderr.read(64 * 1024 + 1)
                        truncated = len(captured) > 64 * 1024
                        captured = captured[: 64 * 1024]
                        error = RuntimeError(
                            "worker_response_unavailable:"
                            f"exitCode={exit_code};"
                            f"stderrBytes={len(captured)};"
                            f"stderrSha256={digest(captured)};"
                            f"stderrTruncated={str(truncated).lower()}"
                        )
                self._responses.put((None, error))

        self._thread = threading.Thread(
            target=consume,
            name="mineru-protocol-probe-reader",
            daemon=True,
        )
        self._thread.start()

    def read(self, deadline: float) -> dict[str, object]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("worker_timeout")
        try:
            response, error = self._responses.get(timeout=remaining)
        except queue.Empty as timeout:
            raise RuntimeError("worker_timeout") from timeout
        if error is not None:
            if isinstance(error, RuntimeError) and str(error).startswith("worker_response_unavailable:"):
                raise RuntimeError(str(error)) from error
            raise RuntimeError("worker_response_unavailable") from error
        if response is None:
            raise RuntimeError("worker_response_unavailable")
        return response


def text_block_counts(document: dict[str, object]) -> tuple[list[int], int]:
    pages = document.get("pages")
    if not isinstance(pages, list):
        raise RuntimeError("worker_document_invalid")
    per_page: list[int] = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("blocks"), list):
            raise RuntimeError("worker_document_invalid")
        count = 0
        for block in page["blocks"]:
            if not isinstance(block, dict):
                raise RuntimeError("worker_document_invalid")
            text = block.get("normalized_text")
            if not isinstance(text, str):
                raise RuntimeError("worker_document_invalid")
            if text.strip():
                count += 1
        per_page.append(count)
    return per_page, sum(per_page)

def quality_summary(document: dict[str, object]) -> list[dict[str, object]]:
    """Return page quality metadata only; never return recognized text."""
    pages = document.get("pages")
    if not isinstance(pages, list):
        raise RuntimeError("worker_document_invalid")
    result: list[dict[str, object]] = []
    for expected_index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get("blocks"), list):
            raise RuntimeError("worker_document_invalid")
        warnings = page.get("warnings")
        risks = page.get("visual_risks")
        if (
            not isinstance(warnings, list)
            or not all(isinstance(value, str) for value in warnings)
            or not isinstance(risks, list)
            or not all(isinstance(value, str) for value in risks)
        ):
            raise RuntimeError("worker_document_invalid")
        result.append(
            {
                "pageIndex": expected_index,
                "status": page.get("status"),
                "rotationDegrees": page.get("rotation_degrees"),
                "coveragePpm": page.get("coverage_ppm"),
                "minimumOcrConfidencePpm": page.get(
                    "minimum_ocr_confidence_ppm"
                ),
                "meanOcrConfidencePpm": page.get("mean_ocr_confidence_ppm"),
                "visualRisks": risks,
                "warnings": warnings,
                "blockCount": len(page["blocks"]),
            }
        )
    return result


def page_count(path: Path) -> int:
    import pypdfium2

    document = pypdfium2.PdfDocument(str(path))
    try:
        count = len(document)
    finally:
        document.close()
    if not 1 <= count <= 200:
        raise RuntimeError("synthetic_page_count_invalid")
    return count


def strict_synthetic(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if (
        not resolved.is_file()
        or resolved.suffix.lower() != ".pdf"
        or not resolved.name.startswith(ALLOWED_PREFIXES)
        or resolved.stat().st_size > 64 * 1024 * 1024
    ):
        raise RuntimeError("only_fixed_synthetic_pdf_is_allowed")
    try:
        from pypdf import PdfReader

        text = "".join(page.extract_text() or "" for page in PdfReader(resolved).pages)
    except Exception as error:
        raise RuntimeError("synthetic_pdf_validation_failed") from error
    if text.strip():
        raise RuntimeError("synthetic_probe_requires_image_only_pdf")
    return resolved


def environment(
    *,
    worker: Path,
    job_root: Path,
    config: Path,
    model_root: Path,
    model_manifest: Path,
    runtime_manifest: Path,
) -> dict[str, str]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve(strict=True)
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files")).resolve(
        strict=True
    )
    isolation_hash = digest(b"diagnostic-only-synthetic-isolation-v1")
    job_policy_hash = digest(
        b"la-mineru-windows-job-v1\n"
        b"active-process-limit=1\n"
        b"kill-on-close=true\n"
        b"suspended-before-assign=true\n"
    )
    return {
        "PATH": str(worker.parent),
        "SystemRoot": str(system_root),
        "WINDIR": str(system_root),
        "ProgramFiles": str(program_files),
        "MINERU_MODEL_SOURCE": "local",
        "MINERU_TOOLS_CONFIG_JSON": str(config),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "DO_NOT_TRACK": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "socks5://127.0.0.1:9",
        "TEMP": str(job_root),
        "TMP": str(job_root),
        "USERPROFILE": str(job_root),
        "HOME": str(job_root),
        "XDG_CACHE_HOME": str(job_root / "cache"),
        "HF_HOME": str(job_root / "cache" / "huggingface"),
        "PADDLE_HOME": str(job_root / "cache" / "paddle"),
        "MPLCONFIGDIR": str(job_root / "cache" / "matplotlib"),
        "CUDA_VISIBLE_DEVICES": "0",
        "LA_MINERU_PROTOCOL_VERSION": PROTOCOL_VERSION,
        "LA_MINERU_DIAGNOSTIC_ONLY": "1",
        "LA_MINERU_WORKER_SHA256": file_digest(worker),
        "LA_MINERU_CONFIG_SHA256": file_digest(config),
        "LA_MINERU_CONFIG_PATH": str(config),
        "LA_MINERU_MODEL_ROOT": str(model_root),
        "LA_MINERU_MODEL_MANIFEST_PATH": str(model_manifest),
        "LA_MINERU_RUNTIME_MANIFEST_PATH": str(runtime_manifest),
        "LA_MINERU_BACKEND": "pipeline",
        "LA_MINERU_LANGUAGE": "ch",
        "LA_MINERU_REQUESTED_DEVICE": "cuda:0",
        "LA_MINERU_MAX_OUTPUT_BYTES": str(512 * 1024 * 1024),
        "LA_MINERU_MODEL_MANIFEST_SHA256": file_digest(model_manifest),
        "LA_MINERU_ISOLATION_EVIDENCE_ID": opaque("iso", isolation_hash.encode()),
        "LA_MINERU_ISOLATION_EVIDENCE_SHA256": isolation_hash,
        "LA_MINERU_QUALIFICATION_REPORT_ID": opaque("qrep", b"diagnostic"),
        "LA_MINERU_JOB_POLICY_SHA256": job_policy_hash,
    }


def preflight_runtime(worker: Path, job_root: Path, worker_env: dict[str, str]) -> None:
    """Expose only the worker's stable failure code for a synthetic diagnostic."""
    preflight_env = dict(worker_env)
    preflight_env.pop("LA_MINERU_PROTOCOL_VERSION", None)
    code = (
        "import os\n"
        f"os.environ['LA_MINERU_PROTOCOL_VERSION']={PROTOCOL_VERSION!r}\n"
        "from lawyer_assistance_mineru_worker.single_process import "
        "install_no_egress_audit_hook\n"
        "from lawyer_assistance_mineru_worker.runtime import RuntimeFailure, WorkerRuntime\n"
        "install_no_egress_audit_hook()\n"
        "try:\n"
        "    WorkerRuntime()\n"
        "except RuntimeFailure as error:\n"
        "    print(str(error))\n"
        "    raise SystemExit(90)\n"
        "except BaseException:\n"
        "    print('worker_runtime_exception')\n"
        "    raise SystemExit(91)\n"
        "print('ok')\n"
    )
    try:
        completed = subprocess.run(
            [str(worker), "-c", code],
            cwd=job_root,
            env=preflight_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("worker_runtime_preflight_timeout") from error
    output = completed.stdout.decode("ascii", "ignore").strip()
    if completed.returncode != 0 or output != "ok" or completed.stderr:
        safe_code = output if SAFE_RUNTIME_CODE.fullmatch(output) else "worker_runtime_preflight_failed"
        raise RuntimeError(f"worker_runtime_preflight:{safe_code}")


def run(arguments: argparse.Namespace) -> dict[str, object]:
    worker = arguments.worker.resolve(strict=True)
    pdf = strict_synthetic(arguments.pdf)
    config = arguments.tools_config.resolve(strict=True)
    model_root = arguments.model_root.resolve(strict=True)
    model_manifest = arguments.model_manifest.resolve(strict=True)
    runtime_manifest = arguments.runtime_manifest.resolve(strict=True)
    if not worker.is_file() or not model_root.is_dir():
        raise RuntimeError("bound_input_invalid")

    with tempfile.TemporaryDirectory(prefix="la-mineru-synthetic-probe-") as temporary:
        job_root = Path(temporary).resolve()
        shutil.copyfile(pdf, job_root / "input.pdf")
        (job_root / "output").mkdir()
        for child in ("cache", "cache/huggingface", "cache/paddle", "cache/matplotlib"):
            (job_root / child).mkdir(exist_ok=True)
        source_sha256 = file_digest(job_root / "input.pdf")
        count = page_count(job_root / "input.pdf")
        request_id = opaque("req", source_sha256.encode())
        job_id = opaque("job", request_id.encode())
        worker_env = environment(
            worker=worker,
            job_root=job_root,
            config=config,
            model_root=model_root,
            model_manifest=model_manifest,
            runtime_manifest=runtime_manifest,
        )
        preflight_runtime(worker, job_root, worker_env)
        process = subprocess.Popen(
            [str(worker)],
            cwd=job_root,
            env=worker_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("worker_pipe_unavailable")
        started = time.monotonic()
        deadline = started + arguments.timeout_seconds
        reader = ResponseReader(process.stdout, process, process.stderr)
        try:
            hello_id = opaque("hello", b"hello")
            write_request(
                process.stdin,
                {
                    "message_type": "hello",
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": hello_id,
                },
            )
            hello = reader.read(deadline)
            health_id = opaque("health", b"health")
            write_request(
                process.stdin,
                {
                    "message_type": "health",
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": health_id,
                },
            )
            health = reader.read(deadline)
            write_request(
                process.stdin,
                {
                    "message_type": "ocr",
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": request_id,
                    "job_id": job_id,
                    "document_id": opaque("doc", source_sha256.encode()),
                    "input_id": opaque("input", job_id.encode()),
                    "expected_output_id": opaque("output", job_id.encode()),
                    "source_sha256": source_sha256,
                    "processing_parameters_sha256": digest(
                        b"diagnostic-synthetic-processing-v1"
                    ),
                    "expected_page_count": count,
                },
            )
            progress = 0
            document: dict[str, object] | None = None
            while time.monotonic() < deadline:
                response = reader.read(deadline)
                if response.get("message_type") == "progress":
                    progress += 1
                    continue
                if response.get("message_type") != "ocr":
                    raise RuntimeError("worker_sequence_invalid")
                payload = response.get("payload")
                if not isinstance(payload, dict) or payload.get("status") != "completed":
                    reason_codes = payload.get("reason_codes") if isinstance(payload, dict) else None
                    safe_codes = (
                        ",".join(value for value in reason_codes if isinstance(value, str))
                        if isinstance(reason_codes, list)
                        else "invalid"
                    )
                    raise RuntimeError(f"worker_ocr_blocked:{safe_codes[:192]}")
                candidate = payload.get("document")
                if not isinstance(candidate, dict):
                    raise RuntimeError("worker_document_missing")
                document = candidate
                break
            if document is None:
                raise RuntimeError("worker_timeout")
            shutdown_id = opaque("shutdown", b"shutdown")
            write_request(
                process.stdin,
                {
                    "message_type": "shutdown",
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": shutdown_id,
                },
            )
            shutdown = reader.read(time.monotonic() + 10)
            process.stdin.close()
            if process.wait(timeout=10) != 0:
                raise RuntimeError("worker_exit_failed")
            stderr = process.stderr.read(1)
            if stderr:
                raise RuntimeError("worker_stderr_not_empty")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        identity = hello.get("identity")
        report = health.get("report")
        if (
            hello.get("status") != "ok"
            or health.get("status") != "ok"
            or not isinstance(identity, dict)
            or not isinstance(report, dict)
            or report.get("case_material_loaded") is not False
            or shutdown.get("status") != "ok"
        ):
            raise RuntimeError("worker_probe_failed")
        pages = document.get("pages")
        if (
            document.get("source_sha256") != source_sha256
            or document.get("page_count") != count
            or not isinstance(pages, list)
            or len(pages) != count
        ):
            raise RuntimeError("worker_document_invalid")
        per_page_text_blocks, total_text_blocks = text_block_counts(document)
        return {
            "ok": True,
            "diagnosticOnly": True,
            "syntheticOnly": True,
            "protocolVersion": PROTOCOL_VERSION,
            "workerVersion": identity.get("worker_version"),
            "mineruVersion": identity.get("mineru_version"),
            "pytorchVersion": identity.get("pytorch_version"),
            "cudaRuntimeVersion": identity.get("cuda_runtime_version"),
            "gpuDriverVersion": identity.get("gpu_driver_version"),
            "pageCount": count,
            "progressMessages": progress,
            "perPageTextBlockCounts": per_page_text_blocks,
            "totalTextBlockCount": total_text_blocks,
            "perPageQuality": quality_summary(document),
            "documentWarnings": document.get("warnings"),
            "sourceSha256": source_sha256,
            "outputSha256": document.get("output_sha256"),
            "durationMs": int((time.monotonic() - started) * 1000),
        }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--worker", type=Path, required=True)
    value.add_argument("--pdf", type=Path, required=True)
    value.add_argument("--tools-config", type=Path, required=True)
    value.add_argument("--model-root", type=Path, required=True)
    value.add_argument("--model-manifest", type=Path, required=True)
    value.add_argument("--runtime-manifest", type=Path, required=True)
    value.add_argument("--timeout-seconds", type=int, default=600)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        result = run(arguments)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {"ok": False, "code": str(error)[:224]},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
