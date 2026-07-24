"""Managed NDJSON worker entry point."""

from __future__ import annotations

import os
import sys
import time
from typing import BinaryIO

from . import PROTOCOL_VERSION
from .output_document import OutputFailure, build_document
from .protocol import ProtocolViolation, ProtocolWriter, envelope, read_request
from .runtime import RuntimeFailure, WorkerRuntime
from .single_process import install_no_egress_audit_hook, run_mineru


def _redirect_runtime_output() -> tuple[BinaryIO, BinaryIO]:
    protocol_fd = os.dup(1)
    protocol_stream = os.fdopen(protocol_fd, "wb", buffering=0)
    null_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null_fd, 1)
    os.dup2(null_fd, 2)
    os.close(null_fd)
    sys.stdout = open(os.devnull, "w", encoding="utf-8", buffering=1)
    sys.stderr = open(os.devnull, "w", encoding="utf-8", buffering=1)
    return sys.stdin.buffer, protocol_stream


def _progress(
    writer: ProtocolWriter,
    request: dict[str, object],
    stage: str,
    completed_pages: int,
    started: float,
) -> None:
    response = envelope("progress", str(request["request_id"]))
    response.update(
        {
            "job_id": request["job_id"],
            "stage": stage,
            "completed_pages": completed_pages,
            "total_pages": request["expected_page_count"],
            "elapsed_ms": max(0, int((time.monotonic() - started) * 1000.0)),
            "reason_codes": [],
        }
    )
    writer.emit(response)


def _reason(error: BaseException) -> str:
    code = str(error)
    if code.startswith("mineru_execution_failed_") and len(code) <= 96 and all(
        character.isascii() and (character.isalnum() or character == "_") for character in code
    ):
        return code
    if "input_hash" in code:
        return "input_hash_mismatch"
    if "model" in code:
        return "model_integrity_failed"
    if "config" in code:
        return "config_integrity_failed"
    if "output_limit" in code or "too_large" in code:
        return "resource_limit_exceeded"
    if "output" in code or "middle" in code or "content" in code or "page_" in code:
        return "output_incomplete"
    if "forbidden" in code or "offline" in code or "isolation" in code:
        return "isolation_unverified"
    if "gpu" in code or "cuda" in code:
        return "gpu_unavailable"
    if "qualification" in code:
        return "qualification_invalid"
    return "worker_failure"


def _blocked_ocr(
    writer: ProtocolWriter,
    request: dict[str, object],
    reason: str,
) -> None:
    response = envelope("ocr", str(request["request_id"]))
    response.update(
        {
            "job_id": request["job_id"],
            "payload": {"status": "blocked", "reason_codes": [reason]},
        }
    )
    writer.emit(response)


def _run_ocr(
    runtime: WorkerRuntime,
    writer: ProtocolWriter,
    request: dict[str, object],
) -> None:
    started = time.monotonic()
    started_at_unix = int(time.time())
    _progress(writer, request, "accepted", 0, started)
    runtime.case_material_loaded = True
    try:
        _progress(writer, request, "loading_models", 0, started)
        _progress(writer, request, "rendering_pages", 0, started)
        _progress(writer, request, "layout_analysis", 0, started)
        _progress(writer, request, "ocr", 0, started)
        run_mineru(runtime, request)
        _progress(
            writer,
            request,
            "validating_output",
            int(request["expected_page_count"]),
            started,
        )
        document = build_document(
            runtime,
            request,
            started_at_unix=started_at_unix,
            started_monotonic=started,
        )
        _progress(
            writer,
            request,
            "finalizing",
            int(request["expected_page_count"]),
            started,
        )
        response = envelope("ocr", str(request["request_id"]))
        response.update(
            {
                "job_id": request["job_id"],
                "payload": {"status": "completed", "document": document},
            }
        )
        writer.emit(response)
    except (RuntimeFailure, OutputFailure, OSError, ValueError) as error:
        _progress(
            writer,
            request,
            "finalizing",
            int(request["expected_page_count"]),
            started,
        )
        _blocked_ocr(writer, request, _reason(error))


def _serve(input_stream: BinaryIO, writer: ProtocolWriter, runtime: WorkerRuntime) -> None:
    state = "new"
    active_job_id: str | None = None
    while True:
        try:
            request = read_request(input_stream)
        except ProtocolViolation:
            os._exit(70)
        if request is None:
            os._exit(0)
        message_type = str(request["message_type"])
        request_id = str(request["request_id"])

        if message_type == "hello" and state == "new":
            response = envelope("hello", request_id)
            response.update(
                {
                    "status": "ok",
                    "identity": runtime.identity(),
                    "reason_codes": [],
                }
            )
            writer.emit(response)
            state = "hello"
            continue

        if message_type == "health" and state == "hello":
            response = envelope("health", request_id)
            response.update(
                {
                    "status": "ok",
                    "report": runtime.health(),
                    "reason_codes": [],
                }
            )
            writer.emit(response)
            state = "healthy"
            continue

        if message_type == "ocr" and state == "healthy":
            active_job_id = str(request["job_id"])
            state = "ocr"
            _run_ocr(runtime, writer, request)
            state = "completed"
            continue

        if message_type == "cancel":
            response = envelope("cancel", request_id)
            response.update(
                {
                    "job_id": request["job_id"],
                    "status": "ok" if request["job_id"] == active_job_id else "blocked",
                    "reason_codes": []
                    if request["job_id"] == active_job_id
                    else ["cancelled_by_host"],
                }
            )
            writer.emit(response)
            continue

        if message_type == "shutdown" and state in {"healthy", "completed"}:
            response = envelope("shutdown", request_id)
            response.update({"status": "ok", "reason_codes": []})
            writer.emit(response)
            os._exit(0)

        os._exit(71)


def bootstrap() -> None:
    input_stream, protocol_stream = _redirect_runtime_output()
    writer = ProtocolWriter(protocol_stream)
    try:
        install_no_egress_audit_hook()
        runtime = WorkerRuntime()
        _serve(input_stream, writer, runtime)
    except BaseException:
        os._exit(72)
