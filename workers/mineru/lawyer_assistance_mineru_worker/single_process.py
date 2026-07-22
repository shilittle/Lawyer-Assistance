"""Invoke MinerU 3.4.3 in-process without any child-process renderer."""

from __future__ import annotations

import concurrent.futures
import hashlib
import sys
from pathlib import Path
from typing import Final

from .runtime import RuntimeFailure, WorkerRuntime

MAX_INPUT_BYTES: Final = 64 * 1024 * 1024


class ImmediateExecutor:
    """The small Executor surface used by MinerU's PDF rendering helper."""

    _max_workers = 1
    _processes: dict[object, object] = {}

    def submit(self, function: object, /, *args: object, **kwargs: object) -> concurrent.futures.Future:
        future: concurrent.futures.Future = concurrent.futures.Future()
        if not future.set_running_or_notify_cancel():
            return future
        try:
            result = function(*args, **kwargs)
        except BaseException as error:
            future.set_exception(error)
        else:
            future.set_result(result)
        return future

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        del wait, cancel_futures


def install_no_egress_audit_hook() -> None:
    blocked = {
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "socket.connect",
        "socket.getaddrinfo",
    }

    def audit(event: str, _arguments: tuple[object, ...]) -> None:
        if event in blocked:
            raise RuntimeFailure("forbidden_runtime_operation")

    sys.addaudithook(audit)


def _patch_pdf_renderer() -> object:
    import mineru.utils.pdf_image_tools as pdf_tools

    executor = ImmediateExecutor()
    pdf_tools._create_pdf_render_executor = lambda max_workers: ImmediateExecutor()
    pdf_tools._pdf_render_executor = executor
    return pdf_tools


def run_mineru(runtime: WorkerRuntime, request: dict[str, object]) -> None:
    runtime.validate_ocr_job_paths()
    input_size = runtime.paths.input_pdf.stat().st_size
    if not 1 <= input_size <= MAX_INPUT_BYTES:
        raise RuntimeFailure("input_size_invalid")
    pdf_bytes = runtime.paths.input_pdf.read_bytes()
    if len(pdf_bytes) != input_size:
        raise RuntimeFailure("input_read_incomplete")
    if hashlib.sha256(pdf_bytes).hexdigest() != request["source_sha256"]:
        raise RuntimeFailure("input_hash_mismatch")
    if runtime.paths.output.resolve(strict=True).parent != runtime.paths.job_root:
        raise RuntimeFailure("output_path_invalid")

    pdf_tools = _patch_pdf_renderer()
    try:
        from mineru.cli.common import do_parse

        do_parse(
            output_dir=str(runtime.paths.output),
            pdf_file_names=["document"],
            pdf_bytes_list=[pdf_bytes],
            p_lang_list=[runtime.language],
            backend=runtime.backend,
            parse_method="ocr",
            formula_enable=True,
            table_enable=True,
            server_url=None,
            f_draw_layout_bbox=False,
            f_draw_span_bbox=False,
            f_dump_md=True,
            f_dump_middle_json=True,
            f_dump_model_output=False,
            f_dump_orig_pdf=False,
            f_dump_content_list=True,
            f_make_md_mode="mm_markdown",
            start_page_id=0,
            end_page_id=int(request["expected_page_count"]) - 1,
            image_analysis=True,
            client_side_output_generation=False,
        )
    except RuntimeFailure:
        raise
    except BaseException as error:
        if runtime.diagnostic_only:
            error_class = type(error).__name__.lower()
            if isinstance(error, ImportError) and isinstance(error.name, str):
                module = "".join(
                    character.lower() if character.isascii() and character.isalnum() else "_"
                    for character in error.name
                ).strip("_")[:48]
                if module:
                    error_class = f"{error_class}_{module}"
            if error_class and all(
                character.isascii() and (character.isalnum() or character == "_")
                for character in error_class
            ):
                raise RuntimeFailure(f"mineru_execution_failed_{error_class}") from error
        raise RuntimeFailure("mineru_execution_failed") from error
    finally:
        try:
            pdf_tools.shutdown_pdf_render_executor()
        except BaseException:
            pass

    if hashlib.sha256(runtime.paths.input_pdf.read_bytes()).hexdigest() != request["source_sha256"]:
        raise RuntimeFailure("input_hash_changed")
