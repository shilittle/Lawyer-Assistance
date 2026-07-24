"""Strict NDJSON codec for ``la-mineru-worker-v1``.

This module intentionally depends only on the Python standard library so it
can reject malformed input before importing OCR runtimes.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import BinaryIO, Final

from . import PROTOCOL_VERSION


MAX_REQUEST_LINE_BYTES: Final = 1024 * 1024
MAX_RESPONSE_LINE_BYTES: Final = 128 * 1024 * 1024
MAX_ID_BYTES: Final = 49
HASH_RE: Final = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID_RE: Final = re.compile(r"^[a-z][a-z0-9]{1,15}_[0-9a-f]{32}$")

REQUEST_FIELDS: Final = {
    "hello": {"message_type", "protocol_version", "request_id"},
    "health": {"message_type", "protocol_version", "request_id"},
    "ocr": {
        "message_type",
        "protocol_version",
        "request_id",
        "job_id",
        "document_id",
        "input_id",
        "expected_output_id",
        "source_sha256",
        "processing_parameters_sha256",
        "expected_page_count",
    },
    "cancel": {"message_type", "protocol_version", "request_id", "job_id"},
    "shutdown": {"message_type", "protocol_version", "request_id"},
}


class ProtocolViolation(ValueError):
    """A stable protocol rejection that never contains request material."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise ProtocolViolation("duplicate_field")
        value[key] = child
    return value


def _opaque(value: object) -> bool:
    return isinstance(value, str) and len(value.encode("utf-8")) <= MAX_ID_BYTES and bool(
        OPAQUE_ID_RE.fullmatch(value)
    )


def _hash(value: object) -> bool:
    return isinstance(value, str) and bool(HASH_RE.fullmatch(value))


def decode_request(line: bytes) -> dict[str, object]:
    if not line or len(line) > MAX_REQUEST_LINE_BYTES or line[:1] != b"{" or line[-1:] != b"}":
        raise ProtocolViolation("line_invalid")
    try:
        value = json.loads(
            line,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ProtocolViolation("number_invalid")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolViolation("json_invalid") from error
    if not isinstance(value, dict):
        raise ProtocolViolation("request_invalid")
    message_type = value.get("message_type")
    if not isinstance(message_type, str) or message_type not in REQUEST_FIELDS:
        raise ProtocolViolation("message_type_invalid")
    if set(value) != REQUEST_FIELDS[message_type]:
        raise ProtocolViolation("field_set_invalid")
    if value.get("protocol_version") != PROTOCOL_VERSION or not _opaque(value.get("request_id")):
        raise ProtocolViolation("envelope_invalid")
    if message_type == "ocr":
        ids = [value.get(name) for name in ("job_id", "document_id", "input_id", "expected_output_id")]
        if not all(_opaque(item) for item in ids) or value["input_id"] == value["expected_output_id"]:
            raise ProtocolViolation("opaque_id_invalid")
        if not _hash(value.get("source_sha256")) or not _hash(
            value.get("processing_parameters_sha256")
        ):
            raise ProtocolViolation("hash_invalid")
        page_count = value.get("expected_page_count")
        if isinstance(page_count, bool) or not isinstance(page_count, int) or not 1 <= page_count <= 10_000:
            raise ProtocolViolation("page_count_invalid")
    elif message_type == "cancel" and not _opaque(value.get("job_id")):
        raise ProtocolViolation("opaque_id_invalid")
    return value


def read_request(stream: BinaryIO) -> dict[str, object] | None:
    line = stream.readline(MAX_REQUEST_LINE_BYTES + 2)
    if not line:
        return None
    if len(line) > MAX_REQUEST_LINE_BYTES + 1 or not line.endswith(b"\n"):
        raise ProtocolViolation("line_invalid")
    line = line[:-1]
    if line.endswith(b"\r"):
        line = line[:-1]
    return decode_request(line)


class ProtocolWriter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def emit(self, value: dict[str, object]) -> None:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        if not encoded or len(encoded) > MAX_RESPONSE_LINE_BYTES or encoded[:1] != b"{":
            raise ProtocolViolation("response_too_large")
        with self._lock:
            self._stream.write(encoded)
            self._stream.write(b"\n")
            self._stream.flush()


def envelope(message_type: str, request_id: str) -> dict[str, object]:
    return {
        "message_type": message_type,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
    }
