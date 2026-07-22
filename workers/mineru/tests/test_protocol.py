import io
import json
import unittest

from lawyer_assistance_mineru_worker import PROTOCOL_VERSION
from lawyer_assistance_mineru_worker.protocol import (
    MAX_REQUEST_LINE_BYTES,
    ProtocolViolation,
    ProtocolWriter,
    decode_request,
    read_request,
)


def opaque(prefix: str, digit: str) -> str:
    return f"{prefix}_{digit * 32}"


def ocr_request() -> dict[str, object]:
    return {
        "message_type": "ocr",
        "protocol_version": PROTOCOL_VERSION,
        "request_id": opaque("req", "1"),
        "job_id": opaque("job", "2"),
        "document_id": opaque("doc", "3"),
        "input_id": opaque("input", "4"),
        "expected_output_id": opaque("output", "5"),
        "source_sha256": "a" * 64,
        "processing_parameters_sha256": "b" * 64,
        "expected_page_count": 3,
    }


class ProtocolCodecTests(unittest.TestCase):
    def test_valid_requests_and_crlf_are_accepted(self) -> None:
        encoded = json.dumps(ocr_request(), separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(decode_request(encoded), ocr_request())
        stream = io.BytesIO(encoded + b"\r\n")
        self.assertEqual(read_request(stream), ocr_request())
        self.assertIsNone(read_request(stream))

    def test_duplicate_unknown_wrong_version_and_nonfinite_are_rejected(self) -> None:
        with self.assertRaisesRegex(ProtocolViolation, "duplicate_field"):
            decode_request(
                b'{"message_type":"hello","protocol_version":"la-mineru-worker-v1",'
                b'"request_id":"req_11111111111111111111111111111111",'
                b'"request_id":"req_22222222222222222222222222222222"}'
            )
        invalid = ocr_request()
        invalid["case_path"] = "C:/synthetic.pdf"
        with self.assertRaisesRegex(ProtocolViolation, "field_set_invalid"):
            decode_request(json.dumps(invalid, separators=(",", ":")).encode())
        invalid = ocr_request()
        invalid["protocol_version"] = "future"
        with self.assertRaisesRegex(ProtocolViolation, "envelope_invalid"):
            decode_request(json.dumps(invalid, separators=(",", ":")).encode())
        raw = json.dumps(ocr_request(), separators=(",", ":")).replace("3}", "NaN}").encode()
        with self.assertRaises(ProtocolViolation):
            decode_request(raw)

    def test_ocr_identifiers_hashes_and_page_limits_fail_closed(self) -> None:
        mutations = (
            ("input_id", opaque("output", "5")),
            ("source_sha256", "A" * 64),
            ("expected_page_count", True),
            ("expected_page_count", 0),
            ("expected_page_count", 10_001),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                request = ocr_request()
                request[field] = value
                with self.assertRaises(ProtocolViolation):
                    decode_request(json.dumps(request, separators=(",", ":")).encode())

    def test_line_framing_and_response_writer_are_bounded_and_deterministic(self) -> None:
        encoded = json.dumps(ocr_request(), separators=(",", ":")).encode()
        with self.assertRaisesRegex(ProtocolViolation, "line_invalid"):
            read_request(io.BytesIO(encoded))
        with self.assertRaisesRegex(ProtocolViolation, "line_invalid"):
            decode_request(b"{" + b" " * MAX_REQUEST_LINE_BYTES + b"}")
        stream = io.BytesIO()
        writer = ProtocolWriter(stream)
        writer.emit({"z": 1, "a": "synthetic"})
        self.assertEqual(stream.getvalue(), b'{"a":"synthetic","z":1}\n')
        with self.assertRaises(ValueError):
            writer.emit({"bad": float("nan")})


if __name__ == "__main__":
    unittest.main()
