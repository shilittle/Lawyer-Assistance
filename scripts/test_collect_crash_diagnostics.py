from __future__ import annotations

import datetime as dt
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import collect_crash_diagnostics as diagnostics


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeInspector(diagnostics.ProcessInspector):
    supported = True

    def __init__(self, snapshots: list[dict[int, diagnostics.RawProcess]]) -> None:
        self.snapshots = list(snapshots)
        self.last = snapshots[0]

    def list_processes(self) -> dict[int, diagnostics.RawProcess]:
        if self.snapshots:
            self.last = self.snapshots.pop(0)
        return self.last

    def start_token(self, pid: int) -> int | None:
        return 1000 + pid if pid in self.last else None

    def memory(self, pid: int) -> diagnostics.ProcessMemory:
        if pid not in self.last:
            return diagnostics.ProcessMemory("unavailable", error_category="process_not_found")
        return diagnostics.ProcessMemory("running", working_set_bytes=4096 + pid, private_bytes=8192 + pid)


def event_reader(*args: object, **kwargs: object) -> dict[str, object]:
    return {"status": "passed", "requested_channels": ["Application"], "channels": [], "event_count": 0}


class CollectCrashDiagnosticsTests(unittest.TestCase):
    def _processes(self) -> dict[int, diagnostics.RawProcess]:
        return {
            1: diagnostics.RawProcess(1, 0, "services.exe"),
            42: diagnostics.RawProcess(42, 1, "lawyer-assistance.exe"),
            43: diagnostics.RawProcess(43, 42, "lawyer-assistance.exe"),
        }

    def _write_process_event(self, directory: Path, *, pid: int, timestamp_unix_ms: int, event: str = "started") -> None:
        (directory / "process-launch.jsonl").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "timestamp_unix_ms": timestamp_unix_ms,
                    "event": event,
                    "build_revision": "a" * 40,
                    "launch_id": "launch-1",
                    "pid": pid,
                    "parent_pid": 1,
                    "role": "daemon",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_normal_window_records_target_parent_child_and_resource_curve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            diagnostics_dir = Path(directory) / "diagnostics"
            diagnostics_dir.mkdir()
            (diagnostics_dir / "process-launch.jsonl").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "timestamp_unix_ms": int(time.time() * 1000) + 100,
                        "event": "started",
                        "build_revision": "a" * 40,
                        "exe_sha256": "b" * 64,
                        "exe_hash_status": "available",
                        "launch_id": "launch-1",
                        "pid": 42,
                        "parent_pid": 1,
                        "role": "daemon",
                        "untrusted_body": "case text must not survive",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            clock = FakeClock()
            report = diagnostics.collect(
                42,
                duration_seconds=0.2,
                interval_ms=100,
                channels=("Application",),
                diagnostics_dir=diagnostics_dir,
                since=dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc),
                until=dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc),
                inspector=FakeInspector([self._processes()]),
                event_reader=event_reader,
                monotonic=clock.monotonic,
                sleeper=clock.sleep,
            )
            self.assertEqual("passed", report["status"])
            self.assertGreaterEqual(report["sample_count"], 2)
            self.assertEqual(42, report["target_pid"])
            self.assertEqual({1, 42, 43}, {item["pid"] for item in report["observed_related_processes"]})
            self.assertTrue(all("working_set_bytes" in row for sample in report["samples"] for row in sample["processes"] if row["state"] == "running"))
            self.assertEqual("passed", report["process_diagnostics"]["status"])
            event = report["process_diagnostics"]["events"][0]
            self.assertNotIn("untrusted_body", event)
            self.assertNotIn("case text must not survive", json.dumps(report, ensure_ascii=False))
            self.assertNotIn(r"C:\\private", json.dumps(report, ensure_ascii=False))
            self.assertFalse(report["restrictions"]["command_lines"])
            self.assertFalse(report["restrictions"]["dumps_enabled"])

    def test_external_target_exit_is_failed_and_records_exited_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            alive = self._processes()
            report = diagnostics.collect(
                42,
                duration_seconds=0.4,
                interval_ms=100,
                channels=("Application",),
                diagnostics_dir=Path(directory),
                inspector=FakeInspector([alive, alive, {}]),
                event_reader=event_reader,
                monotonic=clock.monotonic,
                sleeper=clock.sleep,
            )
            self.assertEqual("failed", report["status"])
            self.assertIn("target_exited", report["observations"])
            self.assertEqual("exited", report["samples"][-1]["processes"][0]["state"])

    def test_missing_process_log_cannot_be_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty"
            empty.mkdir()
            clock = FakeClock()
            report = diagnostics.collect(
                42,
                duration_seconds=0.1,
                interval_ms=100,
                channels=("Application",),
                diagnostics_dir=empty,
                inspector=FakeInspector([self._processes()]),
                event_reader=event_reader,
                monotonic=clock.monotonic,
                sleeper=clock.sleep,
            )
            self.assertEqual("blocked", report["status"])
            self.assertEqual("diagnostic_logs_missing", report["process_diagnostics"]["reason"])

    def test_parent_log_alone_cannot_prove_target_process_logging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            diagnostics_dir = Path(directory)
            self._write_process_event(
                diagnostics_dir,
                pid=1,
                timestamp_unix_ms=int(time.time() * 1000),
            )
            clock = FakeClock()
            report = diagnostics.collect(
                42,
                duration_seconds=0.1,
                interval_ms=100,
                channels=("Application",),
                diagnostics_dir=diagnostics_dir,
                inspector=FakeInspector([self._processes()]),
                event_reader=event_reader,
                monotonic=clock.monotonic,
                sleeper=clock.sleep,
            )
            self.assertEqual("blocked", report["status"])
            self.assertEqual("target_process_log_missing_or_stale", report["process_diagnostics"]["reason"])
            self.assertFalse(report["process_diagnostics"]["target_event_proof"])
            self.assertEqual("related_process", report["process_diagnostics"]["events"][0]["scope"])

    def test_same_pid_record_before_current_start_is_historical_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            diagnostics_dir = Path(directory)
            now_ms = int(time.time() * 1000)
            self._write_process_event(
                diagnostics_dir,
                pid=42,
                timestamp_unix_ms=now_ms - 2_000,
            )
            process_start = now_ms
            result = diagnostics.read_process_diagnostics(
                diagnostics_dir,
                {1, 42},
                target_pid=42,
                target_start_unix_ms=process_start,
            )
            self.assertEqual("blocked", result["status"])
            self.assertEqual("target_process_log_missing_or_stale", result["reason"])
            self.assertFalse(result["target_event_proof"])
            self.assertEqual("target_pid_before_current_start", result["events"][0]["scope"])

    def test_filetime_creation_token_is_converted_for_launch_boundary(self) -> None:
        creation_ms = 1_800_000_000_000
        token = diagnostics.WINDOWS_EPOCH_100NS + creation_ms * diagnostics.FILETIME_100NS_PER_MILLISECOND
        self.assertEqual(creation_ms, diagnostics.filetime_to_unix_ms(token))
        self.assertIsNone(diagnostics.filetime_to_unix_ms(1042))

    def test_omitted_diagnostics_directory_is_explicitly_not_run(self) -> None:
        report = diagnostics.collect(42, duration_seconds=0.1, interval_ms=100, inspector=FakeInspector([self._processes()]), event_reader=event_reader, monotonic=lambda: 0.0, sleeper=lambda _: None)
        self.assertEqual("blocked", report["status"])
        self.assertEqual("not_run", report["process_diagnostics"]["status"])
        self.assertEqual("diagnostics_dir_not_supplied", report["process_diagnostics"]["reason"])

    def test_sanitizer_projects_only_fixed_process_schema(self) -> None:
        raw = {
            "schema_version": 1,
            "timestamp_unix_ms": 10,
            "event": "panic",
            "build_revision": "a" * 40,
            "exe_sha256": "b" * 64,
            "exe_hash_status": "available",
            "launch_id": "launch-1",
            "pid": 42,
            "parent_pid": 1,
            "role": "daemon",
            "phase": "startup",
            "panic": {
                "source_module": r"C:\private\source.rs",
                "line": 7,
                "column": 3,
                "raw_stack": [
                    {"address_hex": "0x1234", "module_binding": "main_executable", "private_text": "secret"},
                    {"address_hex": "0x1235", "module_binding": "unbound_module"},
                    {"address_hex": "0x1236", "module_binding": "unresolved_module"},
                ],
            },
            "body": "private document text",
            "request_url": "https://private.invalid",
        }
        value = diagnostics.sanitize_process_event(raw, {1, 42})
        self.assertIsNotNone(value)
        assert value is not None
        self.assertNotIn("body", value)
        self.assertNotIn("request_url", value)
        self.assertEqual("source.rs", value["panic"]["source_module"])
        self.assertNotIn("private_text", value["panic"]["raw_stack"][0])
        self.assertEqual(
            ["main_executable", "unbound_module", "unresolved_module"],
            [frame["module_binding"] for frame in value["panic"]["raw_stack"]],
        )

    def test_unrelated_process_event_is_dropped(self) -> None:
        raw = {
            "timestamp_unix_ms": 10,
            "event": "started",
            "pid": 99,
            "role": "daemon",
        }
        self.assertIsNone(diagnostics.sanitize_process_event(raw, {42}))

    def test_event_xml_keeps_only_target_match_metadata(self) -> None:
        created = "2026-09-11T00:00:01.000Z"
        xml = f"""
        <Event><System><Provider Name="Application Error"/><EventID>1000</EventID>
        <Level>2</Level><TimeCreated SystemTime="{created}"/></System>
        <EventData><Data Name="ProcessId">42</Data><Data Name="ApplicationPath">C:\\private\\lawyer-assistance.exe</Data>
        <Data Name="FaultingModuleName">C:\\private\\pdfium.dll</Data><Data Name="ExceptionCode">0xc0000005</Data>
        <Data Name="FaultingOffset">0x123</Data><Data Name="Message">private body</Data></EventData></Event>
        """
        events = diagnostics.parse_event_xml(
            xml,
            "Application",
            dt.datetime(2026, 9, 11, tzinfo=dt.timezone.utc),
            dt.datetime(2026, 9, 11, 0, 0, 2, tzinfo=dt.timezone.utc),
            42,
            "lawyer-assistance.exe",
        )
        self.assertEqual(1, len(events))
        self.assertTrue(events[0]["target_match"])
        self.assertEqual("pid", events[0]["match_basis"])
        self.assertEqual("pdfium.dll", events[0]["faulting_module"])
        self.assertEqual("0xC0000005", events[0]["exception_code_hex"])
        self.assertEqual("0x0000000000000123", events[0]["faulting_offset_hex"])
        self.assertNotIn("ApplicationPath", events[0])
        self.assertNotIn("private body", json.dumps(events))

    def test_zero_duration_is_not_run(self) -> None:
        report = diagnostics.collect(42, duration_seconds=0, interval_ms=100)
        self.assertEqual("not_run", report["status"])
        self.assertEqual(0.0, report["elapsed_seconds"])

    def test_non_finite_duration_is_not_run(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                report = diagnostics.collect(42, duration_seconds=value, interval_ms=100)
                self.assertEqual("not_run", report["status"])

    def test_event_channel_is_fixed_allowlist(self) -> None:
        report = diagnostics.collect(42, duration_seconds=0.1, interval_ms=100, channels=("Custom/Private",))
        self.assertEqual("not_run", report["status"])
        self.assertIn("event channel", report["argument_error"])


if __name__ == "__main__":
    unittest.main()
