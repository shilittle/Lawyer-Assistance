"""Collect a bounded, read-only process crash diagnostic record on Windows.

The collector is deliberately narrower than a crash-dump tool.  It samples
one caller-selected PID, the parent and descendants observed through the
Windows process snapshot, and a small whitelist of Application/WER events.
It never reads command lines, persists executable paths, reads document
content, enables WER dumps, restarts a process, uploads data, or stays
resident after the requested window.

The command writes one JSON report and prints the same JSON object to stdout.
Exit codes are status based: 0=passed, 1=failed, 2=blocked, 3=not_run.  A
missing event-log query is therefore visible as ``blocked`` and can never be
silently reported as a successful collection.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
DEFAULT_DURATION_SECONDS = 10.0
DEFAULT_INTERVAL_MS = 500
MAX_DURATION_SECONDS = 600.0
MIN_INTERVAL_MS = 100
MAX_INTERVAL_MS = 10_000
MAX_SAMPLES = 6_000
MAX_RELATED_PROCESSES = 128
MAX_EVENT_BYTES = 2 * 1024 * 1024
MAX_EVENTS_PER_CHANNEL = 64
MAX_DIAGNOSTIC_FILE_BYTES = 256 * 1024
MAX_DIAGNOSTIC_FILES = 64
MAX_DIAGNOSTIC_LINE_BYTES = 64 * 1024
EVENT_CHANNELS = ("Application", "Microsoft-Windows-WER-Diag/Operational")
EVENT_IDS = frozenset({1000, 1001})
WINDOWS_EPOCH_100NS = 116_444_736_000_000_000
FILETIME_100NS_PER_MILLISECOND = 10_000
STATUS_EXIT_CODES = {"passed": 0, "failed": 1, "blocked": 2, "not_run": 3}
PROCESS_EVENT_NAMES = frozenset(
    {
        "started",
        "phase",
        "operation_started",
        "operation_finished",
        "operation_failed",
        "startup_failed",
        "unexpected_stop",
        "normal_stop",
        "child_started",
        "termination_intent",
        "child_exit",
        "worker_runtime_failed",
        "panic",
    }
)
PROCESS_ROLES = frozenset({"daemon", "document_worker", "diagnostics", "diagnostic_fault"})
PROCESS_RESULTS = frozenset({"completed", "failed"})
PROCESS_EXIT_SOURCES = frozenset({"natural", "after_cleanup"})
PROCESS_TERMINATION_INTENTS = frozenset({"cancelled", "timeout", "parent_cleanup", "job_cleanup", "shutdown"})
PROCESS_HASH_STATUSES = frozenset({"available", "unavailable", "mismatch", "unknown"})
SAFE_HEX = re.compile(r"^(?:0x)?[0-9a-fA-F]{1,16}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
REVISION = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_TAG = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SAFE_PROVIDER = re.compile(r"^[A-Za-z0-9 ._:-]{1,128}$")
MODULE_BINDING = re.compile(r"^(?:main_executable|unbound_module|unresolved_module)$")
PDB_IDENTITY = re.compile(r"^rsds-[0-9a-fA-F]{32}-[0-9]{1,10}$")


class DiagnosticError(RuntimeError):
    """An expected, safe-to-report diagnostic error category."""

    def __init__(self, category: str, *, blocked: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.blocked = blocked


@dataclass(frozen=True)
class RawProcess:
    pid: int
    parent_pid: int
    image_name: str | None


@dataclass(frozen=True)
class ProcessMemory:
    state: str
    working_set_bytes: int | None = None
    private_bytes: int | None = None
    error_category: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"state": self.state}
        if self.working_set_bytes is not None:
            value["working_set_bytes"] = self.working_set_bytes
        if self.private_bytes is not None:
            value["private_commit_bytes"] = self.private_bytes
        if self.error_category is not None:
            value["error_category"] = self.error_category
        return value


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def parse_timestamp(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def bounded_duration(value: float) -> float:
    if not math.isfinite(value) or value < 0 or value > MAX_DURATION_SECONDS:
        raise ValueError(f"duration must be between 0 and {MAX_DURATION_SECONDS:g} seconds")
    return value


def filetime_to_unix_ms(value: int | None) -> int | None:
    """Convert a Windows process creation FILETIME without exposing a path.

    ``GetProcessTimes`` returns 100 ns ticks since 1601-01-01.  Test doubles
    often use small opaque tokens, so values that cannot be a plausible
    FILETIME remain unbound rather than being treated as a wall-clock time.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= WINDOWS_EPOCH_100NS:
        return None
    unix_ms = (value - WINDOWS_EPOCH_100NS) // FILETIME_100NS_PER_MILLISECOND
    if unix_ms < 0 or unix_ms > 9_999_999_999_999:
        return None
    return unix_ms


def bounded_interval(value: int) -> int:
    if value < MIN_INTERVAL_MS or value > MAX_INTERVAL_MS:
        raise ValueError(f"interval must be between {MIN_INTERVAL_MS} and {MAX_INTERVAL_MS} milliseconds")
    return value


def validate_channels(value: Sequence[str]) -> tuple[str, ...]:
    channels = tuple(value)
    if any(channel not in EVENT_CHANNELS for channel in channels):
        raise ValueError("event channel is outside the fixed Application/WER allowlist")
    return channels


def validate_pid(value: int) -> int:
    if value <= 0 or value > 0xFFFFFFFF:
        raise ValueError("pid must be a positive Windows process id")
    return value


def safe_image_name(value: str | None) -> str | None:
    """Keep only a basename-like identity, never an executable path."""

    if not value:
        return None
    basename = value.replace("/", "\\").rsplit("\\", 1)[-1].strip()
    if not basename or len(basename) > 128:
        return None
    # Process32First already returns a basename.  This check prevents an
    # accidental future caller from persisting a path or control characters.
    if "\\" in basename or "/" in basename or any(ord(char) < 0x20 for char in basename):
        return None
    return basename


def safe_provider_name(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    return value if SAFE_PROVIDER.fullmatch(value) else None


class ProcessInspector:
    """Small injectable interface used by collection code and unit tests."""

    supported = False

    def list_processes(self) -> dict[int, RawProcess]:
        raise DiagnosticError("process_snapshot_unavailable", blocked=True)

    def start_token(self, pid: int) -> int | None:
        return None

    def memory(self, pid: int) -> ProcessMemory:
        return ProcessMemory("unavailable", error_category="process_inspector_unavailable")


if sys.platform == "win32":

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_int32),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]


    class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("PageFaultCount", ctypes.c_uint32),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]


    class WindowsProcessInspector(ProcessInspector):
        supported = True
        _SNAPSHOT_FLAGS = 0x00000002  # TH32CS_SNAPPROCESS
        _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        _PROCESS_VM_READ = 0x0010
        _ERROR_ACCESS_DENIED = 5
        _ERROR_INVALID_PARAMETER = 87

        def __init__(self) -> None:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._psapi = ctypes.WinDLL("psapi", use_last_error=True)
            self._kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            self._kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            self._kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
            self._kernel32.Process32FirstW.restype = ctypes.c_int
            self._kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
            self._kernel32.Process32NextW.restype = ctypes.c_int
            self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            self._kernel32.CloseHandle.restype = ctypes.c_int
            self._kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
            self._kernel32.OpenProcess.restype = ctypes.c_void_p
            self._kernel32.GetProcessTimes.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
            ]
            self._kernel32.GetProcessTimes.restype = ctypes.c_int
            self._psapi.GetProcessMemoryInfo.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_PROCESS_MEMORY_COUNTERS_EX),
                ctypes.c_uint32,
            ]
            self._psapi.GetProcessMemoryInfo.restype = ctypes.c_int

        def _close(self, handle: ctypes.c_void_p | None) -> None:
            if handle:
                self._kernel32.CloseHandle(handle)

        def list_processes(self) -> dict[int, RawProcess]:
            snapshot = self._kernel32.CreateToolhelp32Snapshot(self._SNAPSHOT_FLAGS, 0)
            if snapshot in (None, ctypes.c_void_p(-1).value):
                error = ctypes.get_last_error()
                raise DiagnosticError(
                    "process_snapshot_access_denied" if error == self._ERROR_ACCESS_DENIED else "process_snapshot_failed",
                    blocked=error == self._ERROR_ACCESS_DENIED,
                )
            result: dict[int, RawProcess] = {}
            try:
                entry = _PROCESSENTRY32W()
                entry.dwSize = ctypes.sizeof(entry)
                if not self._kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                    raise DiagnosticError("process_snapshot_empty", blocked=True)
                while True:
                    pid = int(entry.th32ProcessID)
                    if pid:
                        result[pid] = RawProcess(
                            pid=pid,
                            parent_pid=int(entry.th32ParentProcessID),
                            image_name=safe_image_name(entry.szExeFile),
                        )
                    if not self._kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
            finally:
                self._close(snapshot)
            return result

        def _open(self, pid: int) -> ctypes.c_void_p | None:
            return self._kernel32.OpenProcess(
                self._PROCESS_QUERY_LIMITED_INFORMATION | self._PROCESS_VM_READ,
                0,
                pid,
            )

        def start_token(self, pid: int) -> int | None:
            handle = self._open(pid)
            if not handle:
                return None
            try:
                created, exited, kernel, user = (_FILETIME(), _FILETIME(), _FILETIME(), _FILETIME())
                if not self._kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(created),
                    ctypes.byref(exited),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return None
                return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
            finally:
                self._close(handle)

        def memory(self, pid: int) -> ProcessMemory:
            handle = self._open(pid)
            if not handle:
                error = ctypes.get_last_error()
                category = "process_not_found" if error == self._ERROR_INVALID_PARAMETER else "process_memory_access_denied"
                return ProcessMemory("unavailable", error_category=category)
            try:
                counters = _PROCESS_MEMORY_COUNTERS_EX()
                counters.cb = ctypes.sizeof(counters)
                if not self._psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    error = ctypes.get_last_error()
                    category = "process_not_found" if error == self._ERROR_INVALID_PARAMETER else "process_memory_query_failed"
                    return ProcessMemory("unavailable", error_category=category)
                return ProcessMemory(
                    "running",
                    working_set_bytes=int(counters.WorkingSetSize),
                    private_bytes=int(counters.PrivateUsage),
                )
            finally:
                self._close(handle)


else:

    class WindowsProcessInspector(ProcessInspector):
        """Explicitly blocked outside Windows; no portable process fallback."""

        supported = False


def relation_roles(target_pid: int, processes: Mapping[int, RawProcess]) -> dict[int, str]:
    """Return target, its observed parent, and descendant roles only."""

    target = processes.get(target_pid)
    if target is None:
        return {}
    roles: dict[int, str] = {target_pid: "target"}
    if target.parent_pid in processes and target.parent_pid != target_pid:
        roles[target.parent_pid] = "parent"
    queue = [target_pid]
    while queue and len(roles) < MAX_RELATED_PROCESSES:
        parent = queue.pop(0)
        for pid, process in processes.items():
            if process.parent_pid == parent and pid not in roles:
                roles[pid] = "child"
                queue.append(pid)
                if len(roles) >= MAX_RELATED_PROCESSES:
                    break
    return roles


def make_identity(process: RawProcess, role: str, start_token: int | None, observed_at: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "pid": process.pid,
        "parent_pid": process.parent_pid,
        "role": role,
        "image_name": process.image_name,
        "first_observed_at": observed_at,
        "start_token": start_token,
    }
    start_time = filetime_to_unix_ms(start_token)
    if start_time is not None:
        value["start_time_unix_ms"] = start_time
    return value


def update_identities(
    identities: dict[tuple[int, int | None], dict[str, Any]],
    processes: Mapping[int, RawProcess],
    roles: Mapping[int, str],
    inspector: ProcessInspector,
    observed_at: str,
) -> None:
    for pid, role in roles.items():
        process = processes.get(pid)
        if process is None:
            continue
        token = inspector.start_token(pid)
        key = (pid, token)
        if key not in identities:
            identities[key] = make_identity(process, role, token, observed_at)
        else:
            # A process can be observed first as a child and later as the
            # direct relationship of interest.  Preserve the first identity
            # but record the strongest role without paths or command lines.
            identity = identities[key]
            if role == "target" or (role == "parent" and identity.get("role") == "child"):
                identity["role"] = role


def sample_processes(
    target_pid: int,
    processes: Mapping[int, RawProcess],
    roles: Mapping[int, str],
    inspector: ProcessInspector,
) -> tuple[dict[str, Any], bool, str | None]:
    rows: list[dict[str, Any]] = []
    target_missing = target_pid not in processes
    for pid, role in roles.items():
        process = processes.get(pid)
        if process is None:
            rows.append({"pid": pid, "role": role, "state": "exited"})
            continue
        memory = inspector.memory(pid)
        row = {"pid": pid, "parent_pid": process.parent_pid, "role": role, **memory.as_dict()}
        rows.append(row)
    rows.sort(key=lambda item: (0 if item.get("role") == "target" else 1, int(item["pid"])))
    target_row = next((row for row in rows if row.get("pid") == target_pid), None)
    target_state = str(target_row.get("state")) if target_row else "exited"
    target_access_blocked = bool(
        target_row
        and target_state == "unavailable"
        and target_row.get("error_category") == "process_memory_access_denied"
    )
    return {"processes": rows}, target_missing, "target_memory_access_denied" if target_access_blocked else None


def _safe_int(value: Any, *, maximum: int = 0xFFFFFFFFFFFFFFFF) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if number < 0 or number > maximum:
        return None
    return number


def _safe_string(value: Any, pattern: re.Pattern[str], *, fallback: str | None = None) -> str | None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        return fallback
    return value


def sanitize_process_event(value: Any, related_pids: set[int]) -> dict[str, Any] | None:
    """Project one process JSONL record onto the fixed diagnostic allowlist."""

    if not isinstance(value, dict):
        return None
    schema_version = _safe_int(value.get("schema_version"), maximum=SCHEMA_VERSION)
    if schema_version != SCHEMA_VERSION:
        return None
    event = value.get("event")
    if not isinstance(event, str) or event not in PROCESS_EVENT_NAMES:
        return None
    pid = _safe_int(value.get("pid"), maximum=0xFFFFFFFF)
    child_pid = _safe_int(value.get("child_pid"), maximum=0xFFFFFFFF)
    parent_pid = _safe_int(value.get("parent_pid"), maximum=0xFFFFFFFF)
    if pid is None or not ({pid, child_pid, parent_pid} & related_pids):
        return None
    timestamp = _safe_int(value.get("timestamp_unix_ms"), maximum=9_999_999_999_999)
    if timestamp is None:
        return None
    result: dict[str, Any] = {
        "schema_version": 1,
        "timestamp_unix_ms": timestamp,
        "event": event,
        "build_revision": _safe_string(value.get("build_revision"), REVISION, fallback="unknown"),
        "exe_sha256": _safe_string(value.get("exe_sha256"), SHA256),
        "exe_hash_status": _safe_string(value.get("exe_hash_status"), re.compile(r"^(?:available|unavailable|mismatch|unknown)$"), fallback="unknown"),
        "exe_module_name": safe_image_name(value.get("exe_module_name") if isinstance(value.get("exe_module_name"), str) else None),
        "pdb_identity": _safe_string(value.get("pdb_identity"), PDB_IDENTITY),
        "pdb_identity_status": _safe_string(value.get("pdb_identity_status"), re.compile(r"^(?:available|unavailable|mismatch|unknown)$"), fallback="unknown"),
        "launch_id": _safe_string(value.get("launch_id"), SAFE_TAG, fallback="unknown"),
        "pid": pid,
        "role": _safe_string(value.get("role"), re.compile(r"^(?:daemon|document_worker|diagnostics|diagnostic_fault)$"), fallback="unknown"),
    }
    for key, maximum in (("parent_pid", 0xFFFFFFFF), ("child_pid", 0xFFFFFFFF)):
        number = _safe_int(value.get(key), maximum=maximum)
        if number is not None:
            result[key] = number
    parent_launch = _safe_string(value.get("parent_launch_id"), SAFE_TAG)
    if parent_launch is not None:
        result["parent_launch_id"] = parent_launch
    child_launch = _safe_string(value.get("child_launch_id"), SAFE_TAG)
    if child_launch is not None:
        result["child_launch_id"] = child_launch
    for key in ("phase", "operation_id", "error_code"):
        string = _safe_string(value.get(key), SAFE_TAG)
        if string is not None:
            result[key] = string
    result_value = _safe_string(value.get("result"), re.compile(r"^(?:completed|failed)$"))
    if result_value is not None:
        result["result"] = result_value
    intent = _safe_string(value.get("termination_intent"), re.compile(r"^(?:cancelled|timeout|parent_cleanup|job_cleanup|shutdown)$"))
    if intent is not None:
        result["termination_intent"] = intent
    native_exit = _safe_int(value.get("native_exit_code"))
    exit_hex = _safe_string(value.get("exit_code_hex"), SAFE_HEX)
    if native_exit is not None:
        result["native_exit_code"] = native_exit
        result["exit_code_hex"] = f"0x{native_exit:08X}"
    elif exit_hex is not None:
        result["exit_code_hex"] = exit_hex
    source = _safe_string(value.get("exit_source"), re.compile(r"^(?:natural|after_cleanup)$"))
    if source is not None:
        result["exit_source"] = source
    memory_scope = _safe_string(value.get("memory_scope"), re.compile(r"^self_process$"))
    if memory_scope is not None:
        result["memory_scope"] = memory_scope
    if isinstance(value.get("child_reaped"), bool):
        result["child_reaped"] = value["child_reaped"]
    for key in ("stderr_discarded_bytes", "stderr_read_errors"):
        number = _safe_int(value.get(key))
        if number is not None:
            result[key] = number
    memory = value.get("memory")
    if isinstance(memory, dict):
        working = _safe_int(memory.get("working_set_bytes"))
        private = _safe_int(memory.get("private_commit_bytes"))
        if working is not None or private is not None:
            result["memory"] = {
                key: number
                for key, number in (
                    ("working_set_bytes", working),
                    ("private_commit_bytes", private),
                )
                if number is not None
            }
    panic = value.get("panic")
    if isinstance(panic, dict):
        panic_record: dict[str, Any] = {}
        module = safe_image_name(panic.get("source_module") if isinstance(panic.get("source_module"), str) else None)
        if module:
            panic_record["source_module"] = module
        for key in ("line", "column"):
            number = _safe_int(panic.get(key), maximum=0xFFFFFFFF)
            if number is not None:
                panic_record[key] = number
        frames: list[dict[str, str]] = []
        raw_stack = panic.get("raw_stack")
        if isinstance(raw_stack, list):
            for frame in raw_stack[:24]:
                if not isinstance(frame, dict):
                    continue
                address = _safe_string(frame.get("address_hex"), SAFE_HEX)
                if address is None:
                    continue
                clean_frame = {"address_hex": address}
                module_name = safe_image_name(frame.get("module_name") if isinstance(frame.get("module_name"), str) else None)
                if module_name is not None:
                    clean_frame["module_name"] = module_name
                module_binding = _safe_string(frame.get("module_binding"), MODULE_BINDING)
                if module_binding is not None:
                    clean_frame["module_binding"] = module_binding
                for key in ("module_base_hex", "module_offset_hex"):
                    optional = _safe_string(frame.get(key), SAFE_HEX)
                    if optional is not None:
                        clean_frame[key] = optional
                frames.append(clean_frame)
        if frames:
            panic_record["raw_stack"] = frames
        if panic_record:
            result["panic"] = panic_record
    return result


def read_process_diagnostics(
    directory: Path,
    related_pids: set[int],
    *,
    target_pid: int | None = None,
    target_start_unix_ms: int | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
) -> dict[str, Any]:
    """Read explicit process/panic JSONL files and drop unknown fields.

    Related parent/child records are useful context but cannot establish that
    the requested PID actually emitted diagnostics.  When ``target_pid`` is
    supplied, a successful read therefore requires at least one event whose
    own ``pid`` is the target.  If the Windows process creation FILETIME is
    available, records from that PID before the current creation time remain
    visible as historical evidence but do not prove the current launch.
    """

    result: dict[str, Any] = {
        "status": "blocked",
        "requested": True,
        "target_pid": target_pid,
        "target_start_unix_ms": target_start_unix_ms,
        "files_seen": 0,
        "files_read": 0,
        "events": [],
        "target_event_count": 0,
        "target_event_proof": False,
        "malformed_lines": 0,
        "dropped_unknown_or_unrelated": 0,
        "dropped_outside_window": 0,
    }
    try:
        if directory.is_symlink() or not directory.is_dir():
            result["reason"] = "diagnostics_dir_unavailable"
            return result
        directory = directory.resolve()
        all_candidates = sorted(
            (
                path
                for path in directory.iterdir()
                if path.is_file()
                and not path.is_symlink()
                and re.fullmatch(r"(?:process|panic)-[A-Za-z0-9_.:-]{1,128}(?:\.\d+)?\.jsonl", path.name)
            ),
            key=lambda path: path.name,
        )
        result["files_seen"] = len(all_candidates)
        result["files_truncated"] = max(0, len(all_candidates) - MAX_DIAGNOSTIC_FILES)
        candidates = all_candidates[:MAX_DIAGNOSTIC_FILES]
        if not candidates:
            result["reason"] = "diagnostic_logs_missing"
            return result
        failed = False
        for path in candidates:
            try:
                raw = path.read_bytes()
            except OSError:
                failed = True
                continue
            if len(raw) > MAX_DIAGNOSTIC_FILE_BYTES:
                failed = True
                continue
            result["files_read"] += 1
            for line in raw.splitlines():
                if len(line) > MAX_DIAGNOSTIC_LINE_BYTES:
                    result["malformed_lines"] += 1
                    failed = True
                    continue
                try:
                    value = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    result["malformed_lines"] += 1
                    failed = True
                    continue
                sanitized = sanitize_process_event(value, related_pids)
                if sanitized is None:
                    result["dropped_unknown_or_unrelated"] += 1
                    continue
                if since is not None or until is not None:
                    event_time = dt.datetime.fromtimestamp(
                        sanitized["timestamp_unix_ms"] / 1000,
                        tz=dt.timezone.utc,
                    )
                    if (since is not None and event_time < since) or (until is not None and event_time > until):
                        result["dropped_outside_window"] += 1
                        continue
                if target_pid is not None:
                    if sanitized["pid"] == target_pid:
                        if target_start_unix_ms is not None and sanitized["timestamp_unix_ms"] < target_start_unix_ms:
                            sanitized["scope"] = "target_pid_before_current_start"
                        else:
                            sanitized["scope"] = (
                                "current_target"
                                if target_start_unix_ms is not None
                                else "target_pid_unverified_start"
                            )
                    else:
                        sanitized["scope"] = "related_process"
                if len(result["events"]) < MAX_EVENTS_PER_CHANNEL * 2:
                    result["events"].append(sanitized)
        result["events"].sort(key=lambda item: (item["timestamp_unix_ms"], item["pid"], item["event"]))
        # Count only retained evidence.  A target event beyond the bounded
        # output cap must not make the report look proven when it was dropped.
        result["target_event_count"] = sum(
            item.get("scope") in {"current_target", "target_pid_unverified_start"}
            for item in result["events"]
        )
        if result["malformed_lines"] or failed or result["files_truncated"]:
            result["status"] = "failed"
            result["reason"] = "diagnostic_log_read_failed"
        elif not result["events"]:
            result["status"] = "blocked"
            result["reason"] = "diagnostic_logs_have_no_target_events"
        elif target_pid is not None and result["target_event_count"] == 0:
            result["status"] = "blocked"
            result["reason"] = "target_process_log_missing_or_stale"
        else:
            result["status"] = "passed"
        result["target_event_proof"] = bool(result["target_event_count"])
        return result
    except OSError:
        result["status"] = "blocked"
        result["reason"] = "diagnostics_dir_unavailable"
        return result


def parse_event_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value)
    except (TypeError, ValueError):
        return None


def target_match_from_event(
    event: ET.Element,
    target_pid: int,
    target_image_name: str | None,
) -> tuple[bool, str | None, dict[str, Any]]:
    """Inspect a tiny WER field allowlist in memory and return only a match."""

    pid_names = {"processid", "pid", "faultingprocessid"}
    image_names = {
        "applicationname",
        "appname",
        "faultingapplication",
        "faultingapplicationname",
        "application",
        "p1",
    }
    data = event.find(".//EventData")
    if data is None:
        return False, None, {}
    observed_pid: int | None = None
    faulting_module: str | None = None
    exception_code: int | None = None
    faulting_offset: int | None = None
    image_match = False
    for node in list(data):
        name = str(node.attrib.get("Name", "")).strip().lower()
        value = (node.text or "").strip()
        if not value:
            continue
        if name in pid_names:
            try:
                numeric = int(value, 0)
            except ValueError:
                try:
                    numeric = int(value, 10)
                except ValueError:
                    numeric = -1
            if numeric >= 0:
                observed_pid = numeric
            if numeric == target_pid:
                image_match = True
        if name in image_names and target_image_name:
            candidate = safe_image_name(value)
            if candidate and candidate.casefold() == target_image_name.casefold():
                image_match = True
        if name in {"faultingmodule", "faultingmodulename", "modulename", "module"}:
            candidate = safe_image_name(value)
            if candidate:
                faulting_module = candidate
        if name in {"exceptioncode", "exception_code"}:
            try:
                numeric = int(value, 0)
            except ValueError:
                numeric = None
            if numeric is not None and 0 <= numeric <= 0xFFFFFFFF:
                exception_code = numeric
        if name in {"faultingoffset", "faulting_offset", "offset"}:
            try:
                numeric = int(value, 0)
            except ValueError:
                numeric = None
            if numeric is not None and 0 <= numeric <= 0xFFFFFFFFFFFFFFFF:
                faulting_offset = numeric
    if not image_match:
        return False, None, {}
    basis = "pid" if observed_pid == target_pid else "image_name"
    metadata: dict[str, Any] = {}
    if observed_pid is not None:
        metadata["application_pid"] = observed_pid
    if faulting_module:
        metadata["faulting_module"] = faulting_module
    if exception_code is not None:
        metadata["exception_code_hex"] = f"0x{exception_code:08X}"
    if faulting_offset is not None:
        metadata["faulting_offset_hex"] = f"0x{faulting_offset:016X}"
    return True, basis, metadata


def parse_event_xml(
    text: str,
    channel: str,
    since: dt.datetime,
    until: dt.datetime,
    target_pid: int,
    target_image_name: str | None,
) -> list[dict[str, Any]]:
    if not text.strip():
        return []
    # wevtutil emits Event elements rather than one stable document root on
    # different Windows builds.  Strip declarations before wrapping it.
    body = re.sub(r"<\?xml[^>]*\?>", "", text, flags=re.IGNORECASE)
    try:
        root = ET.fromstring(f"<Events>{body}</Events>")
    except ET.ParseError as error:
        raise DiagnosticError("event_log_xml_invalid") from error
    events: list[dict[str, Any]] = []
    for event in root.findall("Event"):
        system = event.find("System")
        if system is None:
            continue
        event_id_node = system.find("EventID")
        try:
            event_id = int((event_id_node.text or "").strip()) if event_id_node is not None else -1
        except ValueError:
            event_id = -1
        if event_id not in EVENT_IDS:
            continue
        created_node = system.find("TimeCreated")
        created_raw = created_node.attrib.get("SystemTime") if created_node is not None else None
        created = parse_event_time(created_raw)
        if created is None or created < since or created > until:
            continue
        provider_node = system.find("Provider")
        provider = safe_provider_name(provider_node.attrib.get("Name") if provider_node is not None else None)
        level_node = system.find("Level")
        try:
            level = int((level_node.text or "").strip()) if level_node is not None else None
        except ValueError:
            level = None
        matched, basis, fault_metadata = target_match_from_event(event, target_pid, target_image_name)
        # Keep only events attributable to the requested PID or its exact
        # image basename.  System metadata from unrelated applications is not
        # useful for this bounded record and can unnecessarily expose local
        # provider activity.
        if not matched:
            continue
        record = {
            "channel": channel,
            "event_id": event_id,
            "provider": provider,
            "level": level,
            "time_created": created.isoformat(timespec="milliseconds"),
            "target_match": matched,
            "match_basis": basis,
        }
        if fault_metadata:
            record.update(fault_metadata)
        events.append(record)
        if len(events) >= MAX_EVENTS_PER_CHANNEL:
            break
    return events


def _event_query_window_ms(since: dt.datetime, until: dt.datetime) -> int:
    # Query only a bounded recent window.  Exact since/until filtering happens
    # after XML parsing so an event arriving after the capture is excluded.
    now = dt.datetime.now(dt.timezone.utc)
    return max(1, min(86_400_000, int((now - since).total_seconds() * 1000) + 2_000))


def read_event_channel(
    channel: str,
    since: dt.datetime,
    until: dt.datetime,
    target_pid: int,
    target_image_name: str | None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"channel": channel, "status": "blocked", "reason": "unsupported_platform", "events": []}
    executable = shutil.which("wevtutil")
    if not executable:
        return {"channel": channel, "status": "blocked", "reason": "event_log_tool_missing", "events": []}
    query_ms = _event_query_window_ms(since, until)
    query = f"*[System[(EventID=1000 or EventID=1001) and TimeCreated[timediff(@SystemTime) <= {query_ms}]]]"
    command = [executable, "qe", channel, f"/q:{query}", "/f:xml", "/c:256"]
    execute = runner or subprocess.run
    try:
        completed = execute(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"channel": channel, "status": "blocked", "reason": "event_log_query_timeout", "events": []}
    except OSError as error:
        return {
            "channel": channel,
            "status": "blocked" if isinstance(error, FileNotFoundError) else "failed",
            "reason": "event_log_query_unavailable" if isinstance(error, FileNotFoundError) else "event_log_query_error",
            "events": [],
        }
    raw = completed.stdout or ""
    if len(raw.encode("utf-8", errors="replace")) > MAX_EVENT_BYTES:
        return {"channel": channel, "status": "failed", "reason": "event_log_output_limit", "events": []}
    if completed.returncode != 0:
        return {"channel": channel, "status": "blocked", "reason": "event_log_query_failed", "events": []}
    try:
        events = parse_event_xml(raw, channel, since, until, target_pid, target_image_name)
    except DiagnosticError as error:
        return {"channel": channel, "status": "failed", "reason": error.category, "events": []}
    return {"channel": channel, "status": "passed", "event_count": len(events), "events": events}


def read_event_logs(
    channels: Sequence[str],
    since: dt.datetime,
    until: dt.datetime,
    target_pid: int,
    target_image_name: str | None,
    *,
    reader: Callable[..., dict[str, Any]] = read_event_channel,
) -> dict[str, Any]:
    try:
        channels = validate_channels(channels)
    except (TypeError, ValueError):
        return {"status": "not_run", "reason": "invalid_event_channel", "channels": [], "requested_channels": []}
    results = [reader(channel, since, until, target_pid, target_image_name) for channel in channels]
    if not all(isinstance(result, dict) for result in results):
        return {
            "status": "failed",
            "reason": "event_log_reader_invalid_result",
            "channels": [],
            "requested_channels": list(channels),
        }
    statuses = {str(result.get("status")) for result in results}
    if "failed" in statuses:
        status = "failed"
    elif "blocked" in statuses:
        status = "blocked"
    elif "not_run" in statuses:
        status = "not_run"
    elif not statuses:
        status = "not_run"
    elif statuses <= {"passed"}:
        status = "passed"
    else:
        status = "failed"
    return {"status": status, "channels": results, "requested_channels": list(channels)}


def base_report(status: str, *, reason: str | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "passed": status == "passed",
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "restrictions": {
            "read_only": True,
            "target_pid_only": True,
            "command_lines": False,
            "user_paths": False,
            "document_content": False,
            "dumps_enabled": False,
            "background_resident": False,
            "auto_restart": False,
            "upload": False,
        },
    }
    if reason:
        report["reason"] = reason
    return report


def collect(
    pid: int,
    *,
    duration_seconds: float = DEFAULT_DURATION_SECONDS,
    interval_ms: int = DEFAULT_INTERVAL_MS,
    channels: Sequence[str] = EVENT_CHANNELS,
    diagnostics_dir: Path | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    inspector: ProcessInspector | None = None,
    event_reader: Callable[..., dict[str, Any]] = read_event_logs,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Collect one bounded report; dependencies are injectable for tests."""

    try:
        pid = validate_pid(int(pid))
        duration_seconds = bounded_duration(float(duration_seconds))
        interval_ms = bounded_interval(int(interval_ms))
        channels = validate_channels(channels)
    except (TypeError, ValueError) as error:
        report = base_report("not_run", reason="invalid_arguments")
        report["argument_error"] = str(error)
        return report
    started_at = dt.datetime.now(dt.timezone.utc)
    report = base_report("not_run")
    report["started_at"] = started_at.isoformat(timespec="milliseconds")
    report["target_pid"] = pid
    report["requested_duration_seconds"] = duration_seconds
    report["requested_interval_ms"] = interval_ms
    report["requested_channels"] = list(channels)
    report["diagnostics_dir_supplied"] = diagnostics_dir is not None
    if duration_seconds == 0:
        report["reason"] = "duration_zero"
        report["logs"] = {"status": "not_run", "reason": "sampling_not_run", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "sampling_not_run", "events": []}
        report["finished_at"] = utc_now()
        report["elapsed_seconds"] = 0.0
        return report
    if not channels:
        report["status"] = "blocked"
        report["passed"] = False
        report["reason"] = "event_channels_not_requested"
        report["logs"] = {"status": "blocked", "reason": "event_channels_not_requested", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "event_channels_not_requested", "events": []}
        report["finished_at"] = utc_now()
        report["elapsed_seconds"] = 0.0
        return report
    active_inspector = inspector or WindowsProcessInspector()
    if not active_inspector.supported:
        report["status"] = "blocked"
        report["passed"] = False
        report["reason"] = "unsupported_platform"
        report["logs"] = {"status": "blocked", "reason": "sampling_not_available", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "sampling_not_available", "events": []}
        report["finished_at"] = utc_now()
        report["elapsed_seconds"] = 0.0
        return report
    try:
        initial_processes = active_inspector.list_processes()
    except DiagnosticError as error:
        report["status"] = "blocked" if error.blocked else "failed"
        report["passed"] = False
        report["reason"] = error.category
        report["logs"] = {"status": "blocked", "reason": "sampling_not_started", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "sampling_not_started", "events": []}
        report["finished_at"] = utc_now()
        report["elapsed_seconds"] = 0.0
        return report
    target = initial_processes.get(pid)
    if target is None:
        report["status"] = "blocked"
        report["passed"] = False
        report["reason"] = "target_pid_not_observed"
        report["logs"] = {"status": "blocked", "reason": "sampling_not_started", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "sampling_not_started", "events": []}
        report["finished_at"] = utc_now()
        report["elapsed_seconds"] = 0.0
        return report
    target_token = active_inspector.start_token(pid)
    target_start_unix_ms = filetime_to_unix_ms(target_token)
    target_image_name = target.image_name
    roles = relation_roles(pid, initial_processes)
    identities: dict[tuple[int, int | None], dict[str, Any]] = {}
    update_identities(identities, initial_processes, roles, active_inspector, report["started_at"])
    samples: list[dict[str, Any]] = []
    reasons: list[str] = []
    target_exit_observed = False
    resource_blocked = False
    sampling_status = "passed"
    started_mono = monotonic()
    deadline = started_mono + duration_seconds
    while len(samples) < MAX_SAMPLES:
        now_mono = monotonic()
        try:
            current_processes = active_inspector.list_processes()
        except DiagnosticError as error:
            reasons.append(error.category)
            sampling_status = "blocked" if error.blocked else "failed"
            break
        current_target = current_processes.get(pid)
        if current_target is not None and target_token is not None:
            current_token = active_inspector.start_token(pid)
            if current_token is not None and current_token != target_token:
                target_exit_observed = True
                reasons.append("target_pid_reused")
                current_processes = {key: value for key, value in current_processes.items() if key != pid}
                current_target = None
        if current_target is None:
            target_exit_observed = True
            if "target_exited" not in reasons:
                reasons.append("target_exited")
        current_roles = relation_roles(pid, current_processes)
        update_identities(identities, current_processes, current_roles, active_inspector, utc_now())
        sample, target_missing, target_error = sample_processes(pid, current_processes, current_roles or roles, active_inspector)
        sample["sampled_at"] = utc_now()
        sample["elapsed_seconds"] = round(max(0.0, now_mono - started_mono), 3)
        samples.append(sample)
        if target_missing:
            break
        if target_error:
            resource_blocked = True
            reasons.append(target_error)
        if now_mono >= deadline:
            break
        remaining = max(0.0, deadline - now_mono)
        sleeper(min(interval_ms / 1000.0, remaining))
    finished_at = dt.datetime.now(dt.timezone.utc)
    event_since = since or started_at
    event_until = until or finished_at
    if event_until < event_since:
        report["status"] = "not_run"
        report["passed"] = False
        report["reason"] = "invalid_event_time_window"
        report["logs"] = {"status": "not_run", "reason": "invalid_event_time_window", "channels": []}
        report["process_diagnostics"] = {"status": "not_run", "reason": "invalid_event_time_window", "events": []}
    else:
        try:
            logs = event_reader(channels, event_since, event_until, pid, target_image_name)
        except (DiagnosticError, OSError, ValueError):
            logs = {"status": "failed", "reason": "event_log_reader_error", "channels": []}
        if not isinstance(logs, dict):
            logs = {"status": "failed", "reason": "event_log_reader_invalid_result", "channels": []}
        elif logs.get("status") not in STATUS_EXIT_CODES:
            logs = dict(logs)
            logs.update({"status": "failed", "reason": "event_log_reader_invalid_status"})
        related_pids = {int(item.get("pid")) for item in identities.values() if _safe_int(item.get("pid"), maximum=0xFFFFFFFF) is not None}
        related_pids.add(pid)
        if diagnostics_dir is None:
            process_diagnostics = {
                "status": "not_run",
                "requested": False,
                "reason": "diagnostics_dir_not_supplied",
                "events": [],
            }
        else:
            process_diagnostics = read_process_diagnostics(
                diagnostics_dir,
                related_pids,
                target_pid=pid,
                target_start_unix_ms=target_start_unix_ms,
                # Process logs often contain the target's startup record from
                # before this sampler was launched.  The target PID plus the
                # creation timestamp below provides the launch boundary; an
                # implicit sampler start bound would discard that evidence.
                since=since,
                until=event_until,
            )
        if not isinstance(process_diagnostics, dict):
            process_diagnostics = {
                "status": "failed",
                "reason": "process_diagnostics_invalid_result",
                "events": [],
            }
        elif process_diagnostics.get("status") not in STATUS_EXIT_CODES:
            process_diagnostics = dict(process_diagnostics)
            process_diagnostics.update({"status": "failed", "reason": "process_diagnostics_invalid_status"})
        status = sampling_status
        if status == "passed" and target_exit_observed:
            status = "failed"
        if resource_blocked and status == "passed":
            status = "blocked"
        if logs.get("status") == "failed" and status == "passed":
            status = "failed"
        elif logs.get("status") == "blocked" and status == "passed":
            status = "blocked"
        elif logs.get("status") == "not_run" and status == "passed":
            status = "not_run"
        if process_diagnostics.get("status") == "failed" and status == "passed":
            status = "failed"
        elif process_diagnostics.get("status") in {"blocked", "not_run"} and status == "passed":
            status = "blocked"
        report["status"] = status
        report["passed"] = status == "passed"
        report["logs"] = logs
        report["process_diagnostics"] = process_diagnostics
    report["finished_at"] = finished_at.isoformat(timespec="milliseconds")
    report["elapsed_seconds"] = round(max(0.0, monotonic() - started_mono), 3)
    report["target_identity"] = next(
        (
            identity
            for identity in identities.values()
            if identity.get("pid") == pid and identity.get("start_token") == target_token
        ),
        make_identity(target, "target", target_token, report["started_at"]),
    )
    report["observed_related_processes"] = sorted(
        identities.values(), key=lambda item: (0 if item.get("role") == "target" else 1, int(item["pid"]), item.get("start_token") or -1)
    )
    report["samples"] = samples
    report["sample_count"] = len(samples)
    if reasons:
        report["observations"] = sorted(set(reasons))
        if report.get("status") != "passed" and "reason" not in report:
            report["reason"] = sorted(set(reasons))[0]
    return report


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"diagnostic output already exists: {path.name}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(f"diagnostic temporary output already exists: {temporary.name}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="one already-running target Windows PID")
    parser.add_argument("--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--interval-ms", type=int, default=DEFAULT_INTERVAL_MS)
    parser.add_argument("--output", type=Path, required=True, help="new JSON report path")
    parser.add_argument(
        "--diagnostics-dir",
        type=Path,
        help="explicit process JSONL directory; omission is recorded as not_run and blocks success",
    )
    parser.add_argument(
        "--channel",
        dest="channels",
        action="append",
        choices=EVENT_CHANNELS,
        help="event channel to query; repeat for both (default: Application and WER)",
    )
    parser.add_argument("--since", type=parse_timestamp, help="UTC/ISO event-log lower bound")
    parser.add_argument("--until", type=parse_timestamp, help="UTC/ISO event-log upper bound")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parse_args(argv)
        channels = tuple(arguments.channels) if arguments.channels else EVENT_CHANNELS
        report = collect(
            arguments.pid,
            duration_seconds=arguments.duration_seconds,
            interval_ms=arguments.interval_ms,
            channels=channels,
            diagnostics_dir=arguments.diagnostics_dir,
            since=arguments.since,
            until=arguments.until,
        )
        write_report(arguments.output, report)
    except (ValueError, TypeError) as error:
        report = base_report("not_run", reason="invalid_arguments")
        report["argument_error"] = str(error)
        try:
            if "arguments" in locals():
                write_report(arguments.output, report)
        except Exception:
            pass
    except FileExistsError as error:
        report = base_report("failed", reason="output_exists")
        report["error_category"] = type(error).__name__
    except OSError as error:
        report = base_report("failed", reason="output_write_failed")
        report["error_category"] = type(error).__name__
    print(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    return STATUS_EXIT_CODES.get(str(report.get("status")), 1)


if __name__ == "__main__":
    raise SystemExit(main())
