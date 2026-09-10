"""Read only encrypted test dispatch metadata and total provider-reported usage.

This does not open a backend or resume work, read API keys, or read material records.
Copied test workspaces are deduplicated by dispatch ID.
"""
from collections import defaultdict
from pathlib import Path
import json
import sqlite3
import struct

import win32crypt

ROOT = Path(__file__).resolve().parents[1]
ENTROPY = b"LawyerAssistance/privacy/local-protected-blob/v1"


def dispatch(identifier: str, data: bytes) -> dict:
    if data[:6] != b"LAWEB1":
        raise ValueError("invalid encrypted metadata header")
    count = struct.unpack_from("<I", data, 6)[0]
    if not 1 <= count <= 16:
        raise ValueError("invalid encrypted metadata chunk count")
    cursor = 10
    chunks = []
    for index in range(count):
        size = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        _, plain = win32crypt.CryptUnprotectData(data[cursor:cursor + size], ENTROPY, None, None, 1)
        cursor += size
        prefix = f"ai_dispatch/{identifier}/{index}/{count}\0".encode()
        if not plain.startswith(prefix):
            raise ValueError("encrypted metadata binding mismatch")
        chunks.append(plain[len(prefix):])
    if cursor != len(data):
        raise ValueError("trailing encrypted metadata bytes")
    return json.loads(b"".join(chunks))


def main() -> None:
    records = {}
    sources = []
    for path in sorted((ROOT / "output").glob("ai-upgrade-*/**/workspace.sqlite")):
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT id,body FROM objects WHERE kind='ai_dispatch'").fetchall()
        finally:
            connection.close()
        sources.append({"workspace": str(path.parent.relative_to(ROOT)), "dispatches": len(rows)})
        for identifier, body in rows:
            value = dispatch(identifier, body)
            previous = records.get(identifier)
            if previous is None or value.get("finished_at", 0) > previous.get("finished_at", 0):
                records[identifier] = value
    groups = defaultdict(lambda: {"requests": 0, "completed": 0, "failed": 0, "unfinished": 0,
                                  "reported_prompt_tokens": 0, "reported_completion_tokens": 0,
                                  "reported_total_tokens": 0, "requests_without_usage": 0})
    for record in records.values():
        group = groups[(record.get("model", "unknown"), record.get("purpose", "unknown"))]
        group["requests"] += 1
        status = record.get("status")
        group[status if status in {"completed", "failed"} else "unfinished"] += 1
        usage = record.get("usage", {})
        if "total_tokens" not in usage:
            group["requests_without_usage"] += 1
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            group["reported_" + key] += usage.get(key, 0) or 0
    # This disposable browser workspace was removed. Its two run usages are an
    # independent increment; title/test usage not retained here remains unknown.
    browser = json.loads((ROOT / "output/ai-upgrade-browser/browser-report.json").read_text(encoding="utf-8"))
    browser_runs = browser.get("runs", browser.get("aiRuns", []))
    if not browser_runs:
        browser_runs = next((v for v in browser.values() if isinstance(v, list) and v and isinstance(v[0], dict) and "usage" in v[0] and "kind" in v[0]), [])
    browser_tokens = sum(run.get("usage", {}).get("total_tokens", 0) for run in browser_runs)
    direct_diagnostics = {}
    for path in sorted((ROOT / "output/ai-upgrade-response-diagnostic").glob("official-direct-*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            continue
        response = value.get("response", {})
        if value.get("http_status") == 200 and response.get("id") and value.get("usage"):
            direct_diagnostics[response["id"]] = value["usage"].get("total_tokens", 0)
    diagnostic_tokens = sum(direct_diagnostics.values())
    rows = [{"model": model, "purpose": purpose, **value} for (model, purpose), value in sorted(groups.items())]
    report = {
        "schema_version": 1, "source": "read-only DPAPI ai_dispatch metadata; copied dispatch IDs deduplicated",
        "workspaces": sources, "unique_dispatches": len(records), "groups": rows,
        "dispatch_reported_tokens": sum(row["reported_total_tokens"] for row in rows),
        "disposed_browser_run_tokens": browser_tokens, "initial_capability_probe_tokens": 833,
        "direct_diagnostic_requests": len(direct_diagnostics),
        "direct_diagnostic_tokens": diagnostic_tokens,
        "notes": "Only provider-reported retained usage is counted. Requests without usage, including historical interrupted/invalid requests and disposed browser title/connection tests, may have consumed additional tokens. This is not a billing total.",
    }
    report["reported_total_tokens"] = report["dispatch_reported_tokens"] + browser_tokens + 833 + diagnostic_tokens
    output = ROOT / "output/ai-upgrade-usage.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output), "unique_dispatches": len(records), "reported_total_tokens": report["reported_total_tokens"]}))


if __name__ == "__main__":
    main()
