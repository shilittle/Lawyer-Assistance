"""Run the final 1.2.1 local checks with explicit Rust 1.98 and UTF-8 evidence logs.

Run only after parallel implementation has finished. Model tests use their own
synthetic transports; this runner never reads provider keys or starts live AI scripts.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "work/audit-repair"
RELEASE_EXE = str(ROOT / "target/x86_64-pc-windows-msvc/release/lawyer-assistance.exe")
COMMANDS = [
    ("final-format.log", ["cargo", "+1.98.0", "fmt", "--all", "--check"]),
    ("final-rust-tests.log", ["cargo", "+1.98.0", "test", "--locked", "--offline", "--workspace", "--all-targets", "--all-features"]),
    ("final-clippy.log", ["cargo", "+1.98.0", "clippy", "--locked", "--offline", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
    ("final-web.log", ["node", "--check", "apps/web/app.js"]),
    ("final-web.log", ["node", "--check", "apps/web/api.js"]),
    ("final-web.log", ["node", "--test", "apps/web/app.test.js"]),
    ("final-python.log", ["python", "-m", "unittest", "scripts.test_check_utf8_text", "scripts.test_generate_third_party_notices", "scripts.test_package_portable", "scripts.test_prepare_web_smoke_db", "-v"]),
    ("final-native-pdfium.log", ["cargo", "+1.98.0", "test", "--locked", "--offline", "-p", "file-ingest", "--lib", "--", "--ignored"]),
    ("final-formal-tests.log", ["cargo", "+1.98.0", "test", "--locked", "--offline", "-p", "citations", "-p", "retrieval", "--test", "formal_legal_core", "--", "--ignored"]),
    ("final-notices.log", ["python", "scripts/generate_third_party_notices.py", "--check"]),
    ("final-build.log", ["cargo", "+1.98.0", "build", "--locked", "--offline", "--release", "-j", "1", "-p", "lawyer-assistance-server", "--bin", "lawyer-assistance"]),
    ("final-build.log", ["cargo", "+1.98.0", "build", "--locked", "--offline", "--release", "-j", "1", "-p", "legal-mcp", "--bin", "lawyer-assistance-mcp"]),
    ("final-native-suite.log", ["node", "scripts/audit_ui_regression.mjs"]),
    *[("final-native-suite.log", ["node", f"scripts/{name}.mjs", RELEASE_EXE]) for name in (
        "audit_native_smoke", "audit_search_native", "audit_capacity_native",
        "audit_ai_capacity_native", "audit_index_equivalence",
        "audit_document_worker_native", "audit_context_citations_native",
    )],
]


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    environment["LAWYER_ASSISTANCE_PDFIUM"] = str(ROOT / "output/runtime-tools/pdfium.dll")
    environment["LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE"] = str(ROOT / "data/runtime/legal_core.sqlite")
    results, opened = [], set()
    for name, command in COMMANDS:
        started = time.monotonic()
        print(json.dumps({"starting": command, "log": name}), flush=True)
        with (OUTPUT / name).open("ab" if name in opened else "wb") as log:
            opened.add(name)
            log.write(("\n$ " + " ".join(command) + "\n").encode("utf-8"))
            log.flush()
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, check=False)
        row = {"command": command, "log": name, "exit_code": result.returncode, "elapsed_seconds": round(time.monotonic() - started, 3)}
        results.append(row)
        report = {"passed": all(item["exit_code"] == 0 for item in results) and len(results) == len(COMMANDS), "checks": results}
        (OUTPUT / "final-command-results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(row), flush=True)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
