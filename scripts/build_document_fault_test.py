"""Build and preserve the default-off document fault executable for local QA only."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    command = ["cargo", "+1.98.0", "build", "--locked", "--offline", "-j", "1", "--target", TARGET,
               "-p", "lawyer-assistance-server", "--bin", "lawyer-assistance",
               "--features", "document-worker-fault-injection"]
    subprocess.run(command, cwd=ROOT, check=True)
    source = ROOT / "target" / TARGET / "debug" / "lawyer-assistance.exe"
    destination = output / "lawyer-assistance-fault-test.exe"
    shutil.copyfile(source, destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    report = {"test_only": True, "feature": "document-worker-fault-injection", "command": command,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "path": str(destination), "bytes": destination.stat().st_size, "sha256": digest}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
