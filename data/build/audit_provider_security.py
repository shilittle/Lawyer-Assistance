#!/usr/bin/env python3
"""Fail when Git-visible text contains credential files, likely keys, or sensitive logging."""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


BINARY_SUFFIXES = {
    ".7z",
    ".db",
    ".dll",
    ".docx",
    ".exe",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".sqlite",
    ".webp",
    ".zip",
}
EXCLUDED_PARTS = {".git", "node_modules", "target"}
FORBIDDEN_CREDENTIAL_FILENAMES = {
    ".env",
    "api-key.txt",
    "api_key.txt",
    "apikey.txt",
    "credentials.txt",
    "secrets.txt",
}
DUMMY_MARKERS = (
    "contract-secret",
    "cred-manager-secret",
    "dummy",
    "inline-secret",
    "ipc-secret",
    "lawyer-secret",
    "mock",
    "not-a-real",
    "plain-secret",
)

LIKELY_SECRET_PATTERNS = (
    (
        "provider_key_prefix",
        re.compile(r"\b(?:sk|ak)-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "literal_bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
    ),
    (
        "literal_secret_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|access[_-]?token|authorization)"
            r"\s*[:=]\s*[\"'][^\"'\r\n]{12,}[\"']"
        ),
    ),
)
SENSITIVE_LOGGING = re.compile(
    r"(?i)(?:println!|eprintln!|dbg!|tracing::|log::|"
    r"console\.(?:log|debug|info|warn|error))"
    r"[^\r\n]*(?:authorization|api[_-]?key|request\.body|"
    r"response\.body|expose_secret)"
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str


def _is_dummy_line(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in DUMMY_MARKERS)


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if path.name.lower() in FORBIDDEN_CREDENTIAL_FILENAMES:
        findings.append(Finding(path, 1, "credential_file"))
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in LIKELY_SECRET_PATTERNS:
            if pattern.search(line) and (
                rule == "provider_key_prefix" or not _is_dummy_line(line)
            ):
                findings.append(Finding(path, line_number, rule))
        if SENSITIVE_LOGGING.search(line):
            findings.append(Finding(path, line_number, "sensitive_logging"))
    return findings


def candidate_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    candidates: list[Path] = []
    for relative in completed.stdout.splitlines():
        path = root / relative
        if (
            path.is_file()
            and path.suffix.lower() not in BINARY_SUFFIXES
            and not EXCLUDED_PARTS.intersection(path.parts)
        ):
            candidates.append(path)
    return candidates


def audit(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in candidate_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(path.relative_to(root), text))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    findings = audit(root)
    if findings:
        print("provider security audit failed")
        for finding in findings:
            print(f"{finding.path}:{finding.line}: {finding.rule}")
        return 1

    print("provider security audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
