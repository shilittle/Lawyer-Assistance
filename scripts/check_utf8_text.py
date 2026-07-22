"""Reject invalid UTF-8 and common Chinese mojibake in tracked text files."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence


# Keep the allowlist deliberately narrow. In particular, SQLite databases,
# office documents, images, archives, executables, and generated bundles are
# never opened, even if they happen to be tracked by Git.
TEXT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cjs",
        ".conf",
        ".config",
        ".css",
        ".golden",
        ".html",
        ".ini",
        ".js",
        ".json",
        ".jsx",
        ".lock",
        ".md",
        ".mjs",
        ".mts",
        ".properties",
        ".ps1",
        ".py",
        ".rs",
        ".scss",
        ".sh",
        ".snap",
        ".sql",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
TEXT_FILENAMES = frozenset(
    {
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        ".npmrc",
        "dockerfile",
        "justfile",
        "license",
        "makefile",
    }
)

# Use Unicode escapes so the gate's own source does not contain the forbidden
# examples. These are stable, well-known results of decoding Chinese UTF-8 as
# Latin-1/Windows-1252 or GBK, plus the common double-encoding replacement.
MOJIBAKE_MARKERS = (
    ("replacement character decoded as Latin-1", "\u00ef\u00bf\u00bd"),
    ("common GBK replacement artifact", "\u951f\u65a4\u62f7"),
    ("Chinese decoded as Windows-1252", "\u00e4\u00b8\u00ad\u00e6\u2013\u2021"),
    ("Chinese decoded as GBK", "\u6d93\ue15f\u6783"),
    ("legal text decoded as GBK", "\u5a09\u66de\u7de5"),
    ("document text decoded as GBK", "\u93c2\u56e6"),
    ("version text decoded as GBK", "\u9417\u581f\u6e70"),
    ("release text decoded as GBK", "\u9359\u621d\u7af7"),
)
QUESTION_RUN = re.compile(r"\?{3,}")


class GateError(RuntimeError):
    """Raised when the repository cannot be enumerated reliably."""


@dataclass(frozen=True)
class TextIssue:
    path: str
    rule: str
    line: int | None
    column: int | None
    detail: str

    def format(self) -> str:
        location = self.path
        if self.line is not None:
            location += f":{self.line}"
            if self.column is not None:
                location += f":{self.column}"
        return f"{location}: [{self.rule}] {self.detail}"


def is_text_path(relative_path: str) -> bool:
    path = PurePosixPath(relative_path.replace("\\", "/"))
    return path.name.lower() in TEXT_FILENAMES or path.suffix.lower() in TEXT_EXTENSIONS


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous_newline = text.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _code_points(value: str) -> str:
    return " ".join(f"U+{ord(character):04X}" for character in value)


def scan_bytes(relative_path: str, payload: bytes) -> list[TextIssue]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        return [
            TextIssue(
                relative_path,
                "invalid-utf8",
                None,
                None,
                f"strict decoding failed at byte {error.start}",
            )
        ]

    issues: list[TextIssue] = []
    replacement_offset = text.find("\ufffd")
    if replacement_offset >= 0:
        line, column = _line_and_column(text, replacement_offset)
        issues.append(
            TextIssue(
                relative_path,
                "replacement-character",
                line,
                column,
                "contains U+FFFD",
            )
        )

    question_match = QUESTION_RUN.search(text)
    if question_match is not None:
        line, column = _line_and_column(text, question_match.start())
        issues.append(
            TextIssue(
                relative_path,
                "question-mark-run",
                line,
                column,
                f"contains {len(question_match.group(0))} consecutive question marks",
            )
        )

    for description, marker in MOJIBAKE_MARKERS:
        marker_offset = text.find(marker)
        if marker_offset < 0:
            continue
        line, column = _line_and_column(text, marker_offset)
        issues.append(
            TextIssue(
                relative_path,
                "chinese-mojibake",
                line,
                column,
                f"{description} ({_code_points(marker)})",
            )
        )
    return issues


def tracked_text_paths(repository: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise GateError(f"git ls-files failed: {stderr}")

    paths = (os.fsdecode(item) for item in result.stdout.split(b"\0") if item)
    return tuple(sorted(path for path in paths if is_text_path(path)))


def scan_repository(repository: Path) -> tuple[tuple[str, ...], list[TextIssue]]:
    repository = repository.resolve()
    paths = tracked_text_paths(repository)
    issues: list[TextIssue] = []
    for relative_path in paths:
        path = repository / Path(relative_path)
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            # A tracked file may be intentionally deleted in the working tree
            # before the deletion is staged or committed. There are no bytes
            # to validate in that state; Git's own status/diff gates remain
            # responsible for reviewing the deletion itself.
            continue
        except OSError as error:
            issues.append(
                TextIssue(relative_path, "unreadable", None, None, str(error))
            )
            continue
        issues.extend(scan_bytes(relative_path, payload))
    return paths, issues


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Git repository root (defaults to this script's repository)",
    )
    options = parser.parse_args(argv)

    try:
        paths, issues = scan_repository(options.repo)
    except GateError as error:
        print(f"UTF-8 text gate could not run: {error}", file=sys.stderr)
        return 2

    if issues:
        print(
            f"UTF-8 text gate failed: {len(issues)} issue(s) in "
            f"{len(paths)} Git-tracked text file(s).",
            file=sys.stderr,
        )
        for issue in issues:
            print(f"  {issue.format()}", file=sys.stderr)
        return 1

    print(
        f"UTF-8 text gate passed: {len(paths)} Git-tracked text file(s) "
        "decoded strictly and contained no blocked mojibake."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
