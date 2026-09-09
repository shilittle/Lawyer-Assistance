"""Create the small, synthetic legal database used only by WebUI CI smoke tests.

The production legal archive is intentionally not part of a normal checkout.  This
helper builds a disposable database from the checked-in schema and retrieval
fixture, and refuses to write under ``data/runtime`` so it cannot be confused
with a distributable legal resource.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = Path("data/schema/legal_core.sql")
RETRIEVAL_FIXTURE = Path("data/fixtures/legal_core_retrieval_fixture.sql")
SYNTHETIC_DATASET_NAME = "synthetic-web-smoke-not-for-distribution"
SYNTHETIC_DISTRIBUTION_PROFILE = "ci-synthetic-not-for-distribution"


class FixtureError(RuntimeError):
    """The requested CI-only fixture could not be created safely."""


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_fixture(connection: sqlite3.Connection) -> None:
    metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
    expected_metadata = {
        "schema_version": "4",
        "dataset_name": SYNTHETIC_DATASET_NAME,
        "distribution_profile": SYNTHETIC_DISTRIBUTION_PROFILE,
        "coverage_status": "synthetic",
    }
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            raise FixtureError(f"synthetic fixture metadata mismatch for {key}")
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise FixtureError("synthetic fixture failed integrity_check")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise FixtureError("synthetic fixture failed foreign_key_check")
    checks = {
        "contract_search": "SELECT COUNT(*) FROM law_articles WHERE content LIKE '%合同%'",
        "article_detail": "SELECT COUNT(*) FROM law_articles WHERE id = 'cn-civil-code-20210101-465'",
        "version_history": "SELECT COUNT(*) FROM law_versions WHERE document_id = 'cn-civil-code'",
        "relations": "SELECT COUNT(*) FROM law_relations WHERE from_document_id = 'cn-civil-code'",
    }
    for name, query in checks.items():
        if connection.execute(query).fetchone()[0] <= 0:
            raise FixtureError(f"synthetic fixture is missing {name} smoke data")


def prepare_fixture(output: Path, root: Path = ROOT) -> Path:
    """Build ``output`` from the repository schema and retrieval fixture."""
    root = root.resolve()
    output = output.expanduser().resolve()
    runtime_dir = (root / "data" / "runtime").resolve()
    if is_within(output, runtime_dir):
        raise FixtureError("synthetic fixture must never be written under data/runtime")
    if output.suffix != ".sqlite":
        raise FixtureError("synthetic fixture output must use the .sqlite suffix")
    if output.exists() and (not output.is_file() or output.is_symlink()):
        raise FixtureError("synthetic fixture output must be a regular file")

    schema_path = root / SCHEMA
    retrieval_fixture_path = root / RETRIEVAL_FIXTURE
    for path in (schema_path, retrieval_fixture_path):
        if not path.is_file():
            raise FixtureError(f"required fixture input is missing: {path}")

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staging_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.stem}.", suffix=".sqlite.tmp"
    )
    os.close(descriptor)
    staging = Path(staging_name)
    try:
        connection = sqlite3.connect(staging)
        try:
            connection.executescript(schema_path.read_text(encoding="utf-8"))
            connection.executescript(retrieval_fixture_path.read_text(encoding="utf-8"))
            connection.execute("PRAGMA foreign_keys = ON")
            timestamp = "1970-01-01T00:00:00Z"
            connection.executemany(
                """
                INSERT INTO database_metadata (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                [
                    ("dataset_name", SYNTHETIC_DATASET_NAME, timestamp),
                    ("dataset_version", "web-smoke-fixture-v1", timestamp),
                    ("distribution_profile", SYNTHETIC_DISTRIBUTION_PROFILE, timestamp),
                    ("coverage_status", "synthetic", timestamp),
                    (
                        "fixture_notice",
                        "Synthetic CI smoke fixture. Not legal data and not for distribution.",
                        timestamp,
                    ),
                ],
            )
            connection.commit()
            validate_fixture(connection)
        finally:
            connection.close()
        os.replace(staging, output)
    except Exception:
        staging.unlink(missing_ok=True)
        raise
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="temporary .sqlite output path")
    parser.add_argument("--root", default=ROOT, type=Path, help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        output = prepare_fixture(args.output, args.root)
    except (FixtureError, OSError, sqlite3.Error) as error:
        print(f"synthetic Web smoke legal fixture failed: {error}")
        return 1
    print(f"synthetic non-distribution Web smoke legal fixture: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
