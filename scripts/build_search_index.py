#!/usr/bin/env python3
"""Build the optional complete Chinese two-character legal-search index.

The generated SQLite file is an independent, disposable accelerator.  It
contains no authoritative legal text: every row points at an article row in
the source database, and the Rust retrieval path verifies matches literally
against that source.  The builder refuses a source that is not the supported
legal-core schema and records the source manifest identity in the sidecar.

The default invocation reads ``data/runtime/legal_core.sqlite`` and writes
``data/runtime/legal_search_index.sqlite``.  A temporary database is built and
atomically replaced only after the row count and metadata checks succeed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "data" / "runtime" / "legal_core.sqlite"
DEFAULT_OUTPUT = ROOT / "data" / "runtime" / "legal_search_index.sqlite"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_search_index_manifest.json"
SUPPORTED_SCHEMA_VERSION = "4"
SUPPORTED_RUNTIME_SCHEMA_VERSION = "1"
INDEX_SCHEMA_VERSION = "1"


def is_cjk(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x20000 <= codepoint <= 0x2FA1F
        or 0x30000 <= codepoint <= 0x323AF
    )


def chinese_bigrams(text: str) -> Iterator[str]:
    previous: str | None = None
    for character in text:
        if previous is not None and is_cjk(previous) and is_cjk(character):
            yield previous + character
        previous = character


def open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"source must be a regular non-symlink file: {path}")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only = ON")
    return connection


def metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute("SELECT key, value FROM database_metadata").fetchall()
    except sqlite3.DatabaseError as error:
        raise RuntimeError("source database_metadata table is unavailable") from error
    values = {str(key): str(value) for key, value in rows}
    if values.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported source schema_version: {values.get('schema_version')!r}"
        )
    if values.get("runtime_schema_version") != SUPPORTED_RUNTIME_SCHEMA_VERSION:
        raise RuntimeError(
            "search index requires the runtime-slim legal database "
            f"(runtime_schema_version={values.get('runtime_schema_version')!r})"
        )
    source_manifest = values.get("source_manifest_sha256", "")
    if len(source_manifest) != 64:
        raise RuntimeError("source_manifest_sha256 is missing or malformed")
    try:
        int(source_manifest, 16)
    except ValueError as error:
        raise RuntimeError("source_manifest_sha256 is not hexadecimal") from error
    if not values.get("dataset_version"):
        raise RuntimeError("dataset_version is missing")
    return values


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return bool(
        connection.execute(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?)",
            (name,),
        ).fetchone()[0]
    )


def article_rows(connection: sqlite3.Connection) -> Iterable[tuple[int, str]]:
    # Runtime slim keeps the audited source rowid in law_article_rows and
    # stores text in law_article_contents.  The archive fixture has a direct
    # law_articles table; supporting both keeps the builder testable without
    # changing the formal database.
    if table_exists(connection, "law_aliases"):
        alias_expression = "COALESCE(alias_text.text, '')"
        alias_join = """
            LEFT JOIN (
              SELECT document_id,
                     group_concat(alias || char(10) || normalized_alias, char(10)) AS text
              FROM law_aliases
              GROUP BY document_id
            ) AS alias_text ON alias_text.document_id = documents.id
        """
    else:
        alias_expression = "''"
        alias_join = ""
    if table_exists(connection, "law_article_rows") and table_exists(
        connection, "law_article_contents"
    ):
        query = f"""
            SELECT rows.article_rowid,
                   COALESCE(documents.title, '') || char(10) ||
                   COALESCE(rows.article_number, '') || char(10) ||
                   COALESCE(rows.title, '') || char(10) ||
                   COALESCE(contents.content, '') || char(10) ||
                   {alias_expression}
            FROM law_article_rows AS rows
            JOIN law_article_contents AS contents ON contents.content_id = rows.content_id
            JOIN law_documents AS documents ON documents.id = rows.document_id
            {alias_join}
            ORDER BY rows.article_rowid
        """
    elif table_exists(connection, "law_articles"):
        query = f"""
            SELECT articles.rowid,
                   COALESCE(documents.title, '') || char(10) ||
                   COALESCE(articles.article_number, '') || char(10) ||
                   COALESCE(articles.title, '') || char(10) ||
                   COALESCE(articles.content, '') || char(10) ||
                   {alias_expression}
            FROM law_articles AS articles
            JOIN law_documents AS documents ON documents.id = articles.document_id
            {alias_join}
            ORDER BY articles.rowid
        """
    else:
        raise RuntimeError("source has neither runtime article rows nor archive law_articles")
    yield from connection.execute(query)


def source_counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in ("law_documents", "law_versions"):
        counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    if table_exists(connection, "law_article_rows"):
        counts["law_articles"] = int(
            connection.execute("SELECT COUNT(*) FROM law_article_rows").fetchone()[0]
        )
    else:
        counts["law_articles"] = int(
            connection.execute("SELECT COUNT(*) FROM law_articles").fetchone()[0]
        )
    return counts


def initialize_index(connection: sqlite3.Connection, source: dict[str, str], counts: dict[str, int]) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = MEMORY;
        PRAGMA user_version = 1;
        CREATE TABLE search_index_metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE article_bigrams (
          bigram TEXT NOT NULL,
          article_rowid INTEGER NOT NULL,
          PRIMARY KEY (bigram, article_rowid)
        ) WITHOUT ROWID;
        """
    )
    # The primary key is the lookup order used by retrieval.  A second index
    # on rowid only doubles bulk-build writes and is not read at runtime.
    connection.execute("PRAGMA cache_size = -262144")
    entries = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "source_schema_version": source["schema_version"],
        "source_runtime_schema_version": source["runtime_schema_version"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "dataset_version": source["dataset_version"],
        "source_article_count": str(counts["law_articles"]),
    }
    connection.executemany(
        "INSERT INTO search_index_metadata(key, value) VALUES (?, ?)", entries.items()
    )


def build(
    source_path: Path,
    output_path: Path,
    manifest_path: Path,
    batch_size: int = 10_000,
) -> dict[str, object]:
    if batch_size < 1 or batch_size > 2_000_000:
        raise ValueError("batch_size must be between 1 and 2000000")
    source_path = Path(source_path)
    output_path = Path(output_path)
    manifest_path = Path(manifest_path)
    if source_path.is_symlink() or not source_path.is_file():
        raise RuntimeError(f"source must be a regular non-symlink file: {source_path}")
    if output_path.is_symlink():
        raise RuntimeError(f"index output must not be a symlink: {output_path}")
    source_path = source_path.absolute()
    output_path = output_path.absolute()
    manifest_path = manifest_path.absolute()
    if source_path == output_path:
        raise ValueError("source and index output must be different files")
    source_connection = open_read_only(source_path)
    try:
        source_metadata = metadata(source_connection)
        counts = source_counts(source_connection)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.stem}.", suffix=".sqlite.tmp", dir=output_path.parent
        )
        os.close(fd)
        temporary_path = Path(temporary_name)
        try:
            index_connection = sqlite3.connect(temporary_path)
            try:
                initialize_index(index_connection, source_metadata, counts)
                pending: list[tuple[str, int]] = []
                indexed_rows = 0
                indexed_pairs = 0
                for rowid, text in article_rows(source_connection):
                    indexed_rows += 1
                    pairs = set(chinese_bigrams(str(text)))
                    indexed_pairs += len(pairs)
                    pending.extend((pair, int(rowid)) for pair in pairs)
                    if len(pending) >= batch_size:
                        pending.sort()
                        index_connection.executemany(
                            "INSERT OR IGNORE INTO article_bigrams(bigram, article_rowid) VALUES (?, ?)",
                            pending,
                        )
                        index_connection.commit()
                        pending.clear()
                if pending:
                    pending.sort()
                    index_connection.executemany(
                        "INSERT OR IGNORE INTO article_bigrams(bigram, article_rowid) VALUES (?, ?)",
                        pending,
                    )
                index_connection.commit()
                indexed_pairs_distinct = int(
                    index_connection.execute("SELECT COUNT(*) FROM article_bigrams").fetchone()[0]
                )
                if indexed_rows != counts["law_articles"]:
                    raise RuntimeError(
                        "source article count changed while building index: "
                        f"expected {counts['law_articles']}, read {indexed_rows}"
                    )
                final_metadata = metadata(source_connection)
                final_counts = source_counts(source_connection)
                if final_metadata != source_metadata or final_counts != counts:
                    raise RuntimeError(
                        "source identity or row counts changed while building index"
                    )
                index_connection.execute("PRAGMA optimize")
                index_connection.commit()
            finally:
                index_connection.close()
            temporary_path.replace(output_path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
    finally:
        source_connection.close()

    result: dict[str, object] = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "source": str(source_path),
        "output": str(output_path),
        "source_schema_version": source_metadata["schema_version"],
        "source_runtime_schema_version": source_metadata["runtime_schema_version"],
        "source_manifest_sha256": source_metadata["source_manifest_sha256"],
        "dataset_version": source_metadata["dataset_version"],
        "source_counts": counts,
        "indexed_article_rows": indexed_rows,
        "indexed_pairs_before_deduplication": indexed_pairs,
        "distinct_index_pairs": indexed_pairs_distinct,
        "index_size_bytes": output_path.stat().st_size,
    }
    result["manifest_sha256"] = hashlib.sha256(
        json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def verify(index_path: Path, source_path: Path) -> dict[str, object]:
    source_path = Path(source_path)
    index_path = Path(index_path)
    if source_path.is_symlink() or not source_path.is_file():
        raise RuntimeError(f"source must be a regular non-symlink file: {source_path}")
    if index_path.is_symlink() or not index_path.is_file():
        raise RuntimeError(f"index must be a regular non-symlink file: {index_path}")
    source_path = source_path.absolute()
    index_path = index_path.absolute()
    source_connection = open_read_only(source_path)
    try:
        source_metadata = metadata(source_connection)
        counts = source_counts(source_connection)
    finally:
        source_connection.close()
    connection = sqlite3.connect(f"file:{index_path}?mode=ro", uri=True)
    try:
        values = {
            str(key): str(value)
            for key, value in connection.execute("SELECT key, value FROM search_index_metadata")
        }
        if values.get("schema_version") != INDEX_SCHEMA_VERSION:
            raise RuntimeError("unsupported search-index schema")
        for key in ("schema_version", "runtime_schema_version", "source_manifest_sha256", "dataset_version"):
            expected_key = "source_runtime_schema_version" if key == "runtime_schema_version" else key
            expected = (
                INDEX_SCHEMA_VERSION
                if key == "schema_version"
                else source_metadata[key]
            )
            if values.get(expected_key) != expected:
                raise RuntimeError(f"search-index source identity mismatch: {expected_key}")
        indexed_rows = int(values.get("source_article_count", "-1"))
        if indexed_rows != counts["law_articles"]:
            raise RuntimeError("search-index article count does not match source")
        actual_pairs = int(connection.execute("SELECT COUNT(*) FROM article_bigrams").fetchone()[0])
    finally:
        connection.close()
    return {
        "verified": True,
        "source": str(source_path),
        "index": str(index_path),
        "source_manifest_sha256": source_metadata["source_manifest_sha256"],
        "dataset_version": source_metadata["dataset_version"],
        "source_counts": counts,
        "distinct_index_pairs": actual_pairs,
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--batch-size", type=int, default=250_000)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.verify_only:
            result = verify(arguments.output, arguments.source)
        else:
            result = build(
                arguments.source,
                arguments.output,
                arguments.manifest,
                arguments.batch_size,
            )
    except (OSError, RuntimeError, sqlite3.DatabaseError, ValueError) as error:
        print(f"build_search_index: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
