#!/usr/bin/env python3
"""Build the small read-only app database from an audited archival legal core."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_SCHEMA = ROOT / "data" / "schema" / "legal_core_runtime.sql"
DEFAULT_INPUT = ROOT / "data" / "generated" / "legal_core_full.sqlite"
DEFAULT_OUTPUT = ROOT / "data" / "runtime" / "legal_core.sqlite"
DEFAULT_REPORT = ROOT / "data" / "generated" / "legal_core_runtime_report.json"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_core_distribution_manifest.json"
DEFAULT_ARCHIVAL_MANIFEST = ROOT / "data" / "generated" / "legal_core_full_manifest.json"
RUNTIME_PROFILE = "runtime-slim-v1"
UNVERIFIED_RUNTIME_PROFILE = "runtime-slim-v1-ci-fixture"
RUNTIME_SCHEMA_VERSION = "1"
FIXTURE_DATASET_NAME = "ci-fixture-not-for-release"
FIXTURE_DATASET_VERSION = "ci-fixture-unverified"
OMITTED_RUNTIME_TABLES = (
    "source_categories",
    "coverage_audit",
    "history_version_exceptions",
    "ingestion_audit",
    "legal_attachments",
    "guiding_cases",
    "document_templates",
)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_stat_snapshot(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def stable_file_hash(path: Path) -> tuple[dict[str, int], str]:
    before = file_stat_snapshot(path)
    digest = sha256_file(path)
    after = file_stat_snapshot(path)
    if before != after:
        raise RuntimeError(f"source file changed while hashing: {path}")
    return after, digest


def load_json_with_sha256(path: Path) -> tuple[dict[str, Any], str]:
    before = file_stat_snapshot(path)
    payload = path.read_bytes()
    after = file_stat_snapshot(path)
    if before != after:
        raise RuntimeError(f"manifest changed while reading: {path}")
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"manifest must contain a JSON object: {path}")
    return parsed, hashlib.sha256(payload).hexdigest()


def validate_archival_manifest(
    manifest_path: Path,
    source: Path,
    source_stat: dict[str, int],
    source_hash: str,
    metadata: dict[str, str],
    computed_source_manifest_hash: str,
) -> tuple[dict[str, Any], str]:
    manifest, manifest_hash = load_json_with_sha256(manifest_path)
    failures: list[str] = []

    if manifest.get("ci_fixture_allowed") is not False:
        failures.append("ci_fixture_allowed_must_be_false")
    if manifest.get("filename") != source.name:
        failures.append(f"filename:{manifest.get('filename')}!={source.name}")
    try:
        declared_size = int(manifest.get("size_bytes"))
    except (TypeError, ValueError):
        declared_size = -1
    if declared_size != source_stat["size_bytes"]:
        failures.append(f"size:{declared_size}!={source_stat['size_bytes']}")
    if str(manifest.get("sha256", "")).lower() != source_hash:
        failures.append("sha256_mismatch")
    if str(manifest.get("dataset_version")) != metadata.get("dataset_version"):
        failures.append(
            f"dataset_version:{manifest.get('dataset_version')}!={metadata.get('dataset_version')}"
        )
    if str(manifest.get("schema_version")) != metadata.get("schema_version"):
        failures.append(
            f"schema_version:{manifest.get('schema_version')}!={metadata.get('schema_version')}"
        )
    declared_source_manifest_hash = str(manifest.get("source_manifest_sha256", ""))
    if declared_source_manifest_hash != computed_source_manifest_hash:
        failures.append("source_manifest_sha256_mismatch")
    if metadata.get("source_manifest_sha256") != computed_source_manifest_hash:
        failures.append("database_source_manifest_sha256_mismatch")

    if failures:
        raise RuntimeError(f"archival manifest does not match source database: {failures}")
    return manifest, manifest_hash


def write_staged_json(target: Path, payload: dict[str, Any]) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
        dir=target.parent,
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        return Path(handle.name)


def source_manifest_sha256(connection: sqlite3.Connection, schema: str = "main") -> str:
    if schema not in {"main", "source"}:
        raise ValueError(f"unsupported schema: {schema}")
    digest = hashlib.sha256()
    rows: Iterable[sqlite3.Row] = connection.execute(
        f"""
        SELECT source_system_id, external_id, record_type, COALESCE(source_url, ''), checksum
        FROM {schema}.source_records
        ORDER BY source_system_id, external_id, record_type
        """
    )
    for row in rows:
        digest.update(json.dumps(list(row), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def table_exists(connection: sqlite3.Connection, schema: str, name: str) -> bool:
    return bool(
        connection.execute(
            f"SELECT COUNT(*) FROM {schema}.sqlite_master WHERE type IN ('table', 'view') AND name = ?",
            (name,),
        ).fetchone()[0]
    )


def table_count(connection: sqlite3.Connection, schema: str, name: str) -> int:
    if not table_exists(connection, schema, name):
        return 0
    return int(connection.execute(f'SELECT COUNT(*) FROM {schema}."{name}"').fetchone()[0])


def source_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    return dict(connection.execute("SELECT key, value FROM source.database_metadata"))


def validate_archival_source(connection: sqlite3.Connection, allow_unverified: bool) -> dict[str, Any]:
    metadata = source_metadata(connection)
    article_count = table_count(connection, "source", "law_articles")
    fts_count = table_count(connection, "source", "law_articles_fts")
    failures: list[str] = []
    if connection.execute("PRAGMA source.quick_check").fetchone()[0] != "ok":
        failures.append("quick_check_failed")
    if article_count == 0:
        failures.append("empty_law_articles")
    if fts_count != article_count:
        failures.append(f"fts_count:{fts_count}!={article_count}")
    if not allow_unverified:
        if metadata.get("schema_version") != "4":
            failures.append(f"schema_version:{metadata.get('schema_version')}")
        if metadata.get("coverage_status") != "complete":
            failures.append(f"coverage_status:{metadata.get('coverage_status')}")
        if metadata.get("dataset_name") != "official-china-legal-core":
            failures.append(f"dataset_name:{metadata.get('dataset_name')}")
    if failures:
        raise RuntimeError(f"archival source is not eligible for compaction: {failures}")
    return {
        "metadata": metadata,
        "document_count": table_count(connection, "source", "law_documents"),
        "version_count": table_count(connection, "source", "law_versions"),
        "article_count": article_count,
        "distinct_content_count": int(
            connection.execute(
                "SELECT COUNT(DISTINCT content) FROM source.law_articles"
            ).fetchone()[0]
        ),
        "fts_count": fts_count,
        "relation_count": table_count(connection, "source", "law_relations"),
        "source_record_count": table_count(connection, "source", "source_records"),
        "citation_count": table_count(connection, "source", "citation_metadata"),
    }


def copy_runtime_data(
    connection: sqlite3.Connection,
    timestamp: str,
    runtime_profile: str = RUNTIME_PROFILE,
    unverified_source: bool = False,
) -> dict[str, Any]:
    print("[1/6] copying metadata and runtime provenance", flush=True)
    connection.executescript(
        """
        INSERT INTO database_metadata SELECT * FROM source.database_metadata;
        INSERT INTO source_systems SELECT * FROM source.source_systems;
        INSERT INTO source_records (
          id, source_system_id, external_id, record_type, source_url, retrieved_at, checksum
        )
        SELECT id, source_system_id, external_id, record_type, source_url, retrieved_at, checksum
        FROM source.source_records;
        INSERT INTO issuing_authorities SELECT * FROM source.issuing_authorities;
        INSERT INTO law_documents SELECT * FROM source.law_documents;
        INSERT INTO law_versions SELECT * FROM source.law_versions;
        INSERT INTO law_relations SELECT * FROM source.law_relations;
        INSERT INTO law_aliases SELECT * FROM source.law_aliases;
        INSERT INTO legal_topics SELECT * FROM source.legal_topics;
        """
    )

    print("[2/6] deduplicating exact article text without dropping article identities", flush=True)
    connection.executescript(
        """
        CREATE TEMP TABLE content_map (
          content TEXT PRIMARY KEY,
          content_id INTEGER NOT NULL UNIQUE
        ) WITHOUT ROWID;
        INSERT INTO content_map (content, content_id)
        SELECT content, MIN(rowid) FROM source.law_articles GROUP BY content;
        INSERT INTO law_article_contents (content_id, content)
        SELECT content_id, content FROM content_map;
        INSERT INTO law_article_rows (
          article_rowid, id, document_id, version_id, article_number,
          article_order, title, content_id, updated_on
        )
        SELECT
          articles.rowid, articles.id, articles.document_id, articles.version_id,
          articles.article_number, articles.article_order, articles.title,
          content_map.content_id, articles.updated_on
        FROM source.law_articles AS articles
        JOIN content_map ON content_map.content = articles.content;
        INSERT INTO article_topics SELECT * FROM source.article_topics;
        DROP TABLE content_map;
        """
    )

    print("[3/6] compacting citation metadata", flush=True)
    connection.execute(
        """
        INSERT INTO citation_metadata (article_id, citation_id, canonical_label)
        SELECT article_id, citation_id, canonical_label FROM source.citation_metadata
        """
    )

    print("[4/6] building contentless FTS index", flush=True)
    connection.execute(
        """
        INSERT INTO law_articles_fts (
          rowid, article_id, document_id, version_id, document_title,
          article_number, article_title, content
        )
        SELECT
          articles.rowid, articles.id, articles.document_id, articles.version_id,
          documents.title, articles.article_number, COALESCE(articles.title, ''),
          articles.content
        FROM source.law_articles AS articles
        JOIN source.law_documents AS documents ON documents.id = articles.document_id
        """
    )
    connection.execute("INSERT INTO law_articles_fts(law_articles_fts) VALUES('optimize')")

    original_content_bytes = int(
        connection.execute(
            "SELECT COALESCE(SUM(length(CAST(content AS BLOB))), 0) FROM source.law_articles"
        ).fetchone()[0]
    )
    distinct_content_bytes = int(
        connection.execute(
            "SELECT COALESCE(SUM(length(CAST(content AS BLOB))), 0) FROM law_article_contents"
        ).fetchone()[0]
    )
    raw_source_payload_bytes = int(
        connection.execute(
            """
            SELECT COALESCE(SUM(
              COALESCE(length(CAST(raw_json AS BLOB)), 0) +
              COALESCE(length(CAST(raw_text AS BLOB)), 0)
            ), 0) FROM source.source_records
            """
        ).fetchone()[0]
    )
    omitted_counts = {
        table: table_count(connection, "source", table) for table in OMITTED_RUNTIME_TABLES
    }
    source_identity = source_metadata(connection)
    metadata_updates = {
        "distribution_profile": runtime_profile,
        "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
        "runtime_compacted_at": timestamp,
        "runtime_fts_contentless": "true",
        "runtime_article_content_deduplicated": "true",
        "runtime_archival_payload_included": "false",
        "runtime_omitted_tables": ",".join(OMITTED_RUNTIME_TABLES),
        "runtime_source_verification": (
            "unverified_ci_fixture" if unverified_source else "trusted_archival_manifest"
        ),
        "runtime_ci_fixture_allowed": "true" if unverified_source else "false",
    }
    if unverified_source:
        metadata_updates.update(
            {
                "runtime_source_dataset_name": source_identity.get("dataset_name", "unknown"),
                "runtime_source_dataset_version": source_identity.get("dataset_version", "unknown"),
                "runtime_source_coverage_status": source_identity.get("coverage_status", "unknown"),
                "dataset_name": FIXTURE_DATASET_NAME,
                "dataset_version": FIXTURE_DATASET_VERSION,
                "coverage_status": "ci_fixture",
            }
        )
    connection.executemany(
        """
        INSERT INTO database_metadata (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        [(key, value, timestamp) for key, value in metadata_updates.items()],
    )
    return {
        "original_content_bytes": original_content_bytes,
        "distinct_content_bytes": distinct_content_bytes,
        "deduplicated_content_bytes": original_content_bytes - distinct_content_bytes,
        "raw_source_payload_bytes_omitted": raw_source_payload_bytes,
        "omitted_table_rows": omitted_counts,
    }


def verify_runtime_database(
    path: Path,
    expected: dict[str, Any],
    expected_manifest_hash: str,
    runtime_profile: str = RUNTIME_PROFILE,
    expect_ci_fixture: bool = False,
) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
        document_count = table_count(connection, "main", "law_documents")
        version_count = table_count(connection, "main", "law_versions")
        article_count = table_count(connection, "main", "law_articles")
        article_row_count = table_count(connection, "main", "law_article_rows")
        content_count = table_count(connection, "main", "law_article_contents")
        fts_count = table_count(connection, "main", "law_articles_fts")
        relation_count = table_count(connection, "main", "law_relations")
        citation_count = table_count(connection, "main", "citation_metadata")
        source_record_count = table_count(connection, "main", "source_records")
        manifest_hash = source_manifest_sha256(connection)
        fts_content_table = table_exists(connection, "main", "law_articles_fts_content")
        source_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(source_records)")
        }
        omitted_present = [
            table for table in OMITTED_RUNTIME_TABLES if table_exists(connection, "main", table)
        ]
        missing_content = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM law_article_rows AS rows
                LEFT JOIN law_article_contents AS contents ON contents.content_id = rows.content_id
                WHERE contents.content_id IS NULL OR contents.content = ''
                """
            ).fetchone()[0]
        )
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        probe_started = time.perf_counter()
        connection.execute(
            "SELECT rowid FROM law_articles_fts WHERE law_articles_fts MATCH ? LIMIT 20",
            ('"违约责任"',),
        ).fetchall()
        fts_probe_ms = round((time.perf_counter() - probe_started) * 1000, 2)
    finally:
        connection.close()

    failures: list[str] = []
    if integrity != "ok":
        failures.append(f"integrity:{integrity}")
    if foreign_key_errors:
        failures.append(f"foreign_keys:{foreign_key_errors}")
    if metadata.get("distribution_profile") != runtime_profile:
        failures.append(f"distribution_profile:{metadata.get('distribution_profile')}")
    if metadata.get("runtime_schema_version") != RUNTIME_SCHEMA_VERSION:
        failures.append(f"runtime_schema_version:{metadata.get('runtime_schema_version')}")
    expected_verification = (
        "unverified_ci_fixture" if expect_ci_fixture else "trusted_archival_manifest"
    )
    if metadata.get("runtime_source_verification") != expected_verification:
        failures.append(
            f"runtime_source_verification:{metadata.get('runtime_source_verification')}"
        )
    expected_fixture_flag = "true" if expect_ci_fixture else "false"
    if metadata.get("runtime_ci_fixture_allowed") != expected_fixture_flag:
        failures.append(f"runtime_ci_fixture_allowed:{metadata.get('runtime_ci_fixture_allowed')}")
    if expect_ci_fixture:
        if metadata.get("dataset_name") != FIXTURE_DATASET_NAME:
            failures.append(f"fixture_dataset_name:{metadata.get('dataset_name')}")
        if metadata.get("dataset_version") != FIXTURE_DATASET_VERSION:
            failures.append(f"fixture_dataset_version:{metadata.get('dataset_version')}")
        if metadata.get("coverage_status") != "ci_fixture":
            failures.append(f"fixture_coverage_status:{metadata.get('coverage_status')}")
    else:
        for key in ("dataset_name", "dataset_version", "coverage_status", "schema_version"):
            if metadata.get(key) != expected["metadata"].get(key):
                failures.append(
                    f"metadata_{key}:{metadata.get(key)}!={expected['metadata'].get(key)}"
                )
    if document_count != expected["document_count"]:
        failures.append(f"documents:{document_count}!={expected['document_count']}")
    if version_count != expected["version_count"]:
        failures.append(f"versions:{version_count}!={expected['version_count']}")
    if article_count != expected["article_count"] or article_row_count != article_count:
        failures.append(
            f"articles:view={article_count},rows={article_row_count},expected={expected['article_count']}"
        )
    if fts_count != article_count:
        failures.append(f"fts:{fts_count}!={article_count}")
    if content_count != expected["distinct_content_count"]:
        failures.append(
            f"distinct_contents:{content_count}!={expected['distinct_content_count']}"
        )
    if relation_count != expected["relation_count"]:
        failures.append(f"relations:{relation_count}!={expected['relation_count']}")
    if citation_count != expected["citation_count"]:
        failures.append(f"citations:{citation_count}!={expected['citation_count']}")
    if source_record_count != expected["source_record_count"]:
        failures.append(f"source_records:{source_record_count}!={expected['source_record_count']}")
    if manifest_hash != expected_manifest_hash:
        failures.append("source_manifest_sha256_mismatch")
    if fts_content_table:
        failures.append("fts_content_shadow_table_present")
    if {"raw_json", "raw_text"} & source_columns:
        failures.append("archival_source_payload_columns_present")
    if omitted_present:
        failures.append(f"archival_tables_present:{omitted_present}")
    if missing_content:
        failures.append(f"missing_article_content:{missing_content}")
    if failures:
        raise RuntimeError(f"runtime database verification failed: {failures}")
    return {
        "status": "complete",
        "failures": failures,
        "sqlite_integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "runtime_profile": runtime_profile,
        "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
        "dataset_name": metadata.get("dataset_name"),
        "dataset_version": metadata.get("dataset_version"),
        "coverage_status": metadata.get("coverage_status"),
        "document_count": document_count,
        "version_count": version_count,
        "article_count": article_count,
        "article_row_count": article_row_count,
        "distinct_content_count": content_count,
        "fts_count": fts_count,
        "relation_count": relation_count,
        "citation_count": citation_count,
        "source_record_count": source_record_count,
        "source_manifest_sha256": manifest_hash,
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "fts_probe_ms": fts_probe_ms,
    }


def compact(
    source: Path,
    output: Path,
    report_path: Path,
    manifest_path: Path,
    allow_unverified_source: bool = False,
    archival_manifest_path: Path = DEFAULT_ARCHIVAL_MANIFEST,
) -> dict[str, Any]:
    source = source.resolve()
    output = output.resolve()
    report_path = report_path.resolve()
    manifest_path = manifest_path.resolve()
    archival_manifest_path = archival_manifest_path.resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    publication_paths = (output, report_path, manifest_path)
    if len(set(publication_paths)) != len(publication_paths):
        raise ValueError("output, report, and manifest paths must be distinct")
    if source in publication_paths:
        raise ValueError("input must differ from output, report, and manifest paths")
    if not allow_unverified_source and archival_manifest_path in publication_paths:
        raise ValueError("trusted archival manifest must not be overwritten by build outputs")
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = now_iso()
    started = time.perf_counter()
    initial_source_stat, source_hash = stable_file_hash(source)
    source_size = initial_source_stat["size_bytes"]
    runtime_profile = (
        UNVERIFIED_RUNTIME_PROFILE if allow_unverified_source else RUNTIME_PROFILE
    )
    staged_report: Path | None = None
    staged_manifest: Path | None = None

    with tempfile.NamedTemporaryFile(
        prefix="legal_core_runtime_", suffix=".sqlite", delete=False, dir=output.parent
    ) as handle:
        staged = Path(handle.name)
    try:
        connection = sqlite3.connect(staged, uri=True)
        connection.execute("PRAGMA journal_mode = OFF")
        connection.execute("PRAGMA synchronous = OFF")
        connection.execute("PRAGMA temp_store = FILE")
        connection.execute("PRAGMA cache_size = -262144")
        connection.execute("PRAGMA mmap_size = 1073741824")
        try:
            source_uri = f"file:{source.as_posix()}?mode=ro"
            connection.execute("ATTACH DATABASE ? AS source", (source_uri,))
            expected = validate_archival_source(connection, allow_unverified_source)
            expected_manifest_hash = source_manifest_sha256(connection, "source")
            declared_hash = expected["metadata"].get("source_manifest_sha256")
            if declared_hash and declared_hash != expected_manifest_hash:
                raise RuntimeError("archival source manifest hash does not match its source records")
            archival_manifest: dict[str, Any] | None = None
            archival_manifest_hash: str | None = None
            if not allow_unverified_source:
                archival_manifest, archival_manifest_hash = validate_archival_manifest(
                    archival_manifest_path,
                    source,
                    initial_source_stat,
                    source_hash,
                    expected["metadata"],
                    expected_manifest_hash,
                )
            connection.executescript(RUNTIME_SCHEMA.read_text(encoding="utf-8"))
            compaction = copy_runtime_data(
                connection,
                timestamp,
                runtime_profile,
                allow_unverified_source,
            )
            connection.commit()
            print("[5/6] analyzing and vacuuming runtime database", flush=True)
            connection.execute("ANALYZE main")
            connection.execute("PRAGMA main.optimize")
            connection.commit()
            connection.execute("DETACH DATABASE source")
            connection.execute("VACUUM")
            connection.execute("PRAGMA journal_mode = DELETE")
        finally:
            connection.close()

        print("[6/6] verifying compact runtime database", flush=True)
        verification = verify_runtime_database(
            staged,
            expected,
            expected_manifest_hash,
            runtime_profile,
            allow_unverified_source,
        )
        runtime_size = staged.stat().st_size
        runtime_hash = sha256_file(staged)
        final_source_stat, final_source_hash = stable_file_hash(source)
        if final_source_hash != source_hash or final_source_stat != initial_source_stat:
            raise RuntimeError("archival source changed during compaction; refusing publication")
        elapsed_seconds = round(time.perf_counter() - started, 2)
        trust_mode = (
            "unverified_ci_fixture" if allow_unverified_source else "trusted_archival_manifest"
        )
        counts = {
            "documents": verification["document_count"],
            "versions": verification["version_count"],
            "articles": verification["article_count"],
            "article_rows": verification["article_row_count"],
            "distinct_article_contents": verification["distinct_content_count"],
            "fts_rows": verification["fts_count"],
            "relations": verification["relation_count"],
            "citations": verification["citation_count"],
            "source_records": verification["source_record_count"],
        }
        report = {
            "generated_at": timestamp,
            "runtime_profile": runtime_profile,
            "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
            "source_verification": trust_mode,
            "ci_fixture_allowed": allow_unverified_source,
            "input": str(source),
            "output": str(output),
            "input_size_bytes": source_size,
            "output_size_bytes": runtime_size,
            "reduction_bytes": source_size - runtime_size,
            "reduction_percent": round(100 * (source_size - runtime_size) / source_size, 2),
            "input_sha256": source_hash,
            "output_sha256": runtime_hash,
            "source_stat_before": initial_source_stat,
            "source_stat_after": final_source_stat,
            "source_revalidated_after_compaction": True,
            "archival_manifest": (
                {
                    "path": str(archival_manifest_path),
                    "sha256": archival_manifest_hash,
                    "filename": archival_manifest.get("filename") if archival_manifest else None,
                }
                if not allow_unverified_source
                else None
            ),
            "counts": counts,
            "elapsed_seconds": elapsed_seconds,
            "compaction": compaction,
            "verification": verification,
        }
        metadata = expected["metadata"]
        manifest = {
            "dataset_name": verification["dataset_name"],
            "dataset_version": verification["dataset_version"],
            "source_dataset_name": metadata.get("dataset_name", "unknown"),
            "source_dataset_version": metadata.get("dataset_version", "unknown"),
            "coverage_status": verification["coverage_status"],
            "source_coverage_status": metadata.get("coverage_status", "unknown"),
            "data_scope": metadata.get("data_scope", "unknown"),
            "generated_at": timestamp,
            "filename": output.name,
            "size_bytes": runtime_size,
            "sha256": runtime_hash,
            "source_manifest_sha256": expected_manifest_hash,
            "schema_version": metadata.get("schema_version", "4"),
            "runtime_profile": runtime_profile,
            "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
            "archival_source_sha256": source_hash,
            "archival_source_size_bytes": source_size,
            "archival_manifest_filename": (
                archival_manifest_path.name if not allow_unverified_source else None
            ),
            "archival_manifest_sha256": archival_manifest_hash,
            "source_verification": trust_mode,
            "source_revalidated_after_compaction": True,
            "counts": counts,
            "distribution_status": (
                "ci_fixture_not_for_release"
                if allow_unverified_source
                else "local_snapshot_pending_external_publish"
            ),
            "download_url": None,
            "ci_fixture_allowed": allow_unverified_source,
        }
        staged_report = write_staged_json(report_path, report)
        staged_manifest = write_staged_json(manifest_path, manifest)
        staged.replace(output)
        staged_report.replace(report_path)
        staged_report = None
        staged_manifest.replace(manifest_path)
        staged_manifest = None
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return report
    finally:
        if staged.exists():
            staged.unlink()
        if staged_report is not None and staged_report.exists():
            staged_report.unlink()
        if staged_manifest is not None and staged_manifest.exists():
            staged_manifest.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--archival-manifest",
        type=Path,
        default=DEFAULT_ARCHIVAL_MANIFEST,
        help="Trusted manifest that binds the archival input filename, size, hashes, and schema.",
    )
    parser.add_argument(
        "--allow-unverified-source",
        action="store_true",
        help="Allow fixture databases without the production coverage metadata.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    compact(
        arguments.input,
        arguments.output,
        arguments.report,
        arguments.manifest,
        arguments.allow_unverified_source,
        arguments.archival_manifest,
    )
