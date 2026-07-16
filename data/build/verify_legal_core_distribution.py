#!/usr/bin/env python3
"""Download/copy and atomically install a verified legal_core.sqlite release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_core_distribution_manifest.json"
DEFAULT_OUTPUT = ROOT / "apps" / "desktop" / "src-tauri" / "resources" / "legal_core.sqlite"
RUNTIME_PROFILE = "runtime-slim-v1"
RUNTIME_SCHEMA_VERSION = "1"
OFFICIAL_DATASET_NAME = "official-china-legal-core"
COMPLETE_COVERAGE_STATUS = "complete"
TRUSTED_SOURCE_VERIFICATION = "trusted_archival_manifest"
OMITTED_RUNTIME_TABLES = (
    "source_categories",
    "coverage_audit",
    "history_version_exceptions",
    "ingestion_audit",
    "legal_attachments",
    "guiding_cases",
    "document_templates",
)
RUNTIME_COUNT_FIELDS = {
    "document_count": "documents",
    "version_count": "versions",
    "article_count": "articles",
    "article_row_count": "article_rows",
    "distinct_content_count": "distinct_article_contents",
    "fts_count": "fts_rows",
    "relation_count": "relations",
    "citation_count": "citations",
    "source_record_count": "source_records",
}
SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
RUNTIME_MANIFEST_MARKERS = frozenset(
    {
        "runtime_profile",
        "runtime_schema_version",
        "source_verification",
        "archival_source_sha256",
        "archival_manifest_sha256",
        "counts",
    }
)


def _is_windows_drive_path(location: str) -> bool:
    return len(location) >= 2 and location[0].isalpha() and location[1] == ":"


def _is_remote_location(location: str) -> bool:
    return not _is_windows_drive_path(location) and urlparse(location).scheme in {"http", "https"}


def _normalized_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be exactly 64 hexadecimal characters")
    return value.lower()


def _read_location(location: str) -> bytes:
    parsed = urlparse(location)
    if _is_remote_location(location):
        with urllib.request.urlopen(location, timeout=60) as response:
            return response.read()
    if not _is_windows_drive_path(location) and parsed.scheme == "file":
        return Path(urllib.request.url2pathname(parsed.path)).read_bytes()
    if not _is_windows_drive_path(location) and parsed.scheme:
        raise ValueError(f"unsupported manifest scheme: {parsed.scheme}")
    return Path(location).read_bytes()


def load_json(location: str, expected_sha256: str | None = None) -> dict[str, Any]:
    if _is_remote_location(location) and expected_sha256 is None:
        raise RuntimeError(
            "remote manifest requires --manifest-sha256 as an external trust root"
        )
    payload = _read_location(location)
    if expected_sha256 is not None:
        expected = _normalized_sha256(expected_sha256, "manifest SHA-256")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise RuntimeError(f"manifest SHA-256 mismatch: {actual}!={expected}")
    manifest = json.loads(payload.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("distribution manifest must contain a JSON object")
    return manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest_sha256(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    rows: Iterable[sqlite3.Row] = connection.execute(
        """
        SELECT source_system_id, external_id, record_type, COALESCE(source_url, ''), checksum
        FROM source_records
        ORDER BY source_system_id, external_id, record_type
        """
    )
    for row in rows:
        digest.update(json.dumps(list(row), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _local_path(location: str | Path) -> Path:
    if isinstance(location, Path):
        return location
    parsed = urlparse(location)
    if _is_remote_location(location):
        raise ValueError("--verify-only accepts only a local path or file URL")
    if not _is_windows_drive_path(location) and parsed.scheme == "file":
        return Path(urllib.request.url2pathname(parsed.path))
    if not _is_windows_drive_path(location) and parsed.scheme:
        raise ValueError(f"unsupported distribution scheme: {parsed.scheme}")
    return Path(location)


def copy_or_download(source: str, destination: Path) -> None:
    parsed = urlparse(source)
    if _is_remote_location(source):
        with urllib.request.urlopen(source, timeout=300) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output, length=8 * 1024 * 1024)
        return
    if not _is_windows_drive_path(source) and parsed.scheme == "file":
        source_path = Path(urllib.request.url2pathname(parsed.path))
    elif _is_windows_drive_path(source) or not parsed.scheme:
        source_path = Path(source)
    else:
        raise ValueError(f"unsupported distribution scheme: {parsed.scheme}")
    shutil.copy2(source_path, destination)


def _object_exists(connection: sqlite3.Connection, name: str) -> bool:
    return bool(
        connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type IN ('table', 'view') AND name = ?",
            (name,),
        ).fetchone()[0]
    )


def _manifest_int(
    manifest: dict[str, Any], key: str, failures: list[str], *, required: bool
) -> int | None:
    if key not in manifest:
        if required:
            failures.append(f"manifest_missing:{key}")
        return None
    try:
        value = int(manifest[key])
    except (TypeError, ValueError):
        failures.append(f"manifest_invalid_integer:{key}")
        return None
    if value < 0:
        failures.append(f"manifest_invalid_integer:{key}")
        return None
    return value


def _manifest_runtime_count(
    manifest: dict[str, Any], key: str, failures: list[str], *, required: bool
) -> int | None:
    nested_key = RUNTIME_COUNT_FIELDS[key]
    counts = manifest.get("counts")
    if isinstance(counts, dict) and nested_key in counts:
        raw_value = counts[nested_key]
        label = f"counts.{nested_key}"
    elif key in manifest:
        # Pre-release manifests briefly used top-level count names. Keep them
        # readable while requiring every count for a formal runtime release.
        raw_value = manifest[key]
        label = key
    else:
        if required:
            failures.append(f"manifest_missing:counts.{nested_key}")
        return None
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        failures.append(f"manifest_invalid_integer:{label}")
        return None
    if value < 0:
        failures.append(f"manifest_invalid_integer:{label}")
        return None
    return value


def _validate_manifest_contract(manifest: dict[str, Any], failures: list[str]) -> None:
    if manifest.get("ci_fixture_allowed") is not False:
        failures.append("ci_fixture_allowed_must_be_false")
    for key in ("sha256", "source_manifest_sha256"):
        try:
            _normalized_sha256(manifest.get(key), key)
        except ValueError:
            failures.append(f"manifest_invalid_sha256:{key}")


def _manifest_has_runtime_markers(manifest: dict[str, Any]) -> bool:
    return bool(RUNTIME_MANIFEST_MARKERS & manifest.keys())


def _validate_runtime_manifest_contract(
    manifest: dict[str, Any], failures: list[str]
) -> None:
    expected_fields = {
        "runtime_profile": RUNTIME_PROFILE,
        "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
        "source_verification": TRUSTED_SOURCE_VERIFICATION,
        "dataset_name": OFFICIAL_DATASET_NAME,
        "source_dataset_name": OFFICIAL_DATASET_NAME,
        "coverage_status": COMPLETE_COVERAGE_STATUS,
        "source_coverage_status": COMPLETE_COVERAGE_STATUS,
    }
    for key, expected in expected_fields.items():
        actual = manifest.get(key)
        if str(actual) != expected:
            failures.append(f"{key}:{actual}!={expected}")
    for key in ("archival_source_sha256", "archival_manifest_sha256"):
        try:
            _normalized_sha256(manifest.get(key), key)
        except ValueError:
            failures.append(f"manifest_invalid_sha256:{key}")
    for key in RUNTIME_COUNT_FIELDS:
        _manifest_runtime_count(manifest, key, failures, required=True)


def verify_database(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    path = path.resolve()
    failures: list[str] = []
    _validate_manifest_contract(manifest, failures)

    expected_size = _manifest_int(manifest, "size_bytes", failures, required=True)
    actual_size = path.stat().st_size
    expected_sha: str | None
    try:
        expected_sha = _normalized_sha256(manifest.get("sha256"), "sha256")
    except ValueError:
        expected_sha = None
    actual_sha = sha256_file(path)
    if expected_size is not None and actual_size != expected_size:
        failures.append(f"size:{actual_size}!={expected_size}")
    if expected_sha is not None and actual_sha != expected_sha:
        failures.append(f"sha256:{actual_sha}!={expected_sha}")

    integrity: str | None = None
    foreign_key_errors: int | None = None
    metadata: dict[str, str] = {}
    schema_version: str | None = None
    dataset_version: str | None = None
    manifest_hash: str | None = None
    runtime_profile: str | None = None
    runtime_schema_version: str | None = None
    sqlite_user_version: int | None = None
    document_count: int | None = None
    version_count: int | None = None
    article_count: int | None = None
    article_row_count: int | None = None
    distinct_content_count: int | None = None
    fts_count: int | None = None
    relation_count: int | None = None
    citation_count: int | None = None
    source_record_count: int | None = None
    missing_content: int | None = None
    omitted_tables_present: list[str] = []
    omitted_columns_present: list[str] = []
    fts_content_table: bool | None = None
    runtime_contract_required = _manifest_has_runtime_markers(manifest)
    runtime_object_types: dict[str, str | None] = {}
    runtime_fts_sql: str | None = None
    runtime_fts_contentless: bool | None = None

    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        integrity_rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        integrity = "ok" if integrity_rows == ["ok"] else "; ".join(integrity_rows[:10])
        foreign_key_errors = sum(1 for _ in connection.execute("PRAGMA foreign_key_check"))
        metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
        schema_version = metadata.get("schema_version")
        dataset_version = metadata.get("dataset_version")
        manifest_hash = source_manifest_sha256(connection)
        runtime_profile = metadata.get("distribution_profile")
        runtime_schema_version = metadata.get("runtime_schema_version")
        sqlite_user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        runtime_object_names = (
            "law_articles",
            "law_article_rows",
            "law_article_contents",
            "law_articles_fts",
        )
        runtime_objects = {
            str(row[0]): (str(row[1]), str(row[2]) if row[2] is not None else None)
            for row in connection.execute(
                "SELECT name, type, sql FROM sqlite_master "
                f"WHERE name IN ({','.join('?' for _ in runtime_object_names)})",
                runtime_object_names,
            )
        }
        runtime_contract_required = runtime_contract_required or any(
            key.startswith("runtime_") or key == "distribution_profile" for key in metadata
        ) or any(name in runtime_objects for name in ("law_article_rows", "law_article_contents"))

        if runtime_contract_required:
            _validate_runtime_manifest_contract(manifest, failures)
            runtime_object_types = {
                name: runtime_objects.get(name, (None, None))[0]
                for name in runtime_object_names
            }
            runtime_fts_sql = runtime_objects.get("law_articles_fts", (None, None))[1]
            runtime_fts_contentless = bool(
                runtime_fts_sql
                and re.search(
                    r"\busing\s+fts5\b",
                    runtime_fts_sql,
                    re.IGNORECASE,
                )
                and re.search(
                    r"\bcontent\s*=\s*(?:''|\"\")",
                    runtime_fts_sql,
                    re.IGNORECASE,
                )
            )
            document_count = int(
                connection.execute("SELECT COUNT(*) FROM law_documents").fetchone()[0]
            )
            version_count = int(
                connection.execute("SELECT COUNT(*) FROM law_versions").fetchone()[0]
            )
            article_count = int(connection.execute("SELECT COUNT(*) FROM law_articles").fetchone()[0])
            article_row_count = int(
                connection.execute("SELECT COUNT(*) FROM law_article_rows").fetchone()[0]
            )
            distinct_content_count = int(
                connection.execute("SELECT COUNT(*) FROM law_article_contents").fetchone()[0]
            )
            fts_count = int(connection.execute("SELECT COUNT(*) FROM law_articles_fts").fetchone()[0])
            relation_count = int(
                connection.execute("SELECT COUNT(*) FROM law_relations").fetchone()[0]
            )
            citation_count = int(
                connection.execute("SELECT COUNT(*) FROM citation_metadata").fetchone()[0]
            )
            source_record_count = int(
                connection.execute("SELECT COUNT(*) FROM source_records").fetchone()[0]
            )
            missing_content = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM law_article_rows AS rows
                    LEFT JOIN law_article_contents AS contents
                      ON contents.content_id = rows.content_id
                    WHERE contents.content_id IS NULL OR contents.content = ''
                    """
                ).fetchone()[0]
            )
            fts_content_table = _object_exists(connection, "law_articles_fts_content")
            omitted_tables_present = [
                table for table in OMITTED_RUNTIME_TABLES if _object_exists(connection, table)
            ]
            source_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(source_records)")
            }
            citation_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(citation_metadata)")
            }
            omitted_columns_present = sorted(
                {f"source_records.{column}" for column in {"raw_json", "raw_text"} & source_columns}
                | ({"citation_metadata.id"} if "id" in citation_columns else set())
            )
    except sqlite3.Error as error:
        failures.append(f"sqlite_error:{error}")
    finally:
        connection.close()

    if integrity != "ok":
        failures.append(f"sqlite_integrity:{integrity}")
    if foreign_key_errors:
        failures.append(f"foreign_key_errors:{foreign_key_errors}")
    if schema_version != str(manifest.get("schema_version")):
        failures.append(f"schema_version:{schema_version}!={manifest.get('schema_version')}")
    if dataset_version != str(manifest.get("dataset_version")):
        failures.append(f"dataset_version:{dataset_version}!={manifest.get('dataset_version')}")
    if manifest_hash != str(manifest.get("source_manifest_sha256")):
        failures.append("source_manifest_sha256_mismatch")

    if runtime_contract_required:
        if runtime_profile != RUNTIME_PROFILE:
            failures.append(f"database_runtime_profile:{runtime_profile}!={RUNTIME_PROFILE}")
        if runtime_schema_version != RUNTIME_SCHEMA_VERSION:
            failures.append(
                "database_runtime_schema_version:"
                f"{runtime_schema_version}!={RUNTIME_SCHEMA_VERSION}"
            )
        expected_user_version = int(RUNTIME_SCHEMA_VERSION)
        if sqlite_user_version != expected_user_version:
            failures.append(f"sqlite_user_version:{sqlite_user_version}!={expected_user_version}")
        expected_metadata = {
            "dataset_name": OFFICIAL_DATASET_NAME,
            "coverage_status": COMPLETE_COVERAGE_STATUS,
            "runtime_source_verification": TRUSTED_SOURCE_VERIFICATION,
            "runtime_ci_fixture_allowed": "false",
            "runtime_fts_contentless": "true",
            "runtime_archival_payload_included": "false",
        }
        for key, expected in expected_metadata.items():
            actual = metadata.get(key)
            if actual != expected:
                failures.append(f"database_metadata_{key}:{actual}!={expected}")
        expected_object_types = {
            "law_articles": "view",
            "law_article_rows": "table",
            "law_article_contents": "table",
            "law_articles_fts": "table",
        }
        for name, expected_type in expected_object_types.items():
            actual_type = runtime_object_types.get(name)
            if actual_type != expected_type:
                failures.append(f"runtime_object_type:{name}:{actual_type}!={expected_type}")
        if runtime_fts_contentless is not True:
            failures.append("runtime_fts_not_contentless")
        if article_row_count != article_count:
            failures.append(f"article_rows:{article_row_count}!={article_count}")
        if fts_count != article_count:
            failures.append(f"fts_count:{fts_count}!={article_count}")
        if citation_count != article_count:
            failures.append(f"citation_count:{citation_count}!={article_count}")
        if missing_content:
            failures.append(f"missing_article_content:{missing_content}")
        if fts_content_table:
            failures.append("runtime_fts_content_shadow_table_present")
        if omitted_tables_present:
            failures.append(f"archival_tables_present:{','.join(omitted_tables_present)}")
        if omitted_columns_present:
            failures.append(f"archival_columns_present:{','.join(omitted_columns_present)}")

        actual_counts = {
            "document_count": document_count,
            "version_count": version_count,
            "article_count": article_count,
            "article_row_count": article_row_count,
            "distinct_content_count": distinct_content_count,
            "fts_count": fts_count,
            "relation_count": relation_count,
            "citation_count": citation_count,
            "source_record_count": source_record_count,
        }
        for key, actual in actual_counts.items():
            expected = _manifest_runtime_count(manifest, key, [], required=False)
            if expected is not None and actual != expected:
                failures.append(f"{key}:{actual}!={expected}")

    return {
        "status": "complete" if not failures else "failed",
        "failures": failures,
        "size_bytes": actual_size,
        "sha256": actual_sha,
        "sqlite_integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "schema_version": schema_version,
        "dataset_version": dataset_version,
        "source_manifest_sha256": manifest_hash,
        "runtime_profile": runtime_profile,
        "runtime_schema_version": runtime_schema_version,
        "sqlite_user_version": sqlite_user_version,
        "archival_source_sha256": manifest.get("archival_source_sha256"),
        "document_count": document_count,
        "version_count": version_count,
        "article_count": article_count,
        "article_row_count": article_row_count,
        "distinct_content_count": distinct_content_count,
        "fts_count": fts_count,
        "relation_count": relation_count,
        "citation_count": citation_count,
        "source_record_count": source_record_count,
        "missing_article_content": missing_content,
        "omitted_tables_present": omitted_tables_present,
        "omitted_columns_present": omitted_columns_present,
        "runtime_object_types": runtime_object_types,
        "runtime_fts_contentless": runtime_fts_contentless,
    }


def verify_only(
    manifest_location: str,
    database: str | Path,
    manifest_sha256: str | None = None,
) -> int:
    manifest = load_json(manifest_location, manifest_sha256)
    database_path = _local_path(database)
    result = verify_database(database_path, manifest)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "complete" else 1


def install(
    manifest_location: str,
    output: Path,
    source_override: str | None,
    manifest_sha256: str | None = None,
) -> int:
    manifest = load_json(manifest_location, manifest_sha256)
    if manifest.get("ci_fixture_allowed") is not False:
        raise RuntimeError("manifest does not explicitly forbid CI fixture distribution")
    source = source_override or manifest.get("download_url")
    if not source:
        raise RuntimeError(
            "distribution manifest has no download_url; provide --source for an audited local handoff"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="legal_core_download_", suffix=".sqlite", delete=False, dir=output.parent
    ) as handle:
        staged = Path(handle.name)
    try:
        copy_or_download(str(source), staged)
        result = verify_database(staged, manifest)
        if result["status"] != "complete":
            raise RuntimeError(f"legal database verification failed: {result['failures']}")
        staged.replace(output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if staged.exists():
            staged.unlink()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument(
        "--manifest-sha256",
        help="Expected SHA-256 of the raw manifest; required for HTTP(S) manifests.",
    )
    parser.add_argument(
        "--source",
        help="Audited local path/file URL/HTTPS URL overriding manifest download_url.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify --source, or --output when omitted, in place without copying or replacing it.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    if arguments.verify_only:
        database = arguments.source if arguments.source is not None else arguments.output
        return verify_only(arguments.manifest, database, arguments.manifest_sha256)
    return install(
        arguments.manifest,
        arguments.output,
        arguments.source,
        arguments.manifest_sha256,
    )


if __name__ == "__main__":
    raise SystemExit(main())
