#!/usr/bin/env python3
"""Read-only release gate for the SQLite resource bundled by Tauri."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RESOURCE = ROOT / "apps" / "desktop" / "src-tauri" / "resources" / "legal_core.sqlite"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_core_distribution_manifest.json"
VERIFIER_PATH = ROOT / "data" / "build" / "verify_legal_core_distribution.py"
COMPACTOR_PATH = ROOT / "data" / "build" / "compact_legal_core.py"
CI_ALLOW_VARIABLE = "LAWYER_ASSISTANCE_ALLOW_CI_FIXTURE_BUILD"
CI_FIXTURE_ID = "lawyer-assistance-github-actions-runtime-v1"


@lru_cache(maxsize=1)
def load_distribution_verifier() -> Any:
    spec = importlib.util.spec_from_file_location("verify_legal_core_distribution", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load distribution verifier: {VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def load_compactor() -> Any:
    spec = importlib.util.spec_from_file_location("compact_legal_core", COMPACTOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load legal database compactor: {COMPACTOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def open_read_only(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def runtime_facts(path: Path, *, check_integrity: bool = True) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    omitted_runtime_tables = set(load_compactor().OMITTED_RUNTIME_TABLES)
    connection = open_read_only(path)
    try:
        metadata = dict(connection.execute("SELECT key, value FROM database_metadata"))
        objects = dict(
            connection.execute(
                "SELECT name, type FROM sqlite_master WHERE name IN ("
                "'law_articles', 'law_article_rows', 'law_article_contents', "
                "'law_articles_fts', 'law_articles_fts_content')"
            )
        )
        all_objects = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master")
        }
        source_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(source_records)")
        }
        fts_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'law_articles_fts'"
        ).fetchone()
        fts_sql = "" if fts_sql_row is None or fts_sql_row[0] is None else str(fts_sql_row[0])
        compact_fts_sql = "".join(fts_sql.lower().split())
        integrity = (
            str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            if check_integrity
            else None
        )
        foreign_key_errors = (
            len(connection.execute("PRAGMA foreign_key_check").fetchall())
            if check_integrity
            else None
        )
        article_count = int(connection.execute("SELECT COUNT(*) FROM law_articles").fetchone()[0])
        article_row_count = int(
            connection.execute("SELECT COUNT(*) FROM law_article_rows").fetchone()[0]
        )
        content_count = int(
            connection.execute("SELECT COUNT(*) FROM law_article_contents").fetchone()[0]
        )
        fts_count = int(connection.execute("SELECT COUNT(*) FROM law_articles_fts").fetchone()[0])
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
                LEFT JOIN law_article_contents AS contents ON contents.content_id = rows.content_id
                WHERE contents.content_id IS NULL OR contents.content = ''
                """
            ).fetchone()[0]
        )
    finally:
        connection.close()
    return {
        "metadata": metadata,
        "objects": objects,
        "omitted_present": sorted(omitted_runtime_tables & all_objects),
        "source_columns": source_columns,
        "contentless_fts_sql": "content=''" in compact_fts_sql,
        "integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "article_count": article_count,
        "article_row_count": article_row_count,
        "content_count": content_count,
        "fts_count": fts_count,
        "citation_count": citation_count,
        "source_record_count": source_record_count,
        "missing_content": missing_content,
    }


def runtime_schema_failures(
    facts: dict[str, Any], *, expected_profile: str, expect_ci_fixture: bool
) -> list[str]:
    failures: list[str] = []
    metadata = facts["metadata"]
    objects = facts["objects"]
    if facts["integrity"] != "ok":
        failures.append(f"sqlite_integrity:{facts['integrity']}")
    if facts["foreign_key_errors"]:
        failures.append(f"foreign_keys:{facts['foreign_key_errors']}")
    expected_objects = {
        "law_articles": "view",
        "law_article_rows": "table",
        "law_article_contents": "table",
        "law_articles_fts": "table",
    }
    for name, expected_type in expected_objects.items():
        if objects.get(name) != expected_type:
            failures.append(f"object:{name}:{objects.get(name)}!={expected_type}")
    if "law_articles_fts_content" in objects:
        failures.append("runtime_fts_content_shadow_table_present")
    if not facts["contentless_fts_sql"]:
        failures.append("runtime_fts_is_not_declared_contentless")
    if {"raw_json", "raw_text"} & facts["source_columns"]:
        failures.append("archival_source_payload_columns_present")
    if facts["omitted_present"]:
        failures.append(f"archival_tables_present:{facts['omitted_present']}")
    if facts["article_count"] <= 0:
        failures.append("empty_law_articles")
    if facts["article_row_count"] != facts["article_count"]:
        failures.append(
            f"article_rows:{facts['article_row_count']}!={facts['article_count']}"
        )
    if not 0 < facts["content_count"] <= facts["article_count"]:
        failures.append(
            f"article_contents:{facts['content_count']} not in 1..{facts['article_count']}"
        )
    if facts["fts_count"] != facts["article_count"]:
        failures.append(f"fts:{facts['fts_count']}!={facts['article_count']}")
    if facts["citation_count"] != facts["article_count"]:
        failures.append(f"citations:{facts['citation_count']}!={facts['article_count']}")
    if facts["missing_content"]:
        failures.append(f"missing_article_content:{facts['missing_content']}")
    if metadata.get("distribution_profile") != expected_profile:
        failures.append(f"distribution_profile:{metadata.get('distribution_profile')}")
    compactor = load_compactor()
    if metadata.get("runtime_schema_version") != compactor.RUNTIME_SCHEMA_VERSION:
        failures.append(f"runtime_schema_version:{metadata.get('runtime_schema_version')}")
    if metadata.get("runtime_fts_contentless") != "true":
        failures.append(f"runtime_fts_contentless:{metadata.get('runtime_fts_contentless')}")
    if metadata.get("runtime_archival_payload_included") != "false":
        failures.append(
            f"runtime_archival_payload_included:{metadata.get('runtime_archival_payload_included')}"
        )
    if expect_ci_fixture:
        expected_fixture_metadata = {
            "dataset_name": compactor.FIXTURE_DATASET_NAME,
            "dataset_version": compactor.FIXTURE_DATASET_VERSION,
            "coverage_status": "ci_fixture",
            "distribution_profile": compactor.UNVERIFIED_RUNTIME_PROFILE,
            "runtime_source_verification": "unverified_ci_fixture",
            "runtime_ci_fixture_allowed": "true",
            "ci_fixture_id": CI_FIXTURE_ID,
            "runtime_source_dataset_name": compactor.FIXTURE_DATASET_NAME,
            "runtime_source_dataset_version": "ci-runtime-fixture-v1",
            "runtime_source_coverage_status": "fixture",
        }
        for key, expected in expected_fixture_metadata.items():
            if metadata.get(key) != expected:
                failures.append(f"metadata:{key}:{metadata.get(key)}!={expected}")
    else:
        if metadata.get("runtime_source_verification") not in {
            None,
            "trusted_archival_manifest",
        }:
            failures.append(
                f"runtime_source_verification:{metadata.get('runtime_source_verification')}"
            )
        if metadata.get("runtime_ci_fixture_allowed") not in {None, "false"}:
            failures.append(
                f"runtime_ci_fixture_allowed:{metadata.get('runtime_ci_fixture_allowed')}"
            )
    return failures


def verify_formal_resource(resource: Path, manifest_path: Path) -> dict[str, Any]:
    verifier = load_distribution_verifier()
    manifest = verifier.load_json(str(manifest_path))
    if manifest.get("ci_fixture_allowed") is not False:
        raise RuntimeError("formal manifest must explicitly set ci_fixture_allowed=false")
    result = verifier.verify_database(resource, manifest)
    failures = list(result["failures"])
    facts = runtime_facts(resource, check_integrity=False)
    facts["integrity"] = result["sqlite_integrity"]
    facts["foreign_key_errors"] = result["foreign_key_errors"]
    failures.extend(
        runtime_schema_failures(
            facts,
            expected_profile=str(manifest["runtime_profile"]),
            expect_ci_fixture=False,
        )
    )
    metadata = facts["metadata"]
    expected_metadata = {
        "dataset_name": "official-china-legal-core",
        "coverage_status": "complete",
        "dataset_version": str(manifest["dataset_version"]),
        "schema_version": str(manifest["schema_version"]),
        "distribution_profile": str(manifest["runtime_profile"]),
        "runtime_schema_version": str(manifest["runtime_schema_version"]),
    }
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            failures.append(f"metadata:{key}:{metadata.get(key)}!={expected}")
    if failures:
        raise RuntimeError(f"formal legal resource rejected: {failures}")
    return {
        "mode": "formal-manifest",
        "status": "complete",
        "resource": str(resource.resolve()),
        "manifest": str(manifest_path.resolve()),
        "sha256": result["sha256"],
        "dataset_version": metadata["dataset_version"],
        "article_count": facts["article_count"],
        "fts_count": facts["fts_count"],
    }


def verify_ci_fixture(resource: Path) -> dict[str, Any]:
    if os.environ.get("CI", "").lower() != "true" or os.environ.get(
        "GITHUB_ACTIONS", ""
    ).lower() != "true":
        raise RuntimeError(
            f"{CI_ALLOW_VARIABLE}=1 is accepted only inside GitHub Actions with CI=true"
        )
    facts = runtime_facts(resource)
    compactor = load_compactor()
    failures = runtime_schema_failures(
        facts,
        expected_profile=compactor.UNVERIFIED_RUNTIME_PROFILE,
        expect_ci_fixture=True,
    )
    metadata = facts["metadata"]
    expected_metadata = {
        "schema_version": "4",
    }
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            failures.append(f"metadata:{key}:{metadata.get(key)}!={expected}")
    source_manifest_hash = metadata.get("source_manifest_sha256", "")
    if len(source_manifest_hash) != 64 or any(
        character not in "0123456789abcdef" for character in source_manifest_hash.lower()
    ):
        failures.append("metadata:source_manifest_sha256:not-a-sha256")
    if facts["source_record_count"] != 1:
        failures.append(f"source_records:{facts['source_record_count']}!=1")
    if failures:
        raise RuntimeError(f"CI legal resource rejected: {failures}")
    return {
        "mode": "explicit-github-actions-fixture",
        "status": "complete",
        "resource": str(resource.resolve()),
        "fixture_id": metadata["ci_fixture_id"],
        "article_count": facts["article_count"],
        "fts_count": facts["fts_count"],
        "content_count": facts["content_count"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource", type=Path, default=DEFAULT_RESOURCE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    allow_value = os.environ.get(CI_ALLOW_VARIABLE)
    if allow_value is None:
        result = verify_formal_resource(arguments.resource, arguments.manifest)
    elif allow_value == "1":
        result = verify_ci_fixture(arguments.resource)
    else:
        raise RuntimeError(f"{CI_ALLOW_VARIABLE} must be unset or exactly '1'")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"legal resource verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
