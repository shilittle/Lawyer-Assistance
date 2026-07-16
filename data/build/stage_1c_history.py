#!/usr/bin/env python3
"""Normalize official FLK history relations into real multi-version laws.

This is the first independently auditable slice of Stage 1C.  It deliberately
does not claim that the guiding-case, typical-case, or document-template
corpora are complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE = ROOT / "data" / "generated" / "legal_core_full.sqlite"
DEFAULT_REPORT = ROOT / "data" / "generated" / "stage_1c_history_report.json"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_core_full_manifest.json"
DATASET_VERSION = "2026.07.14-history.2"

# Civil Code article 1260 makes these nine statutes cease to be effective when
# the Civil Code takes effect on 2021-01-01. The FLK snapshot marks the
# versions repealed but omits their terminal dates, so this primary-source rule
# is applied explicitly rather than guessed by query code.
# Source: https://wb.flk.npc.gov.cn/flfg/PDF/bd53dd912c1048f2aecbaa229238334b.pdf
CIVIL_CODE_REPEALED_TITLES = (
    "中华人民共和国婚姻法",
    "中华人民共和国继承法",
    "中华人民共和国民法通则",
    "中华人民共和国收养法",
    "中华人民共和国担保法",
    "中华人民共和国合同法",
    "中华人民共和国物权法",
    "中华人民共和国侵权责任法",
    "中华人民共和国民法总则",
)
CIVIL_CODE_REPEAL_EFFECTIVE_TO = "2020-12-31"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class UnionFind:
    def __init__(self) -> None:
        self.parents: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parents.setdefault(item, item)
        if self.parents[item] != item:
            self.parents[item] = self.find(self.parents[item])
        return self.parents[item]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parents[right_root] = left_root

    def components(self) -> list[set[str]]:
        grouped: dict[str, set[str]] = defaultdict(set)
        for item in self.parents:
            grouped[self.find(item)].add(item)
        return list(grouped.values())


@dataclass
class HistoryNormalizationReport:
    relation_count: int
    component_count: int
    merged_family_count: int
    skipped_family_count: int
    removed_document_count: int
    reparented_version_count: int
    bounded_version_count: int
    authoritatively_bounded_version_count: int
    skipped_families: list[dict[str, object]]


def _placeholders(count: int) -> str:
    return ",".join("?" for _ in range(count))


def history_components(connection: sqlite3.Connection) -> tuple[int, list[set[str]]]:
    rows = connection.execute(
        """
        SELECT from_document_id, to_document_id
        FROM law_relations
        WHERE relation_type = 'history_version'
        """
    ).fetchall()
    union_find = UnionFind()
    for left, right in rows:
        union_find.union(left, right)
    return len(rows), union_find.components()


def _versions_for_documents(
    connection: sqlite3.Connection, document_ids: set[str]
) -> list[sqlite3.Row]:
    return connection.execute(
        f"""
        SELECT versions.id, versions.document_id, versions.effective_from,
               versions.published_on, versions.status, documents.source_url,
               documents.title
        FROM law_versions versions
        JOIN law_documents documents ON documents.id = versions.document_id
        WHERE versions.document_id IN ({_placeholders(len(document_ids))})
        ORDER BY versions.effective_from, versions.published_on, versions.id
        """,
        tuple(sorted(document_ids)),
    ).fetchall()


def _valid_iso_date(value: object) -> bool:
    if not isinstance(value, str) or value == "0001-01-01":
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def _skip_reason(versions: list[sqlite3.Row]) -> str | None:
    if len(versions) < 2:
        return "fewer_than_two_versions"
    effective_dates = [row["effective_from"] for row in versions]
    if not all(_valid_iso_date(value) for value in effective_dates):
        return "missing_or_invalid_effective_date"
    if len(set(effective_dates)) != len(effective_dates):
        return "duplicate_effective_date"
    return None


def _canonical_document_id(versions: list[sqlite3.Row]) -> str:
    latest = max(
        versions,
        key=lambda row: (
            row["effective_from"],
            row["published_on"] or "",
            row["id"],
        ),
    )
    return str(latest["document_id"])


def _move_family(
    connection: sqlite3.Connection,
    document_ids: set[str],
    versions: list[sqlite3.Row],
) -> tuple[int, int, int]:
    canonical_id = _canonical_document_id(versions)
    obsolete_ids = sorted(document_ids - {canonical_id})
    if not obsolete_ids:
        return 0, 0, 0

    # Preserve the per-version official URL before removing the old document row.
    for row in versions:
        source_reference = row["source_url"] or "国家法律法规数据库"
        connection.execute(
            "UPDATE law_versions SET source_reference = ? WHERE id = ?",
            (source_reference, row["id"]),
        )

    placeholders = _placeholders(len(document_ids))
    version_ids = [str(row["id"]) for row in versions]
    connection.execute(
        f"UPDATE law_versions SET document_id = ? WHERE document_id IN ({placeholders})",
        (canonical_id, *sorted(document_ids)),
    )
    connection.execute(
        f"UPDATE law_articles SET document_id = ? WHERE version_id IN ({_placeholders(len(version_ids))})",
        (canonical_id, *version_ids),
    )
    connection.execute(
        f"UPDATE legal_attachments SET document_id = ? WHERE document_id IN ({placeholders})",
        (canonical_id, *sorted(document_ids)),
    )
    connection.execute(
        f"UPDATE law_aliases SET document_id = ? WHERE document_id IN ({placeholders})",
        (canonical_id, *sorted(document_ids)),
    )

    # History edges are now represented by law_versions.  Other relations are
    # retained, with obsolete endpoints redirected to the canonical document.
    connection.execute(
        f"""
        DELETE FROM law_relations
        WHERE relation_type = 'history_version'
          AND from_document_id IN ({placeholders})
          AND to_document_id IN ({placeholders})
        """,
        (*sorted(document_ids), *sorted(document_ids)),
    )
    obsolete_placeholders = _placeholders(len(obsolete_ids))
    connection.execute(
        f"UPDATE law_relations SET from_document_id = ? WHERE from_document_id IN ({obsolete_placeholders})",
        (canonical_id, *obsolete_ids),
    )
    connection.execute(
        f"UPDATE law_relations SET to_document_id = ? WHERE to_document_id IN ({obsolete_placeholders})",
        (canonical_id, *obsolete_ids),
    )
    connection.execute(
        "DELETE FROM law_relations WHERE from_document_id = to_document_id"
    )

    bounded = 0
    ordered = sorted(versions, key=lambda row: (row["effective_from"], row["id"]))
    for index, row in enumerate(ordered):
        effective_to = None
        if index + 1 < len(ordered):
            next_from = date.fromisoformat(ordered[index + 1]["effective_from"])
            effective_to = (next_from - timedelta(days=1)).isoformat()
            bounded += 1
        connection.execute(
            "UPDATE law_versions SET effective_to = ? WHERE id = ?",
            (effective_to, row["id"]),
        )

    connection.execute(
        f"DELETE FROM law_documents WHERE id IN ({obsolete_placeholders})",
        obsolete_ids,
    )
    return len(obsolete_ids), len(version_ids), bounded


def normalize_history(connection: sqlite3.Connection) -> HistoryNormalizationReport:
    connection.row_factory = sqlite3.Row
    relation_count, components = history_components(connection)
    removed_documents = 0
    reparented_versions = 0
    bounded_versions = 0
    merged_families = 0
    skipped: list[dict[str, object]] = []

    for document_ids in sorted(components, key=lambda values: sorted(values)[0]):
        versions = _versions_for_documents(connection, document_ids)
        reason = _skip_reason(versions)
        if reason:
            skipped.append(
                {
                    "reason": reason,
                    "document_ids": sorted(document_ids),
                    "titles": sorted({str(row["title"]) for row in versions}),
                    "effective_dates": [row["effective_from"] for row in versions],
                }
            )
            continue
        removed, reparented, bounded = _move_family(connection, document_ids, versions)
        if removed:
            merged_families += 1
            removed_documents += removed
            reparented_versions += reparented
            bounded_versions += bounded

    authoritative_bounded = apply_authoritative_terminal_dates(connection)

    return HistoryNormalizationReport(
        relation_count=relation_count,
        component_count=len(components),
        merged_family_count=merged_families,
        skipped_family_count=len(skipped),
        removed_document_count=removed_documents,
        reparented_version_count=reparented_versions,
        bounded_version_count=bounded_versions,
        authoritatively_bounded_version_count=authoritative_bounded,
        skipped_families=skipped,
    )


def apply_authoritative_terminal_dates(connection: sqlite3.Connection) -> int:
    placeholders = _placeholders(len(CIVIL_CODE_REPEALED_TITLES))
    cursor = connection.execute(
        f"""
        UPDATE law_versions
        SET effective_to = ?
        WHERE status = 'repealed'
          AND effective_to IS NULL
          AND effective_from <= ?
          AND document_id IN (
            SELECT id FROM law_documents WHERE title IN ({placeholders})
          )
        """,
        (
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            *CIVIL_CODE_REPEALED_TITLES,
        ),
    )
    return int(cursor.rowcount)


def authoritative_terminal_date_audit(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    placeholders = _placeholders(len(CIVIL_CODE_REPEALED_TITLES))
    title_count, version_count, violation_count, missing_article_count = connection.execute(
        f"""
        SELECT
          COUNT(DISTINCT CASE
            WHEN versions.effective_to = ? THEN documents.title
          END),
          SUM(CASE WHEN versions.effective_to = ? THEN 1 ELSE 0 END),
          SUM(CASE
            WHEN versions.effective_from <= ?
             AND (versions.effective_to IS NULL OR versions.effective_to > ?)
            THEN 1 ELSE 0
          END),
          SUM(CASE
            WHEN versions.effective_to = ?
             AND NOT EXISTS (
               SELECT 1 FROM law_articles articles WHERE articles.version_id = versions.id
             )
            THEN 1 ELSE 0
          END)
        FROM law_versions versions
        JOIN law_documents documents ON documents.id = versions.document_id
        WHERE documents.title IN ({placeholders})
          AND versions.status = 'repealed'
        """,
        (
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            CIVIL_CODE_REPEAL_EFFECTIVE_TO,
            *CIVIL_CODE_REPEALED_TITLES,
        ),
    ).fetchone()
    return {
        "title_count": int(title_count or 0),
        "version_count": int(version_count or 0),
        "violation_count": int(violation_count or 0),
        "missing_article_count": int(missing_article_count or 0),
    }


def refresh_fts(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE IF EXISTS law_articles_fts")
    connection.execute(
        """
        CREATE VIRTUAL TABLE law_articles_fts USING fts5(
          article_id UNINDEXED,
          document_id UNINDEXED,
          version_id UNINDEXED,
          document_title,
          article_number,
          article_title,
          content,
          tokenize = 'unicode61 remove_diacritics 2'
        )
        """
    )
    connection.execute(
        """
        INSERT INTO law_articles_fts (
          rowid, article_id, document_id, version_id, document_title,
          article_number, article_title, content
        )
        SELECT
          articles.rowid, articles.id, articles.document_id, articles.version_id,
          documents.title, articles.article_number, articles.title, articles.content
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        """
    )
    connection.execute("INSERT INTO law_articles_fts(law_articles_fts) VALUES('optimize')")


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


def upsert_metadata(
    connection: sqlite3.Connection,
    normalization: HistoryNormalizationReport,
) -> dict[str, str]:
    timestamp = now_iso()
    manifest_hash = source_manifest_sha256(connection)
    family_count = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM (
              SELECT document_id FROM law_versions GROUP BY document_id HAVING COUNT(*) > 1
            )
            """
        ).fetchone()[0]
    )
    history_status = "complete_with_declared_exceptions" if family_count >= 3 else "incomplete"
    values = {
        "dataset_version": DATASET_VERSION,
        "data_scope": "stage-1b statutory corpus plus normalized FLK historical version families; Stage 1C case/template corpora pending",
        "source_manifest_sha256": manifest_hash,
        "history_version_status": history_status,
        "history_version_family_count": str(family_count),
        "history_version_exception_count": str(normalization.skipped_family_count),
        "authoritative_terminal_date_count": str(
            normalization.authoritatively_bounded_version_count
        ),
        "authoritative_terminal_date_source": (
            "中华人民共和国民法典第一千二百六十条（2021-01-01施行）"
        ),
        "historical_unknown_end_policy": "exclude_from_dated_queries",
        "database_distribution_manifest": "data/generated/legal_core_distribution_manifest.json",
        "history_normalized_at": timestamp,
    }
    for key, value in values.items():
        connection.execute(
            """
            INSERT INTO database_metadata (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, timestamp),
        )
    return values


def audit_history(connection: sqlite3.Connection) -> dict[str, object]:
    multi_version_document_count = connection.execute(
        """
        SELECT COUNT(*) FROM (
          SELECT document_id FROM law_versions GROUP BY document_id HAVING COUNT(*) > 1
        )
        """
    ).fetchone()[0]
    invalid_interval_count = connection.execute(
        """
        SELECT COUNT(*) FROM law_versions
        WHERE effective_to IS NOT NULL AND effective_to < effective_from
        """
    ).fetchone()[0]
    overlap_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM law_versions earlier
        JOIN law_versions later
          ON later.document_id = earlier.document_id
         AND later.effective_from > earlier.effective_from
        WHERE earlier.effective_to IS NULL
           OR earlier.effective_to >= later.effective_from
        """
    ).fetchone()[0]
    article_document_mismatch_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM law_articles articles
        JOIN law_versions versions ON versions.id = articles.version_id
        WHERE articles.document_id <> versions.document_id
        """
    ).fetchone()[0]
    fts_count = connection.execute("SELECT COUNT(*) FROM law_articles_fts").fetchone()[0]
    article_count = connection.execute("SELECT COUNT(*) FROM law_articles").fetchone()[0]
    foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    authoritative_terminal = authoritative_terminal_date_audit(connection)
    authoritative_terminal_title_count = authoritative_terminal["title_count"]
    examples = [
        {"document_id": row[0], "title": row[1], "version_count": row[2]}
        for row in connection.execute(
            """
            SELECT documents.id, documents.title, COUNT(versions.id)
            FROM law_documents documents
            JOIN law_versions versions ON versions.document_id = documents.id
            GROUP BY documents.id, documents.title
            HAVING COUNT(versions.id) > 1
            ORDER BY COUNT(versions.id) DESC, documents.title
            LIMIT 20
            """
        )
    ]
    failures = []
    if multi_version_document_count < 3:
        failures.append(f"multi_version_document_count:{multi_version_document_count}<3")
    if invalid_interval_count:
        failures.append(f"invalid_interval_count:{invalid_interval_count}")
    if overlap_count:
        failures.append(f"overlap_count:{overlap_count}")
    if article_document_mismatch_count:
        failures.append(f"article_document_mismatch_count:{article_document_mismatch_count}")
    if fts_count != article_count:
        failures.append(f"fts_mismatch:{fts_count}!={article_count}")
    if foreign_key_errors:
        failures.append(f"foreign_key_errors:{foreign_key_errors}")
    if integrity != "ok":
        failures.append(f"sqlite_integrity:{integrity}")
    if authoritative_terminal_title_count != len(CIVIL_CODE_REPEALED_TITLES):
        failures.append(
            "authoritative_terminal_title_count:"
            f"{authoritative_terminal_title_count}!={len(CIVIL_CODE_REPEALED_TITLES)}"
        )
    if authoritative_terminal["version_count"] != len(CIVIL_CODE_REPEALED_TITLES):
        failures.append(
            "authoritative_terminal_version_count:"
            f"{authoritative_terminal['version_count']}!={len(CIVIL_CODE_REPEALED_TITLES)}"
        )
    if authoritative_terminal["violation_count"]:
        failures.append(
            "authoritative_terminal_violation_count:"
            f"{authoritative_terminal['violation_count']}"
        )
    if authoritative_terminal["missing_article_count"]:
        failures.append(
            "authoritative_terminal_missing_article_count:"
            f"{authoritative_terminal['missing_article_count']}"
        )
    return {
        "status": "complete" if not failures else "failed",
        "failures": failures,
        "multi_version_document_count": multi_version_document_count,
        "invalid_interval_count": invalid_interval_count,
        "overlap_count": overlap_count,
        "article_document_mismatch_count": article_document_mismatch_count,
        "article_count": article_count,
        "fts_count": fts_count,
        "foreign_key_errors": foreign_key_errors,
        "sqlite_integrity": integrity,
        "authoritative_terminal_title_count": authoritative_terminal_title_count,
        "authoritative_terminal_version_count": authoritative_terminal["version_count"],
        "authoritative_terminal_violation_count": authoritative_terminal["violation_count"],
        "authoritative_terminal_missing_article_count": authoritative_terminal[
            "missing_article_count"
        ],
        "examples": examples,
    }


def run(database: Path, report_path: Path, manifest_path: Path, strict: bool) -> int:
    if not database.is_file():
        raise FileNotFoundError(database)
    with tempfile.NamedTemporaryFile(
        prefix="legal_core_stage_1c_", suffix=".sqlite", delete=False, dir=database.parent
    ) as handle:
        staged_database = Path(handle.name)
    try:
        shutil.copy2(database, staged_database)
        connection = sqlite3.connect(staged_database)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                normalization = normalize_history(connection)
                refresh_fts(connection)
                metadata = upsert_metadata(connection, normalization)
            audit = audit_history(connection)
        finally:
            connection.close()

        report = {
            "stage": "1C-history-normalization",
            "generated_at": now_iso(),
            "dataset_version": DATASET_VERSION,
            "database": str(database.relative_to(ROOT)),
            "normalization": asdict(normalization),
            "metadata": metadata,
            "audit": audit,
            "stage_1c_status": "partial",
            "pending": [
                "guiding-case official corpus",
                "typical-case official corpus",
                "official document-template corpus",
                "offline GUI manual acceptance",
            ],
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        if strict and audit["status"] != "complete":
            raise RuntimeError(f"Stage 1C history audit failed: {audit['failures']}")

        staged_sha = sha256_file(staged_database)
        manifest = {
            "dataset_version": DATASET_VERSION,
            "generated_at": now_iso(),
            "filename": database.name,
            "size_bytes": staged_database.stat().st_size,
            "sha256": staged_sha,
            "source_manifest_sha256": metadata["source_manifest_sha256"],
            "schema_version": "4",
            "distribution_status": "local_snapshot_pending_external_publish",
            "download_url": None,
            "ci_fixture_allowed": False,
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        staged_database.replace(database)
        print(json.dumps({"report": report, "distribution_manifest": manifest}, ensure_ascii=False, indent=2))
        return 0
    finally:
        if staged_database.exists():
            staged_database.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    raise SystemExit(run(arguments.database, arguments.report, arguments.manifest, arguments.strict))
