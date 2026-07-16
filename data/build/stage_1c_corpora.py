#!/usr/bin/env python3
"""Build the Stage 1C Supreme People's Court case and template corpora."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE = ROOT / "data" / "generated" / "legal_core_full.sqlite"
DEFAULT_CACHE = ROOT / "data" / "build" / "cache" / "spc"
DEFAULT_REPORT = ROOT / "data" / "generated" / "stage_1c_corpora_report.json"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "legal_core_full_manifest.json"
BASE_URL = "https://www.court.gov.cn/"
SOURCE_ID = "spc_court"
DATASET_VERSION = "2026.07.14-stage1c.2"
USER_AGENT = "Lawyer-Assistance legal-data builder/0.1 (+official public data; contact project maintainer)"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stable_id(*parts: object, prefix: str = "") -> str:
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}{digest}"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_text(value: str) -> str:
    value = html.unescape(value).replace("\u3000", " ").replace("\xa0", " ")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in value.replace("\r", "\n").split("\n")]
    return "\n".join(line for line in lines if line).strip()


class ListingParser(HTMLParser):
    def __init__(self, href_pattern: re.Pattern[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.href_pattern = href_pattern
        self.items: list[dict[str, str]] = []
        self._anchor: dict[str, str] | None = None
        self._anchor_text: list[str] = []
        self._in_date = False
        self._date_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "a" and values.get("href") and self.href_pattern.search(values["href"] or ""):
            self._anchor = {"href": values["href"] or "", "title": values.get("title") or ""}
            self._anchor_text = []
        elif tag == "i" and "date" in (values.get("class") or "").split():
            self._in_date = True
            self._date_text = []

    def handle_data(self, data: str) -> None:
        if self._anchor is not None:
            self._anchor_text.append(data)
        if self._in_date:
            self._date_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor is not None:
            self._anchor["title"] = clean_text(self._anchor["title"] or "".join(self._anchor_text))
            self._anchor["published_on"] = ""
            self.items.append(self._anchor)
            self._anchor = None
        elif tag == "i" and self._in_date:
            if self.items:
                self.items[-1]["published_on"] = clean_text("".join(self._date_text))
            self._in_date = False


class DivTextParser(HTMLParser):
    BLOCK_TAGS = {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "strong"}

    def __init__(self, target_classes: set[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.target_classes = target_classes
        self.depth = 0
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if self.depth == 0 and tag == "div" and classes.intersection(self.target_classes):
            self.depth = 1
            return
        if self.depth:
            if tag in {"script", "style"}:
                self._skip_depth += 1
            if tag == "div":
                self.depth += 1
            if tag in self.BLOCK_TAGS:
                self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if not self.depth:
            return
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "div":
            self.depth -= 1

    def handle_data(self, data: str) -> None:
        if self.depth and not self._skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return clean_text("".join(self.parts))


def parse_listing(markup: str, pattern: str) -> list[dict[str, str]]:
    parser = ListingParser(re.compile(pattern))
    parser.feed(markup)
    unique: dict[str, dict[str, str]] = {}
    for item in parser.items:
        item["url"] = urljoin(BASE_URL, item.pop("href"))
        unique[item["url"]] = item
    return list(unique.values())


def parse_content(markup: str, classes: set[str]) -> str:
    parser = DivTextParser(classes)
    parser.feed(markup)
    return parser.text()


def discover_last_page(markup: str, base_path: str) -> int:
    escaped = re.escape(base_path)
    pages = [int(value) for value in re.findall(rf'{escaped}_(\d+)\.html', markup)]
    return max(pages, default=1)


class OfficialFetcher:
    def __init__(self, cache_dir: Path, refresh: bool, min_delay: float) -> None:
        self.cache_dir = cache_dir
        self.refresh = refresh
        self.min_delay = min_delay
        self._lock = threading.Lock()
        self._last_request_at = 0.0

    def _cache_path(self, url: str) -> Path:
        parsed = urlparse(url)
        relative = parsed.path.strip("/") or "index.html"
        if parsed.query:
            relative += "-" + stable_id(parsed.query)
        return self.cache_dir / relative

    def fetch_bytes(self, url: str) -> bytes:
        cache_path = self._cache_path(url)
        if cache_path.is_file() and not self.refresh:
            return cache_path.read_bytes()
        with self._lock:
            remaining = self.min_delay - (time.monotonic() - self._last_request_at)
            if remaining > 0:
                time.sleep(remaining)
            self._last_request_at = time.monotonic()
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    payload = response.read()
                if len(payload) < 500 or b"court.gov.cn" not in payload:
                    raise RuntimeError(f"unexpected official response for {url}: {len(payload)} bytes")
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_bytes(payload)
                return payload
            except (OSError, urllib.error.URLError, RuntimeError) as error:
                last_error = error
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"official fetch failed for {url}: {last_error}")

    def fetch_text(self, url: str) -> tuple[str, bytes]:
        payload = self.fetch_bytes(url)
        return payload.decode("utf-8", errors="strict"), payload


@dataclass
class CorpusRecord:
    external_id: str
    title: str
    published_on: str | None
    source_url: str
    content: str
    checksum: str
    raw_metadata: dict[str, object]


def listing_url(base_path: str, page: int) -> str:
    suffix = "" if page == 1 else f"_{page}"
    return urljoin(BASE_URL, f"{base_path}{suffix}.html")


def collect_paginated_listing(
    fetcher: OfficialFetcher, base_path: str, detail_pattern: str
) -> list[dict[str, str]]:
    first_url = listing_url(base_path, 1)
    first_markup, _ = fetcher.fetch_text(first_url)
    last_page = discover_last_page(first_markup, f"/{base_path}")
    items = parse_listing(first_markup, detail_pattern)
    for page in range(2, last_page + 1):
        markup, _ = fetcher.fetch_text(listing_url(base_path, page))
        items.extend(parse_listing(markup, detail_pattern))
    unique = {item["url"]: item for item in items}
    return sorted(unique.values(), key=lambda item: item["url"])


def hydrate_record(
    fetcher: OfficialFetcher,
    item: dict[str, str],
    content_classes: set[str],
    external_pattern: str,
    metadata: dict[str, object],
) -> CorpusRecord:
    markup, payload = fetcher.fetch_text(item["url"])
    content = parse_content(markup, content_classes)
    if len(content) < 40:
        raise RuntimeError(f"official content missing or too short: {item['url']}")
    match = re.search(external_pattern, item["url"])
    if not match:
        raise RuntimeError(f"cannot derive official id: {item['url']}")
    return CorpusRecord(
        external_id=match.group(1),
        title=item["title"],
        published_on=item.get("published_on") or None,
        source_url=item["url"],
        content=content,
        checksum=sha256_bytes(payload),
        raw_metadata=metadata,
    )


def hydrate_many(
    fetcher: OfficialFetcher,
    items: list[dict[str, str]],
    content_classes: set[str],
    external_pattern: str,
    metadata_factory,
    workers: int,
) -> list[CorpusRecord]:
    results: list[CorpusRecord] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                hydrate_record,
                fetcher,
                item,
                content_classes,
                external_pattern,
                metadata_factory(item),
            ): item
            for item in items
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda record: record.external_id)


def collect_guiding_cases(fetcher: OfficialFetcher, workers: int) -> list[CorpusRecord]:
    items = collect_paginated_listing(
        fetcher,
        "shenpan/gengduo/77",
        r"/shenpan/xiangqing/\d+\.html",
    )
    return hydrate_many(
        fetcher,
        items,
        {"txt_txt"},
        r"/shenpan/xiangqing/(\d+)\.html",
        lambda item: {"corpus": "guiding_case", "listing_title": item["title"]},
        workers,
    )


def guiding_case_number(title: str) -> str | None:
    match = re.search(r"指导(?:性)?案例\s*(\d+)\s*[号:]", title)
    return match.group(1) if match else None


def collect_typical_collections(fetcher: OfficialFetcher, workers: int) -> list[CorpusRecord]:
    items = collect_paginated_listing(
        fetcher,
        "zixun/gengduo/104",
        r"/zixun/xiangqing/\d+\.html",
    )
    return hydrate_many(
        fetcher,
        items,
        {"txt_txt"},
        r"/zixun/xiangqing/(\d+)\.html",
        lambda item: {"corpus": "typical_case_collection", "listing_title": item["title"]},
        workers,
    )


TYPICAL_HEADING_RE = re.compile(
    r"^(?:【\s*)?(?:典型)?案例\s*([一二三四五六七八九十百0-9]+)\s*(?:】|[：:、.．]|\s+)\s*(.+)$"
)
TYPICAL_BODY_MARKERS = ("基本案情", "案情简介", "基本情况", "裁判结果", "处理结果", "典型意义")


def split_typical_cases(record: CorpusRecord) -> list[dict[str, object]]:
    lines = record.content.splitlines()
    candidates: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = TYPICAL_HEADING_RE.match(line.strip())
        if not match:
            continue
        title = clean_text(match.group(2)).strip("—- ")
        lookahead = "\n".join(lines[index + 1 : index + 16])
        if title and any(marker in lookahead for marker in TYPICAL_BODY_MARKERS):
            candidates.append((index, title))
    deduplicated: list[tuple[int, str]] = []
    seen_titles: set[str] = set()
    for index, title in candidates:
        normalized = re.sub(r"\s+", "", title)
        if normalized in seen_titles:
            continue
        seen_titles.add(normalized)
        deduplicated.append((index, title))
    if not deduplicated:
        return [{"title": record.title, "content": record.content, "ordinal": 1}]
    segments: list[dict[str, object]] = []
    for ordinal, (start, title) in enumerate(deduplicated, start=1):
        end = deduplicated[ordinal][0] if ordinal < len(deduplicated) else len(lines)
        content = clean_text("\n".join(lines[start:end]))
        if len(content) >= 80:
            segments.append({"title": title, "content": content, "ordinal": ordinal})
    return segments or [{"title": record.title, "content": record.content, "ordinal": 1}]


def template_category_paths(root_markup: str) -> list[str]:
    values = set(re.findall(r"/susongyangshi/(\d+)\.html", root_markup))
    return sorted((f"susongyangshi/{value}" for value in values), key=lambda value: int(value.rsplit("/", 1)[1]))


def collect_templates(fetcher: OfficialFetcher, workers: int) -> list[CorpusRecord]:
    root_markup, _ = fetcher.fetch_text(urljoin(BASE_URL, "susong.html"))
    items = parse_listing(root_markup, r"/susongyangshi/xiangqing/\d+\.html")
    for base_path in template_category_paths(root_markup):
        items.extend(
            collect_paginated_listing(
                fetcher,
                base_path,
                r"/susongyangshi/xiangqing/\d+\.html",
            )
        )
    unique = {item["url"]: item for item in items}
    return hydrate_many(
        fetcher,
        list(unique.values()),
        {"cpws_content"},
        r"/susongyangshi/xiangqing/(\d+)\.html",
        lambda item: {"corpus": "official_document_template", "listing_title": item["title"]},
        workers,
    )


def ensure_schema_v4(connection: sqlite3.Connection) -> None:
    guiding_columns = {row[1] for row in connection.execute("PRAGMA table_info(guiding_cases)")}
    template_columns = {row[1] for row in connection.execute("PRAGMA table_info(document_templates)")}
    required_guiding = {"case_type", "content", "source_system_id", "source_external_id", "source_record_id", "source_url"}
    required_templates = {"source_system_id", "source_external_id", "source_record_id", "source_url"}
    if not required_guiding.issubset(guiding_columns) or not required_templates.issubset(template_columns):
        if connection.execute("SELECT COUNT(*) FROM guiding_cases").fetchone()[0]:
            raise RuntimeError("cannot migrate non-empty legacy guiding_cases table")
        if connection.execute("SELECT COUNT(*) FROM document_templates").fetchone()[0]:
            raise RuntimeError("cannot migrate non-empty legacy document_templates table")
        connection.executescript(
            """
            DROP TABLE guiding_cases;
            DROP TABLE document_templates;
            CREATE TABLE guiding_cases (
              id TEXT PRIMARY KEY, title TEXT NOT NULL, case_type TEXT NOT NULL,
              case_number TEXT, court TEXT, decided_on TEXT, published_on TEXT,
              summary TEXT NOT NULL, content TEXT NOT NULL,
              related_article_id TEXT REFERENCES law_articles(id),
              source_system_id TEXT NOT NULL REFERENCES source_systems(id),
              source_external_id TEXT NOT NULL,
              source_record_id TEXT NOT NULL REFERENCES source_records(id),
              source_url TEXT NOT NULL, metadata_json TEXT NOT NULL,
              UNIQUE(source_system_id, source_external_id, case_type)
            );
            CREATE TABLE document_templates (
              id TEXT PRIMARY KEY, name TEXT NOT NULL, template_type TEXT NOT NULL,
              content TEXT NOT NULL, metadata_json TEXT NOT NULL, published_on TEXT,
              source_system_id TEXT NOT NULL REFERENCES source_systems(id),
              source_external_id TEXT NOT NULL,
              source_record_id TEXT NOT NULL REFERENCES source_records(id),
              source_url TEXT NOT NULL,
              UNIQUE(source_system_id, source_external_id)
            );
            CREATE INDEX idx_guiding_cases_type ON guiding_cases(case_type, published_on);
            CREATE INDEX idx_guiding_cases_source ON guiding_cases(source_system_id, source_external_id);
            CREATE INDEX idx_document_templates_type ON document_templates(template_type, published_on);
            CREATE INDEX idx_document_templates_source ON document_templates(source_system_id, source_external_id);
            """
        )
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS history_version_exceptions (
          id TEXT PRIMARY KEY,
          reason TEXT NOT NULL,
          document_ids_json TEXT NOT NULL,
          effective_dates_json TEXT NOT NULL,
          source_system_id TEXT NOT NULL REFERENCES source_systems(id),
          source_reference TEXT NOT NULL,
          checked_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_history_version_exceptions_reason
          ON history_version_exceptions(reason);
        """
    )
    connection.execute(
        """
        INSERT INTO database_metadata (key, value, updated_at)
        VALUES ('schema_version', '4', ?)
        ON CONFLICT(key) DO UPDATE SET value = '4', updated_at = excluded.updated_at
        """,
        (now_iso(),),
    )


def insert_source_system(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO source_systems
          (id, name, base_url, official_scope, maintainer, retrieved_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name, base_url = excluded.base_url,
          official_scope = excluded.official_scope, maintainer = excluded.maintainer,
          retrieved_at = excluded.retrieved_at, notes = excluded.notes
        """,
        (
            SOURCE_ID,
            "中华人民共和国最高人民法院",
            BASE_URL,
            "指导性案例、典型案例发布集合、诉讼文书样式",
            "最高人民法院",
            now_iso(),
            "Official public website snapshot; no login-only People's Court Case Database content is included.",
        ),
    )


def insert_source_record(
    connection: sqlite3.Connection, record: CorpusRecord, record_type: str, external_id: str
) -> str:
    record_id = stable_id(SOURCE_ID, external_id, record_type, prefix="src-")
    connection.execute(
        """
        INSERT INTO source_records
          (id, source_system_id, external_id, record_type, source_url,
           retrieved_at, checksum, raw_json, raw_text)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_system_id, external_id, record_type) DO UPDATE SET
          source_url = excluded.source_url, retrieved_at = excluded.retrieved_at,
          checksum = excluded.checksum, raw_json = excluded.raw_json, raw_text = excluded.raw_text
        """,
        (
            record_id,
            SOURCE_ID,
            external_id,
            record_type,
            record.source_url,
            now_iso(),
            record.checksum,
            json.dumps(record.raw_metadata, ensure_ascii=False, sort_keys=True),
            record.content,
        ),
    )
    return record_id


def write_ingestion_audit(
    connection: sqlite3.Connection, external_id: str, scope: str, record: CorpusRecord
) -> None:
    connection.execute(
        """
        INSERT INTO ingestion_audit (
          id, source_system_id, external_id, source_scope, source_url,
          index_status, detail_status, text_status, article_status,
          relation_status, attempts, checksum, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'succeeded', 'succeeded', 'succeeded',
                  'not_applicable', 'not_applicable', 1, ?, ?)
        ON CONFLICT(source_system_id, external_id) DO UPDATE SET
          source_scope = excluded.source_scope, source_url = excluded.source_url,
          index_status = excluded.index_status, detail_status = excluded.detail_status,
          text_status = excluded.text_status, article_status = excluded.article_status,
          relation_status = excluded.relation_status, checksum = excluded.checksum,
          updated_at = excluded.updated_at
        """,
        (
            stable_id(SOURCE_ID, external_id, prefix="ingest-"),
            SOURCE_ID,
            external_id,
            scope,
            record.source_url,
            record.checksum,
            now_iso(),
        ),
    )


def insert_cases(
    connection: sqlite3.Connection, records: list[CorpusRecord], case_type: str
) -> None:
    for record in records:
        source_external_id = f"{case_type}:{record.external_id}"
        source_record_id = insert_source_record(connection, record, case_type, source_external_id)
        case_number = guiding_case_number(record.title) if case_type == "guiding_case" else None
        connection.execute(
            """
            INSERT INTO guiding_cases (
              id, title, case_type, case_number, court, decided_on, published_on,
              summary, content, related_article_id, source_system_id,
              source_external_id, source_record_id, source_url, metadata_json
            ) VALUES (?, ?, ?, ?, '最高人民法院', NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
            ON CONFLICT(source_system_id, source_external_id, case_type) DO UPDATE SET
              title = excluded.title, case_number = excluded.case_number,
              published_on = excluded.published_on, summary = excluded.summary,
              content = excluded.content, source_record_id = excluded.source_record_id,
              source_url = excluded.source_url, metadata_json = excluded.metadata_json
            """,
            (
                stable_id(SOURCE_ID, source_external_id, prefix="case-"),
                record.title,
                case_type,
                case_number,
                record.published_on,
                record.content[:500],
                record.content,
                SOURCE_ID,
                source_external_id,
                source_record_id,
                record.source_url,
                json.dumps(record.raw_metadata, ensure_ascii=False, sort_keys=True),
            ),
        )
        write_ingestion_audit(connection, source_external_id, case_type, record)


def classify_template(title: str) -> str:
    for label, value in (
        ("起诉状", "complaint"),
        ("答辩状", "defense"),
        ("判决书", "judgment"),
        ("裁定书", "ruling"),
        ("调解书", "mediation"),
        ("决定书", "decision"),
        ("通知书", "notice"),
        ("申请书", "application"),
        ("执行", "enforcement"),
    ):
        if label in title:
            return value
    return "other_official_court_document"


def insert_templates(connection: sqlite3.Connection, records: list[CorpusRecord]) -> None:
    for record in records:
        source_external_id = f"template:{record.external_id}"
        source_record_id = insert_source_record(connection, record, "document_template", source_external_id)
        template_type = classify_template(record.title)
        metadata = dict(record.raw_metadata)
        metadata["official_template_id"] = record.external_id
        connection.execute(
            """
            INSERT INTO document_templates (
              id, name, template_type, content, metadata_json, published_on,
              source_system_id, source_external_id, source_record_id, source_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_system_id, source_external_id) DO UPDATE SET
              name = excluded.name, template_type = excluded.template_type,
              content = excluded.content, metadata_json = excluded.metadata_json,
              published_on = excluded.published_on,
              source_record_id = excluded.source_record_id, source_url = excluded.source_url
            """,
            (
                stable_id(SOURCE_ID, source_external_id, prefix="tpl-"),
                record.title,
                template_type,
                record.content,
                json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                record.published_on,
                SOURCE_ID,
                source_external_id,
                source_record_id,
                record.source_url,
            ),
        )
        write_ingestion_audit(connection, source_external_id, "official_document_templates", record)


def insert_individual_typical_cases(
    connection: sqlite3.Connection, records: list[CorpusRecord]
) -> int:
    connection.execute("DELETE FROM guiding_cases WHERE case_type = 'typical_case'")
    connection.execute(
        "DELETE FROM ingestion_audit WHERE source_system_id = ? AND source_scope = 'typical_cases'",
        (SOURCE_ID,),
    )
    inserted = 0
    for collection in records:
        collection_external_id = f"typical_case_collection:{collection.external_id}"
        source_record_id = stable_id(
            SOURCE_ID, collection_external_id, "typical_case_collection", prefix="src-"
        )
        for segment in split_typical_cases(collection):
            title = str(segment["title"])
            content = str(segment["content"])
            title_key = stable_id(re.sub(r"\s+", "", title))
            source_external_id = f"typical_case:{collection.external_id}:{title_key}"
            metadata = {
                "corpus": "typical_case",
                "collection_external_id": collection.external_id,
                "collection_title": collection.title,
                "ordinal": segment["ordinal"],
                "derived_from_complete_official_collection_text": True,
            }
            connection.execute(
                """
                INSERT INTO guiding_cases (
                  id, title, case_type, case_number, court, decided_on, published_on,
                  summary, content, related_article_id, source_system_id,
                  source_external_id, source_record_id, source_url, metadata_json
                ) VALUES (?, ?, 'typical_case', NULL, '最高人民法院', NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
                ON CONFLICT(source_system_id, source_external_id, case_type) DO UPDATE SET
                  title = excluded.title, published_on = excluded.published_on,
                  summary = excluded.summary, content = excluded.content,
                  source_record_id = excluded.source_record_id,
                  source_url = excluded.source_url, metadata_json = excluded.metadata_json
                """,
                (
                    stable_id(SOURCE_ID, source_external_id, prefix="case-"),
                    title,
                    collection.published_on,
                    content[:500],
                    content,
                    SOURCE_ID,
                    source_external_id,
                    source_record_id,
                    collection.source_url,
                    json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                ),
            )
            derived_record = CorpusRecord(
                external_id=source_external_id,
                title=title,
                published_on=collection.published_on,
                source_url=collection.source_url,
                content=content,
                checksum=collection.checksum,
                raw_metadata=metadata,
            )
            write_ingestion_audit(connection, source_external_id, "typical_cases", derived_record)
            inserted += 1
    return inserted


def insert_coverage(
    connection: sqlite3.Connection,
    scope: str,
    count: int,
    source_system_id: str = SOURCE_ID,
    notes: str = "Official listing snapshot and every listed detail page fetched with non-empty text.",
) -> None:
    connection.execute(
        """
        INSERT INTO coverage_audit (
          id, source_system_id, scope, expected_total, fetched_total,
          detail_fetched_total, text_fetched_total, status, checked_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'complete', ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          expected_total = excluded.expected_total, fetched_total = excluded.fetched_total,
          detail_fetched_total = excluded.detail_fetched_total,
          text_fetched_total = excluded.text_fetched_total,
          status = excluded.status, checked_at = excluded.checked_at, notes = excluded.notes
        """,
        (
            stable_id(source_system_id, scope, prefix="coverage-"),
            source_system_id,
            scope,
            count,
            count,
            count,
            count,
            now_iso(),
            notes,
        ),
    )


class UnionFind:
    def __init__(self) -> None:
        self.parents: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parents.setdefault(item, item)
        if self.parents[item] != item:
            self.parents[item] = self.find(self.parents[item])
        return self.parents[item]

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parents[right_root] = left_root

    def components(self) -> list[list[str]]:
        grouped: dict[str, list[str]] = {}
        for item in self.parents:
            grouped.setdefault(self.find(item), []).append(item)
        return [sorted(values) for values in grouped.values()]


def populate_history_exceptions(connection: sqlite3.Connection) -> int:
    union_find = UnionFind()
    for left, right in connection.execute(
        "SELECT from_document_id, to_document_id FROM law_relations WHERE relation_type = 'history_version'"
    ):
        union_find.union(left, right)
    connection.execute("DELETE FROM history_version_exceptions")
    checked_at = now_iso()
    for document_ids in union_find.components():
        placeholders = ",".join("?" for _ in document_ids)
        dates = [
            row[0]
            for row in connection.execute(
                f"SELECT effective_from FROM law_versions WHERE document_id IN ({placeholders}) ORDER BY effective_from",
                document_ids,
            )
        ]
        invalid = [value for value in dates if not value or value == "0001-01-01"]
        if invalid:
            reason = "missing_or_placeholder_effective_date"
        elif len(set(dates)) != len(dates):
            reason = "duplicate_effective_date"
        else:
            reason = "unresolved_official_history_relation"
        exception_id = stable_id("history-exception", *document_ids, prefix="hist-ex-")
        connection.execute(
            """
            INSERT INTO history_version_exceptions (
              id, reason, document_ids_json, effective_dates_json,
              source_system_id, source_reference, checked_at
            ) VALUES (?, ?, ?, ?, 'flk_npc', '国家法律法规数据库 lsyg', ?)
            """,
            (
                exception_id,
                reason,
                json.dumps(document_ids, ensure_ascii=False),
                json.dumps(dates, ensure_ascii=False),
                checked_at,
            ),
        )
    count = connection.execute("SELECT COUNT(*) FROM history_version_exceptions").fetchone()[0]
    insert_coverage(
        connection,
        "history_version_declared_exceptions",
        count,
        source_system_id="flk_npc",
        notes="Every remaining official lsyg family is retained separately with a machine-readable reason; no effective date was inferred.",
    )
    return int(count)


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


def update_metadata(connection: sqlite3.Connection, counts: dict[str, int]) -> dict[str, str]:
    timestamp = now_iso()
    values = {
        "schema_version": "4",
        "dataset_version": DATASET_VERSION,
        "data_scope": "statutory corpus, normalized official history families, SPC guiding cases, SPC typical-case collections, and SPC official document templates",
        "source_manifest_sha256": source_manifest_sha256(connection),
        "stage_1c_corpora_status": "complete",
        "stage_1c_data_status": "complete_with_declared_history_date_exceptions",
        "guiding_case_count": str(counts["guiding_cases"]),
        "guiding_case_batch_notice_count": str(counts["guiding_notices"]),
        "typical_case_collection_count": str(counts["typical_collections"]),
        "typical_case_count": str(counts["typical_cases"]),
        "document_template_count": str(counts["document_templates"]),
        "history_version_exception_count": str(counts["history_exceptions"]),
        "historical_unknown_end_policy": "exclude_from_dated_queries",
        "stage_1c_corpora_snapshot_at": timestamp,
        "database_distribution_manifest": "data/generated/legal_core_distribution_manifest.json",
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


def audit_corpora(connection: sqlite3.Connection, expected: dict[str, int]) -> dict[str, object]:
    actual = {
        "guiding_cases": connection.execute(
            "SELECT COUNT(*) FROM guiding_cases WHERE case_type = 'guiding_case'"
        ).fetchone()[0],
        "guiding_notices": connection.execute(
            "SELECT COUNT(*) FROM guiding_cases WHERE case_type = 'guiding_case_batch_notice'"
        ).fetchone()[0],
        "typical_collections": connection.execute(
            "SELECT COUNT(*) FROM guiding_cases WHERE case_type = 'typical_case_collection'"
        ).fetchone()[0],
        "typical_cases": connection.execute(
            "SELECT COUNT(*) FROM guiding_cases WHERE case_type = 'typical_case'"
        ).fetchone()[0],
        "document_templates": connection.execute("SELECT COUNT(*) FROM document_templates").fetchone()[0],
        "history_exceptions": connection.execute("SELECT COUNT(*) FROM history_version_exceptions").fetchone()[0],
    }
    missing_case_provenance = connection.execute(
        """
        SELECT COUNT(*) FROM guiding_cases
        WHERE source_system_id IS NULL OR source_external_id IS NULL
           OR source_record_id IS NULL OR source_url = '' OR content = ''
        """
    ).fetchone()[0]
    missing_template_provenance = connection.execute(
        """
        SELECT COUNT(*) FROM document_templates
        WHERE source_system_id IS NULL OR source_external_id IS NULL
           OR source_record_id IS NULL OR source_url = '' OR content = ''
        """
    ).fetchone()[0]
    duplicate_guiding_numbers = connection.execute(
        """
        SELECT COUNT(*) FROM (
          SELECT case_number FROM guiding_cases
          WHERE case_type = 'guiding_case' AND case_number IS NOT NULL
          GROUP BY case_number HAVING COUNT(*) > 1
        )
        """
    ).fetchone()[0]
    guiding_numbers = {
        int(row[0])
        for row in connection.execute(
            "SELECT case_number FROM guiding_cases WHERE case_type = 'guiding_case' AND case_number IS NOT NULL"
        )
    }
    missing_guiding_numbers = sorted(set(range(1, max(guiding_numbers, default=0) + 1)) - guiding_numbers)
    coverage_rows = connection.execute(
        """
        SELECT scope, expected_total, fetched_total, text_fetched_total, status
        FROM coverage_audit WHERE source_system_id = ? ORDER BY scope
        """,
        (SOURCE_ID,),
    ).fetchall()
    exception_reason_counts = {
        row[0]: row[1]
        for row in connection.execute(
            "SELECT reason, COUNT(*) FROM history_version_exceptions GROUP BY reason ORDER BY reason"
        )
    }
    foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    failures: list[str] = []
    for key, expected_count in expected.items():
        if actual[key] != expected_count:
            failures.append(f"{key}:{actual[key]}!={expected_count}")
    if actual["guiding_cases"] < 278:
        failures.append(f"guiding_cases:{actual['guiding_cases']}<278")
    if missing_guiding_numbers != [45]:
        failures.append(f"unexpected_missing_guiding_numbers:{missing_guiding_numbers}")
    if not actual["typical_collections"]:
        failures.append("typical_collections:0")
    if not actual["document_templates"]:
        failures.append("document_templates:0")
    if missing_case_provenance:
        failures.append(f"missing_case_provenance:{missing_case_provenance}")
    if missing_template_provenance:
        failures.append(f"missing_template_provenance:{missing_template_provenance}")
    if duplicate_guiding_numbers:
        failures.append(f"duplicate_guiding_numbers:{duplicate_guiding_numbers}")
    if len(coverage_rows) != 4 or any(row[4] != "complete" for row in coverage_rows):
        failures.append("coverage_audit_incomplete")
    if foreign_key_errors:
        failures.append(f"foreign_key_errors:{foreign_key_errors}")
    if integrity != "ok":
        failures.append(f"sqlite_integrity:{integrity}")
    return {
        "status": "complete" if not failures else "failed",
        "failures": failures,
        "counts": actual,
        "missing_case_provenance": missing_case_provenance,
        "missing_template_provenance": missing_template_provenance,
        "duplicate_guiding_numbers": duplicate_guiding_numbers,
        "missing_guiding_numbers": missing_guiding_numbers,
        "coverage": [list(row) for row in coverage_rows],
        "history_exception_reasons": exception_reason_counts,
        "foreign_key_errors": foreign_key_errors,
        "sqlite_integrity": integrity,
    }


def build(
    database: Path,
    cache_dir: Path,
    report_path: Path,
    manifest_path: Path,
    workers: int,
    min_delay: float,
    refresh: bool,
    strict: bool,
) -> int:
    fetcher = OfficialFetcher(cache_dir, refresh=refresh, min_delay=min_delay)
    guiding_all = collect_guiding_cases(fetcher, workers)
    guiding = [record for record in guiding_all if guiding_case_number(record.title)]
    guiding_notices = [record for record in guiding_all if not guiding_case_number(record.title)]
    typical = collect_typical_collections(fetcher, workers)
    templates = collect_templates(fetcher, workers)
    expected = {
        "guiding_cases": len(guiding),
        "guiding_notices": len(guiding_notices),
        "typical_collections": len(typical),
        "document_templates": len(templates),
    }

    with tempfile.NamedTemporaryFile(
        prefix="legal_core_stage_1c_corpora_", suffix=".sqlite", delete=False, dir=database.parent
    ) as handle:
        staged_database = Path(handle.name)
    try:
        shutil.copy2(database, staged_database)
        connection = sqlite3.connect(staged_database)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                ensure_schema_v4(connection)
                insert_source_system(connection)
                insert_cases(connection, guiding, "guiding_case")
                insert_cases(connection, guiding_notices, "guiding_case_batch_notice")
                insert_cases(connection, typical, "typical_case_collection")
                expected["typical_cases"] = insert_individual_typical_cases(connection, typical)
                insert_templates(connection, templates)
                insert_coverage(connection, "guiding_cases_and_batch_notices", len(guiding_all))
                insert_coverage(connection, "typical_case_collections", len(typical))
                insert_coverage(connection, "typical_cases", expected["typical_cases"])
                insert_coverage(connection, "official_document_templates", len(templates))
                expected["history_exceptions"] = populate_history_exceptions(connection)
                metadata = update_metadata(connection, expected)
            audit = audit_corpora(connection, expected)
        finally:
            connection.close()
        report = {
            "stage": "1C-official-corpora",
            "generated_at": now_iso(),
            "dataset_version": DATASET_VERSION,
            "source": {
                "id": SOURCE_ID,
                "base_url": BASE_URL,
                "guiding_listing": urljoin(BASE_URL, "shenpan/gengduo/77.html"),
                "typical_listing": urljoin(BASE_URL, "zixun/gengduo/104.html"),
                "template_listing": urljoin(BASE_URL, "susong.html"),
            },
            "counts": expected,
            "metadata": metadata,
            "audit": audit,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        if strict and audit["status"] != "complete":
            raise RuntimeError(f"Stage 1C corpora audit failed: {audit['failures']}")
        database_sha = sha256_file(staged_database)
        manifest = {
            "dataset_version": DATASET_VERSION,
            "generated_at": now_iso(),
            "filename": database.name,
            "size_bytes": staged_database.stat().st_size,
            "sha256": database_sha,
            "source_manifest_sha256": metadata["source_manifest_sha256"],
            "schema_version": "4",
            "distribution_status": "local_snapshot_pending_external_publish",
            "download_url": None,
            "ci_fixture_allowed": False,
        }
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        staged_database.replace(database)
        print(json.dumps({"counts": expected, "audit": audit, "manifest": manifest}, ensure_ascii=False, indent=2))
        return 0
    finally:
        if staged_database.exists():
            staged_database.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--min-delay", type=float, default=0.08)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    raise SystemExit(
        build(
            arguments.database,
            arguments.cache_dir,
            arguments.report,
            arguments.manifest,
            max(1, arguments.workers),
            max(0.0, arguments.min_delay),
            arguments.refresh,
            arguments.strict,
        )
    )
