#!/usr/bin/env python3
"""Build the read-only Supreme People's Court judicial-case sidecar.

The builder uses only pages that are publicly reachable from the Supreme
People's Court web site.  It keeps response bodies in a resumable cache,
never attempts a browser or login challenge, and replaces the SQLite sidecar
only after a new database passes its integrity checks.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import sqlite3
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SQL = ROOT / "data" / "schema" / "judicial_cases.sql"
DEFAULT_OUTPUT = ROOT / "data" / "runtime" / "judicial_cases.sqlite"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "judicial_cases_manifest.json"
DEFAULT_SOURCES_DOC = ROOT / "data" / "runtime" / "CASE_DATA_SOURCES.md"
DEFAULT_CACHE_DIR = ROOT / "data" / "build" / "cache"

COURT_BASE = "https://www.court.gov.cn"
GUIDING_INDEX_URL = f"{COURT_BASE}/shenpan/gengduo/77.html"
# This notice is an official source record used only to annotate the two
# guiding cases that the Supreme People's Court says are no longer to be
# referred to.  The notice itself is never inserted as a case row.
WITHDRAWN_NOTICE_URL = f"{COURT_BASE}/fabu/xiangqing/282441.html"
REFERENCE_SEARCH_BASE = f"{COURT_BASE}/search.html"
REFERENCE_SEARCH_QUERY = "入库参考案例"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 40
DEFAULT_RETRIES = 3
DEFAULT_PAUSE = 0.35

GUIDING_TITLE_RE = re.compile(r"指导(?:性)?案例\s*([0-9０-９]+)\s*号", re.I)
REFERENCE_NUMBER_RE = re.compile(
    r"入库编号\s*[:：]?\s*([0-9]{4}\s*-\s*[0-9A-Za-z]+(?:\s*-\s*[0-9A-Za-z]+){2,})",
    re.I,
)
CASE_NUMBER_RE = re.compile(
    r"[（(]\s*(\d{4})\s*[）)]\s*([^\n，。；;]{1,100}?号)"
)
DATE_RE = re.compile(r"(\d{4})[-年](\d{1,2})[-月](\d{1,2})")
LISTING_TOTAL_RE = re.compile(r"共\s*([0-9,，]+)\s*篇")
SEARCH_TOTAL_RE = re.compile(r"约\s*([0-9,，]+)\s*个")

SECTION_ALIASES: dict[str, tuple[str, ...]] = {
    "keywords": ("关键词", "关键字"),
    "key_points": ("裁判要点", "裁判要旨", "裁判规则", "裁判观点"),
    "related_laws": ("相关法条", "相关法律", "法律依据"),
    "basic_facts": ("基本案情", "基本事实", "案件事实"),
    "judgment_result": ("裁判结果", "裁判结论", "判决结果", "裁判主文"),
    "reasoning": ("裁判理由", "裁判说理", "裁判思路", "裁判逻辑"),
}
ALL_SECTION_HEADINGS = tuple(
    heading for aliases in SECTION_ALIASES.values() for heading in aliases
)


class BuildError(RuntimeError):
    """A build could not produce a trustworthy replacement database."""


class WafChallengeError(BuildError):
    """An official endpoint returned a challenge page."""


class FetchError(BuildError):
    """A page could not be read from the network or cache."""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def clean_text(value: Any) -> str:
    """Normalize HTML-derived text without losing paragraph boundaries."""

    if value is None:
        return ""
    text = html.unescape(str(value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\u3000", " ").replace("\xa0", " ").replace("\u200b", "")
    lines: list[str] = []
    previous_blank = False
    for raw_line in text.split("\n"):
        line = re.sub(r"[ \t\f\v]+", " ", raw_line).strip()
        if line:
            lines.append(line)
            previous_blank = False
        elif lines and not previous_blank:
            lines.append("")
            previous_blank = True
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def compact_text(value: str) -> str:
    return re.sub(r"[\s:：,，。；;、]+", "", clean_text(value))


def decode_html(body: bytes, content_type: str = "") -> str:
    probe = body[:4096].decode("ascii", errors="ignore")
    charset_match = re.search(r"charset\s*=\s*[\"']?([\w-]+)", content_type, re.I)
    if charset_match is None:
        charset_match = re.search(
            r"charset\s*=\s*[\"']?([\w-]+)", probe, re.I
        )
    encodings = [charset_match.group(1)] if charset_match else []
    encodings.extend(["utf-8", "gb18030"])
    seen: set[str] = set()
    for encoding in encodings:
        encoding = encoding.lower()
        if encoding in seen:
            continue
        seen.add(encoding)
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def looks_like_waf_challenge(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
            "wzws-waf-cgi",
            "wzws_cid",
            "please enable javascript",
            "enable javascript and refresh",
            "javascript challenge",
        )
    )


def official_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "court.gov.cn",
        "www.court.gov.cn",
    }:
        raise BuildError(f"unexpected source host: {url}")
    if parsed.username or parsed.password or parsed.port:
        raise BuildError(f"unexpected source URL authority: {url}")
    return urllib.parse.urlunparse(("https", parsed.hostname, parsed.path, "", parsed.query, ""))


def canonical_url(href: str, base_url: str = COURT_BASE) -> str:
    value = html.unescape((href or "").strip())
    if not value or value.startswith(("javascript:", "mailto:", "#")):
        return ""
    return official_url(urllib.parse.urljoin(base_url, value))


@dataclass(frozen=True)
class ListingItem:
    title: str
    url: str
    listed_date: str | None


@dataclass
class FetchResult:
    url: str
    body: bytes
    cache_path: Path
    fetched_at: str
    content_sha256: str
    from_cache: bool
    stale_cache: bool = False
    refresh_error: str | None = None


@dataclass
class FetchFailure:
    url: str
    kind: str
    error: str
    cache_path: str | None = None


class ListingParser(HTMLParser):
    """Parse only list entries that link to an official case detail page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.li_depth = 0
        self.current: dict[str, Any] | None = None
        self.active_anchor = False
        self.anchor_depth = 0
        self.anchor_parts: list[str] = []
        self.anchor_href = ""
        self.anchor_title = ""
        self.date_depth = 0
        self.date_parts: list[str] = []
        self.items: list[ListingItem] = []
        self.page_urls: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        href = attributes.get("href") or ""
        if "shenpan/gengduo/77" in href:
            self.page_urls.add(href)
        if tag == "li":
            if self.li_depth == 0:
                self.current = {"href": "", "title": "", "text": [], "date": []}
            self.li_depth += 1
        if self.li_depth and tag == "a" and "xiangqing" in href and not self.active_anchor:
            self.active_anchor = True
            self.anchor_depth = 1
            self.anchor_href = href
            self.anchor_title = attributes.get("title") or ""
            self.anchor_parts = []
        elif self.active_anchor:
            self.anchor_depth += 1
        if self.li_depth and tag == "i" and "date" in (attributes.get("class") or "").split():
            self.date_depth = 1
            self.date_parts = []
        elif self.date_depth:
            self.date_depth += 1

    def handle_data(self, data: str) -> None:
        if self.active_anchor:
            self.anchor_parts.append(data)
        if self.date_depth:
            self.date_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.active_anchor:
            self.anchor_depth -= 1
            if self.anchor_depth == 0:
                if self.current is not None:
                    self.current["href"] = self.anchor_href
                    self.current["title"] = self.anchor_title or "".join(self.anchor_parts)
                self.active_anchor = False
        if self.date_depth:
            self.date_depth -= 1
            if self.date_depth == 0 and self.current is not None:
                self.current["date"] = self.date_parts[:]
        if tag == "li" and self.li_depth:
            self.li_depth -= 1
            if self.li_depth == 0 and self.current is not None:
                href = str(self.current.get("href") or "")
                if "xiangqing" in href:
                    self.items.append(
                        ListingItem(
                            title=clean_text(self.current.get("title")),
                            url=href,
                            listed_date=parse_date("".join(self.current.get("date") or [])),
                        )
                    )
                self.current = None


class DetailParser(HTMLParser):
    """Extract the detail title, publication metadata, and `.txt_txt` body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_depth = 0
        self.title_parts: list[str] = []
        self.body_depth = 0
        self.body_parts: list[str] = []
        self.meta_li_depth = 0
        self.meta_parts: list[str] = []
        self.metadata_lines: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        if self.title_depth:
            if tag == "div":
                self.title_depth += 1
        elif tag == "div" and "title" in classes and not self.title_parts:
            self.title_depth = 1
        if self.body_depth:
            if tag == "div":
                self.body_depth += 1
            if tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4"}:
                self.body_parts.append("\n")
        elif tag == "div" and "txt_txt" in classes:
            self.body_depth = 1
        if tag == "li" and self.meta_li_depth == 0 and "message" in classes:
            self.meta_li_depth = 1
            self.meta_parts = []
        elif self.meta_li_depth:
            self.meta_li_depth += 1
        if tag in {"script", "style", "noscript"}:
            self.skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if self.skip_depth and tag in {"script", "style", "noscript"}:
            self.skip_depth -= 1
        if self.title_depth and tag == "div":
            self.title_depth -= 1
        if self.body_depth:
            if tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4"}:
                self.body_parts.append("\n")
            if tag == "div":
                self.body_depth -= 1
        if self.meta_li_depth:
            if tag == "li":
                self.meta_li_depth = 0
                self.metadata_lines.append(clean_text("".join(self.meta_parts)))
            elif self.meta_li_depth > 0:
                self.meta_li_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        if self.title_depth:
            self.title_parts.append(data)
        if self.body_depth:
            self.body_parts.append(data)
        if self.meta_li_depth:
            self.meta_parts.append(data)

    @property
    def title(self) -> str:
        return clean_text("".join(self.title_parts))

    @property
    def body(self) -> str:
        return clean_text("".join(self.body_parts))

    @property
    def source(self) -> str | None:
        for line in self.metadata_lines:
            if "来源" in line:
                return clean_text(line.split("：", 1)[-1].split(":", 1)[-1]) or None
        return None

    @property
    def publication_date(self) -> str | None:
        for line in self.metadata_lines:
            if "发布时间" in line:
                value = parse_date(line)
                if value:
                    return value
        return None


def parse_date(value: str | None) -> str | None:
    if not value:
        return None
    match = DATE_RE.search(clean_text(value))
    if not match:
        return None
    year, month, day = (int(item) for item in match.groups())
    try:
        return dt.date(year, month, day).isoformat()
    except ValueError:
        return None


def parse_listing_page(markup: str, base_url: str = COURT_BASE) -> tuple[list[ListingItem], set[str], int | None]:
    parser = ListingParser()
    parser.feed(markup)
    items = [
        ListingItem(
            title=item.title,
            url=canonical_url(item.url, base_url),
            listed_date=item.listed_date,
        )
        for item in parser.items
        if canonical_url(item.url, base_url)
    ]
    plain_markup = re.sub(r"<[^>]+>", "", markup)
    total_match = LISTING_TOTAL_RE.search(clean_text(plain_markup))
    total = int(total_match.group(1).replace(",", "").replace("，", "")) if total_match else None
    page_urls = {
        canonical_url(value, base_url)
        for value in parser.page_urls
        if canonical_url(value, base_url)
    }
    return items, page_urls, total


def parse_reference_search_page(markup: str, base_url: str = COURT_BASE) -> tuple[list[ListingItem], int | None]:
    parser = ListingParser()
    parser.feed(markup)
    items = [
        ListingItem(
            title=item.title,
            url=canonical_url(item.url, base_url),
            listed_date=item.listed_date,
        )
        for item in parser.items
        if "/zixun/xiangqing/" in item.url and canonical_url(item.url, base_url)
    ]
    plain_markup = re.sub(r"<[^>]+>", "", markup)
    total_match = SEARCH_TOTAL_RE.search(clean_text(plain_markup))
    total = int(total_match.group(1).replace(",", "").replace("，", "")) if total_match else None
    return items, total


def parse_detail_page(markup: str) -> dict[str, Any]:
    parser = DetailParser()
    parser.feed(markup)
    body = parser.body
    source_match = re.search(r"来源\s*[：:]\s*([^<\n]+)", markup)
    publication_match = re.search(r"发布时间\s*[：:]\s*([^<\n]+)", markup)
    source = clean_text(source_match.group(1)) if source_match else parser.source
    publication_date = (
        parse_date(publication_match.group(1)) if publication_match else parser.publication_date
    )
    return {
        "title": parser.title,
        "body": body,
        "source": source,
        "publication_date": publication_date,
        "has_body": bool(body.strip()),
    }


def is_guiding_title(title: str) -> bool:
    return bool(GUIDING_TITLE_RE.search(clean_text(title)))


def is_reference_candidate_title(title: str) -> bool:
    value = clean_text(title)
    return "入库参考案例" in value and "解读" not in value


def parse_guiding_number(value: str) -> int | None:
    match = GUIDING_TITLE_RE.search(clean_text(value))
    if not match:
        return None
    digits = match.group(1).translate(str.maketrans("０１２３４５６７８９", "0123456789"))
    try:
        number = int(digits)
    except ValueError:
        return None
    return number if number > 0 else None


def parse_reference_number(value: str) -> str | None:
    match = REFERENCE_NUMBER_RE.search(clean_text(value))
    if not match:
        return None
    return re.sub(r"\s+", "", match.group(1))


def extract_sections(text: str) -> dict[str, str]:
    lines = clean_text(text).split("\n")
    positions: list[tuple[int, str, str]] = []
    aliases = [
        (heading, key)
        for key, headings in SECTION_ALIASES.items()
        for heading in headings
    ]
    for index, raw_line in enumerate(lines):
        line = clean_text(raw_line).strip(" ：:")
        if not line:
            continue
        compact = compact_text(line)
        for heading, key in aliases:
            heading_compact = compact_text(heading)
            if compact == heading_compact:
                positions.append((index, key, ""))
                break
            if compact.startswith(heading_compact):
                remainder = line[len(heading) :].lstrip(" ：:")
                if remainder and not remainder.startswith(("/", "、")):
                    positions.append((index, key, remainder))
                    break
    positions.sort(key=lambda item: item[0])
    result: dict[str, str] = {}
    for position, (line_index, key, inline) in enumerate(positions):
        end = positions[position + 1][0] if position + 1 < len(positions) else len(lines)
        values = ([inline] if inline else []) + lines[line_index + 1 : end]
        value = clean_text("\n".join(values))
        if key not in result or len(value) > len(result[key]):
            result[key] = value
    return result


def split_keywords(value: str) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[/／,，;；、\n]+", value)
    result: list[str] = []
    for part in parts:
        part = clean_text(part).strip(" ：:")
        if part and part not in result:
            result.append(part)
    return result[:64]


def split_key_points(value: str) -> list[str]:
    if not value:
        return []
    value = clean_text(value)
    matches = list(
        re.finditer(
            r"(?:^|\n)\s*(?:([0-9０-９]+)|([一二三四五六七八九十百千万]+))[\.．、)]\s*",
            value,
        )
    )
    if not matches:
        return [value]
    result: list[str] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        item = clean_text(value[start:end]).strip(" ；;")
        if item:
            result.append(item)
    return result[:64]


def split_related_laws(value: str, full_text: str) -> list[str]:
    source = value or full_text
    result: list[str] = []
    for match in re.finditer(r"《[^》]{1,200}》[^\n]*", source):
        item = clean_text(match.group(0)).strip(" ；;。")
        if item and item not in result:
            result.append(item)
    return result[:64]


def extract_case_number(text: str) -> str | None:
    for match in CASE_NUMBER_RE.finditer(text):
        value = clean_text(f"（{match.group(1)}）{match.group(2)}")
        if value and "最高人民法院审判委员会" not in value:
            return value
    return None


def extract_court(text: str, judgment_result: str) -> str | None:
    explicit = re.search(
        r"(?:审理法院|一审法院|二审法院|终审法院|承办法院)\s*[:：]\s*([^\n，。,；;]{2,80})",
        text,
    )
    if explicit:
        return clean_text(explicit.group(1))
    candidates = re.findall(
        r"[\u4e00-\u9fff]{2,40}(?:知识产权|互联网|海事|铁路运输|高级|中级|基层|人民)法院",
        judgment_result or text,
    )
    candidates = [candidate for candidate in candidates if candidate != "人民法院"]
    return candidates[0] if candidates else None


def extract_withdrawn_guiding_numbers(text: str) -> list[int]:
    """Read numbers from the notice's ``不再参照`` sentence only."""

    value = clean_text(text)
    marker = value.find("不再参照")
    if marker < 0:
        return []
    start = max(
        value.rfind("。", 0, marker),
        value.rfind("！", 0, marker),
        value.rfind("？", 0, marker),
        value.rfind("\n", 0, marker),
    ) + 1
    end_candidates = [
        position
        for position in (
            value.find("。", marker),
            value.find("！", marker),
            value.find("？", marker),
            value.find("\n", marker),
        )
        if position >= 0
    ]
    end = min(end_candidates) if end_candidates else len(value)
    window = value[start:end]
    numbers: list[int] = []
    for match in re.finditer(r"(?<!\d)(\d{1,4})号", window):
        number = int(match.group(1))
        if number not in numbers:
            numbers.append(number)
    return numbers


def build_case_record(
    *,
    item: ListingItem,
    detail: dict[str, Any],
    raw_body: bytes,
    case_type: str,
    fetched_at: str,
) -> tuple[dict[str, Any] | None, str | None]:
    title = clean_text(detail.get("title") or item.title)
    body = clean_text(detail.get("body"))
    if not title:
        return None, "missing_title"
    if not body:
        return None, "missing_body"
    if case_type == "guiding":
        guiding_number = parse_guiding_number(title) or parse_guiding_number(item.title)
        if guiding_number is None:
            return None, "guiding_number_missing"
        case_id = f"spc-guiding-{guiding_number}"
        reference_number = None
    elif case_type == "reference":
        reference_number = parse_reference_number(body) or parse_reference_number(title)
        if reference_number is None:
            return None, "reference_number_missing"
        case_id = f"spc-reference-{reference_number}"
        guiding_number = None
    else:
        raise BuildError(f"unsupported case type: {case_type}")
    sections = extract_sections(body)
    keywords = split_keywords(sections.get("keywords", ""))
    key_points = split_key_points(sections.get("key_points", ""))
    related_laws = split_related_laws(sections.get("related_laws", ""), body)
    publication_date = detail.get("publication_date") or item.listed_date
    case_number = extract_case_number(body)
    judgment_result = sections.get("judgment_result", "")
    court = extract_court(body, judgment_result)
    search_text = clean_text(
        "\n".join(
            part
            for part in (
                title,
                " ".join(keywords),
                case_number or "",
                reference_number or "",
                body,
            )
            if part
        )
    )
    return {
        "case_id": case_id,
        "case_type": case_type,
        "guiding_number": guiding_number,
        "reference_number": reference_number,
        "title": title,
        "keywords_json": json_dumps(keywords),
        "publication_date": publication_date,
        "court": court,
        "case_number": case_number,
        "status": "published",
        "source_url": item.url,
        "search_text": search_text,
        "key_points_json": json_dumps(key_points),
        "basic_facts": sections.get("basic_facts", ""),
        "judgment_result": judgment_result,
        "reasoning": sections.get("reasoning", ""),
        "related_laws_json": json_dumps(related_laws),
        "full_text": body,
        "fetched_at": fetched_at,
        # The service verifies this digest against the persisted full_text
        # UTF-8 bytes.  Keep the raw response digest in the source manifest
        # (FetchResult) so the two integrity claims remain distinct.
        "content_sha256": sha256_bytes(body.encode("utf-8")),
        "missing_sections": [
            key
            for key in ("keywords", "key_points", "basic_facts", "judgment_result", "reasoning")
            if not sections.get(key)
        ],
    }, None


def cache_path_for_url(cache_dir: Path, url: str) -> Path:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/") or "index.html"
    if parsed.query:
        suffix = hashlib.sha256(parsed.query.encode("utf-8")).hexdigest()[:12]
        path = f"{path}--{suffix}"
    return cache_dir / "spc" / path


def _atomic_write(path: Path, body: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body if isinstance(body, bytes) else body.encode("utf-8"))
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


class CachedFetcher:
    """Fetch official pages with atomic, resumable response caching."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        refresh: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        pause: float = DEFAULT_PAUSE,
        opener: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache_dir = cache_dir
        self.refresh = refresh
        self.timeout = timeout
        self.retries = max(0, retries)
        self.pause = max(0.0, pause)
        self.opener = opener or urllib.request.build_opener()
        self.sleep = sleep
        self.results: list[FetchResult] = []
        self.failures: list[FetchFailure] = []

    def _read_cache(self, url: str, path: Path) -> FetchResult:
        body = path.read_bytes()
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        fetched_at = None
        if meta_path.exists():
            try:
                payload = json.loads(meta_path.read_text(encoding="utf-8"))
                if payload.get("fetched_at"):
                    fetched_at = str(payload["fetched_at"])
            except (OSError, ValueError, TypeError):
                fetched_at = None
        if fetched_at is None:
            fetched_at = dt.datetime.fromtimestamp(
                path.stat().st_mtime, tz=dt.timezone.utc
            ).replace(microsecond=0).isoformat()
        return FetchResult(
            url=url,
            body=body,
            cache_path=path,
            fetched_at=fetched_at,
            content_sha256=sha256_bytes(body),
            from_cache=True,
        )

    def fetch(self, url: str) -> FetchResult:
        url = official_url(url)
        path = cache_path_for_url(self.cache_dir, url)
        if path.exists() and not self.refresh:
            result = self._read_cache(url, path)
            self.results.append(result)
            return result
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                request = urllib.request.Request(
                    url,
                    headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
                    method="GET",
                )
                with self.opener.open(request, timeout=self.timeout) as response:
                    body = response.read()
                    content_type = response.headers.get("Content-Type", "")
                    markup = decode_html(body, content_type)
                if looks_like_waf_challenge(markup):
                    raise WafChallengeError(
                        "official endpoint returned a JavaScript/login challenge; no bypass attempted"
                    )
                fetched_at = now_iso()
                _atomic_write(path, body)
                _atomic_write(
                    path.with_suffix(path.suffix + ".meta.json"),
                    json_dumps({"url": url, "fetched_at": fetched_at, "sha256": sha256_bytes(body)}),
                )
                result = FetchResult(
                    url=url,
                    body=body,
                    cache_path=path,
                    fetched_at=fetched_at,
                    content_sha256=sha256_bytes(body),
                    from_cache=False,
                )
                self.results.append(result)
                return result
            except WafChallengeError as error:
                last_error = error
                break
            except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as error:
                last_error = error
                if attempt < self.retries and self.pause:
                    self.sleep(self.pause * (2**attempt))
        message = str(last_error or "unknown fetch error")
        if path.exists():
            stale = self._read_cache(url, path)
            stale.stale_cache = True
            stale.refresh_error = message
            self.results.append(stale)
            self.failures.append(FetchFailure(url=url, kind="refresh_failed_using_cache", error=message, cache_path=str(path)))
            return stale
        kind = "challenge" if isinstance(last_error, WafChallengeError) else "fetch_failed"
        failure = FetchFailure(url=url, kind=kind, error=message, cache_path=None)
        self.failures.append(failure)
        raise FetchError(f"{url}: {message}") from last_error


def page_url(page_number: int) -> str:
    return GUIDING_INDEX_URL if page_number == 1 else f"{COURT_BASE}/shenpan/gengduo/77_{page_number}.html"


def reference_search_url(page_number: int) -> str:
    return f"{REFERENCE_SEARCH_BASE}?{urllib.parse.urlencode({'content': REFERENCE_SEARCH_QUERY, 'page': page_number})}"


def unique_items(items: Iterable[ListingItem]) -> list[ListingItem]:
    seen: set[str] = set()
    result: list[ListingItem] = []
    for item in items:
        if item.url in seen:
            continue
        seen.add(item.url)
        result.append(item)
    return result


@dataclass
class CollectionResult:
    records: list[dict[str, Any]]
    coverage: dict[str, Any]
    excluded: list[dict[str, Any]] = field(default_factory=list)


def collect_guiding(fetcher: CachedFetcher, limit: int | None = None) -> CollectionResult:
    first_result = fetcher.fetch(GUIDING_INDEX_URL)
    first_items, page_links, listed_total = parse_listing_page(
        decode_html(first_result.body), GUIDING_INDEX_URL
    )
    explicit_pages = [
        int(match.group(1) or "1")
        for url in page_links
        if (match := re.search(r"/77(?:_(\d+))?\.html$", url))
    ]
    max_page = max(explicit_pages or [1])
    if listed_total:
        max_page = max(max_page, math.ceil(listed_total / 20))
    listing_items = list(first_items)
    page_failures: list[dict[str, Any]] = []
    for number in range(2, max_page + 1):
        url = page_url(number)
        try:
            result = fetcher.fetch(url)
        except FetchError as error:
            page_failures.append({"url": url, "error": str(error)})
            continue
        page_items, _, _ = parse_listing_page(decode_html(result.body), url)
        listing_items.extend(page_items)
    listing_items = unique_items(listing_items)
    guiding_items: list[ListingItem] = []
    notifications: list[ListingItem] = []
    for item in listing_items:
        if is_guiding_title(item.title):
            guiding_items.append(item)
        else:
            notifications.append(item)
    if limit is not None:
        guiding_items = guiding_items[: max(0, limit)]
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    detail_failures: list[dict[str, Any]] = []
    for item in guiding_items:
        try:
            result = fetcher.fetch(item.url)
        except FetchError as error:
            detail_failures.append({"url": item.url, "title": item.title, "error": str(error)})
            continue
        detail = parse_detail_page(decode_html(result.body))
        record, reason = build_case_record(
            item=item,
            detail=detail,
            raw_body=result.body,
            case_type="guiding",
            fetched_at=result.fetched_at,
        )
        if record is None:
            rejected.append({"url": item.url, "title": item.title, "reason": reason})
        else:
            records.append(record)
    withdrawn_numbers: list[int] = []
    withdrawn_notice_error: str | None = None
    try:
        notice_result = fetcher.fetch(WITHDRAWN_NOTICE_URL)
        notice_detail = parse_detail_page(decode_html(notice_result.body))
        withdrawn_numbers = extract_withdrawn_guiding_numbers(notice_detail.get("body", ""))
    except FetchError as error:
        withdrawn_notice_error = str(error)
    for record in records:
        if record["guiding_number"] in withdrawn_numbers:
            record["status"] = "withdrawn"
    numbers = sorted(
        number
        for number in (parse_guiding_number(item.title) for item in guiding_items)
        if number is not None
    )
    max_number = max(numbers or [0])
    expected_numbers = list(range(1, max_number + 1)) if max_number else []
    present_numbers = sorted({int(row["guiding_number"]) for row in records})
    coverage = {
        "source_url": GUIDING_INDEX_URL,
        "listed_total": listed_total,
        "listing_pages": max_page,
        "listing_entry_count": len(listing_items),
        "guiding_entry_count": len(guiding_items),
        "notification_entry_count": len(notifications),
        "notification_urls": [item.url for item in notifications],
        "expected_guiding_numbers": expected_numbers,
        "present_guiding_numbers": present_numbers,
        "missing_guiding_numbers": sorted(set(expected_numbers) - set(present_numbers)),
        "duplicate_guiding_numbers": sorted(
            number for number in set(numbers) if numbers.count(number) > 1
        ),
        "detail_fetched_count": len(records) + len(rejected),
        "ingested_count": len(records),
        "page_failures": page_failures,
        "detail_failures": detail_failures,
        "withdrawn_notice_url": WITHDRAWN_NOTICE_URL,
        "withdrawn_guiding_numbers": withdrawn_numbers,
        "withdrawn_notice_error": withdrawn_notice_error,
        "rejected": rejected,
        "limited": limit is not None,
    }
    return CollectionResult(records=records, coverage=coverage, excluded=[
        {"url": item.url, "title": item.title, "reason": "official_listing_notification_or_non_case"}
        for item in notifications
    ])


def collect_reference(fetcher: CachedFetcher, limit: int | None = None) -> CollectionResult:
    first_url = reference_search_url(1)
    first_result = fetcher.fetch(first_url)
    first_items, search_total = parse_reference_search_page(
        decode_html(first_result.body), first_url
    )
    max_page = max(1, math.ceil(search_total / 20)) if search_total else 4
    search_items = list(first_items)
    search_failures: list[dict[str, Any]] = []
    for number in range(2, max_page + 1):
        url = reference_search_url(number)
        try:
            result = fetcher.fetch(url)
        except FetchError as error:
            search_failures.append({"url": url, "error": str(error)})
            continue
        page_items, page_total = parse_reference_search_page(decode_html(result.body), url)
        search_items.extend(page_items)
        if page_total:
            search_total = max(search_total or 0, page_total)
    search_items = unique_items(search_items)
    candidates = [item for item in search_items if is_reference_candidate_title(item.title)]
    if limit is not None:
        candidates = candidates[: max(0, limit)]
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    detail_failures: list[dict[str, Any]] = []
    for item in candidates:
        try:
            result = fetcher.fetch(item.url)
        except FetchError as error:
            detail_failures.append({"url": item.url, "title": item.title, "error": str(error)})
            continue
        detail = parse_detail_page(decode_html(result.body))
        record, reason = build_case_record(
            item=item,
            detail=detail,
            raw_body=result.body,
            case_type="reference",
            fetched_at=result.fetched_at,
        )
        if record is None:
            rejected.append({"url": item.url, "title": item.title, "reason": reason})
        else:
            records.append(record)
    excluded = [
        {"url": item.url, "title": item.title, "reason": "official_search_commentary_or_other"}
        for item in search_items
        if item not in candidates
    ]
    coverage = {
        "source_url": first_url,
        "search_total": search_total,
        "search_pages": max_page,
        "search_result_count": len(search_items),
        "candidate_count": len(candidates),
        "detail_fetched_count": len(records) + len(rejected),
        "ingested_count": len(records),
        "search_failures": search_failures,
        "detail_failures": detail_failures,
        "rejected": rejected,
        "limited": limit is not None,
        "selection_rule": "title contains 入库参考案例 and excludes 解读; body must contain 入库编号",
    }
    return CollectionResult(records=records, coverage=coverage, excluded=excluded + rejected)


def validate_records(records: list[dict[str, Any]]) -> None:
    ids: set[str] = set()
    for record in records:
        case_id = str(record["case_id"])
        if case_id in ids:
            raise BuildError(f"duplicate case id: {case_id}")
        ids.add(case_id)
        if record["case_type"] == "guiding":
            if not isinstance(record["guiding_number"], int) or record["reference_number"] is not None:
                raise BuildError(f"guiding identity is invalid: {case_id}")
        elif record["case_type"] == "reference":
            if not record["reference_number"] or record["guiding_number"] is not None:
                raise BuildError(f"reference identity is invalid: {case_id}")
        else:
            raise BuildError(f"case type is invalid: {case_id}")
        if not record["title"] or not record["full_text"]:
            raise BuildError(f"case content is incomplete: {case_id}")
        official_url(record["source_url"])
        if len(record["content_sha256"]) != 64:
            raise BuildError(f"case hash is invalid: {case_id}")


def source_manifest_hash(results: Iterable[FetchResult]) -> str:
    entries = [
        {
            "url": result.url,
            "fetched_at": result.fetched_at,
            "sha256": result.content_sha256,
        }
        for result in sorted(results, key=lambda item: item.url)
    ]
    return hashlib.sha256(json_dumps(entries).encode("utf-8")).hexdigest()


def create_database(
    records: list[dict[str, Any]],
    output: Path,
    *,
    metadata: dict[str, str],
) -> tuple[int, str]:
    validate_records(records)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        connection = sqlite3.connect(temp_path)
        try:
            connection.executescript(SCHEMA_SQL.read_text(encoding="utf-8"))
            connection.executemany(
                "INSERT INTO database_metadata (key, value) VALUES (?, ?)",
                sorted(metadata.items()),
            )
            columns = (
                "case_id", "case_type", "guiding_number", "reference_number", "title",
                "keywords_json", "publication_date", "court", "case_number", "status",
                "source_url", "search_text", "key_points_json", "basic_facts", "judgment_result",
                "reasoning", "related_laws_json", "full_text", "fetched_at", "content_sha256",
            )
            statement = f"INSERT INTO judicial_cases ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
            connection.executemany(
                statement,
                [tuple(record.get(column) for column in columns) for record in records],
            )
            connection.commit()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise BuildError(f"SQLite integrity check failed: {integrity}")
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if user_version != 1:
                raise BuildError(f"unexpected judicial database user_version: {user_version}")
        finally:
            connection.close()
        os.replace(temp_path, output)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return len(records), file_sha256(output)


def render_sources_doc(
    *,
    generated_at: str,
    manifest: dict[str, Any],
) -> str:
    guiding = manifest["coverage"]["guiding"]
    reference = manifest["coverage"]["reference"]
    failures = manifest["failures"]
    status = manifest["coverage_status"]
    missing = guiding.get("missing_guiding_numbers") or []
    missing_text = "、".join(str(number) for number in missing) if missing else "无"
    failure_text = (
        "；".join(f"{item['url']}：{item['error']}" for item in failures)
        if failures
        else "无"
    )
    return f"""# 最高人民法院司法案例 sidecar 数据来源说明

本文件说明随应用分发的 `judicial_cases.sqlite` 的公开来源和覆盖边界。数据库是可替换的只读 sidecar，服务从 `legal_core.sqlite` 所在目录读取它；本构建没有修改 `legal_core.sqlite`。

- 构建时间：`{generated_at}`
- 数据集版本：`{manifest['dataset_version']}`
- SQLite 文件：`{manifest['filename']}`
- SQLite SHA-256：`{manifest['sha256']}`
- 数据库大小：`{manifest['size_bytes']}` 字节
- schema：`{manifest['schema_version']}`，`PRAGMA user_version=1`
- 覆盖状态：`{status}`（该状态保留官方目录缺失项，不把不确定数据写成完整）

## 官方指导案例

来源目录：[最高人民法院指导案例](https://www.court.gov.cn/shenpan/gengduo/77.html)。构建时逐页读取该目录当前公开分页，并对每个案例详情页保存来源 URL、抓取时间和原始响应 SHA-256。目录页面显示共 `{guiding.get('listed_total')}` 篇文章，其中 `{guiding.get('guiding_entry_count')}` 条是“指导案例/指导性案例”条目，另有 `{guiding.get('notification_entry_count')}` 条是发布通知或其他非案例文章；通知没有写入 `judicial_cases`。

目录中出现的指导编号范围为 `{min(guiding.get('expected_guiding_numbers') or [0])}` 至 `{max(guiding.get('expected_guiding_numbers') or [0])}`，按目录和详情页核对后缺失编号：`{missing_text}`。缺失项保留在覆盖审计中，不补录、不根据通知推断案例。

另行核验的官方通知：[关于部分指导性案例不再参照的通知](https://www.court.gov.cn/fabu/xiangqing/282441.html)。通知正文明确 9 号、20 号“指导性案例不再参照”，数据库相应记录的 `status` 为 `withdrawn`；通知正文和通知 URL 仅作为覆盖与状态证据，不作为案例行。

## 公开入库参考案例

来源入口：[最高人民法院站内“入库参考案例”搜索](https://www.court.gov.cn/search.html?content=%E5%85%A5%E5%BA%93%E5%8F%82%E8%80%83%E6%A1%88%E4%BE%8B&page=1)。搜索结果中的正式案例文章和“入库参考案例选介”文章只有在详情正文可读且包含官方“入库编号”时才纳入，`入库参考案例解读`等评论文章被排除；没有使用需要登录的人民法院案例库接口，也没有把典型案例或公告当作参考案例。

本次搜索显示约 `{reference.get('search_total')}` 个结果，读取 `{reference.get('search_pages')}` 页，得到 `{reference.get('candidate_count')}` 个候选条目，成功纳入 `{reference.get('ingested_count')}` 条。参考案例编号和原始官网 URL 均保存在数据库中，候选条目正文缺失或无编号的情况保留在 manifest 审计。

## 抓取和失败处理

响应正文写入 `data/build/cache/spc/`，采用临时文件加原子替换；网络失败时按指数暂停重试，已有缓存可在下一次运行续接。官方返回 JavaScript/WAF/login challenge 时停止该 URL 的抓取，不尝试绕过；刷新失败不会覆盖已有 sidecar。只有新库通过 SQLite integrity check 后才替换目标文件。

本构建记录的未解决抓取失败：`{failure_text}`。

案例正文仅供离线检索和人工核对，使用时仍应打开来源 URL 复核官方页面的现行状态、脱敏内容和事实完整性。
"""


def build(
    *,
    output: Path = DEFAULT_OUTPUT,
    manifest_path: Path = DEFAULT_MANIFEST,
    sources_doc: Path = DEFAULT_SOURCES_DOC,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    refresh: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    pause: float = DEFAULT_PAUSE,
    limit: int | None = None,
    skip_reference: bool = False,
    strict: bool = False,
    fetcher: CachedFetcher | None = None,
) -> dict[str, Any]:
    started_at = now_iso()
    active_fetcher = fetcher or CachedFetcher(
        cache_dir,
        refresh=refresh,
        timeout=timeout,
        retries=retries,
        pause=pause,
    )
    guiding = collect_guiding(active_fetcher, limit=limit)
    reference = (
        CollectionResult(records=[], coverage={"search_total": 0, "search_pages": 0, "candidate_count": 0, "ingested_count": 0}, excluded=[])
        if skip_reference
        else collect_reference(active_fetcher, limit=limit)
    )
    records = guiding.records + reference.records
    validate_records(records)
    source_hash = source_manifest_hash(active_fetcher.results)
    failures = [
        {"url": item.url, "kind": item.kind, "error": item.error, "cache_path": item.cache_path}
        for item in active_fetcher.failures
    ]
    hard_failures = [item for item in failures if item["kind"] != "refresh_failed_using_cache"]
    if strict and hard_failures:
        raise BuildError(f"strict build refused {len(hard_failures)} unresolved fetch failures")
    existing_output = output.exists()
    # A failed source must never turn a healthy existing sidecar into a
    # silently smaller database, regardless of whether this run was an
    # explicit refresh.  Cached responses from a previous successful run keep
    # the normal path usable; an actual fetch failure is recorded above.
    if existing_output and failures:
        raise BuildError(
            "official source failures detected; existing judicial_cases.sqlite was preserved"
        )
    coverage_status = "guiding_catalogue_partial_reference_curated"
    if limit is not None:
        coverage_status = "limited_build"
    if hard_failures:
        coverage_status = "partial_fetch"
    if guiding.coverage.get("missing_guiding_numbers") or reference.coverage.get("detail_failures") or reference.coverage.get("rejected"):
        coverage_status = "guiding_catalogue_partial_reference_curated"
    version_suffix = f"{started_at[:10].replace('-', '')}-{source_hash[:12]}"
    dataset_version = f"judicial-cases-v1-{version_suffix}"
    metadata = {
        "schema_version": "1",
        "dataset_version": dataset_version,
        "generated_at": started_at,
        "source_manifest_sha256": source_hash,
        "coverage_status": coverage_status,
        "guiding_case_count": str(len(guiding.records)),
        "reference_case_count": str(len(reference.records)),
    }
    row_count, database_hash = create_database(records, output, metadata=metadata)
    manifest: dict[str, Any] = {
        "dataset_name": "supreme-people-court-judicial-cases",
        "dataset_version": dataset_version,
        "database_version": dataset_version,
        "generated_at": started_at,
        "filename": output.name,
        "path": str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else str(output),
        "size_bytes": output.stat().st_size,
        "sha256": database_hash,
        "schema_version": "1",
        "coverage_status": coverage_status,
        "source_manifest_sha256": source_hash,
        "row_count": row_count,
        "counts": {
            "guiding": len(guiding.records),
            "reference": len(reference.records),
            "total": row_count,
        },
        "coverage": {"guiding": guiding.coverage, "reference": reference.coverage},
        "excluded": guiding.excluded + reference.excluded,
        "failures": failures,
        "sources": [
            {
                "url": result.url,
                "fetched_at": result.fetched_at,
                "sha256": result.content_sha256,
                "cache_path": str(result.cache_path.relative_to(ROOT))
                if result.cache_path.is_relative_to(ROOT)
                else str(result.cache_path),
                "from_cache": result.from_cache,
                "stale_cache": result.stale_cache,
                "refresh_error": result.refresh_error,
            }
            for result in sorted(active_fetcher.results, key=lambda item: item.url)
        ],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    sources_doc.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(sources_doc, render_sources_doc(generated_at=started_at, manifest=manifest))
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sources-doc", type=Path, default=DEFAULT_SOURCES_DOC)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--refresh", action="store_true", help="Refresh official pages even when cached.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--pause", type=float, default=DEFAULT_PAUSE)
    parser.add_argument("--limit", type=int, default=None, help="Limit each source while developing or testing.")
    parser.add_argument("--skip-reference", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Fail when a source has no usable response or cache.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = build(
            output=args.output,
            manifest_path=args.manifest,
            sources_doc=args.sources_doc,
            cache_dir=args.cache_dir,
            refresh=args.refresh,
            timeout=args.timeout,
            retries=args.retries,
            pause=args.pause,
            limit=args.limit,
            skip_reference=args.skip_reference,
            strict=args.strict,
        )
    except BuildError as error:
        print(f"judicial case build failed: {error}")
        return 2
    print(
        json.dumps(
            {
                "rows": manifest["row_count"],
                "guiding": manifest["counts"]["guiding"],
                "reference": manifest["counts"]["reference"],
                "coverage_status": manifest["coverage_status"],
                "sha256": manifest["sha256"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
