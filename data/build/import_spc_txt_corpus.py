#!/usr/bin/env python3
"""Import the local Supreme People's Court TXT corpus into the case sidecar.

The archive is treated as an immutable data input.  This importer does not
execute anything from the archive and does not make network requests.  The
CSV is the source of the normalized identifiers and per-row digest contract;
the JSON metadata is used only to retain provenance and to fill optional
fields.  One canonical row is written to ``judicial_cases`` for each case,
while every TXT candidate (including API/PDF variants and the status notice)
is retained in ``judicial_case_sources``.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import urllib.parse
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SQL = ROOT / "data" / "schema" / "judicial_cases.sql"
DEFAULT_OUTPUT = ROOT / "data" / "runtime" / "judicial_cases.sqlite"
DEFAULT_MANIFEST = ROOT / "data" / "generated" / "judicial_cases_manifest.json"
DEFAULT_SOURCES_DOC = ROOT / "data" / "runtime" / "CASE_DATA_SOURCES.md"
DEFAULT_BACKUP_DIR = ROOT / "output" / "ai-upgrade-corpus"

CSV_FIELDS = (
    "ID",
    "规范案例标识",
    "类型",
    "标题",
    "指导编号",
    "来源",
    "TXT路径",
    "SHA-256",
)
CSV_TYPES = {"guiding", "api_guiding", "reference", "typical", "pdf", "notices"}
SOURCE_KINDS = {
    "guiding": "guiding",
    "api_guiding": "api_guiding",
    "reference": "reference",
    "typical": "typical",
    "pdf": "pdf",
    "notices": "notice",
}
ALLOWED_SOURCE_HOSTS = {
    "court.gov.cn",
    "www.court.gov.cn",
    "rmfyalk.court.gov.cn",
    "ipc.court.gov.cn",
    "hnlyzy.hncourt.gov.cn",
    "gongbao.court.gov.cn",
}
WITHDRAWN_GUIDING_NUMBERS = {9, 20}
MAX_CASE_TEXT_BYTES = 512 * 1024

SECTION_ALIASES: dict[str, tuple[str, ...]] = {
    "key_points": ("裁判要点", "裁判要旨", "指导意义", "典型意义", "执行实施要点"),
    "basic_facts": ("基本案情", "基本事实", "案件事实"),
    "judgment_result": ("裁判结果", "裁判结论", "判决结果", "执行结果"),
    "reasoning": ("裁判理由", "裁判说理", "裁判思路", "执行理由"),
    "related_laws": ("相关法条", "相关法律", "法律依据", "相关依据"),
}


class ImportError(RuntimeError):
    """The archive cannot produce a complete, verifiable sidecar."""


@dataclass
class SourceRecord:
    source_id: str
    case_id: str | None
    canonical_key: str | None
    normalized_case_id: str
    csv_id: str
    csv_type: str
    source_kind: str
    title: str
    source_url: str
    official_urls_json: str
    archive_path: str
    source_sha256: str
    text_sha256: str
    text_hash_mode: str
    source_host: str | None
    source_role: str | None
    source_authority: str | None
    publication_date: str | None
    fetched_at: str | None
    status: str
    is_primary: int
    source_header: str
    source_text: str
    priority: int

    def inventory(self) -> dict[str, Any]:
        """Return stable, non-content source evidence for the manifest hash."""
        return {
            "source_id": self.source_id,
            "case_id": self.case_id,
            "normalized_case_id": self.normalized_case_id,
            "csv_id": self.csv_id,
            "csv_type": self.csv_type,
            "source_kind": self.source_kind,
            # Keep the portable-package manifest's stable source contract in
            # addition to the more explicit names used by the source table.
            "url": self.source_url,
            "sha256": self.source_sha256,
            "source_url": self.source_url,
            "official_urls": json.loads(self.official_urls_json),
            "archive_path": self.archive_path,
            "source_sha256": self.source_sha256,
            "text_sha256": self.text_sha256,
            "text_hash_mode": self.text_hash_mode,
            "source_host": self.source_host,
            "source_role": self.source_role,
            "source_authority": self.source_authority,
            "publication_date": self.publication_date,
            "fetched_at": self.fetched_at,
            "status": self.status,
            "is_primary": bool(self.is_primary),
        }


@dataclass
class CaseRecord:
    case_id: str
    canonical_key: str
    case_type: str
    guiding_number: int | None
    reference_number: str | None
    title: str
    keywords_json: str
    publication_date: str | None
    court: str | None
    case_number: str | None
    status: str
    source_url: str
    search_text: str
    key_points_json: str
    basic_facts: str
    judgment_result: str
    reasoning: str
    related_laws_json: str
    full_text: str
    fetched_at: str
    content_sha256: str
    source_id: str


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def archive_path(value: str) -> str:
    normalized = value.replace("\\", "/").lstrip("./")
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        raise ImportError(f"archive path is unsafe: {value!r}")
    return normalized


def clean_for_parsing(value: str) -> str:
    """Normalize layout whitespace for field extraction without changing raw text."""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("\u3000", " ").replace("\xa0", " ").replace("\u200b", "")
    lines: list[str] = []
    previous_blank = False
    for raw_line in value.split("\n"):
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


def decode_txt(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ImportError("a TXT candidate is not valid UTF-8/GB18030 text")


def split_source_header(text: str) -> tuple[str, str]:
    """Separate the archive provenance header from the preserved TXT body."""
    match = re.search(r"\n[ \t]*\n", text)
    if not match:
        return "", text
    header = text[: match.start()]
    body = text[match.end() :]
    return header, body


def normalized_hashes(raw: bytes, text: str) -> tuple[str, str, str]:
    return (
        sha256_bytes(raw),
        sha256_bytes(text.encode("utf-8")),
        sha256_bytes(text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")),
    )


def verify_row_digest(expected: str, raw: bytes, text: str) -> tuple[str, str, str]:
    expected = expected.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ImportError(f"CSV SHA-256 is invalid: {expected!r}")
    raw_hash, text_hash, lf_hash = normalized_hashes(raw, text)
    if expected == raw_hash:
        return raw_hash, text_hash, "raw_bytes"
    if expected == text_hash:
        return raw_hash, text_hash, "utf8_text"
    if expected == lf_hash:
        return raw_hash, text_hash, "utf8_text_lf"
    raise ImportError(
        "CSV SHA-256 does not match TXT bytes/text: "
        f"expected={expected} raw={raw_hash} text={text_hash}"
    )


def load_json_metadata(zfile: zipfile.ZipFile) -> dict[str, dict[str, Any]]:
    by_txt: dict[str, dict[str, Any]] = {}
    for name in zfile.namelist():
        if not name.startswith("metadata/") or not name.lower().endswith(".json"):
            continue
        try:
            payload = json.loads(zfile.read(name).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ImportError(f"metadata JSON is invalid: {name}") from error
        txt_name = payload.get("txt_file")
        if not isinstance(txt_name, str):
            continue
        normalized = archive_path(txt_name)
        if normalized in by_txt:
            raise ImportError(f"duplicate metadata for TXT path: {normalized}")
        by_txt[normalized] = payload
    return by_txt


def report_generated_at(zfile: zipfile.ZipFile) -> str:
    for name in ("reports/corpus_manifest.json", "reports\\corpus_manifest.json"):
        try:
            payload = json.loads(zfile.read(name).decode("utf-8"))
        except KeyError:
            continue
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ImportError("reports/corpus_manifest.json is invalid") from error
        value = payload.get("generated_at")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return now_iso()


def first_string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def list_strings(payload: dict[str, Any], *keys: str) -> list[str]:
    result: list[str] = []
    for key in keys:
        value = payload.get(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str) and item.strip() and item.strip() not in result:
                result.append(item.strip())
    return result


def validate_source_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError as error:
        raise ImportError(f"source URL is invalid: {value!r}") from error
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or host not in ALLOWED_SOURCE_HOSTS
        or parsed.username
        or parsed.password
        or parsed.port is not None
    ):
        raise ImportError(f"source URL is outside the official host allowlist: {value}")
    return host


def official_urls(row: dict[str, str], metadata: dict[str, Any]) -> tuple[str, str]:
    candidates = [row.get("来源", ""), first_string(metadata, "source_url", "url") or ""]
    candidates.extend(list_strings(metadata, "source_urls", "listing_urls", "official_urls"))
    candidates.extend(list_strings(metadata, "parent_url"))
    urls: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in urls:
            validate_source_url(candidate)
            urls.append(candidate)
    if not urls:
        raise ImportError(f"source has no official URL: {row.get('ID', '')}")
    return urls[0], json_dumps(urls)


def compact_heading(value: str) -> str:
    return re.sub(r"[\s:：、.．。]+", "", value.strip(" \t:："))


def extract_sections(text: str) -> dict[str, str]:
    lines = clean_for_parsing(text).split("\n")
    aliases = [(compact_heading(alias), key) for key, values in SECTION_ALIASES.items() for alias in values]
    positions: list[tuple[int, str, str]] = []
    for index, raw_line in enumerate(lines):
        line = raw_line.strip(" \t:：")
        if not line:
            continue
        compact = compact_heading(line)
        for alias, key in aliases:
            if compact == alias:
                positions.append((index, key, ""))
                break
            if compact.startswith(alias):
                # Keep an inline heading such as ``裁判结果：驳回上诉``.
                remainder = line[len(alias) :].lstrip(" \t:：")
                if remainder:
                    positions.append((index, key, remainder))
                    break
    positions.sort(key=lambda item: item[0])
    result: dict[str, str] = {}
    for position, (line_index, key, inline) in enumerate(positions):
        end = positions[position + 1][0] if position + 1 < len(positions) else len(lines)
        values = ([inline] if inline else []) + lines[line_index + 1 : end]
        value = clean_for_parsing("\n".join(values))
        if value and (key not in result or len(value) > len(result[key])):
            result[key] = value
    return result


def split_bounded_items(value: str, limit: int = 64, max_bytes: int = 240) -> list[str]:
    result: list[str] = []
    for paragraph in re.split(r"\n+", value or ""):
        item = paragraph.strip(" \t;；。")
        while item:
            byte_count = 0
            cut = 0
            for cut, character in enumerate(item, start=1):
                next_count = byte_count + len(character.encode("utf-8"))
                if next_count > max_bytes:
                    cut -= 1
                    break
                byte_count = next_count
            else:
                cut = len(item)
            if cut == 0:
                raise ImportError("cannot split a text item within the byte limit")
            part, item = item[:cut], item[cut:]
            part = part.strip(" \t;；。")
            if part and part not in result:
                result.append(part)
            if len(result) >= limit:
                return result
    return result[:limit]


def related_laws(value: str, full_text: str) -> list[str]:
    source = value or full_text
    result: list[str] = []
    for match in re.finditer(r"《[^》]{1,200}》[^\n]*", source):
        for item in split_bounded_items(match.group(0), max_bytes=240):
            if item not in result:
                result.append(item)
            if len(result) >= 64:
                return result
    if not result and value:
        result = split_bounded_items(value)
    return result[:64]


def first_content_paragraph(text: str) -> str:
    # TXT files begin with a provenance header.  The first paragraph after
    # that header is a useful fallback for typical article collections.
    parts = [part.strip() for part in re.split(r"\n\s*\n", clean_for_parsing(text))]
    for part in parts:
        if len(part) >= 12 and not any(part.startswith(prefix) for prefix in ("来源", "来源抓取时间", "类型", "状态")):
            return part
    return ""


def title_terms(title: str, text: str, case_type: str) -> list[str]:
    result: list[str] = [case_type]
    for token in re.findall(r"《[^》]{1,100}》", text):
        if token not in result:
            result.append(token)
    for token in re.findall(r"[A-Za-z0-9]{2,32}", title):
        if token not in result:
            result.append(token)
    for run in re.findall(r"[\u4e00-\u9fff]{2,}", title):
        if run not in result:
            result.append(run)
        for start in range(max(1, len(run) - 24)):
            token = run[start : start + 2]
            if token not in result:
                result.append(token)
            if len(result) >= 64:
                return result
    return result[:64]


def safe_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-.")
    if not token:
        raise ImportError(f"cannot make a stable case identifier from {value!r}")
    return token


def parse_positive_int(value: Any, field: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as error:
        raise ImportError(f"{field} is not an integer: {value!r}") from error
    if number <= 0:
        raise ImportError(f"{field} must be positive: {value!r}")
    return number


def guiding_number_from_title(value: str) -> int | None:
    match = re.search(r"指导(?:性)?(?:案例)?\s*(\d+)\s*号", value)
    return int(match.group(1)) if match else None


def canonical_descriptor(row: dict[str, str], metadata: dict[str, Any]) -> tuple[str | None, str | None, str, int | None, str | None, str]:
    csv_type = row["类型"]
    csv_identifier = row["规范案例标识"].strip()
    metadata_id = first_string(metadata, "id") or row["ID"].strip()
    title = first_string(metadata, "title") or row.get("标题", "")
    guiding_number = parse_positive_int(
        metadata.get("guiding_number") or row.get("指导编号") or guiding_number_from_title(title),
        "guiding_number",
    )
    reference_number = first_string(metadata, "reference_number")

    if csv_type == "notices":
        return None, None, "notice", None, None, f"notice:{metadata_id}"
    if csv_type in {"guiding", "api_guiding"} or (csv_type == "pdf" and guiding_number is not None):
        if guiding_number is None:
            raise ImportError(f"guiding number is missing for {row['ID']}")
        key = f"guiding:{guiding_number}"
        return f"spc-guiding-{guiding_number}", key, "guiding", guiding_number, None, key
    if csv_type == "typical":
        # A typical collection article may mention a reference number in its
        # metadata.  Its CSV type controls the searchable domain, so it stays
        # a typical article and is never folded into the reference corpus.
        key = f"typical:{metadata_id}"
        return f"spc-typical-{safe_token(metadata_id)}", key, "typical", None, None, key
    if csv_type in {"reference", "pdf"}:
        if not reference_number:
            suffix = csv_identifier.split(":", 1)[1] if ":" in csv_identifier else metadata_id
            reference_number = suffix.strip()
        if not reference_number:
            raise ImportError(f"reference number is missing for {row['ID']}")
        key = f"reference:{reference_number}"
        return f"spc-reference-{safe_token(reference_number)}", key, "reference", None, reference_number, key
    raise ImportError(f"unsupported CSV type: {csv_type!r}")


def status_for(case_type: str, guiding_number: int | None, metadata: dict[str, Any], text: str) -> str:
    metadata_status = (first_string(metadata, "status") or "").lower()
    if (
        (case_type == "guiding" and guiding_number in WITHDRAWN_GUIDING_NUMBERS)
        or any(token in metadata_status for token in ("撤回", "不再参照", "withdrawn"))
    ):
        return "withdrawn"
    return "published"


def source_priority(csv_type: str, path: str) -> int:
    if csv_type == "guiding" and path.startswith("txt/guiding/"):
        return 0
    if csv_type == "reference" and path.startswith("txt/reference/"):
        return 0
    if csv_type == "typical" and path.startswith("txt/typical/"):
        return 0
    if csv_type == "api_guiding":
        return 1
    if csv_type == "pdf":
        return 2
    if csv_type == "guiding":
        return 3
    return 4


def build_source_and_case(
    row: dict[str, str],
    metadata: dict[str, Any],
    text: str,
    raw: bytes,
    hash_mode: str,
    source_sha256: str,
    text_sha256: str,
    generated_at: str,
    archive_name: str,
) -> tuple[SourceRecord, dict[str, Any] | None]:
    csv_type = row["类型"].strip()
    case_id, canonical_key, case_type, guiding_number, reference_number, source_key = canonical_descriptor(row, metadata)
    source_url, urls_json = official_urls(row, metadata)
    source_host = validate_source_url(source_url)
    title = row["标题"].strip() or first_string(metadata, "title") or row["ID"].strip()
    source_header, source_body = split_source_header(text)
    fetched_at = first_string(metadata, "fetched_at") or generated_at
    publication_date = first_string(metadata, "publication_date", "published_on", "published_at", "decision_date")
    source_status = status_for(case_type, guiding_number, metadata, text)
    source_id = "spc-source-" + sha256_bytes(
        f"{row['ID']}\0{archive_name}\0{row['SHA-256'].strip().lower()}".encode("utf-8")
    )[:32]
    source = SourceRecord(
        source_id=source_id,
        case_id=case_id,
        canonical_key=canonical_key,
        normalized_case_id=row["规范案例标识"].strip(),
        csv_id=row["ID"].strip(),
        csv_type=csv_type,
        source_kind=SOURCE_KINDS[csv_type],
        title=title,
        source_url=source_url,
        official_urls_json=urls_json,
        archive_path=archive_name,
        source_sha256=source_sha256,
        text_sha256=text_sha256,
        text_hash_mode=hash_mode,
        source_host=source_host,
        source_role=first_string(metadata, "source_role"),
        source_authority=first_string(metadata, "source_authority"),
        publication_date=publication_date,
        fetched_at=fetched_at,
        status=source_status,
        is_primary=0,
        source_header=source_header,
        source_text=text,
        priority=source_priority(csv_type, archive_name),
    )
    if case_id is None:
        return source, None

    sections = extract_sections(source_body)
    points = split_bounded_items(sections.get("key_points", ""))
    if not points:
        fallback = first_content_paragraph(source_body)
        points = split_bounded_items(fallback) if fallback else []
    laws = related_laws(sections.get("related_laws", ""), source_body)
    basic_facts = sections.get("basic_facts", "")
    judgment_result = sections.get("judgment_result", "")
    reasoning = sections.get("reasoning", "")
    case_number = first_string(metadata, "case_number")
    if not case_number:
        match = re.search(r"（\s*\d{4}\s*）[^\n]{1,120}?号", source_body)
        case_number = match.group(0).strip() if match else None
    court = first_string(metadata, "court", "source_authority")
    if not court and source_host == "www.court.gov.cn":
        court = "最高人民法院"
    keywords = title_terms(title, source_body, case_type)
    search_text = "\n".join(part for part in (title, " ".join(keywords), case_number or "", reference_number or "", source_body) if part)
    if len(search_text.encode("utf-8")) > MAX_CASE_TEXT_BYTES:
        raise ImportError(f"search text exceeds service limit: {row['ID']}")
    canonical = {
        "case_id": case_id,
        "canonical_key": canonical_key,
        "case_type": case_type,
        "guiding_number": guiding_number,
        "reference_number": reference_number,
        "title": title,
        "keywords_json": json_dumps(keywords),
        "publication_date": publication_date,
        "court": court,
        "case_number": case_number,
        "status": source_status,
        "source_url": source_url,
        "search_text": search_text,
        "key_points_json": json_dumps(points),
        "basic_facts": basic_facts,
        "judgment_result": judgment_result,
        "reasoning": reasoning,
        "related_laws_json": json_dumps(laws),
        "full_text": source_body,
        "fetched_at": fetched_at,
        "content_sha256": sha256_bytes(source_body.encode("utf-8")),
        "source_id": source_id,
        "priority": source.priority,
    }
    return source, canonical


def load_archive(archive: Path) -> tuple[list[CaseRecord], list[SourceRecord], dict[str, Any]]:
    if not archive.is_file() or archive.is_symlink():
        raise ImportError(f"archive must be a regular non-symlink file: {archive}")
    archive_sha256 = file_sha256(archive)
    with zipfile.ZipFile(archive) as zfile:
        names = {archive_path(name): name for name in zfile.namelist() if name and not name.endswith("/")}
        csv_names = [name for name in names if name.lower().endswith(".csv") and "/" not in name]
        if len(csv_names) != 1:
            raise ImportError(f"expected exactly one root CSV manifest, found {csv_names}")
        manifest_name = csv_names[0]
        csv_bytes = zfile.read(names[manifest_name])
        try:
            rows = list(csv.DictReader(io.TextIOWrapper(io.BytesIO(csv_bytes), "utf-8-sig", newline="")))
        except UnicodeDecodeError as error:
            raise ImportError("case CSV is not UTF-8") from error
        if not rows or tuple(rows[0].keys()) != CSV_FIELDS:
            raise ImportError(f"case CSV fields do not match the expected contract: {rows[0].keys() if rows else []}")
        metadata_by_txt = load_json_metadata(zfile)
        generated_at = report_generated_at(zfile)
        sources: list[SourceRecord] = []
        candidates: dict[str, list[tuple[SourceRecord, dict[str, Any]]]] = defaultdict(list)
        for row_number, row in enumerate(rows, start=2):
            missing = [field for field in CSV_FIELDS if not row.get(field, "").strip() and field not in {"指导编号"}]
            if missing:
                raise ImportError(f"CSV row {row_number} misses {missing}")
            csv_type = row["类型"].strip()
            if csv_type not in CSV_TYPES:
                raise ImportError(f"CSV row {row_number} has unsupported type {csv_type!r}")
            txt_name = archive_path(row["TXT路径"])
            if txt_name not in names:
                raise ImportError(f"CSV TXT path is absent from archive: {txt_name}")
            metadata = metadata_by_txt.get(txt_name)
            if metadata is None:
                raise ImportError(f"metadata is absent for TXT path: {txt_name}")
            raw = zfile.read(names[txt_name])
            text = decode_txt(raw)
            source_hash, text_hash, hash_mode = verify_row_digest(row["SHA-256"], raw, text)
            source, canonical = build_source_and_case(
                row,
                metadata,
                text,
                raw,
                hash_mode,
                source_hash,
                text_hash,
                generated_at,
                txt_name,
            )
            sources.append(source)
            if canonical is not None:
                candidates[canonical["canonical_key"]].append((source, canonical))
        if len(sources) != len(rows):
            raise ImportError("source row count does not match CSV row count")
        if len(metadata_by_txt) < len(rows):
            raise ImportError("archive metadata does not cover every CSV TXT row")

        selected: dict[str, tuple[SourceRecord, dict[str, Any]]] = {}
        for key, values in candidates.items():
            selected[key] = min(values, key=lambda item: (item[0].priority, item[0].source_id))
        for source in sources:
            if source.canonical_key in selected and source.source_id == selected[source.canonical_key][0].source_id:
                source.is_primary = 1
        cases: list[CaseRecord] = []
        for key, (source, canonical) in sorted(selected.items(), key=lambda item: item[0]):
            cases.append(CaseRecord(**{field: canonical[field] for field in CaseRecord.__dataclass_fields__ if field != "priority"}))
        for source in sources:
            if source.case_id is None:
                continue
            if source.case_id not in {case.case_id for case in cases}:
                raise ImportError(f"source refers to missing canonical case: {source.source_id}")
        source_inventory = [source.inventory() for source in sorted(sources, key=lambda item: item.source_id)]
        source_manifest_sha256 = sha256_bytes(json_dumps(source_inventory).encode("utf-8"))
        info = {
            "archive": str(archive),
            "archive_sha256": archive_sha256,
            "archive_size_bytes": archive.stat().st_size,
            "generated_at": generated_at,
            "source_manifest_sha256": source_manifest_sha256,
            "csv_rows": len(rows),
            "archive_entries": len(names),
            "source_counts": dict(sorted(Counter(source.csv_type for source in sources).items())),
            "source_kind_counts": dict(sorted(Counter(source.source_kind for source in sources).items())),
            "primary_source_count": sum(source.is_primary for source in sources),
            "withdrawn_case_ids": sorted(case.case_id for case in cases if case.status == "withdrawn"),
        }
        return cases, sources, info


def database_metadata(dataset_version: str, generated_at: str, info: dict[str, Any], cases: Iterable[CaseRecord]) -> dict[str, str]:
    counts = Counter(case.case_type for case in cases)
    return {
        "schema_version": "1",
        "dataset_version": dataset_version,
        "generated_at": generated_at,
        "source_manifest_sha256": info["source_manifest_sha256"],
        "coverage_status": "local_txt_archive_complete_with_source_variants",
        "guiding_case_count": str(counts["guiding"]),
        "reference_case_count": str(counts["reference"]),
        "typical_case_count": str(counts["typical"]),
        "source_row_count": str(info["csv_rows"]),
    }


def atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def create_database(
    cases: list[CaseRecord],
    sources: list[SourceRecord],
    output: Path,
    metadata: dict[str, str],
) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        connection = sqlite3.connect(temp_path)
        try:
            connection.executescript(SCHEMA_SQL.read_text(encoding="utf-8"))
            connection.executemany("INSERT INTO database_metadata (key, value) VALUES (?, ?)", sorted(metadata.items()))
            case_columns = (
                "case_id", "case_type", "guiding_number", "reference_number", "title",
                "keywords_json", "publication_date", "court", "case_number", "status",
                "source_url", "search_text", "key_points_json", "basic_facts", "judgment_result",
                "reasoning", "related_laws_json", "full_text", "fetched_at", "content_sha256",
            )
            case_sql = f"INSERT INTO judicial_cases ({', '.join(case_columns)}) VALUES ({', '.join('?' for _ in case_columns)})"
            connection.executemany(case_sql, [[getattr(case, field) for field in case_columns] for case in cases])
            source_columns = (
                "source_id", "case_id", "normalized_case_id", "csv_id", "csv_type", "source_kind",
                "title", "source_url", "official_urls_json", "archive_path", "source_sha256",
                "text_sha256", "text_hash_mode", "source_host", "source_role", "source_authority",
                "publication_date", "fetched_at", "status", "is_primary", "source_header", "source_text",
            )
            source_sql = f"INSERT INTO judicial_case_sources ({', '.join(source_columns)}) VALUES ({', '.join('?' for _ in source_columns)})"
            connection.executemany(source_sql, [[getattr(source, field) for field in source_columns] for source in sources])
            connection.commit()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            if integrity != "ok" or foreign_keys:
                raise ImportError(f"SQLite integrity check failed: {integrity}; foreign_keys={foreign_keys[:3]}")
            if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ImportError("unexpected judicial database PRAGMA user_version")
        finally:
            connection.close()
        os.replace(temp_path, output)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return file_sha256(output)


def backup_existing(output: Path, backup_dir: Path) -> str | None:
    if not output.exists():
        return None
    if output.is_symlink() or not output.is_file():
        raise ImportError(f"existing output is not a regular database file: {output}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = backup_dir / f"judicial_cases.sqlite.before-spc-{stamp}.sqlite"
    suffix = 1
    while destination.exists():
        destination = backup_dir / f"judicial_cases.sqlite.before-spc-{stamp}-{suffix}.sqlite"
        suffix += 1
    shutil.copy2(output, destination)
    return str(destination)


def render_sources_doc(manifest: dict[str, Any]) -> str:
    counts = manifest["counts"]
    source_counts = manifest["source_counts"]
    return f"""# 最高人民法院案例本地 TXT sidecar 来源说明

本数据库由本地 ZIP 数据包导入，导入过程不执行 ZIP 内的 README 指令，也不联网抓取。`legal_core.sqlite` 保持不变；服务只读打开同目录下的 `judicial_cases.sqlite`。

- 数据包：`{manifest['archive_name']}`
- 数据包 SHA-256：`{manifest['archive_sha256']}`
- 导入时间：`{manifest['generated_at']}`
- SQLite SHA-256：`{manifest['sha256']}`
- schema：`{manifest['schema_version']}`，`PRAGMA user_version=1`
- 来源 TXT 条目：`{manifest['csv_rows']}`；主案例/合集数：`{manifest['row_count']}`
- 指导案例：`{counts.get('guiding', 0)}`；参考案例：`{counts.get('reference', 0)}`；典型案例文章：`{counts.get('typical', 0)}`
- 源变体行数：`{manifest['source_row_count']}`；源清单 SHA-256：`{manifest['source_manifest_sha256']}`

## 类型和去重

`judicial_cases` 对每个规范案例标识保留一个可检索的主文本。指导案例按 `guiding:编号` 归并，参考案例按 `reference:编号` 归并，典型案例按其文章 ID 保留为 `case_type=typical`。典型案例文章可能包含多个案件，全文仍作为一篇典型案例文章保存，不会混入参考案例。

`judicial_case_sources` 保留 CSV 的全部 `{manifest['source_row_count']}` 行和对应 TXT 原文、来源标头、CSV 标识、来源 URL、抓取时间、SHA-256 及主源标记。`source_header` 保留 TXT 开头的来源/抓取元数据，`source_text` 保留完整原文，主案例的 `full_text` 只保存分隔后的正文。73 条 API 指导案例和 PDF 文本是源变体；它们不会造成重复的主案例。状态通知作为 `source_kind=notice` 留在源表中，`case_id` 为 NULL，不会作为案例返回。指导案例 9 号、20 号依据通知标为 `withdrawn`，默认检索排除，历史检索可显式包含。

## 来源主张

CSV 的每一行 SHA-256 均与 ZIP 内 TXT 原始字节核对通过。`source_sha256` 是原始 TXT 字节摘要，`text_sha256` 是 UTF-8 文本摘要；`content_sha256` 是主案例 `full_text` 的 UTF-8 摘要。所有候选来源 URL 均限制为法院官方主机：`www.court.gov.cn`、`rmfyalk.court.gov.cn`、`ipc.court.gov.cn`、`hnlyzy.hncourt.gov.cn` 及 `gongbao.court.gov.cn`。45 号指导案例的主源明确保留洛阳市中级人民法院官方转载 URL `https://hnlyzy.hncourt.gov.cn/public/detail.php?id=6738` 及其来源角色和权威机构字段，同时保留最高人民法院列表 URL。

## 源文件统计

```text
{json.dumps(source_counts, ensure_ascii=False, sort_keys=True)}
```

导入脚本：`data/build/import_spc_txt_corpus.py`。重复导入会先把已有 sidecar 备份到 `output/ai-upgrade-corpus/`，再在临时 SQLite 通过完整性检查后原子替换。
"""


def import_archive(
    archive: Path,
    *,
    output: Path = DEFAULT_OUTPUT,
    manifest_path: Path = DEFAULT_MANIFEST,
    sources_doc: Path = DEFAULT_SOURCES_DOC,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
) -> dict[str, Any]:
    started_at = now_iso()
    cases, sources, info = load_archive(archive)
    counts = Counter(case.case_type for case in cases)
    if counts != Counter({"guiding": 279, "reference": 61, "typical": 419}):
        raise ImportError(f"unexpected canonical case counts: {dict(counts)}")
    if len(sources) != 834 or info["source_counts"] != {"api_guiding": 73, "guiding": 279, "notices": 1, "pdf": 11, "reference": 51, "typical": 419}:
        raise ImportError(f"unexpected source inventory: {len(sources)} {info['source_counts']}")
    dataset_version = f"spc-case-corpus-v1-{info['archive_sha256'][:16]}"
    metadata = database_metadata(dataset_version, started_at, info, cases)
    backup = backup_existing(output, backup_dir)
    database_hash = create_database(cases, sources, output, metadata)
    source_counts = dict(sorted(Counter(source.csv_type for source in sources).items()))
    source_kind_counts = dict(sorted(Counter(source.source_kind for source in sources).items()))
    manifest: dict[str, Any] = {
        "dataset_name": "supreme-people-court-judicial-cases-local-txt",
        "dataset_version": dataset_version,
        "database_version": dataset_version,
        "generated_at": started_at,
        "archive_generated_at": info["generated_at"],
        "archive_name": archive.name,
        "archive_path": str(archive),
        "archive_size_bytes": info["archive_size_bytes"],
        "archive_sha256": info["archive_sha256"],
        "filename": output.name,
        "path": str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else str(output),
        "size_bytes": output.stat().st_size,
        "sha256": database_hash,
        "schema_version": "1",
        "schema": {"tables": ["database_metadata", "judicial_cases", "judicial_case_sources"]},
        "coverage_status": "local_txt_archive_complete_with_source_variants",
        "source_manifest_sha256": info["source_manifest_sha256"],
        "row_count": len(cases),
        "csv_rows": info["csv_rows"],
        "archive_entries": info["archive_entries"],
        "source_row_count": len(sources),
        "primary_source_count": info["primary_source_count"],
        "backup_path": backup,
        "counts": {**dict(sorted(counts.items())), "total": len(cases)},
        "source_counts": source_counts,
        "source_kind_counts": source_kind_counts,
        "withdrawn_case_ids": info["withdrawn_case_ids"],
        "guiding_numbers": [case.guiding_number for case in cases if case.case_type == "guiding"],
        "reference_numbers": [case.reference_number for case in cases if case.case_type == "reference"],
        "sources": [source.inventory() for source in sorted(sources, key=lambda item: item.source_id)],
    }
    atomic_write(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    atomic_write(sources_doc, render_sources_doc(manifest))
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", dest="archive", required=True, type=Path, help="local SPC TXT ZIP data package")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sources-doc", type=Path, default=DEFAULT_SOURCES_DOC)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = import_archive(
            args.archive,
            output=args.output,
            manifest_path=args.manifest,
            sources_doc=args.sources_doc,
            backup_dir=args.backup_dir,
        )
    except (ImportError, OSError, sqlite3.Error, zipfile.BadZipFile) as error:
        print(f"SPC TXT corpus import failed: {error}")
        return 2
    print(json.dumps({key: manifest[key] for key in ("dataset_version", "sha256", "row_count", "source_row_count", "backup_path")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
