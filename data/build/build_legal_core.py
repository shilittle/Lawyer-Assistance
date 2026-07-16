#!/usr/bin/env python3
"""Build the offline legal core database from official Chinese legal sources."""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import datetime as dt
import hashlib
import http.cookiejar
import html
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SQL = ROOT / "data" / "schema" / "legal_core.sql"
DEFAULT_OUTPUT = ROOT / "data" / "generated" / "legal_core_full.sqlite"
DEFAULT_REPORT = ROOT / "data" / "generated" / "legal_core_build_report.json"
CACHE_DIR = ROOT / "data" / "build" / "cache"
STATE_DB = ROOT / "data" / "build" / "state" / "legal_core_jobs.sqlite"

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
HISTORICAL_UNKNOWN_END_POLICY = "exclude_from_dated_queries"

FLK_BASE = "https://flk.npc.gov.cn"
FLK_SOURCE_ID = "flk_npc"
GJGZK_BASE = "https://www.gov.cn/zhengce/xxgk/gjgzk/index.htm?searchWord="
GJGZK_API_BASE = "https://sousuoht.www.gov.cn"
GJGZK_SOURCE_ID = "gjgzk_gov"
GJGZK_ATHENA_LIST = (
    "BD8730CDDA12515E2D9E1B21AA11C0D6"
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 40
COOKIE_JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(COOKIE_JAR))
WORD_APP: Any | None = None
WORD_COM_UNAVAILABLE = False

CHINESE_NUMERAL = "零〇一二两三四五六七八九十百千万亿"
ARTICLE_RE = re.compile(
    rf"^(第[{CHINESE_NUMERAL}0-9０-９]+条(?:之[{CHINESE_NUMERAL}0-9０-９]+)?)\s*(.*)$"
)


@dataclass(frozen=True)
class BuildOptions:
    output: Path
    report: Path
    cache_dir: Path
    state_db: Path
    stage: str
    page_size: int
    workers: int
    limit: int | None
    source: str
    metadata_only: bool
    strict: bool
    sleep: float
    min_delay: float
    max_delay: float
    resume: bool
    stop_on_waf: bool
    refresh_index: bool
    cookie_json: Path | None


class WafChallengeError(RuntimeError):
    """Raised when an official endpoint returns a JavaScript challenge page."""


def looks_like_waf_challenge(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in [
            "wzws-waf-cgi",
            "wzws_cid",
            "please enable javascript",
            "enable javascript and refresh",
            "javascript challenge",
        ]
    )


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self.skip_depth += 1
        elif tag in {"p", "br", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self.skip_depth:
            self.skip_depth -= 1
        elif tag in {"p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return normalize_text("".join(self.parts))


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def stable_id(*parts: object, prefix: str = "") -> str:
    digest = hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()
    return f"{prefix}{digest[:24]}"


def sha256_text(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        parts: list[str] = []
        for key in ("text", "title", "content", "html", "value", "children"):
            if key in value:
                text = coerce_text(value.get(key))
                if text:
                    parts.append(text)
        if not parts:
            parts = [coerce_text(item) for item in value.values()]
        return "\n".join(part for part in parts if part)
    if isinstance(value, (list, tuple)):
        return "\n".join(part for part in (coerce_text(item) for item in value) if part)
    return str(value)


def normalize_text(value: Any) -> str:
    value = coerce_text(value)
    if not value:
        return ""
    value = html.unescape(value)
    value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\u3000", " ")
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n[ \t]+", "\n", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def strip_html(value: Any) -> str:
    value = coerce_text(value)
    if not value:
        return ""
    extractor = TextExtractor()
    extractor.feed(value)
    return extractor.text()


def clean_title(value: str | None) -> str:
    return strip_html(value).strip() if value else ""


def read_or_fetch_json(path: Path, fetcher, *, refresh: bool = False) -> Any:
    if path.exists() and not refresh:
        return json.loads(path.read_text(encoding="utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    data = fetcher()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json_dumps(data), encoding="utf-8")
    tmp.replace(path)
    return data


def rate_limit(options: BuildOptions) -> None:
    if options.metadata_only:
        return
    if options.max_delay > 0:
        low = min(options.min_delay, options.max_delay)
        high = max(options.min_delay, options.max_delay)
        time.sleep(random.uniform(low, high))
    elif options.sleep:
        time.sleep(options.sleep)


def load_cookie_json(path: Path | None) -> None:
    if path is None or not path.exists():
        return
    for item in json.loads(path.read_text(encoding="utf-8")):
        domain = item.get("domain") or urllib.parse.urlparse(FLK_BASE).hostname or ""
        expires = item.get("expires")
        if isinstance(expires, float):
            expires = int(expires)
        if not isinstance(expires, int) or expires <= 0:
            expires = None
        cookie = http.cookiejar.Cookie(
            version=0,
            name=str(item.get("name") or ""),
            value=str(item.get("value") or ""),
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=domain.startswith("."),
            path=str(item.get("path") or "/"),
            path_specified=True,
            secure=bool(item.get("secure")),
            expires=expires,
            discard=expires is None,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": item.get("httpOnly")} if item.get("httpOnly") else {},
            rfc2109=False,
        )
        if cookie.name:
            COOKIE_JAR.set_cookie(cookie)


def open_state_db(options: BuildOptions) -> sqlite3.Connection:
    options.state_db.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(options.state_db)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS legal_core_jobs (
          id TEXT PRIMARY KEY,
          source_system_id TEXT NOT NULL,
          external_id TEXT NOT NULL,
          source_scope TEXT NOT NULL,
          source_url TEXT,
          index_status TEXT NOT NULL DEFAULT 'pending',
          detail_status TEXT NOT NULL DEFAULT 'pending',
          text_status TEXT NOT NULL DEFAULT 'pending',
          article_status TEXT NOT NULL DEFAULT 'pending',
          relation_status TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0,
          checksum TEXT,
          last_error TEXT,
          next_after TEXT,
          updated_at TEXT NOT NULL,
          UNIQUE(source_system_id, external_id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_legal_core_jobs_source ON legal_core_jobs(source_system_id, source_scope)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_legal_core_jobs_status ON legal_core_jobs(detail_status, text_status, article_status, relation_status)"
    )
    return connection


def mark_job(
    state: sqlite3.Connection | None,
    *,
    source_system_id: str,
    external_id: str,
    source_scope: str,
    source_url: str | None,
    index_status: str | None = None,
    detail_status: str | None = None,
    text_status: str | None = None,
    article_status: str | None = None,
    relation_status: str | None = None,
    checksum: str | None = None,
    last_error: str | None = None,
    increment_attempts: bool = False,
) -> None:
    if state is None:
        return
    timestamp = now_iso()
    row_id = stable_id(source_system_id, external_id, prefix="job-")
    state.execute(
        """
        INSERT INTO legal_core_jobs (
          id, source_system_id, external_id, source_scope, source_url,
          index_status, detail_status, text_status, article_status, relation_status,
          attempts, checksum, last_error, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 'pending', 'pending', 'pending', 'pending', 'pending', 0, NULL, NULL, ?)
        ON CONFLICT(source_system_id, external_id) DO NOTHING
        """,
        (row_id, source_system_id, external_id, source_scope, source_url, timestamp),
    )
    assignments = [
        "source_scope = ?",
        "source_url = COALESCE(?, source_url)",
        "updated_at = ?",
    ]
    params: list[Any] = [source_scope, source_url, timestamp]
    for column, value in [
        ("index_status", index_status),
        ("detail_status", detail_status),
        ("text_status", text_status),
        ("article_status", article_status),
        ("relation_status", relation_status),
    ]:
        if value is not None:
            assignments.append(f"{column} = ?")
            params.append(value)
    if checksum is not None:
        assignments.append("checksum = ?")
        params.append(checksum)
    if last_error is not None:
        assignments.append("last_error = ?")
        params.append(last_error[:1000])
    if increment_attempts:
        assignments.append("attempts = attempts + 1")
    params.extend([source_system_id, external_id])
    state.execute(
        f"""
        UPDATE legal_core_jobs
        SET {", ".join(assignments)}
        WHERE source_system_id = ? AND external_id = ?
        """,
        params,
    )


def write_ingestion_audit(
    connection: sqlite3.Connection,
    *,
    source_system_id: str,
    external_id: str,
    source_scope: str,
    source_url: str | None,
    index_status: str,
    detail_status: str,
    text_status: str,
    article_status: str,
    relation_status: str,
    attempts: int = 0,
    checksum: str | None = None,
    last_error: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO ingestion_audit (
          id, source_system_id, external_id, source_scope, source_url,
          index_status, detail_status, text_status, article_status, relation_status,
          attempts, checksum, last_error, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_system_id, external_id) DO UPDATE SET
          source_scope = excluded.source_scope,
          source_url = excluded.source_url,
          index_status = excluded.index_status,
          detail_status = excluded.detail_status,
          text_status = excluded.text_status,
          article_status = excluded.article_status,
          relation_status = excluded.relation_status,
          attempts = excluded.attempts,
          checksum = excluded.checksum,
          last_error = excluded.last_error,
          updated_at = excluded.updated_at
        """,
        (
            stable_id(source_system_id, external_id, prefix="inga-"),
            source_system_id,
            external_id,
            source_scope,
            source_url,
            index_status,
            detail_status,
            text_status,
            article_status,
            relation_status,
            attempts,
            checksum,
            last_error[:1000] if last_error else None,
            now_iso(),
        ),
    )


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 8,
) -> Any:
    body = None
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    }
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json_dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json;charset=utf-8")
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with OPENER.open(req, timeout=DEFAULT_TIMEOUT) as response:
                data = response.read()
            text = data.decode("utf-8", errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                if looks_like_waf_challenge(text):
                    raise WafChallengeError(f"WAF JavaScript challenge from {url}")
                print(f"non-json response from {url}: {text[:160]!r}")
                raise
        except urllib.error.HTTPError as error:
            try:
                error_text = error.read().decode("utf-8", errors="replace")
            except Exception:
                error_text = ""
            if error_text and looks_like_waf_challenge(error_text):
                raise WafChallengeError(f"WAF JavaScript challenge from {url}")
            if error.code in {307, 308} and error.headers.get("Location"):
                url = urllib.parse.urljoin(url, error.headers["Location"])
                delay = 1 + random.random()
                print(f"redirect {error.code} {url}; replaying with cookies after {delay:.1f}s")
                time.sleep(delay)
                continue
            if attempt == retries - 1:
                raise
            delay = min(30.0, (2**attempt) + random.random())
            print(f"retry {attempt + 1}/{retries} {url}: {error}; sleeping {delay:.1f}s")
            time.sleep(delay)
        except WafChallengeError:
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            if attempt == retries - 1:
                raise
            delay = min(30.0, (2**attempt) + random.random())
            print(f"retry {attempt + 1}/{retries} {url}: {error}; sleeping {delay:.1f}s")
            time.sleep(delay)


def download_file(url: str, output: Path, *, retries: int = 4, overwrite: bool = False) -> bool:
    if output.exists() and output.stat().st_size > 0 and not overwrite:
        return True
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Referer": FLK_BASE + "/",
            },
        )
        try:
            with OPENER.open(req, timeout=DEFAULT_TIMEOUT) as response:
                data = response.read()
            preview = data[:4096].decode("utf-8", errors="ignore")
            if looks_like_waf_challenge(preview):
                raise WafChallengeError(f"WAF JavaScript challenge from {url}")
            tmp.write_bytes(data)
            if tmp.stat().st_size == 0:
                raise IOError("downloaded empty file")
            tmp.replace(output)
            return True
        except WafChallengeError:
            if tmp.exists():
                tmp.unlink()
            raise
        except Exception as error:
            if tmp.exists():
                tmp.unlink()
            if attempt == retries - 1:
                print(f"download failed {url}: {error}")
                return False
            time.sleep((2**attempt) + random.random())
    return False


def file_head(path: Path, size: int = 8) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def decode_process_stdout(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace")


def close_word_app() -> None:
    global WORD_APP
    if WORD_APP is None:
        return
    try:
        WORD_APP.Quit()
    except Exception:
        pass
    WORD_APP = None


atexit.register(close_word_app)


def get_word_app() -> Any | None:
    global WORD_APP, WORD_COM_UNAVAILABLE
    if WORD_COM_UNAVAILABLE:
        return None
    if WORD_APP is not None:
        return WORD_APP
    try:
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        WORD_APP = win32com.client.DispatchEx("Word.Application")
        WORD_APP.Visible = False
        WORD_APP.DisplayAlerts = 0
        try:
            WORD_APP.AutomationSecurity = 3
        except Exception:
            pass
        return WORD_APP
    except Exception as error:
        WORD_COM_UNAVAILABLE = True
        print(f"Word COM unavailable for .doc extraction: {error}")
        return None


def word_doc_text(path: Path) -> str:
    app = get_word_app()
    if app is None:
        return ""
    temp_path: Path | None = None
    open_path = path
    if file_head(path).startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") and path.suffix.lower() != ".doc":
        temp = tempfile.NamedTemporaryFile(prefix="legal_core_", suffix=".doc", delete=False)
        temp.close()
        temp_path = Path(temp.name)
        shutil.copyfile(path, temp_path)
        open_path = temp_path
    doc = None
    try:
        doc = app.Documents.Open(str(open_path.resolve()), False, True, False)
        return normalize_text(doc.Content.Text)
    except Exception as error:
        print(f"cannot extract doc text with Word {path}: {error}")
        return ""
    finally:
        if doc is not None:
            try:
                doc.Close(False)
            except Exception:
                pass
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def docx_text(path: Path) -> str:
    head = file_head(path)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return doc_text(path)
    try:
        with zipfile.ZipFile(path) as archive:
            document_xml = archive.read("word/document.xml")
    except Exception as error:
        print(f"cannot read docx {path}: {error}")
        return ""
    try:
        root = ElementTree.fromstring(document_xml)
    except ElementTree.ParseError as error:
        print(f"cannot parse docx xml {path}: {error}")
        return ""
    paragraphs: list[str] = []
    for paragraph in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
        pieces: list[str] = []
        for node in paragraph.iter():
            if node.tag.endswith("}t") and node.text:
                pieces.append(node.text)
            elif node.tag.endswith("}tab"):
                pieces.append("\t")
            elif node.tag.endswith("}br"):
                pieces.append("\n")
        text = "".join(pieces).strip()
        if text:
            paragraphs.append(text)
    return normalize_text("\n".join(paragraphs))


def doc_text(path: Path) -> str:
    if file_head(path).startswith(b"PK\x03\x04"):
        return docx_text(path)
    text = word_doc_text(path)
    if text:
        return text
    try:
        result = subprocess.run(
            ["pandoc", str(path), "-t", "plain"],
            check=True,
            capture_output=True,
            text=False,
            timeout=60,
        )
    except Exception as error:
        print(f"cannot extract doc text {path}: {error}")
        return ""
    return normalize_text(decode_process_stdout(result))


def pdf_text(path: Path) -> str:
    try:
        result = subprocess.run(
            ["pdftotext", "-enc", "UTF-8", str(path), "-"],
            check=True,
            capture_output=True,
            text=False,
            timeout=60,
        )
    except Exception as error:
        print(f"cannot extract pdf text {path}: {error}")
        return ""
    return normalize_text(decode_process_stdout(result))


def rtf_text(path: Path) -> str:
    try:
        source = path.read_bytes().decode("latin-1", errors="ignore")
    except OSError as error:
        print(f"cannot read rtf {path}: {error}")
        return ""

    destinations = {
        "aftncn",
        "aftnsep",
        "aftnsepc",
        "annotation",
        "author",
        "background",
        "bkmkend",
        "bkmkstart",
        "colortbl",
        "colorschememapping",
        "comment",
        "datastore",
        "doccomm",
        "docvar",
        "fonttbl",
        "footer",
        "footerf",
        "footerl",
        "footerr",
        "footnote",
        "generator",
        "header",
        "headerf",
        "headerl",
        "headerr",
        "info",
        "keywords",
        "latentstyles",
        "listoverridetable",
        "listtable",
        "object",
        "panose",
        "pict",
        "revtbl",
        "rsidtbl",
        "stylesheet",
        "subject",
        "themedata",
        "title",
        "xmlnstbl",
    }
    out: list[str] = []
    byte_buffer: list[int] = []
    stack: list[tuple[int, bool]] = []
    ucskip = 1
    curskip = 0
    ignorable = False
    index = 0

    def flush_bytes() -> None:
        if not byte_buffer:
            return
        out.append(bytes(byte_buffer).decode("gb18030", errors="ignore"))
        byte_buffer.clear()

    while index < len(source):
        char = source[index]
        if char == "{":
            flush_bytes()
            stack.append((ucskip, ignorable))
            index += 1
            continue
        if char == "}":
            flush_bytes()
            if stack:
                ucskip, ignorable = stack.pop()
            index += 1
            continue
        if char == "\\":
            index += 1
            if index >= len(source):
                break
            control = source[index]
            if control == "'":
                raw = source[index + 1 : index + 3]
                index += 3
                if curskip > 0:
                    curskip -= 1
                elif not ignorable:
                    try:
                        byte_buffer.append(int(raw, 16))
                    except ValueError:
                        pass
                continue
            if not control.isalpha():
                flush_bytes()
                index += 1
                if control == "*":
                    ignorable = True
                elif control in "{}\\" and not ignorable:
                    out.append(control)
                elif control in "~_" and not ignorable:
                    out.append(" ")
                elif control == "-" and not ignorable:
                    out.append("-")
                continue

            start = index
            while index < len(source) and source[index].isalpha():
                index += 1
            word = source[start:index]
            sign = 1
            if index < len(source) and source[index] == "-":
                sign = -1
                index += 1
            number_start = index
            while index < len(source) and source[index].isdigit():
                index += 1
            parameter: int | None = None
            if number_start != index:
                parameter = sign * int(source[number_start:index])
            if index < len(source) and source[index] == " ":
                index += 1

            if word in destinations:
                flush_bytes()
                ignorable = True
            elif word == "uc" and parameter is not None:
                ucskip = max(0, parameter)
            elif word == "u" and parameter is not None:
                flush_bytes()
                if not ignorable:
                    codepoint = parameter if parameter >= 0 else parameter + 65536
                    out.append(chr(codepoint))
                curskip = ucskip
            elif word in {"par", "line", "sect", "page"}:
                flush_bytes()
                if not ignorable:
                    out.append("\n")
            elif word == "tab":
                flush_bytes()
                if not ignorable:
                    out.append("\t")
            continue

        index += 1
        if curskip > 0:
            curskip -= 1
        elif not ignorable:
            if ord(char) >= 128:
                byte_buffer.append(ord(char))
            else:
                flush_bytes()
                out.append(char)

    flush_bytes()
    return normalize_text("".join(out))


def word_xml_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        print(f"cannot read word xml {path}: {error}")
        return ""
    text = data.decode("utf-8-sig", errors="replace")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        print(f"cannot parse word xml {path}: {error}")
        return ""
    paragraphs: list[str] = []
    for paragraph in root.iter():
        if not paragraph.tag.endswith("}p") and paragraph.tag != "p":
            continue
        pieces: list[str] = []
        for node in paragraph.iter():
            if (node.tag.endswith("}t") or node.tag == "t") and node.text:
                pieces.append(node.text)
            elif node.tag.endswith("}tab"):
                pieces.append("\t")
            elif node.tag.endswith("}br"):
                pieces.append("\n")
        value = "".join(pieces).strip()
        if value:
            paragraphs.append(value)
    if paragraphs:
        return normalize_text("\n".join(paragraphs))
    return strip_html(text)


def raw_ole_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        print(f"cannot read ole document {path}: {error}")
        return ""
    text = data.decode("utf-16le", errors="ignore")
    text = re.sub(
        r"[^\u3400-\u9fffA-Za-z0-9，。、《》；：！？（）()\[\]【】“”‘’：:；;,.!?/\-—\s]+",
        "\n",
        text,
    )
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line and (len(line) >= 8 or re.search(r"[\u3400-\u9fff]{3,}", line))]
    result = normalize_text("\n".join(lines))
    if len(re.findall(r"[\u3400-\u9fff]", result)) < 50:
        return ""
    return result


def document_text(path: Path) -> str:
    head = file_head(path)
    if head.startswith(b"{\\rtf"):
        return rtf_text(path)
    if head.lstrip().startswith(b"<?xml") or head.lstrip().startswith(b"<pkg:"):
        return word_xml_text(path)
    if head.startswith(b"%PDF"):
        return pdf_text(path)
    if head.startswith(b"PK\x03\x04"):
        return docx_text(path)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return doc_text(path) or raw_ole_text(path)
    if path.suffix.lower() == ".pdf":
        return pdf_text(path)
    if path.suffix.lower() == ".docx":
        text = docx_text(path)
        return text or doc_text(path)
    return doc_text(path) or raw_ole_text(path)


def parse_articles(text: str) -> list[tuple[str, int, str | None, str]]:
    text = normalize_text(text)
    if not text:
        return []

    articles: list[tuple[str, int, str | None, str]] = []
    current_number: str | None = None
    current_lines: list[str] = []
    preamble: list[str] = []
    order = 0

    def flush() -> None:
        nonlocal order, current_number, current_lines
        if current_number is None:
            return
        content = normalize_text("\n".join(current_lines))
        if content:
            order += 1
            articles.append((current_number, order, None, content))
        current_number = None
        current_lines = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = ARTICLE_RE.match(line)
        if match:
            flush()
            current_number = match.group(1)
            remainder = match.group(2).strip()
            current_lines = [remainder] if remainder else []
        elif current_number is None:
            preamble.append(line)
        else:
            current_lines.append(line)
    flush()

    preamble_text = normalize_text("\n".join(preamble))
    if preamble_text and (articles or len(preamble_text) >= 80):
        articles.insert(0, ("序言", 0, "序言", preamble_text))
    if not articles:
        articles.append(("全文", 1, None, text))
    return articles


def compact_article_text(value: str) -> str:
    return "".join(ch for ch in normalize_text(value) if ch.isalnum()).lower()


def create_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA_SQL.read_text(encoding="utf-8"))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def insert_source_systems(connection: sqlite3.Connection) -> None:
    timestamp = now_iso()
    rows = [
        (
            FLK_SOURCE_ID,
            "国家法律法规数据库",
            FLK_BASE,
            "现行有效宪法及修正案、法律、行政法规、监察法规、地方性法规、自治条例和单行条例、特殊区域法规、司法解释，以及官方接口公开的历史版本和修改废止决定。",
            "全国人大常委会办公厅",
            timestamp,
            "Official source used for laws, regulations, judicial interpretations, history versions, amendments, and related files.",
        ),
        (
            GJGZK_SOURCE_ID,
            "国家规章库",
            GJGZK_BASE,
            "现行有效部门规章和地方政府规章。",
            "中国政府网",
            timestamp,
            "Official source used for department rules and local government rules that are outside the National Laws and Regulations Database scope.",
        ),
    ]
    connection.executemany(
        """
        INSERT INTO source_systems
          (id, name, base_url, official_scope, maintainer, retrieved_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          base_url = excluded.base_url,
          official_scope = excluded.official_scope,
          maintainer = excluded.maintainer,
          retrieved_at = excluded.retrieved_at,
          notes = excluded.notes
        """,
        rows,
    )


def insert_source_record(
    connection: sqlite3.Connection,
    *,
    source_system_id: str,
    external_id: str,
    record_type: str,
    source_url: str | None,
    raw_json: Any | None = None,
    raw_text: str | None = None,
) -> str:
    record_id = stable_id(source_system_id, external_id, record_type, prefix="src-")
    raw_json_text = json_dumps(raw_json) if raw_json is not None else None
    checksum = sha256_text((raw_json_text or "") + (raw_text or ""))
    connection.execute(
        """
        INSERT INTO source_records
          (id, source_system_id, external_id, record_type, source_url, retrieved_at, checksum, raw_json, raw_text)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_system_id, external_id, record_type) DO UPDATE SET
          source_url = excluded.source_url,
          retrieved_at = excluded.retrieved_at,
          checksum = excluded.checksum,
          raw_json = excluded.raw_json,
          raw_text = excluded.raw_text
        """,
        (
            record_id,
            source_system_id,
            external_id,
            record_type,
            source_url,
            now_iso(),
            checksum,
            raw_json_text,
            raw_text,
        ),
    )
    return record_id


def source_url_for_flk(bbbs: str) -> str:
    return f"{FLK_BASE}/detail?id={urllib.parse.quote(bbbs)}"


def flk_headers() -> dict[str, str]:
    return {
        "Origin": FLK_BASE,
        "Referer": FLK_BASE + "/",
    }


def flk_search_payload(page_no: int, page_size: int) -> dict[str, Any]:
    return {
        "searchContent": "",
        "searchRange": 1,
        "searchType": 2,
        "sxx": [],
        "gbrq": [],
        "sxrq": [],
        "flfgCodeId": [],
        "zdjgCodeId": [],
        "pageNum": page_no,
        "pageSize": page_size,
    }


def fetch_flk_page(options: BuildOptions, page_no: int) -> dict[str, Any]:
    path = options.cache_dir / "flk" / "pages" / f"size-{options.page_size}" / f"{page_no:05}.json"
    return read_or_fetch_json(
        path,
        lambda: request_json(
            FLK_BASE + "/law-search/search/list",
            method="POST",
            payload=flk_search_payload(page_no, options.page_size),
            headers=flk_headers(),
        ),
        refresh=options.refresh_index,
    )


def fetch_flk_detail(options: BuildOptions, bbbs: str) -> dict[str, Any]:
    path = flk_detail_path(options, bbbs)
    return read_or_fetch_json(
        path,
        lambda: request_json(
            FLK_BASE + "/law-search/search/flfgDetails?" + urllib.parse.urlencode({"bbbs": bbbs}),
            headers=flk_headers(),
        ),
    )


def fetch_flk_download_link(
    options: BuildOptions,
    bbbs: str,
    file_format: str = "docx",
    *,
    refresh: bool = False,
) -> dict[str, Any]:
    path = flk_download_link_path(options, bbbs, file_format)
    params = urllib.parse.urlencode({"format": file_format, "bbbs": bbbs, "fileId": ""})
    return read_or_fetch_json(
        path,
        lambda: request_json(
            FLK_BASE + "/law-search/download/pc?" + params,
            headers={"Referer": FLK_BASE + "/"},
        ),
        refresh=refresh,
    )


def flk_detail_path(options: BuildOptions, bbbs: str) -> Path:
    return options.cache_dir / "flk" / "details" / f"{bbbs}.json"


def flk_download_link_path(options: BuildOptions, bbbs: str, file_format: str = "docx") -> Path:
    suffix = "" if file_format == "docx" else f".{file_format}"
    return options.cache_dir / "flk" / "download_links" / f"{bbbs}{suffix}.json"


def flk_document_path(options: BuildOptions, bbbs: str, file_format: str = "docx") -> Path:
    return options.cache_dir / "flk" / "documents" / f"{bbbs}.{file_format}"


def flk_missing_text_path(options: BuildOptions, bbbs: str) -> Path:
    return options.cache_dir / "flk" / "missing_text" / f"{bbbs}.json"


def flk_fallback_text_path(options: BuildOptions, bbbs: str) -> Path:
    return options.cache_dir / "flk" / "fallback_text" / f"{bbbs}.json"


def get_flk_fallback_text(options: BuildOptions, bbbs: str) -> tuple[str, str | None]:
    path = flk_fallback_text_path(options, bbbs)
    if not path.exists():
        return "", None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"cannot read fallback text for FLK {bbbs}: {error}")
        return "", None
    text = normalize_text(payload.get("text"))
    if not text:
        return "", None
    return text, str(path.relative_to(ROOT))


def flk_detail_content_text(detail_data: dict[str, Any]) -> str:
    content = detail_data.get("content")
    if isinstance(content, dict) and "children" in content and not any(
        key in content for key in ("text", "html", "body", "paragraphs")
    ):
        return ""
    return strip_html(content)


def signed_url_expired(url: str, *, margin_seconds: int = 300) -> bool:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    raw_date = (query.get("X-Amz-Date") or [""])[0]
    raw_expires = (query.get("X-Amz-Expires") or [""])[0]
    if not raw_date or not raw_expires:
        return False
    try:
        signed_at = dt.datetime.strptime(raw_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
        expires = int(raw_expires)
    except (TypeError, ValueError):
        return False
    expires_at = signed_at + dt.timedelta(seconds=max(0, expires - margin_seconds))
    return dt.datetime.now(dt.timezone.utc) >= expires_at


def flk_text_needs_network(options: BuildOptions, bbbs: str, detail_data: dict[str, Any]) -> bool:
    if flk_detail_content_text(detail_data) or options.metadata_only:
        return False
    fallback_text, _ = get_flk_fallback_text(options, bbbs)
    if fallback_text:
        return False
    if flk_document_path(options, bbbs).exists() or flk_document_path(options, bbbs, "doc").exists() or flk_document_path(options, bbbs, "pdf").exists():
        return False
    if flk_missing_text_path(options, bbbs).exists():
        return False
    if not flk_download_link_path(options, bbbs).exists():
        return True
    return True


def flk_status(value: Any) -> str:
    return {
        1: "repealed",
        2: "amended",
        3: "in_force",
        4: "not_yet_effective",
    }.get(value, "unspecified")


def flk_document_type(category: str | None, title: str | None) -> str:
    text = f"{category or ''} {title or ''}"
    if "宪法" in text and "解释" not in text:
        return "constitution"
    if "法律解释" in text:
        return "legal_interpretation"
    if "司法解释" in text:
        return "judicial_interpretation"
    if "行政法规" in text:
        return "administrative_regulation"
    if "监察法规" in text:
        return "supervision_regulation"
    if "地方" in text and "法规" in text:
        return "local_regulation"
    if "自治条例" in text or "单行条例" in text:
        return "autonomous_regulation"
    if "经济特区" in text or "浦东新区" in text or "自由贸易港" in text:
        return "special_zone_regulation"
    if "修改" in text or "废止" in text or "决定" in text:
        return "decision"
    if "法律" in text:
        return "law"
    return "legal_document"


def effectiveness_level(document_type: str) -> str:
    mapping = {
        "constitution": "constitution",
        "law": "national_law",
        "legal_interpretation": "national_law",
        "administrative_regulation": "administrative_regulation",
        "supervision_regulation": "supervision_regulation",
        "judicial_interpretation": "judicial_interpretation",
        "department_rule": "department_rule",
        "local_government_rule": "local_government_rule",
    }
    return mapping.get(document_type, document_type)


def authority_id(name: str, source: str) -> str:
    return stable_id(source, name, prefix="auth-")


def upsert_authority(connection: sqlite3.Connection, name: str, authority_type: str) -> str:
    clean_name = clean_title(name) or "未知制定机关"
    row_id = authority_id(clean_name, authority_type)
    connection.execute(
        """
        INSERT INTO issuing_authorities (id, name, authority_type, country_region)
        VALUES (?, ?, ?, 'CN')
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          authority_type = excluded.authority_type
        """,
        (row_id, clean_name, authority_type),
    )
    return row_id


def add_aliases(connection: sqlite3.Connection, document_id: str, title: str) -> None:
    aliases = {title.strip()}
    if title.startswith("中华人民共和国"):
        aliases.add(title.removeprefix("中华人民共和国"))
    if title.endswith("（修订）"):
        aliases.add(title.removesuffix("（修订）"))
    for alias in sorted(a for a in aliases if a):
        connection.execute(
            """
            INSERT OR IGNORE INTO law_aliases (id, document_id, alias, normalized_alias)
            VALUES (?, ?, ?, ?)
            """,
            (stable_id(document_id, alias, prefix="alias-"), document_id, alias, alias),
        )


def upsert_document(
    connection: sqlite3.Connection,
    *,
    document_id: str,
    title: str,
    document_type: str,
    authority_name: str,
    authority_type: str,
    jurisdiction: str,
    status: str,
    promulgated_on: str | None,
    source_url: str | None,
    summary: str,
    source_system_id: str,
    source_external_id: str,
    source_record_id: str | None,
    raw_status: str | None,
    raw_category_code: str | None,
    raw_category_name: str | None,
) -> None:
    auth_id = upsert_authority(connection, authority_name, authority_type)
    connection.execute(
        """
        INSERT INTO law_documents (
          id, title, title_pinyin, document_type, authority_id, jurisdiction,
          effectiveness_level, status, promulgated_on, source_url, summary,
          source_system_id, source_external_id, source_record_id, raw_status,
          raw_category_code, raw_category_name
        )
        VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          title = excluded.title,
          document_type = excluded.document_type,
          authority_id = excluded.authority_id,
          jurisdiction = excluded.jurisdiction,
          effectiveness_level = excluded.effectiveness_level,
          status = excluded.status,
          promulgated_on = excluded.promulgated_on,
          source_url = excluded.source_url,
          summary = excluded.summary,
          source_system_id = excluded.source_system_id,
          source_external_id = excluded.source_external_id,
          source_record_id = excluded.source_record_id,
          raw_status = excluded.raw_status,
          raw_category_code = excluded.raw_category_code,
          raw_category_name = excluded.raw_category_name
        """,
        (
            document_id,
            title,
            document_type,
            auth_id,
            jurisdiction,
            effectiveness_level(document_type),
            status,
            promulgated_on,
            source_url,
            summary,
            source_system_id,
            source_external_id,
            source_record_id,
            raw_status,
            raw_category_code,
            raw_category_name,
        ),
    )
    add_aliases(connection, document_id, title)


def upsert_version(
    connection: sqlite3.Connection,
    *,
    version_id: str,
    document_id: str,
    version_label: str,
    status: str,
    effective_from: str | None,
    effective_to: str | None,
    published_on: str | None,
    source_reference: str,
) -> None:
    connection.execute(
        """
        INSERT INTO law_versions (
          id, document_id, version_label, status, effective_from, effective_to,
          published_on, source_reference
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          version_label = excluded.version_label,
          status = excluded.status,
          effective_from = excluded.effective_from,
          effective_to = excluded.effective_to,
          published_on = excluded.published_on,
          source_reference = excluded.source_reference
        """,
        (
            version_id,
            document_id,
            version_label,
            status,
            effective_from or published_on or "0001-01-01",
            effective_to,
            published_on,
            source_reference,
        ),
    )


def insert_articles(
    connection: sqlite3.Connection,
    *,
    document_id: str,
    version_id: str,
    title: str,
    text: str,
    updated_on: str,
) -> int:
    connection.execute("DELETE FROM citation_metadata WHERE article_id IN (SELECT id FROM law_articles WHERE version_id = ?)", (version_id,))
    connection.execute("DELETE FROM law_articles WHERE version_id = ?", (version_id,))
    count = 0
    seen_numbers: dict[str, int] = {}
    title_key = compact_article_text(title)
    for article_number, order, article_title, content in parse_articles(text):
        if order == 0 and title_key and compact_article_text(content) == title_key:
            continue
        seen_numbers[article_number] = seen_numbers.get(article_number, 0) + 1
        stored_article_number = article_number
        if seen_numbers[article_number] > 1:
            stored_article_number = f"{article_number}-{seen_numbers[article_number]}"
        article_id = stable_id(version_id, stored_article_number, order, prefix="art-")
        connection.execute(
            """
            INSERT INTO law_articles (
              id, document_id, version_id, article_number, article_order, title, content, updated_on
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (article_id, document_id, version_id, stored_article_number, order, article_title, content, updated_on),
        )
        citation = f"《{title}》{article_number}"
        if stored_article_number != article_number:
            citation = f"{citation}（重复条号#{seen_numbers[article_number]}）"
        connection.execute(
            """
            INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label)
            VALUES (?, ?, ?, ?)
            """,
            (
                stable_id(article_id, "citation", prefix="cite-"),
                article_id,
                f"law:{document_id}:{version_id}:art:{order}",
                citation,
            ),
        )
        count += 1
    return count


def insert_flk_categories(connection: sqlite3.Connection, source_system_id: str, category_type: str, node: dict[str, Any], parent_id: str | None = None) -> None:
    name = node.get("name") or "root"
    external_code = str(node.get("codeId")) if node.get("codeId") is not None else None
    row_id = stable_id(source_system_id, category_type, parent_id, external_code, name, prefix="cat-")
    connection.execute(
        """
        INSERT OR REPLACE INTO source_categories
          (id, source_system_id, parent_id, external_code, name, category_type, level, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row_id,
            source_system_id,
            parent_id,
            external_code,
            name,
            category_type,
            int(node.get("level") or 0),
            json_dumps(node),
        ),
    )
    for child in node.get("children") or []:
        insert_flk_categories(connection, source_system_id, category_type, child, row_id)


def get_flk_text(options: BuildOptions, bbbs: str, detail_data: dict[str, Any]) -> tuple[str, bool, str | None]:
    content = flk_detail_content_text(detail_data)
    if content:
        return content, True, None
    if options.metadata_only:
        return "", False, None

    fallback_text, fallback_path = get_flk_fallback_text(options, bbbs)
    if fallback_text:
        return fallback_text, True, fallback_path

    if flk_missing_text_path(options, bbbs).exists():
        return "", False, None

    cached_docx = flk_document_path(options, bbbs)
    if cached_docx.exists():
        text = document_text(cached_docx)
        if text:
            return text, True, str(cached_docx.relative_to(ROOT))

    cached_doc = flk_document_path(options, bbbs, "doc")
    if cached_doc.exists():
        text = document_text(cached_doc)
        if text:
            return text, True, str(cached_doc.relative_to(ROOT))

    cached_pdf = flk_document_path(options, bbbs, "pdf")
    if cached_pdf.exists():
        text = document_text(cached_pdf)
        if text:
            return text, True, str(cached_pdf.relative_to(ROOT))

    for requested_format in ("docx", "pdf"):
        refreshed = False
        while True:
            try:
                link_json = fetch_flk_download_link(options, bbbs, requested_format, refresh=refreshed)
            except WafChallengeError:
                raise
            except Exception as error:
                print(f"{requested_format} download link failed for FLK {bbbs}: {error}")
                break

            url = ((link_json.get("data") or {}).get("url") or "").strip()
            if not url:
                break
            if signed_url_expired(url) and not refreshed:
                refreshed = True
                continue

            parsed_path = urllib.parse.urlparse(url).path
            file_format = Path(parsed_path).suffix.lower().lstrip(".") or requested_format
            if file_format not in {"docx", "doc", "pdf"}:
                file_format = requested_format
            output = flk_document_path(options, bbbs, file_format)
            if download_file(url, output, retries=2, overwrite=refreshed):
                text = document_text(output)
                if text:
                    return text, True, str(output.relative_to(ROOT))
            if refreshed:
                break
            refreshed = True

    return "", False, None


def insert_flk_detail(
    connection: sqlite3.Connection,
    options: BuildOptions,
    row: dict[str, Any],
    detail_json: dict[str, Any],
    text_info: tuple[str, bool, str | None] | None = None,
) -> dict[str, Any]:
    detail = detail_json.get("data") or {}
    bbbs = row["bbbs"]
    source_url = source_url_for_flk(bbbs)
    source_record_id = insert_source_record(
        connection,
        source_system_id=FLK_SOURCE_ID,
        external_id=bbbs,
        record_type="detail",
        source_url=source_url,
        raw_json=detail_json,
    )
    title = clean_title(detail.get("title") or row.get("title"))
    category = clean_title(detail.get("flxz") or row.get("flxz"))
    doc_type = flk_document_type(category, title)
    status = flk_status(detail.get("sxx", row.get("sxx")))
    promulgated_on = detail.get("gbrq") or row.get("gbrq")
    effective_from = detail.get("sxrq") or row.get("sxrq") or promulgated_on
    authority = clean_title(detail.get("zdjgName") or row.get("zdjgName"))
    summary = f"{category or doc_type}；制定机关：{authority or '未知'}；公布日期：{promulgated_on or '未知'}。"
    document_id = f"flk-{bbbs}"
    version_id = f"flk-version-{bbbs}"
    upsert_document(
        connection,
        document_id=document_id,
        title=title or bbbs,
        document_type=doc_type,
        authority_name=authority,
        authority_type="state_authority",
        jurisdiction="CN",
        status=status,
        promulgated_on=promulgated_on,
        source_url=source_url,
        summary=summary,
        source_system_id=FLK_SOURCE_ID,
        source_external_id=bbbs,
        source_record_id=source_record_id,
        raw_status=str(detail.get("sxx", row.get("sxx"))),
        raw_category_code=str(row.get("flfgCodeId")) if row.get("flfgCodeId") is not None else None,
        raw_category_name=category,
    )
    upsert_version(
        connection,
        version_id=version_id,
        document_id=document_id,
        version_label=f"{promulgated_on or effective_from or '未知日期'}公布版本",
        status=status,
        effective_from=effective_from,
        effective_to=None,
        published_on=promulgated_on,
        source_reference="国家法律法规数据库",
    )

    if text_info is None:
        text, has_text, storage_path = get_flk_text(options, bbbs, detail)
    else:
        text, has_text, storage_path = text_info
    article_count = 0
    if text:
        insert_source_record(
            connection,
            source_system_id=FLK_SOURCE_ID,
            external_id=bbbs,
            record_type="text",
            source_url=source_url,
            raw_text=text,
        )
        article_count = insert_articles(
            connection,
            document_id=document_id,
            version_id=version_id,
            title=title or bbbs,
            text=text,
            updated_on=now_iso()[:10],
        )
    elif options.metadata_only:
        article_count = insert_articles(
            connection,
            document_id=document_id,
            version_id=version_id,
            title=title or bbbs,
            text=title or bbbs,
            updated_on=now_iso()[:10],
        )

    oss_file = detail.get("ossFile") or {}
    if storage_path or oss_file:
        connection.execute(
            """
            INSERT OR REPLACE INTO legal_attachments
              (id, document_id, source_system_id, external_id, title, attachment_type, file_type, source_url, storage_path, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_id(document_id, "main-docx", prefix="att-"),
                document_id,
                FLK_SOURCE_ID,
                bbbs,
                title or bbbs,
                "main_text",
                Path(storage_path).suffix.lstrip(".") if storage_path else "docx",
                source_url,
                storage_path,
                json_dumps(oss_file),
            ),
        )

    for item in detail.get("xgzl") or []:
        file_id = item.get("fileId")
        if not file_id:
            continue
        connection.execute(
            """
            INSERT OR REPLACE INTO legal_attachments
              (id, document_id, source_system_id, external_id, title, attachment_type, file_type, source_url, storage_path, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                stable_id(document_id, file_id, "related", prefix="att-"),
                document_id,
                FLK_SOURCE_ID,
                file_id,
                clean_title(item.get("title")) or file_id,
                clean_title(item.get("busiType")) or "related_material",
                item.get("fileType"),
                source_url,
                json_dumps(item),
            ),
        )

    write_ingestion_audit(
        connection,
        source_system_id=FLK_SOURCE_ID,
        external_id=bbbs,
        source_scope="all_official_records",
        source_url=source_url,
        index_status="succeeded",
        detail_status="succeeded",
        text_status="succeeded" if has_text else "missing",
        article_status="succeeded" if article_count > 0 else "missing",
        relation_status="pending",
        checksum=sha256_text(json_dumps(detail_json) + coerce_text(text)),
        last_error=None if has_text else "official text not fetched or empty",
    )

    return {
        "document_id": document_id,
        "bbbs": bbbs,
        "title": title,
        "has_text": has_text,
        "article_count": article_count,
        "history": detail.get("lsyg") or [],
        "amendments": detail.get("xgwj") or [],
    }


def insert_flk_list_document(connection: sqlite3.Connection, row: dict[str, Any]) -> dict[str, Any]:
    bbbs = row["bbbs"]
    source_url = source_url_for_flk(bbbs)
    source_record_id = stable_id(FLK_SOURCE_ID, bbbs, "list_row", prefix="src-")
    title = clean_title(row.get("title")) or bbbs
    category = clean_title(row.get("flxz"))
    doc_type = flk_document_type(category, title)
    status = flk_status(row.get("sxx"))
    promulgated_on = row.get("gbrq")
    effective_from = row.get("sxrq") or promulgated_on
    authority = clean_title(row.get("zdjgName"))
    document_id = f"flk-{bbbs}"
    version_id = f"flk-version-{bbbs}"
    summary = f"{category or doc_type}；制定机关：{authority or '未知'}；公布日期：{promulgated_on or '未知'}。"
    upsert_document(
        connection,
        document_id=document_id,
        title=title,
        document_type=doc_type,
        authority_name=authority,
        authority_type="state_authority",
        jurisdiction="CN",
        status=status,
        promulgated_on=promulgated_on,
        source_url=source_url,
        summary=summary,
        source_system_id=FLK_SOURCE_ID,
        source_external_id=bbbs,
        source_record_id=source_record_id,
        raw_status=str(row.get("sxx")),
        raw_category_code=str(row.get("flfgCodeId")) if row.get("flfgCodeId") is not None else None,
        raw_category_name=category,
    )
    upsert_version(
        connection,
        version_id=version_id,
        document_id=document_id,
        version_label=f"{promulgated_on or effective_from or '未知日期'}列表版本",
        status=status,
        effective_from=effective_from,
        effective_to=None,
        published_on=promulgated_on,
        source_reference="国家法律法规数据库列表",
    )
    article_count = insert_articles(
        connection,
        document_id=document_id,
        version_id=version_id,
        title=title,
        text=f"{title}\n{summary}",
        updated_on=now_iso()[:10],
    )
    write_ingestion_audit(
        connection,
        source_system_id=FLK_SOURCE_ID,
        external_id=bbbs,
        source_scope="all_official_records",
        source_url=source_url,
        index_status="succeeded",
        detail_status="skipped_metadata_only",
        text_status="skipped_metadata_only",
        article_status="placeholder_metadata_only",
        relation_status="skipped_metadata_only",
        checksum=None,
        last_error="metadata-only build",
    )
    return {
        "document_id": document_id,
        "bbbs": bbbs,
        "title": title,
        "has_text": False,
        "article_count": article_count,
        "history": [],
        "amendments": [],
    }


def insert_relation_if_target_exists(
    connection: sqlite3.Connection,
    *,
    from_document_id: str,
    to_document_id: str,
    relation_type: str,
    description: str,
    source_reference: str,
) -> bool:
    if from_document_id == to_document_id:
        return False
    exists = connection.execute(
        "SELECT COUNT(*) FROM law_documents WHERE id IN (?, ?)",
        (from_document_id, to_document_id),
    ).fetchone()[0]
    if exists != 2:
        return False
    connection.execute(
        """
        INSERT OR IGNORE INTO law_relations
          (id, from_document_id, to_document_id, relation_type, description, source_reference)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            stable_id(from_document_id, to_document_id, relation_type, prefix="rel-"),
            from_document_id,
            to_document_id,
            relation_type,
            description,
            source_reference,
        ),
    )
    return True


def amendment_relation_types(item: dict[str, Any]) -> tuple[str, str]:
    title = clean_title(item.get("title"))
    if "废止" in title:
        return "repealed_by", "repeals"
    return "amended_by", "amends"


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
          law_articles.rowid,
          law_articles.id,
          law_articles.document_id,
          law_articles.version_id,
          law_documents.title,
          law_articles.article_number,
          COALESCE(law_articles.title, ''),
          law_articles.content
        FROM law_articles
        JOIN law_documents ON law_documents.id = law_articles.document_id
        """
    )
    connection.execute("INSERT INTO law_articles_fts(law_articles_fts) VALUES('optimize')")


def insert_coverage(
    connection: sqlite3.Connection,
    *,
    source_system_id: str,
    scope: str,
    expected_total: int | None,
    fetched_total: int,
    detail_fetched_total: int,
    text_fetched_total: int,
    status: str,
    notes: str,
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO coverage_audit (
          id, source_system_id, scope, expected_total, fetched_total,
          detail_fetched_total, text_fetched_total, status, checked_at, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            stable_id(source_system_id, scope, prefix="cov-"),
            source_system_id,
            scope,
            expected_total,
            fetched_total,
            detail_fetched_total,
            text_fetched_total,
            status,
            now_iso(),
            notes,
        ),
    )


def build_flk(connection: sqlite3.Connection, options: BuildOptions) -> dict[str, Any]:
    print("Fetching FLK enum data")
    state = open_state_db(options)
    enum_path = options.cache_dir / "flk" / "enumData.json"
    enum_json = read_or_fetch_json(
        enum_path,
        lambda: request_json(FLK_BASE + "/law-search/search/enumData", headers=flk_headers()),
        refresh=options.refresh_index,
    )
    insert_source_record(
        connection,
        source_system_id=FLK_SOURCE_ID,
        external_id="enumData",
        record_type="enum",
        source_url=FLK_BASE,
        raw_json=enum_json,
    )
    enum_data = enum_json.get("data") or {}
    if enum_data.get("flfgfl"):
        insert_flk_categories(connection, FLK_SOURCE_ID, "legal_category", enum_data["flfgfl"])
    if enum_data.get("zdjgfl"):
        insert_flk_categories(connection, FLK_SOURCE_ID, "authority_category", enum_data["zdjgfl"])

    first = fetch_flk_page(options, 1)
    expected_total = int(first.get("total") or 0)
    page_count = (expected_total + options.page_size - 1) // options.page_size
    if options.limit is not None:
        page_count = min(page_count, (options.limit + options.page_size - 1) // options.page_size)
    rows: list[dict[str, Any]] = []
    for page_no in range(1, page_count + 1):
        page = first if page_no == 1 else fetch_flk_page(options, page_no)
        page_rows = page.get("rows") or []
        rows.extend(page_rows)
        print(f"FLK list page {page_no}/{page_count}: rows={len(rows)} expected={expected_total}")
        if options.limit is not None and len(rows) >= options.limit:
            rows = rows[: options.limit]
            break
        if options.refresh_index:
            rate_limit(options)

    raw_fetched_total = len(rows)
    unique_rows: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("bbbs"):
            unique_rows[row["bbbs"]] = row
            insert_source_record(
                connection,
                source_system_id=FLK_SOURCE_ID,
                external_id=row["bbbs"],
                record_type="list_row",
                source_url=source_url_for_flk(row["bbbs"]),
                raw_json=row,
            )
            mark_job(
                state,
                source_system_id=FLK_SOURCE_ID,
                external_id=row["bbbs"],
                source_scope="all_official_records",
                source_url=source_url_for_flk(row["bbbs"]),
                index_status="succeeded",
                checksum=sha256_text(json_dumps(row)),
            )
    rows = list(unique_rows.values())
    state.commit()

    if options.metadata_only:
        for index, row in enumerate(rows, start=1):
            insert_flk_list_document(connection, row)
            if index % 1000 == 0:
                connection.commit()
                print(f"FLK metadata documents {index}/{len(rows)}")
        duplicate_count = raw_fetched_total - len(rows)
        status = "metadata_complete"
        notes = (
            "Official FLK list total matched fetched raw rows; "
            f"{duplicate_count} duplicate bbbs rows collapsed to {len(rows)} unique documents; "
            "detail/text stage intentionally skipped."
        )
        if options.limit is not None:
            status = "partial"
            notes = f"Limited metadata build: fetched {raw_fetched_total} rows from official total {expected_total}."
        elif raw_fetched_total != expected_total:
            status = "incomplete"
            notes = f"Official total {expected_total}, fetched raw rows {raw_fetched_total}, unique rows {len(rows)}."
        insert_coverage(
            connection,
            source_system_id=FLK_SOURCE_ID,
            scope="all_official_records",
            expected_total=expected_total,
            fetched_total=raw_fetched_total,
            detail_fetched_total=0,
            text_fetched_total=0,
            status=status,
            notes=notes,
        )
        report = {
            "source": FLK_SOURCE_ID,
            "expected_total": expected_total,
            "fetched_total": raw_fetched_total,
            "unique_document_total": len(rows),
            "duplicate_row_total": duplicate_count,
            "detail_fetched_total": 0,
            "text_fetched_total": 0,
            "status": status,
            "notes": notes,
        }
        state.commit()
        state.close()
        return report

    detail_results: list[dict[str, Any]] = []
    detail_fetched = 0
    text_fetched = 0
    relation_seed: list[dict[str, Any]] = []
    blocked_error: str | None = None

    def fetch_detail(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, tuple[str, bool, str | None] | None, str | None, bool]:
        bbbs = row["bbbs"]
        network_used = not flk_detail_path(options, bbbs).exists()
        try:
            detail_json = fetch_flk_detail(options, bbbs)
            network_used = network_used or flk_text_needs_network(options, bbbs, detail_json.get("data") or {})
            text_info = get_flk_text(options, bbbs, detail_json.get("data") or {})
            return row, detail_json, text_info, None, network_used
        except WafChallengeError as error:
            return row, None, None, f"blocked_waf_js_challenge: {error}", True
        except Exception as error:
            return row, None, None, str(error), network_used

    executor: concurrent.futures.ThreadPoolExecutor | None = None
    if options.workers == 1 or options.stop_on_waf:
        detail_iter = (fetch_detail(row) for row in rows)
    else:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=options.workers)
        futures = [executor.submit(fetch_detail, row) for row in rows]
        detail_iter = (future.result() for future in concurrent.futures.as_completed(futures))

    for index, (row, detail_json, text_info, error, network_used) in enumerate(detail_iter, start=1):
        bbbs = row.get("bbbs") or ""
        source_url = source_url_for_flk(bbbs)
        if error or detail_json is None:
            is_waf = bool(error and error.startswith("blocked_waf_js_challenge"))
            print(f"FLK detail failed {bbbs}: {error}")
            mark_job(
                state,
                source_system_id=FLK_SOURCE_ID,
                external_id=bbbs,
                source_scope="all_official_records",
                source_url=source_url,
                detail_status="blocked" if is_waf else "failed",
                text_status="blocked" if is_waf else "failed",
                article_status="blocked" if is_waf else "missing",
                relation_status="blocked" if is_waf else "pending",
                last_error=error,
                increment_attempts=True,
            )
            write_ingestion_audit(
                connection,
                source_system_id=FLK_SOURCE_ID,
                external_id=bbbs,
                source_scope="all_official_records",
                source_url=source_url,
                index_status="succeeded",
                detail_status="blocked" if is_waf else "failed",
                text_status="blocked" if is_waf else "failed",
                article_status="blocked" if is_waf else "missing",
                relation_status="blocked" if is_waf else "pending",
                attempts=1,
                checksum=sha256_text(json_dumps(row)),
                last_error=error,
            )
            if is_waf and options.stop_on_waf:
                blocked_error = error
                break
            continue
        try:
            result = insert_flk_detail(connection, options, row, detail_json, text_info)
            detail_results.append(result)
            relation_seed.append(result)
            detail_fetched += 1
            text_fetched += 1 if result["has_text"] else 0
            mark_job(
                state,
                source_system_id=FLK_SOURCE_ID,
                external_id=bbbs,
                source_scope="all_official_records",
                source_url=source_url,
                detail_status="succeeded",
                text_status="succeeded" if result["has_text"] else "missing",
                article_status="succeeded" if result["article_count"] > 0 else "missing",
                relation_status="pending",
                checksum=sha256_text(json_dumps(detail_json) + (coerce_text(text_info[0]) if text_info else "")),
                increment_attempts=True,
            )
        except Exception as insert_error:
            print(f"FLK insert failed {bbbs}: {insert_error}")
            mark_job(
                state,
                source_system_id=FLK_SOURCE_ID,
                external_id=bbbs,
                source_scope="all_official_records",
                source_url=source_url,
                detail_status="failed",
                text_status="failed",
                article_status="failed",
                relation_status="pending",
                last_error=str(insert_error),
                increment_attempts=True,
            )
            continue
        if index % 100 == 0:
            connection.commit()
            state.commit()
            print(f"FLK details {index}/{len(rows)} text={text_fetched}")
        if network_used:
            if options.refresh_index:
                rate_limit(options)
    if executor is not None:
        executor.shutdown(wait=True)

    for result in relation_seed:
        from_document_id = result["document_id"]
        for history in result["history"]:
            target_bbbs = history.get("bbbs")
            if not target_bbbs:
                continue
            target_document_id = f"flk-{target_bbbs}"
            insert_relation_if_target_exists(
                connection,
                from_document_id=from_document_id,
                to_document_id=target_document_id,
                relation_type="history_version",
                description=f"同一标题历史版本：{clean_title(history.get('title')) or target_bbbs}",
                source_reference="国家法律法规数据库 lsyg",
            )
        for amendment in result["amendments"]:
            target_bbbs = amendment.get("bbbs")
            if not target_bbbs:
                continue
            forward_type, reverse_type = amendment_relation_types(amendment)
            insert_relation_if_target_exists(
                connection,
                from_document_id=from_document_id,
                to_document_id=f"flk-{target_bbbs}",
                relation_type=forward_type,
                description=f"相关修改、废止决定：{clean_title(amendment.get('title')) or target_bbbs}",
                source_reference="国家法律法规数据库 xgwj",
            )
            insert_relation_if_target_exists(
                connection,
                from_document_id=f"flk-{target_bbbs}",
                to_document_id=from_document_id,
                relation_type=reverse_type,
                description=f"修改、废止关联来源：{result['title'] or result['bbbs']}",
                source_reference="国家法律法规数据库 xgwj",
            )
        write_ingestion_audit(
            connection,
            source_system_id=FLK_SOURCE_ID,
            external_id=result["bbbs"],
            source_scope="all_official_records",
            source_url=source_url_for_flk(result["bbbs"]),
            index_status="succeeded",
            detail_status="succeeded",
            text_status="succeeded" if result["has_text"] else "missing",
            article_status="succeeded" if result["article_count"] > 0 else "missing",
            relation_status="succeeded",
            checksum=None,
            last_error=None if result["has_text"] else "official text not fetched or empty",
        )
        mark_job(
            state,
            source_system_id=FLK_SOURCE_ID,
            external_id=result["bbbs"],
            source_scope="all_official_records",
            source_url=source_url_for_flk(result["bbbs"]),
            relation_status="succeeded",
        )

    status = "complete"
    notes = "FLK list total matched fetched rows; detail and text counts recorded separately."
    duplicate_count = raw_fetched_total - len(rows)
    if blocked_error:
        status = "blocked"
        notes = f"FLK hydrate stopped by WAF JavaScript challenge after {detail_fetched}/{len(rows)} details: {blocked_error}"
    elif options.limit is not None:
        status = "partial"
        notes = f"Limited build: fetched {raw_fetched_total} rows from official total {expected_total}."
    elif raw_fetched_total != expected_total:
        status = "incomplete"
        notes = f"Official total {expected_total}, fetched raw rows {raw_fetched_total}, unique rows {len(rows)}."
    elif not options.metadata_only and text_fetched < len(rows):
        status = "text_incomplete"
        notes = f"Official raw total matched with {duplicate_count} duplicate rows collapsed, but text fetched for {text_fetched}/{len(rows)} unique documents."
    insert_coverage(
        connection,
        source_system_id=FLK_SOURCE_ID,
        scope="all_official_records",
        expected_total=expected_total,
        fetched_total=raw_fetched_total,
        detail_fetched_total=detail_fetched,
        text_fetched_total=text_fetched,
        status=status,
        notes=notes,
    )
    report = {
        "source": FLK_SOURCE_ID,
        "expected_total": expected_total,
        "fetched_total": raw_fetched_total,
        "unique_document_total": len(rows),
        "duplicate_row_total": duplicate_count,
        "detail_fetched_total": detail_fetched,
        "text_fetched_total": text_fetched,
        "status": status,
        "notes": notes,
    }
    state.commit()
    state.close()
    return report


def gjgzk_app_key() -> str:
    script = r"""
const crypto=require('crypto');
const publicKey=`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWGTHvPbNkzQNxTJwSZbsgHKyLl/OK11kCZNmVVSFK3lUbmHgh7Ain1gdaf7G/ETh/wQm/9BAO/U36yWPizzlwHCUcWJXBRsY10PsnYIlBXH/cjqQaEbmEghxcjdYtLtkudoMfoMDiJk+tPC7UEZd8TI2u26vttNF++6tHi1HdeQIDAQAB
-----END PUBLIC KEY-----`;
const encrypted=crypto.publicEncrypt(
  {key:publicKey,padding:crypto.constants.RSA_PKCS1_PADDING},
  Buffer.from('f8f49ea85885466598c5261f7f8607fb')
).toString('base64');
process.stdout.write(encodeURIComponent(encrypted));
"""
    return subprocess.check_output(["node", "-e", script], text=True).strip()


def gjgzk_headers(app_key: str) -> dict[str, str]:
    return {
        "Origin": "https://www.gov.cn",
        "Referer": GJGZK_BASE,
        "athenaAppKey": app_key,
        "athenaAppName": "%E8%A7%84%E7%AB%A0%E5%BA%93",
    }


def gjgzk_body(rule_class: str, page_no: int, page_size: int) -> dict[str, Any]:
    return {
        "code": "18258ab0ac9",
        "preference": "lawyer-assistance-build",
        "searchFields": [
            {"fieldName": "f_202321807875", "searchWord": rule_class, "searchType": "TERM", "withHighLight": True},
            {"fieldName": "f_202321360426", "searchWord": "", "withHighLight": True},
            {"fieldName": "f_202321758948", "searchWord": "", "withHighLight": True},
            {"fieldName": "f_202321423473", "searchType": "TERM", "searchWord": "", "withHighLight": True},
            {"fieldName": "f_202321159816", "searchWord": "", "searchType": "TERM"},
            {"fieldName": "f_20232380533", "searchType": "TERM", "searchWord": "", "withHighLight": True},
            {"fieldName": "f_202328191239", "searchWord": "", "withHighLight": True, "searchType": "TERM"},
            {"fieldName": "f_20221110222856", "searchWord": "", "withHighLight": True, "searchType": "TERM"},
        ],
        "sorts": [{}, {"sortField": "f_202321915922", "sortOrder": "DESC"}],
        "resultFields": [
            "f_202291670697",
            "f_202355832506",
            "f_20232124962",
            "f_202321124775",
            "f_202321159816",
            "f_202321360426",
            "f_202321423473",
            "f_202321758948",
            "f_202321807875",
            "f_202321864401",
            "f_202321915922",
            "f_202323394765",
            "f_202328191239",
            "f_202344311304",
            "f_2023425676953",
            "f_2023425808265",
            "f_202321136868",
            "f_20232380533",
            "f_20232151076",
            "doc_pub_url",
        ],
        "trackTotalHits": "true",
        "tableName": "t_1860c735d31",
        "pageSize": page_size,
        "pageNo": page_no,
        "granularity": "ALL",
    }


def fetch_gjgzk_page(options: BuildOptions, app_key: str, rule_class: str, page_no: int) -> dict[str, Any]:
    safe_class = "department" if rule_class == "部门规章" else "local"
    path = options.cache_dir / "gjgzk" / safe_class / f"size-{options.page_size}" / f"{page_no:05}.json"
    return read_or_fetch_json(
        path,
        lambda: request_json(
            f"{GJGZK_API_BASE}/athena/forward/{GJGZK_ATHENA_LIST}",
            method="POST",
            payload=gjgzk_body(rule_class, page_no, options.page_size),
            headers=gjgzk_headers(app_key),
        ),
        refresh=options.refresh_index,
    )


def extract_gov_article_text(markup: str) -> str:
    candidates = [
        r'<div[^>]+id=["\']UCAP-CONTENT["\'][^>]*>(.*?)</div>\s*</div>',
        r'<div[^>]+class=["\'][^"\']*pages_content[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]+class=["\'][^"\']*article[^"\']*["\'][^>]*>(.*?)</div>',
    ]
    for pattern in candidates:
        match = re.search(pattern, markup, flags=re.IGNORECASE | re.DOTALL)
        if match:
            text = strip_html(match.group(1))
            if len(text) >= 100:
                return text
    return strip_html(markup)


def fetch_gjgzk_text(options: BuildOptions, url: str) -> tuple[str, bool]:
    if not url or options.metadata_only:
        return "", False
    path = options.cache_dir / "gjgzk" / "html" / f"{stable_id(url)}.html"
    if path.exists():
        markup = path.read_text(encoding="utf-8", errors="ignore")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Referer": GJGZK_BASE, "Accept": "text/html,*/*"},
        )
        try:
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
                data = response.read()
            markup = data.decode("utf-8", errors="ignore")
            if looks_like_waf_challenge(markup):
                raise WafChallengeError(f"WAF JavaScript challenge from {url}")
            path.write_text(markup, encoding="utf-8")
        except WafChallengeError:
            raise
        except Exception as error:
            print(f"GJGZK html fetch failed {url}: {error}")
            return "", False
    text = extract_gov_article_text(markup)
    return text, bool(text)


def gjgzk_api_text(row: dict[str, Any]) -> str:
    text = strip_html(first_scalar(row.get("f_202321758948")))
    if ARTICLE_RE.search(text) or len(text) >= 200:
        return text
    return ""


def gov_url_from_row(row: dict[str, Any]) -> str:
    url = row.get("doc_pub_url")
    if isinstance(url, list) and url:
        return str(url[0])
    if isinstance(url, str) and url:
        return url
    value = row.get("f_20232124962")
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str):
        return value
    return ""


def first_scalar(value: Any) -> Any:
    if isinstance(value, list):
        for item in value:
            if item not in (None, ""):
                return item
        return None
    return value


def insert_gjgzk_row(
    connection: sqlite3.Connection,
    options: BuildOptions,
    rule_class: str,
    row: dict[str, Any],
    text_info: tuple[str, bool] | None = None,
) -> dict[str, Any]:
    url = gov_url_from_row(row)
    external_id = first_scalar(row.get("f_202291670697")) or url or stable_id(row)
    source_record_id = insert_source_record(
        connection,
        source_system_id=GJGZK_SOURCE_ID,
        external_id=str(external_id),
        record_type="list_row",
        source_url=url,
        raw_json=row,
    )
    title = clean_title(first_scalar(row.get("f_202321360426"))) or str(external_id)
    authority = clean_title(first_scalar(row.get("f_20232151076")) or first_scalar(row.get("f_202328191239")))
    if not authority:
        authority = "国务院部门" if rule_class == "部门规章" else "地方人民政府"
    published = (row.get("f_202321915922") or "").split(" ")[0] or None
    doc_type = "department_rule" if rule_class == "部门规章" else "local_government_rule"
    document_id = f"gjgzk-{stable_id(external_id, url)}"
    version_id = f"gjgzk-version-{stable_id(external_id, url)}"
    snippet = strip_html(first_scalar(row.get("f_202321758948"))) or title
    upsert_document(
        connection,
        document_id=document_id,
        title=title,
        document_type=doc_type,
        authority_name=authority,
        authority_type="administrative_authority",
        jurisdiction="CN",
        status="in_force",
        promulgated_on=published,
        source_url=url,
        summary=f"{rule_class}；制定机关：{authority}；发布日期：{published or '未知'}。",
        source_system_id=GJGZK_SOURCE_ID,
        source_external_id=str(external_id),
        source_record_id=source_record_id,
        raw_status="现行有效",
        raw_category_code=None,
        raw_category_name=rule_class,
    )
    upsert_version(
        connection,
        version_id=version_id,
        document_id=document_id,
        version_label=f"{published or '未知日期'}发布版本",
        status="in_force",
        effective_from=published,
        effective_to=None,
        published_on=published,
        source_reference="国家规章库",
    )
    if text_info is None:
        api_text = gjgzk_api_text(row)
        text, has_text = (api_text, True) if api_text else fetch_gjgzk_text(options, url)
    else:
        text, has_text = text_info
    article_count = 0
    if text:
        insert_source_record(
            connection,
            source_system_id=GJGZK_SOURCE_ID,
            external_id=str(external_id),
            record_type="text",
            source_url=url,
            raw_text=text,
        )
        article_count = insert_articles(
            connection,
            document_id=document_id,
            version_id=version_id,
            title=title,
            text=text,
            updated_on=now_iso()[:10],
        )
    elif options.metadata_only:
        text = snippet
        article_count = insert_articles(
            connection,
            document_id=document_id,
            version_id=version_id,
            title=title,
            text=text,
            updated_on=now_iso()[:10],
        )
    write_ingestion_audit(
        connection,
        source_system_id=GJGZK_SOURCE_ID,
        external_id=str(external_id),
        source_scope=rule_class,
        source_url=url,
        index_status="succeeded",
        detail_status="succeeded",
        text_status="succeeded" if has_text else "missing",
        article_status="succeeded" if article_count > 0 else "missing",
        relation_status="not_applicable",
        checksum=sha256_text(json_dumps(row) + (text or "")),
        last_error=None if has_text else "official text not fetched or empty",
    )
    return {
        "document_id": document_id,
        "external_id": external_id,
        "has_text": has_text,
        "article_count": article_count,
    }


def build_gjgzk(connection: sqlite3.Connection, options: BuildOptions) -> list[dict[str, Any]]:
    print("Fetching GJGZK rule data")
    state = open_state_db(options)
    app_key = gjgzk_app_key()
    reports: list[dict[str, Any]] = []
    for rule_class in ["部门规章", "地方政府规章"]:
        first = fetch_gjgzk_page(options, app_key, rule_class, 1)
        data = ((first.get("result") or {}).get("data") or {})
        pager = data.get("pager") or {}
        expected_total = int(pager.get("total") or 0)
        page_count = (expected_total + options.page_size - 1) // options.page_size
        if options.limit is not None:
            page_count = min(page_count, (options.limit + options.page_size - 1) // options.page_size)
        rows: list[dict[str, Any]] = []
        for page_no in range(1, page_count + 1):
            page = first if page_no == 1 else fetch_gjgzk_page(options, app_key, rule_class, page_no)
            page_data = ((page.get("result") or {}).get("data") or {})
            page_rows = page_data.get("list") or []
            rows.extend(page_rows)
            print(f"GJGZK {rule_class} page {page_no}/{page_count}: rows={len(rows)} expected={expected_total}")
            if options.limit is not None and len(rows) >= options.limit:
                rows = rows[: options.limit]
                break
            rate_limit(options)
        for row in rows:
            external_id = str(first_scalar(row.get("f_202291670697")) or gov_url_from_row(row) or stable_id(row))
            url = gov_url_from_row(row)
            mark_job(
                state,
                source_system_id=GJGZK_SOURCE_ID,
                external_id=external_id,
                source_scope=rule_class,
                source_url=url,
                index_status="succeeded",
                detail_status="succeeded",
                checksum=sha256_text(json_dumps(row)),
            )
        state.commit()

        detail_fetched = 0
        text_fetched = 0
        def prepare_row(row: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, bool], str | None, bool]:
            try:
                api_text = gjgzk_api_text(row)
                if api_text:
                    return row, (api_text, True), None, False
                return row, fetch_gjgzk_text(options, gov_url_from_row(row)), None, True
            except WafChallengeError as error:
                return row, ("", False), f"blocked_waf_js_challenge: {error}", True
            except Exception as error:
                return row, ("", False), str(error), True

        blocked_error: str | None = None
        if options.workers == 1 or options.stop_on_waf:
            prepared_rows = (prepare_row(row) for row in rows)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as executor:
                futures = [executor.submit(prepare_row, row) for row in rows]
                prepared_rows = [future.result() for future in concurrent.futures.as_completed(futures)]

        for index, (row, text_info, prepare_error, network_used) in enumerate(prepared_rows, start=1):
            external_id = str(first_scalar(row.get("f_202291670697")) or gov_url_from_row(row) or stable_id(row))
            url = gov_url_from_row(row)
            if prepare_error:
                print(f"GJGZK text fetch failed {rule_class} row {index}: {prepare_error}")
                is_waf = prepare_error.startswith("blocked_waf_js_challenge")
                mark_job(
                    state,
                    source_system_id=GJGZK_SOURCE_ID,
                    external_id=external_id,
                    source_scope=rule_class,
                    source_url=url,
                    text_status="blocked" if is_waf else "failed",
                    article_status="blocked" if is_waf else "missing",
                    relation_status="not_applicable",
                    last_error=prepare_error,
                    increment_attempts=True,
                )
                if is_waf and options.stop_on_waf:
                    blocked_error = prepare_error
                    break
            try:
                result = insert_gjgzk_row(connection, options, rule_class, row, text_info)
                detail_fetched += 1
                text_fetched += 1 if result["has_text"] else 0
                mark_job(
                    state,
                    source_system_id=GJGZK_SOURCE_ID,
                    external_id=external_id,
                    source_scope=rule_class,
                    source_url=url,
                    text_status="succeeded" if result["has_text"] else "missing",
                    article_status="succeeded" if result["article_count"] > 0 else "missing",
                    relation_status="not_applicable",
                    checksum=sha256_text(json_dumps(row) + (coerce_text(text_info[0]) if text_info else "")),
                    increment_attempts=True,
                )
            except Exception as error:
                print(f"GJGZK insert failed {rule_class} row {index}: {error}")
                mark_job(
                    state,
                    source_system_id=GJGZK_SOURCE_ID,
                    external_id=external_id,
                    source_scope=rule_class,
                    source_url=url,
                    text_status="failed",
                    article_status="failed",
                    relation_status="not_applicable",
                    last_error=str(error),
                    increment_attempts=True,
                )
            if index % 100 == 0:
                connection.commit()
                state.commit()
                print(f"GJGZK {rule_class} details {index}/{len(rows)} text={text_fetched}")
            if network_used:
                rate_limit(options)

        status = "complete"
        notes = f"{rule_class} official total matched fetched rows."
        if blocked_error:
            status = "blocked"
            notes = f"{rule_class} hydrate stopped by WAF JavaScript challenge after {detail_fetched}/{len(rows)} rows: {blocked_error}"
        elif options.limit is not None:
            status = "partial"
            notes = f"Limited build: fetched {len(rows)} rows from official total {expected_total}."
        elif len(rows) != expected_total:
            status = "incomplete"
            notes = f"Official total {expected_total}, fetched rows {len(rows)}."
        elif not options.metadata_only and text_fetched < len(rows):
            status = "text_incomplete"
            notes = f"Official total matched, but text fetched for {text_fetched}/{len(rows)} documents."
        insert_coverage(
            connection,
            source_system_id=GJGZK_SOURCE_ID,
            scope=rule_class,
            expected_total=expected_total,
            fetched_total=len(rows),
            detail_fetched_total=detail_fetched,
            text_fetched_total=text_fetched,
            status=status,
            notes=notes,
        )
        reports.append(
            {
                "source": GJGZK_SOURCE_ID,
                "scope": rule_class,
                "expected_total": expected_total,
                "fetched_total": len(rows),
                "detail_fetched_total": detail_fetched,
                "text_fetched_total": text_fetched,
                "status": status,
                "notes": notes,
            }
        )
    state.commit()
    state.close()
    return reports


def update_metadata(connection: sqlite3.Connection, report: dict[str, Any]) -> None:
    timestamp = now_iso()
    statuses = [item["status"] for item in report["coverage"]]
    if any(status == "blocked" for status in statuses):
        coverage_status = "blocked"
    elif all(status == "complete" for status in statuses):
        coverage_status = "complete"
    elif report.get("metadata_only") and all(status in {"complete", "metadata_complete"} for status in statuses):
        coverage_status = "metadata_complete"
    else:
        coverage_status = "incomplete"
    for key, value in {
        "schema_version": "4",
        "dataset_name": "official-china-legal-core",
        "build_completed_at": timestamp,
        "coverage_status": coverage_status,
        "coverage_report": json_dumps(report),
    }.items():
        connection.execute(
            """
            INSERT INTO database_metadata (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, timestamp),
        )


def count_table(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def coverage_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT source_system_id, scope, expected_total, fetched_total,
               detail_fetched_total, text_fetched_total, status, notes
        FROM coverage_audit
        ORDER BY source_system_id, scope
        """
    ).fetchall()
    return [
        {
            "source": row[0],
            "scope": row[1],
            "expected_total": row[2],
            "fetched_total": row[3],
            "detail_fetched_total": row[4],
            "text_fetched_total": row[5],
            "status": row[6],
            "notes": row[7],
        }
        for row in rows
    ]


def count_optional_table(connection: sqlite3.Connection, table: str) -> int:
    return count_table(connection, table) if table_exists(connection, table) else 0


def table_exists(connection: sqlite3.Connection, table: str) -> bool:
    exists = connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?",
        (table,),
    ).fetchone()[0]
    return bool(exists)


def text_marker_hits(connection: sqlite3.Connection) -> int:
    total = 0
    marker_patterns = [
        "%fixture\\_%",
        "%\\_fixture%",
        "%fixture data%",
        "%fixture-data%",
        "%sample\\_%",
        "%\\_sample%",
        "%sample data%",
        "%sample-data%",
        "%sample law%",
        "%sample regulation%",
        "%demo\\_%",
        "%\\_demo%",
        "%demo data%",
        "%demo-data%",
        "%demo law%",
        "%mock data%",
        "%mock law%",
        "%placeholder%",
        "%test data%",
        "%test fixture%",
        "%占位正文%",
        "%占位法条%",
        "%占位法律%",
        "%示例数据%",
        "%示例法律%",
        "%样例数据%",
        "%样例法律%",
        "%测试样例%",
        "%非真实数据%",
    ]
    checks = [
        ("law_documents", "title"),
        ("law_documents", "summary"),
        ("law_articles", "content"),
        ("source_records", "raw_json"),
        ("source_records", "raw_text"),
    ]
    marker_clause = " OR ".join([f"lower({{column}}) LIKE ? ESCAPE '\\'" for _ in marker_patterns])
    for table, column in checks:
        total += int(
            connection.execute(
                f"""
                SELECT COUNT(*) FROM {table}
                WHERE {column} IS NOT NULL
                  AND ({marker_clause.format(column=column)})
                """,
                marker_patterns,
            ).fetchone()[0]
        )
    return total


def authoritative_terminal_date_audit(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    placeholders = ",".join("?" for _ in CIVIL_CODE_REPEALED_TITLES)
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


def audit_connection(connection: sqlite3.Connection) -> dict[str, Any]:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    article_count = count_table(connection, "law_articles")
    fts_count = count_table(connection, "law_articles_fts")
    coverage = coverage_rows(connection)
    coverage_status = (
        connection.execute("SELECT value FROM database_metadata WHERE key = 'coverage_status'").fetchone() or ["incomplete"]
    )[0]
    schema_version = (
        connection.execute("SELECT value FROM database_metadata WHERE key = 'schema_version'").fetchone() or ["unknown"]
    )[0]
    has_ingestion_audit = table_exists(connection, "ingestion_audit")
    invalid_relations = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM law_relations rel
            LEFT JOIN law_documents source ON source.id = rel.from_document_id
            LEFT JOIN law_documents target ON target.id = rel.to_document_id
            WHERE source.id IS NULL OR target.id IS NULL
            """
        ).fetchone()[0]
    )
    missing_source_records = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM law_documents
            WHERE source_system_id IS NULL
               OR source_external_id IS NULL
               OR source_record_id IS NULL
            """
        ).fetchone()[0]
    )
    placeholder_articles = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM law_articles article
            JOIN law_documents document ON document.id = article.document_id
            WHERE article.content = document.title
               OR article.content = document.summary
               OR article.content = document.title || char(10) || document.summary
            """
        ).fetchone()[0]
    )
    blocked_records = 0
    failed_records = 0
    missing_text_records = 0
    missing_article_records = 0
    if has_ingestion_audit:
        blocked_records = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM ingestion_audit
                WHERE detail_status = 'blocked'
                   OR text_status = 'blocked'
                   OR article_status = 'blocked'
                   OR relation_status = 'blocked'
                """
            ).fetchone()[0]
        )
        failed_records = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM ingestion_audit
                WHERE detail_status = 'failed'
                   OR text_status = 'failed'
                   OR article_status = 'failed'
                   OR relation_status = 'failed'
                """
            ).fetchone()[0]
        )
        missing_text_records = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM ingestion_audit
                WHERE text_status IN ('missing', 'failed', 'blocked')
                """
            ).fetchone()[0]
        )
        missing_article_records = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM ingestion_audit
                WHERE article_status IN ('missing', 'failed', 'blocked')
                """
            ).fetchone()[0]
        )
    missing_dates = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM law_versions
            WHERE effective_from IS NULL OR effective_from = '0001-01-01'
            """
        ).fetchone()[0]
    )
    duplicate_source_ids = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM (
              SELECT source_system_id, source_external_id, COUNT(*) AS n
              FROM law_documents
              GROUP BY source_system_id, source_external_id
              HAVING n > 1
            )
            """
        ).fetchone()[0]
    )
    guiding_case_count = count_optional_table(connection, "guiding_cases")
    document_template_count = count_optional_table(connection, "document_templates")
    history_exception_count = count_optional_table(connection, "history_version_exceptions")
    missing_case_provenance = 0
    missing_template_provenance = 0
    if guiding_case_count:
        missing_case_provenance = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM guiding_cases
                WHERE source_system_id IS NULL OR source_external_id IS NULL
                   OR source_record_id IS NULL OR source_url = '' OR content = ''
                """
            ).fetchone()[0]
        )
    if document_template_count:
        missing_template_provenance = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM document_templates
                WHERE source_system_id IS NULL OR source_external_id IS NULL
                   OR source_record_id IS NULL OR source_url = '' OR content = ''
                """
            ).fetchone()[0]
        )
    stage_1c_status = (
        connection.execute("SELECT value FROM database_metadata WHERE key = 'stage_1c_data_status'").fetchone()
        or [None]
    )[0]
    authoritative_terminal = authoritative_terminal_date_audit(connection)
    authoritative_terminal_title_count = authoritative_terminal["title_count"]
    repealed_unknown_terminal_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM law_versions "
            "WHERE status = 'repealed' AND effective_to IS NULL"
        ).fetchone()[0]
    )
    historical_unknown_end_policy = (
        connection.execute(
            "SELECT value FROM database_metadata "
            "WHERE key = 'historical_unknown_end_policy'"
        ).fetchone()
        or [None]
    )[0]
    failures: list[str] = []
    if integrity != "ok":
        failures.append(f"sqlite_integrity:{integrity}")
    if foreign_keys:
        failures.append(f"foreign_key_errors:{len(foreign_keys)}")
    if fts_count != article_count:
        failures.append(f"fts_mismatch:{fts_count}!={article_count}")
    if coverage_status != "complete":
        failures.append(f"coverage_status:{coverage_status}")
    if schema_version != "4":
        failures.append(f"schema_version:{schema_version}")
    if not has_ingestion_audit:
        failures.append("missing_ingestion_audit_table")
    if any(item["status"] != "complete" for item in coverage):
        failures.append("coverage_audit_not_complete")
    if invalid_relations:
        failures.append(f"invalid_relation_endpoints:{invalid_relations}")
    if missing_source_records:
        failures.append(f"missing_source_records:{missing_source_records}")
    if placeholder_articles:
        failures.append(f"placeholder_articles:{placeholder_articles}")
    if blocked_records:
        failures.append(f"blocked_records:{blocked_records}")
    if failed_records:
        failures.append(f"failed_records:{failed_records}")
    if missing_text_records:
        failures.append(f"missing_text_records:{missing_text_records}")
    if missing_article_records:
        failures.append(f"missing_article_records:{missing_article_records}")
    fixture_hits = text_marker_hits(connection)
    if fixture_hits:
        failures.append(f"fixture_demo_marker_hits:{fixture_hits}")
    if duplicate_source_ids:
        failures.append(f"duplicate_source_ids:{duplicate_source_ids}")
    if stage_1c_status:
        if not guiding_case_count:
            failures.append("stage_1c_missing_guiding_cases")
        if not document_template_count:
            failures.append("stage_1c_missing_document_templates")
        if not history_exception_count:
            failures.append("stage_1c_missing_history_exception_audit")
        if missing_case_provenance:
            failures.append(f"missing_case_provenance:{missing_case_provenance}")
        if missing_template_provenance:
            failures.append(f"missing_template_provenance:{missing_template_provenance}")
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
        if (
            repealed_unknown_terminal_count
            and historical_unknown_end_policy != HISTORICAL_UNKNOWN_END_POLICY
        ):
            failures.append(
                "historical_unknown_end_policy:"
                f"{historical_unknown_end_policy}!={HISTORICAL_UNKNOWN_END_POLICY}"
            )
    return {
        "audit_status": "complete" if not failures else "failed",
        "coverage_status": coverage_status,
        "schema_version": schema_version,
        "failures": failures,
        "sqlite_integrity": integrity,
        "foreign_key_errors": len(foreign_keys),
        "article_count": article_count,
        "fts_count": fts_count,
        "invalid_relation_endpoints": invalid_relations,
        "missing_source_records": missing_source_records,
        "placeholder_article_count": placeholder_articles,
        "blocked_record_count": blocked_records,
        "failed_record_count": failed_records,
        "missing_text_record_count": missing_text_records,
        "missing_article_record_count": missing_article_records,
        "missing_date_count": missing_dates,
        "duplicate_source_id_count": duplicate_source_ids,
        "fixture_demo_marker_hits": fixture_hits,
        "guiding_case_count": guiding_case_count,
        "document_template_count": document_template_count,
        "history_version_exception_count": history_exception_count,
        "missing_case_provenance": missing_case_provenance,
        "missing_template_provenance": missing_template_provenance,
        "stage_1c_data_status": stage_1c_status,
        "authoritative_terminal_title_count": authoritative_terminal_title_count,
        "authoritative_terminal_version_count": authoritative_terminal["version_count"],
        "authoritative_terminal_violation_count": authoritative_terminal["violation_count"],
        "authoritative_terminal_missing_article_count": authoritative_terminal[
            "missing_article_count"
        ],
        "repealed_unknown_terminal_count": repealed_unknown_terminal_count,
        "historical_unknown_end_policy": historical_unknown_end_policy,
    }


def build_report_from_connection(connection: sqlite3.Connection, options: BuildOptions, coverage: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "built_at": now_iso(),
        "output": str(options.output),
        "stage": options.stage,
        "metadata_only": options.metadata_only,
        "limit": options.limit,
        "coverage": coverage,
        "counts": {
            "law_documents": count_table(connection, "law_documents"),
            "law_versions": count_table(connection, "law_versions"),
            "law_articles": count_table(connection, "law_articles"),
            "law_relations": count_table(connection, "law_relations"),
            "law_articles_fts": count_table(connection, "law_articles_fts"),
            "source_records": count_table(connection, "source_records"),
            "legal_attachments": count_table(connection, "legal_attachments"),
            "ingestion_audit": count_optional_table(connection, "ingestion_audit"),
            "guiding_cases": count_optional_table(connection, "guiding_cases"),
            "document_templates": count_optional_table(connection, "document_templates"),
            "history_version_exceptions": count_optional_table(connection, "history_version_exceptions"),
        },
    }


def audit_existing_database(options: BuildOptions) -> int:
    if not options.output.exists():
        raise FileNotFoundError(f"database not found: {options.output}")
    connection = sqlite3.connect(options.output)
    try:
        report = build_report_from_connection(connection, options, coverage_rows(connection))
        report["audit"] = audit_connection(connection)
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if options.strict and report["audit"]["audit_status"] != "complete":
            raise RuntimeError(f"strict audit failed: {report['audit']['failures']}")
        return 0
    finally:
        connection.close()


def load_flk_list_rows(options: BuildOptions) -> tuple[int, int, list[dict[str, Any]], int]:
    first = fetch_flk_page(options, 1)
    expected_total = int(first.get("total") or 0)
    page_count = (expected_total + options.page_size - 1) // options.page_size
    if options.limit is not None:
        page_count = min(page_count, (options.limit + options.page_size - 1) // options.page_size)
    rows: list[dict[str, Any]] = []
    for page_no in range(1, page_count + 1):
        page = first if page_no == 1 else fetch_flk_page(options, page_no)
        rows.extend(page.get("rows") or [])
        if options.limit is not None and len(rows) >= options.limit:
            rows = rows[: options.limit]
            break
        if options.refresh_index:
            rate_limit(options)
    raw_total = len(rows)
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("bbbs"):
            unique[row["bbbs"]] = row
    return expected_total, raw_total, list(unique.values()), raw_total - len(unique)


def load_gjgzk_rows(options: BuildOptions, rule_class: str) -> tuple[int, list[dict[str, Any]]]:
    app_key = gjgzk_app_key()
    first = fetch_gjgzk_page(options, app_key, rule_class, 1)
    data = ((first.get("result") or {}).get("data") or {})
    pager = data.get("pager") or {}
    expected_total = int(pager.get("total") or 0)
    page_count = (expected_total + options.page_size - 1) // options.page_size
    if options.limit is not None:
        page_count = min(page_count, (options.limit + options.page_size - 1) // options.page_size)
    rows: list[dict[str, Any]] = []
    for page_no in range(1, page_count + 1):
        page = first if page_no == 1 else fetch_gjgzk_page(options, app_key, rule_class, page_no)
        page_data = ((page.get("result") or {}).get("data") or {})
        rows.extend(page_data.get("list") or [])
        if options.limit is not None and len(rows) >= options.limit:
            rows = rows[: options.limit]
            break
        if options.refresh_index:
            rate_limit(options)
    return expected_total, rows


def run_index_stage(options: BuildOptions) -> int:
    state = open_state_db(options)
    try:
        report: dict[str, Any] = {"stage": "index", "built_at": now_iso(), "coverage": []}
        if options.source in {"all", "flk"}:
            expected, raw_total, rows, duplicates = load_flk_list_rows(options)
            for row in rows:
                mark_job(
                    state,
                    source_system_id=FLK_SOURCE_ID,
                    external_id=row["bbbs"],
                    source_scope="all_official_records",
                    source_url=source_url_for_flk(row["bbbs"]),
                    index_status="succeeded",
                    checksum=sha256_text(json_dumps(row)),
                )
            report["coverage"].append(
                {
                    "source": FLK_SOURCE_ID,
                    "expected_total": expected,
                    "fetched_total": raw_total,
                    "unique_document_total": len(rows),
                    "duplicate_row_total": duplicates,
                    "status": "indexed" if options.limit is None and raw_total == expected else "partial",
                }
            )
        if options.source in {"all", "rules"}:
            for rule_class in ["部门规章", "地方政府规章"]:
                expected, rows = load_gjgzk_rows(options, rule_class)
                for row in rows:
                    external_id = str(first_scalar(row.get("f_202291670697")) or gov_url_from_row(row) or stable_id(row))
                    mark_job(
                        state,
                        source_system_id=GJGZK_SOURCE_ID,
                        external_id=external_id,
                        source_scope=rule_class,
                        source_url=gov_url_from_row(row),
                        index_status="succeeded",
                        detail_status="succeeded",
                        checksum=sha256_text(json_dumps(row)),
                    )
                report["coverage"].append(
                    {
                        "source": GJGZK_SOURCE_ID,
                        "scope": rule_class,
                        "expected_total": expected,
                        "fetched_total": len(rows),
                        "status": "indexed" if options.limit is None and len(rows) == expected else "partial",
                    }
                )
        state.commit()
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    finally:
        state.close()


def run_hydrate_stage(options: BuildOptions) -> int:
    state = open_state_db(options)
    blocked = False
    report: dict[str, Any] = {"stage": "hydrate", "built_at": now_iso(), "coverage": []}
    try:
        if options.source in {"all", "flk"}:
            expected, raw_total, rows, duplicates = load_flk_list_rows(options)
            detail_fetched = 0
            text_fetched = 0
            for index, row in enumerate(rows, start=1):
                bbbs = row["bbbs"]
                network_used = not flk_detail_path(options, bbbs).exists()
                try:
                    detail_json = fetch_flk_detail(options, bbbs)
                    network_used = network_used or flk_text_needs_network(options, bbbs, detail_json.get("data") or {})
                    text, has_text, _storage_path = get_flk_text(options, bbbs, detail_json.get("data") or {})
                    detail_fetched += 1
                    text_fetched += 1 if has_text else 0
                    mark_job(
                        state,
                        source_system_id=FLK_SOURCE_ID,
                        external_id=bbbs,
                        source_scope="all_official_records",
                        source_url=source_url_for_flk(bbbs),
                        index_status="succeeded",
                        detail_status="succeeded",
                        text_status="succeeded" if has_text else "missing",
                        article_status="ready" if has_text else "missing",
                        relation_status="ready",
                        checksum=sha256_text(json_dumps(detail_json) + coerce_text(text)),
                        increment_attempts=True,
                    )
                except WafChallengeError as error:
                    blocked = True
                    mark_job(
                        state,
                        source_system_id=FLK_SOURCE_ID,
                        external_id=bbbs,
                        source_scope="all_official_records",
                        source_url=source_url_for_flk(bbbs),
                        detail_status="blocked",
                        text_status="blocked",
                        article_status="blocked",
                        relation_status="blocked",
                        last_error=f"blocked_waf_js_challenge: {error}",
                        increment_attempts=True,
                    )
                    if options.stop_on_waf:
                        break
                except Exception as error:
                    mark_job(
                        state,
                        source_system_id=FLK_SOURCE_ID,
                        external_id=bbbs,
                        source_scope="all_official_records",
                        source_url=source_url_for_flk(bbbs),
                        detail_status="failed",
                        text_status="failed",
                        article_status="missing",
                        relation_status="pending",
                        last_error=str(error),
                        increment_attempts=True,
                    )
                if index % 100 == 0:
                    state.commit()
                    print(f"FLK hydrate {index}/{len(rows)} text={text_fetched}")
                if network_used:
                    rate_limit(options)
            report["coverage"].append(
                {
                    "source": FLK_SOURCE_ID,
                    "expected_total": expected,
                    "fetched_total": raw_total,
                    "unique_document_total": len(rows),
                    "duplicate_row_total": duplicates,
                    "detail_fetched_total": detail_fetched,
                    "text_fetched_total": text_fetched,
                    "status": "blocked" if blocked else ("hydrated" if detail_fetched == len(rows) else "incomplete"),
                }
            )
        if options.source in {"all", "rules"} and not blocked:
            for rule_class in ["部门规章", "地方政府规章"]:
                expected, rows = load_gjgzk_rows(options, rule_class)
                text_fetched = 0
                for index, row in enumerate(rows, start=1):
                    external_id = str(first_scalar(row.get("f_202291670697")) or gov_url_from_row(row) or stable_id(row))
                    network_used = False
                    try:
                        api_text = gjgzk_api_text(row)
                        if api_text:
                            text, has_text = api_text, True
                        else:
                            network_used = True
                            text, has_text = fetch_gjgzk_text(options, gov_url_from_row(row))
                        text_fetched += 1 if has_text else 0
                        mark_job(
                            state,
                            source_system_id=GJGZK_SOURCE_ID,
                            external_id=external_id,
                            source_scope=rule_class,
                            source_url=gov_url_from_row(row),
                            index_status="succeeded",
                            detail_status="succeeded",
                            text_status="succeeded" if has_text else "missing",
                            article_status="ready" if has_text else "missing",
                            relation_status="not_applicable",
                            checksum=sha256_text(json_dumps(row) + text),
                            increment_attempts=True,
                        )
                    except WafChallengeError as error:
                        blocked = True
                        mark_job(
                            state,
                            source_system_id=GJGZK_SOURCE_ID,
                            external_id=external_id,
                            source_scope=rule_class,
                            source_url=gov_url_from_row(row),
                            text_status="blocked",
                            article_status="blocked",
                            relation_status="not_applicable",
                            last_error=f"blocked_waf_js_challenge: {error}",
                            increment_attempts=True,
                        )
                        if options.stop_on_waf:
                            break
                    if index % 100 == 0:
                        state.commit()
                        print(f"GJGZK {rule_class} hydrate {index}/{len(rows)} text={text_fetched}")
                    if network_used:
                        rate_limit(options)
                report["coverage"].append(
                    {
                        "source": GJGZK_SOURCE_ID,
                        "scope": rule_class,
                        "expected_total": expected,
                        "fetched_total": len(rows),
                        "detail_fetched_total": len(rows),
                        "text_fetched_total": text_fetched,
                        "status": "blocked" if blocked else ("hydrated" if text_fetched == len(rows) else "incomplete"),
                    }
                )
                if blocked and options.stop_on_waf:
                    break
        state.commit()
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if options.strict and (blocked or any(item["status"] not in {"hydrated"} for item in report["coverage"])):
            raise RuntimeError(f"hydrate incomplete: {report['coverage']}")
        return 0
    finally:
        state.close()


def parse_args(argv: list[str]) -> BuildOptions:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--state-db", type=Path, default=STATE_DB)
    parser.add_argument("--stage", choices=["index", "hydrate", "assemble", "audit", "all"], default="all")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--limit", type=int, default=None, help="Limit rows per source for smoke tests.")
    parser.add_argument("--source", choices=["all", "flk", "rules"], default="all")
    parser.add_argument("--metadata-only", action="store_true", help="Do not download/parse document text.")
    parser.add_argument("--strict", action="store_true", help="Fail unless all declared coverage is complete.")
    parser.add_argument("--no-strict", action="store_true", help="Do not fail when coverage audit is incomplete.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Sleep between requests.")
    parser.add_argument("--min-delay", type=float, default=None, help="Minimum polite delay between detail/text requests.")
    parser.add_argument("--max-delay", type=float, default=None, help="Maximum polite delay between detail/text requests.")
    parser.add_argument("--resume", action="store_true", help="Persist per-record job state and reuse cached official records.")
    parser.add_argument("--stop-on-waf", action="store_true", help="Stop the current batch when a WAF JavaScript challenge appears.")
    parser.add_argument("--no-refresh-index", action="store_true", help="Reuse cached list/index pages instead of refreshing the official snapshot boundary.")
    parser.add_argument("--cookie-json", type=Path, default=None, help="Import official-site browser cookies exported as Playwright JSON.")
    args = parser.parse_args(argv)
    min_delay = args.min_delay if args.min_delay is not None else args.sleep
    max_delay = args.max_delay if args.max_delay is not None else args.sleep
    strict = False if args.no_strict else True
    if args.strict:
        strict = True
    return BuildOptions(
        output=args.output,
        report=args.report,
        cache_dir=args.cache_dir,
        state_db=args.state_db,
        stage=args.stage,
        page_size=args.page_size,
        workers=max(1, args.workers),
        limit=args.limit,
        source=args.source,
        metadata_only=args.metadata_only,
        strict=strict,
        sleep=max(0.0, args.sleep),
        min_delay=max(0.0, min_delay),
        max_delay=max(0.0, max_delay),
        resume=args.resume,
        stop_on_waf=args.stop_on_waf,
        refresh_index=not args.no_refresh_index,
        cookie_json=args.cookie_json,
    )


def main(argv: list[str]) -> int:
    options = parse_args(argv)
    load_cookie_json(options.cookie_json)
    if options.stage == "index":
        return run_index_stage(options)
    if options.stage == "hydrate":
        return run_hydrate_stage(options)
    if options.stage == "audit":
        return audit_existing_database(options)

    with tempfile.NamedTemporaryFile(prefix="legal_core_", suffix=".sqlite", delete=False) as handle:
        temp_db = Path(handle.name)
    connection: sqlite3.Connection | None = None
    try:
        connection = create_database(temp_db)
        insert_source_systems(connection)
        coverage: list[dict[str, Any]] = []
        if options.source in {"all", "flk"}:
            flk_report = build_flk(connection, options)
            coverage.append(flk_report)
            connection.commit()
            if options.stop_on_waf and flk_report.get("status") == "blocked":
                raise RuntimeError(f"FLK blocked by WAF: {flk_report.get('notes')}")
        if options.source in {"all", "rules"}:
            coverage.extend(build_gjgzk(connection, options))
            connection.commit()
        refresh_fts(connection)
        report = build_report_from_connection(connection, options, coverage)
        update_metadata(connection, report)
        connection.commit()
        report["audit"] = audit_connection(connection)
        update_metadata(connection, report)
        connection.commit()
        integrity = report["audit"]["sqlite_integrity"]
        foreign_key_errors = report["audit"]["foreign_key_errors"]
        connection.close()
        connection = None
        report["integrity_check"] = integrity
        report["foreign_key_errors"] = foreign_key_errors
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        if integrity != "ok" or foreign_key_errors:
            raise RuntimeError(f"SQLite integrity failed: {integrity}, fk={foreign_key_errors}")
        incomplete = [item for item in coverage if item["status"] != "complete"]
        if options.strict and (incomplete or report["audit"]["audit_status"] != "complete"):
            raise RuntimeError(f"coverage/audit incomplete: coverage={incomplete}, audit={report['audit']['failures']}")
        options.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(temp_db), options.output)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except Exception:
        if connection is not None:
            connection.close()
        if temp_db.exists():
            try:
                temp_db.unlink()
            except PermissionError:
                print(f"temporary database left for inspection: {temp_db}")
        raise


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
