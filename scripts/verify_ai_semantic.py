"""Offline semantic and citation audit for the GLM AI upgrade acceptance run.

This checker is deliberately read-only with respect to the application.  It
reads the saved JSON runs and read-only SQLite databases, then writes only the
two reports below ``output/ai-upgrade-semantic`` (or ``--output-dir``).
It does not call a provider, read a credential, or infer that a JSON citation
is semantically sound merely because its identifier exists.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import unicodedata
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIVE_DIR = ROOT / "output" / "ai-upgrade-live"
DEFAULT_LEGAL_DB = ROOT / "data" / "runtime" / "legal_core.sqlite"
DEFAULT_CASE_DB = ROOT / "data" / "runtime" / "judicial_cases.sqlite"
DEFAULT_PORTABLE_CASE_RESULT = ROOT / "output" / "ai-upgrade-portable" / "case-ai-search.json"
DEFAULT_OUTPUT_DIR = ROOT / "output" / "ai-upgrade-semantic"

EXPECTED_PARTIES = ["清沅测试设备有限公司", "澄岭测试商贸有限公司"]
EXPECTED_AMOUNTS = {
    "contract_total": 126800,
    "paid": 30000,
    "outstanding": 96800,
}
EXPECTED_DATES = {
    "contract_date": (2026, 3, 12),
    "payment_due_date": (2026, 4, 10),
}

ARTICLE_TOKEN = r"[一二三四五六七八九十百千万零〇两\d]{1,12}"
ARTICLE_REF_RE = re.compile(
    rf"(?:(?:《(?P<book>[^》]{{1,100}})》|(?P<bare>中华人民共和国民法典|民法典|中华人民共和国民事诉讼法|民事诉讼法|"
    rf"最高人民法院关于审理买卖合同纠纷案件适用法律问题的解释|买卖合同纠纷案件适用法律问题的解释|"
    rf"最高人民法院关于民事诉讼证据的若干规定|民事诉讼证据的若干规定))\s*)?第(?P<number>{ARTICLE_TOKEN})条"
)
MARKER_RE = re.compile(r"(?<!\d)\[(\d{1,3})\]")
FULL_DATE_RE = re.compile(
    r"(?P<year>20\d{2})\s*(?:年|[-/.])\s*(?P<month>\d{1,2})\s*(?:月|[-/.])\s*(?P<day>\d{1,2})\s*[日号]?"
)
PARTIAL_DATE_RE = re.compile(r"(?<!\d)(?P<month>\d{1,2})\s*月\s*(?P<day>\d{1,2})\s*[日号]?")
AMOUNT_RE = re.compile(
    r"(?<![\d.])(?P<number>\d{1,3}(?:[\s,，]\d{3})+|\d+(?:\.\d+)?)\s*(?P<wan>万)?\s*(?P<unit>元|人民币|万元|块)?"
)
COMPANY_RE = re.compile(r"[\u4e00-\u9fffA-Za-z0-9]{2,24}?(?:有限责任公司|股份有限公司|有限公司)")
COURT_RE = re.compile(r"[\u4e00-\u9fff]{1,24}(?:高级|中级|基层)?人民法院")
PERSON_CONTEXT_RE = re.compile(
    r"(?:法定代表人|联系人|采购经理|签署人|代理人)(?:姓名)?\s*(?:为|是|：|:)\s*([\u4e00-\u9fff]{2,4})(?=[，。；,.;、\s]|$)"
)

GENERIC_COMPANY_CANDIDATES = {
    "买方公司",
    "卖方公司",
    "公司公章",
    "公司意思",
    "公司发生",
    "公司承担",
    "公司有效",
    "公司而非",
    "对方公司",
}
GENERIC_COURTS = {
    "人民法院",
    "最高人民法院",
    "有管辖权的人民法院",
    "受诉人民法院",
    "待补充人民法院",
    "待补充：受诉人民法院",
    "贵院",
}
GENERIC_PERSON_WORDS = {
    "买方",
    "卖方",
    "采购",
    "经理",
    "公司",
    "待补",
    "待补充",
    "姓名",
    "职务",
    "作为",
    "签署",
    "法定",
}


def json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normal(value: Any) -> str:
    """Normalize harmless Unicode/whitespace formatting differences."""

    if value is None:
        return ""
    value = unicodedata.normalize("NFKC", str(value))
    return re.sub(r"\s+", "", value.replace("\u00a0", ""))


def normalize_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def roman_or_chinese_number(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    digits = {
        "零": 0,
        "〇": 0,
        "一": 1,
        "二": 2,
        "两": 2,
        "三": 3,
        "四": 4,
        "五": 5,
        "六": 6,
        "七": 7,
        "八": 8,
        "九": 9,
    }
    units = {"十": 10, "百": 100, "千": 1000, "万": 10000}
    if not value or any(ch not in digits and ch not in units for ch in value):
        return None
    # The article numbers in the corpus are below 10,000.  This parser also
    # handles common forms such as 十、二十、二百零三 and 一万零三。
    if "万" in value:
        left, right = value.split("万", 1)
        left_number = roman_or_chinese_number(left) if left else 1
        right_number = roman_or_chinese_number(right) if right else 0
        if left_number is None or right_number is None:
            return None
        return left_number * 10000 + right_number
    total = 0
    section = 0
    number = 0
    for ch in value:
        if ch in digits:
            number = digits[ch]
        else:
            unit = units[ch]
            if unit == 10_000:
                section += (number or 1) * unit
                number = 0
            else:
                section += (number or 1) * unit
                number = 0
    return total + section + number


def canonical_article_number(token: str) -> str:
    number = roman_or_chinese_number(token)
    return f"第{number if number is not None else token}条"


def article_number_key(value: Any) -> int | str:
    """Compare Chinese and Arabic article-number spellings as one value."""

    text = normal(value)
    if text.startswith("第"):
        text = text[1:]
    if text.endswith("条"):
        text = text[:-1]
    parsed = roman_or_chinese_number(text)
    return parsed if parsed is not None else text


def law_alias_matches(book: str | None, document_title: str) -> bool:
    if not book:
        return True
    book = normal(book)
    title = normal(document_title)
    if "民法典" in book:
        return "民法典" in title
    if "民事诉讼法" in book:
        return "民事诉讼法" in title
    if "买卖合同纠纷案件适用法律问题的解释" in book:
        return "买卖合同纠纷案件适用法律问题的解释" in title
    if "民事诉讼证据" in book:
        return "民事诉讼证据" in title
    return normal(book) in title or title in normal(book)


def excerpt(text: str, start: int, end: int, radius: int = 70) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)].replace("\n", " ")


def parse_amount(raw: str, wan: str | None, unit: str | None) -> float | None:
    try:
        value = float(raw.replace(",", "").replace("，", "").replace(" ", ""))
    except ValueError:
        return None
    if wan or unit == "万元":
        value *= 10000
    return value


def amount_mentions(text: str) -> list[dict[str, Any]]:
    mentions: list[dict[str, Any]] = []
    for match in AMOUNT_RE.finditer(text):
        raw = match.group("number")
        wan = match.group("wan")
        unit = match.group("unit")
        before = text[max(0, match.start() - 18) : match.start()]
        # Do not interpret years, article numbers, or arbitrary prose numbers
        # as money unless a money unit or a nearby money cue is present.
        money_cue = bool(unit or re.search(r"(?:总价|价款|余款|欠款|尚欠|支付|付款|金额|基数|人民币)$", before))
        if not money_cue:
            continue
        value = parse_amount(raw, wan, unit)
        if value is None:
            continue
        mentions.append(
            {
                "raw": match.group(0),
                "value": int(value) if value.is_integer() else value,
                "context": excerpt(text, match.start(), match.end(), 42),
                "offset": match.start(),
            }
        )
    return mentions


def date_mentions(text: str) -> dict[str, Any]:
    full = []
    for match in FULL_DATE_RE.finditer(text):
        value = (
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
        )
        full.append({"value": value, "raw": match.group(0), "context": excerpt(text, match.start(), match.end(), 35)})
    partial = []
    for match in PARTIAL_DATE_RE.finditer(text):
        # Full dates also contain a month/day.  Keep partial entries only if
        # there is no immediately preceding year in this match.
        prefix = text[max(0, match.start() - 8) : match.start()]
        if re.search(r"20\d{2}\s*年?\s*$", prefix):
            continue
        value = (int(match.group("month")), int(match.group("day")))
        partial.append({"value": value, "raw": match.group(0), "context": excerpt(text, match.start(), match.end(), 35)})
    return {"full": full, "partial": partial}


def expected_fact_check(text: str) -> dict[str, Any]:
    amounts = amount_mentions(text)
    by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in amounts:
        for key, expected in EXPECTED_AMOUNTS.items():
            if item["value"] == expected:
                by_value[key].append(item)
    dates = date_mentions(text)
    date_rows = {}
    for key, expected in EXPECTED_DATES.items():
        full_matches = [item for item in dates["full"] if tuple(item["value"]) == expected]
        partial_matches = [
            item
            for item in dates["partial"]
            if tuple(item["value"]) == expected[1:]
        ]
        wrong_year = [
            item
            for item in dates["full"]
            if tuple(item["value"])[1:] == expected[1:] and tuple(item["value"]) != expected
        ]
        if full_matches:
            status = "present"
        elif partial_matches:
            status = "partial_year"
        else:
            status = "not_mentioned"
        date_rows[key] = {
            "expected": f"{expected[0]:04d}-{expected[1]:02d}-{expected[2]:02d}",
            "status": status,
            "full_matches": full_matches,
            "partial_matches": partial_matches,
            "wrong_year_matches": wrong_year,
        }
    amount_rows = {}
    for key, expected in EXPECTED_AMOUNTS.items():
        matches = by_value.get(key, [])
        amount_rows[key] = {
            "expected": expected,
            "status": "present" if matches else "not_mentioned",
            "matches": matches,
        }
    parties = {
        party: {"present": party in text}
        for party in EXPECTED_PARTIES
    }
    return {"amounts": amount_rows, "dates": date_rows, "parties": parties}


def amount_value_anomalies(text: str, mentions: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Find a different amount used in one of the fixture's key fact roles."""

    mentions = mentions if mentions is not None else amount_mentions(text)
    rows = []
    for mention in mentions:
        start = int(mention["offset"])
        before = text[max(0, start - 34) : start]
        context = text[max(0, start - 48) : min(len(text), start + 34)]
        roles = []
        if re.search(r"(?:总价|总价款|合同金额|价款总额)\s*(?:为|是|：|:)?\s*$", before):
            roles.append("contract_total")
        # Require an explicit actual-payment cue.  A contractual obligation
        # such as “约定支付全部价款126800元” is not evidence that 126800 was
        # paid, so it intentionally does not match this branch.
        if re.search(r"(?:仅|只|已|已经|实际)\s*(?:支付|付款|付)\s*(?:价款|款项)?\s*$", before):
            roles.append("paid")
        if re.search(r"(?:剩余|余款|尚欠|欠款)\s*(?:为|是|：|:|人民币)?\s*$", before):
            roles.append("outstanding")
        for role in roles:
            expected = EXPECTED_AMOUNTS[role]
            if mention["value"] != expected:
                rows.append(
                    {
                        "fact": role,
                        "value": mention["value"],
                        "expected": expected,
                        "context": context.replace("\n", " "),
                    }
                )
    return unique_dicts(rows)


def payment_contradictions(text: str) -> list[dict[str, Any]]:
    rows = []
    # These are assertions that the synthetic case has been paid in full or
    # has no debt.  A future/obligation statement such as “应付清” is excluded.
    patterns = [
        r"(?:已|已经|均已|全部已|款项已|全款已|余款已)\s*(?:全部)?(?:支付|付清|结清|清偿|偿还|支付完毕)",
        r"(?:不存在|没有|无)\s*(?:任何)?(?:欠款|余款|债务)",
        r"(?:全部价款|全部款项|全款)\s*(?:均已|已经|已)\s*(?:支付|付清|结清|清偿)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            context = excerpt(text, match.start(), match.end(), 65)
            # “未已支付” is malformed but still not a positive full-payment
            # assertion.  Ordinary “未付清/尚未结清” is also safe.
            prefix = text[max(0, match.start() - 8) : match.start()]
            if re.search(r"(?:未|尚未|并未|没有)\s*$", prefix):
                continue
            rows.append({"text": match.group(0), "context": context})
    return unique_dicts(rows)


def unknown_identity_candidates(text: str) -> dict[str, list[str]]:
    companies = []
    for match in COMPANY_RE.finditer(text):
        candidate = match.group(0)
        if candidate in EXPECTED_PARTIES or any(party in candidate for party in EXPECTED_PARTIES):
            continue
        candidate = candidate.lstrip("与及、向由被告原告的")
        if not candidate or candidate in EXPECTED_PARTIES or candidate in GENERIC_COMPANY_CANDIDATES:
            continue
        if any(word in candidate for word in ("公司公章", "公司发生", "公司承担", "公司意思")):
            continue
        companies.append(candidate)
    courts = []
    for match in COURT_RE.finditer(text):
        candidate = match.group(0)
        if candidate in GENERIC_COURTS:
            continue
        if any(word in candidate for word in ("有管辖权", "受诉", "待补充", "贵院", "本案")):
            continue
        courts.append(candidate)
    people = []
    for match in PERSON_CONTEXT_RE.finditer(text):
        candidate = match.group(1)
        if candidate in GENERIC_PERSON_WORDS or candidate.startswith("待补"):
            continue
        # “买方采购经理” and “公司采购经理” are role descriptions, not
        # names.  Only report a short proper-name candidate here.
        if candidate in {"买方采购", "卖方采购", "公司采购", "采购经理", "签署人"}:
            continue
        people.append(candidate)
    return {
        "unknown_company_candidates": sorted(set(companies)),
        "specific_court_candidates": sorted(set(courts)),
        "person_name_candidates": sorted(set(people)),
    }


def procedural_claims(text: str) -> list[dict[str, Any]]:
    rows = []
    for sentence in re.split(r"(?<=[。！？；])|\n+", text):
        sentence = sentence.strip()
        if not sentence or "法院" not in sentence:
            continue
        # A generated pleading commonly asks the court to grant its claims.
        # That is a requested remedy, not a claim that a court has already
        # issued a judgment or finding.
        if re.search(r"(?:请求法院|请法院|诉讼请求|请求依法支持|请求判令)", sentence):
            continue
        if re.search(r"(?:法院|人民法院)(?:已|已经|曾经)?(?:判决|认定|裁定|查明|支持|驳回|判令)", sentence):
            rows.append({"text": sentence[:300], "reason": "specific_procedural_assertion_without_case_record"})
    return unique_dicts(rows)


def date_logic_issues(text: str) -> list[dict[str, Any]]:
    rows = []
    # “4月10日前” means the deadline is the end of 10 April in this fixture;
    # a loss/interest period starting on 11 April is therefore the consistent
    # expression.  Report wording that labels 11 April as the deadline day.
    for pattern, reason in [
        (r"付款期限届满之日[^。；\n]{0,18}(?:2026年?4月11日|2026[-/]04[-/]11)", "labels_day_after_deadline_as_deadline_day"),
        (r"(?:自|从)约定付款期限届满之日起", "uses_deadline_day_as_loss_start_without_next_day"),
        (r"自(?:付款期限届满之日)?[（(]?2026年?4月10日[）)]?[^。；\n]{0,15}(?:起算|计算)", "interest_start_on_deadline_day_needs_contract_check"),
    ]:
        for match in re.finditer(pattern, text):
            rows.append({"reason": reason, "context": excerpt(text, match.start(), match.end(), 90)})
    return unique_dicts(rows)


def missing_wait_items(text: str) -> list[dict[str, str]]:
    required = {
        "contract_quality_and_inspection_terms": ["检验期限", "质量标准", "质量条款"],
        "quality_objection_timing": ["质量异议", "提出质量", "通知出卖人"],
        "demand_date_and_proof": ["催告", "催告时间", "催告记录"],
        "payment_time_and_proof": ["付款日期", "付款的具体日期", "付款时间", "支付时间", "付款凭证", "支付凭证", "到账时间", "支付方式"],
        "authority_scope": ["授权", "职权", "采购经理"],
        "late_loss_basis": ["违约金", "逾期利息", "LPR", "损失"],
        "jurisdiction_or_dispute_clause": ["管辖", "争议解决", "仲裁"],
    }
    missing = []
    for topic, terms in required.items():
        if not any(term in text for term in terms):
            missing.append({"topic": topic, "expected_terms": terms})
    return missing


def unsupported_conclusions(text: str) -> list[dict[str, Any]]:
    rows = []
    patterns = [
        (
            r"(?:质量异议|质量抗辩)[^。；\n]{0,80}(?:不能成立|不成立|已超出合理|视为质量符合)",
            "absolute_quality_conclusion_from_acceptance_without_quality_test",
        ),
        (
            r"验收单[^。；\n]{0,45}(?:确认|表明)[^。；\n]{0,30}(?:质量符合|质量合格|符合约定)",
            "acceptance_record_is_treated_as_full_quality_confirmation",
        ),
        (
            r"(?:现有材料|以上证据|本案材料)[^。；\n]{0,30}(?:基本具备|充分|齐全)",
            "claims_evidence_is_present_or_sufficient_beyond_prompt_facts",
        ),
        (
            r"买方[^。；\n]{0,30}(?:未在检验期限|未在合理期限|超出合理异议期间)[^。；\n]{0,30}(?:通知|提出异议)",
            "asserts_objection_deadline_expired_without_objection_date",
        ),
        (
            r"合同[^。；\n]{0,40}(?:必然|当然|直接|应当)对[^。；\n]{0,25}(?:买方公司|法人)发生效力",
            "contract_effect_conclusion_needs_authority_and_good_faith_facts",
        ),
    ]
    for pattern, reason in patterns:
        for match in re.finditer(pattern, text):
            rows.append({"reason": reason, "text": match.group(0), "context": excerpt(text, match.start(), match.end(), 85)})
    return unique_dicts(rows)


def article_condition_omissions(text: str) -> list[dict[str, Any]]:
    """Flag paraphrases that use a cited article while dropping its key gate."""

    rows = []
    # Article 583 is conditional: the additional loss must remain after the
    # duty has been performed or a remedy has been taken.  Several generated
    # drafts use it as an unconditional direct basis for late-payment loss.
    for match in re.finditer(r"(?:第五百八十三条|第583条)", text):
        context = excerpt(text, match.start(), match.end(), 150)
        if re.search(r"(?:逾期付款损失|赔偿(?:原告|对方)?(?:由此)?遭受的其他损失|其他损失)", context) and not re.search(
            r"(?:履行义务后|采取补救措施后|在履行(?:义务)?后|补救后)", context
        ):
            rows.append(
                {
                    "reason": "article_583_post_performance_condition_not_stated",
                    "article_number": "第五百八十三条",
                    "context": context,
                }
            )
    return unique_dicts(rows)


def extract_article_refs(text: str) -> list[dict[str, Any]]:
    rows = []
    for match in ARTICLE_REF_RE.finditer(text):
        book = match.group("book") or match.group("bare")
        article_number = canonical_article_number(match.group("number"))
        rows.append(
            {
                "book": book,
                "article_number": article_number,
                "raw": match.group(0),
                "context": excerpt(text, match.start(), match.end(), 75),
                "start": match.start(),
            }
        )
    return unique_dicts(rows, keys=("book", "article_number"))


def unique_dicts(rows: Iterable[dict[str, Any]], keys: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for row in rows:
        identity = tuple(normal(row.get(key)) for key in keys) if keys else tuple(sorted((k, normal(v)) for k, v in row.items()))
        if identity in seen:
            continue
        seen.add(identity)
        result.append(row)
    return result


def open_ro(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def legal_source(con: sqlite3.Connection, article_id: str) -> dict[str, Any] | None:
    row = con.execute(
        """
        SELECT a.id, a.document_id, a.version_id, a.article_number, a.title,
               content.content, document.title, version.version_label,
               version.status, version.effective_from, version.effective_to,
               metadata.citation_id, metadata.canonical_label
        FROM law_article_rows AS a
        JOIN law_article_contents AS content ON content.content_id = a.content_id
        JOIN law_documents AS document ON document.id = a.document_id
        JOIN law_versions AS version ON version.id = a.version_id
        LEFT JOIN citation_metadata AS metadata ON metadata.article_id = a.id
        WHERE a.id = ?
        """,
        (article_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "article_id": row[0],
        "document_id": row[1],
        "version_id": row[2],
        "article_number": row[3],
        "article_title": row[4],
        "content": row[5],
        "title": row[6],
        "version_label": row[7],
        "status": row[8],
        "effective_from": row[9],
        "effective_to": row[10],
        "citation_id": row[11],
        "canonical_label": row[12],
    }


def case_source(con: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
    row = con.execute(
        """
        SELECT case_id, case_type, title, publication_date, court, case_number,
               status, source_url, full_text
        FROM judicial_cases WHERE case_id = ?
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "case_id": row[0],
        "case_type": row[1],
        "title": row[2],
        "publication_date": row[3],
        "court": row[4],
        "case_number": row[5],
        "status": row[6],
        "source_url": row[7],
        "full_text": row[8],
    }


def validate_citation(citation: dict[str, Any], legal_con: sqlite3.Connection | None, case_con: sqlite3.Connection | None) -> dict[str, Any]:
    kind = citation.get("kind") or ("case" if citation.get("case_id") else "article")
    source_id = citation.get("article_id") if kind != "case" else citation.get("case_id")
    result: dict[str, Any] = {
        "kind": kind,
        "source_id": source_id,
        "article_id": citation.get("article_id"),
        "case_id": citation.get("case_id"),
        "status": "fail",
        "field_mismatches": [],
        "content_match": False,
        "quote_status": "absent",
    }
    if not source_id:
        result["issues"] = ["citation_identifier_missing"]
        return result
    if kind == "case":
        source = case_source(case_con, source_id) if case_con else None
        if source is None:
            result["issues"] = ["case_id_not_found"]
            return result
        result["canonical"] = {
            "case_id": source["case_id"],
            "title": source["title"],
            "publication_date": source["publication_date"],
            "status": source["status"],
            "source_url": source["source_url"],
        }
        for field in ("title", "publication_date", "status", "source_url"):
            if citation.get(field) is not None and normal(citation.get(field)) != normal(source.get(field)):
                result["field_mismatches"].append({"field": field, "reported": citation.get(field), "database": source.get(field)})
        content = citation.get("content")
        if content is not None:
            result["content_match"] = normal(content) == normal(source["full_text"])
            if not result["content_match"]:
                result["field_mismatches"].append({"field": "content", "reported": "present", "database": "different"})
        quote = citation.get("quote")
        if quote:
            result["quote_status"] = "exact" if normal(quote) in normal(source["full_text"]) else "mismatch"
        result["status"] = "pass" if not result["field_mismatches"] and result["quote_status"] in {"exact", "absent"} else "fail"
        result["issues"] = [] if result["status"] == "pass" else ["case_citation_mismatch"]
        return result
    source = legal_source(legal_con, source_id) if legal_con else None
    if source is None:
        result["issues"] = ["article_id_not_found"]
        return result
    result["canonical"] = {
        "citation_id": source["citation_id"],
        "canonical_label": source["canonical_label"],
        "article_id": source["article_id"],
        "document_id": source["document_id"],
        "version_id": source["version_id"],
        "title": source["title"],
        "article_number": source["article_number"],
        "version_label": source["version_label"],
        "status": source["status"],
        "effective_from": source["effective_from"],
        "effective_to": source["effective_to"],
    }
    for field, canonical_field in [
        ("article_id", "article_id"),
        ("document_id", "document_id"),
        ("version_id", "version_id"),
        ("title", "title"),
        ("article_number", "article_number"),
        ("version_label", "version_label"),
        ("status", "status"),
        ("effective_from", "effective_from"),
        ("effective_to", "effective_to"),
    ]:
        values_match = (
            article_number_key(citation.get(field)) == article_number_key(source.get(canonical_field))
            if field == "article_number"
            else normal(citation.get(field)) == normal(source.get(canonical_field))
        )
        if citation.get(field) is not None and not values_match:
            result["field_mismatches"].append(
                {"field": field, "reported": citation.get(field), "database": source.get(canonical_field)}
            )
    content = citation.get("content")
    if content is not None:
        result["content_match"] = normal(content) == normal(source["content"])
        if not result["content_match"]:
            result["field_mismatches"].append({"field": "content", "reported": "present", "database": "different"})
    else:
        result["field_mismatches"].append({"field": "content", "reported": "missing", "database": "present"})
    quote = citation.get("quote")
    if quote:
        result["quote_status"] = "exact" if normal(quote) in normal(source["content"]) else "mismatch"
    result["status"] = "pass" if not result["field_mismatches"] and result["quote_status"] in {"exact", "absent"} else "fail"
    result["issues"] = [] if result["status"] == "pass" else ["article_citation_mismatch"]
    return result


def validate_citations(citations: list[dict[str, Any]], legal_con: sqlite3.Connection | None, case_con: sqlite3.Connection | None) -> dict[str, Any]:
    rows = [validate_citation(citation, legal_con, case_con) for citation in citations]
    quote_counts = Counter(row["quote_status"] for row in rows)
    integrity_failures = [row for row in rows if row["status"] == "fail"]
    return {
        "count": len(rows),
        "unique_source_ids": len({row.get("source_id") for row in rows if row.get("source_id")}),
        "rows": rows,
        "integrity_status": "pass" if not integrity_failures else "fail",
        "quote_counts": dict(quote_counts),
        "missing_quote_count": quote_counts.get("absent", 0),
        "quote_mismatch_count": quote_counts.get("mismatch", 0),
        "invalid_count": len(integrity_failures),
    }


def audit_case_search_result(path: Path, case_con: sqlite3.Connection | None) -> dict[str, Any]:
    """Validate the portable case-search artifact against the local case DB."""

    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "status": "not_available" if not path.exists() else "fail",
        "kind": None,
        "run_status": None,
        "citation_validation": None,
        "marker_check": None,
        "tool_steps": [],
        "issues": [],
    }
    if not path.exists():
        result["issues"] = ["portable_case_search_result_missing"]
        return result
    try:
        data = json_load(path)
    except Exception as exc:
        result["issues"] = [f"portable_case_search_result_invalid_json: {exc}"]
        return result
    if not isinstance(data, dict):
        result["issues"] = ["portable_case_search_result_not_object"]
        return result

    content = data.get("content") or ""
    citations = data.get("citations") if isinstance(data.get("citations"), list) else []
    citation_validation = validate_citations(citations, None, case_con)
    markers = sorted({int(value) for value in MARKER_RE.findall(content)})
    out_of_range = [value for value in markers if value < 1 or value > len(citations)]
    marker_check = {
        "markers": markers,
        "out_of_range": out_of_range,
        "status": "pass" if markers and not out_of_range else "review",
    }
    steps = data.get("tool_steps") if isinstance(data.get("tool_steps"), list) else []
    step_rows = [
        {"tool": step.get("tool"), "status": step.get("status"), "query": step.get("query")}
        for step in steps
        if isinstance(step, dict)
    ]
    result.update(
        {
            "kind": data.get("kind"),
            "run_status": data.get("status"),
            "title": data.get("title"),
            "content_length": len(content),
            "citation_count": len(citations),
            "citation_validation": citation_validation,
            "marker_check": marker_check,
            "tool_steps": step_rows,
        }
    )
    if data.get("kind") != "search":
        result["issues"].append("portable_result_kind_is_not_search")
    if data.get("status") != "completed":
        result["issues"].append("portable_result_not_completed")
    if not citations:
        result["issues"].append("portable_result_has_no_citations")
    if citation_validation["integrity_status"] != "pass":
        result["issues"].append("portable_case_citation_identity_or_quote_mismatch")
    if marker_check["status"] != "pass":
        result["issues"].append("portable_result_citation_markers_not_verifiable")
    required_tools = {"legal_search_cases", "legal_get_case"}
    observed_tools = {row["tool"] for row in step_rows}
    if not required_tools.issubset(observed_tools):
        result["issues"].append("portable_result_missing_case_search_or_get_step")
    if any(row["status"] != "completed" for row in step_rows):
        result["issues"].append("portable_result_has_failed_tool_step")
    result["status"] = "pass" if not result["issues"] else "fail"
    return result


def citation_coverage(text: str, citations: list[dict[str, Any]]) -> dict[str, Any]:
    refs = extract_article_refs(text)
    rows = []
    for ref in refs:
        matches = [
            c
            for c in citations
            if c.get("kind", "article") == "article"
            and article_number_key(c.get("article_number")) == article_number_key(ref["article_number"])
            and law_alias_matches(ref.get("book"), c.get("title", ""))
        ]
        if not matches:
            same_number = [c for c in citations if article_number_key(c.get("article_number")) == article_number_key(ref["article_number"])]
            rows.append(
                {
                    "book": ref.get("book"),
                    "article_number": ref["article_number"],
                    "context": ref["context"],
                    "reason": "statute_reference_has_no_matching_final_citation" if not same_number else "law_name_does_not_match_citation_title",
                }
            )
    markers = sorted({int(value) for value in MARKER_RE.findall(text)})
    count = len(citations)
    out_of_range = [value for value in markers if value < 1 or value > count]
    missing_markers = [value for value in range(1, count + 1) if value not in markers]
    return {
        "statutory_references": refs,
        "uncited_statutory_claims": rows,
        "markers": markers,
        "out_of_range_markers": out_of_range,
        "missing_markers_for_citations": missing_markers,
        "marker_status": "pass" if not out_of_range and not (count and not markers) else "review",
    }


def read_docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("word/document.xml"))
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    paragraphs = []
    for paragraph in root.findall(".//w:p", ns):
        paragraphs.append("".join(node.text or "" for node in paragraph.findall(".//w:t", ns)))
    return "\n".join(paragraphs)


def read_pdf_text(path: Path) -> tuple[str | None, str | None]:
    try:
        from pypdf import PdfReader
    except Exception as exc:  # pragma: no cover - environment dependent
        return None, f"pypdf_unavailable: {exc}"
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages), None
    except Exception as exc:  # pragma: no cover - corrupt PDF diagnostic
        return None, f"pdf_read_failed: {exc}"


def export_audit(live_dir: Path, writing_runs: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    runs_without_export = []
    for run in writing_runs:
        run_id = run.get("run_id") or run.get("id") or ""
        short_id = run_id.removeprefix("run_")
        source_stem = Path(str(run.get("_file", ""))).stem
        initial_stem = source_stem if source_stem.startswith("writing-") else ""
        candidates = [
            (initial_stem, "initial"),
            (f"verified-run_{short_id}", "resumed_export"),
        ]
        seen = set()
        found_any = False
        for stem, source_kind in candidates:
            if not stem or stem in seen:
                continue
            seen.add(stem)
            files = {ext: live_dir / f"{stem}.{ext}" for ext in ("txt", "docx", "pdf")}
            if not any(path.exists() for path in files.values()):
                continue
            found_any = True
            row: dict[str, Any] = {
                "run_id": run_id,
                "stem": stem,
                "source_kind": source_kind,
                "files": {},
            }
            for ext, path in files.items():
                info: dict[str, Any] = {"path": str(path), "exists": path.exists()}
                if path.exists():
                    info["bytes"] = path.stat().st_size
                if ext == "txt" and path.exists():
                    text = path.read_text(encoding="utf-8", errors="replace")
                    info.update(
                        {
                            "length": len(text),
                            "markdown_fence": "```" in text,
                            "markdown_heading_lines": sum(bool(re.match(r"^\s*#{1,6}\s", line)) for line in text.splitlines()),
                            "facts": expected_fact_check(text),
                        }
                    )
                elif ext == "docx" and path.exists():
                    try:
                        text = read_docx_text(path)
                        info.update({"extracted_length": len(text), "markdown_fence": "```" in text, "facts": expected_fact_check(text)})
                    except Exception as exc:
                        info["read_error"] = str(exc)
                elif ext == "pdf" and path.exists():
                    text, error = read_pdf_text(path)
                    info["read_error"] = error
                    if text is not None:
                        info.update({"pages_text_length": len(text), "facts": expected_fact_check(text)})
                row["files"][ext] = info
            rows.append(row)
        if not found_any:
            runs_without_export.append(
                {
                    "run_id": run_id,
                    "source_file": run.get("_file"),
                    "status": run.get("status"),
                    "error_code": run.get("error_code"),
                }
            )
    return {
        "export_sets": rows,
        "runs_without_export": runs_without_export,
        "missing_export_run_count": len(runs_without_export),
        "missing_file_count": sum(1 for row in rows for item in row["files"].values() if not item["exists"]),
        "txt_markdown_fence_count": sum(1 for row in rows if row["files"].get("txt", {}).get("markdown_fence")),
    }


def list_file(path: Path, role: str) -> dict[str, Any]:
    row = {"path": str(path), "role": role, "exists": path.exists()}
    if path.exists():
        row["bytes"] = path.stat().st_size
    return row


def load_final_runs(live_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    initial: list[dict[str, Any]] = []
    for pattern in ("search-*.json", "writing-*.json", "chat-*.json"):
        for path in sorted(live_dir.glob(pattern)):
            if path.name.endswith("-resumed.json"):
                continue
            try:
                data = json_load(path)
            except Exception:
                continue
            if isinstance(data, dict) and data.get("kind") in {"search", "writing", "chat"}:
                data = dict(data)
                data["_file"] = path.name
                initial.append(data)
    resumed = []
    resumed_patterns = ("run-*-resumed.json", "run_*-resumed.json", "search-*-resumed.json", "writing-*-resumed.json", "chat-*-resumed.json")
    resumed_paths = sorted({path for pattern in resumed_patterns for path in live_dir.glob(pattern)})
    for path in resumed_paths:
        try:
            data = json_load(path)
        except Exception:
            continue
        if isinstance(data, dict) and data.get("kind") in {"search", "writing", "chat"}:
            data = dict(data)
            data["_file"] = path.name
            resumed.append(data)
    resumed_by_id = {data.get("id"): data for data in resumed if data.get("id")}
    resumed_source_stems = {
        Path(str(data.get("_file", ""))).stem.removesuffix("-resumed")
        for data in resumed
        if str(data.get("_file", "")).endswith("-resumed.json")
    }
    resumed_source_ids = {
        Path(str(data.get("_file", ""))).stem.removesuffix("-resumed")
        for data in resumed
        if Path(str(data.get("_file", ""))).stem.startswith("run_")
        and str(data.get("_file", "")).endswith("-resumed.json")
    }
    finals = []
    intermediates = []
    for data in initial:
        # A paused search/writing snapshot is also an intermediate result.
        # The old branch only filtered non-completed chat snapshots, so
        # ``search-*-paused-*.json`` and ``writing-*-paused-*.json`` could be
        # counted as extra final business runs beside their completed retry.
        # Paused/queued/running snapshots are intermediate states.  Terminal
        # failures remain final attempted runs so the report cannot silently
        # turn a failed business result into an absent run.
        if data.get("status") in {"paused", "queued", "running"}:
            intermediates.append(data)
            continue
        source_stem = Path(str(data.get("_file", ""))).stem
        if source_stem in resumed_source_stems:
            data["_replaced_by_resumed"] = True
            intermediates.append(data)
            continue
        if data.get("id") in resumed_source_ids or (data.get("kind") == "chat" and data.get("id") in resumed_by_id):
            data["_replaced_by_resumed"] = True
            intermediates.append(data)
            continue
        finals.append(data)
    for data in resumed:
        if data.get("status") == "completed":
            finals.append(data)
    # Preserve the acceptance order: search, writing, chat by repeat number.
    finals.sort(key=lambda data: (data.get("kind", ""), data.get("_file", "")))
    searches = [data for data in finals if data.get("kind") == "search"]
    writings = [data for data in finals if data.get("kind") == "writing"]
    chats = [data for data in finals if data.get("kind") == "chat"]
    return finals, searches, writings, chats, intermediates


def run_semantic_audit(
    live_dir: Path,
    legal_db: Path,
    case_db: Path,
    portable_case_result: Path | None = DEFAULT_PORTABLE_CASE_RESULT,
) -> dict[str, Any]:
    finals, searches, writings, chats, intermediates = load_final_runs(live_dir)
    legal_con = None
    case_con = None
    db_errors = []
    try:
        legal_con = open_ro(legal_db)
    except Exception as exc:
        db_errors.append({"database": "legal", "error": str(exc)})
    try:
        case_con = open_ro(case_db)
    except Exception as exc:
        db_errors.append({"database": "case", "error": str(exc)})

    run_rows = []
    aggregate_citations = []
    for data in finals:
        content = data.get("content") or ""
        citations = data.get("citations") if isinstance(data.get("citations"), list) else []
        citation_rows = validate_citations(citations, legal_con, case_con)
        coverage = citation_coverage(content, citations)
        identities = unknown_identity_candidates(content)
        unsupported = unsupported_conclusions(content)
        contradictions = payment_contradictions(content)
        date_issues = date_logic_issues(content)
        facts = expected_fact_check(content)
        fact_errors = []
        amount_anomalies = amount_value_anomalies(content)
        if amount_anomalies:
            fact_errors.append({"fact": "amount_roles", "reason": "key_amount_does_not_match_fixture", "matches": amount_anomalies})
        for key, row in facts["dates"].items():
            if row["wrong_year_matches"]:
                fact_errors.append({"fact": key, "reason": "wrong_year_for_month_day", "matches": row["wrong_year_matches"]})
        if contradictions:
            fact_errors.append({"fact": "payment_state", "reason": "claims_full_payment_or_no_debt", "matches": contradictions})
        if not all(item["present"] for item in facts["parties"].values()):
            fact_errors.append({"fact": "parties", "reason": "one_or_more_prompt_parties_not_mentioned"})
        procedural = procedural_claims(content)
        condition_omissions = article_condition_omissions(content)
        model_issue_count = len(fact_errors) + len(unsupported) + len(condition_omissions) + len(date_issues) + len(procedural) + sum(len(values) for values in identities.values())
        tool_issue_count = citation_rows["invalid_count"] + citation_rows["missing_quote_count"] + citation_rows["quote_mismatch_count"] + len(coverage["uncited_statutory_claims"])
        model_status = "fail" if fact_errors or identities["specific_court_candidates"] else ("review" if model_issue_count else "pass")
        tool_status = "fail" if citation_rows["invalid_count"] or citation_rows["quote_mismatch_count"] else ("review" if tool_issue_count else "pass")
        evaluable = data.get("status") == "completed"
        missing_items = missing_wait_items(content)
        if not evaluable:
            # A terminal provider/tool failure has no final text to judge.
            # Keep it in the final-run inventory, but do not turn the empty
            # content into synthetic missing-fact errors or a semantic pass.
            facts = {"status": "not_evaluable"}
            fact_errors = []
            identities = {
                "unknown_company_candidates": [],
                "specific_court_candidates": [],
                "person_name_candidates": [],
            }
            unsupported = []
            contradictions = []
            date_issues = []
            procedural = []
            condition_omissions = []
            missing_items = []
            model_status = "not_evaluable"
            tool_status = "not_evaluable"
        row = {
            "run_id": data.get("id"),
            "kind": data.get("kind"),
            "source_file": data.get("_file"),
            "status": data.get("status"),
            "evaluable": evaluable,
            "error_code": data.get("error_code"),
            "title": data.get("title"),
            "model": data.get("model"),
            "usage": data.get("usage"),
            "tool_steps": len(data.get("tool_steps") or []),
            "content_length": len(content),
            "facts": facts,
            "model_semantics": {
                "status": model_status,
                "fact_errors": fact_errors,
                "payment_contradictions": contradictions,
                "identity_candidates": identities,
                "specific_procedural_claims": procedural,
                "date_logic_issues": date_issues,
                "unsupported_conclusions": unsupported,
                "article_condition_omissions": condition_omissions,
                "missing_wait_items": missing_items,
            },
            "tool_constraints": {
                "status": tool_status,
                "citation_validation": citation_rows,
                "citation_coverage": coverage,
            },
        }
        run_rows.append(row)
        aggregate_citations.extend(citations)

    checked_files = [
        list_file(live_dir / "live-report.json", "live_run_metadata"),
        list_file(live_dir / "resume-report.json", "resume_metadata"),
    ]
    for pattern, role in [
        ("search-*.json", "search_run"),
        ("writing-*.json", "writing_run"),
        ("chat-*.json", "chat_run_initial"),
        ("run_*-resumed.json", "run_resumed_final"),
        ("search-*-resumed.json", "search_run_resumed_final"),
        ("writing-*-resumed.json", "writing_run_resumed_final"),
        ("chat-*-resumed.json", "chat_run_resumed_final"),
        ("writing-*.txt", "writing_export_txt"),
        ("writing-*.docx", "writing_export_docx"),
        ("writing-*.pdf", "writing_export_pdf"),
        ("verified-run_*.txt", "resumed_writing_export_txt"),
        ("verified-run_*.docx", "resumed_writing_export_docx"),
        ("verified-run_*.pdf", "resumed_writing_export_pdf"),
    ]:
        checked_files.extend(list_file(path, role) for path in sorted(live_dir.glob(pattern)))
    checked_files.extend(
        [
            list_file(legal_db, "legal_citation_database"),
            list_file(case_db, "judicial_case_database"),
        ]
    )
    if portable_case_result is not None:
        checked_files.append(list_file(portable_case_result, "portable_case_search_result"))

    if legal_con:
        legal_metadata = dict(legal_con.execute("SELECT key, value FROM database_metadata").fetchall())
    else:
        legal_metadata = {}
    if case_con:
        case_metadata = dict(case_con.execute("SELECT key, value FROM database_metadata").fetchall())
        case_counts = dict(case_con.execute("SELECT case_type, count(*) FROM judicial_cases GROUP BY case_type").fetchall())
    else:
        case_metadata = {}
        case_counts = {}

    writing_export_audit = export_audit(live_dir, writings)
    portable_case_audit = (
        audit_case_search_result(portable_case_result, case_con)
        if portable_case_result is not None
        else {"status": "not_requested", "exists": False, "issues": []}
    )
    citation_kinds = Counter((citation.get("kind") or ("case" if citation.get("case_id") else "article")) for citation in aggregate_citations)
    source_ids = {
        citation.get("article_id") or citation.get("case_id")
        for citation in aggregate_citations
        if citation.get("article_id") or citation.get("case_id")
    }
    all_model_issues = [
        issue
        for row in run_rows
        for issue in row["model_semantics"]["fact_errors"]
        + row["model_semantics"]["unsupported_conclusions"]
        + row["model_semantics"]["article_condition_omissions"]
        + row["model_semantics"]["date_logic_issues"]
    ]
    all_uncited = [
        {
            "run_id": row["run_id"],
            **item,
        }
        for row in run_rows
        for item in row["tool_constraints"]["citation_coverage"]["uncited_statutory_claims"]
    ]
    report = {
        "audit": {
            "name": "AI upgrade offline semantic audit",
            "generated_by": "scripts/verify_ai_semantic.py",
            "read_only": True,
            "provider_calls": 0,
            "credentials_read": False,
            "live_dir": str(live_dir),
            "legal_db": str(legal_db),
            "case_db": str(case_db),
        },
        "checked_files": checked_files,
        "selection": {
            "final_run_count": len(finals),
            "search_final_count": len(searches),
            "writing_final_count": len(writings),
            "chat_final_count": len(chats),
            "intermediate_count": len(intermediates),
            "intermediate_files": [{"run_id": data.get("id"), "file": data.get("_file"), "status": data.get("status"), "replaced_by_resumed": bool(data.get("_replaced_by_resumed")) or data.get("id") in {row.get("run_id") for row in run_rows}} for data in intermediates],
            "expected_final_shape": {"search": 3, "writing": 3, "chat": 3},
            "shape_status": "pass" if len(searches) == len(writings) == len(chats) == 3 else "review",
        },
        "database": {
            "legal_metadata": legal_metadata,
            "case_metadata": case_metadata,
            "case_counts": case_counts,
            "errors": db_errors,
            "case_citations_in_final_outputs": citation_kinds.get("case", 0),
        },
        "portable_case_search": portable_case_audit,
        "citation_totals": {
            "final_citation_objects": len(aggregate_citations),
            "unique_source_ids": len(source_ids),
            "by_kind": dict(citation_kinds),
            "invalid_citations": sum(row["tool_constraints"]["citation_validation"]["invalid_count"] for row in run_rows),
            "missing_quotes": sum(row["tool_constraints"]["citation_validation"]["missing_quote_count"] for row in run_rows),
            "quote_mismatches": sum(row["tool_constraints"]["citation_validation"]["quote_mismatch_count"] for row in run_rows),
            "uncited_statutory_claims": len(all_uncited),
        },
        "runs": run_rows,
        "aggregate_findings": {
            "model_semantics": {
                "status": "fail" if any(row["model_semantics"]["status"] == "fail" for row in run_rows) else ("review" if any(row["model_semantics"]["status"] == "review" for row in run_rows) else "pass"),
                "fact_error_count": sum(len(row["model_semantics"]["fact_errors"]) for row in run_rows),
                "payment_contradiction_count": sum(len(row["model_semantics"]["payment_contradictions"]) for row in run_rows),
                "specific_court_candidate_count": sum(len(row["model_semantics"]["identity_candidates"]["specific_court_candidates"]) for row in run_rows),
                "person_candidate_count": sum(len(row["model_semantics"]["identity_candidates"]["person_name_candidates"]) for row in run_rows),
                "specific_procedural_claim_count": sum(len(row["model_semantics"]["specific_procedural_claims"]) for row in run_rows),
                "unsupported_conclusion_count": sum(len(row["model_semantics"]["unsupported_conclusions"]) for row in run_rows),
                "article_condition_omission_count": sum(len(row["model_semantics"]["article_condition_omissions"]) for row in run_rows),
                "date_logic_issue_count": sum(len(row["model_semantics"]["date_logic_issues"]) for row in run_rows),
                "representative_findings": all_model_issues[:24],
            },
            "tool_constraints": {
                "status": "fail" if any(row["tool_constraints"]["status"] == "fail" for row in run_rows) else ("review" if any(row["tool_constraints"]["status"] == "review" for row in run_rows) else "pass"),
                "all_final_ids_found_in_database": not any(row["tool_constraints"]["citation_validation"]["invalid_count"] for row in run_rows),
                "all_version_fields_match": not any(row["tool_constraints"]["citation_validation"]["invalid_count"] for row in run_rows),
                "uncited_statutory_claims": all_uncited,
            },
            "missing_wait_items": {
                "runs_with_missing_items": sum(bool(row["model_semantics"]["missing_wait_items"]) for row in run_rows),
                "by_run": [{"run_id": row["run_id"], "items": row["model_semantics"]["missing_wait_items"]} for row in run_rows if row["model_semantics"]["missing_wait_items"]],
            },
        },
        "exports": writing_export_audit,
    }
    if legal_con:
        legal_con.close()
    if case_con:
        case_con.close()
    return report


def markdown_report(report: dict[str, Any]) -> str:
    selection = report["selection"]
    totals = report["citation_totals"]
    findings = report["aggregate_findings"]
    lines = [
        "# AI 产物离线语义核验报告",
        "",
        "本报告只读取已保存的 GLM 运行 JSON、导出文件和本地 SQLite；本次运行未调用模型、未读取密钥。暂停/被恢复的初始快照作为中间状态，使用对应 `*-resumed.json` 作为最终内容；终态失败仍保留在最终尝试清单中。",
        "",
        f"- 最终运行：{selection['final_run_count']}（search {selection['search_final_count']}、writing {selection['writing_final_count']}、chat {selection['chat_final_count']}）；中间状态：{selection['intermediate_count']}。",
        f"- 最终引用对象：{totals['final_citation_objects']}，唯一 source ID：{totals['unique_source_ids']}；案例引用：{totals['by_kind'].get('case', 0)}。",
        f"- 数据库引用完整性：{findings['tool_constraints']['status']}；模型语义状态：{findings['model_semantics']['status']}。两个状态分别表示工具约束和内容语义，不能互相替代。",
        "",
        "## 运行逐项结果",
        "",
        "| 类型 | 文件 | 状态 | 模型语义 | 工具约束 | 引用数 | 未补事项 |",
        "| --- | --- | --- | --- | --- | ---: | ---: |",
    ]
    for row in report["runs"]:
        lines.append(
            f"| {row['kind']} | `{row['source_file']}` | {row['status']} | {row['model_semantics']['status']} | {row['tool_constraints']['status']} | {row['tool_constraints']['citation_validation']['count']} | {len(row['model_semantics']['missing_wait_items'])} |"
        )
    lines.extend(
        [
            "",
            "## 语义发现",
            "",
            f"金额/主体直接事实错误：{findings['model_semantics']['fact_error_count']}；声称已付清或无欠款：{findings['model_semantics']['payment_contradiction_count']}；具体法院候选：{findings['model_semantics']['specific_court_candidate_count']}；姓名候选：{findings['model_semantics']['person_candidate_count']}；具体程序结果断言：{findings['model_semantics'].get('specific_procedural_claim_count', 0)}。",
            f"需要人工复核的无依据或过强结论：{findings['model_semantics']['unsupported_conclusion_count']}；遗漏法条条件：{findings['model_semantics'].get('article_condition_omission_count', 0)}；付款起算日期表述问题：{findings['model_semantics']['date_logic_issue_count']}。这些计数是审计提示，不把模型的法律推断自动当作事实错误。",
            "",
            "代表性问题：",
        ]
    )
    representative = findings["model_semantics"]["representative_findings"]
    if representative:
        for item in representative[:12]:
            lines.append(f"- `{item.get('reason', item.get('fact', 'finding'))}`：{item.get('context', item.get('text', item.get('matches', '')))}")
    else:
        lines.append("- 未发现直接金额/主体矛盾或具体法院、姓名编造候选。")
    lines.extend(
        [
            "",
            "## 引用与版本核验",
            "",
            f"本地法律库引用 ID 未找到：{totals['invalid_citations']}；版本/正文字段不一致：{totals['invalid_citations']}；quote 缺失：{totals['missing_quotes']}；quote 与正文不匹配：{totals['quote_mismatches']}；正文明确写出的法条号未匹配到同法名引用：{totals['uncited_statutory_claims']}。",
            "quote 缺失按 review 记录；其余 ID、文号、法律名称、版本、效力状态、起止日期和正文按数据库逐字段核验。",
            f"便携包案例搜索结果：{report['portable_case_search']['status']}；案例引用 ID、标题、来源 URL、全文和 quote 的逐字段结果详见 JSON。",
            "",
            "## 待补事实",
            "",
        ]
    )
    missing = findings["missing_wait_items"]["by_run"]
    if missing:
        for row in missing:
            lines.append(f"- `{row['run_id']}`：" + "、".join(item["topic"] for item in row["items"]))
    else:
        lines.append("- 9 个最终正文均覆盖预设的待补事实主题。")
    lines.extend(
        [
            "",
            "## 导出检查",
            "",
            f"检查导出集合：{len(report['exports']['export_sets'])}；缺失文件：{report['exports']['missing_file_count']}；TXT 含 Markdown 围栏：{report['exports']['txt_markdown_fence_count']}。PDF/DOCX 文本读取失败时详见 JSON。",
            "",
            "## 文件与数据库来源",
            "",
            f"法律库元数据：`{report['database']['legal_metadata']}`。案例库元数据：`{report['database']['case_metadata']}`；案例类型计数：`{report['database']['case_counts']}`。",
            "详尽逐条结果、文件清单和上下文保存在同目录 `semantic-report.json`。",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-dir", type=Path, default=DEFAULT_LIVE_DIR)
    parser.add_argument("--legal-db", type=Path, default=DEFAULT_LEGAL_DB)
    parser.add_argument("--case-db", type=Path, default=DEFAULT_CASE_DB)
    parser.add_argument("--portable-case-result", type=Path, default=DEFAULT_PORTABLE_CASE_RESULT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    live_dir = normalize_path(args.live_dir)
    legal_db = normalize_path(args.legal_db)
    case_db = normalize_path(args.case_db)
    portable_case_result = normalize_path(args.portable_case_result) if args.portable_case_result else None
    output_dir = normalize_path(args.output_dir)
    report = run_semantic_audit(live_dir, legal_db, case_db, portable_case_result)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "semantic-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "semantic-report.md").write_text(markdown_report(report), encoding="utf-8")
    print(json.dumps({"output_dir": str(output_dir), "citation_totals": report["citation_totals"], "selection": report["selection"], "statuses": {"model_semantics": report["aggregate_findings"]["model_semantics"]["status"], "tool_constraints": report["aggregate_findings"]["tool_constraints"]["status"], "portable_case_search": report["portable_case_search"]["status"]}}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
