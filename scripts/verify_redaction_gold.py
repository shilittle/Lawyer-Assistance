#!/usr/bin/env python3
"""Compare saved redaction exports with the independent blind annotation.

This checker deliberately treats the export text as the only publishable AI
output.  A ``ready`` material whose TXT export is missing is therefore
reported as ``not_evaluable``; the analysis snapshot is useful for diagnosis
but is never used to turn a missing export into a passing result.

The input report is the JSON written by ``smoke_redaction_live.mjs``.  Pass
either that JSON file or an attempt directory with ``--report``.  The checker
only writes ``gold-comparison.json`` and ``gold-comparison-report.md`` in the
attempt directory, so it cannot replace the redaction report, material
snapshots, exports, or workspace database.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GOLD = ROOT / "output" / "ai-upgrade-annotation" / "gold.json"
DEFAULT_MANIFEST = ROOT / "output" / "ai-upgrade-fixtures" / "manifest.json"
DEFAULT_REPORT = ROOT / "output" / "ai-upgrade-redaction" / "redaction-report.json"

_PUNCTUATION = {"，", "。", "、", "；", "：", "！", "？", "（", "）", "【", "】", "《", "》", "“", "”", "‘", "’", "「", "」", "『", "』", "—", "–", "-", ",", ".", ";", ":", "!", "?", "(", ")", "[", "]", "{", "}", "<", ">", '"', "'", "/", "\\", "|", "·", "…", "~", "="}
_CN_DIGITS = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_CN_SMALL_UNITS = {"十": 10, "百": 100, "千": 1000}
_CN_LARGE_UNITS = {"万": 10_000, "亿": 100_000_000}
_QUOTE_TRANSLATION = str.maketrans({"‘": "'", "’": "'", "‚": "'", "‛": "'", "“": '"', "”": '"', "„": '"', "‟": '"'})


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"JSON object expected: {path}")
    return value


def clean_path(value: Any) -> str:
    """Make report and gold material paths comparable without guessing files."""

    if not isinstance(value, str):
        return ""
    text = value.replace("\\", "/").strip()
    if not text:
        return ""
    text = re.sub(r"^\./+", "", text)
    # Absolute report paths are reduced at the fixture materials boundary.
    marker = "/materials/"
    lowered = text.lower()
    index = lowered.find(marker)
    if index >= 0:
        text = text[index + 1 :]
    elif lowered.startswith("materials/"):
        text = text
    return text


def resolve_report_path(argument: Path) -> Path:
    if argument.is_dir():
        candidate = argument / "redaction-report.json"
        if not candidate.exists():
            raise FileNotFoundError(f"attempt directory has no redaction-report.json: {argument}")
        return candidate
    return argument


def compact(text: str) -> str:
    """Normalize Unicode and separators for a cautious near-match diagnostic."""

    normalized = unicodedata.normalize("NFKC", text).casefold()
    return "".join(ch for ch in normalized if not ch.isspace() and ch not in _PUNCTUATION)


def normalized_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).translate(_QUOTE_TRANSLATION)
    return re.sub(r"\s+", "", normalized)


def occurrence_count(text: str, needle: str) -> int:
    if not needle:
        return 0
    return sum(1 for _ in re.finditer(re.escape(needle), text))


def unique_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def entity_texts(record: dict[str, Any]) -> list[str]:
    entities = record.get("entities") or []
    if not isinstance(entities, list):
        return []
    return unique_strings(
        item.get("text", "")
        for item in entities
        if isinstance(item, dict) and isinstance(item.get("text"), str)
    )


def protected_anchor_segments(text: str, entities: Iterable[str]) -> list[str]:
    """Return factual pieces around entities, allowing aliases in the output.

    The gold snippets intentionally contain names and organizations.  Requiring
    the whole snippet would call a correct replacement a fact loss.  Splitting
    around the independently annotated entity strings retains the surrounding
    factual anchors while making that distinction explicit.
    """

    segments = [text]
    for entity in sorted(unique_strings(entities), key=len, reverse=True):
        next_segments: list[str] = []
        for segment in segments:
            next_segments.extend(re.split(re.escape(entity), segment))
        segments = next_segments
    return [normalized_text(segment) for segment in segments if len(normalized_text(segment)) >= 2]


def content_anchor_tokens(text: str) -> list[str]:
    """Extract factual runs while allowing OCR/text-layer insertions.

    OCR and PDF text layers may add a page header or a short connective phrase
    without changing the fact.  Dates and amounts are kept as whole tokens;
    remaining Chinese runs of at least two characters are checked in order of
    presence.  This intentionally does not use fuzzy edit distance, which
    could hide a changed amount, date, or legal fact.
    """

    normalized = normalized_text(text)
    tokens: list[str] = []
    protected: list[tuple[int, int]] = []
    for pattern in (
        r"\d{4}[-/.年]\d{1,2}[-/.月]\d{1,2}日?",
        r"(?:\d{1,3}(?:,\d{3})+|\d{4,})(?:\.\d+)?\s*(?:人民币|元|万元|万|亿元|亿)?",
        r"[零〇一二两三四五六七八九十百千万亿]+(?:人民币|元|万元|万|亿元|亿)",
    ):
        for match in re.finditer(pattern, normalized):
            if any(start <= match.start() < end or start < match.end() <= end for start, end in protected):
                continue
            protected.append((match.start(), match.end()))
            tokens.append(match.group(0))
    mask = list(normalized)
    for start, end in protected:
        for index in range(start, end):
            mask[index] = " "
    remainder = "".join(mask)
    tokens.extend(re.findall(r"[\u3400-\u9fff]{2,}|[A-Za-z][A-Za-z0-9_.-]{1,}", remainder))
    return unique_strings(tokens)


def _token_present_equivalent(token: str, actual: str) -> tuple[bool, str | None]:
    """Match one factual token without weakening date/amount value checks.

    The OCR gold contains both ASCII and Chinese date renderings, while DOCX
    extraction can insert punctuation or table whitespace between Chinese
    runs.  A compact match is only a representation diagnostic; date and
    amount values are still checked separately by ``date_check`` and
    ``amount_check`` before an item can pass.
    """

    token_norm = normalized_text(token)
    actual_norm = normalized_text(actual)
    if token_norm and token_norm in actual_norm:
        return True, None

    token_compact = compact(token)
    actual_compact = compact(actual)
    if token_compact and token_compact in actual_compact:
        return True, "compact_punctuation_whitespace"

    expected_date = date_key(token)
    if expected_date is not None:
        source = unicodedata.normalize("NFKC", actual)
        observed = [
            match.group(0)
            for match in re.finditer(
                r"\d{4}\s*(?:[-/.年])\s*\d{1,2}\s*(?:[-/.月])\s*\d{1,2}\s*日?",
                source,
            )
            if date_key(match.group(0)) == expected_date
        ]
        if observed:
            return True, "date_value_equivalent"

    # Do not interpret short identifiers such as C03 as amounts.  The
    # dedicated amount checker remains the authority for numeric facts.
    if re.search(r"(?:人民币|元|万元|万|亿元|亿)", token):
        expected_amount = amount_value(token)
        if expected_amount is not None:
            observed = [
                raw
                for raw, value in amount_candidates(actual)
                if value == expected_amount
            ]
            if observed:
                return True, "amount_value_equivalent"

    return False, None


def anchor_check(text: str, expected: str, entities: Iterable[str]) -> dict[str, Any]:
    expected_norm = normalized_text(expected)
    actual_norm = normalized_text(text)
    if expected_norm and expected_norm in actual_norm:
        return {"status": "exact" if expected in text else "format_equivalent", "expected": expected}
    expected_compact = compact(expected)
    actual_compact = compact(text)
    if expected_compact and expected_compact in actual_compact:
        return {
            "status": "format_equivalent",
            "expected": expected,
            "matching": "compact punctuation/whitespace",
        }
    segments = protected_anchor_segments(expected, entities)
    missing: list[str] = []
    matched_by_tokens = False
    equivalent_tokens: list[dict[str, str]] = []
    for segment in segments:
        if segment in actual_norm:
            continue
        tokens = content_anchor_tokens(segment)
        missing_tokens: list[str] = []
        for token in tokens:
            matched, mode = _token_present_equivalent(token, text)
            if matched:
                if mode:
                    equivalent_tokens.append({"token": token, "matching": mode})
                continue
            missing_tokens.append(token)
        if tokens and not missing_tokens:
            matched_by_tokens = True
            continue
        missing.extend(missing_tokens or [segment])
    if not missing:
        return {
            "status": "redaction_tolerant" if entities else "content_tolerant",
            "expected": expected,
            "anchors_checked": segments,
            "content_tokens_checked": [token for segment in segments for token in content_anchor_tokens(segment)] if matched_by_tokens else [],
            "equivalent_tokens": equivalent_tokens,
        }
    return {
        "status": "missing_anchors",
        "expected": expected,
        "anchors_checked": segments,
        "missing_anchors": missing,
    }


def chinese_number(text: str) -> Decimal | None:
    """Parse common Chinese integer numerals used in amount renderings."""

    if not text or not any(ch in _CN_DIGITS or ch in _CN_SMALL_UNITS or ch in _CN_LARGE_UNITS for ch in text):
        return None
    total = 0
    section = 0
    number = 0
    for char in text:
        if char in _CN_DIGITS:
            number = _CN_DIGITS[char]
        elif char in _CN_SMALL_UNITS:
            unit = _CN_SMALL_UNITS[char]
            if number == 0:
                number = 1
            section += number * unit
            number = 0
        elif char in _CN_LARGE_UNITS:
            unit = _CN_LARGE_UNITS[char]
            section += number
            if section == 0:
                section = 1
            total += section * unit
            section = 0
            number = 0
        else:
            return None
    value = total + section + number
    return Decimal(value)


def amount_value(text: str) -> Decimal | None:
    normalized = unicodedata.normalize("NFKC", text).replace(",", "").replace("，", "")
    normalized = normalized.strip()
    match = re.search(r"(\d+(?:\.\d+)?)(?:\s*)(万|亿)?", normalized)
    if match:
        try:
            value = Decimal(match.group(1))
        except InvalidOperation:
            return None
        multiplier = {"万": Decimal(10000), "亿": Decimal(100000000)}.get(match.group(2), Decimal(1))
        return value * multiplier
    chinese = re.search(r"[零〇一二两三四五六七八九十百千万亿]+", normalized)
    if not chinese:
        return None
    value = chinese_number(chinese.group(0))
    if value is None:
        return None
    return value


def amount_candidates(text: str) -> list[tuple[str, Decimal]]:
    normalized = unicodedata.normalize("NFKC", text)
    values: list[tuple[str, Decimal]] = []
    # Numeric amounts with an explicit unit are preferred; a long decimal or
    # comma-grouped value without 元 is also useful for a changed-value hint.
    pattern = re.compile(r"(?<![\d])(?:\d{1,3}(?:,\d{3})+|\d{4,})(?:\.\d+)?\s*(?:人民币|元|万元|万|亿元|亿)?")
    for match in pattern.finditer(normalized):
        raw = match.group(0).strip()
        if re.fullmatch(r"\d{4}[-/.年]\d{1,2}[-/.月]\d{1,2}日?", raw):
            continue
        value = amount_value(raw)
        if value is not None:
            values.append((raw, value))
    for match in re.finditer(r"[零〇一二两三四五六七八九十百千万亿]+(?:元|万元|万|亿元|亿)", normalized):
        raw = match.group(0)
        value = amount_value(raw)
        if value is not None:
            values.append((raw, value))
    return values


def amount_check(text: str, expected: str) -> dict[str, Any]:
    if expected in text:
        return {"status": "exact", "expected": expected, "value": str(amount_value(expected))}
    expected_value = amount_value(expected)
    if expected_value is None:
        return {"status": "unparsed_expected", "expected": expected}
    candidates = amount_candidates(text)
    equivalent = [raw for raw, value in candidates if value == expected_value]
    if equivalent:
        return {
            "status": "format_equivalent",
            "expected": expected,
            "value": str(expected_value),
            "equivalent_renderings": unique_strings(equivalent),
        }
    return {
        "status": "missing_or_value_changed",
        "expected": expected,
        "value": str(expected_value),
        "observed_amounts": [{"text": raw, "value": str(value)} for raw, value in candidates],
    }


def date_key(text: str) -> tuple[int, int, int] | None:
    normalized = unicodedata.normalize("NFKC", text)
    match = re.search(r"(\d{4})\s*(?:[-/.年])\s*(\d{1,2})\s*(?:[-/.月])\s*(\d{1,2})\s*日?", normalized)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def date_check(text: str, expected: str) -> dict[str, Any]:
    expected_key = date_key(expected)
    actual_norm = unicodedata.normalize("NFKC", text)
    if expected in actual_norm:
        return {"status": "exact", "expected": expected, "date": list(expected_key or ())}
    if expected_key is None:
        return {"status": "unparsed_expected", "expected": expected}
    observed: list[str] = []
    for match in re.finditer(r"\d{4}\s*(?:[-/.年])\s*\d{1,2}\s*(?:[-/.月])\s*\d{1,2}\s*日?", actual_norm):
        if date_key(match.group(0)) == expected_key:
            observed.append(match.group(0))
    if observed:
        return {"status": "format_equivalent", "expected": expected, "date": list(expected_key), "equivalent_renderings": unique_strings(observed)}
    return {"status": "missing_or_changed", "expected": expected, "date": list(expected_key)}


def find_snapshot(report_dir: Path, material_id: str) -> tuple[Path | None, dict[str, Any] | None]:
    if not material_id:
        return None, None
    candidates = [report_dir / f"{material_id}.json"]
    candidates.extend(path for path in report_dir.rglob(f"{material_id}.json") if path not in candidates)
    for candidate in candidates:
        if candidate.is_file():
            try:
                return candidate, load_json(candidate)
            except (OSError, ValueError, json.JSONDecodeError):
                return candidate, None
    return None, None


def export_candidates(item: dict[str, Any], report_dir: Path) -> list[Path]:
    values: list[Path] = []
    for key in ("export_path", "txt_path", "export", "result_export"):
        value = item.get(key)
        if not isinstance(value, str) or not value:
            continue
        path = Path(value)
        values.append(path if path.is_absolute() else report_dir / path)
    material_id = item.get("material_id") or item.get("id")
    result_id = item.get("result_id")
    for token in (material_id, result_id):
        if isinstance(token, str) and token:
            values.append(report_dir / f"{token}.txt")
            values.extend(report_dir.rglob(f"{token}.txt"))
    result: list[Path] = []
    seen: set[Path] = set()
    for path in values:
        try:
            canonical = path.resolve()
        except OSError:
            canonical = path
        if canonical not in seen:
            seen.add(canonical)
            result.append(path)
    return result


def read_export(item: dict[str, Any], report_dir: Path) -> tuple[Path | None, str | None, str | None]:
    for path in export_candidates(item, report_dir):
        if not path.is_file():
            continue
        try:
            return path, path.read_text(encoding="utf-8"), None
        except UnicodeDecodeError as exc:
            return path, None, f"invalid_utf8: {exc}"
        except OSError as exc:
            return path, None, f"read_failed: {exc}"
    return None, None, None


def path_record_map(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if isinstance(record, dict):
            result[clean_path(record.get("material_path"))].append(record)
    return result


def find_gold(material: dict[str, Any], gold_by_path: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    path = clean_path(material.get("path"))
    exact = gold_by_path.get(path, [])
    if exact:
        return exact[0]
    case_id = material.get("case_id")
    name = Path(path).name
    candidates = [
        record
        for records in gold_by_path.values()
        for record in records
        if record.get("case_id") == case_id and Path(clean_path(record.get("material_path"))).name == name
    ]
    return candidates[0] if len(candidates) == 1 else None


def actual_status(item: dict[str, Any]) -> str:
    value = item.get("status")
    return value if isinstance(value, str) and value else "missing_status"


def _finding_projection(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "text": finding.get("text"),
        "kind": finding.get("kind"),
        "source": finding.get("source"),
        "resolved": finding.get("resolved"),
        "dismissed": finding.get("dismissed"),
        "alias": finding.get("alias"),
        "id": finding.get("id"),
    }


def _replacement_projection(replacement: dict[str, Any]) -> dict[str, Any]:
    return {
        key: replacement.get(key)
        for key in (
            "findingId",
            "alias",
            "sourceStart",
            "sourceEnd",
            "outputStart",
            "outputEnd",
        )
        if key in replacement
    }


def _finding_duplicate_groups(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        text = finding.get("text")
        if isinstance(text, str) and compact(text):
            groups[compact(text)].append(finding)
    result: list[dict[str, Any]] = []
    for key, group in groups.items():
        if len(group) < 2:
            continue
        result.append(
            {
                "normalized_text": key,
                "texts": unique_strings(
                    finding.get("text", "") for finding in group if isinstance(finding.get("text"), str)
                ),
                "count": len(group),
                "unresolved_count": sum(finding.get("resolved") is False for finding in group),
                "kinds": sorted({str(finding.get("kind") or "unknown") for finding in group}),
                "sources": sorted({str(finding.get("source") or "unknown") for finding in group}),
            }
        )
    return sorted(result, key=lambda row: (-row["unresolved_count"], -row["count"], row["normalized_text"]))


def _nested_kind_conflicts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find overlapping candidate spans whose inferred kinds disagree.

    Snapshots currently persist the candidate text rather than candidate
    offsets.  A strict compact-substring relation is therefore used as a
    conservative overlap proxy; it is reported as a diagnostic, not asserted
    to be an exact character-span conflict.
    """

    rows: set[tuple[str, str, str, str]] = set()
    for index, left in enumerate(findings):
        left_text = left.get("text")
        left_kind = str(left.get("kind") or "unknown")
        left_key = compact(left_text) if isinstance(left_text, str) else ""
        if len(left_key) < 2:
            continue
        for right in findings[index + 1 :]:
            right_text = right.get("text")
            right_kind = str(right.get("kind") or "unknown")
            right_key = compact(right_text) if isinstance(right_text, str) else ""
            if len(right_key) < 2 or left_kind == right_kind or left_key == right_key:
                continue
            if left_key in right_key or right_key in left_key:
                short_text, long_text = (left_text, right_text) if len(left_key) <= len(right_key) else (right_text, left_text)
                short_kind, long_kind = (left_kind, right_kind) if len(left_key) <= len(right_key) else (right_kind, left_kind)
                rows.add((str(short_text), short_kind, str(long_text), long_kind))
    return [
        {"shorter_text": short, "shorter_kind": short_kind, "longer_text": long, "longer_kind": long_kind}
        for short, short_kind, long, long_kind in sorted(rows)
    ]


def analysis_summary(
    snapshot: dict[str, Any] | None,
    gold: dict[str, Any] | None = None,
    case_id: str | None = None,
) -> dict[str, Any] | None:
    if not isinstance(snapshot, dict):
        return None
    analysis = snapshot.get("analysis")
    if not isinstance(analysis, dict):
        return {"available": False}
    findings = analysis.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    findings = [finding for finding in findings if isinstance(finding, dict)]
    unresolved = [
        finding.get("text", "")
        for finding in findings
        if finding.get("resolved") is False
    ]
    resolved_count = sum(finding.get("resolved") is True for finding in findings)
    source_counts = Counter(str(finding.get("source") or "unknown") for finding in findings)
    unresolved_source_counts = Counter(str(finding.get("source") or "unknown") for finding in findings if finding.get("resolved") is False)
    kind_counts = Counter(str(finding.get("kind") or "unknown") for finding in findings)
    unresolved_kind_counts = Counter(str(finding.get("kind") or "unknown") for finding in findings if finding.get("resolved") is False)
    replacements = analysis.get("replacements") or []
    if not isinstance(replacements, list):
        replacements = []
    result: dict[str, Any] = {
        "available": True,
        "needs_review": bool(analysis.get("needsReview")),
        "finding_count": len(findings),
        "resolved_count": resolved_count,
        "unresolved_count": len(unresolved),
        "unresolved_text": unique_strings(value for value in unresolved if isinstance(value, str)),
        "finding_source_counts": dict(sorted(source_counts.items())),
        "unresolved_source_counts": dict(sorted(unresolved_source_counts.items())),
        "finding_kind_counts": dict(sorted(kind_counts.items())),
        "unresolved_kind_counts": dict(sorted(unresolved_kind_counts.items())),
        "findings": [_finding_projection(finding) for finding in findings],
        "replacements": [_replacement_projection(replacement) for replacement in replacements if isinstance(replacement, dict)],
        "replacement_count": len(replacements),
        "duplicate_finding_groups": _finding_duplicate_groups(findings),
        "nested_kind_conflicts": _nested_kind_conflicts(findings),
    }
    analysis_text = analysis.get("text") if isinstance(analysis.get("text"), str) else ""
    original_text = snapshot.get("original_text") if isinstance(snapshot.get("original_text"), str) else ""
    if gold is not None:
        residuals: list[dict[str, Any]] = []
        compact_analysis = compact(analysis_text)
        for entity in entity_texts(gold):
            exact_count = occurrence_count(analysis_text, entity)
            near_count = occurrence_count(compact_analysis, compact(entity)) if compact(entity) else 0
            if exact_count or near_count:
                residuals.append(
                    {
                        "text": entity,
                        "original_occurrences": occurrence_count(original_text, entity),
                        "exact_residual_occurrences": exact_count,
                        "normalized_residual_occurrences": near_count,
                    }
                )
        result["analysis_text_gold_residuals"] = residuals
        result["analysis_text_gold_residual_count"] = len(residuals)
        gold_entities = [(entity, compact(entity)) for entity in entity_texts(gold)]
        match_counts: Counter[str] = Counter()
        unresolved_gold_matches: list[dict[str, Any]] = []
        for finding in findings:
            finding_text = finding.get("text")
            finding_key = compact(finding_text) if isinstance(finding_text, str) else ""
            match_kind = "none"
            matched_entity = None
            for entity, entity_key in gold_entities:
                if finding_key and finding_key == entity_key:
                    match_kind = "exact"
                    matched_entity = entity
                    break
                if finding_key and entity_key and (finding_key in entity_key or entity_key in finding_key):
                    match_kind = "overlap"
                    matched_entity = entity
            match_counts[match_kind] += 1
            if finding.get("resolved") is False:
                unresolved_gold_matches.append(
                    {
                        **_finding_projection(finding),
                        "gold_match": match_kind,
                        "matched_gold_entity": matched_entity,
                    }
                )
        result["gold_match_counts"] = dict(sorted(match_counts.items()))
        result["unresolved_gold_match_counts"] = dict(
            sorted(Counter(item["gold_match"] for item in unresolved_gold_matches).items())
        )
        result["unresolved_gold_matches"] = unresolved_gold_matches
    else:
        result["analysis_text_gold_residuals"] = []
        result["analysis_text_gold_residual_count"] = None
        result["gold_match_counts"] = {}
        result["unresolved_gold_match_counts"] = {}
        result["unresolved_gold_matches"] = []
    same_name_entities = [
        entity.get("text")
        for entity in (gold or {}).get("entities", [])
        if isinstance(entity, dict) and entity.get("category") == "same_name_persons" and isinstance(entity.get("text"), str)
    ]
    same_name_findings = [
        finding
        for finding in findings
        if finding.get("text") in same_name_entities
    ]
    if same_name_findings:
        result["same_name_ambiguity"] = {
            "expected_review": case_id == "C07",
            "finding_count": len(same_name_findings),
            "distinct_aliases": unique_strings(
                finding.get("alias", "") for finding in same_name_findings if isinstance(finding.get("alias"), str)
            ),
            "unresolved_count": sum(finding.get("resolved") is False for finding in same_name_findings),
            "note": "C07 has two independently annotated persons with the same name; one shared alias across contexts requires identity review.",
        }
    return result


def compare_ready(gold: dict[str, Any], text: str) -> dict[str, Any]:
    entities = entity_texts(gold)
    residuals: list[dict[str, Any]] = []
    compact_output = compact(text)
    for entity in entities:
        exact_count = occurrence_count(text, entity)
        normalized_entity = compact(entity)
        near_count = occurrence_count(compact_output, normalized_entity) if normalized_entity else 0
        row = {
            "text": entity,
            "category": [
                item.get("category")
                for item in (gold.get("entities") or [])
                if isinstance(item, dict) and item.get("text") == entity
            ],
            "original_occurrences": occurrence_count(gold.get("_original_text", ""), entity),
            "exact_residual_occurrences": exact_count,
            "normalized_residual_occurrences": near_count,
        }
        if exact_count or near_count:
            residuals.append(row)

    facts = gold.get("preserve_facts") or {}
    dates = [date_check(text, value) for value in facts.get("dates", []) if isinstance(value, str)]
    amounts = [amount_check(text, value) for value in facts.get("amounts", []) if isinstance(value, str)]
    snippets = [
        anchor_check(text, value, entities)
        for value in facts.get("key_snippets", [])
        if isinstance(value, str)
    ]
    ocr_expected = [value for value in (gold.get("ocr_expected_text") or []) if isinstance(value, str)]
    ocr = [anchor_check(text, value, entities) for value in ocr_expected]
    return {
        "sensitive_residual": {
            "status": "fail" if residuals else "pass",
            "residual_count": len(residuals),
            "residuals": residuals,
            "matching": "exact plus NFKC/space/punctuation compact diagnostic",
        },
        "facts": {
            "dates": dates,
            "amounts": amounts,
            "key_snippets": snippets,
            "missing_date_count": sum(row["status"] not in {"exact", "format_equivalent"} for row in dates),
            "missing_amount_count": sum(row["status"] not in {"exact", "format_equivalent"} for row in amounts),
            "missing_snippet_count": sum(row["status"] == "missing_anchors" for row in snippets),
        },
        "ocr": {
            "status": (
                "not_applicable"
                if not ocr_expected
                else "fail" if any(row["status"] == "missing_anchors" for row in ocr) else "pass"
            ),
            "expected_count": len(ocr_expected),
            "missing_count": sum(row["status"] == "missing_anchors" for row in ocr),
            "lines": ocr,
        },
    }


def evaluate_item(material: dict[str, Any], gold: dict[str, Any] | None, report_dir: Path) -> dict[str, Any]:
    material_id = material.get("material_id") or material.get("id")
    snapshot_path, snapshot = find_snapshot(report_dir, material_id if isinstance(material_id, str) else "")
    export_path, export_text, export_error = read_export(material, report_dir)
    status = actual_status(material)
    base: dict[str, Any] = {
        "case_id": material.get("case_id"),
        "path": clean_path(material.get("path")),
        "format": material.get("format"),
        "material_id": material_id,
        "expected_file_status": gold.get("file_status") if gold else None,
        "actual": {
            "status": status,
            "reason_code": material.get("reason_code"),
            "result_id": material.get("result_id"),
            "result_error": material.get("result_error"),
            "snapshot_path": str(snapshot_path.relative_to(ROOT)) if snapshot_path and snapshot_path.is_relative_to(ROOT) else str(snapshot_path) if snapshot_path else None,
            "export_path": str(export_path.relative_to(ROOT)) if export_path and export_path.is_relative_to(ROOT) else str(export_path) if export_path else None,
            "export_error": export_error,
            "export_bytes": len(export_text.encode("utf-8")) if export_text is not None else None,
        },
        "analysis_snapshot": analysis_summary(snapshot, gold, material.get("case_id")),
    }
    if gold is None:
        base.update({"evaluation": "unknown_material", "issues": ["no matching blind-gold record"]})
        return base

    expected_damaged = gold.get("file_status") == "must_fail_closed"
    if expected_damaged:
        safe = status in {"failed", "needs_review"} and export_path is None and not material.get("result_id")
        base.update(
            {
                "evaluation": "fail_closed_pass" if safe else "fail_closed_violation",
                "fail_closed": {
                    "expected": True,
                    "status_is_nonpublishable": status in {"failed", "needs_review"},
                    "no_result_id": not bool(material.get("result_id")),
                    "no_export": export_path is None,
                },
            }
        )
        if not safe:
            base["issues"] = ["damaged input was published or did not fail closed"]
        return base

    if status == "needs_review":
        base.update({"evaluation": "needs_review", "issues": [material.get("reason_code") or "manual review required"]})
        return base
    if status in {"queued", "running", "pending", "processing"}:
        base.update({"evaluation": "in_progress", "issues": ["task has not reached a terminal status"]})
        return base
    if status in {"failed", "cancelled", "canceled"}:
        base.update({"evaluation": "failed", "issues": [material.get("reason_code") or status]})
        return base
    if status != "ready":
        base.update({"evaluation": "unknown_status", "issues": [material.get("reason_code") or status]})
        return base
    if export_error or export_text is None:
        base.update(
            {
                "evaluation": "not_evaluable",
                "issues": ["ready result has no readable TXT export"],
                "export_diagnostic": {
                    "analysis_available_without_export": bool(snapshot and isinstance(snapshot.get("analysis"), dict)),
                    "result_error": material.get("result_error"),
                },
            }
        )
        return base
    if not export_text.strip():
        base.update({"evaluation": "not_evaluable", "issues": ["ready TXT export is empty"]})
        return base

    gold_with_original = dict(gold)
    # The original text is only used to report expected entity occurrence
    # counts.  It is taken from the material snapshot when available, never
    # from a secret or protected workspace database.
    if isinstance(snapshot, dict) and isinstance(snapshot.get("original_text"), str):
        gold_with_original["_original_text"] = snapshot["original_text"]
    comparison = compare_ready(gold_with_original, export_text)
    c07_ambiguous = gold.get("case_id") == "C07" and any(
        isinstance(entity, dict) and entity.get("category") == "same_name_persons"
        for entity in (gold.get("entities") or [])
    )
    issues: list[str] = []
    if comparison["sensitive_residual"]["status"] == "fail":
        issues.append("annotated sensitive entity remains in export")
    if comparison["facts"]["missing_date_count"] or comparison["facts"]["missing_amount_count"] or comparison["facts"]["missing_snippet_count"]:
        issues.append("date, amount, or factual anchor is missing/changed")
    if comparison["ocr"]["status"] == "fail":
        issues.append("OCR expected text has missing anchors")
    if c07_ambiguous:
        issues.append("C07 same-name ambiguity requires review; ready output is not accepted")
    base.update(comparison)
    base.update({"evaluation": "fail" if issues else "pass", "issues": issues})
    return base


def expected_counts(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(record.get(key, "") for record in records if record.get(key)).items()))


def build_report(
    gold: dict[str, Any],
    manifest: dict[str, Any],
    observed: dict[str, Any],
    report_path: Path,
    gold_path: Path = DEFAULT_GOLD,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    gold_records = [record for record in gold.get("records", []) if isinstance(record, dict)]
    material_value = observed.get("materials", observed.get("results", []))
    if not isinstance(material_value, list):
        material_value = []
    materials = [item for item in material_value if isinstance(item, dict)]
    gold_by_path = path_record_map(gold_records)
    comparisons: list[dict[str, Any]] = []
    for material in materials:
        gold_record = find_gold(material, gold_by_path)
        if gold_record is not None:
            gold_record = dict(gold_record)
            snapshot_path, snapshot = find_snapshot(report_path.parent, str(material.get("material_id") or material.get("id") or ""))
            if isinstance(snapshot, dict) and isinstance(snapshot.get("original_text"), str):
                gold_record["_original_text"] = snapshot["original_text"]
        comparisons.append(evaluate_item(material, gold_record, report_path.parent))

    observed_paths = [clean_path(item.get("path")) for item in materials if clean_path(item.get("path"))]
    duplicate_paths = sorted(path for path, count in Counter(observed_paths).items() if count > 1)
    expected_format_counts = expected_counts(gold_records, "format")
    observed_format_counts = expected_counts(materials, "format")
    format_names = sorted(set(expected_format_counts) | set(observed_format_counts))
    format_counts = {
        name: {
            "expected": expected_format_counts.get(name, 0),
            "observed": observed_format_counts.get(name, 0),
            "delta": observed_format_counts.get(name, 0) - expected_format_counts.get(name, 0),
        }
        for name in format_names
    }
    status_counts = dict(sorted(Counter(actual_status(item) for item in materials).items()))
    evaluation_counts = dict(sorted(Counter(row.get("evaluation", "unknown") for row in comparisons).items()))
    ready_items = [row for row in comparisons if row["actual"]["status"] == "ready"]
    ready_evaluable = [row for row in ready_items if row.get("evaluation") in {"pass", "fail"}]
    passed = sum(row.get("evaluation") == "pass" for row in ready_evaluable)
    c07 = [row for row in comparisons if row.get("case_id") == "C07"]
    damaged = [row for row in comparisons if row.get("expected_file_status") == "must_fail_closed"]
    report_errors = observed.get("errors") if isinstance(observed.get("errors"), list) else []
    missing_gold = sorted(set(gold_by_path) - set(observed_paths))
    unknown_observed = [row for row in comparisons if row.get("evaluation") == "unknown_material"]
    c07_needs_review = sum(row["actual"]["status"] == "needs_review" for row in c07)
    c07_ready = sum(row["actual"]["status"] == "ready" for row in c07)
    c07_failed = sum(row["actual"]["status"] == "failed" for row in c07)
    if not c07:
        c07_outcome = "not_observed"
    elif c07_ready:
        c07_outcome = "review_violation_ready_output"
    elif c07_failed:
        c07_outcome = "review_observed_but_some_materials_failed"
    else:
        c07_outcome = "review_observed"
    review_rows = [
        row
        for row in comparisons
        if row["actual"]["status"] == "needs_review" and isinstance(row.get("analysis_snapshot"), dict)
    ]

    def merge_snapshot_counters(key: str) -> dict[str, int]:
        merged: Counter[str] = Counter()
        for row in review_rows:
            snapshot = row["analysis_snapshot"]
            values = snapshot.get(key, {})
            if isinstance(values, dict):
                for name, count in values.items():
                    if isinstance(name, str) and isinstance(count, int):
                        merged[name] += count
        return dict(sorted(merged.items()))

    duplicate_groups: list[dict[str, Any]] = []
    nested_conflicts: list[dict[str, Any]] = []
    ordinary_duplicates: list[dict[str, Any]] = []
    unresolved_gold_matches: list[dict[str, Any]] = []
    for row in review_rows:
        snapshot = row["analysis_snapshot"]
        for group in snapshot.get("duplicate_finding_groups", []):
            if not isinstance(group, dict):
                continue
            projection = {
                "case_id": row.get("case_id"),
                "path": row.get("path"),
                **group,
            }
            duplicate_groups.append(projection)
            if row.get("case_id") != "C07":
                ordinary_duplicates.append(projection)
        for conflict in snapshot.get("nested_kind_conflicts", []):
            if isinstance(conflict, dict):
                nested_conflicts.append({"case_id": row.get("case_id"), "path": row.get("path"), **conflict})
        for finding in snapshot.get("unresolved_gold_matches", []):
            if isinstance(finding, dict):
                unresolved_gold_matches.append({"case_id": row.get("case_id"), "path": row.get("path"), **finding})
    residual_snapshot_count = sum(
        bool(row["analysis_snapshot"].get("analysis_text_gold_residuals")) for row in review_rows
    )
    residual_entity_count = sum(
        int(row["analysis_snapshot"].get("analysis_text_gold_residual_count") or 0) for row in review_rows
    )
    c07_review_rows = [row for row in review_rows if row.get("case_id") == "C07"]
    c07_same_name = [
        row["analysis_snapshot"].get("same_name_ambiguity")
        for row in c07_review_rows
        if isinstance(row["analysis_snapshot"].get("same_name_ambiguity"), dict)
    ]
    review_diagnostics = {
        "review_material_count": len(review_rows),
        "finding_count": sum(int(row["analysis_snapshot"].get("finding_count") or 0) for row in review_rows),
        "resolved_count": sum(int(row["analysis_snapshot"].get("resolved_count") or 0) for row in review_rows),
        "unresolved_count": sum(int(row["analysis_snapshot"].get("unresolved_count") or 0) for row in review_rows),
        "replacement_count": sum(int(row["analysis_snapshot"].get("replacement_count") or 0) for row in review_rows),
        "finding_source_counts": merge_snapshot_counters("finding_source_counts"),
        "unresolved_source_counts": merge_snapshot_counters("unresolved_source_counts"),
        "finding_kind_counts": merge_snapshot_counters("finding_kind_counts"),
        "unresolved_kind_counts": merge_snapshot_counters("unresolved_kind_counts"),
        "unresolved_gold_match_counts": dict(
            sorted(Counter(row.get("gold_match", "none") for row in unresolved_gold_matches).items())
        ),
        "unresolved_non_gold_findings": [
            row for row in unresolved_gold_matches if row.get("gold_match") == "none"
        ],
        "unresolved_gold_matches": unresolved_gold_matches,
        "analysis_text_gold_residual_snapshot_count": residual_snapshot_count,
        "analysis_text_gold_residual_entity_count": residual_entity_count,
        "duplicate_finding_group_count": len(duplicate_groups),
        "ordinary_non_c07_duplicate_group_count": len(ordinary_duplicates),
        "ordinary_non_c07_duplicate_groups": ordinary_duplicates,
        "nested_kind_conflict_count": len(nested_conflicts),
        "nested_kind_conflicts": nested_conflicts,
        "c07_same_name_ambiguity": {
            "review_material_count": len(c07_review_rows),
            "same_name_finding_material_count": len(c07_same_name),
            "details": c07_same_name,
            "interpretation": "C07 is an intentional identity ambiguity; it must remain reviewable. It is reported separately from repeated ordinary entities.",
        },
        "representative_review_materials": [
            {
                "case_id": row.get("case_id"),
                "path": row.get("path"),
                "format": row.get("format"),
                "reason_code": row["actual"].get("reason_code"),
                "analysis_snapshot": row.get("analysis_snapshot"),
            }
            for row in review_rows[: min(12, len(review_rows))]
        ],
        "interpretation": [
            "Unresolved and replacement counts are from protected material snapshots and are diagnostic evidence, not export accuracy.",
            "Nested kind conflicts are a conservative text-overlap proxy because snapshots do not persist candidate offsets for unresolved findings.",
            "C07 same-name ambiguity is a required review case; repeated same-text findings in other cases are ordinary duplicate candidates and may indicate missed occurrence resolution or detector overreach.",
        ],
    }

    return {
        "schema_version": "ai-upgrade-redaction-gold-comparison-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": {
            "report": str(report_path),
            "gold": str(gold_path),
            "manifest": str(manifest_path),
            "model": observed.get("model"),
            "report_started_at": observed.get("started_at"),
            "report_completed_at": observed.get("completed_at"),
        },
        "scope": {
            "gold_record_count": len(gold_records),
            "manifest_material_count": manifest.get("material_count"),
            "observed_material_count": len(materials),
            "observed_paths_missing_from_report": len(missing_gold),
            "missing_gold_paths": missing_gold,
            "unknown_observed_count": len(unknown_observed),
            "duplicate_report_paths": duplicate_paths,
        },
        "counts": {
            "actual_status": status_counts,
            "evaluation": evaluation_counts,
            "format": format_counts,
            "ready": {
                "automatic_ready_total": len(ready_items),
                "ready_with_readable_export": len(ready_evaluable),
                "ready_missing_or_unreadable_export": len(ready_items) - len(ready_evaluable),
                "passed": passed,
                "pass_rate_over_ready_with_readable_export": passed / len(ready_evaluable) if ready_evaluable else None,
                "pass_rate_denominator_note": "Only ready results with a readable exported TXT are evaluable; needs_review and failed results are not successes.",
            },
            "needs_review": {
                "total": status_counts.get("needs_review", 0),
                "by_reason": dict(sorted(Counter(item.get("reason_code") or "unspecified" for item in materials if actual_status(item) == "needs_review").items())),
            },
            "failed": {
                "total": status_counts.get("failed", 0),
                "by_reason": dict(sorted(Counter(item.get("reason_code") or "unspecified" for item in materials if actual_status(item) == "failed").items())),
            },
        },
        "c07_same_name_review": {
            "expected_review": True,
            "material_count_observed": len(c07),
            "needs_review_count": c07_needs_review,
            "failed_count": c07_failed,
            "ready_count": c07_ready,
            "outcome": c07_outcome,
            "no_ready_output": c07_ready == 0,
            "strict_review_observed": bool(c07) and c07_needs_review == len(c07),
            "note": "A ready C07 result is rejected even if both names were replaced, because identity ambiguity must enter review.",
        },
        "damaged_input_fail_closed": {
            "expected_count": len(damaged),
            "pass_count": sum(row.get("evaluation") == "fail_closed_pass" for row in damaged),
            "violations": [row for row in damaged if row.get("evaluation") == "fail_closed_violation"],
            "not_observed": len(damaged) == 0,
        },
        "needs_review_diagnostics": review_diagnostics,
        "report_errors": report_errors,
        "comparisons": comparisons,
        "overall_status": (
            "pass"
            if materials
            and not missing_gold
            and not unknown_observed
            and not report_errors
            and all(row.get("evaluation") in {"pass", "fail_closed_pass"} for row in comparisons)
            else "incomplete_or_failed"
        ),
        "limitations": [
            "A material snapshot's analysis.text is never substituted for a missing TXT export.",
            "Exact sensitive matches are failures; NFKC/space/punctuation compact matches are reported as a near-match diagnostic.",
            "Date/amount format equivalents are accepted only when they parse to the same date or numeric value; a different value is reported as missing_or_changed.",
            "OCR checks are separate and only run when a readable export exists; unavailable exports remain not_evaluable.",
        ],
    }


def markdown_report(result: dict[str, Any]) -> str:
    counts = result["counts"]
    ready = counts["ready"]
    diagnostics = result.get("needs_review_diagnostics", {})
    lines = [
        "# 脱敏盲标比对报告",
        "",
        f"结论：`{result['overall_status']}`。",
        "",
        "本报告只把可读取的 UTF-8 TXT 导出作为自动脱敏结果；状态为 `ready` 但导出缺失、为空或无法读取时，记为 `not_evaluable`，不会当作通过。",
        "",
        f"- 金标记录：{result['scope']['gold_record_count']}；本次报告记录：{result['scope']['observed_material_count']}；缺少报告记录：{result['scope']['observed_paths_missing_from_report']}。",
        f"- 自动 `ready`：{ready['automatic_ready_total']}；其中有可读导出：{ready['ready_with_readable_export']}；缺失/不可读导出：{ready['ready_missing_or_unreadable_export']}。",
        f"- 可读导出通过：{ready['passed']}/{ready['ready_with_readable_export']}；通过率：{ready['pass_rate_over_ready_with_readable_export'] if ready['pass_rate_over_ready_with_readable_export'] is not None else '不可计算'}。",
        f"- `needs_review`：{counts['needs_review']['total']}；`failed`：{counts['failed']['total']}。",
        f"- `needs_review` 快照诊断：{diagnostics.get('finding_count', 0)} 个 finding，其中未 resolved {diagnostics.get('unresolved_count', 0)}，已写 replacement {diagnostics.get('replacement_count', 0)}。",
        f"- 快照 `analysis.text` 中仍出现盲标实体的记录：{diagnostics.get('analysis_text_gold_residual_snapshot_count', 0)}，实体种类数：{diagnostics.get('analysis_text_gold_residual_entity_count', 0)}。",
        "",
        "## 状态与格式",
        "",
        "| 项目 | 结果 |",
        "| --- | ---: |",
    ]
    for key, value in counts["actual_status"].items():
        lines.append(f"| 实际状态 `{key}` | {value} |")
    for fmt, row in counts["format"].items():
        lines.append(f"| 格式 `{fmt}`（期望/观察） | {row['expected']} / {row['observed']} |")
    lines.extend(["", "## 逐材料结果", "", "| 案件 | 格式 | 状态 | 评价 | 主要问题 |", "| --- | --- | --- | --- | --- |"])
    for row in result["comparisons"]:
        issues = "；".join(str(value) for value in row.get("issues", []))
        lines.append(f"| {row.get('case_id') or ''} | {row.get('format') or ''} | {row['actual']['status']} | {row.get('evaluation')} | {issues} |")
    lines.extend(
        [
            "",
            "## 特别检查",
            "",
            f"C07 同名身份复核：`{result['c07_same_name_review']['outcome']}`。",
            f"损坏输入 fail-closed：通过 {result['damaged_input_fail_closed']['pass_count']} / 期望 {result['damaged_input_fail_closed']['expected_count']}。",
            f"普通（非 C07）重复候选组：{diagnostics.get('ordinary_non_c07_duplicate_group_count', 0)}；候选文本类别嵌套冲突：{diagnostics.get('nested_kind_conflict_count', 0)}。",
            f"未 resolved 来源：{diagnostics.get('unresolved_source_counts', {})}。",
            f"未 resolved 类别：{diagnostics.get('unresolved_kind_counts', {})}。",
            f"未 resolved 与盲标实体的关系：{diagnostics.get('unresolved_gold_match_counts', {})}（`overlap` 为候选文本包含实体或被实体包含，需人工判断）。",
            "",
            "详细实体残留、日期/金额事实、事实锚点、OCR 缺漏及 needs_review 快照 finding/replacement 见同目录的 `gold-comparison.json`。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="redaction-report.json or its attempt directory")
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD, help="independent blind gold JSON")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="fixture manifest JSON")
    parser.add_argument("--output-dir", type=Path, help="where to write comparison outputs (defaults to report directory)")
    parser.add_argument("--strict", action="store_true", help="return exit code 1 when the comparison is incomplete or failed")
    args = parser.parse_args()

    try:
        report_path = resolve_report_path(args.report)
        report = load_json(report_path)
        gold = load_json(args.gold)
        manifest = load_json(args.manifest)
        result = build_report(gold, manifest, report, report_path, args.gold, args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"verify_redaction_gold: {exc}", file=sys.stderr)
        return 2

    output_dir = args.output_dir or report_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    comparison_path = output_dir / "gold-comparison.json"
    markdown_path = output_dir / "gold-comparison-report.md"
    comparison_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(result), encoding="utf-8")
    print(json.dumps({
        "overall_status": result["overall_status"],
        "comparison": str(comparison_path),
        "report": str(markdown_path),
        "ready_total": result["counts"]["ready"]["automatic_ready_total"],
        "ready_evaluable": result["counts"]["ready"]["ready_with_readable_export"],
        "needs_review": result["counts"]["needs_review"]["total"],
        "failed": result["counts"]["failed"]["total"],
    }, ensure_ascii=False))
    return 1 if args.strict and result["overall_status"] != "pass" else 0


if __name__ == "__main__":
    raise SystemExit(main())
