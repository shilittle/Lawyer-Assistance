"""Build a host-verifiable OCR document from real MinerU output."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable

from . import PROTOCOL_VERSION
from .runtime import RuntimeFailure, WorkerRuntime, ordinary_path, sha256_file, sha256_hex

MAX_OUTPUT_FILES: Final = 10_000
MAX_CONTENT_ENTRIES: Final = 1_000_000
MAX_JSON_DEPTH: Final = 32
LOW_RESOLUTION_EDGE_VARIANCE: Final = 400.0
LOW_CONFIDENCE_PPM: Final = 700_000


class OutputFailure(RuntimeFailure):
    """MinerU output cannot satisfy the production host contract."""


@dataclass(frozen=True)
class Candidate:
    text: str
    confidence: float


@dataclass(frozen=True)
class MiddleBlock:
    raw_bbox: tuple[int, int, int, int]
    candidates: tuple[Candidate, ...]
    layout_confidence: float
    source_type: str


@dataclass(frozen=True)
class PageEvidence:
    width: float
    height: float
    text_blocks: tuple[MiddleBlock, ...]
    all_blocks: tuple[MiddleBlock, ...]


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OutputFailure("duplicate_json_field")
        result[key] = value
    return result


def _load_json(path: Path, maximum: int) -> object:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise OutputFailure("output_read_failed") from error
    if not data or len(data) > maximum:
        raise OutputFailure("output_json_size_invalid")
    try:
        return json.loads(
            data,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                OutputFailure("output_number_invalid")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise OutputFailure("output_json_invalid") from error


def _confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OutputFailure("confidence_missing")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise OutputFailure("confidence_invalid")
    return result


def _dimension(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OutputFailure("page_dimension_invalid")
    result = float(value)
    if not math.isfinite(result) or not 0.0 < result <= 100_000.0:
        raise OutputFailure("page_dimension_invalid")
    return result


def _absolute_bbox(value: object, width: float, height: float) -> tuple[float, float, float, float]:
    if not isinstance(value, list) or len(value) != 4:
        raise OutputFailure("bbox_invalid")
    converted: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise OutputFailure("bbox_invalid")
        coordinate = float(item)
        if not math.isfinite(coordinate) or coordinate < 0.0:
            raise OutputFailure("bbox_invalid")
        converted.append(coordinate)
    left, top, right, bottom = converted
    if left >= right or top >= bottom or right > width or bottom > height:
        raise OutputFailure("bbox_invalid")
    return left, top, right, bottom


def _normalized_middle_bbox(
    value: object, width: float, height: float
) -> tuple[int, int, int, int]:
    left, top, right, bottom = _absolute_bbox(value, width, height)
    return (
        int(left * 1000.0 / width),
        int(top * 1000.0 / height),
        int(right * 1000.0 / width),
        int(bottom * 1000.0 / height),
    )


def _content_bbox(value: object) -> tuple[int, int, int, int]:
    if not isinstance(value, list) or len(value) != 4:
        raise OutputFailure("content_bbox_invalid")
    coordinates: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 1000:
            raise OutputFailure("content_bbox_invalid")
        coordinates.append(item)
    left, top, right, bottom = coordinates
    if left >= right or top >= bottom:
        raise OutputFailure("content_bbox_invalid")
    return left, top, right, bottom


def _collect_candidates(
    block: dict[str, object], output: list[Candidate], depth: int = 0
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise OutputFailure("middle_depth_exceeded")
    block_type = block.get("type")
    block_type = block_type if isinstance(block_type, str) else ""
    score_value = block.get("score")
    block_score = _confidence(score_value) if score_value is not None else None
    lines = block.get("lines", [])
    if not isinstance(lines, list):
        raise OutputFailure("middle_lines_invalid")
    direct: list[Candidate] = []
    for line in lines:
        if not isinstance(line, dict) or not isinstance(line.get("spans"), list):
            raise OutputFailure("middle_spans_invalid")
        for span in line["spans"]:
            if not isinstance(span, dict):
                raise OutputFailure("middle_span_invalid")
            for key in ("content", "html"):
                if key not in span:
                    continue
                text = span[key]
                if not isinstance(text, str) or "\x00" in text:
                    raise OutputFailure("middle_text_invalid")
                text = text.strip()
                if not text:
                    continue
                if "score" in span:
                    confidence = _confidence(span["score"])
                elif (
                    key == "html"
                    and block_type == "table_body"
                    and span.get("type") == "table"
                    and block_score is not None
                ):
                    confidence = block_score
                else:
                    raise OutputFailure("confidence_missing")
                candidate = Candidate(text, confidence)
                direct.append(candidate)
                output.append(candidate)
                if len(output) > MAX_CONTENT_ENTRIES:
                    raise OutputFailure("middle_too_large")
    if len(direct) > 1:
        compact = "".join(item.text for item in direct)
        spaced = " ".join(item.text for item in direct)
        minimum = min(item.confidence for item in direct)
        output.append(Candidate(compact, minimum))
        if spaced != compact:
            output.append(Candidate(spaced, minimum))
    children = block.get("blocks")
    if children is not None:
        if not isinstance(children, list):
            raise OutputFailure("middle_children_invalid")
        for child in children:
            if not isinstance(child, dict):
                raise OutputFailure("middle_child_invalid")
            _collect_candidates(child, output, depth + 1)


def _block_score(blocks: Iterable[dict[str, object]]) -> float:
    scores = []
    for block in blocks:
        if "score" not in block:
            raise OutputFailure("layout_confidence_missing")
        scores.append(_confidence(block["score"]))
    if not scores:
        raise OutputFailure("layout_confidence_missing")
    return min(scores)


def parse_middle(value: object, page_count: int) -> tuple[PageEvidence, ...]:
    if not isinstance(value, dict) or not isinstance(value.get("pdf_info"), list):
        raise OutputFailure("middle_shape_invalid")
    pages = value["pdf_info"]
    if len(pages) != page_count:
        raise OutputFailure("middle_page_count_mismatch")
    result: list[PageEvidence] = []
    for expected_index, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("page_idx") != expected_index:
            raise OutputFailure("middle_page_order_invalid")
        size = page.get("page_size")
        if isinstance(size, list) and len(size) == 2:
            width, height = _dimension(size[0]), _dimension(size[1])
        elif isinstance(size, dict):
            width, height = _dimension(size.get("width")), _dimension(size.get("height"))
        else:
            raise OutputFailure("middle_page_size_invalid")
        para = page.get("para_blocks")
        discarded = page.get("discarded_blocks")
        if not isinstance(para, list) or not isinstance(discarded, list):
            raise OutputFailure("middle_blocks_invalid")
        ordered = para + discarded
        if len(ordered) > MAX_CONTENT_ENTRIES or any(
            not isinstance(block, dict) for block in ordered
        ):
            raise OutputFailure("middle_blocks_invalid")

        text_blocks: list[MiddleBlock] = []
        all_blocks: list[MiddleBlock] = []
        for block in ordered:
            candidates: list[Candidate] = []
            _collect_candidates(block, candidates)
            source_type = block.get("type") if isinstance(block.get("type"), str) else ""
            all_blocks.append(
                MiddleBlock(
                    _normalized_middle_bbox(block.get("bbox"), width, height),
                    tuple(candidates),
                    _block_score((block,)),
                    source_type,
                )
            )

        cursor = 0
        while cursor < len(ordered):
            first = ordered[cursor]
            grouped = [first]
            if first.get("type") == "ref_text":
                cursor += 1
                while cursor < len(ordered) and ordered[cursor].get("type") == "ref_text":
                    grouped.append(ordered[cursor])
                    cursor += 1
            else:
                cursor += 1
            candidates = []
            for block in grouped:
                _collect_candidates(block, candidates)
            if candidates:
                source_type = (
                    first.get("type") if isinstance(first.get("type"), str) else ""
                )
                text_blocks.append(
                    MiddleBlock(
                        _normalized_middle_bbox(first.get("bbox"), width, height),
                        tuple(candidates),
                        _block_score(grouped),
                        source_type,
                    )
                )
        result.append(
            PageEvidence(width, height, tuple(text_blocks), tuple(all_blocks))
        )
    return tuple(result)


def _content_texts(entry: dict[str, object]) -> tuple[str, ...]:
    texts: list[str] = []
    for key in ("text", "equation", "content", "table_body", "code_body", "chart_body"):
        if key not in entry:
            continue
        value = entry[key]
        if not isinstance(value, str):
            raise OutputFailure("content_text_invalid")
        value = value.strip()
        if value:
            texts.append(value)
    for key in (
        "list_items",
        "image_caption",
        "img_caption",
        "image_footnote",
        "table_caption",
        "table_footnote",
        "chart_caption",
        "chart_footnote",
        "code_caption",
        "code_footnote",
    ):
        if key not in entry:
            continue
        values = entry[key]
        if not isinstance(values, list):
            raise OutputFailure("content_text_list_invalid")
        for value in values:
            if not isinstance(value, str):
                raise OutputFailure("content_text_invalid")
            value = value.strip()
            if value:
                texts.append(value)
    return tuple(texts)


def _associate(
    texts: tuple[str, ...],
    bbox: tuple[int, int, int, int],
    blocks: tuple[MiddleBlock, ...],
) -> tuple[int, tuple[float, ...], float]:
    associations: list[tuple[int, tuple[float, ...], float]] = []
    for block_index, block in enumerate(blocks):
        if block.raw_bbox != bbox:
            continue
        confidences: list[float] = []
        used: set[int] = set()
        valid = True
        for text in texts:
            matches = [
                (index, candidate.confidence)
                for index, candidate in enumerate(block.candidates)
                if index not in used and candidate.text == text
            ]
            if len(matches) != 1:
                valid = False
                break
            candidate_index, confidence = matches[0]
            used.add(candidate_index)
            confidences.append(confidence)
        if valid:
            associations.append(
                (block_index, tuple(confidences), block.layout_confidence)
            )
    if len(associations) != 1:
        raise OutputFailure("content_middle_association_invalid")
    return associations[0]


def _visual_score(
    bbox: tuple[int, int, int, int], blocks: tuple[MiddleBlock, ...]
) -> float:
    matches = [
        block.layout_confidence
        for block in blocks
        if block.raw_bbox == bbox and block.source_type in {"image", "chart", "image_body"}
    ]
    if len(matches) != 1:
        raise OutputFailure("visual_middle_association_invalid")
    return matches[0]


def _ppm(value: float) -> int:
    result = int(round(value * 1_000_000.0))
    return min(1_000_000, max(0, result))


def _opaque(prefix: str, seed: bytes) -> str:
    return f"{prefix}_{hashlib.sha256(seed).hexdigest()[:32]}"


def _geometry(
    raw_bbox: tuple[int, int, int, int],
    width_micropoints: int,
    height_micropoints: int,
) -> tuple[dict[str, int], list[dict[str, int]]]:
    left = width_micropoints * raw_bbox[0] // 1000
    top = height_micropoints * raw_bbox[1] // 1000
    right = width_micropoints * raw_bbox[2] // 1000
    bottom = height_micropoints * raw_bbox[3] // 1000
    if left >= right or top >= bottom:
        raise OutputFailure("protocol_geometry_invalid")
    bbox = {
        "left_micropoints": left,
        "top_micropoints": top,
        "right_micropoints": right,
        "bottom_micropoints": bottom,
    }
    polygon = [
        {"x_micropoints": left, "y_micropoints": top},
        {"x_micropoints": right, "y_micropoints": top},
        {"x_micropoints": right, "y_micropoints": bottom},
        {"x_micropoints": left, "y_micropoints": bottom},
    ]
    return bbox, polygon


def _text_type(entry_type: str) -> tuple[str, str, str | None]:
    if entry_type in {"title", "heading"}:
        return "heading", "textual", None
    if entry_type == "table":
        return "table", "complex_table", "complex_table"
    if entry_type in {"equation", "interline_equation", "inline_equation"}:
        return "formula", "formula", None
    if entry_type in {"image_caption", "img_caption"}:
        return "image_caption", "textual", None
    return "text", "textual", None


def _block(
    *,
    page_index: int,
    order: int,
    text: str,
    raw_bbox: tuple[int, int, int, int],
    width_micropoints: int,
    height_micropoints: int,
    block_type: str,
    classification: str,
    ocr_confidence: float,
    layout_confidence: float,
) -> dict[str, object]:
    bbox, polygon = _geometry(raw_bbox, width_micropoints, height_micropoints)
    seed = (
        f"{page_index}\n{order}\n{text}\n{raw_bbox}\n{block_type}".encode("utf-8")
    )
    return {
        "block_id": _opaque("blk", b"block\n" + seed),
        "block_type": block_type,
        "reading_order": order,
        "raw_text_ref": _opaque("obj", b"raw\n" + seed),
        "normalized_text": text,
        "bbox": bbox,
        "polygon": polygon,
        "coordinate_system": "page_micropoints",
        "ocr_confidence_ppm": _ppm(ocr_confidence),
        "layout_confidence_ppm": _ppm(layout_confidence),
        "confidence_available": True,
        "source_locator": {
            "page_index": page_index,
            "source_block_index": order,
        },
        "visual_classification": classification,
    }


def parse_content(
    value: object, pages: tuple[PageEvidence, ...]
) -> tuple[tuple[list[dict[str, object]], set[str]], ...]:
    if not isinstance(value, list) or len(value) > MAX_CONTENT_ENTRIES:
        raise OutputFailure("content_shape_invalid")
    result: list[tuple[list[dict[str, object]], set[str]]] = [
        ([], set()) for _ in pages
    ]
    used: list[set[int]] = [set() for _ in pages]
    previous_page = 0
    for entry_index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise OutputFailure("content_entry_invalid")
        page_index = entry.get("page_idx")
        if (
            isinstance(page_index, bool)
            or not isinstance(page_index, int)
            or not 0 <= page_index < len(pages)
            or (entry_index > 0 and page_index < previous_page)
        ):
            raise OutputFailure("content_page_order_invalid")
        previous_page = page_index
        entry_type = entry.get("type")
        entry_type = entry_type if isinstance(entry_type, str) else ""
        texts = _content_texts(entry)
        bbox_value = entry.get("bbox")
        if not texts:
            explicitly_empty = (
                entry_type == "text"
                and isinstance(entry.get("text"), str)
                and not entry["text"].strip()
            )
            if entry_type not in {"image", "chart"} and not explicitly_empty:
                raise OutputFailure("content_entry_incomplete")
            if bbox_value is not None:
                _content_bbox(bbox_value)
        raw_bbox = _content_bbox(bbox_value) if bbox_value is not None else None
        evidence = pages[page_index]
        width_micropoints = int(round(evidence.width * 1_000_000.0))
        height_micropoints = int(round(evidence.height * 1_000_000.0))
        blocks, risks = result[page_index]

        if texts:
            if raw_bbox is None:
                raise OutputFailure("content_bbox_missing")
            middle_index, confidences, layout_confidence = _associate(
                texts, raw_bbox, evidence.text_blocks
            )
            if middle_index in used[page_index]:
                raise OutputFailure("middle_block_reused")
            used[page_index].add(middle_index)
            block_type, classification, risk = _text_type(entry_type)
            if risk is not None:
                risks.add(risk)
            for text, confidence in zip(texts, confidences, strict=True):
                if not text or "\x00" in text or "\ufffd" in text:
                    raise OutputFailure("content_text_invalid")
                blocks.append(
                    _block(
                        page_index=page_index,
                        order=len(blocks),
                        text=text,
                        raw_bbox=raw_bbox,
                        width_micropoints=width_micropoints,
                        height_micropoints=height_micropoints,
                        block_type=block_type,
                        classification=classification,
                        ocr_confidence=confidence,
                        layout_confidence=layout_confidence,
                    )
                )

        if entry_type in {"image", "chart"}:
            if raw_bbox is None:
                raise OutputFailure("visual_bbox_missing")
            visual_confidence = _visual_score(raw_bbox, evidence.all_blocks)
            risks.add("screenshot")
            blocks.append(
                _block(
                    page_index=page_index,
                    order=len(blocks),
                    text="",
                    raw_bbox=raw_bbox,
                    width_micropoints=width_micropoints,
                    height_micropoints=height_micropoints,
                    block_type="screenshot",
                    classification="screenshot",
                    ocr_confidence=visual_confidence,
                    layout_confidence=visual_confidence,
                )
            )
    for page_index, evidence in enumerate(pages):
        if len(used[page_index]) != len(evidence.text_blocks):
            raise OutputFailure("middle_coverage_incomplete")
        if not any(str(block["normalized_text"]).strip() for block in result[page_index][0]):
            raise OutputFailure("page_text_incomplete")
    return tuple(result)


def _safe_output_files(root: Path, maximum_bytes: int) -> list[tuple[str, Path, int, str]]:
    ordinary_path(root, directory=True)
    files: list[tuple[str, Path, int, str]] = []
    total = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        ordinary_path(current_path, directory=True)
        for directory in directories:
            ordinary_path(current_path / directory, directory=True)
        for name in names:
            path = current_path / name
            ordinary_path(path, directory=False)
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError as error:
                raise OutputFailure("output_path_escape") from error
            if not relative or any(character in relative for character in "\r\n\x00"):
                raise OutputFailure("output_name_invalid")
            size = path.stat().st_size
            total += size
            if total > maximum_bytes or len(files) >= MAX_OUTPUT_FILES:
                raise OutputFailure("output_limit_exceeded")
            files.append((relative, path, size, sha256_file(path)))
    if not files:
        raise OutputFailure("output_empty")
    files.sort(key=lambda entry: entry[0])
    if len({entry[0].casefold() for entry in files}) != len(files):
        raise OutputFailure("output_name_collision")
    return files


def output_tree_sha256(files: list[tuple[str, Path, int, str]]) -> str:
    canonical = bytearray(b"la-mineru-output-tree-v1\n")
    for relative, _path, size, digest in files:
        canonical.extend(relative.encode("utf-8"))
        canonical.extend(b"\n")
        canonical.extend(str(size).encode("ascii"))
        canonical.extend(b"\n")
        canonical.extend(digest.encode("ascii"))
        canonical.extend(b"\n")
    return sha256_hex(bytes(canonical))


def _unique_suffix(
    files: list[tuple[str, Path, int, str]], suffix: str
) -> Path:
    matches = [path for relative, path, _size, _digest in files if relative.endswith(suffix)]
    if len(matches) != 1:
        raise OutputFailure("required_output_ambiguous")
    return matches[0]


def _low_resolution(image: object) -> bool:
    """Conservative blur/downsampling signal over pixels only; no OCR text."""
    try:
        from PIL import Image, ImageFilter, ImageStat
    except Exception as error:
        raise OutputFailure("image_quality_analyzer_unavailable") from error
    if not isinstance(image, Image.Image) or image.width < 8 or image.height < 8:
        raise OutputFailure("page_image_invalid")
    grayscale = image.convert("L")
    edges = grayscale.filter(ImageFilter.FIND_EDGES)
    interior = edges.crop((2, 2, edges.width - 2, edges.height - 2))
    variance = ImageStat.Stat(interior).var[0]
    if not math.isfinite(variance):
        raise OutputFailure("page_image_quality_invalid")
    return variance < LOW_RESOLUTION_EDGE_VARIANCE


def _render_page_evidence(
    input_pdf: Path, expected_pages: int
) -> tuple[tuple[int, int, int, str, bool], ...]:
    try:
        import pypdfium2
    except Exception as error:
        raise OutputFailure("pdf_renderer_unavailable") from error
    try:
        document = pypdfium2.PdfDocument(str(input_pdf))
    except Exception as error:
        raise OutputFailure("pdf_open_failed") from error
    rendered: list[tuple[int, int, int, str, bool]] = []
    try:
        if len(document) != expected_pages:
            raise OutputFailure("pdf_page_count_mismatch")
        for page_index in range(expected_pages):
            page = document[page_index]
            try:
                width, height = page.get_size()
                rotation = int(page.get_rotation()) % 360
                if rotation not in {0, 90, 180, 270}:
                    raise OutputFailure("pdf_rotation_invalid")
                bitmap = page.render(scale=2.0, rotation=0)
                try:
                    image = bitmap.to_pil().convert("RGB")
                    pixels = image.tobytes()
                    digest = hashlib.sha256()
                    digest.update(b"la-mineru-page-image-v1\n")
                    digest.update(f"{image.width}\n{image.height}\nRGB\n".encode("ascii"))
                    digest.update(pixels)
                    rendered.append(
                        (
                            int(round(width * 1_000_000.0)),
                            int(round(height * 1_000_000.0)),
                            rotation,
                            digest.hexdigest(),
                            _low_resolution(image),
                        )
                    )
                finally:
                    bitmap.close()
            finally:
                page.close()
    finally:
        document.close()
    return tuple(rendered)


def build_document(
    runtime: WorkerRuntime,
    request: dict[str, object],
    *,
    started_at_unix: int,
    started_monotonic: float,
) -> dict[str, object]:
    files = _safe_output_files(runtime.paths.output, runtime.max_output_bytes)
    output_sha256 = output_tree_sha256(files)
    content_path = _unique_suffix(files, "_content_list.json")
    middle_path = _unique_suffix(files, "_middle.json")
    page_count = int(request["expected_page_count"])
    maximum_json = min(runtime.max_output_bytes, 128 * 1024 * 1024)
    middle = parse_middle(_load_json(middle_path, maximum_json), page_count)
    parsed = parse_content(_load_json(content_path, maximum_json), middle)
    rendered = _render_page_evidence(runtime.paths.input_pdf, page_count)
    source_sha256 = sha256_file(runtime.paths.input_pdf)
    if source_sha256 != request["source_sha256"]:
        raise OutputFailure("input_hash_changed")

    protocol_pages: list[dict[str, object]] = []
    for page_index, ((blocks, risks), evidence, render) in enumerate(
        zip(parsed, middle, rendered, strict=True)
    ):
        width_micropoints, height_micropoints, rotation, page_hash, low_resolution = render
        expected_width = int(round(evidence.width * 1_000_000.0))
        expected_height = int(round(evidence.height * 1_000_000.0))
        if (
            abs(width_micropoints - expected_width) > 1_000_000
            or abs(height_micropoints - expected_height) > 1_000_000
        ):
            raise OutputFailure("page_dimension_mismatch")
        confidences = [int(block["ocr_confidence_ppm"]) for block in blocks]
        if not confidences:
            raise OutputFailure("page_blocks_missing")
        area = 0
        warnings = []
        if low_resolution:
            warnings.append("low_resolution")
        if min(confidences) < LOW_CONFIDENCE_PPM:
            warnings.append("low_confidence")
        for block in blocks:
            bbox = block["bbox"]
            area += (bbox["right_micropoints"] - bbox["left_micropoints"]) * (
                bbox["bottom_micropoints"] - bbox["top_micropoints"]
            )
        page_area = width_micropoints * height_micropoints
        coverage = min(1_000_000, max(1, area * 1_000_000 // page_area))
        protocol_pages.append(
            {
                "page_index": page_index,
                "width_micropoints": width_micropoints,
                "height_micropoints": height_micropoints,
                "rotation_degrees": rotation,
                "page_image_sha256": page_hash,
                "status": "ok",
                "blocks": blocks,
                "coverage_ppm": coverage,
                "minimum_ocr_confidence_ppm": min(confidences),
                "mean_ocr_confidence_ppm": sum(confidences) // len(confidences),
                "visual_risks": sorted(risks),
                "warnings": warnings,
                "completeness": {
                    "dimensions_verified": True,
                    "page_image_hash_verified": True,
                    "reading_order_contiguous": True,
                    "geometry_validated": True,
                    "confidences_complete": True,
                    "visual_regions_classified": True,
                    "output_tree_confined": True,
                    "passed": True,
                },
            }
        )

    duration_ms = max(1, int((time.monotonic() - started_monotonic) * 1000.0))
    return {
        "protocol_version": PROTOCOL_VERSION,
        "document_id": request["document_id"],
        "source_sha256": source_sha256,
        "input_unmodified_sha256": source_sha256,
        "page_count": page_count,
        "pages": protocol_pages,
        "provenance": {
            "worker_version": runtime.identity()["worker_version"],
            "worker_sha256": runtime.worker_sha256,
            "protocol_version": PROTOCOL_VERSION,
            "python_version": runtime.python_version,
            "mineru_version": runtime.mineru_version,
            "pytorch_version": runtime.pytorch_version,
            "cuda_runtime_version": runtime.cuda_runtime_version,
            "gpu_driver_version": runtime.gpu_driver_version,
            "requested_device": runtime.requested_device(),
            "actual_device": runtime.actual_device,
            "model_version": runtime.model_version,
            "model_manifest_sha256": runtime.model_manifest_sha256,
            "config_sha256": runtime.config_sha256,
            "isolation_evidence_id": runtime.isolation_evidence_id,
            "isolation_evidence_sha256": runtime.isolation_evidence_sha256,
            "qualification_report_id": runtime.qualification_report_id,
            "processing_parameters_sha256": request["processing_parameters_sha256"],
            "started_at_unix": started_at_unix,
            "duration_ms": duration_ms,
        },
        "warnings": [],
        "completeness": {
            "input_hash_verified": True,
            "page_count_verified": True,
            "pages_contiguous": True,
            "block_ids_unique": True,
            "all_pages_complete": True,
            "provenance_complete": True,
            "output_tree_confined": True,
            "passed": True,
        },
        "output_sha256": output_sha256,
    }
