#!/usr/bin/env python3
"""Generate deterministic image-only PDFs for local MinerU acceptance tests.

The fixtures contain no real case data. Every PDF page is a raster image so a
native PDF text extractor cannot satisfy the test without the local OCR path.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

WIDTH = 1240
HEIGHT = 1754
FONT_PATHS = (
    Path(r"C:\Windows\Fonts\msyh.ttc"),
    Path(r"C:\Windows\Fonts\simhei.ttf"),
    Path(r"C:\Windows\Fonts\arial.ttf"),
)


def font(size: int) -> ImageFont.FreeTypeFont:
    path = next((candidate for candidate in FONT_PATHS if candidate.is_file()), None)
    if path is None:
        raise RuntimeError("No approved local test font is available")
    return ImageFont.truetype(str(path), size=size)


def blank() -> Image.Image:
    return Image.new("RGB", (WIDTH, HEIGHT), "white")


def draw_lines(
    draw: ImageDraw.ImageDraw,
    lines: list[str],
    x: int,
    y: int,
    size: int = 36,
    spacing: int = 20,
) -> int:
    face = font(size)
    for line in lines:
        draw.text((x, y), line, fill="black", font=face)
        y += size + spacing
    return y


def normal_table_seal_page() -> Image.Image:
    image = blank()
    draw = ImageDraw.Draw(image)
    y = draw_lines(
        draw,
        [
            "LAWYER ASSISTANCE OCR CANARY 2026",
            "本页为完全合成的本地 OCR 验收材料",
            "测试主体甲与测试主体乙仅用于验证脱敏链路",
        ],
        80,
        90,
        42,
        24,
    )
    top = y + 35
    left = 80
    right = WIDTH - 80
    rows = 5
    row_height = 100
    columns = [left, 390, 760, right]
    for x in columns:
        draw.line((x, top, x, top + rows * row_height), fill="black", width=4)
    for row in range(rows + 1):
        yy = top + row * row_height
        draw.line((left, yy, right, yy), fill="black", width=4)
    cells = [
        ("序号", "事项", "结果"),
        ("1", "页序检查", "通过"),
        ("2", "表格识别", "通过"),
        ("3", "印章干扰", "可复核"),
        ("4", "本地离线", "强制"),
    ]
    face = font(31)
    for row, values in enumerate(cells):
        for column, value in enumerate(values):
            draw.text(
                (columns[column] + 22, top + row * row_height + 28),
                value,
                fill="black",
                font=face,
            )
    center = (WIDTH - 235, top + rows * row_height + 260)
    draw.ellipse(
        (center[0] - 145, center[1] - 145, center[0] + 145, center[1] + 145),
        outline=(200, 0, 0),
        width=13,
    )
    draw.text(
        (center[0] - 92, center[1] - 31),
        "合成测试",
        fill=(200, 0, 0),
        font=font(43),
    )
    draw_lines(
        draw,
        ["页码 1 / 2", "EXPECTED TOKEN: LOCAL OCR ONLY"],
        80,
        HEIGHT - 230,
        31,
        16,
    )
    return image


def double_column_page() -> Image.Image:
    image = blank()
    draw = ImageDraw.Draw(image)
    draw.text((80, 80), "双栏布局验收页", fill="black", font=font(46))
    draw.line((WIDTH // 2, 170, WIDTH // 2, HEIGHT - 180), fill=(100, 100, 100), width=2)
    left = [
        "左栏第一段：只允许本机 OCR。",
        "左栏第二段：保持阅读顺序。",
        "左栏第三段：检测边界框。",
        "左栏第四段：禁止网络回退。",
    ]
    right = [
        "右栏第一段：内容完全合成。",
        "右栏第二段：输出必须可复核。",
        "右栏第三段：缺页立即失败。",
        "右栏第四段：哈希变化失效。",
    ]
    draw_lines(draw, left, 80, 220, 32, 90)
    draw_lines(draw, right, WIDTH // 2 + 45, 220, 32, 90)
    draw.text((80, HEIGHT - 170), "页码 2 / 2", fill="black", font=font(31))
    return image


def rotated_page() -> Image.Image:
    source = Image.new("RGB", (HEIGHT, WIDTH), "white")
    draw = ImageDraw.Draw(source)
    draw_lines(
        draw,
        [
            "ROTATED PAGE OCR CANARY",
            "旋转页面必须先校正方向再识别",
            "本页不含任何真实案件信息",
            "EXPECTED TOKEN: ROTATION VERIFIED",
        ],
        95,
        210,
        48,
        45,
    )
    rotated = source.rotate(90, expand=True, fillcolor="white")
    image = blank()
    image.paste(rotated.resize((WIDTH, HEIGHT)), (0, 0))
    return image


def low_resolution_page() -> Image.Image:
    low = Image.new("RGB", (620, 877), "white")
    draw = ImageDraw.Draw(low)
    draw_lines(
        draw,
        [
            "LOW RESOLUTION OCR CANARY",
            "低清页面需要人工复核",
            "EXPECTED TOKEN: LOW RESOLUTION",
        ],
        45,
        90,
        24,
        34,
    )
    return low.resize((WIDTH, HEIGHT), Image.Resampling.BILINEAR)


def unreadable_handwriting_page() -> Image.Image:
    image = blank()
    draw = ImageDraw.Draw(image)
    points = [
        (90, 250),
        (230, 170),
        (340, 390),
        (480, 210),
        (630, 430),
        (790, 190),
        (940, 410),
        (1120, 240),
    ]
    for offset in range(7):
        shifted = [(x, y + offset * 145) for x, y in points]
        draw.line(shifted, fill=(25, 25, 40), width=8, joint="curve")
    draw.rectangle((70, 90, WIDTH - 70, HEIGHT - 90), outline=(160, 160, 160), width=3)
    return image


def write_image_pdf(path: Path, pages: list[Image.Image], jpeg_quality: int = 90) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    output = canvas.Canvas(str(path), pagesize=A4, pageCompression=1)
    page_width, page_height = A4
    for page in pages:
        encoded = io.BytesIO()
        page.save(encoded, format="JPEG", quality=jpeg_quality, optimize=False, progressive=False)
        encoded.seek(0)
        output.drawImage(
            ImageReader(encoded),
            0,
            0,
            width=page_width,
            height=page_height,
            preserveAspectRatio=False,
            mask=None,
        )
        output.showPage()
    output.save()


def assert_image_only_pdf(path: Path, expected_pages: int) -> None:
    reader = PdfReader(path)
    if len(reader.pages) != expected_pages:
        raise RuntimeError(
            f"{path.name}: expected {expected_pages} pages, found {len(reader.pages)}"
        )
    extracted = "".join(page.extract_text() or "" for page in reader.pages).strip()
    if extracted:
        raise RuntimeError(f"{path.name}: unexpected searchable text layer")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, default=Path("tmp/pdfs"))
    args = parser.parse_args()
    output = args.output_directory.resolve()
    write_image_pdf(
        output / "privacy-vnext-ocr-positive.pdf",
        [normal_table_seal_page(), double_column_page()],
    )
    write_image_pdf(
        output / "privacy-vnext-ocr-rotated.pdf",
        [rotated_page()],
    )
    write_image_pdf(
        output / "privacy-vnext-ocr-low-resolution.pdf",
        [low_resolution_page()],
        jpeg_quality=42,
    )
    write_image_pdf(
        output / "privacy-vnext-ocr-unreadable-handwriting.pdf",
        [unreadable_handwriting_page()],
        jpeg_quality=70,
    )
    assert_image_only_pdf(output / "privacy-vnext-ocr-positive.pdf", 2)
    assert_image_only_pdf(output / "privacy-vnext-ocr-rotated.pdf", 1)
    assert_image_only_pdf(output / "privacy-vnext-ocr-low-resolution.pdf", 1)
    assert_image_only_pdf(output / "privacy-vnext-ocr-unreadable-handwriting.pdf", 1)
    for path in sorted(output.glob("privacy-vnext-ocr-*.pdf")):
        print(f"IMAGE_ONLY_OK {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
