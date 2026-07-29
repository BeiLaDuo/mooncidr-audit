from pathlib import Path
import sys

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "submission-application-one-page.md"
PDF_OUT = ROOT / "docs" / "submission-application.pdf"
PNG_OUT = ROOT / "docs" / "submission-application-preview.png"
FONT_REGULAR = Path(r"C:\Windows\Fonts\Noto Sans SC (TrueType).otf")
FONT_BOLD = Path(r"C:\Windows\Fonts\Noto Sans SC Bold (TrueType).otf")
SEP = "\uFF1A"


def load_font(size, bold=False):
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REGULAR), size)


def draw_wrapped(draw, text, x, y, max_width, font, fill, line_gap=12, prefix=""):
    text = prefix + text
    lines = []
    current = ""
    for char in text:
        candidate = current + char
        if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = char
    if current:
        lines.append(current)
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += font.size + line_gap
    return y


def main():
    lines = [
        line.strip().replace("`", "")
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
    ]
    lines = [line for line in lines if line]

    width, height = 2480, 3508
    margin = 170
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    title_font = load_font(58, bold=True)
    heading_font = load_font(36, bold=True)
    body_font = load_font(32)
    small_font = load_font(29)
    meta_key_font = load_font(31, bold=True)
    meta_value_font = load_font(31)

    title = lines[0].lstrip("# ")
    title_width = draw.textbbox((0, 0), title, font=title_font)[2]
    draw.text(((width - title_width) // 2, 130), title, font=title_font, fill=(15, 23, 42))

    meta_lines = lines[1:4]
    body_lines = lines[4:]
    meta_items = []
    for line in meta_lines:
        if SEP in line:
            key, value = line.split(SEP, 1)
            meta_items.append((key, value))
    meta_items.append(("\u8bb8\u53ef\u8bc1", "Apache-2.0"))

    x0, y0 = margin, 265
    row_height = 82
    left_width = 330
    right_width = width - 2 * margin - left_width
    for index, (key, value) in enumerate(meta_items):
        y = y0 + index * row_height
        draw.rectangle([x0, y, x0 + left_width, y + row_height], fill=(238, 242, 247), outline=(203, 213, 225), width=2)
        draw.rectangle([x0 + left_width, y, x0 + left_width + right_width, y + row_height], fill=(255, 255, 255), outline=(203, 213, 225), width=2)
        draw.text((x0 + 24, y + 23), key, font=meta_key_font, fill=(17, 24, 39))
        draw.text((x0 + left_width + 24, y + 23), value, font=meta_value_font, fill=(31, 41, 55))

    y = y0 + len(meta_items) * row_height + 58
    max_width = width - 2 * margin
    for line in body_lines:
        if SEP in line and not line.startswith("- "):
            key, value = line.split(SEP, 1)
            draw.text((margin, y), key, font=heading_font, fill=(17, 24, 39))
            y += 56
            y = draw_wrapped(draw, value, margin, y, max_width, body_font, fill=(31, 41, 55))
            y += 22
        elif line.startswith("- "):
            y = draw_wrapped(draw, line[2:], margin + 30, y, max_width - 30, body_font, fill=(31, 41, 55), prefix="- ")
        else:
            y = draw_wrapped(draw, line, margin, y, max_width, body_font, fill=(31, 41, 55))
            y += 12

    footer = "\u672c\u7533\u62a5\u4e66\u4e3a\u4e00\u9875\u6458\u8981\u7248\uff1b\u8be6\u7ec6\u8bf4\u660e\u89c1 docs/submission-application.md\u3002"
    draw.text((margin, height - 150), footer, font=small_font, fill=(100, 116, 139))

    if "--preview" in sys.argv:
        image.save(PNG_OUT)
        print(PNG_OUT)
    image.save(PDF_OUT, "PDF", resolution=300.0)
    print(PDF_OUT)


if __name__ == "__main__":
    main()
