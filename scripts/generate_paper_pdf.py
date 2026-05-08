#!/usr/bin/env python3
"""
Generate docs/paper.pdf from docs/paper.md using ReportLab.

Academic single-column layout with:
  - Title / author / abstract cover block
  - Numbered sections and subsections
  - Styled tables with captions
  - Monospace code blocks
  - Numbered reference list
  - DUEL framework link in page footer

Usage:
    python scripts/generate_paper_pdf.py
"""

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Paths ─────────────────────────────────────────────────────────────────────

DOCS_DIR   = Path(__file__).parent.parent / "docs"
INPUT_MD   = DOCS_DIR / "paper.md"
OUTPUT_PDF = DOCS_DIR / "paper.pdf"

GITHUB_URL  = "https://github.com/0xDanielSec/duel-framework"
FOOTER_TEXT = f"DUEL - Dual Unified Evasion Loop  |  {GITHUB_URL}"

# ── Page geometry ─────────────────────────────────────────────────────────────

PAGE_W, PAGE_H = A4
ML = 28 * mm      # left margin
MR = 28 * mm      # right margin
MT = 20 * mm      # top margin
MB = 20 * mm      # bottom margin
CW = PAGE_W - ML - MR  # usable content width

# ── Colour palette ─────────────────────────────────────────────────────────────

C = {
    "navy":   HexColor("#0f2044"),
    "dark":   HexColor("#1e3a5f"),
    "blue":   HexColor("#1a5cbf"),
    "red":    HexColor("#9b1c1c"),
    "green":  HexColor("#14532d"),
    "border": HexColor("#c8d4e8"),
    "hdr":    HexColor("#1e3a5f"),
    "alt":    HexColor("#f8fafc"),
    "code_bg":HexColor("#f1f5f9"),
    "code_bd":HexColor("#cbd5e1"),
    "text":   HexColor("#111827"),
    "muted":  HexColor("#6b7280"),
    "rule":   HexColor("#9fb3cc"),
    "abs_bg": HexColor("#f0f4f8"),
    "abs_bd": HexColor("#93b4d0"),
}


# ── Style registry ────────────────────────────────────────────────────────────

def _s(name, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **kw)


STYLES: dict[str, ParagraphStyle] = {
    # ── Cover ────────────────────────────────────────────────────────────── #
    "doc_title": _s("doc_title",
        fontName="Times-Bold", fontSize=19, textColor=C["navy"],
        alignment=TA_CENTER, leading=25, spaceAfter=5 * mm,
    ),
    "author_name": _s("author_name",
        fontName="Times-Bold", fontSize=11, textColor=C["text"],
        alignment=TA_CENTER, leading=16, spaceAfter=1 * mm,
    ),
    "author_aff": _s("author_aff",
        fontName="Times-Italic", fontSize=10, textColor=C["muted"],
        alignment=TA_CENTER, leading=14, spaceAfter=1 * mm,
    ),
    "preprint": _s("preprint",
        fontName="Helvetica-BoldOblique", fontSize=9, textColor=C["blue"],
        alignment=TA_CENTER, spaceAfter=5 * mm,
    ),
    # ── Abstract ─────────────────────────────────────────────────────────── #
    "abs_hdr": _s("abs_hdr",
        fontName="Helvetica-Bold", fontSize=9, textColor=C["muted"],
        alignment=TA_CENTER, letterSpacing=2, spaceAfter=2 * mm,
    ),
    "abs_body": _s("abs_body",
        fontName="Times-Roman", fontSize=9.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=14,
        leftIndent=6 * mm, rightIndent=6 * mm,
    ),
    # ── Sections ─────────────────────────────────────────────────────────── #
    "h1": _s("h1",
        fontName="Times-Bold", fontSize=13, textColor=C["navy"],
        spaceBefore=10 * mm, spaceAfter=3 * mm, leading=17,
        borderPadding=(0, 0, 2, 0),
    ),
    "h2": _s("h2",
        fontName="Times-Bold", fontSize=11, textColor=C["dark"],
        spaceBefore=6 * mm, spaceAfter=2 * mm, leading=14,
    ),
    # ── Body ─────────────────────────────────────────────────────────────── #
    "body": _s("body",
        fontName="Times-Roman", fontSize=10.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=16, spaceAfter=3 * mm,
        firstLineIndent=5 * mm,
    ),
    "body_ni": _s("body_ni",
        fontName="Times-Roman", fontSize=10.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=16, spaceAfter=3 * mm,
    ),
    "finding": _s("finding",
        fontName="Times-Roman", fontSize=10.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=16, spaceAfter=2 * mm,
        leftIndent=5 * mm,
        borderPadding=(3, 0, 3, 0),
    ),
    "bullet": _s("bullet",
        fontName="Times-Roman", fontSize=10.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=16, spaceAfter=1.5 * mm,
        leftIndent=8 * mm, firstLineIndent=-5 * mm,
    ),
    # ── Tables ───────────────────────────────────────────────────────────── #
    "tbl_caption": _s("tbl_caption",
        fontName="Times-Bold", fontSize=9.5, textColor=C["text"],
        alignment=TA_CENTER, spaceBefore=4 * mm, spaceAfter=1.5 * mm,
    ),
    "th": _s("th",
        fontName="Helvetica-Bold", fontSize=8, textColor=white,
        alignment=TA_CENTER, leading=11,
    ),
    "td": _s("td",
        fontName="Helvetica", fontSize=8, textColor=C["text"],
        leading=11, wordWrap="LTR",
    ),
    "td_c": _s("td_c",
        fontName="Helvetica", fontSize=8, textColor=C["text"],
        alignment=TA_CENTER, leading=11,
    ),
    # ── Code ─────────────────────────────────────────────────────────────── #
    "code": _s("code",
        fontName="Courier", fontSize=8, textColor=C["text"],
        leading=11, leftIndent=3 * mm, rightIndent=3 * mm,
        spaceAfter=3 * mm,
    ),
    # ── References ───────────────────────────────────────────────────────── #
    "ref": _s("ref",
        fontName="Times-Roman", fontSize=9.5, textColor=C["text"],
        alignment=TA_JUSTIFY, leading=13,
        leftIndent=8 * mm, firstLineIndent=-8 * mm,
        spaceAfter=2 * mm,
    ),
    "bibtex_body": _s("bibtex_body",
        fontName="Courier", fontSize=8, textColor=C["text"],
        leading=11,
    ),
    "disclaimer": _s("disclaimer",
        fontName="Times-Italic", fontSize=9, textColor=C["muted"],
        alignment=TA_CENTER, leading=13, spaceBefore=5 * mm,
    ),
}


# ── Inline markdown → ReportLab XML ──────────────────────────────────────────

def _inline(text: str) -> str:
    """Convert inline markdown to ReportLab XML. Must HTML-escape first."""
    text = html.escape(text, quote=False)
    # **bold**
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    # *italic*
    text = re.sub(r"\*([^*]+?)\*", r"<i>\1</i>", text)
    # `code`
    text = re.sub(r"`([^`]+?)`",
                  r'<font face="Courier" size="8">\1</font>', text)
    # [text](url) → underlined text
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"<u>\1</u>", text)
    return text


def _p(text: str, style: str) -> Paragraph:
    return Paragraph(_inline(text), STYLES[style])


# ── Markdown table parser ─────────────────────────────────────────────────────

def _is_tbl_row(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") and s.endswith("|")


def _is_tbl_sep(line: str) -> bool:
    return _is_tbl_row(line) and bool(re.match(r"\|[\s\-:|]+\|", line.strip()))


def _split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _build_table(headers: list[str], rows: list[list[str]]) -> Table:
    """Build a styled ReportLab Table from header + data rows."""
    n_cols = len(headers)
    col_w  = CW / n_cols

    header_row = [Paragraph(_inline(h), STYLES["th"]) for h in headers]
    data_rows  = []
    for row in rows:
        data_rows.append([
            Paragraph(_inline(cell), STYLES["td_c"] if cell.replace(".", "").replace("%", "").replace("-", "").isdigit() else STYLES["td"])
            for cell in row
        ])

    tbl = Table([header_row] + data_rows, colWidths=[col_w] * n_cols, repeatRows=1)

    style = [
        ("BACKGROUND",    (0, 0), (-1, 0),  C["hdr"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 1), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.4, C["border"]),
    ]
    for i in range(2, len(data_rows) + 1, 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C["alt"]))

    tbl.setStyle(TableStyle(style))
    return tbl


# ── Code block builder ────────────────────────────────────────────────────────

def _build_code(lines: list[str]) -> Table:
    """Render a monospace code block with a light background."""
    text = "<br/>".join(html.escape(ln, quote=False) for ln in lines)
    para = Paragraph(f'<font face="Courier" size="8">{text}</font>',
                     ParagraphStyle("code_inner", fontName="Courier",
                                    fontSize=8, textColor=C["text"],
                                    leading=11, leftIndent=3*mm, rightIndent=3*mm,
                                    wordWrap="LTR"))
    t = Table([[para]], colWidths=[CW])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["code_bg"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3 * mm),
        ("LINEBEFORE",    (0, 0), (-1, -1), 3, C["blue"]),
        ("BOX",           (0, 0), (-1, -1), 0.4, C["code_bd"]),
    ]))
    return t


# ── Abstract box ──────────────────────────────────────────────────────────────

def _build_abstract_box(text: str) -> Table:
    """Render abstract in a bordered grey box."""
    inner = [
        Paragraph("ABSTRACT", STYLES["abs_hdr"]),
        Paragraph(_inline(text), STYLES["abs_body"]),
    ]
    t = Table([[inner]], colWidths=[CW])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["abs_bg"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5 * mm),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5 * mm),
        ("BOX",           (0, 0), (-1, -1), 1.2, C["abs_bd"]),
    ]))
    return t


# ── Section rule ──────────────────────────────────────────────────────────────

def _section_rule() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5,
                      color=C["rule"], spaceAfter=1 * mm)


# ── Page footer ───────────────────────────────────────────────────────────────

def _footer(canvas, doc):
    canvas.saveState()
    y = MB - 10 * mm
    canvas.setStrokeColor(C["rule"])
    canvas.setLineWidth(0.5)
    canvas.line(ML, y + 4 * mm, PAGE_W - MR, y + 4 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C["muted"])
    canvas.drawString(ML, y, FOOTER_TEXT)
    canvas.drawRightString(PAGE_W - MR, y, f"Page {doc.page}")
    canvas.restoreState()


# ── Markdown parser ───────────────────────────────────────────────────────────

class _Block:
    __slots__ = ("kind", "payload")
    def __init__(self, kind: str, payload):
        self.kind    = kind
        self.payload = payload


def _parse(source: str) -> list[_Block]:
    lines  = source.splitlines()
    blocks: list[_Block] = []
    i      = 0
    n      = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # ── Code block ──────────────────────────────────────────────────── #
        if stripped.startswith("```"):
            lang   = stripped[3:].strip()
            i     += 1
            code_lines: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # closing ```
            blocks.append(_Block("code", {"lang": lang, "lines": code_lines}))
            continue

        # ── Horizontal rule ─────────────────────────────────────────────── #
        if re.match(r"^---+$", stripped):
            blocks.append(_Block("hr", None))
            i += 1
            continue

        # ── H1 title ────────────────────────────────────────────────────── #
        if stripped.startswith("# ") and not stripped.startswith("## "):
            blocks.append(_Block("h1", stripped[2:].strip()))
            i += 1
            continue

        # ── H2 section ──────────────────────────────────────────────────── #
        if stripped.startswith("## "):
            blocks.append(_Block("h2", stripped[3:].strip()))
            i += 1
            continue

        # ── H3 subsection ───────────────────────────────────────────────── #
        if stripped.startswith("### "):
            blocks.append(_Block("h3", stripped[4:].strip()))
            i += 1
            continue

        # ── Table ────────────────────────────────────────────────────────── #
        if _is_tbl_row(stripped):
            headers = _split_row(stripped)
            i += 1
            # skip separator row
            if i < n and _is_tbl_sep(lines[i]):
                i += 1
            rows: list[list[str]] = []
            while i < n and _is_tbl_row(lines[i].strip()):
                rows.append(_split_row(lines[i]))
                i += 1
            blocks.append(_Block("table", {"headers": headers, "rows": rows}))
            continue

        # ── Empty line ───────────────────────────────────────────────────── #
        if not stripped:
            blocks.append(_Block("blank", None))
            i += 1
            continue

        # ── Bold-only line (author, finding label, caption, etc.) ───────── #
        # Treat as paragraph — the inline converter handles **bold**
        blocks.append(_Block("para", stripped))
        i += 1

    return blocks


# ── Story builder ─────────────────────────────────────────────────────────────

def _build_story(blocks: list[_Block]) -> list:
    story: list = []
    in_abstract     = False
    abstract_lines: list[str] = []
    in_references   = False
    in_bibtex       = False
    pending_caption: str | None = None
    after_blank     = True   # first paragraph of a section: no indent

    def flush_abstract():
        nonlocal in_abstract, abstract_lines
        if abstract_lines:
            story.append(_build_abstract_box(" ".join(abstract_lines)))
            story.append(Spacer(1, 4 * mm))
        in_abstract    = False
        abstract_lines = []

    i = 0
    n = len(blocks)

    while i < n:
        b = blocks[i]

        # ── Code block ─────────────────────────────────────────────────── #
        if b.kind == "code":
            if in_abstract:
                flush_abstract()
            story.append(_build_code(b.payload["lines"]))
            after_blank = True
            i += 1
            continue

        # ── Horizontal rule ────────────────────────────────────────────── #
        if b.kind == "hr":
            if in_abstract:
                flush_abstract()
            story.append(Spacer(1, 2 * mm))
            story.append(_section_rule())
            story.append(Spacer(1, 2 * mm))
            after_blank = True
            i += 1
            continue

        # ── H1 — document title ────────────────────────────────────────── #
        if b.kind == "h1":
            story.append(Spacer(1, 3 * mm))
            story.append(Paragraph(_inline(b.payload), STYLES["doc_title"]))
            story.append(Spacer(1, 3 * mm))
            i += 1
            continue

        # ── H2 — major section ─────────────────────────────────────────── #
        if b.kind == "h2":
            if in_abstract:
                flush_abstract()
            sec_title = b.payload

            if sec_title.lower() == "abstract":
                in_abstract  = True
                abstract_lines = []
                i += 1
                continue

            if sec_title.lower() in ("references", "reference"):
                in_references = True
                story.append(PageBreak())
                story.append(Paragraph(sec_title, STYLES["h1"]))
                story.append(_section_rule())
                i += 1
                continue

            if "bibtex" in sec_title.lower():
                in_bibtex = True
                story.append(Paragraph(sec_title, STYLES["h1"]))
                i += 1
                continue

            # Normal numbered section
            story.append(Paragraph(_inline(sec_title), STYLES["h1"]))
            story.append(_section_rule())
            after_blank = True
            i += 1
            continue

        # ── H3 — subsection ───────────────────────────────────────────────── #
        if b.kind == "h3":
            if in_abstract:
                flush_abstract()
            story.append(Paragraph(_inline(b.payload), STYLES["h2"]))
            after_blank = True
            i += 1
            continue

        # ── Table ──────────────────────────────────────────────────────── #
        if b.kind == "table":
            if in_abstract:
                flush_abstract()
            tbl = _build_table(b.payload["headers"], b.payload["rows"])
            elems = []
            if pending_caption:
                elems.append(Paragraph(_inline(pending_caption), STYLES["tbl_caption"]))
                pending_caption = None
            elems.append(tbl)
            elems.append(Spacer(1, 3 * mm))
            story.append(KeepTogether(elems))
            after_blank = True
            i += 1
            continue

        # ── Blank line ─────────────────────────────────────────────────── #
        if b.kind == "blank":
            if in_abstract and abstract_lines:
                abstract_lines.append(" ")
            after_blank = True
            i += 1
            continue

        # ── Paragraph ──────────────────────────────────────────────────── #
        if b.kind == "para":
            text = b.payload

            # Collect contiguous paragraphs into the abstract
            if in_abstract:
                abstract_lines.append(text)
                i += 1
                continue

            # BibTeX section — already handled by code block; plain paras get body style
            # Reference items: start with [N]
            if in_references and re.match(r"^\[\d+\]", text):
                story.append(Paragraph(_inline(text), STYLES["ref"]))
                i += 1
                continue

            # Author / affiliation block: lines right after the title that
            # are bold (author name) or plain (affiliation, email, preprint)
            # Detect preprint badge line
            if re.match(r"^\*\*Preprint", text):
                story.append(Paragraph(_inline(text.strip("*")), STYLES["preprint"]))
                i += 1
                continue

            # Author name (bold line at top of document, before first ---)
            if re.match(r"^\*\*[A-Z][^*]+\*\*$", text) and not any(
                bl.kind == "h2" for bl in blocks[:i]
            ):
                story.append(Paragraph(_inline(text), STYLES["author_name"]))
                i += 1
                continue

            # Affiliation / email lines before first ---
            first_hr = next(
                (j for j, bl in enumerate(blocks) if bl.kind == "hr"), n
            )
            if i < first_hr and not text.startswith("#"):
                story.append(Paragraph(_inline(text), STYLES["author_aff"]))
                i += 1
                continue

            # Table caption: bold paragraph immediately before a table block
            next_non_blank = next(
                (j for j in range(i + 1, n) if blocks[j].kind != "blank"), n
            )
            if (next_non_blank < n and blocks[next_non_blank].kind == "table"
                    and re.match(r"^\*\*Table", text)):
                pending_caption = text
                i += 1
                continue

            # Finding label: **Finding N: ...**
            if re.match(r"^\*\*Finding \d+:", text):
                story.append(Paragraph(_inline(text), STYLES["finding"]))
                after_blank = True
                i += 1
                continue

            # Bullet / list item starting with •, -, *, N.
            if re.match(r"^[•\-\*]\s", text) or re.match(r"^\d+\.\s", text):
                story.append(Paragraph(_inline(text), STYLES["bullet"]))
                i += 1
                continue

            # Disclaimer (italic only)
            if text.startswith("*") and text.endswith("*") and not text.startswith("**"):
                story.append(Paragraph(_inline(text), STYLES["disclaimer"]))
                i += 1
                continue

            # Regular paragraph
            style = "body_ni" if after_blank else "body"
            story.append(Paragraph(_inline(text), STYLES[style]))
            after_blank = False
            i += 1
            continue

        i += 1  # safety advance

    if in_abstract:
        flush_abstract()

    return story


# ── Main ──────────────────────────────────────────────────────────────────────

def generate() -> Path:
    source = INPUT_MD.read_text(encoding="utf-8")
    blocks = _parse(source)
    story  = _build_story(blocks)

    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=ML, rightMargin=MR,
        topMargin=MT,  bottomMargin=MB + 8 * mm,
        title="Scaling Laws Do Not Predict Adversarial Robustness in "
              "LLM-Based Security Detection Systems",
        author="Daniel Gomes",
        subject="DUEL Framework — Adversarial LLM Security Research",
        creator="DUEL Framework / ReportLab",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return OUTPUT_PDF


if __name__ == "__main__":
    from rich.console import Console
    console = Console()
    console.print("\n[bold yellow]DUEL — Paper PDF Generator[/bold yellow]")
    console.print(f"  [dim]Input:[/dim]  {INPUT_MD}")
    console.print(f"  [dim]Output:[/dim] {OUTPUT_PDF}")

    if not INPUT_MD.exists():
        console.print(f"[red]Error: {INPUT_MD} not found[/red]")
        sys.exit(1)

    try:
        path = generate()
        size_kb = path.stat().st_size // 1024
        console.print(f"\n[bold green]OK PDF generated:[/bold green] {path}  ([dim]{size_kb} KB[/dim])\n")
    except Exception as exc:
        console.print(f"\n[red]Error: {exc}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
