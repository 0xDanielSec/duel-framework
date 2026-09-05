#!/usr/bin/env python3
"""
Generate docs/ERRATA.pdf from docs/ERRATA.md using ReportLab.

Reuses the style registry and low-level markdown helpers (inline formatting,
table rendering, page footer) from generate_paper_pdf.py, but with a much
simpler block parser suited to ERRATA.md's flat structure (H1 title, H2
numbered items, paragraphs, tables, `---` rules) rather than the paper's
cover/abstract/numbered-sections/references layout.

Usage:
    python scripts/generate_errata_pdf.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.units import mm

from generate_paper_pdf import (  # noqa: E402 — reuse, don't reimplement
    C, CW, ML, MR, MT, MB, STYLES,
    _build_table, _footer, _inline, _is_tbl_row, _is_tbl_sep, _split_row,
)
from reportlab.lib.pagesizes import A4

DOCS_DIR   = Path(__file__).parent.parent / "docs"
INPUT_MD   = DOCS_DIR / "ERRATA.md"
OUTPUT_PDF = DOCS_DIR / "ERRATA.pdf"

GITHUB_URL = "https://github.com/0xDanielSec/duel-framework"


def _build_story(lines: list[str]) -> list:
    story: list = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i].rstrip("\n")
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "---":
            story.append(Spacer(1, 4 * mm))
            i += 1
            continue

        if stripped.startswith("# "):
            story.append(Paragraph(_inline(stripped[2:]), STYLES["doc_title"]))
            i += 1
            continue

        if stripped.startswith("## "):
            story.append(Paragraph(_inline(stripped[3:]), STYLES["h1"]))
            i += 1
            continue

        if _is_tbl_row(stripped):
            header = _split_row(stripped)
            i += 1
            if i < n and _is_tbl_sep(lines[i].strip()):
                i += 1
            rows = []
            while i < n and _is_tbl_row(lines[i].strip()):
                rows.append(_split_row(lines[i].strip()))
                i += 1
            story.append(Spacer(1, 2 * mm))
            story.append(_build_table(header, rows))
            story.append(Spacer(1, 3 * mm))
            continue

        if stripped.startswith(">"):
            # blockquote used as a callout — treat like a bold quoted line
            story.append(Paragraph(_inline(stripped.lstrip("> ").strip()), STYLES["finding"]))
            i += 1
            continue

        # Plain paragraph
        story.append(Paragraph(_inline(stripped), STYLES["body_ni"]))
        i += 1

    return story


def generate() -> Path:
    lines = INPUT_MD.read_text(encoding="utf-8").splitlines()
    story = _build_story(lines)

    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=ML, rightMargin=MR,
        topMargin=MT, bottomMargin=MB + 8 * mm,
        title="Errata — Scaling Laws Do Not Predict Adversarial Robustness",
        author="Daniel Gomes",
        subject="DUEL Framework — Errata to the published paper",
        creator="DUEL Framework / ReportLab",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return OUTPUT_PDF


if __name__ == "__main__":
    if not INPUT_MD.exists():
        print(f"Error: {INPUT_MD} not found", file=sys.stderr)
        sys.exit(1)
    try:
        path = generate()
        size_kb = path.stat().st_size // 1024
        print(f"OK PDF generated: {path} ({size_kb} KB)")
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
