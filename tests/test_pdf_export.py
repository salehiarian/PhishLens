from __future__ import annotations

from reportlab.platypus import Paragraph, Spacer, Table

from core.models import AnalysisResult
from core.pdf_export import (
    add_summary_section,
    add_top_reasons,
    build_metadata_table,
    build_pdf_styles,
    build_ticket_summary_pdf,
    split_summary_lines,
)


def _analysis(top_reasons=None) -> AnalysisResult:
    return AnalysisResult(
        score=78,
        risk_level="High",
        confidence=86,
        triggered_rules=[],
        top_reasons=top_reasons if top_reasons is not None else ["Reason 1", "Reason 2", "Reason 3", "Reason 4", "Reason 5"],
    )


def test_build_ticket_summary_pdf_returns_non_empty_pdf_bytes() -> None:
    pdf_bytes = build_ticket_summary_pdf("Line one\nLine two", _analysis())

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_build_ticket_summary_pdf_handles_empty_summary() -> None:
    pdf_bytes = build_ticket_summary_pdf("", _analysis())
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500


def test_split_summary_lines_strips_and_skips_empty_lines() -> None:
    assert split_summary_lines(" A \n\nB\r\n C ") == ["A", "B", "C"]


def test_build_metadata_table_returns_table_with_expected_rows() -> None:
    table = build_metadata_table(_analysis())
    assert isinstance(table, Table)
    assert table._cellvalues[0] == ["Risk score", "78/100"]
    assert table._cellvalues[1] == ["Risk level", "High"]
    assert table._cellvalues[2] == ["Confidence", "86%"]


def test_build_pdf_styles_returns_three_named_styles() -> None:
    title_style, heading_style, body_style = build_pdf_styles()
    assert title_style.name == "PhishLensTitle"
    assert heading_style.name == "PhishLensHeading"
    assert body_style.name == "PhishLensBody"


def test_add_top_reasons_appends_heading_reasons_and_spacer() -> None:
    _, heading_style, body_style = build_pdf_styles()
    elements = []

    add_top_reasons(_analysis(), body_style, elements, heading_style)

    assert isinstance(elements[0], Paragraph)
    assert len(elements) == 6
    assert isinstance(elements[-1], Spacer)


def test_add_top_reasons_does_nothing_when_no_reasons() -> None:
    _, heading_style, body_style = build_pdf_styles()
    elements = []

    add_top_reasons(_analysis(top_reasons=[]), body_style, elements, heading_style)
    assert elements == []


def test_add_summary_section_adds_fallback_line_for_empty_summary() -> None:
    _, heading_style, body_style = build_pdf_styles()
    elements = []

    add_summary_section(body_style, elements, heading_style, "")

    assert len(elements) == 2
    assert isinstance(elements[0], Paragraph)
    assert isinstance(elements[1], Paragraph)
