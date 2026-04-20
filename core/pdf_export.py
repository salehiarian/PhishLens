from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.models import AnalysisResult

def build_ticket_summary_pdf(summary: str, analysis_result: AnalysisResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
        title="PhishLens Ticket Summary",
    )

    title_style, heading_style, body_style = build_pdf_styles()


    elements = [Paragraph("PhishLens Ticket Summary", title_style)]

    meta_table = build_metadata_table(analysis_result)
    elements.extend([meta_table, Spacer(1, 10)])

    add_top_reasons(analysis_result, body_style, elements, heading_style)

    add_summary_section(body_style, elements, heading_style, summary)

    doc.build(elements)
    return buffer.getvalue()


def split_summary_lines(summary: str) -> list[str]:
    return [line.strip() for line in summary.replace("\r\n", "\n").split("\n") if line.strip()]


def build_pdf_styles() -> tuple[ParagraphStyle, ParagraphStyle, ParagraphStyle]:
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "PhishLensTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10,
    )

    heading_style = ParagraphStyle(
        "PhishLensHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=5,
    )

    body_style = ParagraphStyle(
        "PhishLensBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=4,
    )

    return title_style, heading_style, body_style

def build_metadata_table(analysis_result: AnalysisResult) -> Table:
    metadata = [
        ["Risk score", f"{analysis_result.score}/100"],
        ["Risk level", analysis_result.risk_level],
        ["Confidence", f"{analysis_result.confidence}%"],
    ]
    meta_table = Table(metadata, colWidths=[120, 300])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return meta_table

def add_top_reasons(analysis_result: AnalysisResult, body_style: ParagraphStyle, elements: list[Paragraph],
                    heading_style: ParagraphStyle):
    if analysis_result.top_reasons:
        elements.append(Paragraph("Top reasons", heading_style))
        for reason in analysis_result.top_reasons[:4]:
            elements.append(Paragraph(f"• {escape(reason)}", body_style))
        elements.append(Spacer(1, 6))


def add_summary_section(body_style: ParagraphStyle, elements: list[Paragraph], heading_style: ParagraphStyle,
                        summary: str):
    elements.append(Paragraph("Ticket-ready summary", heading_style))
    summary_lines = split_summary_lines(summary)
    if summary_lines:
        for line in summary_lines:
            elements.append(Paragraph(escape(line), body_style))
    else:
        elements.append(Paragraph("No summary text provided.", body_style))
