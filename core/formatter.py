from core.models import AnalysisResult, ParsedEmail
from core.config import (
    DEFAULT_NOT_FOUND,
    DEFAULT_NO_URLS,
    DEFAULT_NO_FINDINGS,
)

def build_ticket_summary(parsed: ParsedEmail, analysis: AnalysisResult, next_steps: list[str]) -> str:
    lines = [
        f"Subject: {_get_subject(parsed)}",
        f"Sender: {_get_sender(parsed)}",
        f"URLs: {_get_urls_text(parsed)}",
        f"Findings: {_get_findings_text(analysis)}",
        f"Recommendation: \n{_get_recommendation(next_steps)}",
    ]
    return "\n".join(lines)


def _get_subject(parsed: ParsedEmail) -> str:
    return parsed.subject or DEFAULT_NOT_FOUND


def _get_sender(parsed: ParsedEmail) -> str:
    return parsed.from_email or parsed.from_raw or DEFAULT_NOT_FOUND


def _get_urls_text(parsed: ParsedEmail) -> str:
    return ", ".join(parsed.urls) if parsed.urls else DEFAULT_NO_URLS


def _get_findings_text(analysis: AnalysisResult) -> str:
    return "; ".join(analysis.top_reasons) if analysis.top_reasons else DEFAULT_NO_FINDINGS


def _get_recommendation(next_steps: list[str]) -> str:
    if not next_steps:
        return "- Verify through official channels before taking action."

    return "\n".join(f"- {step}" for step in next_steps)