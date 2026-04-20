from __future__ import annotations

from pathlib import Path
import sys
import types

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import streamlit  # noqa: F401
except ModuleNotFoundError:
    streamlit_stub = types.ModuleType("streamlit")

    def _noop(*args, **kwargs):
        return None

    streamlit_stub.markdown = _noop
    streamlit_stub.write = _noop
    streamlit_stub.caption = _noop
    streamlit_stub.info = _noop
    streamlit_stub.progress = _noop
    streamlit_stub.text_area = _noop
    streamlit_stub.text_input = _noop
    streamlit_stub.toggle = lambda *args, **kwargs: False
    streamlit_stub.button = lambda *args, **kwargs: False
    streamlit_stub.download_button = _noop
    streamlit_stub.columns = lambda *args, **kwargs: []
    streamlit_stub.tabs = lambda *args, **kwargs: []
    streamlit_stub.container = lambda *args, **kwargs: None

    components_pkg = types.ModuleType("streamlit.components")
    v1_mod = types.ModuleType("streamlit.components.v1")
    v1_mod.html = _noop
    components_pkg.v1 = v1_mod

    streamlit_stub.components = types.SimpleNamespace(v1=v1_mod)

    sys.modules["streamlit"] = streamlit_stub
    sys.modules["streamlit.components"] = components_pkg
    sys.modules["streamlit.components.v1"] = v1_mod

from core.models import AIResult, AnalysisResult, ParsedEmail, RuleResult


@pytest.fixture
def parsed_email_basic() -> ParsedEmail:
    return ParsedEmail(
        subject="Security alert",
        body_text="Please verify your account now. Click here: http://bit.ly/verify",
        from_raw="Microsoft Support <alert@secure-notify-mail.com>",
        from_email="alert@secure-notify-mail.com",
        from_domain="secure-notify-mail.com",
        reply_to_raw="support@random-helpdesk.net",
        reply_to_email="support@random-helpdesk.net",
        reply_to_domain="random-helpdesk.net",
        urls=["http://bit.ly/verify"],
        url_domains=["bit.ly"],
        suspicious_phrases=["security alert", "verify your account", "click here"],
    )


@pytest.fixture
def rule_result_factory():
    def _make(
        *,
        rule_id: str,
        weight: int,
        triggered: bool = True,
        reason: str | None = None,
        name: str | None = None,
        evidence: list[str] | None = None,
    ) -> RuleResult:
        return RuleResult(
            rule_id=rule_id,
            name=name or rule_id,
            triggered=triggered,
            weight=weight,
            reason=reason or f"reason for {rule_id}",
            evidence=evidence or [],
        )

    return _make


@pytest.fixture
def analysis_result_factory(rule_result_factory):
    def _make(
        *,
        score: int = 0,
        risk_level: str = "Low",
        confidence: int = 60,
        rules: list[RuleResult] | None = None,
    ) -> AnalysisResult:
        triggered_rules = rules or []
        top_reasons = [r.reason for r in triggered_rules[:4]]
        return AnalysisResult(
            score=score,
            risk_level=risk_level,
            confidence=confidence,
            triggered_rules=triggered_rules,
            top_reasons=top_reasons,
        )

    return _make


@pytest.fixture
def ai_result_factory():
    def _make(
        *,
        explanation: str = "AI explanation",
        suspicion_score: int | None = None,
        category: str | None = None,
        confidence_label: str | None = None,
        reasons: list[str] | None = None,
        used_ai: bool = True,
        model_used: str = "llama3.2:3b",
        error: str | None = None,
    ) -> AIResult:
        return AIResult(
            explanation=explanation,
            suspicion_score=suspicion_score,
            category=category,
            confidence_label=confidence_label,
            reasons=reasons or [],
            next_steps=[],
            ticket_summary="",
            model_used=model_used,
            used_ai=used_ai,
            error=error,
        )

    return _make
