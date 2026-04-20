from __future__ import annotations

from core.models import AnalysisResult, RuleResult
from ui import components


def test_get_triggered_rule_by_id_returns_matching_rule() -> None:
    analysis = AnalysisResult(
        score=50,
        risk_level="Medium",
        confidence=70,
        triggered_rules=[
            RuleResult("urgency_language", "Urgency", True, 12, "Urgency found"),
            RuleResult("shortened_url", "Shortener", True, 10, "Shortener found"),
        ],
        top_reasons=[],
    )

    match = components.get_triggered_rule_by_id(analysis, "shortened_url")
    missing = components.get_triggered_rule_by_id(analysis, "not_here")

    assert match is not None
    assert match.rule_id == "shortened_url"
    assert missing is None


def test_estimate_rule_card_height_respects_min_and_max_bounds() -> None:
    short_rule = RuleResult("r1", "Short", True, 5, "tiny", [])
    long_rule = RuleResult(
        "r2",
        "Very long rule name",
        True,
        5,
        "This is a very long reason " * 20,
        ["evidence " * 20] * 3,
    )

    short_height = components.estimate_rule_card_height(short_rule)
    long_height = components.estimate_rule_card_height(long_rule)

    assert 170 <= short_height <= 340
    assert 170 <= long_height <= 340
    assert long_height >= short_height


def test_render_bullet_list_writes_markdown_bullets(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(components.st, "markdown", lambda text, **kwargs: calls.append(text))

    components.render_bullet_list(["one", "two"])

    assert calls == ["- one\n- two"]


def test_render_section_title_uses_expected_css_class(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(components.st, "markdown", lambda text, **kwargs: calls.append((text, kwargs)))

    components.render_section_title("Top reasons")

    assert "ph-section-title" in calls[0][0]
    assert calls[0][1].get("unsafe_allow_html") is True


def test_rule_container_falls_back_when_height_argument_not_supported(monkeypatch) -> None:
    call_kwargs = []

    def fake_container(**kwargs):
        call_kwargs.append(kwargs)
        if "height" in kwargs:
            raise TypeError("height not supported")
        return {"ok": True}

    monkeypatch.setattr(components.st, "container", fake_container)

    result = components.rule_container(220)

    assert result == {"ok": True}
    assert call_kwargs[0] == {"border": True, "height": 220}
    assert call_kwargs[1] == {"border": True}


def test_render_top_reasons_writes_fallback_message_when_no_reasons(monkeypatch) -> None:
    analysis = AnalysisResult(score=0, risk_level="Low", confidence=60, triggered_rules=[], top_reasons=[])

    title_calls = []
    write_calls = []
    monkeypatch.setattr(components, "render_section_title", lambda title: title_calls.append(title))
    monkeypatch.setattr(components.st, "write", lambda text: write_calls.append(text))

    components.render_top_reasons(analysis)

    assert title_calls == ["Top reasons"]
    assert write_calls == ["No major phishing indicators were triggered."]
