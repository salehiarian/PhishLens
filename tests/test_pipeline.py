from __future__ import annotations

from core.models import AIResult, AnalysisResult, AnalysisPayload, ParsedEmail, RuleResult
from core.pipeline import build_analysis_payload


def _parsed() -> ParsedEmail:
    return ParsedEmail(
        subject="Subject",
        body_text="Body",
        from_raw="from@domain.com",
        from_email="from@domain.com",
        from_domain="domain.com",
        reply_to_raw="reply@other.com",
        reply_to_email="reply@other.com",
        reply_to_domain="other.com",
        urls=["http://bit.ly/x"],
        url_domains=["bit.ly"],
        suspicious_phrases=["urgent"],
    )


def test_pipeline_orchestrates_parse_rules_ai_blend_and_formatting(monkeypatch) -> None:
    calls = []

    parsed = _parsed()
    rule_analysis = AnalysisResult(
        score=62,
        risk_level="Medium",
        confidence=70,
        triggered_rules=[RuleResult("urgency_language", "Urgency", True, 12, "Urgency language detected")],
        top_reasons=["Urgency language detected"],
    )
    ai_result = AIResult(
        explanation="AI review",
        suspicion_score=80,
        category="phishing",
        confidence_label="high",
        reasons=["AI reason"],
        used_ai=True,
    )
    blended = AnalysisResult(
        score=67,
        risk_level="Medium",
        confidence=75,
        triggered_rules=rule_analysis.triggered_rules,
        top_reasons=rule_analysis.top_reasons,
    )

    monkeypatch.setattr("core.pipeline.parse_email_content", lambda *args: calls.append("parse") or parsed)
    monkeypatch.setattr("core.pipeline.analyze_email", lambda p: calls.append("rules") or rule_analysis)
    monkeypatch.setattr("core.pipeline.generate_ai_result", lambda p, a, model: calls.append("ai") or ai_result)
    monkeypatch.setattr("core.pipeline.blend_rule_and_ai_scores", lambda r, a: calls.append("blend") or blended)
    monkeypatch.setattr("core.pipeline.build_next_steps", lambda analysis: calls.append("steps") or ["step 1", "step 2"])
    monkeypatch.setattr("core.pipeline.build_ticket_summary", lambda p, a, s: calls.append("summary") or "ticket summary")

    payload = build_analysis_payload(
        email="email text",
        from_address="from@domain.com",
        reply_to_address="reply@other.com",
        subject="subject",
        model="llama3.2:3b",
    )

    assert isinstance(payload, AnalysisPayload)
    assert payload.parsed == parsed
    assert payload.analysis == blended
    assert payload.ai_result == ai_result
    assert payload.next_steps == ["step 1", "step 2"]
    assert payload.ticket_summary == "ticket summary"
    assert calls == ["parse", "rules", "ai", "blend", "steps", "summary"]


def test_pipeline_uses_rule_result_when_ai_is_unavailable(monkeypatch) -> None:
    parsed = _parsed()
    rule_analysis = AnalysisResult(score=45, risk_level="Medium", confidence=68, triggered_rules=[], top_reasons=[])
    ai_failure = AIResult(explanation="fallback", used_ai=False, error="offline")

    monkeypatch.setattr("core.pipeline.parse_email_content", lambda *args: parsed)
    monkeypatch.setattr("core.pipeline.analyze_email", lambda p: rule_analysis)
    monkeypatch.setattr("core.pipeline.generate_ai_result", lambda p, a, model: ai_failure)
    monkeypatch.setattr("core.pipeline.blend_rule_and_ai_scores", lambda r, a: r)
    monkeypatch.setattr("core.pipeline.build_next_steps", lambda analysis: ["rule-only step"])
    monkeypatch.setattr("core.pipeline.build_ticket_summary", lambda p, a, s: "rule-only summary")

    payload = build_analysis_payload("mail", "from", "reply", "subject", model="llama3.2:3b")

    assert payload.analysis == rule_analysis
    assert payload.ai_result.used_ai is False
    assert payload.next_steps == ["rule-only step"]


def test_pipeline_passes_rule_analysis_into_blend_as_foundation(monkeypatch) -> None:
    parsed = _parsed()
    rule_analysis = AnalysisResult(score=30, risk_level="Low", confidence=60, triggered_rules=[], top_reasons=[])
    ai_result = AIResult(explanation="ai", suspicion_score=90, confidence_label="high", used_ai=True)

    captured = {}

    monkeypatch.setattr("core.pipeline.parse_email_content", lambda *args: parsed)
    monkeypatch.setattr("core.pipeline.analyze_email", lambda p: rule_analysis)
    monkeypatch.setattr("core.pipeline.generate_ai_result", lambda p, a, model: ai_result)

    def fake_blend(rule_arg, ai_arg):
        captured["rule"] = rule_arg
        captured["ai"] = ai_arg
        return rule_arg

    monkeypatch.setattr("core.pipeline.blend_rule_and_ai_scores", fake_blend)
    monkeypatch.setattr("core.pipeline.build_next_steps", lambda analysis: [])
    monkeypatch.setattr("core.pipeline.build_ticket_summary", lambda p, a, s: "")

    build_analysis_payload("mail", "from", "reply", "subject", model="llama3.2:3b")

    assert captured["rule"] is rule_analysis
    assert captured["ai"] is ai_result
