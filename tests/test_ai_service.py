from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from core.ai_service import (
    AI_UNAVAILABLE_MESSAGE,
    build_ai_prompt,
    call_ollama,
    extract_json_object,
    generate_ai_result,
    normalize_category,
    normalize_confidence_label,
    normalize_reasons,
    normalize_score,
    parse_ai_json,
)
from core.models import AnalysisResult, ParsedEmail, RuleResult


def _parsed() -> ParsedEmail:
    return ParsedEmail(
        subject="Security alert",
        body_text="Please verify your account now",
        from_raw="Microsoft Support <alert@secure-notify-mail.com>",
        from_email="alert@secure-notify-mail.com",
        from_domain="secure-notify-mail.com",
        reply_to_raw="support@random-helpdesk.net",
        reply_to_email="support@random-helpdesk.net",
        reply_to_domain="random-helpdesk.net",
        urls=["http://bit.ly/verify"],
        url_domains=["bit.ly"],
        suspicious_phrases=["security alert", "verify your account"],
    )


def _analysis() -> AnalysisResult:
    return AnalysisResult(
        score=72,
        risk_level="High",
        confidence=82,
        triggered_rules=[
            RuleResult(
                "high_risk_phrases",
                "High risk",
                True,
                15,
                "Suspicious account wording",
                ["verify your account"],
            ),
        ],
        top_reasons=["Suspicious account wording"],
    )


def test_build_ai_prompt_contains_key_sections() -> None:
    prompt = build_ai_prompt(_parsed(), _analysis())

    assert "Return only valid JSON" in prompt
    assert "Phishing analysis findings:" in prompt
    assert "Parsed email:" in prompt
    assert "URLs:" in prompt
    assert "Triggered rules:" in prompt


def test_extract_json_object_extracts_embedded_json() -> None:
    raw = 'Some prefix {"a":1,"b":2} suffix'
    assert extract_json_object(raw) == '{"a":1,"b":2}'


def test_extract_json_object_raises_for_missing_json() -> None:
    with pytest.raises(ValueError):
        extract_json_object("no json here")


def test_parse_ai_json_parses_valid_payload() -> None:
    raw = '{"suspicion_score": 77, "category": "phishing", "confidence": "high", "reasons": ["r1"], "explanation": "ok"}'
    payload = parse_ai_json(raw)
    assert payload["suspicion_score"] == 77
    assert payload["category"] == "phishing"


def test_parse_ai_json_raises_for_invalid_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_ai_json("{invalid-json}")


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 0), ("42", 42), (150, 100), (-10, 0), ("not-int", 0)],
)
def test_normalize_score(value, expected) -> None:
    assert normalize_score(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "safe"), ("PHISHING", "phishing"), ("unknown", "safe")],
)
def test_normalize_category(value, expected) -> None:
    assert normalize_category(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "low"), ("HIGH", "high"), ("other", "low")],
)
def test_normalize_confidence_label(value, expected) -> None:
    assert normalize_confidence_label(value) == expected


def test_normalize_reasons_filters_blank_values() -> None:
    assert normalize_reasons([" reason one ", "", "  ", 123]) == ["reason one", "123"]
    assert normalize_reasons("not-a-list") == []


def test_call_ollama_uses_requests_post_and_returns_response_text(monkeypatch) -> None:
    mock_response = Mock()
    mock_response.json.return_value = {"response": '{"explanation": "ok"}'}
    mock_response.raise_for_status.return_value = None

    post_calls = {}

    def fake_post(url, json=None, timeout=None):
        post_calls["url"] = url
        post_calls["json"] = json
        post_calls["timeout"] = timeout
        return mock_response

    monkeypatch.setattr("core.ai_service.requests.post", fake_post)

    result = call_ollama(prompt="hello", model="llama3.2:3b")
    assert result == '{"explanation": "ok"}'
    assert post_calls["json"]["stream"] is False


def test_generate_ai_result_returns_success_payload_on_valid_json(monkeypatch) -> None:
    raw_json = json.dumps(
        {
            "suspicion_score": 88,
            "category": "phishing",
            "confidence": "high",
            "reasons": ["credential bait"],
            "explanation": "This email is suspicious.",
        }
    )
    monkeypatch.setattr("core.ai_service.call_ollama", lambda prompt, model: raw_json)

    result = generate_ai_result(_parsed(), _analysis(), model="llama3.2:3b")

    assert result.used_ai is True
    assert result.suspicion_score == 88
    assert result.category == "phishing"
    assert result.confidence_label == "high"
    assert result.reasons == ["credential bait"]
    assert result.explanation == "This email is suspicious."


def test_generate_ai_result_falls_back_cleanly_when_ollama_fails(monkeypatch) -> None:
    def raise_error(prompt, model):
        raise RuntimeError("connection failed")

    monkeypatch.setattr("core.ai_service.call_ollama", raise_error)

    result = generate_ai_result(_parsed(), _analysis(), model="llama3.2:3b")

    assert result.used_ai is False
    assert result.explanation == AI_UNAVAILABLE_MESSAGE
    assert "connection failed" in (result.error or "")
