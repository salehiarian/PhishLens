from __future__ import annotations

from core.models import AIResult, AnalysisResult, ParsedEmail, RuleResult
from core.rules import (
    blend_rule_and_ai_scores,
    check_brand_link_mismatch,
    check_excessive_punctuation_or_caps,
    check_from_reply_to_mismatch,
    check_high_risk_phrases,
    check_impersonation_wording,
    check_ip_based_link,
    check_long_or_messy_domain,
    check_many_links_in_short_email,
    check_punycode_link,
    check_scam_offer_language,
    check_shortened_url,
    check_spam_lure_language,
    check_suspicious_link_domain,
    check_suspicious_url_keywords,
    check_too_many_subdomains,
    check_urgency_language,
    run_rules,
    score_rules,
)


def _parsed(**overrides) -> ParsedEmail:
    base = ParsedEmail(
        subject="Security alert",
        body_text="Please verify your account now.",
        from_raw="Microsoft Support <alert@secure-notify-mail.com>",
        from_email="alert@secure-notify-mail.com",
        from_domain="secure-notify-mail.com",
        reply_to_raw="support@random-helpdesk.net",
        reply_to_email="support@random-helpdesk.net",
        reply_to_domain="random-helpdesk.net",
        urls=["http://bit.ly/verify"],
        url_domains=["bit.ly"],
        suspicious_phrases=["urgent", "verify your account", "click here"],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_from_reply_to_mismatch_rule_triggers_when_domains_differ() -> None:
    result = check_from_reply_to_mismatch(_parsed())
    assert result.triggered is True
    assert result.weight == 20


def test_urgency_language_rule_triggers_for_urgent_phrase() -> None:
    result = check_urgency_language(_parsed())
    assert result.triggered is True
    assert "urgent" in result.evidence


def test_high_risk_phrase_rule_triggers_for_verify_account() -> None:
    result = check_high_risk_phrases(_parsed())
    assert result.triggered is True
    assert "verify your account" in result.evidence


def test_impersonation_wording_triggers_for_brand_sender_text() -> None:
    result = check_impersonation_wording(_parsed())
    assert result.triggered is True
    assert "microsoft" in result.evidence


def test_suspicious_link_domain_triggers_for_login_keyword_in_host() -> None:
    parsed = _parsed(url_domains=["secure-login-check.example.com"])
    result = check_suspicious_link_domain(parsed)
    assert result.triggered is True


def test_brand_link_mismatch_triggers_when_brand_does_not_match_link_host() -> None:
    parsed = _parsed(subject="PayPal account notice", url_domains=["mail-verify-check.net"])
    result = check_brand_link_mismatch(parsed)
    assert result.triggered is True


def test_shortened_url_triggers_for_known_shortener_domain() -> None:
    result = check_shortened_url(_parsed(url_domains=["bit.ly"]))
    assert result.triggered is True


def test_spam_lure_language_triggers_for_lure_phrase() -> None:
    parsed = _parsed(suspicious_phrases=["winner", "claim your prize"])
    result = check_spam_lure_language(parsed)
    assert result.triggered is True


def test_scam_offer_language_triggers_from_subject_or_body() -> None:
    parsed = _parsed(subject="Risk-free investment today", body_text="No experience needed")
    result = check_scam_offer_language(parsed)
    assert result.triggered is True


def test_excessive_punctuation_or_caps_triggers_for_spam_style_text() -> None:
    parsed = _parsed(subject="WIN BIG NOW!!!", body_text="Act now!!! $$$")
    result = check_excessive_punctuation_or_caps(parsed)
    assert result.triggered is True


def test_link_hardening_rules_trigger_for_ip_punycode_many_links_and_keywords() -> None:
    parsed = _parsed(
        body_text="short body",
        urls=[
            "http://192.168.1.10/login",
            "http://xn--paypal-alert-abc.com/verify",
            "http://a.b.c.d.example.com/update",
            "http://normal.example.com/signin",
        ],
        url_domains=[
            "192.168.1.10",
            "xn--paypal-alert-abc.com",
            "a.b.c.d.example.com",
            "normal.example.com",
        ],
    )

    assert check_ip_based_link(parsed).triggered is True
    assert check_punycode_link(parsed).triggered is True
    assert check_many_links_in_short_email(parsed).triggered is True
    assert check_suspicious_url_keywords(parsed).triggered is True
    assert check_too_many_subdomains(parsed).triggered is True
    assert check_long_or_messy_domain(parsed).triggered is True


def test_score_rules_zero_trigger_case_returns_zero_score_and_low_risk() -> None:
    rules = [RuleResult("r1", "r1", False, 20, "reason")]
    analysis = score_rules(rules)

    assert analysis.score == 0
    assert analysis.risk_level == "Low"
    assert analysis.confidence == 60
    assert analysis.top_reasons == []


def test_score_rules_caps_to_100_for_many_strong_triggers() -> None:
    triggered = [
        RuleResult("a", "a", True, 25, "a"),
        RuleResult("b", "b", True, 25, "b"),
        RuleResult("c", "c", True, 25, "c"),
        RuleResult("d", "d", True, 20, "d"),
    ]
    analysis = score_rules(triggered)
    assert analysis.score == 100
    assert analysis.risk_level == "High"


def test_score_rules_sorts_top_reasons_by_weight_and_limits_length() -> None:
    rules = [
        RuleResult("r1", "r1", True, 10, "reason 1"),
        RuleResult("r2", "r2", True, 18, "reason 2"),
        RuleResult("r3", "r3", True, 12, "reason 3"),
        RuleResult("r4", "r4", True, 16, "reason 4"),
        RuleResult("r5", "r5", True, 14, "reason 5"),
    ]
    analysis = score_rules(rules)
    assert analysis.top_reasons[0] == "reason 2"
    assert len(analysis.top_reasons) <= 5


def test_blend_rule_and_ai_scores_uses_rules_as_foundation_when_ai_available() -> None:
    rule_analysis = AnalysisResult(score=80, risk_level="High", confidence=78, triggered_rules=[], top_reasons=[])
    ai_result = AIResult(explanation="ok", suspicion_score=50, confidence_label="medium", used_ai=True)

    blended = blend_rule_and_ai_scores(rule_analysis, ai_result)

    assert blended.score == 75
    assert blended.risk_level == "High"
    assert blended.confidence >= rule_analysis.confidence


def test_blend_rule_and_ai_scores_caps_ai_influence_when_rule_score_is_zero() -> None:
    rule_analysis = AnalysisResult(score=0, risk_level="Low", confidence=60, triggered_rules=[], top_reasons=[])
    ai_result = AIResult(explanation="ok", suspicion_score=95, confidence_label="high", used_ai=True)

    blended = blend_rule_and_ai_scores(rule_analysis, ai_result)

    assert blended.score <= 69
    assert blended.risk_level in {"Low", "Medium"}


def test_blend_rule_and_ai_scores_falls_back_to_rule_only_when_ai_unavailable() -> None:
    rule_analysis = AnalysisResult(score=52, risk_level="Medium", confidence=68, triggered_rules=[], top_reasons=[])
    ai_result = AIResult(explanation="fallback", suspicion_score=None, used_ai=False)

    blended = blend_rule_and_ai_scores(rule_analysis, ai_result)
    assert blended == rule_analysis


def test_run_rules_returns_results_for_all_configured_checks(parsed_email_basic) -> None:
    results = run_rules(parsed_email_basic)
    assert results
    assert all(isinstance(item, RuleResult) for item in results)
