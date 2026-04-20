import json
import requests
import time
from typing import Any
from core.debug import debug
from core.config import AI_TIMEOUT_SECONDS, DEFAULT_MODEL, OLLAMA_URL, ALLOWED_CONFIDENCE_LABELS, ALLOWED_AI_CATEGORIES, \
    AI_ENABLED
from core.models import AIResult, AnalysisResult, ParsedEmail

AI_UNAVAILABLE_MESSAGE = (
    "AI explanation is unavailable. Showing rule-based results."
)


def build_ai_prompt(parsed: ParsedEmail, analysis: AnalysisResult) -> str:
    prompt_sections = [
        _build_prompt_instructions(),
        _build_analysis_section(analysis),
        _build_parsed_email_section(parsed),
        _build_urls_section(parsed.urls),
        _build_suspicious_phrases_section(parsed.suspicious_phrases),
        _build_triggered_rules_section(analysis),
    ]
    return "\n\n".join(section for section in prompt_sections if section).strip()


def generate_ai_result(
    parsed: ParsedEmail,
    analysis: AnalysisResult,
    model: str = DEFAULT_MODEL,
) -> AIResult:

    if not AI_ENABLED:
        return _build_failure_result(model, Exception("AI is disabled"))



    try:
        prompt = build_ai_prompt(parsed, analysis)
        debug(
            "AI_START",
            model=model,
            score=analysis.score,
            risk=analysis.risk_level,
            triggered=len(analysis.triggered_rules),
            prompt_chars=len(prompt)
        )

        start = time.perf_counter()
        debug(
            "OLLAMA_REQUEST",
            url=OLLAMA_URL,
            timeout=AI_TIMEOUT_SECONDS,
            model=model,
            prompt_chars=len(prompt)
        )

        raw_response = call_ollama(prompt=prompt, model=model)
        debug(
            "OLLAMA_RESPONSE",
            latency_ms=round((time.perf_counter() - start) * 1000),
            response_chars=len(raw_response)
        )

        response_data = parse_ai_json(raw_response)
        debug("AI_PARSED", keys=list(response_data.keys()))

        return _build_success_result(response_data, model)

    except Exception as exc:
        debug("AI_ERROR", error_type=type(exc).__name__, error_message=str(exc))
        return _build_failure_result(model, exc)


def call_ollama(prompt: str, model: str = DEFAULT_MODEL) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0, "top_p": 0.9},
        "keep_alive": "10m",
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=AI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    response_data = response.json()
    return str(response_data.get("response", "")).strip()


def parse_ai_json(raw_text: str) -> dict[str, Any]:
    json_text = extract_json_object(raw_text)
    return json.loads(json_text)


def _build_prompt_instructions() -> str:
    return """
You are a pro phishing email triage assistant. You are reviewing an email for possible phishing, scam, or spam risk.

Use only the facts provided below.
Do not add facts, guesses, or recommendations that are not supported by the input.
Write clearly and simply for a non-technical user.

Return only valid JSON in this exact format:
{
  "suspicion_score": 0,
  "category": "safe",
  "confidence": "low",
  "reasons": ["short reason 1", "short reason 2", ...],
  "explanation": "4 to 8 lines in plain language"
}

Rules:
- suspicion_score must be an integer from 0 to 100
- category must be one of: safe, spam, phishing, scam
- confidence must be one of: low, medium, high
- reasons must contain only short, evidence-based phrases
- explanation must stay grounded in the provided facts
""".strip()


def _build_analysis_section(analysis: AnalysisResult) -> str:
    return f"""
Phishing analysis findings:
- Risk Level: {analysis.risk_level}
- Score: {analysis.score}/100
- Confidence: {analysis.confidence}%
""".strip()


def _build_parsed_email_section(parsed: ParsedEmail) -> str:
    return f"""
Parsed email:
- Subject: {value_or_not_found(parsed.subject)}
- From: {value_or_not_found(parsed.from_raw)}
- From Email: {value_or_not_found(parsed.from_email)}
- From Domain: {value_or_not_found(parsed.from_domain)}
- Reply-To: {value_or_not_found(parsed.reply_to_raw)}
- Reply-To Email: {value_or_not_found(parsed.reply_to_email)}
- Reply-To Domain: {value_or_not_found(parsed.reply_to_domain)}
""".strip()


def _build_urls_section(urls: list[str]) -> str:
    return f"URLs:\n{_format_bullet_list(urls)}"


def _build_suspicious_phrases_section(phrases: list[str]) -> str:
    phrase_text = ", ".join(phrases) if phrases else "none"
    return f"Suspicious phrases:\n- {phrase_text}"


def _build_triggered_rules_section(analysis: AnalysisResult) -> str:
    if not analysis.triggered_rules:
        return "Triggered rules:\n- none"

    rule_lines = []
    for rule in analysis.triggered_rules:
        evidence_text = ", ".join(rule.evidence) if rule.evidence else "none"
        rule_lines.append(
            f"- {rule.reason} (weight: {rule.weight}) | evidence: {evidence_text}"
        )

    return f"Triggered rules:\n{'\n'.join(rule_lines)}"


def _format_bullet_list(items: list[str]) -> str:
    if not items:
        return "- none"
    return "\n".join(f"- {item}" for item in items)


def value_or_not_found(value: str | None) -> str:
    return value or "Not found"


def extract_json_object(raw_text: str) -> str:
    start_index = raw_text.find("{")
    end_index = raw_text.rfind("}")

    if start_index == -1 or end_index == -1 or end_index <= start_index:
        raise ValueError("AI response did not contain valid JSON.")

    return raw_text[start_index : end_index + 1]


def require_explanation(payload: dict[str, Any]) -> str:
    explanation = str(payload.get("explanation", "")).strip()
    if not explanation:
        raise ValueError("AI response did not contain an explanation.")
    return explanation


def normalize_score(value: Any) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        score = 0
    return max(0, min(100, score))


def normalize_category(value: Any) -> str:
    category = str(value or "safe").strip().lower()
    if category not in ALLOWED_AI_CATEGORIES:
        return "safe"
    return category


def normalize_confidence_label(value: Any) -> str:
    confidence_label = str(value or "low").strip().lower()
    if confidence_label not in ALLOWED_CONFIDENCE_LABELS:
        return "low"
    return confidence_label


def normalize_reasons(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    reasons = []
    for item in value:
        reason = str(item).strip()
        if reason:
            reasons.append(reason)

    return reasons


def _build_success_result(payload: dict[str, Any], model: str) -> AIResult:

    return AIResult(
        explanation=require_explanation(payload),
        suspicion_score=normalize_score(payload.get("suspicion_score")),
        category=normalize_category(payload.get("category")),
        confidence_label=normalize_confidence_label(payload.get("confidence")),
        reasons=normalize_reasons(payload.get("reasons")),
        next_steps=[],
        ticket_summary="",
        model_used=model,
        used_ai=True,
        error=None,
    )


def _build_failure_result(model: str, exc: Exception) -> AIResult:
    return AIResult(
        explanation=AI_UNAVAILABLE_MESSAGE,
        suspicion_score=None,
        category=None,
        confidence_label=None,
        reasons=[],
        next_steps=[],
        ticket_summary="",
        model_used=model,
        used_ai=False,
        error=str(exc),
    )