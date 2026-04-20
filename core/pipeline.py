from core.debug import debug, debug_hybrid_score
from core.formatter import build_ticket_summary
from core.models import AIResult, AnalysisPayload
from core.parser import parse_email_content
from core.recommendations import build_next_steps
from core.ai_service import generate_ai_result
from core.rules import analyze_email, blend_rule_and_ai_scores

AI_EXPLANATION_PLACEHOLDER = "AI explanation not generated yet."


def build_analysis_payload(email: str, from_address: str, reply_to_address: str, subject: str, model: str) -> AnalysisPayload:
    parsed = parse_email_content(email, from_address, reply_to_address, subject)
    debug(
        "APP_PARSED",
        subject=parsed.subject,
        body_text=parsed.body_text,
        from_raw=parsed.from_raw,
        from_email=parsed.from_email,
        from_domain=parsed.from_domain,
        reply_to_raw=parsed.reply_to_raw,
        reply_to_email=parsed.reply_to_email,
        reply_to_domain=parsed.reply_to_domain,
        urls=len(parsed.urls),
        url_domains=len(parsed.url_domains),
        phrases=len(parsed.suspicious_phrases),
    )

    rule_analysis = analyze_email(parsed)

    ai_result = generate_ai_result(parsed, rule_analysis, model=model)
    final_analysis = blend_rule_and_ai_scores(rule_analysis, ai_result)

    debug_hybrid_score(
        rule_score=rule_analysis.score,
        ai_score=ai_result.suspicion_score,
        final_score=final_analysis.score,
        ai_used=ai_result.used_ai,
        ai_capped=rule_analysis.score == 0 and final_analysis.score < (ai_result.suspicion_score or 0),
    )

    recommended_next_steps = build_next_steps(final_analysis)
    final_ticket_summary = build_ticket_summary(parsed, final_analysis, recommended_next_steps)

    return AnalysisPayload(
        parsed=parsed,
        analysis=final_analysis,
        ai_result=ai_result,
        next_steps=recommended_next_steps,
        ticket_summary=final_ticket_summary,
    )
