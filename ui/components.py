from typing import Sequence

import streamlit as st

from core.models import AIResult, AnalysisResult, ParsedEmail, RuleResult
from ui.constants import (
    MAX_TOP_REASONS, FACTS_COLUMN_WIDTHS, MAX_FACT_DOMAINS, MAX_FACT_PHRASES, \
    MISMATCH_RULE_ID, MAX_RULE_EVIDENCE, RULES_PER_ROW,
)

def render_bullet_list(items: Sequence[str]) -> None:
    st.markdown("\n".join(f"- {item}" for item in items))


def render_section_title(title: str) -> None:
    st.markdown(f'<div class="ph-section-title">{title}</div>', unsafe_allow_html=True)


def get_triggered_rule_by_id(analysis_result: AnalysisResult, rule_id: str) -> RuleResult | None:
    for rule in analysis_result.triggered_rules:
        if rule.rule_id == rule_id:
            return rule
    return None


def estimate_rule_card_height(rule: RuleResult) -> int:

    chars = len(rule.name) + len(rule.reason) + sum(len(item) for item in rule.evidence[:3])
    estimated_lines = max(5, (chars // 42) + 3)
    return max(170, min(340, estimated_lines * 22))


def rule_container(height: int):
    """Prefer equal-height rule cards; fallback if height is unsupported."""
    try:
        return st.container(border=True, height=height)
    except TypeError:
        return st.container(border=True)



def render_back_button() -> bool:
    return st.button("Back to Analyze", use_container_width=False)


def render_risk_card(analysis_result: AnalysisResult, summary: str, ticket_summary_pdf: bytes) -> None:

    left, right = st.columns([1, 1], gap="small")

    with left:
        badge = "HIGH RISK" if analysis_result.risk_level == "High" else analysis_result.risk_level.upper()
        st.markdown(f'<div class="risk-badge">{badge}</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="risk-score">{analysis_result.score}</div>', unsafe_allow_html=True)
        st.markdown('<div class="muted">Risk score out of 100</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="small-label">Confidence</div>', unsafe_allow_html=True)
        st.progress(analysis_result.confidence / 100)
        st.markdown(
            f'<div class="muted" style="text-align:right;">{analysis_result.confidence}% ({analysis_result.risk_level})</div>',
            unsafe_allow_html=True,
        )

        st.download_button(
            "Download Ticket Summary",
            data=ticket_summary_pdf,
            file_name="phishlens_ticket_summary.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    st.caption("Final score is based mainly on rules, with AI as a supporting signal.")


def render_top_reasons(analysis_result: AnalysisResult) -> None:
    render_section_title("Top reasons")
    if analysis_result.top_reasons:
        render_bullet_list(analysis_result.top_reasons[:MAX_TOP_REASONS])
    else:
        st.write("No major phishing indicators were triggered.")


def render_facts_tab(email: ParsedEmail, analysis_result: AnalysisResult) -> None:
    col1, col2 = st.columns(FACTS_COLUMN_WIDTHS, gap="small")

    with col1:
        st.markdown("**URLs found**")
        if email.urls:
            for url in email.urls:
                st.markdown(f"- `{url}`")
        else:
            st.write("No URLs found")

        st.markdown('<div style="height:0.35rem;"></div>', unsafe_allow_html=True)
        st.markdown("**Other extracted facts**")
        domains = ", ".join(email.url_domains[:MAX_FACT_DOMAINS]) if email.url_domains else "None"
        phrases = ", ".join(email.suspicious_phrases[:MAX_FACT_PHRASES]) if email.suspicious_phrases else "None"
        st.markdown(f"**Domains:** {domains}")
        st.markdown(f"**Suspicious phrases:** {phrases}")

    with col2:
        st.markdown("**Counts**")
        st.write(f"Links: {len(email.urls)}")
        st.write(f"URL domains: {len(email.url_domains)}")

        st.markdown('<div style="height:0.35rem;"></div>', unsafe_allow_html=True)
        mismatch_rule = get_triggered_rule_by_id(analysis_result, MISMATCH_RULE_ID)
        st.markdown("**Header mismatch**")
        if mismatch_rule and mismatch_rule.evidence:
            render_bullet_list(mismatch_rule.evidence)
        else:
            st.write("No clear mismatch found")


def render_rule_card(rule: RuleResult, row_height: int) -> None:
    with rule_container(row_height):
        st.markdown(f"**{rule.name}** (+{rule.weight})")
        st.write(rule.reason)
        if rule.evidence:
            render_bullet_list(rule.evidence[:MAX_RULE_EVIDENCE])


def render_rules_tab(analysis_result: AnalysisResult) -> None:
    if not analysis_result.triggered_rules:
        st.write("No rules triggered.")
        return

    rules = analysis_result.triggered_rules
    for row_start in range(0, len(rules), RULES_PER_ROW):
        row_rules = rules[row_start : row_start + RULES_PER_ROW]
        cols = st.columns(len(row_rules), gap="medium")
        row_height = max(estimate_rule_card_height(rule) for rule in row_rules)

        for col, rule in zip(cols, row_rules):
            with col:
                render_rule_card(rule, row_height)


def render_citations_tab() -> None:
    st.info("No external citations in this MVP. Findings are based on local parsing and rule checks.")


def render_flag_details(email: ParsedEmail, analysis_result: AnalysisResult, ai_result: AIResult | None = None) -> None:
    render_section_title("Why flagged this")

    facts_tab, rules_tab = st.tabs(["Facts", "Rules Triggered"])

    with facts_tab:
        render_facts_tab(email, analysis_result)

    with rules_tab:
        render_rules_tab(analysis_result)

    if ai_result and ai_result.used_ai:
        st.markdown("---")
        st.markdown("**AI review**")

        if ai_result.category:
            st.write(f"Category: {ai_result.category.title()}")

        if ai_result.reasons:
            render_bullet_list(ai_result.reasons[:3])


def render_ai_explanation(result: AIResult) -> None:
    render_section_title("AI explanation")
    st.write(result.explanation)

    if result.used_ai:
        st.caption(f"Generated locally with Ollama model: {result.model_used}")

        if result.category:
            st.markdown(f"**Category:** {result.category.title()}")

        if result.reasons:
            st.markdown("**Reasons:**")
            render_bullet_list(result.reasons[:3])
    else:
        st.caption("AI output unavailable. Showing rule-based results instead.")


def render_next_steps(steps: Sequence[str]) -> None:
    render_section_title("Recommended next steps")
    render_bullet_list(steps)


def render_ticket_summary(summary: str) -> None:
    render_section_title("Ticket-ready summary")
    st.caption("Select and copy the summary below.")
    st.text_area("Copy this summary", value=summary, height=175, label_visibility="collapsed")


def render_parsed_details(email: ParsedEmail, toggle_key: str = "show_parsed_details") -> None:
    show_details = st.toggle("Expand parsed details", key=toggle_key)
    if not show_details:
        st.caption("Expand to view parsed details.")
        return

    st.markdown(f"**Subject:** {email.subject or 'Not found'}")
    st.markdown(f"**From:** {email.from_raw or 'Not found'}")
    st.markdown(f"**Reply-To:** {email.reply_to_raw or 'Not found'}")
