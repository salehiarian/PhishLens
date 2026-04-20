from contextlib import AbstractContextManager
from typing import cast

import streamlit as st

from core.config import DEFAULT_MODEL, STATE_IS_ANALYZING, STATE_ANALYSIS_PAYLOAD, MAX_EMAIL_INPUT_CHARS
from core.debug import debug
from core.models import AnalysisPayload, AIResult, AnalysisResult, ParsedEmail
from core.pdf_export import build_ticket_summary_pdf
from core.pipeline import build_analysis_payload
from ui.constants import (
    RESULT_HEADER_COLS, TOP_SECTION_COLS, ANALYZE_INFO_TEXT, INPUT_EMAIL_HEIGHT, \
    COMPACT_INPUT_EMAIL_HEIGHT, NEXT_STEP_BASE_HEIGHT, \
    PARSED_EXPANDED_HEIGHT, NEXT_STEP_LINE_HEIGHT, PARSED_COLLAPSED_HEIGHT, TICKET_SUMMARY_PANEL_HEIGHT, \
    SECOND_ROW_MIN_HEIGHT, SECOND_ROW_BOTTOM_PADDING, NEXT_STEP_WRAP_CHARS, SECOND_ROW_MAX_HEIGHT, AI_NOT_READY_TEXT, \
    PARSED_DETAILS_TOGGLE_KEY, BOTTOM_SECTION_COLS
)

from ui.components import (
    render_ai_explanation,
    render_back_button,
    render_flag_details,
    render_next_steps,
    render_parsed_details,
    render_risk_card,
    render_ticket_summary,
    render_top_reasons,
)
from ui.layout import bordered_container, estimate_paired_panel_height
from ui.styles import inject_styles

st.set_page_config(page_title="PhishLens", page_icon="📧", layout="wide")


def spinner_context(message: str) -> AbstractContextManager[None]:
    return cast(AbstractContextManager[None], cast(object, st.spinner(message)))


def estimate_second_row_height(next_steps: list[str], parsed_expanded: bool) -> int:
    step_lines = 0
    for step in next_steps:
        text = step.strip()
        if not text:
            continue
        wraps = max(1, (len(text) - 1) // NEXT_STEP_WRAP_CHARS + 1)
        step_lines += wraps

    next_steps_height = NEXT_STEP_BASE_HEIGHT + step_lines * NEXT_STEP_LINE_HEIGHT
    parsed_height = PARSED_EXPANDED_HEIGHT if parsed_expanded else PARSED_COLLAPSED_HEIGHT
    content_height = max(next_steps_height, TICKET_SUMMARY_PANEL_HEIGHT, parsed_height)
    return min(SECOND_ROW_MAX_HEIGHT, max(SECOND_ROW_MIN_HEIGHT, content_height + SECOND_ROW_BOTTOM_PADDING))


def init_state() -> None:

    st.session_state.setdefault(STATE_IS_ANALYZING, False)
    st.session_state.setdefault(STATE_ANALYSIS_PAYLOAD, False)


def render_input_section(has_results: bool) -> tuple[str, str, str, str]:
    if not has_results:
        st.title("PhishLens")
        st.subheader("Phishing Email Triage Tool")
        st.write(ANALYZE_INFO_TEXT)
        email_text = st.text_area("Please enter the email text:", height=INPUT_EMAIL_HEIGHT)
        from_address = st.text_input("From address (optional)")
        reply_to_address = st.text_input("Reply-To address (optional)")
        subject = st.text_input("Subject (optional)")
        # header_text = st.text_area("Please enter email headers (optional)", height=INPUT_HEADER_HEIGHT)
        return email_text, from_address, reply_to_address, subject

    st.caption("Analysis results")
    with st.expander("Analyze another email", expanded=False):
        email_text = st.text_area("Please enter the email text:", height=COMPACT_INPUT_EMAIL_HEIGHT)
        from_address = st.text_input("From address (optional)")
        reply_to_address = st.text_input("Reply-To address (optional)")
        subject = st.text_input("Subject (optional)")
    return email_text, from_address, reply_to_address, subject


def handle_analyze_action(email_text: str, from_address: str, reply_to_address: str, subject: str, model_name: str) -> None:
    debug("APP_ANALYZE_CLICK", email_chars=len(email_text), from_address=len(from_address), reply_to_address=len(reply_to_address), subject=len(subject), model=model_name)

    if len(email_text) > MAX_EMAIL_INPUT_CHARS:
        st.warning("Email text is too large. Please paste a shorter input.")
        return

    if not email_text.strip():
        st.warning("Please enter email")
        st.session_state[STATE_ANALYSIS_PAYLOAD] = None
        return

    st.session_state[STATE_IS_ANALYZING] = True
    try:
        with spinner_context("Analyzing..."):
            payload = build_analysis_payload(email_text, from_address, reply_to_address, subject, model_name)
        if reply_to_address.strip() and payload.parsed.reply_to_domain is None:
            st.warning(
                "Reply-To format not recognized. Use name@domain.com or Name <name@domain.com>."
            )
        st.session_state[STATE_ANALYSIS_PAYLOAD] = payload
    finally:
        st.session_state[STATE_IS_ANALYZING] = False
    st.rerun()


def render_results(payload: AnalysisPayload, model_name: str) -> None:
    parsed_email = payload.parsed
    email_analysis = payload.analysis
    recommended_steps = payload.next_steps
    ticket_summary_text = payload.ticket_summary
    ai_result = payload.ai_result

    render_top_results_section(ai_result, email_analysis, model_name, parsed_email, payload, ticket_summary_text)
    render_bottom_results_section(parsed_email, recommended_steps, ticket_summary_text)


def render_bottom_results_section(parsed_email: ParsedEmail, recommended_steps: list[str], ticket_summary_text: str):
    parsed_expanded = bool(st.session_state.get(PARSED_DETAILS_TOGGLE_KEY, False))
    second_row_height = estimate_second_row_height(recommended_steps, parsed_expanded)

    steps_col, ticket_col, parsed_col = st.columns(BOTTOM_SECTION_COLS, gap="small")
    with steps_col:
        with bordered_container(second_row_height):
            render_next_steps(recommended_steps)
    with ticket_col:
        with bordered_container(second_row_height):
            render_ticket_summary(ticket_summary_text)
    with parsed_col:
        with bordered_container(second_row_height):
            render_parsed_details(parsed_email, toggle_key=PARSED_DETAILS_TOGGLE_KEY)


def render_top_results_section(ai_result: AIResult, email_analysis: AnalysisResult, model_name: str,
                               parsed_email: ParsedEmail, payload: AnalysisPayload, ticket_summary_text: str):
    header_left, header_right = st.columns(RESULT_HEADER_COLS, gap="small")
    ticket_summary_pdf = build_ticket_summary_pdf(ticket_summary_text, email_analysis)

    with header_left:
        st.markdown("### Results")
    with header_right:
        if render_back_button():
            st.session_state[STATE_ANALYSIS_PAYLOAD] = None
            st.rerun()

    with st.container(border=True):
        render_risk_card(email_analysis, ticket_summary_text, ticket_summary_pdf)

    flagged_col, ai_col = st.columns(TOP_SECTION_COLS, gap="small")
    paired_panel_height = estimate_paired_panel_height(ai_result)
    with flagged_col:
        with bordered_container(paired_panel_height):
            render_flag_details(parsed_email, email_analysis, ai_result)
    with ai_col:
        with bordered_container(paired_panel_height):
            render_top_reasons(email_analysis)
            st.markdown('<div style="height:0.3rem;"></div>', unsafe_allow_html=True)

            if payload.ai_result and payload.ai_result.explanation:
                render_ai_explanation(payload.ai_result)
            else:
                st.info(AI_NOT_READY_TEXT)


def main() -> None:
    init_state()
    payload = st.session_state[STATE_ANALYSIS_PAYLOAD]
    has_results = isinstance(payload, AnalysisPayload)
    inject_styles(compact=has_results)

    email_text, from_address, reply_to_address, subject = render_input_section(has_results)
    model_name = st.text_input("Ollama model", value=DEFAULT_MODEL)

    if st.button("Analyze", disabled=st.session_state[STATE_IS_ANALYZING]):
        handle_analyze_action(email_text, from_address, reply_to_address, subject, model_name)

    payload = st.session_state[STATE_ANALYSIS_PAYLOAD]
    if isinstance(payload, AnalysisPayload):
        render_results(payload, model_name)


main()
