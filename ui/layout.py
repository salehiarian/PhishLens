from math import ceil

import streamlit as st

from core.models import AIResult

MIN_PAIRED_PANEL_HEIGHT = 340
MAX_PAIRED_PANEL_HEIGHT = 520
BASE_PAIRED_PANEL_HEIGHT = 240
CHARS_PER_LINE_ESTIMATE = 96
HEIGHT_PER_LINE = 16
MIN_LINE_ESTIMATE = 4


def bordered_container(height: int | None = None):
    if height is None:
        return st.container(border=True)

    try:
        return st.container(border=True, height=height)
    except TypeError:
        return st.container(border=True)


def estimate_paired_panel_height(ai_result: AIResult | None) -> int | None:
    if not ai_result or not ai_result.used_ai or not ai_result.explanation:
        return None

    explanation = ai_result.explanation.strip()
    if not explanation:
        return None

    lines = max(MIN_LINE_ESTIMATE, ceil(len(explanation) / CHARS_PER_LINE_ESTIMATE))
    return min(
        MAX_PAIRED_PANEL_HEIGHT,
        max(MIN_PAIRED_PANEL_HEIGHT, BASE_PAIRED_PANEL_HEIGHT + lines * HEIGHT_PER_LINE),
    )
