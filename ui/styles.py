import streamlit as st


def inject_styles(compact: bool = False) -> None:
    compact_css = """
    .block-container { padding-top: 0.35rem; padding-bottom: 0.45rem; }
    .element-container { margin-bottom: 0.06rem; }
    .ph-section-title { margin-bottom: 0.3rem; font-size: 0.95rem; }
    p, li, div, label { font-size: 0.8rem; line-height: 1.2; }
    button[data-baseweb="tab"] { padding: 0.16rem 0.45rem !important; font-size: 0.76rem !important; }
    """ if compact else ""

    st.markdown(
        f"""
        <style>
        .block-container {{
            padding-top: 0.6rem;
            padding-bottom: 0.8rem;
            padding-left: 0.7rem;
            padding-right: 0.7rem;
            max-width: 90%;
        }}

        h1, h2, h3 {{ color: #1f2937; margin-bottom: 0.35rem; }}
        h1 {{ font-size: 1.5rem; }}
        h2 {{ font-size: 1.1rem; }}
        h3 {{ font-size: 0.98rem; }}

        p, li, div, label {{ font-size: 0.85rem; }}

        .ph-card {{
            background: #ffffff;
            border: 1px solid #dbe3ef;
            border-radius: 14px;
            padding: 10px 12px;
            margin-bottom: 8px;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
        }}

        .ph-section-title {{ font-size: 1.05rem; font-weight: 700; color: #1f2937; margin-bottom: 8px; }}
        .risk-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 700;
            border: 1px solid #f3b0b0;
            background: #fff1f1;
            color: #c53030;
            margin-bottom: 6px;
        }}
        .risk-score {{
            font-size: clamp(3.2rem, 6.8vw, 4.6rem);
            font-weight: 800;
            line-height: 0.95;
            color: #1f2937;
            margin-bottom: 0;
            margin-left: 0.3rem;
        }}
        .muted {{ color: #667085; font-size: 0.8rem; line-height: 1.2; }}
        .small-label {{ font-weight: 700; color: #344054; margin-bottom: 2px; font-size: 0.82rem; }}

        .fact-box {{
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            padding: 8px 10px;
            height: 100%;
        }}

        .ph-scroll-panel {{
            max-height: min(38vh, 360px);
            overflow-y: auto;
            padding-right: 0.25rem;
        }}

        ul, ol {{ margin-top: 0.1rem; margin-bottom: 0.1rem; padding-left: 1.15rem; }}
        li {{ margin-bottom: 0.12rem; }}

        div[data-baseweb="tab-list"] {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            width: 100%;
            gap: 0.25rem;
            margin-bottom: 0.35rem;
        }}
        button[data-baseweb="tab"] {{
            width: 100%;
            justify-content: center;
            padding: 0.2rem 0.5rem !important;
            border-radius: 10px !important;
            font-size: 0.78rem !important;
        }}
        div[role="tabpanel"] {{ padding-top: 0.15rem; }}

        .stButton > button, .stDownloadButton > button {{
            border-radius: 10px;
            padding-top: 0.28rem;
            padding-bottom: 0.28rem;
            font-size: 0.85rem;
            font-weight: 600;
        }}

        .stDownloadButton > button {{
            width: 100%;
            height: 42px !important;
            min-height: 42px;
            box-sizing: border-box !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            padding-top: 0 !important;
            padding-bottom: 0 !important;
            padding-left: 12px !important;
            padding-right: 12px !important;
            line-height: 1 !important;
            white-space: nowrap !important;
        }}

        .stDownloadButton {{
            margin-top: 4px !important;
        }}

        .stProgress {{ margin-top: 0.05rem; margin-bottom: 0.08rem; }}
        .stTextArea textarea {{ font-size: 0.85rem !important; line-height: 1.25 !important; }}
        .stCheckbox {{ margin-bottom: -0.15rem; }}
        pre, code {{ font-size: 0.84rem !important; line-height: 1.3 !important; }}
        .element-container {{ margin-bottom: 0.12rem; }}
        details {{ margin-top: 0.3rem; }}

        @media (max-width: 1200px) {{
            .block-container {{ max-width: 96%; }}
            .risk-score {{ font-size: clamp(2.4rem, 9vw, 3.2rem); }}
        }}

        @media (max-width: 900px) {{
            .block-container {{ padding-left: 0.8rem; padding-right: 0.8rem; max-width: 100%; }}
            .ph-card {{ background: transparent; border: none; padding: 6px 0; margin-bottom: 8px; box-shadow: none; }}
            .ph-section-title {{ font-size: 1rem; }}
            div[data-baseweb="tab-list"] {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
        }}

        {compact_css}
        </style>
        """,
        unsafe_allow_html=True,
    )
