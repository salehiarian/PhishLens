import os

def _get_streamlit_secret(name: str) -> str | None:
    try:
        import streamlit as st

        if name in st.secrets:
            return str(st.secrets[name])
    except (ModuleNotFoundError, AttributeError, RuntimeError):
        return None

    return None


def get_setting(name: str, default: str) -> str:
    secret_value = _get_streamlit_secret(name)
    if secret_value is not None:
        return secret_value

    env_value = os.getenv(name, default)
    if env_value is not None and env_value.strip():
        return env_value

    return default


def get_bool_setting(name: str, default: bool) -> bool:
    default_value = "true" if default else "false"
    return get_setting(name, default_value).strip().lower() == "true"


def get_int_setting(name: str, default: int) -> int:
    try:
        return int(get_setting(name, str(default)))
    except (TypeError, ValueError):
        return default

AI_ENABLED = get_bool_setting("AI_ENABLED", True)
AI_PROVIDER = get_setting("AI_PROVIDER", "ollama")
OLLAMA_URL = get_setting("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
DEFAULT_MODEL = get_setting("DEFAULT_MODEL", "llama3.2:3b")
AI_TIMEOUT_SECONDS = get_int_setting("AI_TIMEOUT_SECONDS", 60)
DEBUG = get_bool_setting("DEBUG", False)

MAX_SCORE = 99
MEDIUM_RISK_MIN = 30
HIGH_RISK_MIN = 65
STRONG_RULE_WEIGHT = 15
MAX_TOP_REASONS = 4

EXCLAMATION_BOUND = 4
QUESTION_BOUND = 4
CAPS_BOUND = 8

SPAM_LURE_WEIGHT = 14
SCAM_OFFER_WEIGHT = 16
EXCESSIVE_PUNCTUATION_CAP_WEIGHT = 8
IP_BASED_WEIGHT = 18
PUNYCODE_LINK_WEIGHT = 18
MANY_LINKS_WEIGHT = 10
SUSPICIOUS_URL_KEYWORD_WEIGHT = 10

TOO_MANY_SUBDOMAINS_WEIGHT = 10
LONG_MESSY_DOMAIN_WEIGHT = 12

ALLOWED_AI_CATEGORIES = {"safe", "spam", "phishing", "scam"}
ALLOWED_CONFIDENCE_LABELS = {"low", "medium", "high"}
BRANDS = ["microsoft", "paypal", "apple", "google", "amazon"]

STATE_IS_ANALYZING = "is_analyzing"
STATE_ANALYSIS_PAYLOAD = "analysis_payload"

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

DEFAULT_NOT_FOUND = "Not found"
DEFAULT_NO_URLS = "None"
DEFAULT_NO_FINDINGS = "No major indicators"

MAX_EMAIL_INPUT_CHARS = 20000