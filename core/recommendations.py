from core.models import AnalysisResult


def build_next_steps(analysis: AnalysisResult) -> list[str]:
    steps = get_base_next_steps(analysis.risk_level)
    triggered_rul_ids = {rule.rule_id for rule in analysis.triggered_rules}

    if "from_reply_to_mismatch" in triggered_rul_ids:
        steps.append("Do not reply directly to the email. Use official contact details instead.")

    if has_link_risk(triggered_rul_ids):
        steps.append("Do not click the link. Visit the website manually if you need to verify it.")

    if "high_risk_phrases" in triggered_rul_ids:
        steps.append("Do not enter your password, verification code, or personal details.")

    if has_spam_or_scam_risk(triggered_rul_ids):
        steps.append("Do not respond, claim rewards, send money, or share financial information.")

    if "invoice_payment_language" in triggered_rul_ids:
        steps.append("Confirm the request with the company or finance team using known contact details before making any payment.")

    return deduplicate_steps(steps)[:5]

def get_base_next_steps(risk_level: str) -> list[str]:

    if risk_level == "High":
        return [
            "Do not click links or open attachments.",
            "Do not reply to the email.",
            "Verify the request with the official website or a known contact method.",
        ]

    if risk_level == "Medium":
        return [
            "Be careful with links, attachments, and requests for sensitive information.",
            "Verify the sender with a trusted channel before taking action.",
            "Do not enter your password or verification code unless you confirm the source.",
        ]

    return [
        "No strong warning signs were found, but stay cautious.",
        "Verify unexpected requests with an official source before taking action.",
        "Avoid clicking links or opening attachments unless you trust the sender.",
    ]


def has_link_risk(triggered_rule_ids: set[str]) -> bool:
    link_related_rules = {
        "suspicious_link_domain",
        "shortened_url",
        "ip_based_link",
        "punycode_link",
        "long_or_messy_domain",
        "suspicious_url_keywords",
        "too_many_subdomains",
    }
    return bool(link_related_rules & triggered_rule_ids)


def has_spam_or_scam_risk(triggered_rule_ids: set[str]) -> bool:
    spam_or_scam_rules = {
        "spam_lure_language",
        "scam_offer_language",
    }
    return bool(spam_or_scam_rules & triggered_rule_ids)


def deduplicate_steps(steps: list[str]) -> list[str]:
    unique_steps: list[str] = []

    for step in steps:
        if step not in unique_steps:
            unique_steps.append(step)

    return unique_steps