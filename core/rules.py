from typing import Sequence
from core.models import ParsedEmail, RuleResult, AnalysisResult, AIResult
import re

from core.config import (
    HIGH_RISK_MIN,
    MAX_SCORE,
    MAX_TOP_REASONS,
    MEDIUM_RISK_MIN,
    STRONG_RULE_WEIGHT,
    SPAM_LURE_WEIGHT,
    SCAM_OFFER_WEIGHT,
    EXCLAMATION_BOUND,
    QUESTION_BOUND,
    CAPS_BOUND,
    EXCESSIVE_PUNCTUATION_CAP_WEIGHT,
    IP_BASED_WEIGHT,
    PUNYCODE_LINK_WEIGHT,
    MANY_LINKS_WEIGHT,
    SUSPICIOUS_URL_KEYWORD_WEIGHT,
    TOO_MANY_SUBDOMAINS_WEIGHT,
    LONG_MESSY_DOMAIN_WEIGHT,
    BRANDS,
    SHORTENER_DOMAINS,
)

from data.suspicious_phrases import (
    HIGH_RISK_PHRASES,
    IMPERSONATION_KEYWORDS,
    SUSPICIOUS_TLDS,
    URGENT_PHRASES,
    SCAM_OFFER_PHRASES,
    SPAM_LURE_PHRASES,
)


def _brand_in_host(brand: str, host: str) -> bool:
    return re.search(rf"(^|[.-]){re.escape(brand)}([.-]|$)", host) is not None


def build_search_text(*parts: str | None) -> str:
    return " ".join(part or "" for part in parts).lower()


def _normalize_host(domain: str) -> str:
    return domain.lower().split(":", 1)[0].strip(".")

def is_ip_host(host: str) -> bool:
    return re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) is not None


def count_subdomains(host: str) -> int:
    parts = host.split(".")
    return max(0, len(parts) - 2)


def make_rule_result(
    rule_id: str,
    name: str,
    triggered: bool,
    weight: int,
    reason: str,
    evidence: Sequence[str] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        name=name,
        triggered=triggered,
        weight=weight,
        reason=reason,
        evidence=evidence or [],
    )


def check_from_reply_to_mismatch(parsed: ParsedEmail) -> RuleResult:
    triggered = (
        parsed.from_domain is not None
        and parsed.reply_to_domain is not None
        and parsed.from_domain != parsed.reply_to_domain
    )

    evidence = []
    if triggered:
        evidence.append(f"From domain: {parsed.from_domain}")
        evidence.append(f"Reply-To domain: {parsed.reply_to_domain}")

    return make_rule_result(
        rule_id="from_reply_to_mismatch",
        name="From / Reply-To mismatch",
        triggered=triggered,
        weight=20,
        reason="Reply-To domain doesn’t match From domain",
        evidence=evidence,
    )


def check_urgency_language(parsed: ParsedEmail) -> RuleResult:
    urgency_hits = [
        phrase for phrase in parsed.suspicious_phrases
        if phrase.lower() in URGENT_PHRASES
    ]

    triggered = len(urgency_hits) > 0

    return make_rule_result(
        rule_id="urgency_language",
        name="Urgency language",
        triggered=triggered,
        weight=12,
        reason="Urgency language detected",
        evidence=urgency_hits,
    )


def check_high_risk_phrases(parsed: ParsedEmail) -> RuleResult:
    hits = [
        phrase for phrase in parsed.suspicious_phrases
        if phrase.lower() in HIGH_RISK_PHRASES
    ]

    triggered = len(hits) > 0

    return make_rule_result(
        rule_id="high_risk_phrases",
        name="Credential / security bait language",
        triggered=triggered,
        weight=15,
        reason="Suspicious account or credential-related phrases found",
        evidence=hits,
    )


def check_impersonation_wording(parsed: ParsedEmail) -> RuleResult:
    source_text = build_search_text(parsed.from_raw, parsed.subject)

    hits = [word for word in IMPERSONATION_KEYWORDS if word in source_text]
    triggered = len(hits) > 0

    return make_rule_result(
        rule_id="impersonation_wording",
        name="Display-name or brand impersonation wording",
        triggered=triggered,
        weight=15,
        reason="Sender wording suggests brand or support impersonation",
        evidence=hits,
    )


def check_suspicious_link_domain(parsed: ParsedEmail) -> RuleResult:
    suspicious_domains = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_domains.append(domain)
            continue

        if host.count("-") >= 2:
            suspicious_domains.append(domain)
            continue

        if "login" in host or "secure" in host or "verify" in host:
            suspicious_domains.append(domain)

    triggered = len(suspicious_domains) > 0

    return make_rule_result(
        rule_id="suspicious_link_domain",
        name="Suspicious link domain",
        triggered=triggered,
        weight=18,
        reason="Link domain looks suspicious",
        evidence=suspicious_domains,
    )


def check_brand_link_mismatch(parsed: ParsedEmail) -> RuleResult:

    text_blob = build_search_text(parsed.subject, parsed.from_raw)

    mentioned_brands = [brand for brand in BRANDS if brand in text_blob]
    hosts = [_normalize_host(domain) for domain in parsed.url_domains if domain]

    mismatches = []
    if mentioned_brands and hosts:
        domains_text = ", ".join(parsed.url_domains)
        for brand in mentioned_brands:
            matching_domain_found = any(_brand_in_host(brand, host) for host in hosts)
            if not matching_domain_found:
                mismatches.append(
                    f"Brand mentioned: {brand}, but URL domains: {domains_text}"
                )

    triggered = len(mismatches) > 0

    return make_rule_result(
        rule_id="brand_link_mismatch",
        name="Brand / link mismatch",
        triggered=triggered,
        weight=18,
        reason="Link domain differs from brand mentioned",
        evidence=mismatches,
    )


def check_shortened_url(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)

        for shortener in SHORTENER_DOMAINS:
            if host == shortener or host.endswith(f".{shortener}"):
                hits.append(domain)
                break

    triggered = len(hits) > 0

    return make_rule_result(
        rule_id="shortened_url",
        name="Shortened URL",
        triggered=triggered,
        weight=10,
        reason="Shortened URL detected",
        evidence=hits,
    )


def check_spam_lure_language(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for phrase in parsed.suspicious_phrases:
        if phrase.lower() in SPAM_LURE_PHRASES:
            hits.append(phrase)

    return make_rule_result(
        rule_id="spam_lure_language",
        name="Spam lure language",
        triggered=bool(hits),
        weight=SPAM_LURE_WEIGHT,
        reason="Spam-like promotional or lure language detected",
        evidence=hits,
    )


def check_scam_offer_language(parsed: ParsedEmail) -> RuleResult:
    text = build_search_text(parsed.subject, parsed.from_raw, parsed.body_text)

    hits = [phrase for phrase in SCAM_OFFER_PHRASES if phrase in text]

    return make_rule_result(
        rule_id="scam_offer_language",
        name="Scam offer language",
        triggered=bool(hits),
        weight=SCAM_OFFER_WEIGHT,
        reason="Scam-like offer language detected",
        evidence=hits,
    )

def check_ip_based_link(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)
        if is_ip_host(host):
            hits.append(domain)

    return make_rule_result(
        rule_id="ip_based_link",
        name="IP-based link",
        triggered=bool(hits),
        weight=IP_BASED_WEIGHT,
        reason="Link uses an IP address instead of a normal domain",
        evidence=hits,
    )

def check_punycode_link(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)
        if "xn--" in host:
            hits.append(domain)

    return make_rule_result(
        rule_id="punycode_link",
        name="Punycode link",
        triggered=bool(hits),
        weight=PUNYCODE_LINK_WEIGHT,
        reason="Link may use a lookalike domain",
        evidence=hits,
    )

def check_many_links_in_short_email(parsed: ParsedEmail) -> RuleResult:
    body_text = (parsed.body_text or "").strip()
    link_count = len(parsed.urls)

    triggered = len(body_text) < 400 and link_count >= 3
    evidence = [f"Body length: {len(body_text)}", f"Link count: {link_count}"] if triggered else []

    return make_rule_result(
        rule_id="many_links_short_email",
        name="Many links in short email",
        triggered=triggered,
        weight=MANY_LINKS_WEIGHT,
        reason="Short email contains many links",
        evidence=evidence,
    )

def check_suspicious_url_keywords(parsed: ParsedEmail) -> RuleResult:
    keywords = ["login", "verify", "secure", "update", "reset", "signin"]
    hits = []

    for url in parsed.urls:
        lowered = url.lower()
        if any(keyword in lowered for keyword in keywords):
            hits.append(url)

    return make_rule_result(
        rule_id="suspicious_url_keywords",
        name="Suspicious URL keywords",
        triggered=bool(hits),
        weight=SUSPICIOUS_URL_KEYWORD_WEIGHT,
        reason="URL contains suspicious login or verification wording",
        evidence=hits,
    )


def check_too_many_subdomains(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)
        if count_subdomains(host) >= 3:
            hits.append(domain)

    return make_rule_result(
        rule_id="too_many_subdomains",
        name="Too many subdomains",
        triggered=bool(hits),
        weight=TOO_MANY_SUBDOMAINS_WEIGHT,
        reason="Link uses an unusually deep subdomain structure",
        evidence=hits,
    )

def check_excessive_punctuation_or_caps(parsed: ParsedEmail) -> RuleResult:
    text = build_search_text(parsed.subject, parsed.from_raw, parsed.body_text)
    subject = (parsed.subject or "").strip()

    evidence = []

    punctuation_patterns = ["!!!", "???", "!?!", "?!?", "$$$"]
    for pattern in punctuation_patterns:
        if pattern in text:
            evidence.append(f"Excessive punctuation found: {pattern}")
            break

    exclamation_count = text.count("!")
    question_count = text.count("?")

    if exclamation_count >= EXCLAMATION_BOUND:
        evidence.append("Too many exclamation marks")
    if question_count >= QUESTION_BOUND:
        evidence.append("Too many question marks")

    if re.search(r"[!?$]{4,}", text):
        evidence.append("Repeated punctuation sequence found")

    if subject and len(subject) >= CAPS_BOUND and subject.isupper():
        evidence.append("Subject is all caps")

    return make_rule_result(
        rule_id="excessive_punctuation_or_caps",
        name="Excessive punctuation or caps",
        triggered=bool(evidence),
        weight=EXCESSIVE_PUNCTUATION_CAP_WEIGHT,
        reason="Spam-style punctuation or all-caps wording detected",
        evidence=evidence,
    )

def check_long_or_messy_domain(parsed: ParsedEmail) -> RuleResult:
    hits = []

    for domain in parsed.url_domains:
        host = _normalize_host(domain)
        if len(host) > 35 or host.count("-") >= 3:
            hits.append(domain)

    return make_rule_result(
        rule_id="long_or_messy_domain",
        name="Long or messy domain",
        triggered=bool(hits),
        weight=LONG_MESSY_DOMAIN_WEIGHT,
        reason="Link domain looks unusually long or cluttered",
        evidence=hits,
    )

def get_ai_weight(ai_result: AIResult) -> float:
    if not ai_result.used_ai or ai_result.suspicion_score is None:
        return 0.0

    if ai_result.confidence_label == "high":
        return 0.25
    if ai_result.confidence_label == "medium":
        return 0.18
    return 0.10

def blend_rule_and_ai_scores(
    rule_analysis: AnalysisResult,
    ai_result: AIResult,
) -> AnalysisResult:
    rule_score = rule_analysis.score

    if not ai_result.used_ai or ai_result.suspicion_score is None:
        return rule_analysis

    ai_score = ai_result.suspicion_score
    ai_weight = get_ai_weight(ai_result)
    rule_weight = 1.0 - ai_weight

    final_score = round((rule_score * rule_weight) + (ai_score * ai_weight))

    if rule_score == 0:
        final_score = min(final_score, HIGH_RISK_MIN - 1)

    final_score = min(final_score, MAX_SCORE)

    if final_score >= HIGH_RISK_MIN:
        risk_level = "High"
    elif final_score >= MEDIUM_RISK_MIN:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    confidence = max(rule_analysis.confidence, 65 if ai_result.used_ai else rule_analysis.confidence)

    return AnalysisResult(
        score=final_score,
        risk_level=risk_level,
        confidence=confidence,
        triggered_rules=rule_analysis.triggered_rules,
        top_reasons=rule_analysis.top_reasons,
    )


RULE_CHECKS = (
    check_from_reply_to_mismatch,
    check_urgency_language,
    check_high_risk_phrases,
    check_spam_lure_language,
    check_scam_offer_language,
    check_excessive_punctuation_or_caps,
    check_impersonation_wording,
    check_suspicious_link_domain,
    check_long_or_messy_domain,
    check_ip_based_link,
    check_punycode_link,
    check_many_links_in_short_email,
    check_suspicious_url_keywords,
    check_too_many_subdomains,
    check_brand_link_mismatch,
    check_shortened_url,
)


def run_rules(parsed: ParsedEmail) -> list[RuleResult]:
    return [check(parsed) for check in RULE_CHECKS]


def score_rules(rule_results: Sequence[RuleResult]) -> AnalysisResult:
    triggered_rules = [rule for rule in rule_results if rule.triggered]

    raw_score = sum(rule.weight for rule in triggered_rules)

    strong_rule_count = sum(1 for rule in triggered_rules if rule.weight >= STRONG_RULE_WEIGHT)

    if raw_score == 0:
        score = 0
    elif raw_score >= 90 and strong_rule_count >= 4:
        score = 100
    else:
        score = min(raw_score, 95)

    if score >= HIGH_RISK_MIN:
        risk_level = "High"
    elif score >= MEDIUM_RISK_MIN:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not triggered_rules:
        confidence = 60
    elif score < MEDIUM_RISK_MIN:
        confidence = min(65, 50 + len(triggered_rules) * 5)
    elif score < HIGH_RISK_MIN:
        confidence = min(80, 60 + len(triggered_rules) * 6)
    else:
        confidence = min(95, 75 + len(triggered_rules) * 4)

    sorted_rules = sorted(triggered_rules, key=lambda r: r.weight, reverse=True)
    top_reasons = [rule.reason for rule in sorted_rules[:MAX_TOP_REASONS]]

    return AnalysisResult(
        score=score,
        risk_level=risk_level,
        confidence=confidence,
        triggered_rules=sorted_rules,
        top_reasons=top_reasons,
    )


def analyze_email(parsed: ParsedEmail) -> AnalysisResult:
    rules = run_rules(parsed)
    return score_rules(rules)