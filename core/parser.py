from email.utils import parseaddr
from urllib.parse import urlparse

from core.models import ParsedEmail
from data.suspicious_phrases import SUSPICIOUS_PHRASES

import re

_DOMAIN_ONLY_RE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

def _normalize_domain(domain: str) -> str | None:
    domain = domain.strip().strip(".")
    if not domain:
        return None
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

def is_valid_email(email_address: str) -> bool:
    if not email_address or "@" not in email_address:
        return False

    local, domain = email_address.rsplit("@", 1)
    if not local or any(ch.isspace() for ch in local):
        return False

    normalized_domain = _normalize_domain(domain)
    return normalized_domain is not None and _DOMAIN_ONLY_RE.fullmatch(normalized_domain) is not None


def join_text_parts(text_parts: list[str | None]) -> str:
    return "\n".join(part.strip() for part in text_parts if part and part.strip())


def extract_urls(text: str) -> list[str]:
    if not text:
        return []

    urls = []
    pattern = r'https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+'
    found = re.findall(pattern, text, flags=re.IGNORECASE)
    seen = set()

    for url in found:
        clean = url.strip(".,);]")
        if clean not in seen:
            seen.add(clean)
            urls.append(clean)

    return urls


def extract_email_field(raw_text: str, field_name: str) -> str | None:
    if not raw_text:
        return None

    pattern = rf"(?im)^{re.escape(field_name)}\s*:\s*(.+)$"
    match = re.search(pattern, raw_text)
    if match:
        return match.group(1).strip()

    return None


def extract_email_address(value: str | None) -> str | None:
    if not value:
        return None

    cleaned = re.sub(r"(?im)^\s*(from|reply-to)\s*:\s*", "", value).strip()
    _, parsed = parseaddr(cleaned)
    candidate = (parsed or cleaned).strip().strip("<>")

    if "@" not in candidate:
        return None

    local, domain = candidate.rsplit("@", 1)
    normalized_domain = _normalize_domain(domain)
    if not local or normalized_domain is None:
        return None

    email = f"{local}@{normalized_domain}"
    return email if is_valid_email(email) else None



def extract_domain(value: str | None) -> str | None:
    if not value:
        return None

    email = extract_email_address(value)
    if email:
        return email.rsplit("@", 1)[1]

    cleaned = re.sub(r"(?im)^\s*(from|reply-to)\s*:\s*", "", value).strip().strip("<> ")
    if "@" in cleaned:
        _, domain = cleaned.rsplit("@", 1)
        normalized_domain = _normalize_domain(domain)
        if normalized_domain and _DOMAIN_ONLY_RE.fullmatch(normalized_domain):
            return normalized_domain

    normalized_domain = _normalize_domain(cleaned)
    if normalized_domain and _DOMAIN_ONLY_RE.fullmatch(normalized_domain):
        return normalized_domain

    return None




def extract_url_domains(urls: list[str]) -> list[str]:
    domains = []
    seen = set()

    for url in urls:
        normalized = url
        if normalized.startswith("www."):
            normalized = "http://" + normalized

        parsed = urlparse(normalized)
        domain = parsed.netloc.lower().replace("www.", "")

        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)

    return domains


def find_suspicious_phrases(text: str) -> list[str]:
    if not text:
        return []

    lowered_text = text.lower()
    found = []
    for suspicious_phrase in SUSPICIOUS_PHRASES:
        if suspicious_phrase.lower() in lowered_text:
            found.append(suspicious_phrase)

    return found


def parse_email_content(email_text: str, from_address: str, reply_to_address: str, subject: str) -> ParsedEmail:

    input_from_raw = (from_address or "").strip()
    input_reply_to_raw = (reply_to_address or "").strip()
    input_subject = (subject or "").strip()
    body_text = (email_text or "").strip()

    header_from_raw = extract_email_field(body_text, "From")
    header_reply_to_raw = extract_email_field(body_text, "Reply-To")
    header_subject = extract_email_field(body_text, "Subject")

    resolved_from_raw = input_from_raw or header_from_raw
    resolved_reply_to_raw = input_reply_to_raw or header_reply_to_raw
    resolved_subject = input_subject or header_subject

    from_email = extract_email_address(resolved_from_raw)
    reply_to_email = extract_email_address(resolved_reply_to_raw)

    search_text = join_text_parts(
        [body_text, resolved_from_raw, resolved_reply_to_raw, resolved_subject],
    )

    urls = extract_urls(search_text)
    url_domains = extract_url_domains(urls)
    suspicious_phrases = find_suspicious_phrases(search_text)

    return ParsedEmail(
        subject=resolved_subject,
        body_text=body_text,
        from_raw=resolved_from_raw,
        from_email=from_email,
        from_domain=extract_domain(from_email),
        reply_to_raw=resolved_reply_to_raw,
        reply_to_email=reply_to_email,
        reply_to_domain=extract_domain(reply_to_email),
        urls=urls,
        url_domains=url_domains,
        suspicious_phrases=suspicious_phrases,
    )
