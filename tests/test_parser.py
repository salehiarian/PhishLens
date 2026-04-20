from __future__ import annotations

import pytest

from core.models import ParsedEmail
from core.parser import (
    extract_domain,
    extract_email_address,
    extract_email_field,
    extract_url_domains,
    extract_urls,
    find_suspicious_phrases,
    is_valid_email,
    join_text_parts,
    parse_email_content,
)


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("user@example.com", True),
        ("support+tag@secure-notify-mail.com", True),
        ("supportß@random-helpdesk.net", True),
        ("user@bücher.de", True),
        ("", False),
        ("not-an-email", False),
        ("user@", False),
        ("@example.com", False),
        ("user name@example.com", False),
    ],
)
def test_is_valid_email(email: str, expected: bool) -> None:
    assert is_valid_email(email) is expected


def test_join_text_parts_ignores_empty_values_and_strips_each_part() -> None:
    result = join_text_parts(["  first  ", None, "", "  ", "second", " third "])
    assert result == "first\nsecond\nthird"


def test_extract_urls_finds_unique_urls_and_cleans_trailing_punctuation() -> None:
    text = (
        "Visit https://example.com/path, then www.sample.org and "
        "https://example.com/path. Also http://test.net/login);"
    )

    assert extract_urls(text) == [
        "https://example.com/path",
        "www.sample.org",
        "http://test.net/login",
    ]


def test_extract_urls_returns_empty_list_for_empty_input() -> None:
    assert extract_urls("") == []


def test_extract_email_field_reads_headers_case_insensitively() -> None:
    raw = "FROM: Alice <alice@example.com>\nreply-to: help@sample.org\nSubject: Alert"

    assert extract_email_field(raw, "From") == "Alice <alice@example.com>"
    assert extract_email_field(raw, "Reply-To") == "help@sample.org"
    assert extract_email_field(raw, "Subject") == "Alert"


def test_extract_email_field_returns_none_when_field_missing() -> None:
    assert extract_email_field("Body only", "Reply-To") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("user@example.com", "user@example.com"),
        ("From: Microsoft Support <Alert@Example.com>", "Alert@example.com"),
        ("Reply-To: supportß@random-helpdesk.net", "supportß@random-helpdesk.net"),
        ("Person <user@bücher.de>", "user@xn--bcher-kva.de"),
        ("no-email-here", None),
    ],
)
def test_extract_email_address_supports_direct_header_and_unicode_formats(raw: str, expected: str | None) -> None:
    assert extract_email_address(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("user@example.com", "example.com"),
        ("Reply-To: supportß@random-helpdesk.net", "random-helpdesk.net"),
        ("random-helpdesk.net", "random-helpdesk.net"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("invalid domain", None),
        ("", None),
    ],
)
def test_extract_domain_handles_email_header_and_domain_only_values(raw: str, expected: str | None) -> None:
    assert extract_domain(raw) == expected


def test_extract_url_domains_normalizes_www_and_deduplicates() -> None:
    urls = [
        "www.Example.com/login",
        "https://www.example.com/account",
        "http://sub.example.com",
        "https://api.sample.org:8443/v1",
    ]

    assert extract_url_domains(urls) == [
        "example.com",
        "sub.example.com",
        "api.sample.org:8443",
    ]


def test_find_suspicious_phrases_is_case_insensitive() -> None:
    text = "URGENT: please Verify Your Account and click here now."
    assert find_suspicious_phrases(text) == ["urgent", "verify your account", "click here"]


def test_find_suspicious_phrases_returns_empty_for_empty_text() -> None:
    assert find_suspicious_phrases("") == []


def test_parse_email_content_prefers_explicit_inputs_over_header_fallback() -> None:
    email_text = (
        "From: old-sender@old-domain.com\n"
        "Reply-To: old-reply@old-domain.com\n"
        "Subject: Old subject\n"
        "Body with https://example.com and urgent language."
    )

    parsed = parse_email_content(
        email_text=email_text,
        from_address="New Sender <new@sender.com>",
        reply_to_address="reply@different.com",
        subject="New Subject",
    )

    assert isinstance(parsed, ParsedEmail)
    assert parsed.from_raw == "New Sender <new@sender.com>"
    assert parsed.from_email == "new@sender.com"
    assert parsed.from_domain == "sender.com"
    assert parsed.reply_to_raw == "reply@different.com"
    assert parsed.reply_to_email == "reply@different.com"
    assert parsed.reply_to_domain == "different.com"
    assert parsed.subject == "New Subject"
    assert "https://example.com" in parsed.urls
    assert "example.com" in parsed.url_domains
    assert "urgent" in parsed.suspicious_phrases


def test_parse_email_content_falls_back_to_headers_when_optional_inputs_blank() -> None:
    email_text = (
        "From: Microsoft Support <alert@secure-notify-mail.com>\n"
        "Reply-To: supportß@random-helpdesk.net\n"
        "Subject: Security Alert\n"
        "Please verify your account now. Click here: http://bit.ly/verify"
    )

    parsed = parse_email_content(
        email_text=email_text,
        from_address="",
        reply_to_address="",
        subject="",
    )

    assert parsed.from_raw == "Microsoft Support <alert@secure-notify-mail.com>"
    assert parsed.from_email == "alert@secure-notify-mail.com"
    assert parsed.from_domain == "secure-notify-mail.com"
    assert parsed.reply_to_raw == "supportß@random-helpdesk.net"
    assert parsed.reply_to_email == "supportß@random-helpdesk.net"
    assert parsed.reply_to_domain == "random-helpdesk.net"
    assert parsed.subject == "Security Alert"
    assert parsed.urls == ["http://bit.ly/verify"]
    assert parsed.url_domains == ["bit.ly"]


def test_parse_email_content_handles_unparseable_reply_to_without_crashing() -> None:
    parsed = parse_email_content(
        email_text="No headers here",
        from_address="sender@example.com",
        reply_to_address="not-a-reply-to",
        subject="Notice",
    )

    assert parsed.from_domain == "example.com"
    assert parsed.reply_to_email is None
    assert parsed.reply_to_domain is None
