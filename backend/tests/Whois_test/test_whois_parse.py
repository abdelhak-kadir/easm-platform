from datetime import UTC, datetime, timedelta

from app.models import Severity
from app.tools.whois.parse import _as_list, _first, parse

SAMPLE_WHOIS_RESPONSE = {
    "domain_name": ["EXAMPLE.COM", "example.com"],
    "registrar": "Example Registrar, LLC",
    "whois_server": "whois.example-registrar.com",
    "creation_date": "2000-01-01T12:00:00+00:00",
    "updated_date": "2025-06-01T08:30:00+00:00",
    "expiration_date": "2099-01-01T12:00:00+00:00",
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "status": ["clientTransferProhibited"],
    "emails": ["admin@example.com"],
    "dnssec": "unsigned",
    "org": "Example Org",
    "country": "US",
}


def _iso_in(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------
# parse() -- overall shape
# ---------------------------------------------------------------------


def test_parse_handles_empty_response():
    assert parse({}) == []


def test_parse_without_domain_name_skips_registration_finding():
    minimal = {"expiration_date": _iso_in(100)}
    findings = parse(minimal)
    assert all(f["finding_type"] != "domain_registration" for f in findings)


def test_parse_returns_one_registration_finding_when_far_from_expiry():
    findings = parse(SAMPLE_WHOIS_RESPONSE)
    reg_findings = [f for f in findings if f["finding_type"] == "domain_registration"]
    assert len(reg_findings) == 1
    # far-future expiration -> no expiry finding at all
    assert all(f["finding_type"] != "domain_expiry" for f in findings)


# ---------------------------------------------------------------------
# _parse_registration (via parse())
# ---------------------------------------------------------------------


def test_registration_finding_has_expected_fields():
    findings = parse(SAMPLE_WHOIS_RESPONSE)
    reg = next(f for f in findings if f["finding_type"] == "domain_registration")

    assert reg["title"] == "Domain registration for EXAMPLE.COM"
    assert reg["severity"] == Severity.INFO
    assert reg["data"]["domain"] == "EXAMPLE.COM"
    assert reg["data"]["registrar"] == "Example Registrar, LLC"
    assert reg["data"]["whois_server"] == "whois.example-registrar.com"
    assert reg["data"]["creation_date"] == "2000-01-01T12:00:00+00:00"
    assert reg["data"]["name_servers"] == ["ns1.example.com", "ns2.example.com"]
    assert reg["data"]["status"] == ["clientTransferProhibited"]
    assert reg["data"]["emails"] == ["admin@example.com"]
    assert reg["data"]["org"] == "Example Org"
    assert reg["data"]["country"] == "US"


def test_registration_finding_normalizes_scalar_domain_name():
    raw = {**SAMPLE_WHOIS_RESPONSE, "domain_name": "example.com", "registrar": "Solo Registrar"}
    findings = parse(raw)
    reg = next(f for f in findings if f["finding_type"] == "domain_registration")

    assert reg["data"]["domain"] == "example.com"
    assert reg["data"]["registrar"] == "Solo Registrar"


def test_registration_finding_handles_missing_optional_fields():
    minimal = {"domain_name": "example.com"}
    findings = parse(minimal)
    reg = next(f for f in findings if f["finding_type"] == "domain_registration")

    assert reg["data"]["domain"] == "example.com"
    assert reg["data"]["registrar"] is None
    assert reg["data"]["name_servers"] == []
    assert reg["data"]["status"] == []
    assert reg["data"]["emails"] == []


# ---------------------------------------------------------------------
# _parse_expiry (via parse())
# ---------------------------------------------------------------------


def test_expiry_finding_absent_when_no_expiration_date():
    raw = {"domain_name": "example.com"}
    findings = parse(raw)
    assert all(f["finding_type"] != "domain_expiry" for f in findings)


def test_expiry_finding_absent_when_far_in_the_future():
    raw = {"domain_name": "example.com", "expiration_date": _iso_in(100)}
    findings = parse(raw)
    assert all(f["finding_type"] != "domain_expiry" for f in findings)


def test_expiry_finding_medium_severity_when_expiring_soon():
    raw = {"domain_name": "example.com", "expiration_date": _iso_in(15)}
    findings = parse(raw)
    expiry = next(f for f in findings if f["finding_type"] == "domain_expiry")

    assert expiry["severity"] == Severity.MEDIUM
    assert "expires in" in expiry["title"]
    assert 0 <= expiry["data"]["days_remaining"] <= 30


def test_expiry_finding_medium_severity_at_exact_warning_boundary():
    raw = {"domain_name": "example.com", "expiration_date": _iso_in(30)}
    findings = parse(raw)
    expiry = next(f for f in findings if f["finding_type"] == "domain_expiry")

    assert expiry["severity"] == Severity.MEDIUM


def test_expiry_finding_high_severity_when_already_expired():
    raw = {"domain_name": "example.com", "expiration_date": _iso_in(-10)}
    findings = parse(raw)
    expiry = next(f for f in findings if f["finding_type"] == "domain_expiry")

    assert expiry["severity"] == Severity.HIGH
    assert "expired" in expiry["title"]
    assert expiry["data"]["days_remaining"] < 0


def test_expiry_finding_data_includes_raw_expiration_date():
    expiration_raw = _iso_in(10)
    raw = {"domain_name": "example.com", "expiration_date": expiration_raw}
    findings = parse(raw)
    expiry = next(f for f in findings if f["finding_type"] == "domain_expiry")

    assert expiry["data"]["expiration_date"] == expiration_raw


def test_expiry_finding_uses_first_value_when_expiration_date_is_a_list():
    raw = {
        "domain_name": "example.com",
        "expiration_date": [_iso_in(10), _iso_in(9999)],
    }
    findings = parse(raw)
    expiry_findings = [f for f in findings if f["finding_type"] == "domain_expiry"]
    assert len(expiry_findings) == 1
    assert expiry_findings[0]["severity"] == Severity.MEDIUM


# ---------------------------------------------------------------------
# _first / _as_list helpers
# ---------------------------------------------------------------------


def test_first_returns_first_element_of_list():
    assert _first(["a", "b"]) == "a"


def test_first_returns_none_for_empty_list():
    assert _first([]) is None


def test_first_returns_scalar_unchanged():
    assert _first("a") == "a"


def test_first_returns_none_for_none():
    assert _first(None) is None


def test_as_list_wraps_scalar():
    assert _as_list("a") == ["a"]


def test_as_list_passes_through_list():
    assert _as_list(["a", "b"]) == ["a", "b"]


def test_as_list_returns_empty_list_for_none():
    assert _as_list(None) == []
