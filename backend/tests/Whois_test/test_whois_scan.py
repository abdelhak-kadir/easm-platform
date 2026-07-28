from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from app.tools.whois.scan import (
    WhoisNoDataError,
    WhoisRateLimitError,
    WhoisScanError,
    _to_json_safe,
    _to_registrable_domain,
    run,
)

SAMPLE_WHOIS_RESULT = {
    "domain_name": ["EXAMPLE.COM", "example.com"],
    "registrar": "Example Registrar, LLC",
    "whois_server": "whois.example-registrar.com",
    "creation_date": datetime(2000, 1, 1, 12, 0, 0),
    "updated_date": datetime(2025, 6, 1, 8, 30, 0),
    "expiration_date": datetime(2030, 1, 1, 12, 0, 0),
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "status": ["clientTransferProhibited"],
    "emails": ["admin@example.com"],
    "dnssec": "unsigned",
    "org": "Example Org",
    "country": "US",
}


# ---------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_reduces_subdomain_to_registrable_domain(mock_whois):
    mock_whois.return_value = SAMPLE_WHOIS_RESULT

    run("app.staging.example.com")

    mock_whois.assert_called_once_with("example.com")


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_calls_whois_with_bare_domain_unchanged(mock_whois):
    mock_whois.return_value = SAMPLE_WHOIS_RESULT

    run("example.com")

    mock_whois.assert_called_once_with("example.com")


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_returns_json_safe_dict(mock_whois):
    mock_whois.return_value = SAMPLE_WHOIS_RESULT

    result = run("example.com")

    assert result["creation_date"] == "2000-01-01T12:00:00+00:00"
    assert result["expiration_date"] == "2030-01-01T12:00:00+00:00"
    assert result["domain_name"] == ["EXAMPLE.COM", "example.com"]
    assert result["registrar"] == "Example Registrar, LLC"


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_raises_no_data_error_when_result_missing_domain_name(mock_whois):
    mock_whois.return_value = {"registrar": "Someone"}

    with pytest.raises(WhoisNoDataError, match="No WHOIS data available"):
        run("no-record.invalid")


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_raises_no_data_error_when_result_is_empty(mock_whois):
    mock_whois.return_value = {}

    with pytest.raises(WhoisNoDataError):
        run("no-record.invalid")


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_raises_no_data_error_when_result_is_none(mock_whois):
    mock_whois.return_value = None

    with pytest.raises(WhoisNoDataError):
        run("no-record.invalid")


@pytest.mark.parametrize(
    "message",
    [
        "Rate limit exceeded, please wait",
        "quota exceeded for this billing period",
        "too many requests, slow down",
    ],
)
@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_raises_rate_limit_error_on_throttling_messages(mock_whois, message):
    mock_whois.side_effect = Exception(message)

    with pytest.raises(WhoisRateLimitError, match="rate limit reached"):
        run("example.com")


@patch("app.tools.whois.scan.whois_lib.whois")
def test_run_raises_generic_scan_error_on_other_exceptions(mock_whois):
    mock_whois.side_effect = Exception("connection refused")

    with pytest.raises(WhoisScanError, match="WHOIS lookup failed"):
        run("example.com")


# ---------------------------------------------------------------------
# _to_registrable_domain
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset_value,expected",
    [
        ("example.com", "example.com"),
        ("app.staging.example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("a.b.c.example.com", "example.com"),
    ],
)
def test_to_registrable_domain(asset_value, expected):
    assert _to_registrable_domain(asset_value) == expected


def test_to_registrable_domain_falls_back_to_input_when_no_match():
    # A bare single-label value has nothing to reduce -- the regex
    # won't match, so the original (lowercased/stripped by the
    # caller's own handling upstream) value is returned as-is.
    assert _to_registrable_domain("localhost") == "localhost"


# ---------------------------------------------------------------------
# _to_json_safe
# ---------------------------------------------------------------------


def test_to_json_safe_converts_naive_datetime_to_aware_isoformat():
    result = _to_json_safe(datetime(2025, 6, 1, 8, 30, 0))
    assert result == "2025-06-01T08:30:00+00:00"


def test_to_json_safe_preserves_already_aware_datetime():
    aware = datetime(2025, 6, 1, 8, 30, 0, tzinfo=UTC)
    result = _to_json_safe(aware)
    assert result == "2025-06-01T08:30:00+00:00"


def test_to_json_safe_recurses_into_dict():
    result = _to_json_safe({"created": datetime(2020, 1, 1), "name": "example"})
    assert result == {"created": "2020-01-01T00:00:00+00:00", "name": "example"}


def test_to_json_safe_recurses_into_list():
    result = _to_json_safe([datetime(2020, 1, 1), "plain-string", 42])
    assert result == ["2020-01-01T00:00:00+00:00", "plain-string", 42]


def test_to_json_safe_recurses_into_nested_structures():
    result = _to_json_safe({"dates": [datetime(2020, 1, 1), datetime(2021, 1, 1, tzinfo=UTC)]})
    assert result == {"dates": ["2020-01-01T00:00:00+00:00", "2021-01-01T00:00:00+00:00"]}


def test_to_json_safe_leaves_non_datetime_scalars_unchanged():
    assert _to_json_safe("hello") == "hello"
    assert _to_json_safe(42) == 42
    assert _to_json_safe(None) is None
