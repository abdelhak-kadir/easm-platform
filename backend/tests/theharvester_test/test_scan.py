from unittest.mock import MagicMock, patch

import pytest
import requests
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.theharvester.scan import (
    TheHarvesterNoDataError,
    TheHarvesterRateLimitError,
    TheHarvesterScanError,
    run,
)

# ── helpers ───────────────────────────────────────────────────────────


def _crtsh_response(*name_values: str) -> list[dict]:
    """Build a crt.sh-style JSON response from name_value strings."""
    return [{"id": i, "name_value": nv} for i, nv in enumerate(name_values, 1)]


def _mock_resp(json_data=None, *, status_code=200, exc=None):
    """Build a MagicMock that behaves like a requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data if json_data is not None else []
    if exc:
        mock_resp.raise_for_status.side_effect = exc
    return mock_resp


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_hosts(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("mail.example.com\nwww.example.com"))

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com"}
    assert result["domain"] == "example.com"


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_ips_in_san(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("93.184.216.34\n1.2.3.4"))

    result = run("example.com")
    assert len(result["ips"]) == 2
    assert "93.184.216.34" in result["ips"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_emails_in_san(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("admin@example.com"))

    result = run("example.com")
    assert "admin@example.com" in result["emails"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_deduplicates_hosts(mock_get):
    mock_get.return_value = _mock_resp(
        _crtsh_response("sub.example.com\nsub.example.com\nwww.example.com")
    )

    result = run("example.com")
    assert result["hosts"] == ["sub.example.com", "www.example.com"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_excludes_naked_domain(mock_get):
    """The queried domain itself should not appear as a discovered host."""
    mock_get.return_value = _mock_resp(_crtsh_response("example.com\nwww.example.com"))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_excludes_third_party_domains(mock_get):
    """Only subdomains of the target domain are kept — unrelated domains
    that happen to share a cert are filtered out."""
    mock_get.return_value = _mock_resp(
        _crtsh_response("www.example.com\nunrelated.org\nother.example.com")
    )

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "other.example.com"}


@patch("app.tools.theharvester.scan.requests.get")
def test_run_strips_trailing_dot(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("sub.example.com"))

    result = run("example.com.")
    assert result["domain"] == "example.com"


@patch("app.tools.theharvester.scan.requests.get")
def test_run_includes_sources_used(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("sub.example.com"))

    result = run("example.com")
    assert "crtsh" in result["sources_used"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_handles_multiple_entries(mock_get):
    mock_get.return_value = _mock_resp(
        [
            {"id": 1, "name_value": "www.example.com\ncdn.example.com"},
            {"id": 2, "name_value": "mail.example.com"},
        ]
    )

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "cdn.example.com", "mail.example.com"}


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_when_all_empty(mock_get):
    mock_get.return_value = _mock_resp([])

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_when_all_filtered(mock_get):
    """If all SAN entries are third-party domains or the target itself,
    the result set is effectively empty."""
    mock_get.return_value = _mock_resp(_crtsh_response("example.com\nunrelated.org"))

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


# ── error cases ───────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    with pytest.raises(TheHarvesterScanError, match="timed out"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_rate_limit_on_429(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.side_effect = requests.HTTPError("429 Client Error", response=mock_resp)

    with pytest.raises(TheHarvesterRateLimitError, match="rate-limited"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_on_crtsh_404(mock_get):
    """crt.sh returns bare 404 (not an empty array) when a domain has
    no certs — must be treated as no-data, not a scan failure."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.side_effect = requests.HTTPError("404 Client Error", response=mock_resp)

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("elysec-int.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_rate_limit_on_502(mock_get):
    """5xx errors from CRT.sh are transient server failures — retryable."""
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)

    with pytest.raises(TheHarvesterRateLimitError, match="server error"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_http_error(mock_get):
    """4xx errors (other than 429) are permanent client errors — not retryable."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_get.side_effect = requests.HTTPError("400 Bad Request", response=mock_resp)

    with pytest.raises(TheHarvesterScanError, match="CRT.sh request failed"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("Connection refused")

    with pytest.raises(TheHarvesterScanError, match="CRT.sh request failed"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_handles_invalid_json(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    # Invalid JSON → empty results → NoDataError
    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(TheHarvesterNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(TheHarvesterRateLimitError, ToolRateLimitError)
