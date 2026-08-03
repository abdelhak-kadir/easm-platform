from unittest.mock import MagicMock, patch

import pytest
import requests
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.censys.scan import (
    CensysNoDataError,
    CensysRateLimitError,
    CensysScanError,
    run,
)

# ── helpers ───────────────────────────────────────────────────────────


def _mock_resp(json_data=None, *, status_code=200):
    """Build a MagicMock that behaves like a requests.Response."""
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data if json_data is not None else {}
    return m


def _host_result(**overrides) -> dict:
    """Minimal valid Censys host response with sensible defaults."""
    return {
        "result": {
            "ip": "1.2.3.4",
            "location": {
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "province": "California",
                "coordinates": {"latitude": 37.4056, "longitude": -122.0775},
            },
            "autonomous_system": {
                "asn": 15169,
                "organization": "Google LLC",
                "description": "GOOGLE",
            },
            "last_updated_at": "2026-07-15T00:00:00Z",
            "services": [
                {
                    "port": 443,
                    "service_name": "HTTP",
                    "extended_service_name": "HTTPS",
                    "transport_protocol": "TCP",
                    "banner": "HTTP/1.1 200 OK",
                    "software": [{"product": "nginx", "version": "1.18.0"}],
                }
            ],
            **overrides,
        }
    }


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"})
def test_run_returns_host_result(mock_get):
    mock_get.return_value = _mock_resp(_host_result())

    result = run("1.2.3.4")
    assert result["ip"] == "1.2.3.4"
    assert len(result["services"]) == 1


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"})
def test_run_uses_basic_auth(mock_get):
    mock_get.return_value = _mock_resp(_host_result())

    run("1.2.3.4")
    assert mock_get.call_args[1]["auth"] == ("test-id", "test-secret")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"})
def test_run_strips_whitespace(mock_get):
    mock_get.return_value = _mock_resp(_host_result())

    run("  1.2.3.4  ")
    mock_get.assert_called_once()
    assert "1.2.3.4" in mock_get.call_args[0][0]


# ── missing credentials ───────────────────────────────────────────────


@patch.dict("os.environ", {}, clear=True)
def test_run_raises_no_data_without_api_id():
    with pytest.raises(CensysNoDataError, match="CENSYS_API_ID and CENSYS_API_SECRET"):
        run("1.2.3.4")


@patch.dict("os.environ", {"CENSYS_API_ID": "id-only"}, clear=True)
def test_run_raises_no_data_without_api_secret():
    with pytest.raises(CensysNoDataError, match="CENSYS_API_ID and CENSYS_API_SECRET"):
        run("1.2.3.4")


# ── invalid input ──────────────────────────────────────────────────────


@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_on_non_ip():
    with pytest.raises(CensysScanError, match="not a valid IP"):
        run("example.com")


# ── error cases ────────────────────────────────────────────────────────


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_rate_limit_on_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    with pytest.raises(CensysRateLimitError, match="timed out"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_no_data_on_404(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.side_effect = requests.HTTPError("404 Not Found", response=mock_resp)

    with pytest.raises(CensysNoDataError, match="No Censys data"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_no_data_on_401(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.side_effect = requests.HTTPError("401 Unauthorized", response=mock_resp)

    with pytest.raises(CensysNoDataError, match="access denied"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_no_data_on_403(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_get.side_effect = requests.HTTPError("403 Forbidden", response=mock_resp)

    with pytest.raises(CensysNoDataError, match="access denied"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_rate_limit_on_429(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.side_effect = requests.HTTPError("429 Too Many Requests", response=mock_resp)

    with pytest.raises(CensysRateLimitError, match="rate-limited"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_rate_limit_on_502(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)

    with pytest.raises(CensysRateLimitError, match="server error"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_scan_error_on_400(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_get.side_effect = requests.HTTPError("400 Bad Request", response=mock_resp)

    with pytest.raises(CensysScanError, match="host lookup failed"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_scan_error_on_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("Connection refused")

    with pytest.raises(CensysScanError, match="connection failed"):
        run("1.2.3.4")


@patch("app.tools.censys.scan.requests.get")
@patch.dict("os.environ", {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"})
def test_run_raises_no_data_when_result_is_empty(mock_get):
    mock_get.return_value = _mock_resp({})

    with pytest.raises(CensysNoDataError, match="No Censys data"):
        run("1.2.3.4")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(CensysNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(CensysRateLimitError, ToolRateLimitError)
