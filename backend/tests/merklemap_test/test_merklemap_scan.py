from unittest.mock import MagicMock, patch

import pytest
import requests
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.merklemap.scan import (
    MerkleMapNoDataError,
    MerkleMapRateLimitError,
    MerkleMapScanError,
    run,
)

# ── helpers ───────────────────────────────────────────────────────────


def _mock_resp(json_data=None, *, status_code=200):
    m = MagicMock(spec=requests.Response)
    m.status_code = status_code
    m.json.return_value = json_data if json_data is not None else {}
    m.raise_for_status = MagicMock()
    return m


def _api_page(*hosts: str, count: int | None = None) -> dict:
    """Minimal valid MerkleMap search response."""
    return {
        "count": count if count is not None else len(hosts),
        "results": [
            {"hostname": h, "subject_common_name": h, "first_seen": "2026-01-01T00:00:00Z"}
            for h in hosts
        ],
    }


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_returns_hosts(mock_get):
    mock_get.return_value = _mock_resp(_api_page("mail.example.com", "www.example.com", count=2))

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com"}
    assert result["domain"] == "example.com"
    assert result["sources_used"] == ["merklemap"]


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_deduplicates_hosts(mock_get):
    mock_get.return_value = _mock_resp(
        _api_page("sub.example.com", "sub.example.com", "www.example.com", count=3)
    )

    result = run("example.com")
    assert result["hosts"] == ["sub.example.com", "www.example.com"]


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_strips_trailing_dot(mock_get):
    mock_get.return_value = _mock_resp(_api_page("sub.example.com", count=1))

    result = run("example.com.")
    assert result["domain"] == "example.com"


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_filters_wildcard_hosts(mock_get):
    mock_get.return_value = _mock_resp(_api_page("*.example.com", "www.example.com", count=2))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_filters_third_party_domains(mock_get):
    mock_get.return_value = _mock_resp(
        _api_page("www.example.com", "unrelated.org", "other.example.com", count=3)
    )

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "other.example.com"}


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_excludes_naked_domain(mock_get):
    mock_get.return_value = _mock_resp(_api_page("example.com", "www.example.com", count=2))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_paginates(mock_get):
    mock_get.side_effect = [
        _mock_resp(_api_page("a.example.com", count=2)),
        _mock_resp(_api_page("b.example.com", count=2)),
        _mock_resp({"count": 2, "results": []}),
    ]

    result = run("example.com")
    assert result["hosts"] == ["a.example.com", "b.example.com"]
    assert mock_get.call_count == 3


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_no_data_when_empty_results(mock_get):
    mock_get.return_value = _mock_resp({"count": 0, "results": []})

    with pytest.raises(MerkleMapNoDataError, match="No subdomains found"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_no_data_when_all_filtered(mock_get):
    mock_get.return_value = _mock_resp(_api_page("unrelated.org", "example.com", count=2))

    with pytest.raises(MerkleMapNoDataError, match="No subdomains found"):
        run("example.com")


def test_run_raises_no_data_for_wildcard_domain():
    with patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"}):
        with pytest.raises(MerkleMapNoDataError, match="Wildcard domains"):
            run("*.example.com")


@patch.dict("os.environ", {}, clear=True)
def test_run_raises_no_data_without_api_key():
    with pytest.raises(MerkleMapNoDataError, match="MERKLEMAP_API_KEY"):
        run("example.com")


# ── error cases ───────────────────────────────────────────────────────


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_rate_limit_on_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    with pytest.raises(MerkleMapRateLimitError, match="timed out"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_no_data_on_401(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.side_effect = requests.HTTPError("401 Unauthorized", response=mock_resp)

    with pytest.raises(MerkleMapNoDataError, match="access denied"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_no_data_on_403(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_get.side_effect = requests.HTTPError("403 Forbidden", response=mock_resp)

    with pytest.raises(MerkleMapNoDataError, match="access denied"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_rate_limit_on_429(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.side_effect = requests.HTTPError("429 Too Many Requests", response=mock_resp)

    with pytest.raises(MerkleMapRateLimitError, match="rate-limited"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_rate_limit_on_502(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)

    with pytest.raises(MerkleMapRateLimitError, match="server error"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_scan_error_on_400(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_get.side_effect = requests.HTTPError("400 Bad Request", response=mock_resp)

    with pytest.raises(MerkleMapScanError, match="request failed"):
        run("example.com")


@patch("app.tools.merklemap.scan.requests.get")
@patch.dict("os.environ", {"MERKLEMAP_API_KEY": "test-key"})
def test_run_raises_scan_error_on_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("Connection refused")

    with pytest.raises(MerkleMapScanError, match="connection failed"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(MerkleMapNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(MerkleMapRateLimitError, ToolRateLimitError)
