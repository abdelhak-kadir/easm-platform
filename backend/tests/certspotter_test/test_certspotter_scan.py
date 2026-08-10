from unittest import mock

import pytest
import requests
from app.tools.certspotter.scan import (
    CertSpotterNoDataError,
    CertSpotterRateLimitError,
    CertSpotterScanError,
    run,
)

_ISSUANCES = [
    {"id": "abc", "dns_names": ["example.com", "www.example.com"]},
    {"id": "def", "dns_names": ["mail.example.com", "www.example.com"]},
]

_EMPTY_PAGE: list = []


def _mock_response(status=200, json_data=None):
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data or _ISSUANCES
    return resp


def test_run_finds_subdomains():
    with mock.patch("requests.get", return_value=_mock_response()) as get:
        data = run("example.com")
    assert get.called
    assert "www.example.com" in data["hosts"]
    assert "mail.example.com" in data["hosts"]
    assert "example.com" not in data["hosts"]


@mock.patch.dict("os.environ", {"CERTSPOTTER_API_KEY": "test-key"})
def test_run_with_api_key():
    with mock.patch("requests.get", return_value=_mock_response()) as get:
        run("example.com")
    headers = get.call_args.kwargs.get("headers", {})
    assert headers.get("Authorization") == "Bearer test-key"


def test_run_paginates():
    page1 = [_ISSUANCES[0]]
    page2 = [_ISSUANCES[1]]
    with mock.patch(
        "requests.get",
        side_effect=[_mock_response(json_data=page1), _mock_response(json_data=page2)],
    ) as get:
        data = run("example.com")
    assert get.call_count == 2
    assert "www.example.com" in data["hosts"]
    assert "mail.example.com" in data["hosts"]


def test_run_empty_result():
    with mock.patch("requests.get", return_value=_mock_response(json_data=[])):
        with pytest.raises(CertSpotterNoDataError):
            run("example.com")


def test_run_429_rate_limit():
    with mock.patch("requests.get", return_value=_mock_response(status=429)):
        with pytest.raises(CertSpotterRateLimitError):
            run("example.com")


def test_run_400_no_data():
    with mock.patch("requests.get", return_value=_mock_response(status=400)):
        with pytest.raises(CertSpotterNoDataError):
            run("example.com")


def test_run_api_error_object():
    resp = _mock_response(json_data={"code": "rate_limited", "message": "slow down"})
    resp.status_code = 200
    with mock.patch("requests.get", return_value=resp):
        with pytest.raises(CertSpotterRateLimitError):
            run("example.com")


def test_run_timeout_is_rate_limit():
    with mock.patch("requests.get", side_effect=requests.Timeout):
        with pytest.raises(CertSpotterRateLimitError):
            run("example.com")


def test_run_connection_error():
    with mock.patch("requests.get", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(CertSpotterScanError):
            run("example.com")


def test_run_empty_domain():
    with pytest.raises(CertSpotterNoDataError):
        run("")
