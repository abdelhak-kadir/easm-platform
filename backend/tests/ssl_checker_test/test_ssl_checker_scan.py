from unittest import mock

import pytest
import requests
from app.tools.ssl_checker.scan import (
    SslCheckerNoDataError,
    SslCheckerRateLimitError,
    SslCheckerScanError,
    run,
)

_VALID_RESPONSE = {
    "domain": "example.com",
    "cn": "example.com",
    "issuer": "Let's Encrypt",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-12-31T23:59:59Z",
    "days_left": 143,
    "expired": False,
    "serial_hex": "abc123",
    "fingerprint_sha256": "a" * 64,
    "sans": ["example.com", "www.example.com"],
    "key_type": "RSA",
    "key_size": 2048,
    "signature_algorithm": "sha256WithRSAEncryption",
}


def _mock_response(status=200, json_data=None):
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data or _VALID_RESPONSE
    resp.text = ""
    return resp


def test_run_fetches_cert():
    with mock.patch("requests.get", return_value=_mock_response()) as get:
        data = run("example.com")
    get.assert_called_once()
    assert data["domain"] == "example.com"
    assert data["issuer"] == "Let's Encrypt"


def test_run_strips_dots_and_lowercases():
    with mock.patch("requests.get", return_value=_mock_response()) as get:
        run("  Example.COM.  ")
    call_args = get.call_args.kwargs["params"]
    assert call_args["domain"] == "example.com"


def test_run_429_rate_limit():
    resp = _mock_response(status=429)
    resp.text = "Rate limit exceeded"
    with mock.patch("requests.get", return_value=resp):
        with pytest.raises(SslCheckerRateLimitError):
            run("example.com")


def test_run_502_rate_limit():
    with mock.patch("requests.get", return_value=_mock_response(status=502)):
        with pytest.raises(SslCheckerRateLimitError):
            run("example.com")


def test_run_503_rate_limit():
    with mock.patch("requests.get", return_value=_mock_response(status=503)):
        with pytest.raises(SslCheckerRateLimitError):
            run("example.com")


def test_run_400_no_data():
    with mock.patch("requests.get", return_value=_mock_response(status=400)):
        with pytest.raises(SslCheckerNoDataError):
            run("example.com")


def test_run_unexpected_status():
    with mock.patch("requests.get", return_value=_mock_response(status=418)):
        with pytest.raises(SslCheckerScanError):
            run("example.com")


def test_run_empty_cn_is_no_data():
    data = dict(_VALID_RESPONSE, cn="")
    with mock.patch("requests.get", return_value=_mock_response(json_data=data)):
        with pytest.raises(SslCheckerNoDataError):
            run("example.com")


def test_run_timeout_is_rate_limit():
    with mock.patch("requests.get", side_effect=requests.Timeout):
        with pytest.raises(SslCheckerRateLimitError):
            run("example.com")


def test_run_connection_error():
    with mock.patch("requests.get", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(SslCheckerScanError):
            run("example.com")


def test_run_empty_domain():
    with pytest.raises(SslCheckerNoDataError):
        run("")
