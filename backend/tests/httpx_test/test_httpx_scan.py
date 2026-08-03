import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.base import ToolNoDataError
from app.tools.httpx.scan import HttpxNoDataError, HttpxScanError, run

# ── helpers ───────────────────────────────────────────────────────────


def _httpx_jsonl(responses: list[dict]) -> str:
    """Build a JSONL string from httpx response dicts."""
    return "\n".join(json.dumps(r) for r in responses)


def _simple_resp(**overrides) -> dict:
    """Minimal httpx JSON response."""
    return {
        "url": "https://example.com",
        "input": "example.com",
        "status_code": 200,
        "title": "Example Domain",
        "tech": ["HSTS"],
        "webserver": "nginx",
        "ip": "93.184.216.34",
        **overrides,
    }


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_returns_single_response(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=_httpx_jsonl([_simple_resp()]))

    result = run("example.com")
    assert result["target"] == "example.com"
    assert len(result["responses"]) == 1
    assert result["responses"][0]["status_code"] == 200
    assert result["sources_used"] == ["httpx"]


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_returns_multiple_responses(mock_run):
    """httpx can emit multiple JSON lines for http+https, redirects, etc."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=_httpx_jsonl(
            [
                _simple_resp(url="https://example.com"),
                _simple_resp(url="http://example.com", status_code=301),
            ]
        ),
    )

    result = run("example.com")
    assert len(result["responses"]) == 2


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_skips_invalid_json_lines(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=(
            '{"url": "https://example.com", "status_code": 200}\n'
            "not json\n"
            '{"url": "http://example.com", "status_code": 301}'
        ),
    )

    result = run("example.com")
    assert len(result["responses"]) == 2


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_no_data_when_empty_stdout(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="")

    with pytest.raises(HttpxNoDataError, match="No HTTP"):
        run("example.com")


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_no_data_when_all_lines_invalid(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="not json\n{{broken\n")

    with pytest.raises(HttpxNoDataError, match="No HTTP"):
        run("example.com")


# ── error cases ───────────────────────────────────────────────────────


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_scan_error_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("httpx", 90)

    with pytest.raises(HttpxScanError, match="timed out"):
        run("example.com")


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_no_data_on_no_host_found(mock_run):
    """httpx exits non-zero with 'no host found' — that's no-data, not a failure."""
    mock_run.side_effect = subprocess.CalledProcessError(1, "httpx", stderr=b"no host found")

    with pytest.raises(HttpxNoDataError):
        run("example.com")


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_scan_error_on_other_nonzero_exit(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(2, "httpx", stderr=b"invalid flag")

    with pytest.raises(HttpxScanError, match="exited 2"):
        run("example.com")


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_scan_error_on_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(HttpxScanError, match="not found on PATH"):
        run("example.com")


@patch("app.tools.httpx.scan.subprocess.run")
def test_run_raises_scan_error_on_os_error(mock_run):
    mock_run.side_effect = OSError("disk full")

    with pytest.raises(HttpxScanError, match="OS error"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(HttpxNoDataError, ToolNoDataError)
