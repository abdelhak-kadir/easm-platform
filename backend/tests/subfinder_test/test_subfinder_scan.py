import subprocess
from unittest.mock import patch

import pytest
from app.tools.base import ToolNoDataError
from app.tools.subfinder.scan import (
    SubfinderNoDataError,
    SubfinderScanError,
    _filter_subdomains,
    run,
)

# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_returns_hosts(mock_run):
    mock_run.return_value.stdout = "mail.example.com\nwww.example.com\napi.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com", "api.example.com"}
    assert result["domain"] == "example.com"
    assert result["sources_used"] == ["subfinder"]


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_deduplicates_hosts(mock_run):
    mock_run.return_value.stdout = "sub.example.com\nsub.example.com\nwww.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com")
    assert result["hosts"] == ["sub.example.com", "www.example.com"]


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_strips_trailing_dot(mock_run):
    mock_run.return_value.stdout = "sub.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com.")
    assert result["domain"] == "example.com"


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_filters_wildcard_hosts(mock_run):
    mock_run.return_value.stdout = "*.example.com\nwww.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_filters_third_party_domains(mock_run):
    mock_run.return_value.stdout = "www.example.com\nunrelated.org\nother.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "other.example.com"}


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_excludes_naked_domain(mock_run):
    mock_run.return_value.stdout = "example.com\nwww.example.com"
    mock_run.return_value.returncode = 0

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_no_data_when_empty_stdout(mock_run):
    mock_run.return_value.stdout = ""
    mock_run.return_value.returncode = 0

    with pytest.raises(SubfinderNoDataError, match="No subdomains found"):
        run("example.com")


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_no_data_when_all_filtered(mock_run):
    mock_run.return_value.stdout = "unrelated.org\nexample.com"
    mock_run.return_value.returncode = 0

    with pytest.raises(SubfinderNoDataError, match="No subdomains found"):
        run("example.com")


def test_run_raises_no_data_for_wildcard_domain():
    with pytest.raises(SubfinderNoDataError, match="Wildcard domains"):
        run("*.example.com")


# ── error cases ───────────────────────────────────────────────────────


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_scan_error_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("subfinder", 180)

    with pytest.raises(SubfinderScanError, match="timed out"):
        run("example.com")


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_scan_error_on_nonzero_exit(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "subfinder", stderr=b"some error")

    with pytest.raises(SubfinderScanError, match="exited 1"):
        run("example.com")


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_scan_error_on_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(SubfinderScanError, match="not found on PATH"):
        run("example.com")


@patch("app.tools.subfinder.scan.subprocess.run")
def test_run_raises_scan_error_on_os_error(mock_run):
    mock_run.side_effect = OSError("disk full")

    with pytest.raises(SubfinderScanError, match="OS error"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(SubfinderNoDataError, ToolNoDataError)


# ── filter helpers ────────────────────────────────────────────────────


def test_filter_subdomains_keeps_only_target():
    assert _filter_subdomains(
        ["mail.example.com", "www.example.com", "cdn.unrelated.org"], "example.com"
    ) == {"mail.example.com", "www.example.com"}


def test_filter_subdomains_excludes_wildcards():
    assert _filter_subdomains(["*.example.com", "www.example.com"], "example.com") == {
        "www.example.com"
    }


def test_filter_subdomains_excludes_naked_domain():
    assert "example.com" not in _filter_subdomains(
        ["example.com", "www.example.com"], "example.com"
    )


def test_filter_subdomains_handles_empty():
    assert _filter_subdomains([], "example.com") == set()
