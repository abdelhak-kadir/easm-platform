import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.amass.scan import (
    AmassNoDataError,
    AmassScanError,
    _filter_subdomains,
    run,
)
from app.tools.base import ToolNoDataError

# ── helpers ───────────────────────────────────────────────────────────


def _amass_ok():
    """Return a MagicMock that simulates a successful amass enum call."""
    m = MagicMock()
    m.returncode = 0
    return m


def _oam_subs_ok(*hosts: str):
    """Return a MagicMock that simulates successful oam_subs output."""
    m = MagicMock()
    m.returncode = 0
    m.stdout = "\n".join(hosts)
    return m


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_returns_hosts(mock_run):
    mock_run.side_effect = [
        _amass_ok(),  # amass enum
        _oam_subs_ok("mail.example.com", "www.example.com"),  # oam_subs
    ]

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com"}
    assert result["domain"] == "example.com"
    assert result["sources_used"] == ["amass"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_filters_wildcards(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        _oam_subs_ok("*.example.com", "www.example.com"),
    ]

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_filters_third_party_domains(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        _oam_subs_ok("www.example.com", "unrelated.org"),
    ]

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_strips_trailing_dot(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        _oam_subs_ok("sub.example.com"),
    ]

    result = run("example.com.")
    assert result["domain"] == "example.com"


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_no_data_when_oam_subs_empty(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        _oam_subs_ok(),  # empty stdout
    ]

    with pytest.raises(AmassNoDataError, match="No subdomains found"):
        run("example.com")


def test_run_raises_no_data_for_wildcard_domain():
    with pytest.raises(AmassNoDataError, match="Wildcard domains"):
        run("*.example.com")


# ── error cases: amass enum ───────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_amass_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("amass", 900)

    with pytest.raises(AmassScanError, match="timed out"):
        run("example.com")


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_amass_nonzero_exit(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "amass", stderr=b"network error")

    with pytest.raises(AmassScanError, match="exited 1"):
        run("example.com")


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_amass_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(AmassScanError, match="not found on PATH"):
        run("example.com")


# ── error cases: oam_subs ─────────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_oam_subs_timeout(mock_run):
    """Amass enum succeeds but oam_subs times out."""
    mock_run.side_effect = [
        _amass_ok(),
        subprocess.TimeoutExpired("oam_subs", 120),
    ]

    with pytest.raises(AmassScanError, match="timed out"):
        run("example.com")


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_oam_subs_nonzero_exit(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        subprocess.CalledProcessError(1, "oam_subs", stderr=b"no data"),
    ]

    with pytest.raises(AmassScanError, match="exited 1"):
        run("example.com")


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_on_oam_subs_missing_binary(mock_run):
    mock_run.side_effect = [
        _amass_ok(),
        FileNotFoundError(),
    ]

    with pytest.raises(AmassScanError, match="not found on PATH"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(AmassNoDataError, ToolNoDataError)


# ── filter helpers ────────────────────────────────────────────────────


def test_filter_subdomains_keeps_only_target():
    assert _filter_subdomains(["mail.example.com", "cdn.unrelated.org"], "example.com") == {
        "mail.example.com"
    }


def test_filter_subdomains_handles_empty():
    assert _filter_subdomains([], "example.com") == set()
