import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.amass.scan import (
    AmassNoDataError,
    AmassScanError,
    _extract_fqdns,
    _filter_subdomains,
    run,
)
from app.tools.base import ToolNoDataError

# ── helpers ───────────────────────────────────────────────────────────


def _amass_stdout(*fqdn_names: str) -> str:
    """Build Amass v4 edge-format stdout from a list of FQDN names.

    Each name is wrapped in a synthetic edge line::

        name (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
    """
    lines = []
    for name in fqdn_names:
        lines.append(f"{name} (FQDN) --> a_record --> 1.2.3.4 (IPAddress)")
    return "\n".join(lines)


def _amass_ok(hosts: tuple[str, ...] = ()) -> MagicMock:
    """Return a MagicMock that simulates a successful amass enum call."""
    m = MagicMock()
    m.returncode = 0
    m.stdout = _amass_stdout(*hosts)
    return m


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_returns_hosts(mock_run):
    mock_run.return_value = _amass_ok(("mail.example.com", "www.example.com"))

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com"}
    assert result["domain"] == "example.com"
    assert result["sources_used"] == ["amass"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_filters_wildcards(mock_run):
    mock_run.return_value = _amass_ok(("*.example.com", "www.example.com"))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_filters_third_party_domains(mock_run):
    mock_run.return_value = _amass_ok(("www.example.com", "unrelated.org"))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.amass.scan.subprocess.run")
def test_run_strips_trailing_dot(mock_run):
    mock_run.return_value = _amass_ok(("sub.example.com",))

    result = run("example.com.")
    assert result["domain"] == "example.com"


@patch("app.tools.amass.scan.subprocess.run")
def test_run_extracts_fqdns_from_edge_format(mock_run):
    """Real Amass v4 output — edge-format lines with FQDN tokens on both sides."""
    mock_run.return_value = MagicMock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = (
        "elysec-int.com (FQDN) --> ns_record --> ns1.adk-media.com (FQDN)\n"
        "mail.elysec-int.com (FQDN) --> cname_record --> elysec-int.com (FQDN)\n"
        "webmail.elysec-int.com (FQDN) --> a_record --> 5.196.101.122 (IPAddress)\n"
    )

    result = run("elysec-int.com")
    assert set(result["hosts"]) == {"mail.elysec-int.com", "webmail.elysec-int.com"}


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.amass.scan.subprocess.run")
def test_run_raises_no_data_when_amass_returns_no_fqdns(mock_run):
    mock_run.return_value = _amass_ok()  # empty stdout

    with pytest.raises(AmassNoDataError, match="No subdomains found"):
        run("example.com")


def test_run_raises_no_data_for_wildcard_domain():
    with pytest.raises(AmassNoDataError, match="Wildcard domains"):
        run("*.example.com")


# ── error cases ───────────────────────────────────────────────────────


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


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(AmassNoDataError, ToolNoDataError)


# ── _extract_fqdns ────────────────────────────────────────────────────


def test_extract_fqdns_from_edge_line():
    line = "mail.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"
    assert _extract_fqdns(line) == ["mail.example.com"]


def test_extract_fqdns_both_sides():
    line = "sub.example.com (FQDN) --> cname_record --> other.example.com (FQDN)"
    assert _extract_fqdns(line) == ["sub.example.com", "other.example.com"]


def test_extract_fqdns_no_match():
    assert _extract_fqdns("no fqdn tokens here") == []


def test_extract_fqdns_multiple_lines():
    stdout = (
        "a.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\n"
        "b.example.com (FQDN) --> cname_record --> c.example.com (FQDN)\n"
        "The enumeration has finished\n"
    )
    assert _extract_fqdns(stdout) == ["a.example.com", "b.example.com", "c.example.com"]


# ── filter helpers ────────────────────────────────────────────────────


def test_filter_subdomains_keeps_only_target():
    assert _filter_subdomains(["mail.example.com", "cdn.unrelated.org"], "example.com") == {
        "mail.example.com"
    }


def test_filter_subdomains_handles_empty():
    assert _filter_subdomains([], "example.com") == set()
