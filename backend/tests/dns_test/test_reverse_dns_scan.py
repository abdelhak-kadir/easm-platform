from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
from app.tools.reverse_dns.scan import (
    ReverseDnsNoDataError,
    ReverseDnsRateLimitError,
    ReverseDnsScanError,
    run,
)


def _mock_rdata(hostname: str) -> MagicMock:
    rdata = MagicMock()
    rdata.target = hostname
    return rdata


# ---------------------------------------------------------------------
# run() -- success paths
# ---------------------------------------------------------------------


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve")
def test_run_returns_hostname_for_valid_ip(mock_resolve):
    mock_resolve.return_value = [_mock_rdata("mail.example.com.")]

    result = run("93.184.216.34")

    assert result["ip"] == "93.184.216.34"
    assert result["hostnames"] == ["mail.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve")
def test_run_returns_multiple_hostnames_in_order(mock_resolve):
    mock_resolve.return_value = [
        _mock_rdata("mail.example.com."),
        _mock_rdata("web.example.com."),
    ]

    result = run("93.184.216.34")

    assert result["hostnames"] == ["mail.example.com", "web.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve")
def test_run_ptr_query_matches_reverse_address_and_has_no_trailing_dot(mock_resolve):
    mock_resolve.return_value = [_mock_rdata("mail.example.com.")]

    result = run("93.184.216.34")

    assert result["ptr_query"].endswith("in-addr.arpa")
    assert not result["ptr_query"].endswith(".")


# ---------------------------------------------------------------------
# run() -- invalid input
# ---------------------------------------------------------------------


def test_run_raises_scan_error_for_invalid_ip():
    with pytest.raises(ReverseDnsScanError, match="not a valid IP address"):
        run("not-an-ip")


def test_run_raises_scan_error_for_domain_instead_of_ip():
    # This tool only accepts IPs -- see registry.py's asset_types.
    with pytest.raises(ReverseDnsScanError, match="not a valid IP address"):
        run("example.com")


# ---------------------------------------------------------------------
# run() -- DNS error mapping
# ---------------------------------------------------------------------


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN)
def test_run_raises_no_data_error_on_nxdomain(mock_resolve):
    with pytest.raises(ReverseDnsNoDataError, match="No PTR record"):
        run("93.184.216.34")


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer)
def test_run_raises_no_data_error_on_no_answer(mock_resolve):
    with pytest.raises(ReverseDnsNoDataError, match="No PTR record"):
        run("93.184.216.34")


@patch("app.tools.reverse_dns.scan.dns.resolver.resolve", side_effect=dns.resolver.Timeout)
def test_run_raises_rate_limit_error_on_timeout(mock_resolve):
    with pytest.raises(ReverseDnsRateLimitError):
        run("93.184.216.34")


@patch(
    "app.tools.reverse_dns.scan.dns.resolver.resolve",
    side_effect=dns.exception.DNSException("boom"),
)
def test_run_raises_generic_scan_error_on_other_dns_exception(mock_resolve):
    with pytest.raises(ReverseDnsScanError, match="Reverse DNS lookup failed"):
        run("93.184.216.34")


# ---------------------------------------------------------------------
# error class hierarchy (relied on by app.tools.base dispatch in tasks.py)
# ---------------------------------------------------------------------


def test_rate_limit_error_is_also_tool_rate_limit_error():
    from app.tools.base import ToolRateLimitError

    assert issubclass(ReverseDnsRateLimitError, ToolRateLimitError)
    assert issubclass(ReverseDnsRateLimitError, ReverseDnsScanError)


def test_no_data_error_is_also_tool_no_data_error():
    from app.tools.base import ToolNoDataError

    assert issubclass(ReverseDnsNoDataError, ToolNoDataError)
    assert issubclass(ReverseDnsNoDataError, ReverseDnsScanError)
