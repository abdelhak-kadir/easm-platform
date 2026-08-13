from unittest.mock import MagicMock, patch

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


def _mock_resolver(results: list) -> MagicMock:
    """Build a resolver mock whose resolve() plays back *results* (answers
    or exceptions) across consecutive calls — one per resolver attempt."""
    resolver = MagicMock()
    resolver.resolve.side_effect = results
    return resolver


# ---------------------------------------------------------------------
# run() -- success paths
# ---------------------------------------------------------------------


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_returns_hostname_for_valid_ip(mock_resolver_cls):
    mock_resolver_cls.return_value = _mock_resolver([[_mock_rdata("mail.example.com.")]])

    result = run("93.184.216.34")

    assert result["ip"] == "93.184.216.34"
    assert result["hostnames"] == ["mail.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_returns_multiple_hostnames_in_order(mock_resolver_cls):
    mock_resolver_cls.return_value = _mock_resolver(
        [[_mock_rdata("mail.example.com."), _mock_rdata("web.example.com.")]]
    )

    result = run("93.184.216.34")

    assert result["hostnames"] == ["mail.example.com", "web.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_ptr_query_matches_reverse_address_and_has_no_trailing_dot(mock_resolver_cls):
    mock_resolver_cls.return_value = _mock_resolver([[_mock_rdata("mail.example.com.")]])

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
# run() -- DNS error mapping (resolver fallback chain)
# ---------------------------------------------------------------------


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_raises_no_data_error_on_nxdomain(mock_resolver_cls):
    """NXDOMAIN is authoritative — no fallback resolver is consulted."""
    mock_resolver_cls.return_value = _mock_resolver([dns.resolver.NXDOMAIN()])
    with pytest.raises(ReverseDnsNoDataError, match="No PTR record"):
        run("93.184.216.34")


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_raises_no_data_error_on_no_answer(mock_resolver_cls):
    mock_resolver_cls.return_value = _mock_resolver([dns.resolver.NoAnswer()])
    with pytest.raises(ReverseDnsNoDataError, match="No PTR record"):
        run("93.184.216.34")


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_falls_back_to_public_resolvers_after_servfail(mock_resolver_cls):
    """Docker DNS answers SERVFAIL → a public fallback resolves fine."""
    resolver = _mock_resolver([dns.resolver.NoNameservers(), [_mock_rdata("web.example.com.")]])
    mock_resolver_cls.return_value = resolver

    result = run("93.184.216.34")

    assert result["hostnames"] == ["web.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_falls_back_to_public_resolvers_after_timeout(mock_resolver_cls):
    resolver = _mock_resolver(
        [dns.resolver.Timeout(), dns.resolver.Timeout(), [_mock_rdata("db.example.com.")]]
    )
    mock_resolver_cls.return_value = resolver

    result = run("93.184.216.34")

    assert result["hostnames"] == ["db.example.com"]


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_raises_no_data_when_all_resolvers_servfail(mock_resolver_cls):
    """Every resolver SERVFAILs (broken/lame reverse zone) → clean no-data,
    not a scan failure — that's a property of the target's DNS."""
    mock_resolver_cls.return_value = _mock_resolver([dns.resolver.NoNameservers()] * 4)
    with pytest.raises(ReverseDnsNoDataError, match="No PTR record resolvable"):
        run("93.184.216.34")


@patch("app.tools.reverse_dns.scan.dns.resolver.Resolver")
def test_run_raises_rate_limit_when_all_resolvers_timeout(mock_resolver_cls):
    mock_resolver_cls.return_value = _mock_resolver([dns.resolver.Timeout()] * 4)
    with pytest.raises(ReverseDnsRateLimitError, match="timed out"):
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
