from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
from app.tools.email_security.scan import (
    EmailSecurityNoDataError,
    EmailSecurityRateLimitError,
    EmailSecurityScanError,
    run,
)


def _txt_answer(*strings_per_record: str) -> list[MagicMock]:
    """Build a fake dns.resolver.resolve(..., 'TXT') return value --
    one rdata per record, each with a `.strings` tuple of byte chunks."""
    return [MagicMock(strings=(s.encode(),)) for s in strings_per_record]


# ---------------------------------------------------------------------
# run() -- SPF
# ---------------------------------------------------------------------


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_finds_spf_record(mock_resolve):
    def side_effect(name, rtype):
        if name == "example.com":
            return _txt_answer("v=spf1 include:_spf.example.com ~all")
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert result["spf_record"] == "v=spf1 include:_spf.example.com ~all"


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_returns_none_spf_when_no_matching_txt_record(mock_resolve):
    def side_effect(name, rtype):
        if name == "example.com":
            return _txt_answer("some-other-verification-record")
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert result["spf_record"] is None


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_returns_none_spf_when_no_answer(mock_resolve):
    def side_effect(name, rtype):
        if name == "example.com":
            raise dns.resolver.NoAnswer
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert result["spf_record"] is None


# ---------------------------------------------------------------------
# run() -- DMARC
# ---------------------------------------------------------------------


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_finds_dmarc_record(mock_resolve):
    def side_effect(name, rtype):
        if name == "_dmarc.example.com":
            return _txt_answer("v=DMARC1; p=reject; rua=mailto:d@example.com")
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert result["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:d@example.com"


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_returns_none_dmarc_when_subdomain_missing(mock_resolve):
    def side_effect(name, rtype):
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert result["dmarc_record"] is None


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_raises_rate_limit_error_on_dmarc_timeout(mock_resolve):
    def side_effect(name, rtype):
        if name == "example.com":
            raise dns.resolver.NoAnswer
        raise dns.resolver.Timeout

    mock_resolve.side_effect = side_effect

    with pytest.raises(EmailSecurityRateLimitError):
        run("example.com")


# ---------------------------------------------------------------------
# run() -- DKIM (best-effort selector probing)
# ---------------------------------------------------------------------


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_finds_dkim_selector(mock_resolve):
    def side_effect(name, rtype):
        if name == "default._domainkey.example.com":
            return _txt_answer("v=DKIM1; k=rsa; p=MIGfMA0GCSq...")
        raise dns.resolver.NXDOMAIN

    mock_resolve.side_effect = side_effect
    result = run("example.com")

    assert "default" in result["dkim_selectors_found"]


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_returns_empty_dkim_selectors_when_none_match(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NXDOMAIN
    result = run("example.com")

    assert result["dkim_selectors_found"] == []
    assert result["dkim_selectors_checked"]  # still reports what was probed


# ---------------------------------------------------------------------
# run() -- domain-level failures
# ---------------------------------------------------------------------


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_raises_no_data_error_when_domain_does_not_exist(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NXDOMAIN

    with pytest.raises(EmailSecurityNoDataError, match="does not exist"):
        run("no-such-domain.invalid")


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_raises_rate_limit_error_on_spf_timeout(mock_resolve):
    mock_resolve.side_effect = dns.resolver.Timeout

    with pytest.raises(EmailSecurityRateLimitError):
        run("example.com")


@patch("app.tools.email_security.scan.dns.resolver.resolve")
def test_run_raises_generic_scan_error_on_other_dns_exception(mock_resolve):
    mock_resolve.side_effect = dns.exception.DNSException("boom")

    with pytest.raises(EmailSecurityScanError, match="SPF lookup failed"):
        run("example.com")


# ---------------------------------------------------------------------
# error class hierarchy
# ---------------------------------------------------------------------


def test_rate_limit_error_is_also_tool_rate_limit_error():
    from app.tools.base import ToolRateLimitError

    assert issubclass(EmailSecurityRateLimitError, ToolRateLimitError)


def test_no_data_error_is_also_tool_no_data_error():
    from app.tools.base import ToolNoDataError

    assert issubclass(EmailSecurityNoDataError, ToolNoDataError)
