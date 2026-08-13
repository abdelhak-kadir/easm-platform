"""Reverse DNS (PTR) lookup for IP assets.

Resolution strategy: system resolver first, then a chain of public
resolvers (Cloudflare, Google, Quad9). Docker's embedded DNS server
(127.0.0.11) frequently answers PTR queries with SERVFAIL even when the
record resolves fine upstream, so the fallback chain is essential inside
containers.

A PTR that *no* resolver can answer is a property of the target's DNS
infrastructure — many reverse zones are broken (lame delegation) or
simply empty. That maps to ``ReverseDnsNoDataError`` (a clean no-data
outcome), not a scan failure.
"""

import ipaddress

import dns.resolver
import dns.reversename

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

# Public resolvers tried after the system resolver fails.
_FALLBACK_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
_RESOLVER_TIMEOUT_S = 5
_RESOLVER_LIFETIME_S = 10


class ReverseDnsScanError(ToolScanError):
    """Raised when a reverse DNS lookup can't be completed."""


class ReverseDnsRateLimitError(ReverseDnsScanError, ToolRateLimitError):
    """Raised when the resolver is throttled — safe to retry."""


class ReverseDnsNoDataError(ReverseDnsScanError, ToolNoDataError):
    """Raised when there's no PTR record for the IP — not a failure."""


def _make_resolver(nameserver: str | None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = _RESOLVER_TIMEOUT_S
    resolver.lifetime = _RESOLVER_LIFETIME_S
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def _query_ptr(ip: str, query_name) -> list[str]:
    """Resolve the PTR record, trying the system resolver then each
    public fallback in turn.

    NXDOMAIN / NoAnswer are terminal: the reverse zone simply has no PTR
    for this address, and re-asking another resolver won't change that.
    Timeouts move on to the next resolver; when every resolver times out
    the outcome is retryable. When every resolver refuses (SERVFAIL —
    typically a broken/lame reverse delegation) it's a clean no-data
    outcome with the failures spelled out in the message.
    """
    failures: list[str] = []
    all_timed_out = True

    for nameserver in (None, *_FALLBACK_RESOLVERS):
        try:
            answer = _make_resolver(nameserver).resolve(query_name, "PTR")
            return [str(rdata.target).rstrip(".") for rdata in answer]
        except dns.resolver.NXDOMAIN:
            raise ReverseDnsNoDataError(f"No PTR record for {ip}") from None
        except dns.resolver.NoAnswer:
            raise ReverseDnsNoDataError(f"No PTR record for {ip}") from None
        except dns.resolver.Timeout:
            failures.append(f"{nameserver or 'system'}: timeout")
        except dns.resolver.NoNameservers as e:
            all_timed_out = False
            failures.append(f"{nameserver or 'system'}: {e}")
        except dns.exception.DNSException as e:
            all_timed_out = False
            failures.append(f"{nameserver or 'system'}: {e}")

    detail = "; ".join(failures)
    if all_timed_out:
        raise ReverseDnsRateLimitError(f"All PTR resolvers timed out for {ip}: {detail}") from None
    raise ReverseDnsNoDataError(
        f"No PTR record resolvable for {ip} (reverse zone broken or empty: {detail})"
    )


def run(asset_value: str) -> dict:
    """Resolve an IP to its PTR (reverse DNS) hostname.

    Only applies to IP assets — see registry.py's asset_types.
    Returns a JSON-safe dict; raw_data persisted straight into
    ScanResult.raw_data (JSONB).
    """
    try:
        ipaddress.ip_address(asset_value)
    except ValueError as e:
        raise ReverseDnsScanError(f"'{asset_value}' is not a valid IP address") from e

    query_name = dns.reversename.from_address(asset_value)
    hostnames = _query_ptr(asset_value, query_name)

    return {
        "ip": asset_value,
        "ptr_query": str(query_name).rstrip("."),
        "hostnames": hostnames,
    }
