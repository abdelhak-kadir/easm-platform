import ipaddress

import dns.resolver
import dns.reversename

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError


class ReverseDnsScanError(ToolScanError):
    """Raised when a reverse DNS lookup can't be completed."""


class ReverseDnsRateLimitError(ReverseDnsScanError, ToolRateLimitError):
    """Raised when the resolver is throttled — safe to retry."""


class ReverseDnsNoDataError(ReverseDnsScanError, ToolNoDataError):
    """Raised when there's no PTR record for the IP — not a failure."""


def run(asset_value: str) -> dict:
    """
    Resolve an IP to its PTR (reverse DNS) hostname.

    Only applies to IP assets — see registry.py's asset_types.
    Returns a JSON-safe dict; raw_data persisted straight into
    ScanResult.raw_data (JSONB).
    """
    try:
        ipaddress.ip_address(asset_value)
    except ValueError as e:
        raise ReverseDnsScanError(f"'{asset_value}' is not a valid IP address") from e

    query_name = dns.reversename.from_address(asset_value)

    try:
        answer = dns.resolver.resolve(query_name, "PTR")
    except dns.resolver.NXDOMAIN:
        raise ReverseDnsNoDataError(f"No PTR record for {asset_value}") from None
    except dns.resolver.NoAnswer:
        raise ReverseDnsNoDataError(f"No PTR record for {asset_value}") from None
    except dns.resolver.Timeout as e:
        raise ReverseDnsRateLimitError(f"DNS resolver timeout for {asset_value}: {e}") from e
    except dns.exception.DNSException as e:
        raise ReverseDnsScanError(f"Reverse DNS lookup failed for {asset_value}: {e}") from e

    hostnames = [str(rdata.target).rstrip(".") for rdata in answer]

    return {
        "ip": asset_value,
        "ptr_query": str(query_name).rstrip("."),
        "hostnames": hostnames,
    }
