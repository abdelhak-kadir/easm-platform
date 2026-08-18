"""IP blacklist / reputation check: DNSBL (RBL) lookups + Tor exit + AbuseIPDB.

Checks an IP against the major free realtime blacklists (Spamhaus ZEN/XBL,
SpamCop, Barracuda, DroneBL, AbuseAT), whether the IP is currently a Tor
exit node (official Onionoo API), and — when ``ABUSEIPDB_API_KEY`` is set
in the environment — the AbuseIPDB abuse score.

RBL mechanics: blacklists publish their data as DNS zones. Querying
``<reversed-ip>.<zone>`` for an A record answers ``127.0.0.x`` when the IP
is listed and NXDOMAIN (no answer) when it isn't. No answer is the
expected happy path — it is *not* an error. Only a DNS outage across
every zone is a retryable failure.
"""

import ipaddress
import os

import dns.resolver
import requests

from app.tools.base import ToolRateLimitError, ToolScanError

# Public resolvers tried after the system resolver (same reasoning as
# reverse_dns: Docker's embedded DNS can SERVFAIL queries that upstream
# resolvers answer fine).
_FALLBACK_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
_RESOLVER_TIMEOUT_S = 5
_RESOLVER_LIFETIME_S = 10

# (label, zone) pairs — the label is used verbatim in findings.
_RBL_ZONES = (
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Spamhaus XBL", "xbl.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("DroneBL", "dnsbl.dronebl.org"),
    ("AbuseAT", "dbl.abuseat.org"),
)

_TOR_EXIT_API = "https://onionoo.torproject.org/details?ip={ip}"
_ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
_ABUSEIPDB_MAX_AGE_DAYS = 90


class IpBlacklistScanError(ToolScanError):
    """Raised when an IP blacklist check can't be completed."""


class IpBlacklistRateLimitError(IpBlacklistScanError, ToolRateLimitError):
    """Raised when every blacklist DNS query fails — transient, safe to retry."""


def run(asset_value: str) -> dict:
    """Check one IP against RBLs, Tor exit nodes, and AbuseIPDB.

    Only applies to IP assets — see registry.py's asset_types.
    Returns a JSON-safe dict; raw_data persisted straight into
    ScanResult.raw_data (JSONB).
    """
    try:
        ip_obj = ipaddress.ip_address(asset_value)
    except ValueError as e:
        raise IpBlacklistScanError(f"'{asset_value}' is not a valid IP address") from e

    # RBL DNS zones are IPv4-only in practice; Onionoo/AbuseIPDB handle
    # both, so IPv6 targets just skip the DNS part.
    if ip_obj.version == 6:
        rbl_results: list[dict] = []
    else:
        rbl_results = [_check_rbl(asset_value, label, zone) for label, zone in _RBL_ZONES]

    listed = [r for r in rbl_results if r["listed"]]
    errors = [r for r in rbl_results if r.get("error")]
    if rbl_results and not listed and len(errors) == len(rbl_results):
        detail = "; ".join(r["error"] for r in errors)
        raise IpBlacklistRateLimitError(
            f"All blacklist DNS queries failed for {asset_value}: {detail}"
        )

    return {
        "ip": asset_value,
        "rbl": rbl_results,
        "tor_exit": _check_tor_exit(asset_value),
        "abuseipdb": _check_abuseipdb(asset_value),
    }


def _make_resolver(nameserver: str | None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = _RESOLVER_TIMEOUT_S
    resolver.lifetime = _RESOLVER_LIFETIME_S
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def _reversed_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_rbl(ip: str, label: str, zone: str) -> dict:
    """Query one blacklist zone for the IP.

    NXDOMAIN / NoAnswer are terminal and mean "not listed" — re-asking
    another resolver won't change that. Timeouts / SERVFAIL move on to
    the next resolver; if every resolver fails the zone is recorded as
    an error (never as "not listed", so a partial outage can't produce a
    false clean bill of health).
    """
    query_name = f"{_reversed_ip(ip)}.{zone}"
    for nameserver in (None, *_FALLBACK_RESOLVERS):
        try:
            answer = _make_resolver(nameserver).resolve(query_name, "A")
            return {
                "zone": label,
                "listed": True,
                "code": str(answer[0]),
                "query": query_name,
                "reason": _listing_reason(query_name),
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"zone": label, "listed": False, "query": query_name}
        except (dns.resolver.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
            continue  # try the next resolver
    return {"zone": label, "listed": False, "error": f"unresolvable: {query_name}"}


def _listing_reason(query_name: str) -> str:
    """Best-effort TXT query for the listing reason — Spamhaus and others
    publish a human-readable explanation next to the 127.0.0.x code."""
    try:
        answer = _make_resolver(None).resolve(query_name, "TXT")
        return " ".join("".join(rdata.strings) for rdata in answer)
    except Exception:
        return ""


def _check_tor_exit(ip: str) -> bool:
    """Best-effort Tor exit-node check via the official Onionoo API.

    Never raises: an unreachable Tor API means "not an exit node" for
    this run, not a scan failure.
    """
    try:
        resp = requests.get(_TOR_EXIT_API.format(ip=ip), timeout=8)
        resp.raise_for_status()
        relays = resp.json().get("relays", [])
        return any("Exit" in relay.get("flags", []) for relay in relays)
    except requests.RequestException:
        return False


def _check_abuseipdb(ip: str) -> dict | None:
    """Best-effort AbuseIPDB check — requires ``ABUSEIPDB_API_KEY``.

    Returns None (skipped) when no key is configured, and an error dict
    instead of raising on API failures — a missing/invalid key or quota
    exhaustion must never fail the scan when the RBL part succeeded.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
    try:
        resp = requests.get(
            _ABUSEIPDB_API,
            params={"ipAddress": ip, "maxAgeInDays": str(_ABUSEIPDB_MAX_AGE_DAYS)},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 401:
            return {"error": "clé API invalide (401)"}
        if resp.status_code == 429:
            return {"error": "quota API dépassé (429)"}
        resp.raise_for_status()
        data = resp.json().get("data") or {}
        return {
            "score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": bool(data.get("isWhitelisted")),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
        }
    except requests.RequestException as e:
        return {"error": f"requête échouée : {e}"}
