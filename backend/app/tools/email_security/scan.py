import dns.exception
import dns.resolver

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim", "mail"]


class EmailSecurityScanError(ToolScanError):
    """Raised when an email-security DNS lookup can't be completed."""


class EmailSecurityRateLimitError(EmailSecurityScanError, ToolRateLimitError):
    """Raised when the resolver is throttled — safe to retry."""


class EmailSecurityNoDataError(EmailSecurityScanError, ToolNoDataError):
    """Raised when the domain itself doesn't exist — not a failure."""


def run(asset_value: str) -> dict:
    """
    Check a domain's email-authentication posture: SPF, DMARC, and a
    best-effort DKIM selector probe.

    Unlike WHOIS/Shodan, an *absent* record here is itself the
    security-relevant signal (no DMARC means the domain is easier to
    spoof) -- so this only raises EmailSecurityNoDataError when the
    domain itself doesn't exist (NXDOMAIN at the apex). A domain that
    exists but has none of SPF/DMARC/DKIM still returns normally, so
    `parse()` can turn each gap into its own finding.
    """
    domain = asset_value.strip().lower().rstrip(".")

    try:
        spf_records = _txt_lookup(domain)
    except dns.resolver.NXDOMAIN as e:
        raise EmailSecurityNoDataError(f"Domain '{domain}' does not exist") from e
    except dns.resolver.Timeout as e:
        raise EmailSecurityRateLimitError(f"DNS resolver timeout for {domain}: {e}") from e
    except dns.exception.DNSException as e:
        raise EmailSecurityScanError(f"SPF lookup failed for {domain}: {e}") from e

    spf_record = _first_matching(spf_records, "v=spf1")

    try:
        dmarc_records = _txt_lookup(f"_dmarc.{domain}")
        dmarc_record = _first_matching(dmarc_records, "v=DMARC1")
    except dns.resolver.Timeout as e:
        raise EmailSecurityRateLimitError(f"DNS resolver timeout for _dmarc.{domain}: {e}") from e
    except dns.exception.DNSException:
        dmarc_record = None

    found_dkim_selectors = [
        selector for selector in _DKIM_SELECTORS if _has_dkim_record(domain, selector)
    ]

    return {
        "domain": domain,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "dkim_selectors_checked": _DKIM_SELECTORS,
        "dkim_selectors_found": found_dkim_selectors,
    }


def _has_dkim_record(domain: str, selector: str) -> bool:
    try:
        records = _txt_lookup(f"{selector}._domainkey.{domain}")
    except dns.exception.DNSException:
        return False
    return any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records)


def _txt_lookup(name: str, rtype: str = "TXT") -> list[str]:
    """NoAnswer -> no such record, not an error (empty list). NXDOMAIN is
    intentionally NOT caught here -- callers need to decide whether a
    non-existent domain is fatal (apex SPF lookup) or just means 'no
    record' (DKIM selector probe)."""
    try:
        answer = dns.resolver.resolve(name, rtype)
    except dns.resolver.NoAnswer:
        return []
    return [str(rdata).strip('"') for rdata in answer]


def _first_matching(records: list[str], prefix: str) -> str | None:
    for record in records:
        if record.lower().startswith(prefix.lower()):
            return record
    return None
