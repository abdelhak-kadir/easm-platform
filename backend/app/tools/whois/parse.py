from datetime import UTC, datetime

from app.models import Severity
from app.tools.whois._util import to_aware

_EXPIRY_WARNING_DAYS = 30


def parse(raw_data: dict) -> list[dict]:
    """Turn a JSON-safe WHOIS response (see scan.run) into Finding-ready dicts."""
    findings = []

    if raw_data.get("domain_name"):
        findings.append(_parse_registration(raw_data))

    expiry_finding = _parse_expiry(raw_data)
    if expiry_finding:
        findings.append(expiry_finding)

    return findings


def _parse_registration(raw_data: dict) -> dict:
    domain = _first(raw_data.get("domain_name"))
    return {
        "finding_type": "domain_registration",
        "title": f"Domain registration for {domain}",
        "severity": Severity.INFO,
        "data": {
            "domain": domain,
            "registrar": _first(raw_data.get("registrar")),
            "whois_server": raw_data.get("whois_server"),
            "creation_date": _first(raw_data.get("creation_date")),
            "updated_date": _first(raw_data.get("updated_date")),
            "expiration_date": _first(raw_data.get("expiration_date")),
            "name_servers": _as_list(raw_data.get("name_servers")),
            "status": _as_list(raw_data.get("status")),
            "emails": _as_list(raw_data.get("emails")),
            "dnssec": raw_data.get("dnssec"),
            "org": raw_data.get("org"),
            "country": raw_data.get("country"),
        },
    }


def _parse_expiry(raw_data: dict) -> dict | None:
    """Flag domains that have already expired or are expiring soon.

    WHOIS doesn't carry a severity of its own the way Shodan's CVSS-scored
    vulns do, so this derives one from how close the domain is to
    lapsing -- an expired or soon-to-expire domain is a real
    attack-surface risk (squatting, hijack) worth surfacing as its own
    finding.
    """
    expiration_raw = _first(raw_data.get("expiration_date"))
    if not expiration_raw:
        return None

    expiration = to_aware(datetime.fromisoformat(expiration_raw))
    days_remaining = (expiration - datetime.now(UTC)).days

    if days_remaining < 0:
        severity = Severity.HIGH
        title = f"Domain expired {abs(days_remaining)} day(s) ago"
    elif days_remaining <= _EXPIRY_WARNING_DAYS:
        severity = Severity.MEDIUM
        title = f"Domain expires in {days_remaining} day(s)"
    else:
        return None

    return {
        "finding_type": "domain_expiry",
        "title": title,
        "severity": severity,
        "data": {
            "expiration_date": expiration_raw,
            "days_remaining": days_remaining,
        },
    }


def _first(value):
    """python-whois returns either a scalar or a list depending on the
    registrar's response format -- normalize to a single value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
