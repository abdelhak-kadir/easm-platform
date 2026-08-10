"""Parse CrtMgr SSL certificate response into findings."""

from app.models import Severity

_EXPIRY_CRITICAL_DAYS = 0  # already expired
_EXPIRY_HIGH_DAYS = 14  # expiring within 2 weeks
_EXPIRY_MEDIUM_DAYS = 30  # expiring within 30 days


def parse(raw_data: dict) -> list[dict]:
    """Turn a CrtMgr SSL checker response into Finding-ready dicts.

    Always emits one ``ssl_certificate`` finding with severity derived
    from the remaining validity period.  When SANs contain hostnames
    beyond the target domain itself, a ``discovered_assets`` finding
    is also emitted so the existing suggest-discovered UI can surface
    newly found subdomains for human acceptance.
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    sans: list[str] = raw_data.get("sans") or []
    days_left = raw_data.get("days_left")

    findings = [_parse_certificate(raw_data, days_left)]

    # Emit discovered_assets for SANs that aren't the target domain itself
    new_hosts = _filter_new_hosts(sans, domain)
    if new_hosts:
        findings.append(
            {
                "finding_type": "discovered_assets",
                "title": f"{len(new_hosts)} hôte(s) trouvé(s) via certificat SSL de {domain}",
                "severity": Severity.INFO,
                "data": {
                    "category": "hosts",
                    "domain": domain,
                    "items": sorted(new_hosts),
                    "sources_used": ["crtmgr_ssl"],
                },
            }
        )

    return findings


def _parse_certificate(raw_data: dict, days_left: int | None) -> dict:
    domain = raw_data.get("domain", "")
    issuer = raw_data.get("issuer", "")
    expired = raw_data.get("expired", False)
    sans: list[str] = raw_data.get("sans") or []

    severity = _expiry_severity(days_left, expired)

    if expired:
        title = f"Certificat SSL expiré pour {domain}"
    elif days_left is not None and days_left <= _EXPIRY_HIGH_DAYS:
        title = f"Certificat SSL expire dans {days_left} jour(s) pour {domain}"
    elif days_left is not None and days_left <= _EXPIRY_MEDIUM_DAYS:
        title = f"Certificat SSL expire dans {days_left} jour(s) pour {domain}"
    else:
        title = f"Certificat SSL pour {domain} (valide, {days_left or '?'} jour(s))"

    return {
        "finding_type": "ssl_certificate",
        "title": title,
        "severity": severity,
        "data": {
            "domain": domain,
            "cn": raw_data.get("cn"),
            "issuer": issuer,
            "not_before": raw_data.get("not_before"),
            "not_after": raw_data.get("not_after"),
            "days_left": days_left,
            "expired": expired,
            "serial_hex": raw_data.get("serial_hex"),
            "fingerprint_sha256": raw_data.get("fingerprint_sha256"),
            "sans": sans,
            "key_type": raw_data.get("key_type"),
            "key_size": raw_data.get("key_size"),
            "signature_algorithm": raw_data.get("signature_algorithm"),
        },
    }


def _expiry_severity(days_left: int | None, expired: bool) -> Severity:
    if expired:
        return Severity.HIGH
    if days_left is not None and days_left <= _EXPIRY_CRITICAL_DAYS:
        return Severity.HIGH
    if days_left is not None and days_left <= _EXPIRY_HIGH_DAYS:
        return Severity.MEDIUM
    if days_left is not None and days_left <= _EXPIRY_MEDIUM_DAYS:
        return Severity.LOW
    return Severity.INFO


def _filter_new_hosts(sans: list[str], target_domain: str) -> list[str]:
    """Return SAN entries that are subdomains of *target_domain* and
    not the target itself (including the ``www`` variant)."""
    if not target_domain:
        return []
    new: list[str] = []
    for name in sans:
        name = name.strip().lower().rstrip(".")
        if not name:
            continue
        if name == target_domain:
            continue
        if name == f"www.{target_domain}":
            continue
        # Only keep names that belong to the target domain's namespace
        if name.endswith(f".{target_domain}") or name == target_domain:
            new.append(name)
    return new
