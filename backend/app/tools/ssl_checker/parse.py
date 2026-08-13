"""Parse CrtMgr SSL certificate response into findings."""

from app.models import Severity

_EXPIRY_CRITICAL_DAYS = 0  # already expired
_EXPIRY_HIGH_DAYS = 14  # expiring within 2 weeks
_EXPIRY_MEDIUM_DAYS = 30  # expiring within 30 days


def parse(raw_data: dict) -> list[dict]:
    """Turn an SSL/TLS assessment response into Finding-ready dicts.

    Always emits one ``ssl_certificate`` finding with severity derived
    from the remaining validity period.  When SANs contain hostnames
    beyond the target domain itself, a ``discovered_assets`` finding
    is also emitted so the existing suggest-discovered UI can surface
    newly found subdomains for human acceptance.

    When the live TLS probe (``tls_scan`` key) is present, each weak
    configuration item — old TLS versions, weak ciphers, CRIME
    compression, Heartbleed, POODLE — becomes a ``vulnerability``
    finding with an indicative CVSS.
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

    findings.extend(_parse_tls_findings(raw_data.get("tls_scan")))

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
            "key_size": sanitize_key_size(raw_data.get("key_size")),
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


# ── key_size sanitization ──────────────────────────────────────────────

# The CrtMgr API occasionally leaks a Python object repr into its
# ``key_size`` field for EC certificates (e.g. "SECP256R1 <cryptography.
# hazmat... object at 0x7f...>"). Map the curve name back to its real
# bit size so the frontend renders "EC 256 bits" instead of the repr.
_CURVE_BIT_SIZES: dict[str, int] = {
    "SECP256R1": 256,
    "SECP256K1": 256,
    "SECP384R1": 384,
    "SECP521R1": 521,
    "X25519": 253,
    "ED25519": 253,
    "X448": 448,
    "ED448": 448,
}


def sanitize_key_size(key_size) -> int | str | None:
    """Return a display-safe key size for a raw CrtMgr ``key_size`` value."""
    if key_size is None or not isinstance(key_size, str):
        return key_size
    if "object at 0x" in key_size:
        curve = key_size.split()[0]
        return _CURVE_BIT_SIZES.get(curve, curve)
    return key_size


# ── TLS probe findings ─────────────────────────────────────────────────


# ssl-enum-ciphers warning text → (severity, indicative CVSS). First
# keyword match wins; anything unmatched is LOW.
_WARNING_RULES: list[tuple[str, Severity, float]] = [
    ("RC4", Severity.HIGH, 8.1),
    ("EXPORT", Severity.HIGH, 7.4),
    ("SWEET32", Severity.MEDIUM, 6.5),
    ("64-bit block cipher", Severity.MEDIUM, 6.5),
    ("DES", Severity.MEDIUM, 6.5),
    ("weak key exchange", Severity.MEDIUM, 6.5),
    ("512-bit", Severity.MEDIUM, 6.5),
    ("no perfect forward secrecy", Severity.LOW, 4.0),
    ("forward secrecy", Severity.LOW, 4.0),
    ("CBC", Severity.LOW, 3.7),
]

_TLS_VERSION_RULES: dict[str, tuple[Severity, float]] = {
    "TLSv1.0": (Severity.MEDIUM, 6.5),
    "TLSv1.1": (Severity.LOW, 3.7),
}


def _parse_tls_findings(tls_scan: dict | None) -> list[dict]:
    """Turn the nmap TLS probe result into vulnerability findings."""
    if not tls_scan:
        return []

    findings: list[dict] = []
    for port_info in tls_scan.get("ports") or []:
        port = port_info.get("port")
        findings.extend(_parse_tls_port(port_info, port))
    return findings


def _parse_tls_port(port_info: dict, port: int) -> list[dict]:
    findings: list[dict] = []

    # Old TLS versions still accepted
    for version in port_info.get("tls_versions") or []:
        if version in _TLS_VERSION_RULES:
            severity, cvss = _TLS_VERSION_RULES[version]
            findings.append(
                _vuln(
                    port,
                    f"{version} est toujours accepté sur le port {port} — "
                    "protocole obsolète, à désactiver",
                    severity,
                    cvss,
                )
            )

    # ssl-enum-ciphers warnings
    for warning in port_info.get("warnings") or []:
        severity, cvss = _warning_severity(warning)
        findings.append(_vuln(port, f"TLS (port {port}): {warning}", severity, cvss))

    # CRIME: compression enabled
    compressors = port_info.get("compressors") or []
    if any("NULL" not in c for c in compressors):
        findings.append(
            _vuln(
                port,
                f"Compression TLS activée sur le port {port} (risque CRIME)",
                Severity.MEDIUM,
                6.5,
            )
        )

    # Heartbleed / POODLE / DROWN / CCS / Ticketbleed script states
    state_rules: list[tuple[str, str, Severity, float]] = [
        ("heartbleed", "Heartbleed", Severity.CRITICAL, 9.4),
        ("poodle", "POODLE", Severity.HIGH, 8.1),
        ("sslv2_drown", "DROWN (SSLv2)", Severity.HIGH, 7.4),
        ("ccs_injection", "CCS Injection", Severity.HIGH, 7.4),
        ("ticketbleed", "Ticketbleed", Severity.MEDIUM, 5.3),
    ]
    for field, name, severity, cvss in state_rules:
        if port_info.get(field) == "VULNERABLE":
            findings.append(
                _vuln(port, f"{name}: serveur vulnérable sur le port {port}", severity, cvss)
            )

    return findings


def _warning_severity(warning: str) -> tuple[Severity, float]:
    for keyword, severity, cvss in _WARNING_RULES:
        if keyword.lower() in warning.lower():
            return severity, cvss
    return Severity.LOW, 3.7


def _vuln(port: int, summary: str, severity: Severity, cvss: float) -> dict:
    return {
        "finding_type": "vulnerability",
        "title": summary.split(" — ")[0][:255],
        "severity": severity,
        "data": {
            "cvss": cvss,
            "summary": summary,
            "port": port,
        },
    }
