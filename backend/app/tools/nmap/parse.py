from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn an nmap scan dict into Finding-ready dicts.

    Produces one ``host_info`` finding (IP, hostnames, OS, port list)
    plus one ``open_port`` finding per detected service.

    When a service carries both a ``product`` and ``version``, the
    Shodan CVEDB is queried (best-effort, cached) and any matched CVEs
    are emitted as ``vulnerability`` findings with CVSS-derived severity.
    """
    findings: list[dict] = []

    ip = raw_data.get("ip")
    if ip:
        findings.append(_parse_host_info(raw_data))

    for port_info in raw_data.get("ports") or []:
        findings.append(_parse_port(port_info))

    # ── CVE correlation (best-effort, cached) ──────────────────────
    for port_info in raw_data.get("ports") or []:
        product = port_info.get("product") or ""
        version = port_info.get("version") or ""
        if product and version:
            findings.extend(_correlate_cves(product, version))

    return findings


def _correlate_cves(product: str, version: str) -> list[dict]:
    """Best-effort CVE lookup for a detected service version.

    Failures are silent — the port finding still exists; CVEs are a bonus.
    """
    try:
        from app.lib.cve import lookup_cves
    except ImportError:  # pragma: no cover
        return []

    cves = lookup_cves(product, version)
    findings: list[dict] = []
    for cve in cves:
        findings.append(
            {
                "finding_type": "vulnerability",
                "title": cve["cve_id"],
                "severity": _severity_from_cvss(cve.get("cvss", 0)),
                "data": {
                    "cvss": cve.get("cvss", 0),
                    "summary": cve.get("summary", ""),
                },
            }
        )
    return findings


def _severity_from_cvss(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss >= 0.1:
        return Severity.LOW
    return Severity.INFO


def _parse_host_info(result: dict) -> dict:
    ip = result.get("ip")
    hostnames = result.get("hostnames") or []
    os_name = result.get("os")
    ports = sorted(p["port"] for p in (result.get("ports") or []))

    return {
        "finding_type": "host_info",
        "title": f"Host information for {ip}",
        "severity": Severity.INFO,
        "data": {
            "ip": ip,
            "org": None,
            "isp": None,
            "asn": None,
            "hostnames": hostnames,
            "domains": [],
            "country_name": None,
            "country_code": None,
            "city": None,
            "region_code": None,
            "latitude": None,
            "longitude": None,
            "os": os_name,
            "tags": [],
            "ports": ports,
            "last_update": None,
        },
    }


def _parse_port(port_info: dict) -> dict:
    port = port_info.get("port")
    protocol = (port_info.get("protocol") or "tcp").lower()
    product = port_info.get("product") or ""
    service = port_info.get("service") or ""
    version = port_info.get("version") or ""
    extrainfo = port_info.get("extrainfo") or ""

    label = product or service or f"port {port}"
    title = f"Open port {port}/{protocol}" + (f" ({label})" if label else "")

    parts = []
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    if extrainfo:
        parts.append(f"({extrainfo})")
    banner = " ".join(parts) if parts else ""

    return {
        "finding_type": "open_port",
        "title": title,
        "severity": Severity.INFO,
        "data": {
            "port": port,
            "transport": protocol,
            "product": product or service,
            "version": version,
            "banner": banner,
        },
    }
