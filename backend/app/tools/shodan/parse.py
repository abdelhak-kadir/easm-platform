from app.models import Severity

# Shodan doesn't give a severity for open ports directly, so we treat them
# as informational and let vulnerabilities carry the real risk signal.
_CVSS_THRESHOLDS = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw Shodan host response into a list of Finding-ready dicts."""
    findings = []

    if raw_data.get("ip_str"):
        findings.append(_parse_host_info(raw_data))

    findings.extend(_parse_open_port(service) for service in raw_data.get("data", []))

    for cve_id, vuln_info in raw_data.get("vulns", {}).items():
        findings.append(_parse_vulnerability(cve_id, vuln_info))

    return findings


def _parse_host_info(raw_data: dict) -> dict:
    """Everything Shodan knows about the host itself, as a single finding.

    Kept under one generic finding_type ("host_info") rather than a
    Shodan-specific shape, so a results viewer can render it without
    knowing which tool produced it -- other tools (whois, censys) can
    emit the same finding_type later with whatever subset of fields
    they have.
    """
    ip = raw_data.get("ip_str")
    return {
        "finding_type": "host_info",
        "title": f"Host information for {ip}",
        "severity": Severity.INFO,
        "data": {
            "ip": ip,
            "org": raw_data.get("org"),
            "isp": raw_data.get("isp"),
            "asn": raw_data.get("asn"),
            "hostnames": raw_data.get("hostnames", []),
            "domains": raw_data.get("domains", []),
            "country_name": raw_data.get("country_name"),
            "country_code": raw_data.get("country_code"),
            "city": raw_data.get("city"),
            "region_code": raw_data.get("region_code"),
            "latitude": raw_data.get("latitude"),
            "longitude": raw_data.get("longitude"),
            "os": raw_data.get("os"),
            "tags": raw_data.get("tags", []),
            "ports": raw_data.get("ports", []),
            "last_update": raw_data.get("last_update"),
        },
    }


def _parse_open_port(service: dict) -> dict:
    port = service.get("port")
    transport = service.get("transport", "tcp")
    product = service.get("product", "")
    title = f"Open port {port}/{transport}" + (f" ({product})" if product else "")

    return {
        "finding_type": "open_port",
        "title": title,
        "severity": Severity.INFO,
        "data": {
            "port": port,
            "transport": transport,
            "product": product,
            "version": service.get("version", ""),
            "banner": (service.get("data") or "")[:500],
        },
    }


def _parse_vulnerability(cve_id: str, vuln_info: dict) -> dict:
    cvss = vuln_info.get("cvss") or 0.0
    return {
        "finding_type": "vulnerability",
        "title": cve_id,
        "severity": _severity_from_cvss(cvss),
        "data": {
            "cvss": cvss,
            "summary": vuln_info.get("summary", ""),
        },
    }


def _severity_from_cvss(cvss: float) -> Severity:
    for threshold, severity in _CVSS_THRESHOLDS:
        if cvss >= threshold:
            return severity
    return Severity.INFO
