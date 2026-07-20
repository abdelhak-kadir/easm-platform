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
    findings = [_parse_open_port(service) for service in raw_data.get("data", [])]

    for cve_id, vuln_info in raw_data.get("vulns", {}).items():
        findings.append(_parse_vulnerability(cve_id, vuln_info))

    return findings


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
