import re

from app.models import Severity

# vulners.nse output lines look like:
#   CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
_VULNERS_LINE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)\s+(https?://\S+)")


def parse(raw_data: dict) -> list[dict]:
    """Turn an nmap scan dict into Finding-ready dicts.

    Produces one ``host_info`` finding (IP, hostnames, OS, port list),
    one ``open_port`` finding per detected service (enriched with CPE,
    HTTP title and TLS cert CN when the NSE scripts saw them), and one
    ``vulnerability`` finding per CVE reported by the vulners NSE script.

    When a service carries both a ``product`` and ``version`` and the
    vulners script returned nothing for it, the Shodan CVEDB is queried
    (best-effort, cached) as a fallback.
    """
    findings: list[dict] = []

    ip = raw_data.get("ip")
    if ip:
        findings.append(_parse_host_info(raw_data))

    for port_info in raw_data.get("ports") or []:
        findings.append(_parse_port(port_info))

    # ── CVE correlation: vulners script first, Shodan CVEDB fallback ──
    vulners_seen: set[str] = set()
    for output in (raw_data.get("host_scripts") or {}).values():
        for cve in _parse_vulners_output(output):
            if cve["cve_id"] in vulners_seen:
                continue
            vulners_seen.add(cve["cve_id"])
            findings.append(_vuln_finding(cve))

    for port_info in raw_data.get("ports") or []:
        product = port_info.get("product") or ""
        version = port_info.get("version") or ""
        if product and version:
            findings.extend(_correlate_cves(product, version))

    return findings


def _parse_vulners_output(output: str) -> list[dict]:
    """Extract CVE entries from a vulners.nse script output block."""
    cves: list[dict] = []
    for line in output.splitlines():
        match = _VULNERS_LINE_RE.search(line.strip())
        if match:
            cves.append(
                {
                    "cve_id": match.group(1),
                    "cvss": float(match.group(2)),
                    "url": match.group(3),
                }
            )
    return cves


def _vuln_finding(cve: dict) -> dict:
    return {
        "finding_type": "vulnerability",
        "title": cve["cve_id"],
        "severity": _severity_from_cvss(cve["cvss"]),
        "data": {
            "cvss": cve["cvss"],
            "summary": f"Vuln détectée par nmap (vulners) : {cve['url']}",
        },
    }


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
    os_accuracy = result.get("os_accuracy")
    ports = sorted(p["port"] for p in (result.get("ports") or []))

    os_display = os_name
    if os_name and os_accuracy:
        os_display = f"{os_name} (précision {os_accuracy}%)"

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
            "os": os_display,
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

    scripts = port_info.get("scripts") or {}

    http_title = _http_title(scripts)
    # ssl-cert: "Subject: commonName=foo, ..."
    ssl_cert_cn = _script_field(scripts, "ssl-cert", r"Subject:.*?commonName=([^,\s]+)")

    data: dict = {
        "port": port,
        "transport": protocol,
        "product": product or service,
        "version": version,
        "banner": banner,
    }
    if port_info.get("cpe"):
        data["cpe"] = port_info["cpe"]
    if http_title:
        data["http_title"] = http_title
    if ssl_cert_cn:
        data["ssl_cert_cn"] = ssl_cert_cn

    return {
        "finding_type": "open_port",
        "title": title,
        "severity": Severity.INFO,
        "data": data,
    }


def _script_field(scripts: dict[str, str], script_id: str, pattern: str) -> str | None:
    """Extract the first capture group of *pattern* from a script's output."""
    output = scripts.get(script_id)
    if not output:
        return None
    match = re.search(pattern, output)
    return match.group(1).strip() if match else None


def _http_title(scripts: dict[str, str]) -> str | None:
    """Page title from the http-title script output.

    Output shapes encountered in the wild:
    - ``Title: Example Domain``
    - ``Site doesn't have a title (text/html).``
    - ``400 The plain HTTP request was sent to HTTPS port`` (TLS port
      probed with plain HTTP — still tells us the port expects TLS)
    """
    output = scripts.get("http-title")
    if not output:
        return None

    title_match = re.search(r"Title:\s*(.+)", output)
    if title_match:
        return title_match.group(1).strip()

    no_title_match = re.search(r"doesn't have a title\s*(?:\(([^)]+)\))?", output)
    if no_title_match:
        content_type = no_title_match.group(1)
        if content_type:
            return f"pas de titre ({content_type})"
        return "pas de titre"

    first_line = output.splitlines()[0].strip()
    return first_line or None
