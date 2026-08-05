from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn an nmap scan dict into Finding-ready dicts.

    Produces one ``host_info`` finding (IP, hostnames, OS, port list)
    plus one ``open_port`` finding per detected service.
    """
    findings: list[dict] = []

    ip = raw_data.get("ip")
    if ip:
        findings.append(_parse_host_info(raw_data))

    for port_info in raw_data.get("ports") or []:
        findings.append(_parse_port(port_info))

    return findings


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
