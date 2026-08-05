from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a passive nmap list-scan dict into a list of Finding-ready dicts.

    For ``-sL`` (passive list scan), nmap only provides hostnames from
    DNS PTR resolution — no port or OS data. Produces a single
    ``host_info`` finding per IP scanned.
    """
    findings: list[dict] = []

    ip = raw_data.get("ip")
    if ip:
        findings.append(_parse_host_info(raw_data))

    return findings


def _parse_host_info(result: dict) -> dict:
    ip = result.get("ip")
    hostnames = result.get("hostnames") or []

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
            "os": None,
            "tags": [],
            "ports": [],
            "last_update": None,
        },
    }
