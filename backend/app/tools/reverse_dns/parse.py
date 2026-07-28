from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw reverse-DNS response into Finding-ready dicts."""
    hostnames = raw_data.get("hostnames") or []
    if not hostnames:
        return []

    primary = hostnames[0]
    return [
        {
            "finding_type": "reverse_dns",
            "title": f"Reverse DNS: {raw_data.get('ip')} → {primary}",
            "severity": Severity.INFO,
            "data": {
                "ip": raw_data.get("ip"),
                "hostnames": hostnames,
            },
        }
    ]
