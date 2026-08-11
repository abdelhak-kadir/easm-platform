from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    if not raw_data:
        return []
    domain = raw_data.get("domain", "")
    hosts: list = raw_data.get("hosts") or []
    if not hosts:
        return []
    return [
        {
            "finding_type": "discovered_assets",
            "title": f"{len(hosts)} domaine(s) dans le CSP de {domain}",
            "severity": Severity.INFO,
            "data": {
                "category": "hosts",
                "domain": domain,
                "items": sorted(hosts),
                "sources_used": raw_data.get("sources_used") or [],
            },
        }
    ]
