from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn raw subfinder output into Finding-ready dicts.

    Produces a single ``discovered_assets`` finding with ``category: "hosts"``
    — same schema as theHarvester, so the existing suggest-discovered UI and
    acceptance endpoints work unchanged.
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    hosts: list = raw_data.get("hosts") or []
    if not hosts:
        return []

    return [
        {
            "finding_type": "discovered_assets",
            "title": f"{len(hosts)} hôte(s) trouvé(s) pour {domain}",
            "severity": Severity.INFO,
            "data": {
                "category": "hosts",
                "domain": domain,
                "items": sorted(hosts),
                "sources_used": raw_data.get("sources_used") or [],
            },
        }
    ]
