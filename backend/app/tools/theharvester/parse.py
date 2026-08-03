from app.models import Severity

_CATEGORIES = [
    ("emails", "email"),
    ("hosts", "host"),
    ("ips", "IP"),
    ("urls", "URL"),
]


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw theHarvester response into Finding-ready dicts.

    One finding per non-empty category (emails, hosts, IPs, URLs).
    All are ``severity: INFO`` — passive OSINT results are neutral
    discoveries, not weaknesses.
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    sources_used = raw_data.get("sources_used") or []

    findings: list[dict] = []
    for key, label in _CATEGORIES:
        items: list = raw_data.get(key) or []
        if items:
            findings.append(
                {
                    "finding_type": "discovered_assets",
                    "title": f"{len(items)} {label}(s) trouvé(s) pour {domain}",
                    "severity": Severity.INFO,
                    "data": {
                        "category": key,
                        "domain": domain,
                        "items": sorted(items),
                        "sources_used": sources_used,
                    },
                }
            )

    return findings
