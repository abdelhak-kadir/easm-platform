from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn PublicWWW output into Finding-ready dicts.

    Produces:

    1. ``host_info`` — pages referencing the domain + technology stack detected
    2. ``discovered_assets`` — subdomains found in page URLs/snippets
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    hosts: list = raw_data.get("hosts") or []
    ips: list = raw_data.get("ips") or []
    urls: list = raw_data.get("urls") or []
    tech: dict = raw_data.get("technologies") or {}
    total_hits = raw_data.get("total_hits", 0)
    pages_found = raw_data.get("pages_found", len(urls))
    findings: list[dict] = []

    # ── host_info — source-code reference summary ──────────────────
    host_data: dict = {
        "source": "publicwww",
        "total_references": total_hits,
        "pages_found": pages_found,
    }
    if tech:
        host_data["technologies_detected"] = [
            f"{name} ({count} occurrences)" for name, count in tech.items()
        ]

    findings.append(
        {
            "finding_type": "host_info",
            "title": f"PublicWWW: {pages_found} page(s) référencent {domain}",
            "severity": Severity.INFO,
            "data": host_data,
        }
    )

    # ── discovered_assets — hosts found ────────────────────────────
    items = hosts + [f"IP:{ip}" for ip in ips]
    if items:
        findings.append(
            {
                "finding_type": "discovered_assets",
                "title": f"{len(items)} actif(s) découvert(s) via PublicWWW pour {domain}",
                "severity": Severity.INFO,
                "data": {
                    "category": "hosts",
                    "domain": domain,
                    "items": sorted(items),
                    "sources_used": raw_data.get("sources_used") or [],
                },
            }
        )

    return findings
