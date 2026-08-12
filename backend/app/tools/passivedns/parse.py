from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    if not raw_data:
        return []
    domain = raw_data.get("domain", "")
    hosts: list = raw_data.get("hosts") or []
    virtual: dict = raw_data.get("virtual_hosts") or {}
    cf_hosts: list = raw_data.get("cloudflare_hosts") or []
    sources_hit: list = raw_data.get("sources_hit") or []
    findings: list[dict] = []

    # ── host_info — virtual host + Cloudflare summary ──────────────
    host_data: dict = {
        "source": "passivedns",
        "sources_hit": sources_hit,
        "total_sources": len(sources_hit),
    }
    if virtual:
        host_data["virtual_host_groups"] = {ip: hosts for ip, hosts in virtual.items()}
        host_data["virtual_host_count"] = len(virtual)
    if cf_hosts:
        host_data["cloudflare_hosts"] = cf_hosts
        host_data["cloudflare_count"] = len(cf_hosts)

    findings.append(
        {
            "finding_type": "host_info",
            "title": (
                f"PassiveDNS: {len(hosts)} hôte(s) via {len(sources_hit)} source(s)"
                + (f" | {len(virtual)} IP(s) multi-hôtes" if virtual else "")
                + (f" | {len(cf_hosts)} Cloudflare" if cf_hosts else "")
            ),
            "severity": Severity.INFO,
            "data": host_data,
        }
    )

    # ── discovered_assets ──────────────────────────────────────────
    findings.append(
        {
            "finding_type": "discovered_assets",
            "title": f"{len(hosts)} hôte(s) via DNS passif pour {domain}",
            "severity": Severity.INFO,
            "data": {
                "category": "hosts",
                "domain": domain,
                "items": sorted(hosts),
                "sources_used": raw_data.get("sources_used") or [],
            },
        }
    )

    # ── Cloudflare warning ─────────────────────────────────────────
    if cf_hosts:
        findings.append(
            {
                "finding_type": "host_info",
                "title": f"{len(cf_hosts)} hôte(s) derrière Cloudflare pour {domain}",
                "severity": Severity.INFO,
                "data": {
                    "source": "passivedns",
                    "cloudflare_hosts": cf_hosts,
                    "note": (
                        "Cloudflare proxies hide the real origin server — "
                        "port scanning and direct IP analysis may be inaccurate"
                    ),
                },
            }
        )

    return findings
