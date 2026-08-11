from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn DNS enumeration output into Finding-ready dicts.

    Produces up to two findings:

    1. ``host_info`` — DNS records summary (NS, MX, SOA)
    2. ``discovered_assets`` — subdomain hosts found via DNS enumeration
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    records: dict = raw_data.get("records") or {}
    ips: list = raw_data.get("ips") or []
    hosts: list = raw_data.get("hosts") or []
    findings: list[dict] = []

    # Build a concise DNS summary
    ns_list = [r.get("nameserver", "") for r in records.get("ns", [])]
    mx_list = [
        f"{r.get('exchange', '')} (pref={r.get('preference', '?')})" for r in records.get("mx", [])
    ]
    soa_mname = ""
    soa_rname = ""
    soa_recs = records.get("soa", [])
    if soa_recs:
        soa_mname = soa_recs[0].get("mname", "")
        soa_rname = soa_recs[0].get("rname", "")

    # host_info finding — summarises what DNS knows about this domain
    host_info_data: dict = {}
    if ns_list:
        host_info_data["ns_records"] = ns_list
    if mx_list:
        host_info_data["mx_records"] = mx_list
    if soa_mname:
        host_info_data["soa_mname"] = soa_mname
    if soa_rname:
        host_info_data["soa_rname"] = soa_rname
    if ips:
        host_info_data["ips"] = ips

    host_info_data.update(
        {
            "a_record_count": len(records.get("a", [])),
            "aaaa_record_count": len(records.get("aaaa", [])),
            "cname_record_count": len(records.get("cname", [])),
            "txt_record_count": len(records.get("txt", [])),
        }
    )

    if host_info_data:
        parts = [f"{host_info_data.get('a_record_count', 0)} A"]
        if host_info_data.get("aaaa_record_count"):
            parts.append(f"{host_info_data['aaaa_record_count']} AAAA")
        if mx_list:
            parts.append(f"{len(mx_list)} MX")
        if ns_list:
            parts.append(f"{len(ns_list)} NS")

        findings.append(
            {
                "finding_type": "host_info",
                "title": f"DNS: {', '.join(parts)} pour {domain}",
                "severity": Severity.INFO,
                "data": host_info_data,
            }
        )

    # discovered_assets finding — subdomain hosts
    if hosts:
        findings.append(
            {
                "finding_type": "discovered_assets",
                "title": f"{len(hosts)} hôte(s) DNS trouvé(s) pour {domain}",
                "severity": Severity.INFO,
                "data": {
                    "category": "hosts",
                    "domain": domain,
                    "items": sorted(hosts),
                    "sources_used": raw_data.get("sources_used") or [],
                },
            }
        )

    return findings
