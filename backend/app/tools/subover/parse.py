from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    if not raw_data:
        return []
    hostname = raw_data.get("hostname", "")
    vulnerable: list[dict] = raw_data.get("vulnerable") or []
    findings: list[dict] = []
    for v in vulnerable:
        sev = Severity.HIGH if v.get("dangling") else Severity.LOW
        findings.append(
            {
                "finding_type": "vulnerability",
                "title": f"Subdomain takeover: {hostname} → {v['service']}",
                "severity": sev,
                "data": {
                    "source": "subover",
                    "cve": "",
                    "cname": v["cname"],
                    "service": v["service"],
                    "dangling": v["dangling"],
                    "hostname": hostname,
                    "description": (
                        f"CNAME {hostname} → {v['cname']} ({v['service']})"
                        f" — {'DANGLING' if v['dangling'] else 'ok'}"
                    ),
                },
            }
        )
    return findings
