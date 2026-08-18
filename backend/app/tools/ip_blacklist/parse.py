"""Pure parsing for the IP blacklist tool — scan.py output → findings.

Three finding types:
- ``ip_reputation`` — one summary row per scan: zones checked, listing
  counts, Tor status, AbuseIPDB score. Always present, so a clean result
  is still visible in the UI as a completed, verified check.
- ``rbl_listing`` — one per blacklist that listed the IP (HIGH).
- ``abuseipdb_report`` — the AbuseIPDB verdict, severity mapped from the
  0-100 abuse confidence score. Skipped when the API wasn't called or
  returned an error.
"""

from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw ip_blacklist scan response into Finding-ready dicts."""
    ip = raw_data.get("ip", "")
    rbl = raw_data.get("rbl") or []
    listed = [r for r in rbl if r.get("listed")]
    errors = [r for r in rbl if r.get("error")]

    abuseipdb = raw_data.get("abuseipdb") or {}
    abuseipdb_ok = "error" not in abuseipdb and bool(abuseipdb)

    findings = [
        _parse_summary(ip, rbl, listed, errors, raw_data.get("tor_exit"), abuseipdb_ok, abuseipdb)
    ]

    findings.extend(_parse_listing(ip, entry) for entry in listed)

    if abuseipdb_ok:
        findings.append(_parse_abuseipdb(ip, abuseipdb))

    return findings


def _parse_summary(
    ip: str,
    rbl: list[dict],
    listed: list[dict],
    errors: list[dict],
    tor_exit,
    abuseipdb_ok: bool,
    abuseipdb: dict,
) -> dict:
    listed_count = len(listed)
    abuseipdb_score = (abuseipdb.get("score") or 0) if abuseipdb_ok else 0
    if listed_count:
        title = (
            f"Réputation de {ip} — {listed_count} blacklist" f"{'s' if listed_count > 1 else ''}"
        )
    elif abuseipdb_score > 0:
        title = f"Réputation de {ip} — signalé sur AbuseIPDB " f"(score {abuseipdb_score}/100)"
    elif errors:
        title = f"Réputation de {ip} — vérification partielle ({len(errors)} zone(s) en erreur)"
    else:
        title = f"Réputation de {ip} — non listé"

    data: dict = {
        "ip": ip,
        "zones_checked": len(rbl) - len(errors),
        # RBL-only count — AbuseIPDB has its own field below, so a 0 here
        # never contradicts a "signalé sur AbuseIPDB" title.
        "rbl_listed_count": listed_count,
        "zones_with_errors": len(errors),
        "tor_exit": bool(tor_exit),
    }
    if abuseipdb_ok:
        data["abuseipdb_score"] = abuseipdb_score
        data["abuseipdb_reported"] = abuseipdb_score > 0

    return {
        "finding_type": "ip_reputation",
        "title": title,
        "severity": Severity.INFO,
        "data": data,
    }


def _parse_listing(ip: str, entry: dict) -> dict:
    return {
        "finding_type": "rbl_listing",
        "title": f"{ip} listé sur {entry['zone']}",
        "severity": Severity.HIGH,
        "data": {
            "ip": ip,
            "zone": entry["zone"],
            "code": entry.get("code", ""),
            "query": entry.get("query", ""),
            "reason": entry.get("reason", ""),
        },
    }


def _parse_abuseipdb(ip: str, data: dict) -> dict:
    score = data.get("score") or 0
    if score >= 70:
        severity = Severity.HIGH
    elif score >= 30:
        severity = Severity.MEDIUM
    elif score >= 1:
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    return {
        "finding_type": "abuseipdb_report",
        "title": f"Signalements AbuseIPDB — score {score}/100",
        "severity": severity,
        "data": {
            "ip": ip,
            "score": score,
            "total_reports": data.get("total_reports"),
            "distinct_users": data.get("distinct_users"),
            "last_reported_at": data.get("last_reported_at"),
            "is_whitelisted": data.get("is_whitelisted"),
            "usage_type": data.get("usage_type"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("country_code"),
        },
    }
