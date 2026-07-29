from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw email_security response into Finding-ready dicts.

    Unlike most other tools, an absent record here IS a finding in its
    own right (a spoofing/phishing gap) -- so SPF and DMARC always
    produce a finding, present or not. DKIM stays best-effort: a miss
    across all probed selectors isn't proof of absence, so it produces
    no finding either way (see scan.py's `_DKIM_SELECTORS` note).
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain")
    findings = [
        _parse_spf(domain, raw_data.get("spf_record")),
        _parse_dmarc(domain, raw_data.get("dmarc_record")),
    ]

    dkim_finding = _parse_dkim(domain, raw_data.get("dkim_selectors_found") or [])
    if dkim_finding:
        findings.append(dkim_finding)

    return findings


def _parse_spf(domain: str, spf_record: str | None) -> dict:
    if spf_record:
        return {
            "finding_type": "email_security",
            "title": f"SPF record found for {domain}",
            "severity": Severity.INFO,
            "data": {"check": "spf", "present": True, "record": spf_record},
        }
    return {
        "finding_type": "email_security",
        "title": f"No SPF record for {domain}",
        "severity": Severity.MEDIUM,
        "data": {"check": "spf", "present": False, "record": None},
    }


_DMARC_POLICY_SEVERITY = {
    "reject": Severity.INFO,
    "quarantine": Severity.LOW,
    "none": Severity.MEDIUM,
}


def _parse_dmarc(domain: str, dmarc_record: str | None) -> dict:
    if not dmarc_record:
        return {
            "finding_type": "email_security",
            "title": f"No DMARC record for {domain}",
            "severity": Severity.HIGH,
            "data": {"check": "dmarc", "present": False, "record": None, "policy": None},
        }

    policy = _extract_dmarc_policy(dmarc_record)
    severity = _DMARC_POLICY_SEVERITY.get(policy, Severity.MEDIUM)

    return {
        "finding_type": "email_security",
        "title": f"DMARC record found for {domain} (policy={policy or 'unknown'})",
        "severity": severity,
        "data": {"check": "dmarc", "present": True, "record": dmarc_record, "policy": policy},
    }


def _parse_dkim(domain: str, found_selectors: list[str]) -> dict | None:
    if not found_selectors:
        return None

    return {
        "finding_type": "email_security",
        "title": f"DKIM selector(s) found for {domain}",
        "severity": Severity.INFO,
        "data": {"check": "dkim", "present": True, "selectors": found_selectors},
    }


def _extract_dmarc_policy(record: str) -> str | None:
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return part.split("=", 1)[1].strip().lower()
    return None
