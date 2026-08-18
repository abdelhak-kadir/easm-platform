from app.models import Severity
from app.tools.ip_blacklist.parse import parse


def _clean_scan(ip: str = "93.184.216.34") -> dict:
    """A scan where no RBL lists the IP and no AbuseIPDB key was set."""
    return {
        "ip": ip,
        "rbl": [
            {"zone": "Spamhaus ZEN", "listed": False, "query": f"{_rev(ip)}.zen.spamhaus.org"},
            {"zone": "SpamCop", "listed": False, "query": f"{_rev(ip)}.bl.spamcop.net"},
        ],
        "tor_exit": False,
        "abuseipdb": None,
    }


def _rev(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _listed_scan(ip: str = "1.2.3.4") -> dict:
    return {
        "ip": ip,
        "rbl": [
            {
                "zone": "Spamhaus ZEN",
                "listed": True,
                "code": "127.0.0.2",
                "query": f"{_rev(ip)}.zen.spamhaus.org",
                "reason": "SBL123456 - Spam source",
            },
            {"zone": "SpamCop", "listed": False, "query": f"{_rev(ip)}.bl.spamcop.net"},
        ],
        "tor_exit": False,
        "abuseipdb": None,
    }


# ---------------------------------------------------------------------
# summary finding (always present)
# ---------------------------------------------------------------------


def test_clean_scan_yields_summary_finding_only():
    findings = parse(_clean_scan())

    assert len(findings) == 1
    summary = findings[0]
    assert summary["finding_type"] == "ip_reputation"
    assert summary["severity"] == Severity.INFO
    assert summary["data"]["rbl_listed_count"] == 0
    assert summary["data"]["zones_checked"] == 2
    assert summary["data"]["tor_exit"] is False
    assert "abuseipdb_score" not in summary["data"]


def test_listed_scan_yields_summary_plus_one_listing():
    findings = parse(_listed_scan())

    assert len(findings) == 2
    summary = next(f for f in findings if f["finding_type"] == "ip_reputation")
    listing = next(f for f in findings if f["finding_type"] == "rbl_listing")

    assert summary["data"]["rbl_listed_count"] == 1
    assert listing["severity"] == Severity.HIGH
    assert listing["title"] == "1.2.3.4 listé sur Spamhaus ZEN"
    assert listing["data"]["code"] == "127.0.0.2"
    assert listing["data"]["reason"] == "SBL123456 - Spam source"


def test_multiple_listings_yield_one_finding_each():
    scan = _listed_scan()
    scan["rbl"].append(
        {"zone": "DroneBL", "listed": True, "code": "127.0.0.5", "query": "", "reason": ""}
    )

    listings = [f for f in parse(scan) if f["finding_type"] == "rbl_listing"]

    assert len(listings) == 2
    assert {f["data"]["zone"] for f in listings} == {"Spamhaus ZEN", "DroneBL"}


def test_tor_exit_flag_flows_into_summary():
    scan = _clean_scan()
    scan["tor_exit"] = True

    summary = parse(scan)[0]

    assert summary["data"]["tor_exit"] is True


def test_partial_dns_errors_reported_but_not_fatal():
    scan = _clean_scan()
    scan["rbl"][1] = {"zone": "SpamCop", "listed": False, "error": "unresolvable: x.bl.spamcop.net"}

    summary = parse(scan)[0]

    assert summary["data"]["zones_checked"] == 1
    assert summary["data"]["zones_with_errors"] == 1


# ---------------------------------------------------------------------
# AbuseIPDB report finding
# ---------------------------------------------------------------------


def _scan_with_abuseipdb(score: int, **extra) -> dict:
    scan = _clean_scan()
    scan["abuseipdb"] = {
        "score": score,
        "total_reports": 12,
        "distinct_users": 4,
        "last_reported_at": "2026-08-01T10:00:00Z",
        "is_whitelisted": False,
        "usage_type": "Web Hosting",
        "isp": "OVH SAS",
        "domain": "ovh.net",
        "country_code": "FR",
        **extra,
    }
    return scan


def test_abuseipdb_high_score_maps_to_high_severity():
    report = next(
        f for f in parse(_scan_with_abuseipdb(85)) if f["finding_type"] == "abuseipdb_report"
    )

    assert report["severity"] == Severity.HIGH
    assert report["data"]["score"] == 85
    assert report["data"]["total_reports"] == 12
    assert report["data"]["distinct_users"] == 4
    assert report["data"]["isp"] == "OVH SAS"


def test_abuseipdb_medium_score_maps_to_medium_severity():
    report = next(
        f for f in parse(_scan_with_abuseipdb(40)) if f["finding_type"] == "abuseipdb_report"
    )
    assert report["severity"] == Severity.MEDIUM


def test_abuseipdb_low_score_maps_to_low_severity():
    report = next(
        f for f in parse(_scan_with_abuseipdb(5)) if f["finding_type"] == "abuseipdb_report"
    )
    assert report["severity"] == Severity.LOW


def test_abuseipdb_zero_score_is_info():
    report = next(
        f for f in parse(_scan_with_abuseipdb(0)) if f["finding_type"] == "abuseipdb_report"
    )
    assert report["severity"] == Severity.INFO


def test_summary_title_mentions_abuseipdb_when_rbl_clean():
    # RBL-clean yet flagged on AbuseIPDB: the summary must not claim
    # "non listé" — the two cards would contradict each other.
    findings = parse(_scan_with_abuseipdb(60))
    summary = next(f for f in findings if f["finding_type"] == "ip_reputation")

    assert "non listé" not in summary["title"]
    assert "signalé sur AbuseIPDB (score 60/100)" in summary["title"]
    assert summary["data"]["rbl_listed_count"] == 0
    assert summary["data"]["abuseipdb_score"] == 60
    assert summary["data"]["abuseipdb_reported"] is True


def test_abuseipdb_error_skips_report_finding():
    scan = _clean_scan()
    scan["abuseipdb"] = {"error": "quota API dépassé (429)"}

    findings = parse(scan)

    assert all(f["finding_type"] != "abuseipdb_report" for f in findings)
    assert "abuseipdb_score" not in findings[0]["data"]


def test_empty_scan_yields_no_findings():
    assert parse({}) == []
