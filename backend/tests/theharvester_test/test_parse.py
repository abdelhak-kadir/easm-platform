from app.models import Severity
from app.tools.theharvester.parse import parse

# ── empty / edge cases ────────────────────────────────────────────────


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_none():
    assert parse(None) == []


def test_parse_omits_empty_categories():
    raw = {
        "domain": "example.com",
        "emails": [],
        "hosts": [],
        "ips": [],
        "urls": [],
    }
    assert parse(raw) == []


def test_parse_omits_missing_keys():
    raw = {"domain": "example.com"}
    assert parse(raw) == []


# ── single-category findings ──────────────────────────────────────────


def test_parse_emails_finding():
    raw = {
        "domain": "example.com",
        "emails": ["admin@example.com", "contact@example.com"],
        "sources_used": ["crtsh", "hackertarget"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "discovered_assets"
    assert f["data"]["category"] == "emails"
    assert f["data"]["items"] == ["admin@example.com", "contact@example.com"]
    assert f["data"]["sources_used"] == ["crtsh", "hackertarget"]
    assert f["severity"] == Severity.INFO


def test_parse_hosts_finding():
    raw = {
        "domain": "example.com",
        "hosts": ["mail.example.com", "www.example.com"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "discovered_assets"
    assert f["data"]["category"] == "hosts"
    assert f["severity"] == Severity.INFO


def test_parse_ips_finding():
    raw = {"domain": "example.com", "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]}
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["data"]["category"] == "ips"
    assert len(f["data"]["items"]) == 2


def test_parse_urls_finding():
    raw = {
        "domain": "example.com",
        "urls": ["https://example.com/login", "https://example.com/api"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["data"]["category"] == "urls"
    assert f["severity"] == Severity.INFO


# ── multi-category findings ───────────────────────────────────────────


def test_parse_all_categories():
    raw = {
        "domain": "example.com",
        "emails": ["x@example.com"],
        "hosts": ["sub.example.com"],
        "ips": ["1.2.3.4"],
        "urls": ["http://example.com"],
    }
    findings = parse(raw)
    assert len(findings) == 4
    categories = {f["data"]["category"] for f in findings}
    assert categories == {"emails", "hosts", "ips", "urls"}


def test_parse_sorts_items():
    raw = {"domain": "example.com", "hosts": ["b.example.com", "a.example.com"]}
    findings = parse(raw)
    assert findings[0]["data"]["items"] == ["a.example.com", "b.example.com"]


def test_parse_domain_in_title():
    raw = {"domain": "example.org", "emails": ["x@example.org"]}
    findings = parse(raw)
    assert "example.org" in findings[0]["title"]


# ── severity ──────────────────────────────────────────────────────────


def test_all_findings_are_info_severity():
    raw = {
        "domain": "example.com",
        "emails": ["x@example.com"],
        "hosts": ["sub.example.com"],
        "ips": ["10.0.0.1"],
        "urls": ["http://example.com"],
    }
    for f in parse(raw):
        assert f["severity"] == Severity.INFO, f"Expected INFO for {f['data']['category']}"
