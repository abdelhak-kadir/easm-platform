from app.models import Severity
from app.tools.nmap.parse import parse

# ── Sample passive scan dict (what scan.py returns after -sL XML parsing) ─

SAMPLE_SCAN = {
    "ip": "93.184.216.34",
    "hostnames": ["example.com", "mail.example.com"],
}

SINGLE_HOSTNAME = {
    "ip": "8.8.8.8",
    "hostnames": ["dns.google"],
}


# ── host_info tests ────────────────────────────────────────────────────


def test_parse_returns_one_finding():
    findings = parse(SAMPLE_SCAN)
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "host_info"


def test_host_info_finding_has_ip():
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["data"]["ip"] == "93.184.216.34"


def test_host_info_finding_has_hostnames():
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["data"]["hostnames"] == ["example.com", "mail.example.com"]


def test_host_info_finding_has_title():
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["title"] == "Host information for 93.184.216.34"


def test_host_info_severity_is_info():
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["severity"] == Severity.INFO


def test_host_info_ports_is_empty():
    """-sL is passive — no port scan, ports list is empty."""
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["data"]["ports"] == []


def test_host_info_os_is_none():
    """-sL is passive — no OS detection."""
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["data"]["os"] is None


def test_host_info_geo_fields_are_none():
    """-sL only resolves DNS — no geo/org data."""
    findings = parse(SAMPLE_SCAN)
    data = findings[0]["data"]
    assert data["org"] is None
    assert data["isp"] is None
    assert data["asn"] is None
    assert data["country_name"] is None
    assert data["city"] is None


# ── edge cases ─────────────────────────────────────────────────────────


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_missing_ip():
    data = {"hostnames": ["example.com"]}
    assert parse(data) == []


def test_parse_handles_missing_hostnames():
    data = {"ip": "10.0.0.1"}
    findings = parse(data)
    assert findings[0]["data"]["hostnames"] == []


def test_parse_handles_hostnames_as_none():
    data = {"ip": "10.0.0.1", "hostnames": None}
    findings = parse(data)
    assert findings[0]["data"]["hostnames"] == []


def test_parse_handles_empty_hostnames():
    data = {"ip": "10.0.0.1", "hostnames": []}
    findings = parse(data)
    assert findings[0]["data"]["hostnames"] == []


def test_domains_field_is_always_empty():
    """Nmap -sL doesn't resolve forward DNS domains."""
    findings = parse(SAMPLE_SCAN)
    assert findings[0]["data"]["domains"] == []


def test_all_findings_are_info_severity():
    findings = parse(SAMPLE_SCAN)
    assert all(f["severity"] == Severity.INFO for f in findings)
