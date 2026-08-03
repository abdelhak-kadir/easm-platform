from app.models import Severity
from app.tools.amass.parse import parse


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_none():
    assert parse(None) == []


def test_parse_omits_empty_hosts():
    assert parse({"domain": "example.com", "hosts": []}) == []


def test_parse_hosts_finding():
    raw = {
        "domain": "example.com",
        "hosts": ["mail.example.com", "cdn.example.com"],
        "sources_used": ["amass"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "discovered_assets"
    assert f["data"]["category"] == "hosts"
    assert f["data"]["items"] == ["cdn.example.com", "mail.example.com"]
    assert f["data"]["sources_used"] == ["amass"]
    assert f["severity"] == Severity.INFO


def test_parse_domain_in_title():
    raw = {"domain": "example.org", "hosts": ["x.example.org"]}
    findings = parse(raw)
    assert "example.org" in findings[0]["title"]
