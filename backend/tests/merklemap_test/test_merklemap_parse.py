from app.models import Severity
from app.tools.merklemap.parse import parse


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_none():
    assert parse(None) == []


def test_parse_omits_empty_hosts():
    assert parse({"domain": "example.com", "hosts": []}) == []


def test_parse_hosts_finding():
    raw = {
        "domain": "example.com",
        "hosts": ["mail.example.com", "www.example.com"],
        "sources_used": ["merklemap"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "discovered_assets"
    assert f["data"]["category"] == "hosts"
    assert f["data"]["items"] == ["mail.example.com", "www.example.com"]
    assert f["data"]["sources_used"] == ["merklemap"]
    assert f["severity"] == Severity.INFO


def test_parse_sorts_items():
    raw = {"domain": "example.com", "hosts": ["b.example.com", "a.example.com"]}
    findings = parse(raw)
    assert findings[0]["data"]["items"] == ["a.example.com", "b.example.com"]


def test_parse_domain_in_title():
    raw = {"domain": "example.org", "hosts": ["x.example.org"]}
    findings = parse(raw)
    assert "example.org" in findings[0]["title"]
