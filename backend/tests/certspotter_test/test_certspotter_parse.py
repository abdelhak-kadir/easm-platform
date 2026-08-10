from app.tools.certspotter.parse import parse


def test_parse_single_host():
    findings = parse(
        {
            "domain": "example.com",
            "hosts": ["www.example.com"],
            "sources_used": ["certspotter"],
        }
    )
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "discovered_assets"
    assert findings[0]["data"]["category"] == "hosts"
    assert "www.example.com" in findings[0]["data"]["items"]


def test_parse_multiple_hosts():
    findings = parse(
        {
            "domain": "example.com",
            "hosts": ["www.example.com", "mail.example.com", "api.example.com"],
            "sources_used": ["certspotter"],
        }
    )
    assert len(findings) == 1
    assert len(findings[0]["data"]["items"]) == 3


def test_parse_empty_hosts():
    findings = parse(
        {
            "domain": "example.com",
            "hosts": [],
            "sources_used": ["certspotter"],
        }
    )
    assert findings == []


def test_parse_empty_raw():
    assert parse({}) == []
    assert parse(None) == []
