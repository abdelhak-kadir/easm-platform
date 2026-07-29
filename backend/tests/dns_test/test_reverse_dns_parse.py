from app.models import Severity
from app.tools.reverse_dns.parse import parse


def test_parse_handles_empty_response():
    assert parse({}) == []


def test_parse_returns_empty_list_when_no_hostnames_key():
    raw = {"ip": "93.184.216.34"}
    assert parse(raw) == []


def test_parse_returns_empty_list_when_hostnames_is_empty_list():
    raw = {"ip": "93.184.216.34", "hostnames": []}
    assert parse(raw) == []


def test_parse_returns_one_finding_for_single_hostname():
    raw = {"ip": "93.184.216.34", "hostnames": ["mail.example.com"]}
    findings = parse(raw)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_type"] == "reverse_dns"
    assert finding["title"] == "Reverse DNS: 93.184.216.34 → mail.example.com"
    assert finding["severity"] == Severity.INFO
    assert finding["data"]["ip"] == "93.184.216.34"
    assert finding["data"]["hostnames"] == ["mail.example.com"]


def test_parse_uses_first_hostname_in_title_when_multiple_present():
    raw = {
        "ip": "93.184.216.34",
        "hostnames": ["mail.example.com", "web.example.com"],
    }
    findings = parse(raw)

    assert len(findings) == 1
    assert findings[0]["title"] == "Reverse DNS: 93.184.216.34 → mail.example.com"
    # all hostnames still preserved in data, even though only the first is titled
    assert findings[0]["data"]["hostnames"] == ["mail.example.com", "web.example.com"]


def test_parse_handles_missing_ip_gracefully():
    raw = {"hostnames": ["mail.example.com"]}
    findings = parse(raw)

    assert findings[0]["data"]["ip"] is None
    assert findings[0]["title"] == "Reverse DNS: None → mail.example.com"
