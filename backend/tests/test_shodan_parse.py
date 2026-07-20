from app.models import Severity
from app.tools.shodan.parse import parse

SAMPLE_SHODAN_RESPONSE = {
    "ip_str": "93.184.216.34",
    "data": [
        {
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
        },
        {
            "port": 22,
            "transport": "tcp",
            "product": "OpenSSH",
            "version": "8.2p1",
            "data": "SSH-2.0-OpenSSH_8.2p1",
        },
    ],
    "vulns": {
        "CVE-2021-1234": {"cvss": 9.8, "summary": "Critical remote code execution"},
        "CVE-2020-5678": {"cvss": 5.3, "summary": "Medium severity info disclosure"},
    },
}


def test_parse_returns_finding_per_open_port():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    port_findings = [f for f in findings if f["finding_type"] == "open_port"]
    assert len(port_findings) == 2


def test_parse_returns_finding_per_vulnerability():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    vuln_findings = [f for f in findings if f["finding_type"] == "vulnerability"]
    assert len(vuln_findings) == 2


def test_open_port_finding_has_expected_fields():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    http_finding = next(f for f in findings if f["data"]["port"] == 80)

    assert http_finding["title"] == "Open port 80/tcp (nginx)"
    assert http_finding["severity"] == Severity.INFO
    assert http_finding["data"]["product"] == "nginx"
    assert http_finding["data"]["version"] == "1.18.0"


def test_critical_cvss_maps_to_critical_severity():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    finding = next(f for f in findings if f["title"] == "CVE-2021-1234")
    assert finding["severity"] == Severity.CRITICAL


def test_medium_cvss_maps_to_medium_severity():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    finding = next(f for f in findings if f["title"] == "CVE-2020-5678")
    assert finding["severity"] == Severity.MEDIUM


def test_parse_handles_no_open_ports_or_vulns():
    assert parse({"ip_str": "1.2.3.4"}) == []


def test_parse_handles_missing_optional_fields():
    minimal = {"data": [{"port": 443, "transport": "tcp"}]}
    findings = parse(minimal)
    assert findings[0]["title"] == "Open port 443/tcp"
    assert findings[0]["data"]["product"] == ""
