from app.models import Severity
from app.tools.shodan.parse import parse

SAMPLE_SHODAN_RESPONSE = {
    "ip_str": "93.184.216.34",
    "org": "Edgecast Inc.",
    "isp": "Edgecast Inc.",
    "asn": "AS15133",
    "hostnames": ["example.com", "www.example.com"],
    "domains": ["example.com"],
    "country_name": "United States",
    "country_code": "US",
    "city": "Los Angeles",
    "region_code": "CA",
    "latitude": 34.0544,
    "longitude": -118.2441,
    "os": None,
    "tags": ["cdn"],
    "ports": [22, 80, 443],
    "last_update": "2026-07-15T09:12:33.123456",
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


def test_parse_returns_one_host_info_finding():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    host_info_findings = [f for f in findings if f["finding_type"] == "host_info"]
    assert len(host_info_findings) == 1


def test_host_info_finding_has_expected_fields():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    host_info = next(f for f in findings if f["finding_type"] == "host_info")

    assert host_info["title"] == "Host information for 93.184.216.34"
    assert host_info["severity"] == Severity.INFO
    assert host_info["data"]["org"] == "Edgecast Inc."
    assert host_info["data"]["asn"] == "AS15133"
    assert host_info["data"]["hostnames"] == ["example.com", "www.example.com"]
    assert host_info["data"]["country_name"] == "United States"
    assert host_info["data"]["tags"] == ["cdn"]


def test_open_port_finding_has_expected_fields():
    findings = parse(SAMPLE_SHODAN_RESPONSE)
    http_finding = next(
        f for f in findings if f["finding_type"] == "open_port" and f["data"]["port"] == 80
    )

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


def test_parse_handles_empty_response():
    assert parse({}) == []


def test_parse_without_ip_str_skips_host_info():
    minimal = {"data": [{"port": 443, "transport": "tcp"}]}
    findings = parse(minimal)
    assert all(f["finding_type"] != "host_info" for f in findings)


def test_parse_handles_missing_optional_fields():
    minimal = {"data": [{"port": 443, "transport": "tcp"}]}
    findings = parse(minimal)
    assert findings[0]["title"] == "Open port 443/tcp"
    assert findings[0]["data"]["product"] == ""
