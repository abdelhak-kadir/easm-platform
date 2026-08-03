from app.models import Severity
from app.tools.censys.parse import parse

SAMPLE_CENSYS_RESPONSE = {
    "ip": "93.184.216.34",
    "location": {
        "country": "United States",
        "country_code": "US",
        "city": "Los Angeles",
        "province": "California",
        "coordinates": {"latitude": 34.0544, "longitude": -118.2441},
    },
    "autonomous_system": {
        "asn": 15133,
        "organization": "Edgecast Inc.",
        "description": "EDGECAST",
        "name": "EDGECAST",
        "country_code": "US",
    },
    "last_updated_at": "2026-07-15T09:12:33.123456Z",
    "operating_system": {
        "product": "Linux",
        "description": "Linux 4.15",
    },
    "services": [
        {
            "port": 80,
            "service_name": "HTTP",
            "extended_service_name": "HTTPS",
            "transport_protocol": "TCP",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            "software": [
                {"product": "nginx", "version": "1.18.0"},
                {"product": "OpenSSL", "version": "1.1.1"},
            ],
        },
        {
            "port": 22,
            "service_name": "SSH",
            "transport_protocol": "TCP",
            "banner": "SSH-2.0-OpenSSH_8.2p1",
        },
    ],
}


def test_parse_returns_one_host_info_finding():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    host_info = [f for f in findings if f["finding_type"] == "host_info"]
    assert len(host_info) == 1


def test_host_info_finding_has_expected_fields():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    host_info = next(f for f in findings if f["finding_type"] == "host_info")

    assert host_info["title"] == "Host information for 93.184.216.34"
    assert host_info["severity"] == Severity.INFO
    assert host_info["data"]["ip"] == "93.184.216.34"
    assert host_info["data"]["org"] == "Edgecast Inc."
    assert host_info["data"]["asn"] == 15133
    assert host_info["data"]["country_name"] == "United States"
    assert host_info["data"]["country_code"] == "US"
    assert host_info["data"]["city"] == "Los Angeles"
    assert host_info["data"]["region_code"] == "California"
    assert host_info["data"]["latitude"] == 34.0544
    assert host_info["data"]["longitude"] == -118.2441
    assert host_info["data"]["os"] == "Linux 4.15"
    assert host_info["data"]["ports"] == [22, 80]
    assert host_info["data"]["last_update"] == "2026-07-15T09:12:33.123456Z"


def test_parse_returns_finding_per_service():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    port_findings = [f for f in findings if f["finding_type"] == "open_port"]
    assert len(port_findings) == 2


def test_open_port_finding_has_title_with_port_and_transport():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    http_finding = next(
        f for f in findings if f["finding_type"] == "open_port" and f["data"]["port"] == 80
    )
    assert http_finding["title"] == "Open port 80/tcp (HTTPS)"
    assert http_finding["severity"] == Severity.INFO
    assert http_finding["data"]["port"] == 80
    assert http_finding["data"]["transport"] == "tcp"
    assert http_finding["data"]["product"] == "HTTPS"


def test_open_port_uses_service_name_when_no_extended():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    ssh_finding = next(
        f for f in findings if f["finding_type"] == "open_port" and f["data"]["port"] == 22
    )
    assert ssh_finding["title"] == "Open port 22/tcp (SSH)"
    assert ssh_finding["data"]["product"] == "SSH"


def test_banner_includes_software_when_present():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    http_finding = next(
        f for f in findings if f["finding_type"] == "open_port" and f["data"]["port"] == 80
    )
    assert "nginx 1.18.0" in http_finding["data"]["banner"]
    assert "OpenSSL 1.1.1" in http_finding["data"]["banner"]


def test_banner_falls_back_to_service_banner():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    ssh_finding = next(
        f for f in findings if f["finding_type"] == "open_port" and f["data"]["port"] == 22
    )
    assert "SSH-2.0" in ssh_finding["data"]["banner"]


def test_parse_handles_empty_response():
    assert parse({}) == []


def test_parse_without_ip_skips_host_info():
    minimal = {"services": [{"port": 443, "transport_protocol": "TCP"}]}
    findings = parse(minimal)
    assert all(f["finding_type"] != "host_info" for f in findings)


def test_parse_handles_missing_optional_fields():
    minimal = {"services": [{"port": 443, "transport_protocol": "TCP"}]}
    findings = parse(minimal)
    assert findings[0]["title"] == "Open port 443/tcp"
    assert findings[0]["data"]["product"] == ""


def test_parse_handles_missing_location_and_asn():
    minimal = {"ip": "10.0.0.1"}
    findings = parse(minimal)
    host_info = findings[0]
    assert host_info["data"]["org"] is None
    assert host_info["data"]["asn"] is None
    assert host_info["data"]["country_name"] is None
    assert host_info["data"]["os"] is None
    assert host_info["data"]["ports"] == []


def test_parse_handles_services_as_none():
    data = {"ip": "10.0.0.1", "services": None}
    findings = parse(data)
    assert len(findings) == 1  # just host_info


def test_all_findings_are_info_severity():
    findings = parse(SAMPLE_CENSYS_RESPONSE)
    assert all(f["severity"] == Severity.INFO for f in findings)
