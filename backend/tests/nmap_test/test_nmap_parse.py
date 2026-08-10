from app.models import Severity
from app.tools.nmap.parse import parse

SAMPLE_SCAN = {
    "ip": "93.184.216.34",
    "hostnames": ["example.com"],
    "os": "Linux 4.15",
    "ports": [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": "1.18.0",
            "extrainfo": "Ubuntu",
        },
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "product": "nginx",
            "version": "1.18.0",
            "extrainfo": "",
        },
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "extrainfo": "Ubuntu Linux",
        },
    ],
}


# ── host_info ──────────────────────────────────────────────────────────


def test_parse_returns_one_host_info():
    findings = parse(SAMPLE_SCAN)
    host_info = [f for f in findings if f["finding_type"] == "host_info"]
    assert len(host_info) == 1


def test_host_info_has_ip_hostnames_os_ports():
    f = next(f for f in parse(SAMPLE_SCAN) if f["finding_type"] == "host_info")
    assert f["data"]["ip"] == "93.184.216.34"
    assert f["data"]["hostnames"] == ["example.com"]
    assert f["data"]["os"] == "Linux 4.15"
    assert f["data"]["ports"] == [22, 80, 443]


def test_host_info_severity_is_info():
    f = next(f for f in parse(SAMPLE_SCAN) if f["finding_type"] == "host_info")
    assert f["severity"] == Severity.INFO


# ── open_port ──────────────────────────────────────────────────────────


def test_parse_returns_three_open_ports():
    ports = [f for f in parse(SAMPLE_SCAN) if f["finding_type"] == "open_port"]
    assert len(ports) == 3


def test_open_port_http_has_product_and_banner():
    p = next(
        f
        for f in parse(SAMPLE_SCAN)
        if f["finding_type"] == "open_port" and f["data"]["port"] == 80
    )
    assert p["title"] == "Open port 80/tcp (nginx)"
    assert p["data"]["product"] == "nginx"
    assert p["data"]["version"] == "1.18.0"
    assert "nginx 1.18.0 (Ubuntu)" in p["data"]["banner"]


def test_open_port_ssh_has_banner():
    p = next(
        f
        for f in parse(SAMPLE_SCAN)
        if f["finding_type"] == "open_port" and f["data"]["port"] == 22
    )
    assert "OpenSSH 8.2p1 (Ubuntu Linux)" in p["data"]["banner"]


def test_open_port_falls_back_to_service_name():
    data = {
        "ip": "10.0.0.1",
        "ports": [{"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql"}],
    }
    p = next(f for f in parse(data) if f["finding_type"] == "open_port")
    assert "mysql" in p["title"]
    assert p["data"]["product"] == "mysql"


def test_open_port_without_service_or_product():
    data = {"ip": "10.0.0.1", "ports": [{"port": 9999, "protocol": "tcp", "state": "open"}]}
    p = next(f for f in parse(data) if f["finding_type"] == "open_port")
    assert "port 9999" in p["title"]


# ── edge cases ─────────────────────────────────────────────────────────


def test_parse_empty_dict():
    assert parse({}) == []


def test_parse_missing_ip():
    data = {"ports": [{"port": 80, "protocol": "tcp", "state": "open"}]}
    findings = parse(data)
    assert all(f["finding_type"] != "host_info" for f in findings)


def test_parse_missing_ports():
    data = {"ip": "10.0.0.1"}
    f = next(f for f in parse(data) if f["finding_type"] == "host_info")
    assert f["data"]["ports"] == []


def test_parse_ports_none():
    data = {"ip": "10.0.0.1", "ports": None}
    f = next(f for f in parse(data) if f["finding_type"] == "host_info")
    assert f["data"]["ports"] == []


def test_parse_missing_os():
    data = {"ip": "10.0.0.1", "ports": [{"port": 443, "protocol": "tcp", "state": "open"}]}
    f = next(f for f in parse(data) if f["finding_type"] == "host_info")
    assert f["data"]["os"] is None


def test_parse_missing_hostnames():
    data = {"ip": "10.0.0.1", "ports": [{"port": 443, "protocol": "tcp", "state": "open"}]}
    f = next(f for f in parse(data) if f["finding_type"] == "host_info")
    assert f["data"]["hostnames"] == []


def test_ports_are_sorted():
    data = {
        "ip": "10.0.0.1",
        "ports": [
            {"port": 8080, "protocol": "tcp", "state": "open"},
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 443, "protocol": "tcp", "state": "open"},
        ],
    }
    f = next(f for f in parse(data) if f["finding_type"] == "host_info")
    assert f["data"]["ports"] == [22, 443, 8080]


def test_all_info_severity():
    assert all(f["severity"] == Severity.INFO for f in parse(SAMPLE_SCAN))
