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


def test_open_port_tcpwrapped_still_reported():
    # "80/tcp open tcpwrapped" is a legitimate open port — it must yield an
    # open_port finding even though no service banner was extracted.
    data = {
        "ip": "10.0.0.1",
        "ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "tcpwrapped"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "tcpwrapped"},
        ],
    }
    ports = [f for f in parse(data) if f["finding_type"] == "open_port"]
    assert len(ports) == 2
    p80 = next(f for f in ports if f["data"]["port"] == 80)
    assert p80["title"] == "Open port 80/tcp (tcpwrapped)"
    assert p80["data"]["product"] == "tcpwrapped"
    assert p80["data"]["version"] == ""


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


# ── vulnerability findings (vulners NSE output) ─────────────────────────

# A realistic vulners.nse block for Apache 2.4.49: CVE lines, an
# "*EXPLOIT*" line (still a CVE — CVSS 10), and non-CVE entries
# (PACKETSTORM/MSF IDs) that must be ignored.
_VULNERS_OUTPUT = (
    " cpe:/a:apache:http_server:2.4.49:\n"
    "  CVE-2017-15906\t5.0\thttps://vulners.com/cve/CVE-2017-15906\n"
    "  *EXPLOIT*\tCVE-2017-15715\t10.0\thttps://vulners.com/cve/CVE-2017-15715\n"
    "  PACKETSTORM:181114\t0.0\thttps://vulners.com/packetstorm/PACKETSTORM:181114\n"
    "  MSF:apache-mod_negotiation-scan\t0.0\thttps://vulners.com/metasploit/MSF:apache-mod_negotiation-scan\n"
)


def _scan_with_vulners() -> dict:
    # No product/version on purpose: parse() would otherwise attempt a
    # live CVEDB lookup via _correlate_cves — these tests stay offline.
    return {
        "ip": "93.184.216.34",
        "ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "scripts": {"vulners": _VULNERS_OUTPUT},
            }
        ],
    }


def test_vulners_in_per_port_scripts_produces_vulnerability_findings():
    # Regression: vulners.nse runs per-port, so its output lives in
    # ports[i].scripts, not host_scripts — these findings used to
    # silently vanish.
    scan = _scan_with_vulners()
    vulns = [f for f in parse(scan) if f["finding_type"] == "vulnerability"]
    assert [f["title"] for f in vulns] == ["CVE-2017-15906", "CVE-2017-15715"]


def test_vulners_finding_has_cvss_severity_and_summary():
    f = next(f for f in parse(_scan_with_vulners()) if f["title"] == "CVE-2017-15906")
    assert f["severity"] == Severity.MEDIUM
    assert f["data"]["cvss"] == 5.0
    assert "https://vulners.com/cve/CVE-2017-15906" in f["data"]["summary"]


def test_vulners_exploit_line_is_critical():
    f = next(f for f in parse(_scan_with_vulners()) if f["title"] == "CVE-2017-15715")
    assert f["severity"] == Severity.CRITICAL
    assert f["data"]["cvss"] == 10.0


def test_same_cve_on_two_ports_emitted_once():
    scan = _scan_with_vulners()
    scan["ports"].append(
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "scripts": {"vulners": _VULNERS_OUTPUT},
        }
    )
    vulns = [f for f in parse(scan) if f["finding_type"] == "vulnerability"]
    assert len(vulns) == 2


def test_vulners_in_host_scripts_still_parsed():
    scan = _scan_with_vulners()
    scan["host_scripts"] = {"vulners": _VULNERS_OUTPUT}
    vulns = [f for f in parse(scan) if f["finding_type"] == "vulnerability"]
    assert len(vulns) == 2
