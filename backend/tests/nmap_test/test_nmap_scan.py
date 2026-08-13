import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.nmap.scan import NmapNoDataError, NmapRateLimitError, NmapScanError, run


def _nmap_xml(ip="93.184.216.34", hostnames=None, os_name=None, ports=None, host_up=True):
    """Build an nmap ``-sT -sV --top-ports`` XML string."""
    hostname_elems = ""
    if hostnames:
        hostname_elems = "\n".join(f'<hostname name="{h}" type="PTR"/>' for h in hostnames)

    port_elems = ""
    if ports:
        port_elems = "\n".join(
            f"""<port protocol="{p.get('protocol', 'tcp')}" portid="{p['port']}">
          <state state="{p.get('state', 'open')}"/>
          <service
            name="{p.get('service', '')}"
            product="{p.get('product', '')}"
            version="{p.get('version', '')}"
            extrainfo="{p.get('extrainfo', '')}"
          />
        </port>"""
            for p in ports
        )

    os_elem = f'<os><osmatch name="{os_name}" accuracy="98"/></os>' if os_name else ""
    state_attr = 'state="up"' if host_up else 'state="down"'

    return f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status {state_attr}/>
    <address addr="{ip}" addrtype="ipv4"/>
    <hostnames>{hostname_elems}</hostnames>
    <ports>{port_elems}</ports>
    {os_elem}
  </host>
</nmaprun>"""


def _mock_proc(stdout="", stderr="", returncode=0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


# ── success ────────────────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_returns_ip_hostnames_and_ports(mock_run):
    mock_run.return_value = _mock_proc(
        stdout=_nmap_xml(
            hostnames=["example.com"],
            ports=[
                {"port": 80, "service": "http", "product": "nginx", "version": "1.18.0"},
                {"port": 443, "service": "https", "product": "nginx", "version": "1.18.0"},
            ],
        )
    )

    result = run("93.184.216.34")
    assert result["ip"] == "93.184.216.34"
    assert result["hostnames"] == ["example.com"]
    assert len(result["ports"]) == 2


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_strips_whitespace(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(ports=[{"port": 22, "service": "ssh"}]))

    run("  93.184.216.34  ")
    assert "93.184.216.34" in mock_run.call_args[0][0]


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_extracts_os_detection(mock_run):
    mock_run.return_value = _mock_proc(
        stdout=_nmap_xml(
            os_name="Linux 4.15",
            ports=[{"port": 80, "service": "http"}],
        )
    )

    result = run("93.184.216.34")
    assert result["os"] == "Linux 4.15"


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_uses_advanced_scan_flags(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(ports=[{"port": 80, "service": "http"}]))

    run("93.184.216.34")
    cmd = mock_run.call_args[0][0]
    assert "-sT" in cmd
    assert "-sV" in cmd
    assert "-sC" in cmd
    assert "-O" in cmd
    assert "--top-ports" in cmd
    assert "500" in cmd
    assert "--host-timeout" in cmd
    assert "--script" in cmd
    assert "vulners" in cmd
    assert "-oX" in cmd


# ── invalid input ──────────────────────────────────────────────────────


def test_run_raises_on_non_ip():
    with pytest.raises(NmapScanError, match="not a valid IP"):
        run("example.com")


# ── errors ─────────────────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_rate_limit_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap", "1.2.3.4"], timeout=120)
    with pytest.raises(NmapRateLimitError, match="timed out"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_nonzero_exit(mock_run):
    mock_run.return_value = _mock_proc(stderr="Permission denied", returncode=1)
    with pytest.raises(NmapScanError, match="exited with code 1"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_file_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()
    with pytest.raises(NmapScanError, match="nmap binary not found"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_host_down(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(host_up=False))
    with pytest.raises(NmapNoDataError, match="Host is down"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_no_open_ports(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(ports=[]))
    with pytest.raises(NmapNoDataError, match="No open ports"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_no_host_element(mock_run):
    mock_run.return_value = _mock_proc(stdout="<nmaprun/>")
    with pytest.raises(NmapNoDataError, match="no <host>"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_handles_invalid_xml(mock_run):
    mock_run.return_value = _mock_proc(stdout="not xml")
    with pytest.raises(NmapScanError, match="Failed to parse"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_parses_port_without_service_element(mock_run):
    xml = _nmap_xml(ports=[{"port": 8080, "protocol": "tcp"}])
    mock_run.return_value = _mock_proc(stdout=xml)

    result = run("93.184.216.34")
    assert len(result["ports"]) == 1
    assert result["ports"][0]["port"] == 8080
    assert result["ports"][0]["service"] == ""


# ── error hierarchy ────────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(NmapNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(NmapRateLimitError, ToolRateLimitError)
