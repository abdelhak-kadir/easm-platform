import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.nmap.scan import NmapNoDataError, NmapRateLimitError, NmapScanError, run

# ── helpers ───────────────────────────────────────────────────────────


def _nmap_xml(ip="93.184.216.34", hostnames=None):
    """Build a minimal nmap ``-sL`` (list scan) XML string.

    ``-sL`` is passive — it only does DNS resolution, no port scan."""
    hostname_elems = ""
    if hostnames:
        hostname_elems = "\n".join(f'<hostname name="{h}" type="PTR"/>' for h in hostnames)

    return f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sL -oX - {ip}">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <hostnames>{hostname_elems}</hostnames>
  </host>
  <runstats><finished time="123" timestr="now" elapsed="0.1"/></runstats>
</nmaprun>"""


def _mock_proc(stdout="", stderr="", returncode=0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


# ── success cases ──────────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_returns_ip_and_hostnames(mock_run):
    mock_run.return_value = _mock_proc(
        stdout=_nmap_xml(hostnames=["example.com", "mail.example.com"])
    )

    result = run("93.184.216.34")
    assert result["ip"] == "93.184.216.34"
    assert result["hostnames"] == ["example.com", "mail.example.com"]


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_strips_whitespace(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(hostnames=["example.com"]))

    run("  93.184.216.34  ")
    call_args = mock_run.call_args[0][0]
    assert "93.184.216.34" in call_args


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_single_hostname(mock_run):
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(hostnames=["dns.google"]))

    result = run("8.8.8.8")
    assert result["hostnames"] == ["dns.google"]


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_uses_list_scan(mock_run):
    """Verify the scan uses -sL (passive list scan, no packets)."""
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(hostnames=["example.com"]))

    run("93.184.216.34")
    cmd = mock_run.call_args[0][0]
    assert "-sL" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    # Must NOT use -sT or -sV (those are active)
    assert "-sT" not in cmd
    assert "-sV" not in cmd


# ── invalid input ──────────────────────────────────────────────────────


def test_run_raises_on_non_ip():
    with pytest.raises(NmapScanError, match="not a valid IP"):
        run("example.com")


def test_run_raises_on_cidr():
    with pytest.raises(NmapScanError, match="not a valid IP"):
        run("10.0.0.0/24")


def test_run_raises_on_domain_name():
    with pytest.raises(NmapScanError, match="not a valid IP"):
        run("www.google.com")


# ── subprocess errors ──────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_rate_limit_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap", "1.2.3.4"], timeout=120)

    with pytest.raises(NmapRateLimitError, match="timed out"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_nonzero_exit(mock_run):
    mock_run.return_value = _mock_proc(stdout="", stderr="Permission denied", returncode=1)

    with pytest.raises(NmapScanError, match="exited with code 1"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_file_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError("nmap not found")

    with pytest.raises(NmapScanError, match="nmap binary not found"):
        run("1.2.3.4")


# ── no data / edge cases ───────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_no_hostnames(mock_run):
    """-sL with no PTR records — nothing resolved, not a failure."""
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(hostnames=[]))

    with pytest.raises(NmapNoDataError, match="No hostnames resolved"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_no_hostnames_element(mock_run):
    """-sL XML without any <hostnames> element at all."""
    xml = _nmap_xml(hostnames=[]).replace("<hostnames></hostnames>", "")
    mock_run.return_value = _mock_proc(stdout=xml)

    with pytest.raises(NmapNoDataError, match="No hostnames resolved"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_no_data_when_no_host_element(mock_run):
    mock_run.return_value = _mock_proc(
        stdout="""<?xml version="1.0"?>
<nmaprun scanner="nmap"><runstats/></nmaprun>"""
    )

    with pytest.raises(NmapNoDataError, match="no <host>"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_handles_invalid_xml(mock_run):
    mock_run.return_value = _mock_proc(stdout="not valid xml at all")

    with pytest.raises(NmapScanError, match="Failed to parse nmap XML"):
        run("1.2.3.4")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_handles_ptrs_with_trailing_dot(mock_run):
    """Fully-qualified PTR records have trailing dots — verify they're kept."""
    mock_run.return_value = _mock_proc(stdout=_nmap_xml(hostnames=["web.example.com."]))

    result = run("93.184.216.34")
    assert result["hostnames"] == ["web.example.com."]


# ── error hierarchy ────────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(NmapNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(NmapRateLimitError, ToolRateLimitError)


def test_scan_error_is_tool_scan_error():
    from app.tools.base import ToolScanError as BaseScanError

    assert issubclass(NmapScanError, BaseScanError)
