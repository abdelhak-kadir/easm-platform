"""Tests for the staged, retrying nmap scanner (app/tools/nmap/scan.py).

``subprocess.run`` is invoked once per stage (up to 3 per attempt) and the
whole pipeline is retried up to ``_MAX_ATTEMPTS`` times when the target
appears unresponsive — tests model that with ``side_effect`` sequences.
"""

import logging
import subprocess
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

import pytest
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.nmap.scan import (
    NmapNoResponsiveHostError,
    NmapRateLimitError,
    NmapScanError,
    _nmap_slot,
    _parse_nmap_xml,
    run,
)

IP = "93.184.216.34"


def _nmap_xml(ip=IP, hostnames=None, os_name=None, ports=None, host_up=True, host_scripts=None):
    """Build an nmap ``-sT -sV --top-ports`` XML string."""
    hostname_elems = ""
    if hostnames:
        hostname_elems = "\n".join(f'<hostname name="{h}" type="PTR"/>' for h in hostnames)

    port_elems = "\n".join(_port_elem(p) for p in (ports or []))

    os_elem = f'<os><osmatch name="{os_name}" accuracy="98"/></os>' if os_name else ""
    state_attr = 'state="up"' if host_up else 'state="down"'

    hostscript_elems = ""
    if host_scripts:
        hostscript_elems = (
            "<hostscript>\n"
            + "\n".join(
                f'<script id="{sid}" output="{output}"/>' for sid, output in host_scripts.items()
            )
            + "\n</hostscript>"
        )

    return f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status {state_attr}/>
    <address addr="{ip}" addrtype="ipv4"/>
    <hostnames>{hostname_elems}</hostnames>
    <ports>{port_elems}</ports>
    {os_elem}
    {hostscript_elems}
  </host>
</nmaprun>"""


def _port_elem(p):
    scripts = ""
    for sid, output in (p.get("scripts") or {}).items():
        scripts += f'<script id="{sid}" output="{output}"/>'
    return f"""<port protocol="{p.get('protocol', 'tcp')}" portid="{p['port']}">
          <state state="{p.get('state', 'open')}"/>
          <service
            name="{p.get('service', '')}"
            product="{p.get('product', '')}"
            version="{p.get('version', '')}"
            extrainfo="{p.get('extrainfo', '')}"
          />
          {scripts}
        </port>"""


def _mock_proc(stdout="", stderr="", returncode=0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


def _silent_xml():
    """nmap output where the target never appeared (no <host> element)."""
    return "<nmaprun/>"


def _happy_procs(ports, versioned_ports, script_ports, os_name="Linux 4.15", host_scripts=None):
    """The three stage outputs for a responsive host, as a side_effect list."""
    return [
        _mock_proc(stdout=_nmap_xml(ports=ports)),
        _mock_proc(stdout=_nmap_xml(ports=versioned_ports, os_name=os_name)),
        _mock_proc(stdout=_nmap_xml(ports=script_ports, host_scripts=host_scripts)),
    ]


@pytest.fixture(autouse=True)
def _no_external_services():
    """Tests must not hit the real Redis semaphore or DNS: free the nmap
    slot immediately and skip the PTR lookup."""
    with patch("app.tools.nmap.scan._nmap_slot", return_value=nullcontext()):
        with patch("app.tools.nmap.scan._resolve_sni_hostname", return_value=None):
            yield


# ── success ────────────────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_merges_stages(mock_run):
    mock_run.side_effect = [
        _mock_proc(stdout=_nmap_xml(ports=[{"port": 80}, {"port": 443}])),
        _mock_proc(
            stdout=_nmap_xml(
                ports=[
                    {"port": 80, "service": "http", "product": "nginx", "version": "1.18.0"},
                    {"port": 443, "service": "https", "product": "nginx", "version": "1.18.0"},
                ],
                os_name="Linux 4.15",
            )
        ),
        _mock_proc(
            stdout=_nmap_xml(
                ports=[
                    {"port": 80, "scripts": {"http-title": "Example"}},
                    {"port": 443, "scripts": {"ssl-cert": "CN=example.com"}},
                ],
                host_scripts={"ssh-hostkey": "2048 aa:bb"},
            )
        ),
    ]

    result = run(IP)
    assert result["ip"] == IP
    assert result["os"] == "Linux 4.15"
    assert [p["port"] for p in result["ports"]] == [80, 443]

    http = result["ports"][0]
    assert http["service"] == "http"
    assert http["product"] == "nginx"
    assert http["version"] == "1.18.0"
    assert http["scripts"]["http-title"] == "Example"
    assert result["host_scripts"]["ssh-hostkey"] == "2048 aa:bb"


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_strips_whitespace(mock_run):
    mock_run.side_effect = _happy_procs(
        [{"port": 22}], [{"port": 22, "service": "ssh"}], [{"port": 22}]
    )

    run(f"  {IP}  ")
    for call in mock_run.call_args_list:
        assert IP in call.args[0]


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_uses_light_first_pass(mock_run):
    mock_run.side_effect = _happy_procs(
        [{"port": 80}, {"port": 443}],
        [{"port": 80}, {"port": 443}],
        [{"port": 80}, {"port": 443}],
    )

    run(IP)
    stage1 = mock_run.call_args_list[0].args[0]
    stage2 = mock_run.call_args_list[1].args[0]
    stage3 = mock_run.call_args_list[2].args[0]

    # Stage 1: light connect scan — no versioning, scripts or OS fingerprinting.
    assert "-sT" in stage1 and "-Pn" in stage1 and "--top-ports" in stage1
    assert "500" in stage1 and "--host-timeout" in stage1 and "-oX" in stage1
    for heavy in ("-sV", "-sC", "-O", "--script"):
        assert heavy not in stage1

    # Stage 2: version/OS detection on the open ports only.
    assert "-sV" in stage2 and "-sC" in stage2 and "-O" in stage2
    assert "--osscan-guess" in stage2 and "-p" in stage2 and "80,443" in stage2

    # Stage 3: NSE scripts on the open ports only.
    assert "--script" in stage3 and "-p" in stage3
    assert any("vulners" in arg for arg in stage3)


# ── retries (silent target is not a definitive answer) ─────────────────


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_retries_when_host_silent(mock_run, mock_sleep):
    mock_run.side_effect = [
        _mock_proc(stdout=_silent_xml()),
        _mock_proc(stdout=_silent_xml()),
        *_happy_procs([{"port": 22, "service": "ssh"}], [{"port": 22}], [{"port": 22}]),
    ]

    result = run(IP)
    assert result["ports"][0]["port"] == 22
    assert mock_run.call_count == 5
    assert mock_sleep.call_count == 2


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_no_responsive_host_after_retries(mock_run, mock_sleep):
    mock_run.side_effect = [_mock_proc(stdout=_silent_xml())] * 3

    with pytest.raises(NmapNoResponsiveHostError, match="aucune réponse exploitable"):
        run(IP)
    assert mock_run.call_count == 3
    assert mock_sleep.call_count == 2


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_timeout_raises_no_responsive_host(mock_run, mock_sleep, caplog):
    mock_run.side_effect = [subprocess.TimeoutExpired(cmd=["nmap", IP], timeout=300, output="")] * 3
    caplog.set_level(logging.INFO)

    # The final user-facing message is the generic French copy; the
    # timeout detail lives in the per-attempt logs for debugging.
    with pytest.raises(NmapNoResponsiveHostError, match="aucune réponse exploitable"):
        run(IP)
    assert mock_run.call_count == 3
    assert "timed out" in caplog.text


# ── attempt logging + outcome classification ───────────────────────────


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_logs_attempt_status_duration_and_host_element(mock_run, mock_sleep, caplog):
    # First attempt: XML with no <host> at all; second: responsive host.
    mock_run.side_effect = [
        _mock_proc(stdout=_silent_xml()),
        *_happy_procs([{"port": 22, "service": "ssh"}], [{"port": 22}], [{"port": 22}]),
    ]
    caplog.set_level(logging.INFO)

    run(IP)

    assert f"target={IP}" in caplog.text
    assert "attempt 1/3" in caplog.text and "attempt 2/3" in caplog.text
    assert "status=no_responsive_host" in caplog.text
    assert "status=NMAP_SUCCESS" in caplog.text
    assert "host_element=False" in caplog.text
    assert "duration=" in caplog.text
    assert "open_ports=1" in caplog.text


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_logs_execution_error_classification(mock_run, mock_sleep, caplog):
    mock_run.return_value = _mock_proc(stderr="Permission denied", returncode=1)
    caplog.set_level(logging.INFO)

    with pytest.raises(NmapScanError):
        run(IP)
    assert mock_run.call_count == 1  # execution errors are never retried
    assert "status=NMAP_EXECUTION_ERROR" in caplog.text


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_logs_final_classification_after_retries(mock_run, mock_sleep, caplog):
    mock_run.side_effect = [_mock_proc(stdout=_silent_xml())] * 3
    caplog.set_level(logging.INFO)

    with pytest.raises(NmapNoResponsiveHostError, match="après plusieurs tentatives"):
        run(IP)

    assert "final classification NMAP_NO_RESPONSIVE_HOST" in caplog.text
    # Per-invocation traces carry the stage + exit status.
    assert "nmap invocation target=" in caplog.text
    assert "stage=discovery" in caplog.text


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_respects_configured_attempts_and_delay(mock_run, mock_sleep):
    mock_run.side_effect = [_mock_proc(stdout=_silent_xml())] * 3
    with (
        patch("app.tools.nmap.scan._MAX_ATTEMPTS", 2),
        patch("app.tools.nmap.scan._RETRY_DELAY_S", 5.0),
    ):
        with pytest.raises(NmapNoResponsiveHostError):
            run(IP)

    assert mock_run.call_count == 2
    assert mock_sleep.call_count == 1
    mock_sleep.assert_called_once_with(5.0)


@patch("app.tools.nmap.scan.time.sleep")
@patch("app.tools.nmap.scan.subprocess.run")
def test_run_succeeds_on_second_attempt(mock_run, mock_sleep):
    mock_run.side_effect = [
        _mock_proc(stdout=_silent_xml()),
        *_happy_procs([{"port": 80}], [{"port": 80}], [{"port": 80}]),
    ]

    result = run(IP)
    assert [p["port"] for p in result["ports"]] == [80]
    assert mock_sleep.call_count == 1


# ── empty-result classification details (host element flags) ───────────


def test_parse_nmap_xml_missing_host_element_flag():
    with pytest.raises(NmapNoResponsiveHostError, match="no <host> element") as exc_info:
        _parse_nmap_xml("<nmaprun/>")
    assert exc_info.value.host_element_found is False


def test_parse_nmap_xml_host_down_flag():
    xml = _nmap_xml(host_up=False)
    with pytest.raises(NmapNoResponsiveHostError, match="not 'up'") as exc_info:
        _parse_nmap_xml(xml)
    assert exc_info.value.host_element_found is True


def test_parse_nmap_xml_up_but_no_open_ports_flag():
    with pytest.raises(NmapNoResponsiveHostError, match="no open ports") as exc_info:
        _parse_nmap_xml(_nmap_xml(ports=[]))
    assert exc_info.value.host_element_found is True


# ── mid-pipeline silence falls back instead of failing ─────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_falls_back_when_host_goes_quiet_mid_pipeline(mock_run):
    mock_run.side_effect = [
        _mock_proc(stdout=_nmap_xml(ports=[{"port": 80, "service": "http"}])),
        _mock_proc(stdout=_silent_xml()),
        _mock_proc(stdout=_silent_xml()),
    ]

    result = run(IP)
    assert [p["port"] for p in result["ports"]] == [80]
    assert result["ports"][0]["service"] == "http"
    assert result["ports"][0]["scripts"] == {}


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_keeps_tcpwrapped_open_port(mock_run):
    # A tcpwrapped port is reported open by nmap without a service probe
    # response — it must survive the pipeline as an open-port finding.
    mock_run.side_effect = [
        _mock_proc(stdout=_nmap_xml(ports=[{"port": 80, "state": "open"}])),
        _mock_proc(stdout=_silent_xml()),
        _mock_proc(stdout=_silent_xml()),
    ]

    result = run(IP)
    assert len(result["ports"]) == 1
    assert result["ports"][0]["port"] == 80
    assert result["ports"][0]["state"] == "open"


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_keeps_tcpwrapped_service_from_version_stage(mock_run):
    # 80/443 open with only "tcpwrapped" from the service probe — a
    # successful scan, not a failure: the open-port findings must survive
    # even though HTTP/TLS/NSE enrichment adds nothing.
    mock_run.side_effect = [
        _mock_proc(stdout=_nmap_xml(ports=[{"port": 80}, {"port": 443}])),
        _mock_proc(
            stdout=_nmap_xml(
                ports=[
                    {"port": 80, "service": "tcpwrapped", "extrainfo": "tcpwrapped"},
                    {"port": 443, "service": "tcpwrapped", "extrainfo": "tcpwrapped"},
                ]
            )
        ),
        _mock_proc(stdout=_silent_xml()),
    ]

    result = run(IP)
    assert [p["port"] for p in result["ports"]] == [80, 443]
    assert all(p["state"] == "open" for p in result["ports"])
    assert all(p["service"] == "tcpwrapped" for p in result["ports"])


# ── invalid input / execution errors (never retried) ───────────────────


def test_run_raises_on_non_ip():
    with pytest.raises(NmapScanError, match="not a valid IP"):
        run("example.com")


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_nonzero_exit(mock_run):
    mock_run.return_value = _mock_proc(stderr="Permission denied", returncode=1)

    with pytest.raises(NmapScanError, match="exited with code 1"):
        run(IP)
    assert mock_run.call_count == 1


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_raises_scan_error_on_file_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(NmapScanError, match="nmap binary not found"):
        run(IP)


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_handles_invalid_xml(mock_run):
    mock_run.return_value = _mock_proc(stdout="not xml")

    with pytest.raises(NmapScanError, match="Failed to parse"):
        run(IP)
    assert mock_run.call_count == 1


# ── parsing details ────────────────────────────────────────────────────


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_parses_port_without_service_element(mock_run):
    mock_run.side_effect = _happy_procs([{"port": 8080}], [{"port": 8080}], [{"port": 8080}])

    result = run(IP)
    assert len(result["ports"]) == 1
    assert result["ports"][0]["port"] == 8080
    assert result["ports"][0]["service"] == ""


@patch("app.tools.nmap.scan.subprocess.run")
def test_run_uses_ptr_as_sni_name(mock_run):
    with patch("app.tools.nmap.scan._resolve_sni_hostname", return_value="ptr.example.com"):
        mock_run.side_effect = _happy_procs([{"port": 443}], [{"port": 443}], [{"port": 443}])
        run(IP)

    stage3 = mock_run.call_args_list[2].args[0]
    assert "--script-args" in stage3
    assert "tls.servername=ptr.example.com" in stage3


# ── Redis token semaphore ──────────────────────────────────────────────


def test_slot_acquires_and_releases_token():
    fake = MagicMock()
    fake.set.return_value = False  # pool already initialized — skip the init RPUSH
    fake.blpop.return_value = [b"nmap:semaphore:tokens", b"nmap-0"]

    with patch("app.tools.nmap.scan._redis_client", return_value=fake):
        with _nmap_slot():
            pass

    fake.blpop.assert_called_once()
    fake.rpush.assert_called_once_with("nmap:semaphore:tokens", "nmap-0")


def test_slot_raises_rate_limit_when_queue_full():
    fake = MagicMock()
    fake.set.return_value = True
    fake.blpop.return_value = None

    with patch("app.tools.nmap.scan._redis_client", return_value=fake):
        with patch("app.tools.nmap.scan._NMAP_SLOT_WAIT_S", 0):
            with pytest.raises(NmapRateLimitError, match="queue saturée"):
                with _nmap_slot():
                    pass


def test_slot_blpop_timeout_stays_below_socket_timeout():
    # The BLPOP timeout (5 s) must stay below the client's socket_timeout
    # (10 s): beyond it redis-py raises TimeoutError on the blocking read,
    # which the semaphore's generic fallback swallows and the cap would
    # silently disengage under wave contention.
    fake = MagicMock()
    fake.set.return_value = False
    fake.blpop.return_value = None

    with patch("app.tools.nmap.scan._redis_client", return_value=fake):
        with patch("app.tools.nmap.scan._NMAP_SLOT_WAIT_S", 0):
            with pytest.raises(NmapRateLimitError):
                with _nmap_slot():
                    pass

    fake.blpop.assert_called_once_with("nmap:semaphore:tokens", timeout=5)


# ── error hierarchy ────────────────────────────────────────────────────


def test_no_responsive_host_is_tool_nodata():
    assert issubclass(NmapNoResponsiveHostError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(NmapRateLimitError, ToolRateLimitError)
