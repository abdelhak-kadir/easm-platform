import ipaddress
import logging
import subprocess
import xml.etree.ElementTree as ET

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_NMAP_BIN = "nmap"
_NMAP_TIMEOUT_S = 120


class NmapScanError(ToolScanError):
    """Raised when an nmap scan can't be completed."""


class NmapRateLimitError(NmapScanError, ToolRateLimitError):
    """Raised when nmap encounters rate-limiting or transient network error — safe to retry."""


class NmapNoDataError(NmapScanError, ToolNoDataError):
    """Raised when nmap finds nothing — host down or no open ports."""


def run(asset_value: str) -> dict:
    """Run an nmap TCP connect scan with service detection against an IP.

    Scans the top 100 most common ports (``--top-ports 100``) with TCP
    connect (``-sT`` — no raw sockets needed) and service version
    detection (``-sV``). Typical scan time: 20–40 seconds.

    Returns a dict with ``ip``, ``hostnames``, ``os``, and ``ports`` keys
    suitable for :func:`app.tools.nmap.parse.parse`.
    """
    ip = asset_value.strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise NmapScanError(f"'{ip}' is not a valid IP address — nmap requires an IP") from None

    # -sT           = TCP connect scan (no raw sockets, works without root)
    # -sV           = service version detection
    # --top-ports N = only scan the N most common ports (fast)
    cmd = [_NMAP_BIN, "-sT", "-sV", "--top-ports", "100", "-oX", "-", ip]
    stdout = ""
    stderr = ""
    timed_out = False

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT_S,
        )
        stdout = proc.stdout or ""
        stderr = (proc.stderr or "").strip()
    except FileNotFoundError:
        raise NmapScanError("nmap binary not found — install nmap in the container image") from None
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        timed_out = True
        _logger.info(
            "nmap timed out after %ds for %s — parsing partial XML output (%d bytes)",
            _NMAP_TIMEOUT_S,
            ip,
            len(stdout),
        )

    if not timed_out and proc.returncode != 0:
        raise NmapScanError(
            f"nmap exited with code {proc.returncode} for {ip}" + (f": {stderr}" if stderr else "")
        )

    try:
        result = _parse_nmap_xml(stdout.strip())
        return result
    except NmapNoDataError:
        if timed_out:
            raise NmapRateLimitError(
                f"nmap timed out after {_NMAP_TIMEOUT_S}s for {ip} "
                f"with no open ports in partial output"
            ) from None
        raise
    except Exception as e:
        raise NmapScanError(f"Failed to parse nmap XML output for {ip}: {e}") from e


def _parse_nmap_xml(xml_string: str) -> dict:
    """Parse nmap ``-sT -sV --top-ports`` XML output into a structured dict.

    Raises ``NmapNoDataError`` when the host is down or has no open ports.
    """
    root = ET.fromstring(xml_string)

    host_elem = root.find("host")
    if host_elem is None:
        raise NmapNoDataError("nmap XML has no <host> element")

    status_elem = host_elem.find("status")
    if status_elem is None or status_elem.get("state") != "up":
        raise NmapNoDataError("Host is down")

    address_elem = host_elem.find("address")
    ip = address_elem.get("addr") if address_elem is not None else "unknown"

    hostnames: list[str] = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name")
            if name:
                hostnames.append(name)

    os_name: str | None = None
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name")

    ports: list[dict] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_elem.find("service")
            ports.append(
                {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state.get("state", "open"),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "extrainfo": service.get("extrainfo", "") if service is not None else "",
                }
            )

    if not ports:
        raise NmapNoDataError(f"No open ports found for {ip}")

    return {
        "ip": ip,
        "hostnames": hostnames,
        "os": os_name,
        "ports": ports,
    }
