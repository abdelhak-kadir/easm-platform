import ipaddress
import subprocess
import xml.etree.ElementTree as ET

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_NMAP_BIN = "nmap"
_NMAP_TIMEOUT_S = 120


class NmapScanError(ToolScanError):
    """Raised when an nmap scan can't be completed."""


class NmapRateLimitError(NmapScanError, ToolRateLimitError):
    """Raised when nmap encounters rate-limiting or a transient network error — safe to retry."""


class NmapNoDataError(NmapScanError, ToolNoDataError):
    """Raised when nmap resolves no hostnames — not a failure, just nothing to report."""


def run(asset_value: str) -> dict:
    """Run a passive nmap list scan against an IP.

    Uses ``-sL`` (list scan) which only performs DNS reverse resolution
    to discover hostnames — **no packets are sent to the target**. This is
    passive recon, safe for external attack surface discovery.

    Returns a dict with ``hostnames`` suitable for
    :func:`app.tools.nmap.parse.parse`.
    """
    ip = asset_value.strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise NmapScanError(f"'{ip}' is not a valid IP address — nmap requires an IP") from None

    # -sL  = list scan (DNS resolution only, no packets to target — passive)
    # -n   = skip reverse DNS (would defeat the purpose of -sL for EASM)
    # We intentionally do NOT pass -n so nmap resolves PTR records.
    cmd = [_NMAP_BIN, "-sL", "-oX", "-", ip]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT_S,
        )
    except FileNotFoundError:
        raise NmapScanError("nmap binary not found — install nmap in the container image") from None
    except subprocess.TimeoutExpired:
        raise NmapRateLimitError(f"nmap scan timed out after {_NMAP_TIMEOUT_S}s for {ip}") from None

    if proc.returncode != 0:
        stderr = proc.stderr.strip() if proc.stderr else ""
        raise NmapScanError(
            f"nmap exited with code {proc.returncode} for {ip}" + (f": {stderr}" if stderr else "")
        )

    try:
        return _parse_nmap_xml(proc.stdout.strip())
    except NmapNoDataError:
        raise
    except Exception as e:
        raise NmapScanError(f"Failed to parse nmap XML output for {ip}: {e}") from e


def _parse_nmap_xml(xml_string: str) -> dict:
    """Parse nmap XML output into a structured dict.

    For ``-sL`` (passive list scan), nmap only returns hostnames from DNS
    resolution — no port scan data. Raises ``NmapNoDataError`` when
    nothing usable was found (no hostnames resolved).
    """
    root = ET.fromstring(xml_string)

    host_elem = root.find("host")
    if host_elem is None:
        raise NmapNoDataError("nmap XML has no <host> element")

    address_elem = host_elem.find("address")
    ip = address_elem.get("addr") if address_elem is not None else "unknown"

    hostnames: list[str] = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name")
            if name:
                hostnames.append(name)

    # -sL does not have <os> or <ports> elements
    if not hostnames:
        raise NmapNoDataError(f"No hostnames resolved for {ip}")

    return {
        "ip": ip,
        "hostnames": hostnames,
    }
