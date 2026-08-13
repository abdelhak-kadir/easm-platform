"""SSL/TLS assessment: certificate check + live TLS configuration probe.

Two sources, both always attempted:

1. **CrtMgr public API** — certificate metadata (CN, issuer, validity
   window, SANs, key type/size). Rate limits: 3/min, 20/hour, 50/day
   per IP. Exceeding them returns 429.
2. **nmap TLS probe** — live protocol/cipher assessment via the
   ssl-enum-ciphers, tls-alpn, tls-version-enum, ssl-heartbleed and
   ssl-poodle NSE scripts. Feeds vulnerability findings for weak TLS
   versions, weak ciphers, CRIME compression, Heartbleed and POODLE.

The probe is best-effort: a broken probe never fails the scan — the
certificate findings still come through (see parse.py for how the probe
results map to vulnerability findings).
"""

import logging
import re
import subprocess
import xml.etree.ElementTree as ET

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError
from app.tools.ssl_checker.parse import sanitize_key_size

_logger = logging.getLogger(__name__)

_CRTMGR_URL = "https://api.crtmgr.com/api/v1/ssl-checker"
_CRTMGR_TIMEOUT_S = 15

_NMAP_BIN = "nmap"
_TLS_PROBE_PORTS = "443,8443"
# Scripts pinned to what nmap 7.95 ships — a name that doesn't match
# makes the NSE engine quit with no output at all, so never assume
# a script exists. tls-version-enum is NOT in the default script set;
# ssl-enum-ciphers reports the TLS versions anyway.
_TLS_PROBE_SCRIPTS = (
    "ssl-enum-ciphers,tls-alpn,ssl-heartbleed,ssl-poodle,"
    "sslv2-drown,ssl-ccs-injection,tls-ticketbleed"
)
_TLS_PROBE_TIMEOUT_S = 120
_TLS_HOST_TIMEOUT_S = "100s"

# CrtMgr is behind Cloudflare.  429 and 5xx have different meanings:
# - 429: genuine rate limit — retry later
# - 502/503: transient Cloudflare or origin hiccup — retry later
# - 504: origin is DOWN — retrying won't help, treat as hard failure
_RETRYABLE_STATUSES = frozenset({429, 502, 503})


def _clean_error_body(resp: requests.Response) -> str:
    """Extract a readable error from a Cloudflare-wrapped HTML response."""
    text = (resp.text or "").strip()
    if not text:
        return ""
    # If it looks like HTML, extract just the <title> or return a short summary
    if text.startswith("<!") or text.startswith("<html"):
        import re

        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
        if match:
            return match.group(1)[:200]
        return f"HTML response ({len(text)} bytes)"
    return text[:200]


class SslCheckerScanError(ToolScanError):
    """Raised when an SSL certificate check can't be completed."""


class SslCheckerRateLimitError(SslCheckerScanError, ToolRateLimitError):
    """Raised when CrtMgr rate-limits or has a transient server error — safe to retry."""


class SslCheckerNoDataError(SslCheckerScanError, ToolNoDataError):
    """Raised when the target has no reachable HTTPS service — not a failure."""


def run(asset_value: str) -> dict:
    """Fetch the live TLS certificate for *asset_value* from CrtMgr.

    Returns the JSON response containing CN, issuer, validity window,
    SANs, key type / size, fingerprint, and expiry status.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise SslCheckerNoDataError("Empty domain — nothing to check")

    try:
        resp = requests.get(
            _CRTMGR_URL,
            params={"domain": domain},
            timeout=_CRTMGR_TIMEOUT_S,
        )

        if resp.status_code in _RETRYABLE_STATUSES:
            detail = _clean_error_body(resp) or f"HTTP {resp.status_code}"
            raise SslCheckerRateLimitError(
                f"CrtMgr returned {resp.status_code} for {domain}: {detail}"
            )

        if resp.status_code == 400:
            raise SslCheckerNoDataError(
                f"CrtMgr rejected the request for {domain} (400) — domain may not resolve"
            )

        if resp.status_code == 504:
            raise SslCheckerScanError(
                f"CrtMgr origin is unreachable (504) for {domain} — "
                "the upstream service is down, not a rate-limit issue"
            )

        if resp.status_code != 200:
            raise SslCheckerScanError(
                f"CrtMgr returned unexpected status {resp.status_code} for {domain}"
            )

        data = resp.json()

    except requests.Timeout:
        raise SslCheckerRateLimitError(
            f"CrtMgr timed out after {_CRTMGR_TIMEOUT_S}s for {domain}"
        ) from None
    except requests.ConnectionError as exc:
        raise SslCheckerScanError(f"CrtMgr connection failed for {domain}: {exc}") from exc
    except SslCheckerScanError:
        raise
    except Exception as exc:
        raise SslCheckerScanError(f"Unexpected error checking SSL for {domain}: {exc}") from exc

    # A 200 with no CN means the API accepted the request but couldn't connect
    # to the target — treat as clean no-data.
    if not data.get("cn"):
        raise SslCheckerNoDataError(
            f"No certificate found for {domain} — target may not serve HTTPS"
        )

    # CrtMgr leaks Python object reprs into key_size for EC certs
    # (e.g. "SECP256R1 <...object at 0x...>") — sanitize before the
    # raw_data lands in the database.
    data["key_size"] = sanitize_key_size(data.get("key_size"))

    _logger.info(
        "SSL cert fetched for %s: issuer=%s, days_left=%s",
        domain,
        data.get("issuer"),
        data.get("days_left"),
    )

    # Live TLS configuration probe (best-effort — never fails the scan).
    data["tls_scan"] = _probe_tls(domain)

    return data


# ── nmap TLS configuration probe ──────────────────────────────────────


def _probe_tls(domain: str) -> dict | None:
    """Probe the live TLS configuration of *domain* with nmap NSE scripts.

    Returns a ``{"ports": [...]}`` dict with, per open TLS port: offered
    TLS versions, cipher strength grade, ssl-enum-ciphers warnings,
    compressors, Heartbleed/POODLE state and ALPN protocols. Returns
    ``None`` on any failure — the caller treats the probe as optional.
    """
    # -sV matters: the ssl-* scripts' portrules match on the detected
    # service (shortport.ssl). Without it they stay silent on hosts
    # that refuse pre-TLS1.3 handshakes.
    cmd = [
        _NMAP_BIN,
        "-Pn",
        "-sT",
        "-sV",
        "-p",
        _TLS_PROBE_PORTS,
        "--script",
        _TLS_PROBE_SCRIPTS,
        "--host-timeout",
        _TLS_HOST_TIMEOUT_S,
        "-oX",
        "-",
        domain,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TLS_PROBE_TIMEOUT_S,
        )
    except FileNotFoundError:
        _logger.warning("TLS probe skipped for %s — nmap binary not found", domain)
        return None
    except subprocess.TimeoutExpired:
        _logger.warning("TLS probe timed out for %s", domain)
        return None
    except OSError as e:
        _logger.warning("TLS probe OS error for %s: %s", domain, e)
        return None

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        _logger.warning(
            "TLS probe failed for %s (exit %d) — no TLS findings",
            domain,
            proc.returncode,
        )
        return None

    try:
        return _parse_tls_xml(proc.stdout)
    except Exception as e:
        _logger.warning("TLS probe XML parse failed for %s: %s", domain, e)
        return None


def _parse_tls_xml(xml_string: str) -> dict:
    """Parse the nmap XML of the TLS probe into a structured dict."""
    root = ET.fromstring(xml_string)
    host = root.find("host")
    if host is None:
        return {"ports": []}

    ports: list[dict] = []
    ports_elem = host.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state = port_elem.find("state")
            state_value = state.get("state") if state is not None else ""
            if state_value not in ("open", "open|filtered"):
                continue

            scripts: dict[str, str] = {}
            for script_elem in port_elem.findall("script"):
                output = script_elem.get("output") or ""
                if output:
                    scripts[script_elem.get("id", "")] = output

            ports.append(
                {
                    "port": int(port_elem.get("portid", 0)),
                    "state": state_value,
                    "tls_versions": _extract_tls_versions(scripts),
                    "least_strength": _extract_least_strength(scripts),
                    "warnings": _extract_warnings(scripts),
                    "compressors": _extract_compressors(scripts),
                    "heartbleed": _extract_script_state(scripts, "ssl-heartbleed"),
                    "poodle": _extract_script_state(scripts, "ssl-poodle"),
                    "sslv2_drown": _extract_script_state(scripts, "sslv2-drown"),
                    "ccs_injection": _extract_script_state(scripts, "ssl-ccs-injection"),
                    "ticketbleed": _extract_script_state(scripts, "tls-ticketbleed"),
                    "alpn": _extract_alpn(scripts),
                }
            )

    return {"ports": ports}


# ── NSE script output extraction helpers ──────────────────────────────


def _extract_tls_versions(scripts: dict[str, str]) -> list[str]:
    """TLS versions offered, from the ssl-enum-ciphers section headers
    (each version gets a "TLSv1.X:" section when offered)."""
    versions: set[str] = set()
    output = scripts.get("ssl-enum-ciphers") or ""
    for line in output.splitlines():
        for m in re.finditer(r"TLSv1\.[0-3]", line.strip()):
            versions.add(m.group(0))
    return sorted(versions)


def _extract_least_strength(scripts: dict[str, str]) -> str | None:
    output = scripts.get("ssl-enum-ciphers") or ""
    match = re.search(r"least strength:\s*([A-F]+)", output)
    return match.group(1) if match else None


def _extract_warnings(scripts: dict[str, str]) -> list[str]:
    """Warnings listed by ssl-enum-ciphers (SWEET32, weak DH, no PFS, …)."""
    output = scripts.get("ssl-enum-ciphers") or ""
    warnings: list[str] = []
    in_warnings = False
    for line in output.splitlines():
        stripped = line.strip()
        if in_warnings:
            if not stripped or stripped.startswith("least strength"):
                break
            warnings.append(stripped)
        elif stripped == "warnings:":
            in_warnings = True
    return warnings


def _extract_compressors(scripts: dict[str, str]) -> list[str]:
    """Compressors offered (e.g. "1 - NULL"). Anything but NULL means
    TLS compression is on → CRIME-style attack surface."""
    output = scripts.get("ssl-enum-ciphers") or ""
    compressors: list[str] = []
    in_section = False
    for line in output.splitlines():
        stripped = line.strip()
        if in_section:
            if not stripped or ":" in stripped and " - " not in stripped:
                break
            compressors.append(stripped)
        elif stripped == "compressors:":
            in_section = True
    return compressors


def _extract_script_state(scripts: dict[str, str], script_id: str) -> str | None:
    """ "State: VULNERABLE" / "State: NOT VULNERABLE" from a script."""
    output = scripts.get(script_id) or ""
    match = re.search(r"State:\s*(\S+)", output)
    return match.group(1) if match else None


def _extract_alpn(scripts: dict[str, str]) -> list[str]:
    """ALPN protocols from the tls-alpn script ("ALPN: h2, http/1.1")."""
    output = scripts.get("tls-alpn") or ""
    match = re.search(r"ALPN:\s*(.+)", output)
    if not match:
        return []
    return [p.strip() for p in match.group(1).split(",") if p.strip()]
