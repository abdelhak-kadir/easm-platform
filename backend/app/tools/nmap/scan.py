"""Nmap integration — resilient, staged scanning.

Throttled targets are the norm in EASM, not the exception: firewalls
answer slowly or not at all for stretches at a time, so a single nmap
pass can conclude "host down" purely because it ran during a silent
window.  This module therefore:

1. **Retries the full pipeline** (up to ``_MAX_ATTEMPTS``, with a short
   delay between attempts) before ever concluding the target is
   unresponsive.
2. **Scans in three stages**, running expensive enumeration only when
   there is something to enumerate:

   - Stage 1 — host/port discovery (fast connect scan, no versioning):
     decides whether the target answers at all and which ports are open.
   - Stage 2 — service/version detection (``-sV -sC -O``) on the open
     ports only.
   - Stage 3 — NSE enrichment (vulners, http-title, ssl-cert, …) on the
     open ports only.

   A host that stops answering between stages is not a failure: the
   pipeline falls back to the previous stage's data.

3. **Caps concurrent nmap executions** across the whole worker fleet via
   a Redis token semaphore (prefork workers share no memory), so a wave
   that promotes 20 subdomains can't fire 20 heavy scans at once on top
   of Shodan/Amass/theHarvester.

Error taxonomy (distinct from the tool contract's three types):
``NmapScanError``  — execution problem (binary missing, exit != 0,
                      unparseable XML): the tool itself failed.
``NmapNoResponsiveHostError`` — after retries, the target never
                      answered: the tool worked, the host just had
                      nothing to give (no-data, not a failure).
``NmapRateLimitError`` — nmap queue saturated: transient, retry later.

These map onto the three outcome classes also exposed as constants used
in the attempt/final logs: ``NMAP_EXECUTION_ERROR``,
``NMAP_NO_RESPONSIVE_HOST``, ``NMAP_SUCCESS``.
"""

import ipaddress
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from functools import lru_cache

import dns.resolver
import dns.reversename

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_NMAP_BIN = "nmap"
_NMAP_TIMEOUT_S = 300  # per subprocess invocation
_TOP_PORTS = "500"


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Integer config from env var *name*, clamped to >= *minimum*.

    Falls back to *default* when unset or malformed — a bad env value
    must not take every scan down at import time.
    """

    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    """Float config from env var *name*, clamped to >= *minimum* (see ``_env_int``)."""

    try:
        return max(minimum, float(os.environ.get(name, str(default))))
    except ValueError:
        return default


# Retries: a silent window is not a definitive answer.  Configurable via
# env (docker-compose / .env): NMAP_MAX_ATTEMPTS, NMAP_RETRY_DELAY_S.
_MAX_ATTEMPTS = _env_int("NMAP_MAX_ATTEMPTS", 3)
_RETRY_DELAY_S = _env_float("NMAP_RETRY_DELAY_S", 8.0)

# Per-stage host timeouts: stage 1 must abort quickly on silent hosts;
# the later stages only touch ports already known to be open.
_STAGE1_HOST_TIMEOUT = "120s"
_STAGE2_HOST_TIMEOUT = "180s"
_STAGE3_HOST_TIMEOUT = "180s"

# NSE scripts that enrich the port scan for ASM purposes:
# - vulners       → known CVEs with CVSS for each detected service
# - http-title    → page title behind the port
# - ssl-cert      → certificate CN + SANs presented on the port
# - ssl-enum-ciphers / tls-alpn → TLS configuration of the port
_NMAP_SCRIPTS = "vulners,http-title,ssl-cert,ssl-enum-ciphers,tls-alpn"

# Concurrency cap for nmap across the worker fleet (Redis semaphore).
_MAX_CONCURRENT_NMAP = _env_int("NMAP_MAX_CONCURRENT", 3)
_NMAP_TOKENS_KEY = "nmap:semaphore:tokens"
_NMAP_SEMAPHORE_INIT_KEY = "nmap:semaphore:init"
_NMAP_SLOT_WAIT_S = 600  # max time queued for a free nmap slot

# User-facing outcome, shown as the ScanJob detail when the target never
# answered.  Technical reasons (missing <host>, timeouts, …) stay in the
# worker logs for debugging.
_NO_RESPONSIVE_HOST_MSG = (
    "Nmap terminé, mais aucune réponse exploitable n'a été obtenue de la "
    "cible après plusieurs tentatives."
)


class NmapScanError(ToolScanError):
    """nmap could not be executed or its output could not be interpreted."""


class NmapRateLimitError(NmapScanError, ToolRateLimitError):
    """The nmap queue is saturated — safe to retry later."""


class NmapNoResponsiveHostError(NmapScanError, ToolNoDataError):
    """After retries the target never answered — not a tool failure.

    ``host_element_found`` records whether the XML at least contained a
    ``<host>`` element (host down or up-but-no-open-ports) as opposed to
    no host element at all — the attempt logs report it for debugging.
    """

    def __init__(self, message: str, host_element_found: bool = False):
        super().__init__(message)
        self.host_element_found = host_element_found


# Outcome classes used in the attempt and final logs, so an operator can
# tell a working-tool/quiet-host from a genuinely broken run at a glance.
NMAP_EXECUTION_ERROR = "NMAP_EXECUTION_ERROR"
NMAP_NO_RESPONSIVE_HOST = "NMAP_NO_RESPONSIVE_HOST"
NMAP_SUCCESS = "NMAP_SUCCESS"


def run(asset_value: str) -> dict:
    """Run the staged nmap pipeline against an IP, retrying when the
    target appears unresponsive.

    Returns a dict with ``ip``, ``hostnames``, ``os``, ``ports`` (each
    carrying CPE + per-port script output) and ``host_scripts`` keys
    suitable for :func:`app.tools.nmap.parse.parse`.
    """
    ip = asset_value.strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise NmapScanError(f"'{ip}' is not a valid IP address — nmap requires an IP") from None

    with _nmap_slot():
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            attempt_started = time.monotonic()
            try:
                result = _scan_once(ip)
            except NmapNoResponsiveHostError as e:
                retrying = attempt < _MAX_ATTEMPTS
                _logger.info(
                    "nmap attempt %d/%d target=%s status=no_responsive_host "
                    "duration=%.1fs host_element=%s reason=%s%s",
                    attempt,
                    _MAX_ATTEMPTS,
                    ip,
                    time.monotonic() - attempt_started,
                    e.host_element_found,
                    e,
                    f" — retrying in {_RETRY_DELAY_S:.0f}s" if retrying else "",
                )
                if retrying:
                    time.sleep(_RETRY_DELAY_S)
                continue
            except NmapScanError as e:
                # NmapNoResponsiveHostError was handled above; anything else
                # here is an execution problem — never retried, and logged
                # with the attempt's classification for the record.
                _logger.error(
                    "nmap attempt %d/%d target=%s status=%s duration=%.1fs error=%s",
                    attempt,
                    _MAX_ATTEMPTS,
                    ip,
                    NMAP_EXECUTION_ERROR,
                    time.monotonic() - attempt_started,
                    e,
                )
                raise

            _logger.info(
                "nmap attempt %d/%d target=%s status=%s duration=%.1fs open_ports=%d",
                attempt,
                _MAX_ATTEMPTS,
                ip,
                NMAP_SUCCESS,
                time.monotonic() - attempt_started,
                len(result["ports"]),
            )
            return result

    _logger.warning(
        "nmap final classification %s for %s after %d attempt(s)",
        NMAP_NO_RESPONSIVE_HOST,
        ip,
        _MAX_ATTEMPTS,
    )
    raise NmapNoResponsiveHostError(_NO_RESPONSIVE_HOST_MSG)


def _scan_once(ip: str) -> dict:
    """Run the three-stage pipeline once.

    Stage 1 decides responsiveness; stages 2 and 3 are best-effort
    enrichment — a host that goes quiet between stages falls back to the
    previous stage's data instead of failing the scan.
    """
    discovery = _run_nmap(_stage1_args(), ip, stage="discovery")
    # _run_nmap already raises NmapNoResponsiveHostError when the host is
    # absent/down or no open ports came back — reaching here means the
    # stage 1 port list is non-empty.
    port_list = ",".join(str(p["port"]) for p in discovery["ports"])

    versioned: dict | None = None
    try:
        versioned = _run_nmap(_stage2_args(port_list), ip, stage="version")
    except NmapNoResponsiveHostError:
        _logger.warning("nmap stage 2 (versions) saw no host for %s — keeping stage 1 data", ip)

    enriched: dict | None = None
    try:
        enriched = _run_nmap(_stage3_args(port_list, ip), ip, stage="nse")
    except NmapNoResponsiveHostError:
        _logger.warning("nmap stage 3 (NSE) saw no host for %s — keeping stage 1-2 data", ip)

    return _merge_stages(discovery, versioned, enriched)


def _stage1_args() -> list[str]:
    """Host/port discovery: light connect scan, no versioning or scripts.

    ``-Pn`` skips the ping-based host discovery — that is exactly the
    step that wrongly concluded "host down" on a throttled target, since
    a filtered ICMP + TCP probe makes nmap skip the port scan entirely.
    The connect scan itself is the reliable signal.
    """
    return [
        "-sT",
        "-Pn",
        "-T4",
        "--top-ports",
        _TOP_PORTS,
        "--host-timeout",
        _STAGE1_HOST_TIMEOUT,
    ]


def _stage2_args(port_list: str) -> list[str]:
    """Service/version detection + OS fingerprinting on known-open ports."""
    return [
        "-sT",
        "-Pn",
        "-sV",
        "-sC",
        "-O",
        "--osscan-guess",
        "-T4",
        "-p",
        port_list,
        "--host-timeout",
        _STAGE2_HOST_TIMEOUT,
    ]


def _stage3_args(port_list: str, ip: str) -> list[str]:
    """NSE enrichment (vulners, http-title, ssl-cert, …) on known-open
    ports.  ``-sV`` lets the vulners script pick the right CVE feed."""
    args = [
        "-sT",
        "-Pn",
        "-sV",
        "-T4",
        "-p",
        port_list,
        "--host-timeout",
        _STAGE3_HOST_TIMEOUT,
        "--script",
        _NMAP_SCRIPTS,
    ]

    # SNI-strict hosts (Cloudflare edge, most CDNs) refuse TLS handshakes
    # that don't carry a known hostname, which silences every ssl-* script.
    # When the IP has a PTR record, use it as the SNI name so ssl-cert /
    # ssl-enum-ciphers can still report. Best-effort — no PTR, no SNI,
    # and the other scripts (http-title, …) still run.
    sni_name = _resolve_sni_hostname(ip)
    if sni_name:
        args += ["--script-args", f"tls.servername={sni_name}"]

    return args


def _run_nmap(extra_args: list[str], ip: str, stage: str = "") -> dict:
    """Run one nmap invocation and parse its XML.

    Raises ``NmapScanError`` for execution problems (binary missing,
    non-zero exit, unparseable output) and ``NmapNoResponsiveHostError``
    when the target didn't answer (host down, filtered, or a timeout
    that produced no usable output).  On timeout, the partial XML is
    parsed instead of being discarded.
    """
    cmd = [_NMAP_BIN, "-oX", "-", *extra_args, ip]
    invocation_started = time.monotonic()
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

    # Per-invocation trace: which stage, how it ended (exit code or
    # timeout) and how long it took.  The command itself only ever
    # contains flags + the target IP, but it isn't logged anyway — the
    # stage label is enough to reproduce a run.
    _logger.info(
        "nmap invocation target=%s stage=%s status=%s duration=%.1fs output_bytes=%d",
        ip,
        stage or "scan",
        "timeout" if timed_out else f"exit={proc.returncode}",
        time.monotonic() - invocation_started,
        len(stdout),
    )

    if not timed_out and proc.returncode != 0:
        raise NmapScanError(
            f"nmap exited with code {proc.returncode} for {ip}" + (f": {stderr}" if stderr else "")
        )

    try:
        if not stdout.strip():
            if timed_out:
                raise NmapNoResponsiveHostError(
                    f"nmap timed out after {_NMAP_TIMEOUT_S}s for {ip} with no output",
                    host_element_found=False,
                )
            raise NmapScanError(f"nmap produced no output for {ip}")
        return _parse_nmap_xml(stdout.strip())
    except NmapNoResponsiveHostError:
        raise
    except Exception as e:
        raise NmapScanError(f"Failed to parse nmap XML output for {ip}: {e}") from e


def _parse_nmap_xml(xml_string: str) -> dict:
    """Parse nmap ``-sT`` XML output into a structured dict.

    Raises ``NmapNoResponsiveHostError`` when the host is down, absent,
    or has no open ports — never ``NmapScanError``: the XML parsed fine,
    the target simply had nothing to give.
    """
    root = ET.fromstring(xml_string)

    host_elem = root.find("host")
    if host_elem is None:
        raise NmapNoResponsiveHostError("nmap XML has no <host> element", host_element_found=False)

    status_elem = host_elem.find("status")
    if status_elem is None or status_elem.get("state") != "up":
        raise NmapNoResponsiveHostError(
            "nmap XML <host> status is not 'up'", host_element_found=True
        )

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
    os_accuracy: str | None = None
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name")
            os_accuracy = osmatch.get("accuracy")

    ports: list[dict] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_elem.find("service")
            cpe = None
            if service is not None:
                cpe_elem = service.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    cpe = cpe_elem.text
            scripts = {}
            for script_elem in port_elem.findall("script"):
                output = script_elem.get("output") or ""
                if output:
                    scripts[script_elem.get("id", "")] = output
            ports.append(
                {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state.get("state", "open"),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "extrainfo": service.get("extrainfo", "") if service is not None else "",
                    "cpe": cpe,
                    "scripts": scripts,
                }
            )

    host_scripts: dict[str, str] = {}
    hostscript_elem = host_elem.find("hostscript")
    if hostscript_elem is not None:
        for script_elem in hostscript_elem.findall("script"):
            output = script_elem.get("output") or ""
            if output:
                host_scripts[script_elem.get("id", "")] = output

    if not ports:
        raise NmapNoResponsiveHostError(
            "nmap XML <host> is up but reports no open ports", host_element_found=True
        )

    return {
        "ip": ip,
        "hostnames": hostnames,
        "os": os_name,
        "os_accuracy": os_accuracy,
        "ports": ports,
        "host_scripts": host_scripts,
    }


def _merge_stages(discovery: dict, versioned: dict | None, enriched: dict | None) -> dict:
    """Merge the three stages into one result dict.

    Stage 1 provides the port list; stage 2 fills in service/product/
    version/CPE/OS; stage 3 attaches NSE script outputs (per-port and
    host-level).  Later stages may be None (host went quiet) — the data
    from earlier stages is kept.
    """
    result: dict = {
        "ip": discovery.get("ip", "unknown"),
        "hostnames": discovery.get("hostnames") or [],
        "os": discovery.get("os"),
        "os_accuracy": discovery.get("os_accuracy"),
        "ports": [],
        "host_scripts": dict(discovery.get("host_scripts") or {}),
    }

    ports_by_key = {
        (p.get("protocol", "tcp"), p.get("port")): p for p in (discovery.get("ports") or [])
    }

    for stage in (versioned, enriched):
        if not stage:
            continue
        if stage.get("os"):
            result["os"] = stage["os"]
            result["os_accuracy"] = stage.get("os_accuracy")
        for port in stage.get("ports") or []:
            key = (port.get("protocol", "tcp"), port.get("port"))
            target = ports_by_key.get(key)
            if target is None:
                ports_by_key[key] = port
                continue
            # Version stage fills service/product/version; script stage adds scripts.
            for field in ("service", "product", "version", "extrainfo", "cpe"):
                if port.get(field) and not target.get(field):
                    target[field] = port[field]
            target.setdefault("scripts", {}).update(port.get("scripts") or {})
        result["host_scripts"].update(stage.get("host_scripts") or {})

    result["ports"] = sorted(
        ports_by_key.values(), key=lambda p: (p.get("protocol", "tcp"), p.get("port", 0))
    )
    return result


def _resolve_sni_hostname(ip: str) -> str | None:
    """Best-effort PTR hostname for *ip*, to use as the TLS SNI name.

    Mirrors the resolver fallback chain of the reverse_dns tool: system
    resolver first, then public resolvers. Returns None on any failure —
    the scan proceeds without an SNI name.
    """
    try:
        query_name = dns.reversename.from_address(ip)
        for nameserver in (None, "1.1.1.1", "8.8.8.8"):
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            if nameserver:
                resolver.nameservers = [nameserver]
            try:
                answer = resolver.resolve(query_name, "PTR")
                return str(answer[0].target).rstrip(".")
            except dns.exception.DNSException:
                continue
    except Exception:
        pass
    return None


# ── Redis token semaphore ─────────────────────────────────────────────
# Prefork workers share no memory, so a module-level semaphore can't
# cap nmap across the fleet.  Tokens live in Redis: acquire = BLPOP,
# release = RPUSH.  Best-effort — if Redis is unavailable the scan runs
# without a cap (and logs it) rather than failing.
#
# Known trade-off: a token held by a process that is killed mid-scan is
# lost until the Redis key expires or the pool is re-initialized.  The
# per-invocation timeout bounds how long a slot can be held, which keeps
# this rare in practice.


class _QueueTimeout(Exception):
    pass


@contextmanager
def _nmap_slot():
    """Context manager limiting concurrent nmap executions."""
    client = _redis_client()
    if client is None:
        yield
        return

    try:
        token = _acquire_token(client)
    except _QueueTimeout:
        raise NmapRateLimitError(
            f"nmap queue saturée — aucune place libre après {_NMAP_SLOT_WAIT_S}s"
        ) from None
    except Exception as e:  # pragma: no cover — Redis down is an env issue
        _logger.warning("nmap semaphore unavailable (%s) — running without concurrency cap", e)
        yield
        return

    try:
        yield
    finally:
        client.rpush(_NMAP_TOKENS_KEY, token)


def _acquire_token(client) -> str:
    """Block until a nmap slot is free, up to ``_NMAP_SLOT_WAIT_S``."""
    # One-time pool init — SETNX ensures only one process creates it.
    if client.set(_NMAP_SEMAPHORE_INIT_KEY, "1", nx=True):
        client.rpush(_NMAP_TOKENS_KEY, *[f"nmap-{i}" for i in range(_MAX_CONCURRENT_NMAP)])

    deadline = time.monotonic() + _NMAP_SLOT_WAIT_S
    while True:
        # The BLPOP timeout must stay below the client's socket_timeout
        # (10 s): redis-py raises TimeoutError when a blocking read
        # exceeds socket_timeout, which would land in the generic
        # "semaphore unavailable" fallback and silently disable the cap.
        # A short BLPOP + the poll loop above keeps the wait bounded and
        # the cap engaged.
        token = client.blpop(_NMAP_TOKENS_KEY, timeout=5)
        if token:
            return token[1].decode()
        if time.monotonic() >= deadline:
            raise _QueueTimeout()


@lru_cache(maxsize=1)
def _redis_client():
    """Lazily build the Redis client (avoids a broker dependency at
    import time for pure unit tests).  None when Redis is unavailable."""
    url = os.environ.get("REDIS_URL")
    if not url:
        return None
    try:
        import redis

        return redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=10)
    except Exception:  # pragma: no cover
        return None
