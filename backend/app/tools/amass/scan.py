import logging
import re
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

# 120 s is generous for passive enumeration — Amass v4 queries public APIs
# (cr t.sh, AbuseIPDB, etc.) which typically respond within seconds.  If
# it takes longer than this something is wrong (network partition, API
# outage, hung subprocess) and the orchestrator needs the failure signal
# promptly so it can advance the wave.
_AMASS_TIMEOUT_S = 120  # 2 min subprocess timeout

# Passed to amass -timeout (minutes per data source).  3 min is
# conservative — most sources respond within 10-30 s.  This cap
# prevents a single slow source (e.g. a rate-limited API) from
# dragging the whole enumeration past the subprocess timeout.
_AMASS_SOURCE_TIMEOUT = "3"  # minutes

# Amass v4 edge-format line: ``source (FQDN) --> relation --> target (FQDN)``
# Extract every ``name (FQDN)`` token from these lines.
_FQDN_RE = re.compile(r"(\S+)\s+\(FQDN\)")


class AmassScanError(ToolScanError):
    """Raised when Amass enumeration fails."""


class AmassNoDataError(AmassScanError, ToolNoDataError):
    """Raised when Amass finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via OWASP Amass CLI (v4).

    Amass v4 outputs results directly to stdout in edge format::

        sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)

    We extract every FQDN token, filter to subdomains of the target, and
    discard the edge-relationship metadata.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if "*" in domain:
        raise AmassNoDataError(f"Wildcard domains are not queryable: {domain}")

    cmd = [
        "amass",
        "enum",
        "-passive",
        "-nocolor",
        "-timeout",
        _AMASS_SOURCE_TIMEOUT,
        "-d",
        domain,
    ]

    _logger.info(
        "Amass enum starting for %s (timeout=%ds, source_timeout=%smin)",
        domain,
        _AMASS_TIMEOUT_S,
        _AMASS_SOURCE_TIMEOUT,
    )

    try:
        proc = subprocess.run(
            cmd,
            timeout=_AMASS_TIMEOUT_S,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as e:
        _logger.error("Amass enum timed out after %ds for %s", _AMASS_TIMEOUT_S, domain)
        raise AmassScanError(f"Amass enum timed out after {_AMASS_TIMEOUT_S}s for {domain}") from e
    except FileNotFoundError:
        _logger.error("Amass binary not found on PATH")
        raise AmassScanError(
            "Amass binary not found on PATH — install via "
            "go install github.com/owasp-amass/amass/v4/...@latest"
        ) from None
    except OSError as e:
        _logger.error("Amass enum OS error for %s: %s", domain, e)
        raise AmassScanError(f"Amass enum OS error for {domain}: {e}") from e

    # Amass v4 can return non-zero exit codes for transient issues
    # (DNS failures, API rate limits) that still produce partial results.
    # We log the error but try to parse whatever output we got.
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        _logger.warning(
            "Amass enum exited %d for %s (stderr: %s)",
            proc.returncode,
            domain,
            stderr[:500] if stderr else "(empty)",
        )

    hosts = sorted(_filter_subdomains(_extract_fqdns(proc.stdout), domain))

    if not hosts:
        detail = ""
        if stderr:
            detail = f": {stderr[:200]}"
        _logger.info("Amass enum found no subdomains for %s%s", domain, detail)
        raise AmassNoDataError(f"No subdomains found for {domain}{detail}")

    _logger.info("Amass enum found %d subdomain(s) for %s", len(hosts), domain)

    return {
        "domain": domain,
        "hosts": hosts,
        "emails": [],
        "ips": [],
        "urls": [],
        "sources_used": ["amass"],
    }


# ── helpers ───────────────────────────────────────────────────────────


def _extract_fqdns(stdout: str) -> list[str]:
    """Pull every ``name (FQDN)`` token from Amass v4 edge-format output."""
    return _FQDN_RE.findall(stdout)


def _filter_subdomains(names: list[str], domain: str) -> set[str]:
    """Keep only hostnames that belong to the target domain."""
    result: set[str] = set()
    for h in names:
        h = h.strip().lower().rstrip(".")
        if not h or h == domain:
            continue
        if h.startswith("*.") or "*" in h:
            continue
        if h.endswith(f".{domain}"):
            result.add(h)
    return result
