import logging
import re
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

# Amass v4 produces subdomain results quickly (5-10 s) but then hangs
# indefinitely while resolving A/AAAA/NS records of every node in the
# edge graph.  A 90 s timeout catches the useful output and kills the
# tail-end DNS resolution.  If stdout is non-empty after the kill we
# treat it as a clean completion, not a failure.
_AMASS_TIMEOUT_S = 90

# Per-source timeout passed to amass -timeout (minutes).  2 min is
# generous — most APIs respond in 10-30 s.
_AMASS_SOURCE_TIMEOUT = "2"

# Amass v4 edge-format line: ``source (FQDN) --> relation --> target (FQDN)``
# Extract every ``name (FQDN)`` token from these lines.
_FQDN_RE = re.compile(r"(\S+)\s+\(FQDN\)")


class AmassScanError(ToolScanError):
    """Raised when Amass enumeration fails."""


class AmassNoDataError(AmassScanError, ToolNoDataError):
    """Raised when Amass finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via OWASP Amass CLI (v4).

    Amass v4 outputs edge-format results to stdout::

        sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)

    We extract every FQDN token, filter to subdomains of the target, and
    discard the edge-relationship metadata.

    **Important**: Amass v4 does NOT exit cleanly with ``-passive`` — it
    keeps running DNS resolution on non-subdomain nodes (NS records, ASN
    edges, netblocks) long after the subdomain results are emitted.  The
    subprocess timeout is deliberately tight and treated as a **normal
    completion path** — if stdout was captured before the kill we parse
    it and return results.
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

    stdout = ""
    stderr = ""
    timed_out = False

    try:
        proc = subprocess.run(
            cmd,
            timeout=_AMASS_TIMEOUT_S,
            capture_output=True,
            text=True,
        )
        stdout = proc.stdout or ""
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            _logger.warning(
                "Amass enum exited %d for %s (stderr: %s)",
                proc.returncode,
                domain,
                stderr[:500] if stderr else "(empty)",
            )
    except subprocess.TimeoutExpired as e:
        # Amass v4 hangs after producing subdomain output — this is
        # EXPECTED behaviour.  Read whatever it wrote to stdout before
        # the kill and treat it as a successful partial result.
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        timed_out = True
        _logger.info(
            "Amass enum timed out after %ds for %s — parsing partial output (%d bytes)",
            _AMASS_TIMEOUT_S,
            domain,
            len(stdout),
        )
    except subprocess.CalledProcessError as e:
        _logger.error("Amass enum exited %d for %s", e.returncode, domain)
        raise AmassScanError(f"Amass exited {e.returncode} for {domain}") from e
    except FileNotFoundError:
        _logger.error("Amass binary not found on PATH")
        raise AmassScanError(
            "Amass binary not found on PATH — install via "
            "go install github.com/owasp-amass/amass/v4/...@latest"
        ) from None
    except OSError as e:
        _logger.error("Amass enum OS error for %s: %s", domain, e)
        raise AmassScanError(f"Amass enum OS error for {domain}: {e}") from e

    hosts = sorted(_filter_subdomains(_extract_fqdns(stdout), domain))

    if not hosts:
        detail = ""
        if stderr:
            detail = f": {stderr[:200]}"
        if timed_out:
            detail = (
                f" (timed out after {_AMASS_TIMEOUT_S}s, no subdomains in partial output){detail}"
            )
        _logger.info("Amass enum found no subdomains for %s%s", domain, detail)
        raise AmassNoDataError(f"No subdomains found for {domain}{detail}")

    _logger.info(
        "Amass enum found %d subdomain(s) for %s%s",
        len(hosts),
        domain,
        " (partial output after timeout)" if timed_out else "",
    )

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
