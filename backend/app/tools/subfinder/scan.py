import logging
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

# subprocess.run() timeout — hard cap.  If Subfinder runs longer than this
# the process is killed and any partial stdout is parsed.
_SUBFINDER_TIMEOUT_S = 120  # 2 min

# Passed to subfinder -timeout (SECONDS per source, default 30).
_SUBFINDER_SOURCE_TIMEOUT = "30"

# Passed to subfinder -max-time (MINUTES for the whole enumeration, default 10).
# We cap this tightly because the subprocess timeout above is the real hard limit.
_SUBFINDER_MAX_TIME = "2"


class SubfinderScanError(ToolScanError):
    """Raised when subfinder enumeration fails."""


class SubfinderNoDataError(SubfinderScanError, ToolNoDataError):
    """Raised when subfinder finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via Subfinder CLI.

    Shells out to ``subfinder -d <domain> -silent`` and returns discovered
    hostnames.  The subprocess timeout is a hard cap — if Subfinder hangs
    (e.g. a stuck DNS query) the process is killed and any partial output
    is parsed rather than discarded.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if "*" in domain:
        raise SubfinderNoDataError(f"Wildcard domains are not queryable: {domain}")

    cmd = [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-timeout",
        _SUBFINDER_SOURCE_TIMEOUT,
        "-max-time",
        _SUBFINDER_MAX_TIME,
    ]

    _logger.info(
        "Subfinder starting for %s (timeout=%ds, source_timeout=%ss, max_time=%smin)",
        domain,
        _SUBFINDER_TIMEOUT_S,
        _SUBFINDER_SOURCE_TIMEOUT,
        _SUBFINDER_MAX_TIME,
    )

    stdout = ""
    stderr = ""
    timed_out = False

    try:
        proc = subprocess.run(
            cmd,
            timeout=_SUBFINDER_TIMEOUT_S,
            capture_output=True,
            text=True,
        )
        stdout = proc.stdout or ""
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            _logger.warning(
                "Subfinder exited %d for %s (stderr: %s)",
                proc.returncode,
                domain,
                stderr[:500] if stderr else "(empty)",
            )
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        timed_out = True
        _logger.info(
            "Subfinder timed out after %ds for %s — parsing partial output (%d bytes)",
            _SUBFINDER_TIMEOUT_S,
            domain,
            len(stdout),
        )
    except FileNotFoundError:
        _logger.error("Subfinder binary not found on PATH")
        raise SubfinderScanError(
            "Subfinder binary not found on PATH — install via "
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ) from None
    except OSError as e:
        _logger.error("Subfinder OS error for %s: %s", domain, e)
        raise SubfinderScanError(f"Subfinder OS error for {domain}: {e}") from e

    hosts = sorted(_filter_subdomains(stdout.splitlines(), domain))

    if not hosts:
        detail = ""
        if stderr:
            detail = f": {stderr[:200]}"
        if timed_out:
            detail = (
                f" (timed out after {_SUBFINDER_TIMEOUT_S}s,"
                f" no subdomains in partial output){detail}"
            )
        _logger.info("Subfinder found no subdomains for %s%s", domain, detail)
        raise SubfinderNoDataError(f"No subdomains found for {domain}{detail}")

    _logger.info(
        "Subfinder found %d subdomain(s) for %s%s",
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
        "sources_used": ["subfinder"],
    }


# ── helpers ───────────────────────────────────────────────────────────


def _filter_subdomains(lines: list[str], domain: str) -> set[str]:
    """Keep only hostnames that belong to the target domain.

    Subfinder can return garbage lines, empty strings, and wildcard
    entries — this filters them out so they don't pollute the asset
    discovery pipeline.
    """
    result: set[str] = set()
    for line in lines:
        h = line.strip().lower().rstrip(".")
        if not h or h == domain:
            continue
        if h.startswith("*.") or "*" in h:
            continue
        if h.endswith(f".{domain}"):
            result.add(h)
    return result
