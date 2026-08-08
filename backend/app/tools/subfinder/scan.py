import logging
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_SUBFINDER_TIMEOUT_S = 120  # 2 min — passive enum via public APIs
_SUBFINDER_SOURCE_TIMEOUT = "30"  # seconds per source, passed to subfinder -timeout


class SubfinderScanError(ToolScanError):
    """Raised when subfinder enumeration fails."""


class SubfinderNoDataError(SubfinderScanError, ToolNoDataError):
    """Raised when subfinder finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via Subfinder CLI.

    Shells out to ``subfinder -d <domain> -silent -timeout <n>`` and
    returns discovered hostnames.  Non-zero exit codes are logged but
    partial output is parsed anyway — Subfinder sometimes exits 1 after
    transient source failures while still producing valid results.
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
    ]

    _logger.info(
        "Subfinder starting for %s (timeout=%ds, source_timeout=%ss)",
        domain,
        _SUBFINDER_TIMEOUT_S,
        _SUBFINDER_SOURCE_TIMEOUT,
    )

    try:
        proc = subprocess.run(
            cmd,
            timeout=_SUBFINDER_TIMEOUT_S,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as e:
        _logger.error("Subfinder timed out after %ds for %s", _SUBFINDER_TIMEOUT_S, domain)
        raise SubfinderScanError(
            f"Subfinder timed out after {_SUBFINDER_TIMEOUT_S}s for {domain}"
        ) from e
    except FileNotFoundError:
        _logger.error("Subfinder binary not found on PATH")
        raise SubfinderScanError(
            "Subfinder binary not found on PATH — install via "
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ) from None
    except OSError as e:
        _logger.error("Subfinder OS error for %s: %s", domain, e)
        raise SubfinderScanError(f"Subfinder OS error for {domain}: {e}") from e

    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        _logger.warning(
            "Subfinder exited %d for %s (stderr: %s)",
            proc.returncode,
            domain,
            stderr[:500] if stderr else "(empty)",
        )

    hosts = sorted(_filter_subdomains(proc.stdout.splitlines(), domain))

    if not hosts:
        detail = ""
        if stderr:
            detail = f": {stderr[:200]}"
        _logger.info("Subfinder found no subdomains for %s%s", domain, detail)
        raise SubfinderNoDataError(f"No subdomains found for {domain}{detail}")

    _logger.info("Subfinder found %d subdomain(s) for %s", len(hosts), domain)

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
