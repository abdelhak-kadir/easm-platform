import logging
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_SUBFINDER_TIMEOUT_S = 180  # generous timeout for passive enumeration
_SUBFINDER_SOURCE_TIMEOUT = "30"  # per-source timeout passed to subfinder -timeout flag


class SubfinderScanError(ToolScanError):
    """Raised when subfinder enumeration fails."""


class SubfinderNoDataError(SubfinderScanError, ToolNoDataError):
    """Raised when subfinder finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via Subfinder CLI.

    Shells out to ``subfinder -d <domain> -silent -timeout <n>`` and
    returns discovered hostnames. Follows the same subprocess-with-timeout
    pattern as theHarvester — timeouts, crashes, and missing binaries all
    raise (unlike theHarvester's CLI which is a complementary source;
    Subfinder *is* the tool, so a broken install must not masquerade as
    "no data").
    """
    domain = asset_value.strip().lower().rstrip(".")

    # Wildcard domains are not queryable — reject early.
    if "*" in domain:
        raise SubfinderNoDataError(f"Wildcard domains are not queryable: {domain}")

    try:
        proc = subprocess.run(
            [
                "subfinder",
                "-d",
                domain,
                "-silent",
                "-timeout",
                _SUBFINDER_SOURCE_TIMEOUT,
            ],
            timeout=_SUBFINDER_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.TimeoutExpired as e:
        raise SubfinderScanError(
            f"Subfinder timed out after {_SUBFINDER_TIMEOUT_S}s for {domain}"
        ) from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise SubfinderScanError(f"Subfinder exited {e.returncode} for {domain}{detail}") from e
    except FileNotFoundError:
        raise SubfinderScanError(
            "Subfinder binary not found on PATH — install via "
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ) from None
    except OSError as e:
        raise SubfinderScanError(f"Subfinder OS error for {domain}: {e}") from e

    hosts = sorted(_filter_subdomains(proc.stdout.splitlines(), domain))

    if not hosts:
        raise SubfinderNoDataError(f"No subdomains found for {domain}")

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
