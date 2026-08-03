import logging
import re
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_AMASS_TIMEOUT_S = 900  # 15 min — passive enum is slow but -timeout 10 caps it
_AMASS_SOURCE_TIMEOUT = "10"  # minutes, passed to amass -timeout flag

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

    try:
        proc = subprocess.run(
            [
                "amass",
                "enum",
                "-passive",
                "-nocolor",
                "-timeout",
                _AMASS_SOURCE_TIMEOUT,
                "-d",
                domain,
            ],
            timeout=_AMASS_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.TimeoutExpired as e:
        raise AmassScanError(f"Amass enum timed out after {_AMASS_TIMEOUT_S}s for {domain}") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise AmassScanError(f"Amass enum exited {e.returncode} for {domain}{detail}") from e
    except FileNotFoundError:
        raise AmassScanError(
            "Amass binary not found on PATH — install via "
            "go install github.com/owasp-amass/amass/v4/...@latest"
        ) from None
    except OSError as e:
        raise AmassScanError(f"Amass enum OS error for {domain}: {e}") from e

    hosts = sorted(_filter_subdomains(_extract_fqdns(proc.stdout), domain))

    if not hosts:
        raise AmassNoDataError(f"No subdomains found for {domain}")

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
