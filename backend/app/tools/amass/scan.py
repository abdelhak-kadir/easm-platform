import logging
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_AMASS_TIMEOUT_S = 900  # 15 min — passive enum is slow but -timeout 10 caps it
_AMASS_SOURCE_TIMEOUT = "10"  # minutes, passed to amass -timeout flag
_OAM_SUBS_TIMEOUT_S = 120


class AmassScanError(ToolScanError):
    """Raised when Amass enumeration fails."""


class AmassNoDataError(AmassScanError, ToolNoDataError):
    """Raised when Amass finds nothing — target may have no subdomains."""


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via OWASP Amass CLI.

    Two-step process:
    1. ``amass enum --passive -d <domain> -timeout <n>`` — writes results
       into Amass's local datastore (``$HOME/.config/amass/output/``).
    2. ``oam_subs -names -d <domain>`` — reads names back from the datastore.

    The Amass datastore is local to the container; concurrent Celery workers
    share it safely because Amass writes per-domain files internally.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if "*" in domain:
        raise AmassNoDataError(f"Wildcard domains are not queryable: {domain}")

    # Step 1 — passive enumeration (writes to datastore)
    try:
        subprocess.run(
            [
                "amass",
                "enum",
                "--passive",
                "-nocolor",
                "-timeout",
                _AMASS_SOURCE_TIMEOUT,
                "-d",
                domain,
            ],
            timeout=_AMASS_TIMEOUT_S,
            capture_output=True,
            check=True,
        )
    except subprocess.TimeoutExpired as e:
        raise AmassScanError(f"Amass enum timed out after {_AMASS_TIMEOUT_S}s for {domain}") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        detail = f": {stderr}" if stderr else ""
        raise AmassScanError(f"Amass enum exited {e.returncode} for {domain}{detail}") from e
    except FileNotFoundError:
        raise AmassScanError(
            "Amass binary not found on PATH — install via "
            "go install github.com/owasp-amass/amass/v4/...@latest"
        ) from None
    except OSError as e:
        raise AmassScanError(f"Amass enum OS error for {domain}: {e}") from e

    # Step 2 — extract names from the datastore
    try:
        proc = subprocess.run(
            ["oam_subs", "-names", "-d", domain],
            timeout=_OAM_SUBS_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.TimeoutExpired as e:
        raise AmassScanError(f"oam_subs timed out after {_OAM_SUBS_TIMEOUT_S}s for {domain}") from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise AmassScanError(f"oam_subs exited {e.returncode} for {domain}{detail}") from e
    except FileNotFoundError:
        raise AmassScanError(
            "oam_subs binary not found on PATH — it is bundled with Amass v4+; "
            "ensure amass is installed and symlinked as oam_subs"
        ) from None
    except OSError as e:
        raise AmassScanError(f"oam_subs OS error for {domain}: {e}") from e

    hosts = sorted(_filter_subdomains(proc.stdout.splitlines(), domain))

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


def _filter_subdomains(lines: list[str], domain: str) -> set[str]:
    """Keep only hostnames that belong to the target domain."""
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
