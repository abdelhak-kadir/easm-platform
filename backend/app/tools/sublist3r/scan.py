"""Sublist3r — passive subdomain enumeration via search-engine scraping.

Runs Sublist3r as a subprocess (the Celery worker is a daemon and cannot
spawn child processes from an imported library).  Sublist3r must be
installed at ``/opt/sublist3r`` (see base.Dockerfile).

Bruteforce (subbrute) is explicitly disabled — OSINT-only passive collection.
"""

import logging
import os
import subprocess

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_SOURCES = "google,yahoo,bing,baidu,ask,virustotal,netcraft,dnsdumpster,threatcrowd"
_SUBLIST3R_SCRIPT = "/opt/sublist3r/sublist3r.py"
_TIMEOUT_S = 90


class Sublist3rScanError(ToolScanError):
    pass


class Sublist3rRateLimitError(Sublist3rScanError, ToolRateLimitError):
    pass


class Sublist3rNoDataError(Sublist3rScanError, ToolNoDataError):
    pass


def run(asset_value: str) -> dict:
    """Passive subdomain enumeration via Sublist3r search-engine scraping.

    Runs as a subprocess to avoid Celery daemon restrictions.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain or "*" in domain:
        raise Sublist3rNoDataError(f"Invalid domain: {domain!r}")

    if not os.path.isfile(_SUBLIST3R_SCRIPT):
        raise Sublist3rScanError(
            f"Sublist3r not found at {_SUBLIST3R_SCRIPT} — "
            "clone https://github.com/aboul3la/Sublist3r.git into the image"
        )

    _logger.info("Sublist3r starting for %s — engines: %s (bruteforce disabled)", domain, _SOURCES)

    stdout = ""
    stderr = ""
    timed_out = False

    try:
        proc = subprocess.run(
            [
                "python3",
                _SUBLIST3R_SCRIPT,
                "-d",
                domain,
                "-e",
                _SOURCES,
                "-t",
                "20",  # threads
            ],
            timeout=_TIMEOUT_S,
            capture_output=True,
            text=True,
        )
        stdout = proc.stdout or ""
        stderr = (proc.stderr or "").strip()
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        timed_out = True
        _logger.info(
            "Sublist3r timed out after %ds for %s — parsing partial output (%d bytes)",
            _TIMEOUT_S,
            domain,
            len(stdout),
        )
    except FileNotFoundError as e:
        raise Sublist3rScanError(f"Sublist3r script not found at {_SUBLIST3R_SCRIPT}") from e
    except OSError as e:
        raise Sublist3rScanError(f"Sublist3r OS error: {e}") from e

    # Parse subdomains from stdout — one per line after header lines
    stdout = stdout.strip()
    hosts: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip().lower().rstrip(".")
        # Skip header/status lines
        if not line or line.startswith("[") or line.startswith("[-]") or line.startswith("[*]"):
            continue
        if line.startswith("subdomains found") or line.startswith("Total"):
            continue
        # Valid subdomain
        if line.endswith(f".{domain}") and line != domain and "*" not in line:
            hosts.add(line)

    if not hosts:
        detail = ""
        if stderr:
            detail = f": {stderr[:200]}"
        if timed_out:
            detail = f" (timed out after {_TIMEOUT_S}s, no subdomains in partial output){detail}"
        raise Sublist3rNoDataError(f"No subdomains found for {domain} via search engines{detail}")

    hosts_list = sorted(hosts)
    _logger.info(
        "Sublist3r found %d subdomain(s) for %s%s",
        len(hosts_list),
        domain,
        " (partial output after timeout)" if timed_out else "",
    )

    return {
        "domain": domain,
        "hosts": hosts_list,
        "emails": [],
        "ips": [],
        "urls": [],
        "sources_used": ["sublist3r"],
    }
