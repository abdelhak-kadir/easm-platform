import ipaddress
import json
import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

# Certificate Transparency — the one source that actually works reliably.
# Every other "source" in theHarvester is either an HTML scraper (fragile,
# breaks when upstream changes), requires an API key, or rate-limits
# aggressively. CRT.sh is a public JSON API: no auth, no scraping, 1–5 s.
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_CRTSH_TIMEOUT_S = 30

# crt.sh goes down (502/504) or rate-limits fairly often. Retry a few
# times with backoff before giving up — most outages last seconds, not
# minutes, and this avoids burning a Celery-level retry for nothing.
_CRTSH_MAX_ATTEMPTS = 3
_CRTSH_RETRY_DELAYS_S = (2, 5)

# theHarvester CLI — complementary source, run via subprocess for isolation.
# API-based sources only: duckduckgo and bing are HTML scrapers that are
# slow, break when upstream changes, and regularly push the whole CLI run
# past the 90s timeout. The API sources finish in seconds.
_HARVESTER_TIMEOUT_S = 90
_HARVESTER_SOURCES = "crtsh,otx,threatminer,hackertarget,rapiddns"

# DNS-based extraction: A/AAAA records for each discovered hostname.
# Disabled by default (adds latency proportional to host count) but
# useful when you want IPs alongside subdomains.
_RESOLVE_IPS = False

# Bare-IP regex — crt.sh name_value fields sometimes contain raw IPs
# from cert SAN entries.
_IP_RE = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b" r"|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)


class TheHarvesterScanError(ToolScanError):
    """Raised when a theHarvester search can't be completed."""


class TheHarvesterRateLimitError(TheHarvesterScanError, ToolRateLimitError):
    """Raised when a source engine rate-limits — safe to retry."""


class TheHarvesterNoDataError(TheHarvesterScanError, ToolNoDataError):
    """Raised when no data is found — target may have no public footprint."""


# ── theHarvester CLI (subprocess) ──────────────────────────────────────


def _run_theharvester_cli(domain: str) -> dict | None:
    """Run the real theHarvester CLI as a subprocess, with timeout isolation.

    Returns parsed JSON on success, ``None`` on any failure (timeout, crash,
    missing binary, invalid JSON output, etc.). This is a **complementary**
    source — crt.sh's direct API remains the reliable base path. The CLI adds
    DuckDuckGo, Bing, OTX, ThreatMiner, HackerTarget, and RapidDNS results
    without pulling theHarvester's asyncio event loop into the Celery worker.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "result"  # theHarvester appends .json
        try:
            subprocess.run(
                [
                    "theHarvester",
                    "-d",
                    domain,
                    "-b",
                    _HARVESTER_SOURCES,
                    "-f",
                    str(out_path),
                ],
                timeout=_HARVESTER_TIMEOUT_S,
                capture_output=True,
                check=True,
            )
        except subprocess.TimeoutExpired:
            _logger.warning(
                "theHarvester CLI timed out after %ds for %s — "
                "attempting to read partial output",
                _HARVESTER_TIMEOUT_S,
                domain,
            )
        except subprocess.CalledProcessError as e:
            _logger.warning("theHarvester CLI exited %d for %s: %s", e.returncode, domain, e.stderr)
            return None
        except FileNotFoundError:
            _logger.warning("theHarvester CLI binary not found on PATH — skipping CLI enrichment")
            return None
        except OSError as e:
            _logger.warning("theHarvester CLI OS error for %s: %s", domain, e)
            return None

        json_file = out_path.with_suffix(".json")
        if not json_file.exists():
            _logger.warning("theHarvester CLI produced no output file for %s", domain)
            return None

        try:
            raw = json.loads(json_file.read_text())
        except (ValueError, OSError) as e:
            _logger.warning("theHarvester CLI JSON decode failed for %s: %s", domain, e)
            return None

        if not isinstance(raw, dict):
            _logger.warning("theHarvester CLI returned non-dict JSON for %s", domain)
            return None

        return raw


def run(asset_value: str) -> dict:
    """Passive OSINT discovery against a domain.

    Two-phase collection — **both sources always get a chance**:

    1. **crt.sh direct API** — reliable JSON API, no auth. Errors from
       crt.sh are caught and saved; they only surface if the CLI also
       finds nothing. If the CLI succeeds, crt.sh errors are logged and
       discarded — we have data, no need to retry.

    2. **theHarvester CLI** — complementary subprocess with timeout.
       Runs even when crt.sh is down (502, timeout, etc.). Silently
       skipped on any failure — never the critical path.

    Returns discovered hostnames, IPs, emails, and the list of sources
    that contributed data.
    """
    domain = asset_value.strip().lower().rstrip(".")

    # Wildcard cert entries (e.g. *.example.com) aren't real queryable
    # domains — crt.sh hangs or returns garbage when fed a literal `*`.
    if domain.startswith("*.") or "*" in domain:
        raise TheHarvesterNoDataError(f"Wildcard domains are not queryable: {domain}")

    all_hosts: set[str] = set()
    all_ips: set[str] = set()
    all_emails: set[str] = set()
    sources_used: list[str] = []
    crtsh_error: Exception | None = None

    # ── phase 1: crt.sh (non-fatal — errors are saved, not raised) ────
    try:
        _query_crtsh(domain, all_hosts, all_ips, all_emails)
        sources_used.append("crtsh")
    except TheHarvesterScanError as e:
        crtsh_error = e
        _logger.warning("crt.sh unavailable for %s: %s", domain, e)

    # ── phase 2: theHarvester CLI (always runs) ───────────────────────
    harvester_result = _run_theharvester_cli(domain)
    if harvester_result:
        cli_hosts = harvester_result.get("hosts") or []
        cli_ips = harvester_result.get("ips") or []
        cli_emails = harvester_result.get("emails") or []

        all_hosts.update(_filter_subdomains(cli_hosts, domain))
        all_ips.update(_filter_valid_ips(cli_ips))
        all_emails.update(_filter_domain_emails(cli_emails, domain))

        if cli_hosts or cli_ips or cli_emails:
            sources_used.append("theharvester_cli")

    hosts = sorted(all_hosts)
    ips = sorted(all_ips, key=_ip_sort_key)

    if _RESOLVE_IPS and hosts:
        ips = sorted({*ips, *_resolve_hostnames(hosts)}, key=_ip_sort_key)

    data: dict = {
        "domain": domain,
        "emails": sorted(all_emails),
        "hosts": hosts,
        "ips": ips,
        "urls": [],
        "sources_used": sources_used,
    }

    if not any(data[k] for k in ("emails", "hosts", "ips", "urls")):
        # If crt.sh had a transient error and CLI found nothing, surface
        # the crt.sh error so Celery can retry. If crt.sh had a permanent
        # error (or just found nothing), that's a clean no-data outcome.
        if crtsh_error is not None:
            raise crtsh_error
        raise TheHarvesterNoDataError(f"No public data found for {domain}")

    return data


# ── CRT.sh ────────────────────────────────────────────────────────────


def _query_crtsh(
    domain: str,
    hosts: set[str],
    ips: set[str],
    emails: set[str],
) -> None:
    """Fetch cert transparency entries from crt.sh and extract hostnames,
    IPs, and email addresses from the name_value / common_name fields."""
    url = _CRTSH_URL.format(domain=domain)
    last_error: Exception | None = None
    for attempt in range(_CRTSH_MAX_ATTEMPTS):
        if attempt:
            time.sleep(_CRTSH_RETRY_DELAYS_S[attempt - 1])
        try:
            resp = requests.get(url, timeout=_CRTSH_TIMEOUT_S)
            resp.raise_for_status()
        except requests.Timeout:
            last_error = TheHarvesterRateLimitError(
                f"CRT.sh request timed out after {_CRTSH_TIMEOUT_S}s for {domain}"
            )
            _logger.warning(
                "crt.sh attempt %d/%d timed out for %s",
                attempt + 1,
                _CRTSH_MAX_ATTEMPTS,
                domain,
            )
            continue
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if status == 404:
                # crt.sh returns bare 404 (not an empty JSON array) when a
                # domain has no certificates in the transparency log — that's
                # a legitimate "nothing found" outcome, not a failure. Leave
                # hosts/ips/emails empty; run()'s existing empty-result check
                # turns that into TheHarvesterNoDataError on its own.
                return
            if status == 429:
                last_error = TheHarvesterRateLimitError(f"CRT.sh rate-limited for {domain}")
                _logger.warning(
                    "crt.sh attempt %d/%d rate-limited for %s",
                    attempt + 1,
                    _CRTSH_MAX_ATTEMPTS,
                    domain,
                )
                continue
            if status >= 500:
                # 502/503/504 are transient server errors — safe to retry
                last_error = TheHarvesterRateLimitError(
                    f"CRT.sh server error ({status}) for {domain}"
                )
                _logger.warning(
                    "crt.sh attempt %d/%d got %d for %s",
                    attempt + 1,
                    _CRTSH_MAX_ATTEMPTS,
                    status,
                    domain,
                )
                continue
            raise TheHarvesterScanError(f"CRT.sh request failed for {domain}: {e}") from e
        except requests.RequestException as e:
            last_error = TheHarvesterScanError(f"CRT.sh request failed for {domain}: {e}")
            _logger.warning(
                "crt.sh attempt %d/%d failed for %s: %s",
                attempt + 1,
                _CRTSH_MAX_ATTEMPTS,
                domain,
                e,
            )
            continue
        break  # request succeeded — parse below
    else:
        # All attempts failed
        assert last_error is not None
        raise last_error

    try:
        entries: list[dict] = resp.json()
    except ValueError:
        return  # empty or malformed response — not an error

    for entry in entries:
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if not value:
                continue
            for name in str(value).splitlines():
                name = name.strip().lower().rstrip(".")
                if not name or name == domain:
                    continue
                if name.startswith("*.") or "*" in name:
                    continue  # wildcard cert — not a real queryable hostname
                if name.endswith(f".{domain}") or name == domain:
                    hosts.add(name)
                elif _IP_RE.fullmatch(name):
                    ips.add(name)
                elif "@" in name and _email_matches_domain(name, domain):
                    emails.add(name)


# ── optional DNS resolution ───────────────────────────────────────────


def _resolve_hostnames(hostnames: list[str]) -> set[str]:
    """Best-effort A/AAAA resolution for discovered hostnames."""
    import socket

    resolved: set[str] = set()
    for host in hostnames:
        try:
            resolved.add(socket.gethostbyname(host))
        except OSError:
            pass
    return resolved


# ── helpers ───────────────────────────────────────────────────────────


def _filter_subdomains(hosts: list[str], domain: str) -> set[str]:
    """Keep only hostnames that belong to the target domain.

    theHarvester CLI can return unrelated third-party domains from search
    engine results — this filters them out so they don't pollute the asset
    discovery pipeline."""
    result: set[str] = set()
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if not h or h == domain:
            continue
        if h.startswith("*.") or "*" in h:
            continue
        if h.endswith(f".{domain}"):
            result.add(h)
    return result


def _filter_valid_ips(raw_ips: list[str]) -> set[str]:
    """Keep only syntactically valid IP addresses from CLI results."""
    result: set[str] = set()
    for raw in raw_ips:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ipaddress.ip_address(raw)
            result.add(raw)
        except ValueError:
            pass
    return result


def _filter_domain_emails(emails: list[str], domain: str) -> set[str]:
    """Keep only emails that plausibly belong to the target domain."""
    return {e.strip().lower() for e in emails if _email_matches_domain(e.strip().lower(), domain)}


def _email_matches_domain(email: str, domain: str) -> bool:
    """Check whether *email* belongs to *domain* (best-effort — only
    compares the last two labels, so it under-handles .co.uk & friends)."""
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    registrable = ".".join(parts[-2:])
    return email.endswith("@" + registrable) or email.endswith("." + registrable)


def _ip_sort_key(ip: str):
    """Sort IPs numerically rather than lexicographically."""
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return ipaddress.ip_address("0.0.0.0")
