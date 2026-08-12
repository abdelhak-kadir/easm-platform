import json
import logging
import subprocess

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_HTTPX_TIMEOUT_S = 90
_HTTPX_PER_TARGET_TIMEOUT = "15"  # seconds, passed to httpx -timeout flag


class HttpxScanError(ToolScanError):
    """Raised when an httpx probe fails."""


class HttpxNoDataError(HttpxScanError, ToolNoDataError):
    """Raised when httpx finds no live HTTP service — target may not serve HTTP(S)."""


def run(asset_value: str) -> dict:
    """HTTP/HTTPS liveness probe via ProjectDiscovery httpx CLI.

    Runs ``httpx -u <target>`` (single-target mode) so the per-asset tool
    contract is respected — one ScanJob per subdomain/IP, versioned
    ScanResult history, and Celery-level concurrency.

    Returns parsed JSON with status code, title, technologies, server
    headers, IP, CDN, and redirect location when available.
    """
    target = asset_value.strip().lower().rstrip(".")

    stdout = ""
    stderr = ""
    timed_out = False

    try:
        proc = subprocess.run(
            [
                "httpx",
                "-u",
                target,
                "-silent",
                "-json",
                "-timeout",
                _HTTPX_PER_TARGET_TIMEOUT,
                "-follow-redirects",
                "-tech-detect",
                "-title",
                "-status-code",
                "-ip",
                "-server",
                "-cdn",
                "-websocket",
                "-location",
            ],
            timeout=_HTTPX_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=True,
        )
        stdout = proc.stdout or ""
        stderr = _to_str(proc.stderr)
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        timed_out = True
        _logger.info(
            "httpx timed out after %ds for %s — parsing partial output (%d bytes)",
            _HTTPX_TIMEOUT_S,
            target,
            len(stdout),
        )
    except subprocess.CalledProcessError as e:
        # httpx exits non-zero when no live host is found — that's
        # a clean "no data" outcome, not a failure.
        stderr = _to_str(e.stderr)
        stdout = _to_str(e.stdout)
        if "no host found" in stderr.lower() or "no host found" in stdout.lower():
            raise HttpxNoDataError(f"No HTTP(S) service found for {target}") from e
        raise HttpxScanError(f"httpx exited {e.returncode} for {target}: {stderr}") from e
    except FileNotFoundError:
        raise HttpxScanError(
            "httpx binary not found on PATH — install via "
            "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ) from None
    except OSError as e:
        raise HttpxScanError(f"httpx OS error for {target}: {e}") from e

    # httpx -json emits one JSON object per line (JSONL) when there are
    # multiple results (e.g. http + https redirect chains).
    responses: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            responses.append(json.loads(line))
        except ValueError:
            _logger.debug("httpx: skipping non-JSON output line for %s: %.120s", target, line)

    if not responses:
        if timed_out:
            raise HttpxScanError(
                f"httpx timed out after {_HTTPX_TIMEOUT_S}s for {target} " f"with no partial output"
            )
        raise HttpxNoDataError(f"No HTTP(S) service found for {target}")

    return {
        "target": target,
        "responses": responses,
        "sources_used": ["httpx"],
    }


# ── helpers ───────────────────────────────────────────────────────────


def _to_str(value: str | bytes | None) -> str:
    """Normalise stderr/stdout from subprocess (may be bytes or str)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
