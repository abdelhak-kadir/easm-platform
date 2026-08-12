import csv
import glob
import logging
import re
import subprocess
import tempfile

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_HOLEHE_TIMEOUT_S = 90
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class HoleheScanError(ToolScanError):
    """Raised when a holehe lookup can't be completed."""


class HoleheRateLimitError(HoleheScanError, ToolRateLimitError):
    """Raised when holehe times out — many of its 100+ checks may be
    transiently rate-limited by target services; safe to retry."""


class HoleheNoDataError(HoleheScanError, ToolNoDataError):
    """Raised when the email isn't registered on any checked service."""


def run(asset_value: str) -> dict:
    """
    Check which of holehe's 100+ supported services an email address
    is registered on.

    holehe's CLI has no stdout JSON mode -- its only machine-readable
    output is `-C`, which writes a `holehe_{timestamp}_{email}_results.csv`
    file into the current working directory. This runs holehe inside a
    scratch temp dir (so the CSV lands somewhere predictable and is
    cleaned up automatically) and parses that file -- the same
    "subprocess writes a file, we read the file" pattern theHarvester's
    CLI phase already uses.
    """
    email = asset_value.strip()

    if not _EMAIL_RE.match(email):
        raise HoleheScanError(f"'{email}' is not a valid email address")

    with tempfile.TemporaryDirectory() as tmp:
        timed_out = False
        try:
            subprocess.run(
                ["holehe", email, "-C"],
                cwd=tmp,
                timeout=_HOLEHE_TIMEOUT_S,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            _logger.info(
                "holehe timed out after %ds for %s — attempting to parse partial CSV",
                _HOLEHE_TIMEOUT_S,
                email,
            )
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            detail = f": {stderr}" if stderr else ""
            raise HoleheScanError(f"holehe exited {e.returncode} for {email}{detail}") from e
        except FileNotFoundError:
            raise HoleheScanError(
                "holehe binary not found on PATH — install via `pip install holehe`"
            ) from None
        except OSError as e:
            raise HoleheScanError(f"holehe OS error for {email}: {e}") from e

        csv_files = glob.glob(f"{tmp}/holehe_*_results.csv")
        if not csv_files:
            if timed_out:
                raise HoleheRateLimitError(
                    f"holehe timed out after {_HOLEHE_TIMEOUT_S}s for {email} "
                    f"with no partial CSV output"
                )
            raise HoleheNoDataError(f"No holehe results produced for {email}")

        rows = _read_csv(csv_files[0])

    services = [
        {
            "name": row.get("name", ""),
            "domain": row.get("domain") or row.get("name", ""),
            "emailrecovery": row.get("emailrecovery") or None,
            "phoneNumber": row.get("phoneNumber") or None,
        }
        for row in rows
        if _row_is_used(row)
    ]

    if not services:
        raise HoleheNoDataError(f"Email {email} is not registered on any checked service")

    return {"email": email, "services": services}


def _read_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _row_is_used(row: dict) -> bool:
    """holehe's CSV `exists` column is the literal string 'True'/'False'."""
    return str(row.get("exists", "")).strip().lower() == "true"
