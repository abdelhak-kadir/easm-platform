import csv
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from app.tools.holehe.scan import (
    HoleheNoDataError,
    HoleheRateLimitError,
    HoleheScanError,
    run,
)


def _write_holehe_csv(tmp_path, email, rows):
    path = tmp_path / f"holehe_123_{email}_results.csv"
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "name",
                "domain",
                "rateLimit",
                "exists",
                "emailrecovery",
                "phoneNumber",
                "others",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    return path


@patch("app.tools.holehe.scan.subprocess.run")
@patch("app.tools.holehe.scan.tempfile.TemporaryDirectory")
def test_run_returns_used_services(mock_tmpdir, mock_run, tmp_path):
    mock_tmpdir.return_value.__enter__.return_value = str(tmp_path)
    _write_holehe_csv(
        tmp_path,
        "user@example.com",
        [
            {"name": "twitter", "domain": "twitter.com", "exists": "True"},
            {"name": "netflix", "domain": "netflix.com", "exists": "False"},
        ],
    )
    mock_run.return_value = MagicMock()

    result = run("user@example.com")

    assert result["email"] == "user@example.com"
    assert len(result["services"]) == 1
    assert result["services"][0]["name"] == "twitter"


def test_run_raises_on_invalid_email():
    with pytest.raises(HoleheScanError, match="not a valid email"):
        run("not-an-email")


@patch("app.tools.holehe.scan.subprocess.run")
def test_run_raises_rate_limit_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("holehe", 90)
    with pytest.raises(HoleheRateLimitError, match="timed out"):
        run("user@example.com")


@patch("app.tools.holehe.scan.subprocess.run")
def test_run_raises_scan_error_on_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError()
    with pytest.raises(HoleheScanError, match="not found on PATH"):
        run("user@example.com")


@patch("app.tools.holehe.scan.subprocess.run")
@patch("app.tools.holehe.scan.tempfile.TemporaryDirectory")
def test_run_raises_no_data_when_no_service_used(mock_tmpdir, mock_run, tmp_path):
    mock_tmpdir.return_value.__enter__.return_value = str(tmp_path)
    _write_holehe_csv(
        tmp_path,
        "user@example.com",
        [
            {"name": "netflix", "domain": "netflix.com", "exists": "False"},
        ],
    )
    mock_run.return_value = MagicMock()

    with pytest.raises(HoleheNoDataError, match="not registered"):
        run("user@example.com")


@patch("app.tools.holehe.scan.subprocess.run")
@patch("app.tools.holehe.scan.tempfile.TemporaryDirectory")
def test_run_raises_no_data_when_no_csv_produced(mock_tmpdir, mock_run, tmp_path):
    mock_tmpdir.return_value.__enter__.return_value = str(tmp_path)
    mock_run.return_value = MagicMock()

    with pytest.raises(HoleheNoDataError, match="No holehe results"):
        run("user@example.com")


def test_rate_limit_is_tool_rate_limit():
    from app.tools.base import ToolRateLimitError

    assert issubclass(HoleheRateLimitError, ToolRateLimitError)


def test_nodata_is_tool_nodata():
    from app.tools.base import ToolNoDataError

    assert issubclass(HoleheNoDataError, ToolNoDataError)
