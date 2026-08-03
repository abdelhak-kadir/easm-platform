import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.theharvester.scan import (
    TheHarvesterNoDataError,
    TheHarvesterRateLimitError,
    TheHarvesterScanError,
    _filter_domain_emails,
    _filter_subdomains,
    _filter_valid_ips,
    _run_theharvester_cli,
    run,
)

# ── helpers ───────────────────────────────────────────────────────────


def _crtsh_response(*name_values: str) -> list[dict]:
    """Build a crt.sh-style JSON response from name_value strings."""
    return [{"id": i, "name_value": nv} for i, nv in enumerate(name_values, 1)]


def _mock_resp(json_data=None, *, status_code=200, exc=None):
    """Build a MagicMock that behaves like a requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data if json_data is not None else []
    if exc:
        mock_resp.raise_for_status.side_effect = exc
    return mock_resp


# ── success cases ─────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_hosts(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("mail.example.com\nwww.example.com"))

    result = run("example.com")
    assert set(result["hosts"]) == {"mail.example.com", "www.example.com"}
    assert result["domain"] == "example.com"


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_ips_in_san(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("93.184.216.34\n1.2.3.4"))

    result = run("example.com")
    assert len(result["ips"]) == 2
    assert "93.184.216.34" in result["ips"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_finds_emails_in_san(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("admin@example.com"))

    result = run("example.com")
    assert "admin@example.com" in result["emails"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_deduplicates_hosts(mock_get):
    mock_get.return_value = _mock_resp(
        _crtsh_response("sub.example.com\nsub.example.com\nwww.example.com")
    )

    result = run("example.com")
    assert result["hosts"] == ["sub.example.com", "www.example.com"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_excludes_naked_domain(mock_get):
    """The queried domain itself should not appear as a discovered host."""
    mock_get.return_value = _mock_resp(_crtsh_response("example.com\nwww.example.com"))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_excludes_third_party_domains(mock_get):
    """Only subdomains of the target domain are kept — unrelated domains
    that happen to share a cert are filtered out."""
    mock_get.return_value = _mock_resp(
        _crtsh_response("www.example.com\nunrelated.org\nother.example.com")
    )

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "other.example.com"}


@patch("app.tools.theharvester.scan.requests.get")
def test_run_strips_trailing_dot(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("sub.example.com"))

    result = run("example.com.")
    assert result["domain"] == "example.com"


@patch("app.tools.theharvester.scan.requests.get")
def test_run_includes_sources_used(mock_get):
    mock_get.return_value = _mock_resp(_crtsh_response("sub.example.com"))

    result = run("example.com")
    assert "crtsh" in result["sources_used"]


@patch("app.tools.theharvester.scan.requests.get")
def test_run_handles_multiple_entries(mock_get):
    mock_get.return_value = _mock_resp(
        [
            {"id": 1, "name_value": "www.example.com\ncdn.example.com"},
            {"id": 2, "name_value": "mail.example.com"},
        ]
    )

    result = run("example.com")
    assert set(result["hosts"]) == {"www.example.com", "cdn.example.com", "mail.example.com"}


# ── no-data cases ─────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_when_all_empty(mock_get):
    mock_get.return_value = _mock_resp([])

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_when_all_filtered(mock_get):
    """If all SAN entries are third-party domains or the target itself,
    the result set is effectively empty."""
    mock_get.return_value = _mock_resp(_crtsh_response("example.com\nunrelated.org"))

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


# ── error cases ───────────────────────────────────────────────────────


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_timeout(mock_get):
    mock_get.side_effect = requests.Timeout()

    with pytest.raises(TheHarvesterScanError, match="timed out"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_rate_limit_on_429(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.side_effect = requests.HTTPError("429 Client Error", response=mock_resp)

    with pytest.raises(TheHarvesterRateLimitError, match="rate-limited"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_filters_wildcard_hosts(mock_get):
    """Wildcard cert entries (*.example.com) are not real queryable hosts
    and must never appear as discovered assets."""
    mock_get.return_value = _mock_resp(_crtsh_response("*.example.com\nwww.example.com"))

    result = run("example.com")
    assert result["hosts"] == ["www.example.com"]


def test_run_raises_no_data_for_wildcard_domain():
    """Passing *.example.com directly as the target should raise
    NoDataError immediately — wildcards aren't queryable (no HTTP call
    is made, so no patch needed)."""
    with pytest.raises(TheHarvesterNoDataError, match="Wildcard domains"):
        run("*.example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_on_crtsh_404(mock_get):
    """crt.sh returns bare 404 (not an empty array) when a domain has
    no certs — must be treated as no-data, not a scan failure."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.side_effect = requests.HTTPError("404 Client Error", response=mock_resp)

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("elysec-int.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_rate_limit_on_502(mock_get):
    """5xx errors from CRT.sh are transient server failures — retryable."""
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)

    with pytest.raises(TheHarvesterRateLimitError, match="server error"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_http_error(mock_get):
    """4xx errors (other than 429) are permanent client errors — not retryable."""
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_get.side_effect = requests.HTTPError("400 Bad Request", response=mock_resp)

    with pytest.raises(TheHarvesterScanError, match="CRT.sh request failed"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_scan_error_on_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("Connection refused")

    with pytest.raises(TheHarvesterScanError, match="CRT.sh request failed"):
        run("example.com")


@patch("app.tools.theharvester.scan.requests.get")
def test_run_handles_invalid_json(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    # Invalid JSON → empty results → NoDataError
    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


# ── error hierarchy ───────────────────────────────────────────────────


def test_nodata_is_tool_nodata():
    assert issubclass(TheHarvesterNoDataError, ToolNoDataError)


def test_rate_limit_is_tool_rate_limit():
    assert issubclass(TheHarvesterRateLimitError, ToolRateLimitError)


# ── theHarvester CLI subprocess integration ────────────────────────────


def _cli_result_json(hosts=None, ips=None, emails=None) -> str:
    """Build a theHarvester CLI-style JSON output file."""
    return json.dumps({"hosts": hosts or [], "ips": ips or [], "emails": emails or []})


def _write_cli_output(hosts=None, ips=None, emails=None) -> str:
    """Create a real temp file with CLI-style JSON for _run_theharvester_cli."""
    tmp = tempfile.mkdtemp()
    out_path = Path(tmp) / "result.json"
    out_path.write_text(_cli_result_json(hosts, ips, emails))
    # Return the parent dir so the code's `out_path.with_suffix(".json")` resolves
    return tmp


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_merges_cli_hosts_with_crtsh(mock_get, mock_run):
    """CLI hostnames are merged with crt.sh hostnames."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(hosts=["mail.example.com", "cdn.example.com"])
        result = run("example.com")

    assert set(result["hosts"]) == {"www.example.com", "mail.example.com", "cdn.example.com"}
    assert "theharvester_cli" in result["sources_used"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_merges_cli_ips_and_emails(mock_get, mock_run):
    """CLI-discovered IPs and emails are merged."""
    mock_get.return_value = _mock_resp(_crtsh_response("93.184.216.34"))
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(
            ips=["1.2.3.4", "5.6.7.8"], emails=["contact@example.com"]
        )
        result = run("example.com")

    assert set(result["ips"]) == {"93.184.216.34", "1.2.3.4", "5.6.7.8"}
    assert set(result["emails"]) == {"contact@example.com"}


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_falls_back_to_crtsh_on_cli_timeout(mock_get, mock_run):
    """When CLI times out, crt.sh results are still returned."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.side_effect = subprocess.TimeoutExpired("theHarvester", 90)

    result = run("example.com")

    assert result["hosts"] == ["www.example.com"]
    assert result["sources_used"] == ["crtsh"]  # CLI contributed nothing


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_falls_back_to_crtsh_on_cli_crash(mock_get, mock_run):
    """When CLI crashes (non-zero exit), crt.sh results are still returned."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.side_effect = subprocess.CalledProcessError(1, "theHarvester", stderr=b"crash")

    result = run("example.com")

    assert result["hosts"] == ["www.example.com"]
    assert result["sources_used"] == ["crtsh"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_falls_back_to_crtsh_on_missing_binary(mock_get, mock_run):
    """When theHarvester binary is not installed, crt.sh still works."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.side_effect = FileNotFoundError("theHarvester not found")

    result = run("example.com")

    assert result["hosts"] == ["www.example.com"]
    assert result["sources_used"] == ["crtsh"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_falls_back_to_crtsh_on_no_output_file(mock_get, mock_run):
    """When CLI runs but produces no JSON file, crt.sh still works."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.return_value = MagicMock()

    with patch.object(Path, "exists", return_value=False):  # no .json produced
        result = run("example.com")

    assert result["hosts"] == ["www.example.com"]
    assert result["sources_used"] == ["crtsh"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_falls_back_to_crtsh_on_invalid_json(mock_get, mock_run):
    """When CLI produces broken JSON, crt.sh still works."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = "not valid json {{{"
        result = run("example.com")

    assert result["hosts"] == ["www.example.com"]
    assert result["sources_used"] == ["crtsh"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_filters_cli_third_party_hosts(mock_get, mock_run):
    """CLI may return unrelated domains from search results — they must be filtered."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(
            hosts=["mail.example.com", "unrelated.org", "evil.example.com.phishing.net"]
        )
        result = run("example.com")

    assert "mail.example.com" in result["hosts"]
    assert "unrelated.org" not in result["hosts"]
    assert "evil.example.com.phishing.net" not in result["hosts"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_cli_does_not_add_sources_when_empty(mock_get, mock_run):
    """When CLI returns hosts/ips/emails all empty, it is NOT listed in sources_used."""
    mock_get.return_value = _mock_resp(_crtsh_response("www.example.com"))
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(hosts=[], ips=[], emails=[])
        result = run("example.com")

    assert result["sources_used"] == ["crtsh"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_no_data_when_both_crtsh_and_cli_empty(mock_get, mock_run):
    """When both crt.sh AND CLI produce nothing, NoDataError is raised."""
    mock_get.return_value = _mock_resp([])
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(hosts=[], ips=[], emails=[])
        with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
            run("example.com")


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_cli_no_data_does_not_prevent_crtsh_nodata(mock_get, mock_run):
    """CLI timing out doesn't hide the fact that crt.sh also found nothing."""
    mock_get.return_value = _mock_resp([])
    mock_run.side_effect = subprocess.TimeoutExpired("theHarvester", 90)

    with pytest.raises(TheHarvesterNoDataError, match="No public data found"):
        run("example.com")


# ── CLI result filtering helpers ───────────────────────────────────────


def test_filter_subdomains_keeps_only_target_domain():
    hosts = [
        "mail.example.com",
        "www.example.com",
        "cdn.unrelated.org",
        "evil.example.com.fake.net",
    ]
    result = _filter_subdomains(hosts, "example.com")
    assert result == {"mail.example.com", "www.example.com"}


def test_filter_subdomains_excludes_wildcards():
    assert _filter_subdomains(["*.example.com", "www.example.com"], "example.com") == {
        "www.example.com"
    }


def test_filter_subdomains_excludes_naked_domain():
    assert "example.com" not in _filter_subdomains(
        ["example.com", "www.example.com"], "example.com"
    )


def test_filter_subdomains_handles_empty_list():
    assert _filter_subdomains([], "example.com") == set()


def test_filter_valid_ips_keeps_valid():
    assert "93.184.216.34" in _filter_valid_ips(["93.184.216.34", "not-an-ip", "1.2.3.4"])


def test_filter_valid_ips_rejects_invalid():
    assert "not-an-ip" not in _filter_valid_ips(["not-an-ip", "abc"])


def test_filter_valid_ips_handles_ipv6():
    result = _filter_valid_ips(["2606:2800:220:1:248:1893:25c8:1946"])
    assert len(result) == 1


def test_filter_valid_ips_handles_empty():
    assert _filter_valid_ips([]) == set()


def test_filter_domain_emails_keeps_matching():
    result = _filter_domain_emails(["admin@example.com", "contact@other.org"], "example.com")
    assert result == {"admin@example.com"}


def test_filter_domain_emails_handles_empty():
    assert _filter_domain_emails([], "example.com") == set()


# ── CLI runner unit tests ──────────────────────────────────────────────


@patch("app.tools.theharvester.scan.subprocess.run")
def test_run_theharvester_cli_returns_none_on_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("theHarvester", 90)
    assert _run_theharvester_cli("example.com") is None


@patch("app.tools.theharvester.scan.subprocess.run")
def test_run_theharvester_cli_returns_none_on_crash(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "theHarvester")
    assert _run_theharvester_cli("example.com") is None


@patch("app.tools.theharvester.scan.subprocess.run")
def test_run_theharvester_cli_returns_none_on_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError()
    assert _run_theharvester_cli("example.com") is None


# ── CLI saves the day when crt.sh is down ─────────────────────────────


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_cli_succeeds_when_crtsh_fails_with_502(mock_get, mock_run):
    """crt.sh returns 502 → CLI finds data → result returned, no error.
    This is THE critical path for resilience: crt.sh outage must never
    block the pipeline when theHarvester CLI is available."""
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(
            hosts=["mail.example.com", "vpn.example.com"],
            ips=["198.51.100.1"],
        )
        result = run("example.com")

    assert set(result["hosts"]) == {"mail.example.com", "vpn.example.com"}
    assert result["ips"] == ["198.51.100.1"]
    assert result["sources_used"] == ["theharvester_cli"]  # crt.sh NOT in sources


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_cli_succeeds_when_crtsh_times_out(mock_get, mock_run):
    """crt.sh times out → CLI finds data → success. Same resilience pattern."""
    mock_get.side_effect = requests.Timeout()
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(hosts=["db.example.com"])
        result = run("example.com")

    assert result["hosts"] == ["db.example.com"]
    assert result["sources_used"] == ["theharvester_cli"]


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_crtsh_error_when_both_sources_fail(mock_get, mock_run):
    """crt.sh 502 + CLI timeout → crt.sh error re-raised so Celery can retry.
    The CLI timeout alone is silent, but crt.sh's transient error must
    still bubble up so the task layer knows to retry."""
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_get.side_effect = requests.HTTPError("502 Bad Gateway", response=mock_resp)
    mock_run.side_effect = subprocess.TimeoutExpired("theHarvester", 90)

    with pytest.raises(TheHarvesterRateLimitError, match="server error"):
        run("example.com")


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_raises_crtsh_timeout_when_cli_also_fails(mock_get, mock_run):
    """crt.sh timeout + CLI crash → crt.sh error re-raised."""
    mock_get.side_effect = requests.Timeout()
    mock_run.side_effect = subprocess.CalledProcessError(1, "theHarvester")

    with pytest.raises(TheHarvesterScanError, match="timed out"):
        run("example.com")


@patch("app.tools.theharvester.scan.subprocess.run")
@patch("app.tools.theharvester.scan.requests.get")
def test_run_both_sources_succeed_with_overlap(mock_get, mock_run):
    """crt.sh AND CLI both find data → merged with dedup, both in sources."""
    mock_get.return_value = _mock_resp(
        _crtsh_response("www.example.com\nmail.example.com\n93.184.216.34")
    )
    mock_run.return_value = MagicMock()

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text") as mock_read,
    ):
        mock_read.return_value = _cli_result_json(
            hosts=["mail.example.com", "cdn.example.com"],
            ips=["93.184.216.34", "198.51.100.1"],
            emails=["admin@example.com"],
        )
        result = run("example.com")

    # mail.example.com found by both → deduped
    # 93.184.216.34 found by both → deduped
    assert set(result["hosts"]) == {"www.example.com", "mail.example.com", "cdn.example.com"}
    assert len(result["ips"]) == 2  # 93.184.216.34 + 198.51.100.1
    assert result["emails"] == ["admin@example.com"]
    assert set(result["sources_used"]) == {"crtsh", "theharvester_cli"}
