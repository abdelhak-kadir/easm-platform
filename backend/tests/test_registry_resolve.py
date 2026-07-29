"""Tests for the chained-scan resolver functions in app.tools.registry.

Covers the fix for the Shodan -> WHOIS chain re-doing a reverse DNS
lookup over the network even when a REVERSE_DNS ScanJob already
completed for the same IP asset in the same discovery batch.

`_resolve_ip_to_domain` should now check for a cached, COMPLETED
REVERSE_DNS ScanResult first and only fall back to a live
`reverse_dns_scan.run()` call when no cache is available.
"""

from unittest.mock import MagicMock, patch

from app.models import Asset, ScanResult
from app.tools.registry import _resolve_domain_to_ip, _resolve_ip_to_domain


def _make_db_with_asset_and_cache(asset, cached_result):
    """Build a MagicMock db session where:
    - db.query(Asset)....first() -> asset
    - db.query(ScanResult).join(ScanJob)....first() -> cached_result
    """
    db = MagicMock()

    def query_side_effect(model):
        m = MagicMock()
        if model is Asset:
            m.filter.return_value.first.return_value = asset
        elif model is ScanResult:
            m.join.return_value.filter.return_value.order_by.return_value.first.return_value = (
                cached_result
            )
        return m

    db.query.side_effect = query_side_effect
    return db


def _make_db_no_asset():
    """db session where the IP asset itself isn't found (e.g. it
    doesn't exist yet as an Asset row) -- forces the live-lookup path.
    """
    db = MagicMock()

    def query_side_effect(model):
        m = MagicMock()
        if model is Asset:
            m.filter.return_value.first.return_value = None
        return m

    db.query.side_effect = query_side_effect
    return db


# ---------------------------------------------------------------------
# _resolve_domain_to_ip (unaffected by the fix, but signature changed
# to accept `db` -- confirm it still works and ignores it safely).
# ---------------------------------------------------------------------


@patch("app.tools.registry.socket.gethostbyname", return_value="93.184.216.34")
def test_resolve_domain_to_ip_success(mock_resolve):
    db = MagicMock()
    result = _resolve_domain_to_ip(db, "example.com")
    assert result == "93.184.216.34"
    mock_resolve.assert_called_once_with("example.com")


@patch("app.tools.registry.socket.gethostbyname", side_effect=OSError)
def test_resolve_domain_to_ip_failure_returns_none(mock_resolve):
    db = MagicMock()
    assert _resolve_domain_to_ip(db, "not-a-real-domain.invalid") is None


# ---------------------------------------------------------------------
# _resolve_ip_to_domain -- cache-hit paths (the actual fix)
# ---------------------------------------------------------------------


@patch("app.tools.registry.reverse_dns_scan.run")
def test_resolve_ip_to_domain_uses_cache_and_skips_live_scan(mock_live_scan):
    asset = MagicMock(id=1)
    cached_result = MagicMock()
    cached_result.raw_data = {"hostnames": ["mail.example.com"]}
    db = _make_db_with_asset_and_cache(asset, cached_result)

    result = _resolve_ip_to_domain(db, "93.184.216.34")

    assert result == "example.com"
    mock_live_scan.assert_not_called()


@patch("app.tools.registry.reverse_dns_scan.run")
def test_resolve_ip_to_domain_cache_hit_with_no_hostnames_skips_live_scan(mock_live_scan):
    """A completed REVERSE_DNS scan that found nothing (no PTR record)
    should NOT trigger a retry over the network -- 'completed with
    empty result' is itself a cached, authoritative answer."""
    asset = MagicMock(id=1)
    cached_result = MagicMock()
    cached_result.raw_data = {"hostnames": []}
    db = _make_db_with_asset_and_cache(asset, cached_result)

    result = _resolve_ip_to_domain(db, "93.184.216.34")

    assert result is None
    mock_live_scan.assert_not_called()


# ---------------------------------------------------------------------
# _resolve_ip_to_domain -- fallback to a live lookup
# ---------------------------------------------------------------------


@patch("app.tools.registry.reverse_dns_scan.run")
def test_resolve_ip_to_domain_falls_back_when_asset_not_found(mock_live_scan):
    """No Asset row for this IP yet -- can't have a cached scan for
    something that doesn't exist, so it must hit the network."""
    mock_live_scan.return_value = {"hostnames": ["mail.example.com"]}
    db = _make_db_no_asset()

    result = _resolve_ip_to_domain(db, "93.184.216.34")

    assert result == "example.com"
    mock_live_scan.assert_called_once_with("93.184.216.34")


@patch("app.tools.registry.reverse_dns_scan.run")
def test_resolve_ip_to_domain_falls_back_when_no_completed_scan_cached(mock_live_scan):
    """Asset exists, but no COMPLETED REVERSE_DNS ScanResult for it
    yet (e.g. Reverse DNS is still PENDING/RUNNING in this discovery
    batch, or was never run) -- must hit the network rather than
    block or return stale/missing data."""
    mock_live_scan.return_value = {"hostnames": ["mail.example.com"]}
    asset = MagicMock(id=1)
    db = _make_db_with_asset_and_cache(asset, cached_result=None)

    result = _resolve_ip_to_domain(db, "93.184.216.34")

    assert result == "example.com"
    mock_live_scan.assert_called_once_with("93.184.216.34")


@patch("app.tools.registry.reverse_dns_scan.run", side_effect=Exception("boom"))
def test_resolve_ip_to_domain_live_scan_error_returns_none(mock_live_scan):
    db = _make_db_no_asset()
    assert _resolve_ip_to_domain(db, "93.184.216.34") is None


@patch("app.tools.registry.reverse_dns_scan.run", return_value={"hostnames": []})
def test_resolve_ip_to_domain_live_scan_no_hostnames_returns_none(mock_live_scan):
    db = _make_db_no_asset()
    assert _resolve_ip_to_domain(db, "93.184.216.34") is None
