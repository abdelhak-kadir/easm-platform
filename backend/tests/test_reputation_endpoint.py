"""Tests for the reputation aggregation (backend/app/api/routers/assets.py).

``_aggregate_reputation`` is a pure function of its session — mocked here
so no database is needed.  Query chain order in the helper:

1. ``db.query(Asset.id).filter(or_(...)).all()`` → member ids
2. ``db.query(Asset).filter(Asset.id.in_(...)).all()`` → member rows
3. ``db.query(ScanResult).join(ScanJob).filter(...).order_by(...).all()``
   → latest ip_blacklist results per member
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

from app.models import AssetType


def _member(id_: int, value: str, asset_type: AssetType) -> MagicMock:
    a = MagicMock()
    a.id = id_
    a.value = value
    a.asset_type = asset_type
    return a


def _finding(ftype: str, data: dict) -> MagicMock:
    f = MagicMock()
    f.finding_type = ftype
    f.data = data
    return f


def _result(asset_id: int, findings: list[MagicMock], version: int = 1) -> MagicMock:
    r = MagicMock()
    r.scan_job = MagicMock()
    r.scan_job.asset_id = asset_id
    r.findings = findings
    r.version = version
    r.created_at = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC)
    return r


def _base_db(ids, members, results):
    """Return a MagicMock db whose three query chains return the given data."""
    db = MagicMock()
    q_ids = MagicMock()
    q_ids.filter.return_value = q_ids
    q_ids.all.return_value = [(i,) for i in ids]

    q_members = MagicMock()
    q_members.filter.return_value = q_members
    q_members.all.return_value = members

    q_results = MagicMock()
    q_results.join.return_value = q_results
    q_results.filter.return_value = q_results
    q_results.order_by.return_value = q_results
    q_results.all.return_value = results

    db.query.side_effect = [q_ids, q_members, q_results]
    return db


class TestAggregateReputation:
    def test_aggregates_across_root_linked_assets(self):
        from app.api.routers.assets import _aggregate_reputation

        domain = _member(1, "example.com", AssetType.DOMAIN)
        sub_ip = _member(2, "10.0.0.1", AssetType.IP)
        sub_ip2 = _member(3, "10.0.0.2", AssetType.IP)

        listed = _result(
            2,
            [
                # Real parse.py output carries the score in the summary too
                _finding(
                    "ip_reputation",
                    {"rbl_listed_count": 2, "tor_exit": True, "abuseipdb_score": 85},
                ),
                _finding(
                    "rbl_listing",
                    {
                        "ip": "10.0.0.1",
                        "zone": "zen.spamhaus.org",
                        "code": "127.0.0.2",
                        "query": "2.0.0.10.zen.spamhaus.org",
                        "reason": "",
                    },
                ),
                _finding(
                    "rbl_listing",
                    {
                        "ip": "10.0.0.1",
                        "zone": "bl.spamcop.net",
                        "code": "127.0.0.2",
                        "query": "",
                        "reason": "",
                    },
                ),
                _finding("abuseipdb_report", {"ip": "10.0.0.1", "score": 85}),
            ],
        )
        clean = _result(
            3,
            [_finding("ip_reputation", {"rbl_listed_count": 0, "tor_exit": False})],
        )

        db = _base_db([1, 2, 3], [domain, sub_ip, sub_ip2], [listed, clean])
        out = _aggregate_reputation(db, 1)

        assert out["total_ips"] == 3
        assert out["listed_ips"] == 1
        assert out["total_zone_listings"] == 2

        by_ip = {e["ip"]: e for e in out["ips"]}
        assert by_ip["10.0.0.1"]["listed_count"] == 2
        assert by_ip["10.0.0.1"]["tor_exit"] is True
        assert by_ip["10.0.0.1"]["abuseipdb_score"] == 85
        assert by_ip["10.0.0.1"]["abuseipdb"]["score"] == 85
        assert len(by_ip["10.0.0.1"]["zones"]) == 2
        assert by_ip["10.0.0.2"]["listed_count"] == 0

        zones = {z["zone"]: z for z in out["by_zone"]}
        assert zones["zen.spamhaus.org"]["count"] == 1
        assert zones["zen.spamhaus.org"]["listed_ips"] == ["10.0.0.1"]
        assert zones["bl.spamcop.net"]["count"] == 1

    def test_latest_version_per_asset_only(self):
        """Two results for the same asset → only the newest version counts."""
        from app.api.routers.assets import _aggregate_reputation

        ip = _member(2, "10.0.0.1", AssetType.IP)
        stale = _result(2, [_finding("ip_reputation", {"rbl_listed_count": 3})], version=1)
        latest = _result(2, [_finding("ip_reputation", {"rbl_listed_count": 1})], version=2)

        db = _base_db([1, 2], [_member(1, "example.com", AssetType.DOMAIN), ip], [latest, stale])
        out = _aggregate_reputation(db, 1)

        assert out["listed_ips"] == 1
        by_ip = {e["ip"]: e for e in out["ips"]}
        assert by_ip["10.0.0.1"]["listed_count"] == 1  # version 2 wins

    def test_unchecked_ips_reported(self):
        """IP members without a completed blacklist scan are listed as unchecked."""
        from app.api.routers.assets import _aggregate_reputation

        ip_checked = _member(2, "10.0.0.1", AssetType.IP)
        ip_unchecked = _member(3, "10.0.0.2", AssetType.IP)

        result = _result(2, [_finding("ip_reputation", {"rbl_listed_count": 0})])
        db = _base_db(
            [1, 2, 3],
            [_member(1, "example.com", AssetType.DOMAIN), ip_checked, ip_unchecked],
            [result],
        )

        out = _aggregate_reputation(db, 1)
        assert out["unchecked_ips"] == ["10.0.0.2"]

    def test_by_zone_sorted_by_count_desc(self):
        from app.api.routers.assets import _aggregate_reputation

        members = [
            _member(1, "example.com", AssetType.DOMAIN),
            _member(2, "10.0.0.1", AssetType.IP),
            _member(3, "10.0.0.2", AssetType.IP),
            _member(4, "10.0.0.3", AssetType.IP),
        ]
        results = [
            _result(
                2,
                [
                    _finding("ip_reputation", {"rbl_listed_count": 2}),
                    _finding("rbl_listing", {"ip": "10.0.0.1", "zone": "zen.spamhaus.org"}),
                    _finding("rbl_listing", {"ip": "10.0.0.1", "zone": "bl.spamcop.net"}),
                ],
            ),
            _result(
                3,
                [
                    _finding("ip_reputation", {"rbl_listed_count": 1}),
                    _finding("rbl_listing", {"ip": "10.0.0.2", "zone": "zen.spamhaus.org"}),
                ],
            ),
            _result(4, [_finding("ip_reputation", {"rbl_listed_count": 0})]),
        ]
        db = _base_db([1, 2, 3, 4], members, results)
        out = _aggregate_reputation(db, 1)

        assert [z["zone"] for z in out["by_zone"]] == ["zen.spamhaus.org", "bl.spamcop.net"]
        assert out["by_zone"][0]["count"] == 2
        assert out["by_zone"][0]["listed_ips"] == ["10.0.0.1", "10.0.0.2"]
        assert out["listed_ips"] == 2

    def test_empty_membership_returns_zeroed_response(self):
        from app.api.routers.assets import _aggregate_reputation

        db = _base_db([], [], [])
        out = _aggregate_reputation(db, 999)

        assert out["total_ips"] == 0
        assert out["listed_ips"] == 0
        assert out["total_zone_listings"] == 0
        assert out["ips"] == []
        assert out["by_zone"] == []
        assert out["unchecked_ips"] == []
