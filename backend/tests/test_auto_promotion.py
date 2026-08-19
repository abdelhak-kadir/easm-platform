"""Tests for ``_auto_promote_discovered_hosts`` (backend/app/orchestrator.py).

Pure unit tests with ``unittest.mock`` — no database or Celery broker
needed.  The helper's only DB dependency is the session passed in, so the
query chains are mocked in the order the helper issues them:

1. ``db.query(ScanResult).join(...).filter(...).order_by(...).all()``
   → the current round's discovery results
2. ``db.query(Asset.value).filter(...).all()`` → already-tracked values
3. per candidate: ``db.query(Asset).filter(...).first()`` → existing asset
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from app.models import AssetStatus, AssetType, DiscoveryRun, ToolName
from sqlalchemy.exc import IntegrityError


def _make_root(value: str = "example.com") -> MagicMock:
    r = MagicMock()
    r.id = 1
    r.value = value
    r.asset_type = AssetType.DOMAIN
    return r


def _make_run(
    auto_promoted_hosts: list[str] | None = None,
    round_number: int = 1,
    max_rounds: int = 5,
    current_round_asset_ids: list[int] | None = None,
) -> MagicMock:
    r = MagicMock(spec=DiscoveryRun)
    r.id = 7
    r.root_asset_id = 1
    r.round_number = round_number
    r.max_rounds = max_rounds
    r.current_round_asset_ids = current_round_asset_ids or [1, 2]
    r.auto_promoted_hosts = auto_promoted_hosts
    r.created_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
    return r


def _make_result(asset_id: int, tool: ToolName, hosts: list[str]) -> MagicMock:
    res = MagicMock()
    res.scan_job = MagicMock()
    res.scan_job.asset_id = asset_id
    res.scan_job.tool = tool
    res.raw_data = {"hosts": hosts}
    res.version = 1
    res.created_at = datetime(2026, 8, 1, 13, 0, 0, tzinfo=UTC)
    return res


def _run_helper(db, run, root, hosts_by_asset, tracked=()):
    """Run _auto_promote_discovered_hosts with the standard query chain.

    hosts_by_asset: list of (asset_id, tool, hosts) result tuples.
    tracked: values returned by the tracked-asset query.
    Per-host find-or-create queries all return None → every eligible
    candidate goes down the creation path.
    """
    from app.orchestrator import _auto_promote_discovered_hosts

    results_q = MagicMock()
    results_q.join.return_value = results_q
    results_q.filter.return_value = results_q
    results_q.order_by.return_value = results_q
    results_q.all.return_value = [
        _make_result(aid, tool, hosts) for aid, tool, hosts in hosts_by_asset
    ]

    tracked_q = MagicMock()
    tracked_q.filter.return_value = tracked_q
    tracked_q.all.return_value = [(v,) for v in tracked]

    def _find_query(*_args):
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = None
        return q

    # One find-or-create query per candidate host — a generous spare count
    # (30) covers the largest test (15 promotions).
    db.query.side_effect = [results_q, tracked_q] + [_find_query() for _ in range(30)]

    return _auto_promote_discovered_hosts(db, run, root)


class TestAutoPromote:
    def test_budget_cap_and_deterministic_order(self):
        """50 candidates, 5 already in budget → exactly 15 promoted, alphabetical."""
        db = MagicMock()
        root = _make_root()
        run = _make_run(auto_promoted_hosts=[f"a{i}.example.com" for i in range(5)])
        hosts = [f"host{i}.example.com" for i in range(50)]

        with patch("app.orchestrator.Asset") as mock_asset:
            promoted = _run_helper(db, run, root, [(1, ToolName.SUBFINDER, hosts)])

        assert len(promoted) == 15
        created_values = [
            c.kwargs["value"] for c in mock_asset.call_args_list if c.kwargs.get("value")
        ]
        # Deterministic alphabetical pick — note "host1" < "host10" < "host2"
        # in string sort, so the first 15 are NOT host0..host14 numerically.
        assert created_values == sorted(hosts)[:15]
        assert created_values[0] == "host0.example.com"
        assert created_values[-1] == sorted(hosts)[14]
        assert len(run.auto_promoted_hosts) == 20  # 5 previous + 15 new
        assert run.auto_promoted_hosts == sorted(run.auto_promoted_hosts)

    def test_created_assets_carry_run_and_root_link(self):
        db = MagicMock()
        root = _make_root()
        run = _make_run()

        with patch("app.orchestrator.Asset") as mock_asset:
            _run_helper(db, run, root, [(1, ToolName.THEHARVESTER, ["a.example.com"])])

        mock_asset.assert_called_once()
        kwargs = mock_asset.call_args.kwargs
        assert kwargs["asset_type"] == AssetType.SUBDOMAIN
        assert kwargs["status"] == AssetStatus.PENDING
        assert kwargs["discovery_run_id"] == run.id
        assert kwargs["root_asset_id"] == run.root_asset_id

    def test_skips_already_tracked_and_already_promoted(self):
        db = MagicMock()
        root = _make_root()
        run = _make_run(auto_promoted_hosts=["promoted.example.com"])
        hosts = [
            "new.example.com",
            "tracked.example.com",
            "promoted.example.com",
            "another.example.com",
        ]

        with patch("app.orchestrator.Asset") as mock_asset:
            promoted = _run_helper(
                db, run, root, [(1, ToolName.SUBFINDER, hosts)], tracked=["tracked.example.com"]
            )

        assert len(promoted) == 2
        values = [c.kwargs["value"] for c in mock_asset.call_args_list]
        assert values == ["another.example.com", "new.example.com"]
        assert run.auto_promoted_hosts == [
            "another.example.com",
            "new.example.com",
            "promoted.example.com",
        ]

    def test_suffix_filter_keeps_only_root_subdomains(self):
        db = MagicMock()
        root = _make_root("example.com")
        run = _make_run()
        hosts = [
            "ok.example.com",
            "EXAMPLE.COM.",  # root itself, trailing dot
            "evil-other.net",  # off-root noise
            "*.wildcard.example.com",  # wildcard
            "",  # empty
            "UPPER.example.com",  # normalized to lowercase
        ]

        with patch("app.orchestrator.Asset") as mock_asset:
            promoted = _run_helper(db, run, root, [(1, ToolName.AMASS, hosts)])

        values = [c.kwargs["value"] for c in mock_asset.call_args_list]
        assert values == ["ok.example.com", "upper.example.com"]
        assert len(promoted) == 2

    def test_latest_version_per_asset_tool_pair(self):
        """Duplicate (asset, tool) results → only the latest version's hosts count."""
        db = MagicMock()
        root = _make_root()
        run = _make_run()

        res_new = _make_result(1, ToolName.SUBFINDER, ["new.example.com"])
        res_new.version = 2
        results_q = MagicMock()
        results_q.join.return_value = results_q
        results_q.filter.return_value = results_q
        results_q.order_by.return_value = results_q
        results_q.all.return_value = [
            res_new,  # version 2 — wins
            _make_result(1, ToolName.SUBFINDER, ["stale.example.com"]),  # version 1 — dropped
        ]
        tracked_q = MagicMock()
        tracked_q.filter.return_value = tracked_q
        tracked_q.all.return_value = []
        # Per-host find-or-create query → None (creation path)
        find_q = MagicMock()
        find_q.filter.return_value = find_q
        find_q.first.return_value = None
        db.query.side_effect = [results_q, tracked_q, find_q]

        from app.orchestrator import _auto_promote_discovered_hosts

        with patch("app.orchestrator.Asset") as mock_asset:
            _auto_promote_discovered_hosts(db, run, root)

        values = [c.kwargs["value"] for c in mock_asset.call_args_list]
        assert values == ["new.example.com"]

    def test_round_at_max_rounds_promotes_nothing(self):
        db = MagicMock()
        run = _make_run(round_number=5, max_rounds=5)

        from app.orchestrator import _auto_promote_discovered_hosts

        assert _auto_promote_discovered_hosts(db, run, _make_root()) == []
        db.query.assert_not_called()

    def test_budget_exhausted_promotes_nothing(self):
        db = MagicMock()
        run = _make_run(auto_promoted_hosts=[f"h{i}.example.com" for i in range(20)])

        from app.orchestrator import _auto_promote_discovered_hosts

        assert _auto_promote_discovered_hosts(db, run, _make_root()) == []
        db.query.assert_not_called()

    def test_no_discovery_results_promotes_nothing(self):
        db = MagicMock()
        run = _make_run()

        results_q = MagicMock()
        results_q.join.return_value = results_q
        results_q.filter.return_value = results_q
        results_q.order_by.return_value = results_q
        results_q.all.return_value = []
        db.query.return_value = results_q

        from app.orchestrator import _auto_promote_discovered_hosts

        assert _auto_promote_discovered_hosts(db, run, _make_root()) == []
        assert run.auto_promoted_hosts is None

    def test_no_hosts_in_results_promotes_nothing(self):
        db = MagicMock()
        run = _make_run()

        results_q = MagicMock()
        results_q.join.return_value = results_q
        results_q.filter.return_value = results_q
        results_q.order_by.return_value = results_q
        results_q.all.return_value = [_make_result(1, ToolName.SUBFINDER, [])]
        db.query.return_value = results_q

        from app.orchestrator import _auto_promote_discovered_hosts

        assert _auto_promote_discovered_hosts(db, run, _make_root()) == []

    def test_integrity_error_savepoint_fallback(self):
        """Concurrent duplicate INSERT → savepoint rollback + re-query, host
        skipped; later candidates still promote."""
        from app.orchestrator import _auto_promote_discovered_hosts

        db = MagicMock()
        root = _make_root()
        run = _make_run()
        hosts = ["dup.example.com", "fresh.example.com"]

        results_q = MagicMock()
        results_q.join.return_value = results_q
        results_q.filter.return_value = results_q
        results_q.order_by.return_value = results_q
        results_q.all.return_value = [_make_result(1, ToolName.SUBFINDER, hosts)]
        tracked_q = MagicMock()
        tracked_q.filter.return_value = tracked_q
        tracked_q.all.return_value = []  # not tracked yet

        # Query call order:
        #  0. results_q          (discovery results)
        #  1. tracked_q          (already-tracked values → none)
        #  2. find_q1            (pre-check dup → None, we insert)
        #  3. find_q2            (pre-check fresh → None, we insert)
        #  4. find_q3            (re-query AFTER the IntegrityError → raced asset)
        existing = MagicMock()
        find_q1 = MagicMock()
        find_q1.filter.return_value = find_q1
        find_q1.first.return_value = None
        find_q2 = MagicMock()
        find_q2.filter.return_value = find_q2
        find_q2.first.return_value = None
        find_q3 = MagicMock()
        find_q3.filter.return_value = find_q3
        find_q3.first.return_value = existing
        db.query.side_effect = [results_q, tracked_q, find_q1, find_q2, find_q3]

        # The FIRST savepoint hits the unique constraint (another worker won
        # the race on dup.example.com) → rollback + re-query finds it.  The
        # second savepoint succeeds normally.
        begin_calls = [0]

        def _begin_nested():
            begin_calls[0] += 1
            if begin_calls[0] == 1:
                raise IntegrityError("dup", {}, Exception())
            return MagicMock()  # successful savepoint context manager

        db.begin_nested.side_effect = _begin_nested

        with patch("app.orchestrator.Asset") as mock_asset:
            promoted = _auto_promote_discovered_hosts(db, run, root)

        # Only the fresh host was promoted; the raced host was skipped
        # without being counted against the budget.
        assert len(promoted) == 1
        assert mock_asset.call_args.kwargs["value"] == "fresh.example.com"
        assert run.auto_promoted_hosts == ["fresh.example.com"]
        db.rollback.assert_called_once()
