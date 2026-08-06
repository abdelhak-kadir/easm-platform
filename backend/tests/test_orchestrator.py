"""Tests for the wave-based discovery orchestrator (backend/app/orchestrator.py).

These tests use ``unittest.mock`` to avoid real database or Celery broker
access — no Redis/Postgres container is needed to run them.
"""

from datetime import UTC, datetime
from unittest.mock import ANY, MagicMock, patch

import pytest
from app.models import AssetStatus, AssetType, DiscoveryRun, ToolName

# ── helpers ──────────────────────────────────────────────────────────────


def _make_asset(
    id_: int = 1,
    value: str = "example.com",
    asset_type: AssetType = AssetType.DOMAIN,
    status: AssetStatus = AssetStatus.PENDING,
    discovery_run_id: int | None = None,
) -> MagicMock:
    a = MagicMock()
    a.id = id_
    a.value = value
    a.asset_type = asset_type
    a.status = status
    a.discovery_run_id = discovery_run_id
    return a


def _make_run(
    id_: int = 1,
    root_asset_id: int = 1,
    round_number: int = 1,
    max_rounds: int = 5,
    status: str = "running",
    current_round_asset_ids: list[int] | None = None,
) -> MagicMock:
    r = MagicMock(spec=DiscoveryRun)
    r.id = id_
    r.root_asset_id = root_asset_id
    r.round_number = round_number
    r.max_rounds = max_rounds
    r.status = status
    r.current_round_asset_ids = current_round_asset_ids
    r.created_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
    r.completed_at = None
    return r


def _mock_query_chain(return_value=None):
    """Return a MagicMock whose filter/join/distinct chains all return itself."""
    m = MagicMock()
    m.filter.return_value = m
    m.join.return_value = m
    m.distinct.return_value = m
    if return_value is not None:
        m.all.return_value = return_value
    return m


# ── create_discovery_run ────────────────────────────────────────────────


class TestCreateDiscoveryRun:
    def test_creates_run_and_tags_root_asset(self):
        from app.orchestrator import create_discovery_run

        db = MagicMock()
        root = _make_asset(1, "example.com", AssetType.DOMAIN, AssetStatus.PENDING)
        db.get.return_value = root

        run = create_discovery_run(db, 1, max_rounds=3)

        db.get.assert_called_once_with(ANY, 1)
        db.add.assert_called_once()
        db.flush.assert_called_once()
        assert root.discovery_run_id == run.id
        assert root.status == AssetStatus.PENDING  # stays PENDING — schedule_round promotes it
        assert run.max_rounds == 3
        assert run.root_asset_id == 1
        db.commit.assert_called_once()

    def test_raises_valueerror_when_asset_not_found(self):
        from app.orchestrator import create_discovery_run

        db = MagicMock()
        db.get.return_value = None

        with pytest.raises(ValueError, match="not found"):
            create_discovery_run(db, 999, max_rounds=5)


# ── schedule_round ──────────────────────────────────────────────────────


class TestScheduleRound:
    def test_skips_when_run_not_found(self):
        from app.orchestrator import schedule_round

        db = MagicMock()
        db.get.return_value = None

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = schedule_round(42)

        assert "error" in result

    def test_skips_when_run_not_running(self):
        from app.orchestrator import schedule_round

        run = _make_run(status="completed")
        db = MagicMock()
        db.get.return_value = run

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = schedule_round(1)

        assert result["status"] == "skipped"

    def test_completes_when_no_pending_assets(self):
        from app.orchestrator import schedule_round

        run = _make_run(status="running")
        db = MagicMock()
        db.get.return_value = run
        db.query.return_value = _mock_query_chain([])

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = schedule_round(1)

        assert result["status"] == "completed"
        assert run.status == "completed"
        assert run.completed_at is not None

    def test_queues_tools_and_advances_round(self):
        from app.orchestrator import schedule_round

        run = _make_run(status="running", round_number=0)
        asset = _make_asset(
            1, "example.com", AssetType.DOMAIN, AssetStatus.PENDING, discovery_run_id=1
        )

        db = MagicMock()
        db.get.return_value = run
        q = _mock_query_chain([asset])
        q.first.return_value = None
        db.query.return_value = q

        mock_spec = MagicMock()
        mock_spec.tool = ToolName.WHOIS

        mock_task = MagicMock()
        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch("app.orchestrator.tools_for_asset_type", return_value=[mock_spec]),
            patch("app.tasks.run_tool_scan", mock_task),
        ):
            result = schedule_round(1)

        assert result["status"] == "scheduled"
        assert result["round"] == 1
        assert result["asset_count"] == 1
        assert run.round_number == 1
        assert asset.status == AssetStatus.RUNNING
        mock_task.delay.assert_called_once()

    def test_skips_duplicate_jobs(self):
        from app.orchestrator import schedule_round

        run = _make_run(status="running", round_number=0)
        asset = _make_asset(
            1, "example.com", AssetType.DOMAIN, AssetStatus.PENDING, discovery_run_id=1
        )

        db = MagicMock()
        db.get.return_value = run
        q = _mock_query_chain([asset])
        q.first.return_value = MagicMock()  # non-None → duplicate
        db.query.return_value = q

        mock_spec = MagicMock()
        mock_spec.tool = ToolName.WHOIS

        mock_task = MagicMock()
        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch("app.orchestrator.tools_for_asset_type", return_value=[mock_spec]),
            patch("app.tasks.run_tool_scan", mock_task),
        ):
            result = schedule_round(1)

        mock_task.delay.assert_not_called()
        assert result["status"] == "scheduled"


# ── collect_round ───────────────────────────────────────────────────────
#
# collect_round is a @celery_app.task(bind=True) — when called directly
# via the task proxy, Celery's __call__ passes args through to
# Task.run(), which prepends the task instance as `self`.  So callers
# should pass ONLY ``run_id`` (the `self` task instance is injected by
# Celery).  To observe retry behaviour we mock ``self.retry`` on the
# *task* object rather than passing a hand-rolled fake `self`.


class TestCollectRound:
    def test_skips_when_run_not_found(self):
        from app.orchestrator import collect_round

        db = MagicMock()
        db.get.return_value = None

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = collect_round(42)

        assert "error" in result

    def test_skips_when_run_not_running(self):
        from app.orchestrator import collect_round

        run = _make_run(status="completed")
        db = MagicMock()
        db.get.return_value = run

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = collect_round(1)

        assert result["status"] == "skipped"

    def test_retries_when_jobs_still_active(self):
        from app.orchestrator import collect_round

        run = _make_run(current_round_asset_ids=[1, 2])
        db = MagicMock()
        db.get.return_value = run
        q = _mock_query_chain()
        q.count.return_value = 1  # active job(s)
        db.query.return_value = q

        # Patch retry on the *task instance* — collect_round is a bound
        # task, so it receives `self` as the task and calls self.retry().
        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch.object(collect_round, "retry", side_effect=Exception("celery-retry")),
        ):
            with pytest.raises(Exception, match="celery-retry"):
                collect_round(1)

    def test_marks_assets_done_and_collects_spawned(self):
        from app.orchestrator import collect_round

        run = _make_run(current_round_asset_ids=[1], round_number=1, max_rounds=5)
        asset = _make_asset(1, status=AssetStatus.RUNNING)
        spawned = _make_asset(2, "sub.example.com", AssetType.SUBDOMAIN, AssetStatus.PENDING)
        spawned.discovery_run_id = None

        db = MagicMock()
        # db.get called for run + each asset in the round
        db.get.side_effect = lambda model, id_: run if id_ == 1 else asset if id_ == 1 else None
        # Actually: collect_round gets run via db.get(DiscoveryRun, run_id),
        # then for each aid in current_round_asset_ids: db.get(Asset, aid)
        db.get.side_effect = lambda model, id_: (
            {1: run, 2: asset}.get(id_) if id_ in (1, 2) else None
        )
        # Wait, that's wrong too. Let me think: db.get is called with (DiscoveryRun, 1)
        # then with (Asset, 1). Mock.get doesn't differentiate models.

        # Simpler: use a list side_effect for successive calls
        db.get.side_effect = [run, asset]

        q = _mock_query_chain()
        q.count.return_value = 0  # no active
        db.query.return_value = q

        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch("app.orchestrator._collect_spawned_assets", return_value=[spawned]),
            patch("app.orchestrator.schedule_round") as mock_sched,
        ):
            result = collect_round(1)

        assert result["status"] == "next_round"
        assert result["new_assets"] == 1
        assert spawned.discovery_run_id == 1
        mock_sched.delay.assert_called_once_with(1)

    def test_completes_run_when_no_spawned_at_max_rounds(self):
        from app.orchestrator import collect_round

        run = _make_run(current_round_asset_ids=[1], round_number=5, max_rounds=5)

        db = MagicMock()
        db.get.side_effect = [run, _make_asset(1, status=AssetStatus.RUNNING)]
        q = _mock_query_chain()
        q.count.return_value = 0
        db.query.return_value = q

        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch("app.orchestrator._collect_spawned_assets", return_value=[]),
            patch("app.orchestrator.schedule_round") as mock_sched,
        ):
            result = collect_round(1)

        assert result["status"] == "completed"
        assert result["final_status"] == "max_rounds_reached"
        assert run.completed_at is not None
        mock_sched.delay.assert_not_called()

    def test_completes_with_spawned_but_max_rounds_reached(self):
        from app.orchestrator import collect_round

        run = _make_run(current_round_asset_ids=[1], round_number=5, max_rounds=5)
        spawned = _make_asset(2)

        db = MagicMock()
        db.get.side_effect = [run, _make_asset(1, status=AssetStatus.RUNNING)]
        q = _mock_query_chain()
        q.count.return_value = 0
        db.query.return_value = q

        with (
            patch("app.orchestrator.SessionLocal", return_value=db),
            patch("app.orchestrator._collect_spawned_assets", return_value=[spawned]),
            patch("app.orchestrator.schedule_round") as mock_sched,
        ):
            result = collect_round(1)

        assert result["status"] == "completed"
        assert result["final_status"] == "max_rounds_reached"
        mock_sched.delay.assert_not_called()

    def test_completes_when_empty_round(self):
        from app.orchestrator import collect_round

        run = _make_run(current_round_asset_ids=None)

        db = MagicMock()
        db.get.return_value = run

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = collect_round(1)

        assert result["status"] == "completed"
        assert run.status == "completed"

    def test_noop_when_round_already_advanced(self):
        """Duplicate collect_round becomes a no-op when run is no longer running."""
        from app.orchestrator import collect_round

        run = _make_run(status="completed")
        db = MagicMock()
        db.get.return_value = run

        with patch("app.orchestrator.SessionLocal", return_value=db):
            result = collect_round(1)

        assert result["status"] == "skipped"


# ── _collect_spawned_assets ─────────────────────────────────────────────


class TestCollectSpawnedAssets:
    def test_finds_chained_assets(self):
        from app.orchestrator import _collect_spawned_assets

        run = _make_run(id_=1)
        spawned_asset = _make_asset(10, "10.0.0.1", AssetType.IP, discovery_run_id=None)

        db = MagicMock()
        # Three db.query() calls in _collect_spawned_assets:
        # 1. db.query(ScanJob.id).join(...).filter(...).subquery()
        # 2. db.query(ScanJob.spawned_asset_id).filter(...).distinct().all()
        # 3. db.query(Asset).filter(...).all()
        q1 = MagicMock()
        q1.join.return_value = q1
        q1.filter.return_value = q1
        q1.subquery.return_value = MagicMock(name="subq")

        q2 = MagicMock()
        q2.filter.return_value = q2
        q2.distinct.return_value = q2
        q2.all.return_value = [(10,)]

        q3 = MagicMock()
        q3.filter.return_value = q3
        q3.all.return_value = [spawned_asset]

        db.query.side_effect = [q1, q2, q3]

        result = _collect_spawned_assets(db, run)
        assert len(result) == 1
        assert result[0].id == 10

    def test_ignores_already_tagged_assets(self):
        from app.orchestrator import _collect_spawned_assets

        run = _make_run(id_=1)

        db = MagicMock()
        q1 = MagicMock()
        q1.join.return_value = q1
        q1.filter.return_value = q1
        q1.subquery.return_value = MagicMock(name="subq")

        q2 = MagicMock()
        q2.filter.return_value = q2
        q2.distinct.return_value = q2
        q2.all.return_value = [(10,)]

        q3 = MagicMock()
        q3.filter.return_value = q3
        q3.all.return_value = []  # already tagged → filtered out

        db.query.side_effect = [q1, q2, q3]

        result = _collect_spawned_assets(db, run)
        assert len(result) == 0

    def test_returns_empty_when_no_spawned_ids(self):
        from app.orchestrator import _collect_spawned_assets

        run = _make_run(id_=1)

        db = MagicMock()
        q1 = MagicMock()
        q1.join.return_value = q1
        q1.filter.return_value = q1
        q1.subquery.return_value = MagicMock(name="subq")

        q2 = MagicMock()
        q2.filter.return_value = q2
        q2.distinct.return_value = q2
        q2.all.return_value = []  # no spawned ids

        db.query.side_effect = [q1, q2]

        result = _collect_spawned_assets(db, run)
        assert result == []


# ── get_run_status ──────────────────────────────────────────────────────


class TestGetRunStatus:
    def test_returns_none_when_run_not_found(self):
        from app.orchestrator import get_run_status

        db = MagicMock()
        db.get.return_value = None

        assert get_run_status(db, 999) is None

    def test_returns_correct_counts(self):
        from app.orchestrator import get_run_status

        run = _make_run(id_=1, round_number=2, max_rounds=5)
        root = _make_asset(1, "example.com")

        db = MagicMock()
        # db.get called with (DiscoveryRun, run_id) then (Asset, root_asset_id)
        db.get.side_effect = [run, root]

        # All queries share the same base mock, but some use .join() and
        # some don't.  Make both chains work by having .join return self.
        base_q = MagicMock()
        base_q.filter.return_value = base_q
        base_q.join.return_value = base_q
        # count() calls: total_assets, pending, running, done, active_jobs
        base_q.count.side_effect = [10, 2, 3, 5, 1]
        db.query.return_value = base_q

        result = get_run_status(db, 1)

        assert result is not None
        assert result["id"] == 1
        assert result["round_number"] == 2
        assert result["max_rounds"] == 5
        assert result["status"] == "running"
        assert result["assets"]["total"] == 10
        assert result["assets"]["pending"] == 2
        assert result["assets"]["running"] == 3
        assert result["assets"]["done"] == 5
        assert result["active_jobs"] == 1
        assert result["root_asset"]["value"] == "example.com"


# ── Integration / import verification ───────────────────────────────────


class TestDiscoveryIntegration:
    def test_all_symbols_importable(self):
        from app.orchestrator import (
            _collect_spawned_assets,
            collect_round,
            create_discovery_run,
            get_run_status,
            schedule_round,
        )

        assert callable(schedule_round)
        assert callable(collect_round)
        assert callable(_collect_spawned_assets)
        assert callable(create_discovery_run)
        assert callable(get_run_status)
