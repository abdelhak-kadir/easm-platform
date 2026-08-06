"""Wave-based discovery orchestrator.

Replaces point-to-point chaining with a ``schedule_round → collect_round``
loop powered by the ``DiscoveryRun`` table (§1).  Each round queues every
applicable tool against every pending asset in the run; when all jobs
finish, spawned assets are collected and the next round begins — up to
``max_rounds``.
"""

import logging
from datetime import UTC, datetime

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, AssetStatus, DiscoveryRun, ScanJob, ScanStatus
from app.tools.registry import tools_for_asset_type

_logger = logging.getLogger(__name__)

# Maximum number of times collect_round will retry itself while waiting
# for in-flight scan jobs to settle (5 s delay × 12 attempts = 60 s window).
_COLLECT_MAX_RETRIES = 12


# ── public API (called from routers) ──────────────────────────────────


def create_discovery_run(db, root_asset_id: int, max_rounds: int = 5) -> DiscoveryRun:
    """Create a ``DiscoveryRun``, tag the root asset, and commit.

    Returns the persisted run so the caller can enqueue the first round.
    """
    root = db.get(Asset, root_asset_id)
    if root is None:
        raise ValueError(f"Asset {root_asset_id} not found")

    run = DiscoveryRun(root_asset_id=root_asset_id, max_rounds=max_rounds)
    db.add(run)
    db.flush()  # get run.id

    root.discovery_run_id = run.id
    # Leave root.status as PENDING — schedule_round picks up PENDING
    # assets and sets them to RUNNING itself.
    db.commit()
    db.refresh(run)
    return run


# ── Celery tasks ──────────────────────────────────────────────────────


@celery_app.task
def schedule_round(run_id: int) -> dict:
    """Queue every applicable tool for every PENDING asset in *run_id*.

    Assets are set to RUNNING and their ids are recorded in the run's
    ``current_round_asset_ids`` column.
    """
    db = SessionLocal()
    try:
        run = db.get(DiscoveryRun, run_id)
        if run is None:
            return {"error": f"DiscoveryRun {run_id} not found"}

        if run.status != "running":
            return {"status": "skipped", "reason": f"run status is '{run.status}'"}

        # Gather PENDING assets for this run
        pending = (
            db.query(Asset)
            .filter(
                Asset.discovery_run_id == run_id,
                Asset.status == AssetStatus.PENDING,
            )
            .all()
        )

        if not pending:
            run.status = "completed"
            run.completed_at = datetime.now(UTC)
            db.commit()
            return {"status": "completed", "reason": "no pending assets"}

        asset_ids: list[int] = []
        for asset in pending:
            asset.status = AssetStatus.RUNNING
            db.flush()
            asset_ids.append(asset.id)

            for spec in tools_for_asset_type(asset.asset_type):
                existing = (
                    db.query(ScanJob)
                    .filter(
                        ScanJob.asset_id == asset.id,
                        ScanJob.tool == spec.tool,
                        ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                    )
                    .first()
                )
                if existing:
                    continue  # already queued or running — skip duplicate

                job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
                db.add(job)
                db.flush()

                # Lazy import — avoids circular dependency at module level
                from app.tasks import run_tool_scan

                run_tool_scan.delay(job.id)

        run.round_number += 1
        run.current_round_asset_ids = asset_ids
        db.commit()

        _logger.info(
            "Round %d scheduled — %d asset(s), run_id=%d",
            run.round_number,
            len(asset_ids),
            run_id,
        )
        return {
            "status": "scheduled",
            "round": run.round_number,
            "asset_count": len(asset_ids),
        }
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=_COLLECT_MAX_RETRIES, default_retry_delay=5)
def collect_round(self, run_id: int) -> dict:
    """Check whether every scan for the current round has settled.

    If jobs are still PENDING/RUNNING the task retries itself (Celery
    ``self.retry``) after a short delay.  Once everything is done the
    round's assets are marked DONE, spawned assets are collected, and
    either the next round is scheduled or the run is completed.
    """
    db = SessionLocal()
    try:
        run = db.get(DiscoveryRun, run_id)
        if run is None:
            return {"error": f"DiscoveryRun {run_id} not found"}

        if run.status != "running":
            return {"status": "skipped", "reason": f"run status is '{run.status}'"}

        if not run.current_round_asset_ids:
            # Nothing to collect — probably schedule_round found no work
            run.status = "completed"
            run.completed_at = datetime.now(UTC)
            db.commit()
            return {"status": "completed", "reason": "empty round"}

        # Count still-active jobs for this round's assets
        active = (
            db.query(ScanJob)
            .filter(
                ScanJob.asset_id.in_(run.current_round_asset_ids),
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
            .count()
        )

        if active > 0:
            _logger.debug("collect_round run_id=%d — %d job(s) still active", run_id, active)
            raise self.retry()

        # ── all jobs settled ──────────────────────────────────────

        # Mark round assets DONE
        for aid in run.current_round_asset_ids:
            asset = db.get(Asset, aid)
            if asset is not None and asset.status == AssetStatus.RUNNING:
                asset.status = AssetStatus.DONE

        db.flush()

        # Collect spawned assets (created by _spawn_chained_scan during this run)
        spawned = _collect_spawned_assets(db, run)

        if spawned and run.round_number < run.max_rounds:
            for a in spawned:
                a.discovery_run_id = run.id
            db.commit()
            _logger.info(
                "Round %d collected — %d new asset(s), advancing to round %d, run_id=%d",
                run.round_number,
                len(spawned),
                run.round_number + 1,
                run_id,
            )
            schedule_round.delay(run_id)
            return {
                "status": "next_round",
                "round": run.round_number,
                "new_assets": len(spawned),
            }

        # No more rounds — finish
        run.status = "max_rounds_reached" if run.round_number >= run.max_rounds else "completed"
        run.completed_at = datetime.now(UTC)
        db.commit()

        _logger.info(
            "Run %d finished — status=%s, rounds=%d",
            run_id,
            run.status,
            run.round_number,
        )
        return {
            "status": "completed",
            "rounds": run.round_number,
            "final_status": run.status,
        }
    finally:
        db.close()


# ── helpers ───────────────────────────────────────────────────────────


def _collect_spawned_assets(db, run: DiscoveryRun) -> list[Asset]:
    """Return assets that were spawned by scan jobs belonging to *run*
    but are not yet tagged with the run's ``discovery_run_id``.
    """
    # Jobs for this run's rounds — any scan job whose owning asset
    # belongs to the run (discovery_run_id == run.id).
    run_job_ids = (
        db.query(ScanJob.id)
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(Asset.discovery_run_id == run.id)
        .subquery()
    )

    spawned_ids = (
        db.query(ScanJob.spawned_asset_id)
        .filter(
            ScanJob.id.in_(run_job_ids),
            ScanJob.spawned_asset_id.isnot(None),
        )
        .distinct()
        .all()
    )

    if not spawned_ids:
        return []

    spawned_id_list = [row[0] for row in spawned_ids]

    # Only pick up assets that aren't already tagged for this (or another) run
    return (
        db.query(Asset)
        .filter(
            Asset.id.in_(spawned_id_list),
            Asset.discovery_run_id.is_(None),
        )
        .all()
    )


def get_run_status(db, run_id: int) -> dict | None:
    """Return a frontend-friendly status object for *run_id*."""
    run = db.get(DiscoveryRun, run_id)
    if run is None:
        return None

    root = db.get(Asset, run.root_asset_id)

    total_assets = db.query(Asset).filter(Asset.discovery_run_id == run_id).count()
    pending = (
        db.query(Asset)
        .filter(
            Asset.discovery_run_id == run_id,
            Asset.status == AssetStatus.PENDING,
        )
        .count()
    )
    running = (
        db.query(Asset)
        .filter(
            Asset.discovery_run_id == run_id,
            Asset.status == AssetStatus.RUNNING,
        )
        .count()
    )
    done = (
        db.query(Asset)
        .filter(
            Asset.discovery_run_id == run_id,
            Asset.status == AssetStatus.DONE,
        )
        .count()
    )

    active_jobs = (
        db.query(ScanJob)
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(
            Asset.discovery_run_id == run_id,
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
        .count()
    )

    return {
        "id": run.id,
        "root_asset": {
            "id": root.id if root else None,
            "value": root.value if root else None,
        },
        "round_number": run.round_number,
        "max_rounds": run.max_rounds,
        "status": run.status,
        "assets": {
            "total": total_assets,
            "pending": pending,
            "running": running,
            "done": done,
        },
        "active_jobs": active_jobs,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }
