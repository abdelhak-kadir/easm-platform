"""Wave-based discovery orchestrator.

Replaces point-to-point chaining with a ``schedule_round → collect_round``
loop powered by the ``DiscoveryRun`` table (§1).  Each round queues every
applicable tool against every pending asset in the run; when all jobs
finish, spawned assets are collected and the next round begins — up to
``max_rounds``.
"""

import logging
from datetime import UTC, datetime

from celery.exceptions import Retry
from sqlalchemy.exc import IntegrityError

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, AssetStatus, DiscoveryRun, RunStatus, ScanJob, ScanStatus
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

    existing = (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.root_asset_id == root_asset_id,
            DiscoveryRun.status == RunStatus.RUNNING,
        )
        .first()
    )
    if existing is not None:
        raise ValueError(
            f"Asset {root_asset_id} already has an active discovery run "
            f"(run_id={existing.id}). Wait for it to complete before starting a new one."
        )

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


# Statuses that mean "there is already a ScanJob for this (asset, tool)
# pair — do not create another one."  We treat COMPLETED and FAILED the
# same way because the unique constraint on (asset_id, tool) makes
# creating a second row impossible regardless.  Re-scanning the same
# asset with the same tool is a future feature, not the current wave
# orchestrator behaviour.
_EXISTING_JOB_STATUSES = frozenset(
    {ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.COMPLETED, ScanStatus.FAILED}
)


@celery_app.task(autoretry_for=(Exception,), max_retries=3, default_retry_delay=10)
def schedule_round(run_id: int) -> dict:
    """Queue every applicable tool for every PENDING asset in *run_id*.

    Assets are set to RUNNING and their ids are recorded in the run's
    ``current_round_asset_ids`` column.

    Already-scanned assets (those with any existing ScanJob for a tool)
    are skipped — each asset+tool pair is scanned at most once per run.

    Uses a savepoint around individual job inserts so a concurrent
    duplicate never rolls back the entire round's work.
    """
    db = SessionLocal()
    job_ids_to_dispatch: list[int] = []
    try:
        # SELECT ... FOR UPDATE serializes concurrent schedule_round
        # calls, preventing phantom round_number increments when two
        # instances snapshot the same PENDING list and both increment
        # the counter (audit N7).  The lock is held only for the
        # duration of DB reads/writes — Celery dispatch happens after
        # commit, outside the critical section.
        run = db.query(DiscoveryRun).filter(DiscoveryRun.id == run_id).with_for_update().first()
        if run is None:
            return {"error": f"DiscoveryRun {run_id} not found"}

        if run.status != RunStatus.RUNNING:
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
            # No PENDING work — but there might be RUNNING assets (e.g. from
            # continue_discovery) whose in-flight jobs will poke collect_round.
            running_count = (
                db.query(Asset)
                .filter(
                    Asset.discovery_run_id == run_id,
                    Asset.status == AssetStatus.RUNNING,
                )
                .count()
            )
            if running_count > 0:
                return {
                    "status": "waiting",
                    "reason": f"{running_count} asset(s) still running — "
                    "collect_round will advance when jobs settle",
                }

            run.status = RunStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            db.commit()
            return {"status": "completed", "reason": "no pending or running assets"}

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
                        ScanJob.status.in_(_EXISTING_JOB_STATUSES),
                    )
                    .first()
                )
                if existing is not None:
                    continue  # already tracked — skip

                job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
                db.add(job)
                # Savepoint: if a concurrent schedule_round already inserted
                # this (asset, tool) pair, only *this* insert rolls back —
                # the rest of the round is untouched.
                try:
                    with db.begin_nested():
                        db.flush()
                except IntegrityError:
                    _logger.debug(
                        "schedule_round run_id=%d — duplicate (asset=%d, tool=%s), skipped",
                        run_id,
                        asset.id,
                        spec.tool,
                    )
                    db.rollback()  # roll back the savepoint only
                    continue

                db.refresh(job)
                job_ids_to_dispatch.append(job.id)

        run.round_number += 1
        run.current_round_asset_ids = asset_ids
        db.commit()

        # ── dispatch AFTER commit — workers never see uncommitted rows ──
        if job_ids_to_dispatch:
            # Lazy import — avoids circular dependency at module level
            from app.tasks import run_tool_scan

            for job_id in job_ids_to_dispatch:
                try:
                    run_tool_scan.delay(job_id)
                except Exception:
                    _logger.warning(
                        "schedule_round run_id=%d — failed to dispatch job %d "
                        "(Redis unavailable?). Job will be reaped by periodic sweep.",
                        run_id,
                        job_id,
                    )

        _logger.info(
            "Round %d scheduled — %d asset(s), %d job(s), run_id=%d",
            run.round_number,
            len(asset_ids),
            len(job_ids_to_dispatch),
            run_id,
        )
        return {
            "status": "scheduled",
            "round": run.round_number,
            "asset_count": len(asset_ids),
            "job_count": len(job_ids_to_dispatch),
        }
    except Exception:
        _logger.exception("schedule_round run_id=%d failed", run_id)
        raise
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=_COLLECT_MAX_RETRIES, default_retry_delay=5)
def collect_round(self, run_id: int) -> dict:
    """Check whether every scan for the current round has settled.

    If jobs are still PENDING/RUNNING the task retries itself (Celery
    ``self.retry``) after a short delay.  Once everything is done the
    round's assets are marked DONE, spawned assets are collected, and
    either the next round is scheduled or the run is completed.

    Concurrency-safe via two guards:

    1. **Fast-path idempotency** — if all round assets are already DONE,
       the round was settled by a previous collector.  Return immediately;
       do NOT proceed to spawn collection or termination.  The collector
       that actually performed the settle is solely responsible for the
       advance/terminate decision.

    2. **SELECT FOR UPDATE row lock** — before performing the settle, the
       DiscoveryRun row is locked.  After acquiring the lock the run state
       is re-verified.  This serializes concurrent collectors so exactly
       one performs the advance/terminate transition.  The critical section
       is milliseconds of DB reads/writes with zero external I/O.
    """
    db = SessionLocal()
    try:
        run = db.get(DiscoveryRun, run_id)
        if run is None:
            return {"error": f"DiscoveryRun {run_id} not found"}

        if run.status != RunStatus.RUNNING:
            return {"status": "skipped", "reason": f"run status is '{run.status}'"}

        if not run.current_round_asset_ids:
            # Nothing to collect — probably schedule_round found no work
            run.status = RunStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            db.commit()
            return {"status": "completed", "reason": "empty round"}

        # ── fast-path idempotency — has this round already been settled? ──
        round_assets = db.query(Asset).filter(Asset.id.in_(run.current_round_asset_ids)).all()
        if all(a.status == AssetStatus.DONE for a in round_assets):
            _logger.debug(
                "collect_round run_id=%d round=%d — already settled by another collector",
                run_id,
                run.round_number,
            )
            return {
                "status": "already_settled",
                "round": run.round_number,
                "reason": "another collector already settled this round",
            }

        # ── count still-active jobs ──────────────────────────────────
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

        # ── acquire row lock and re-verify round identity ─────────────
        # Serializes concurrent collectors so exactly one performs the
        # settle + advance/terminate transition.
        run_locked = (
            db.query(DiscoveryRun).filter(DiscoveryRun.id == run_id).with_for_update().first()
        )

        if run_locked is None:
            return {"error": f"DiscoveryRun {run_id} vanished"}
        if run_locked.status != RunStatus.RUNNING:
            return {
                "status": "skipped",
                "reason": f"run status changed to '{run_locked.status}'",
            }
        if run_locked.current_round_asset_ids != run.current_round_asset_ids:
            _logger.debug(
                "collect_round run_id=%d — round identity changed under us " "(was %s, now %s)",
                run_id,
                run.current_round_asset_ids,
                run_locked.current_round_asset_ids,
            )
            return {
                "status": "already_settled",
                "round": run_locked.round_number,
                "reason": "round identity changed — another collector advanced the run",
            }

        # ── mark round assets DONE ──────────────────────────────────
        for asset in round_assets:
            if asset.status == AssetStatus.RUNNING:
                asset.status = AssetStatus.DONE
        db.flush()

        # ── collect spawned assets ──────────────────────────────────
        spawned = _collect_spawned_assets(db, run_locked)

        if spawned and run_locked.round_number < run_locked.max_rounds:
            for a in spawned:
                a.discovery_run_id = run_locked.id
            db.commit()
            _logger.info(
                "Round %d collected — %d new asset(s), advancing to round %d, run_id=%d",
                run_locked.round_number,
                len(spawned),
                run_locked.round_number + 1,
                run_id,
            )
            schedule_round.delay(run_id)
            return {
                "status": "next_round",
                "round": run_locked.round_number,
                "new_assets": len(spawned),
            }

        # ── no more rounds — finish ────────────────────────────────
        run_locked.status = (
            RunStatus.MAX_ROUNDS_REACHED
            if run_locked.round_number >= run_locked.max_rounds
            else RunStatus.COMPLETED
        )
        run_locked.completed_at = datetime.now(UTC)
        db.commit()

        _logger.info(
            "Run %d finished — status=%s, rounds=%d",
            run_id,
            run_locked.status,
            run_locked.round_number,
        )
        return {
            "status": "completed",
            "rounds": run_locked.round_number,
            "final_status": run_locked.status,
        }
    except Retry:
        raise
    except Exception:
        _logger.exception("collect_round run_id=%d failed", run_id)
        raise
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
