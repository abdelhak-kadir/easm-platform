import logging
import os
from datetime import UTC, datetime

import redis
from celery.exceptions import MaxRetriesExceededError, Retry
from sqlalchemy.exc import IntegrityError

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, Finding, ScanJob, ScanResult, ScanStatus
from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError
from app.tools.registry import ToolSpec, get_tool_spec

_logger = logging.getLogger(__name__)

# ── collect_round poke debounce ──────────────────────────────────────

# Without dedup, N job completions per round produce N pokes to
# collect_round, each retrying up to 12 times — up to 12N retry tasks
# per round.  A Redis-backed distributed lock (SET NX EX) ensures only
# one poke per run_id across all Celery prefork workers within a 5 s
# window.

_REDIS_URL = os.environ.get("REDIS_URL")
_redis: "redis.Redis | None" = None


def _get_redis() -> "redis.Redis":
    """Lazy-init a Redis client shared across worker invocations."""
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
    return _redis


def _maybe_poke_collect_round(run_id: int) -> None:
    """Poke ``collect_round`` for *run_id* using a distributed debounce
    lock (Redis ``SET NX EX 15``).

    The lock TTL (15 s) is longer than the countdown (5 s) so a newly
    poked collector has time to start and claim the run before another
    poke fires.  Falls through to the poke if Redis is unavailable —
    duplicate pokes are harmless (idempotency guards in
    ``collect_round`` serialize them), but a missed poke would stall
    the wave forever.
    """
    from app.orchestrator import collect_round

    key = f"collect_round_poke:{run_id}"
    try:
        acquired = _get_redis().set(key, "1", nx=True, ex=15)
        if not acquired:
            return
    except Exception:
        # Redis unavailable — fall through and poke anyway.
        pass

    collect_round.apply_async((run_id,), countdown=5)


def _spawn_chained_scan(db, job: ScanJob, asset: Asset, spec: ToolSpec) -> None:
    """If `spec` declares a chained tool, resolve the spawn value from
    this asset, find-or-create the spawned asset, and queue a job for
    it. No-op if the spec doesn't chain or resolution fails/returns
    nothing (e.g. domain has no A record).

    Called for EVERY final outcome (completed, completed_no_data, AND
    failure) -- DNS resolution doesn't depend on WHOIS actually having a
    record for the domain, so a chain-eligible tool should still try even
    when its own lookup came back empty or errored out.

    Safe against concurrent workers: uses the DB unique constraint on
    (asset_id, tool) as a guardrail with an explicit pre-check for the
    common case.
    """
    if not spec.spawns or not spec.resolve_spawn_value:
        return

    spawn_value = spec.resolve_spawn_value(db, asset.value)
    if not spawn_value:
        return

    # Find-or-create the spawned asset.  The unique constraint on
    # (value, asset_type) prevents duplicates; if two workers race, one
    # gets IntegrityError and re-queries.
    spawned_asset = (
        db.query(Asset)
        .filter(Asset.value == spawn_value, Asset.asset_type == spec.spawn_asset_type)
        .first()
    )
    if spawned_asset is None:
        # Inherit the parent asset's discovery_run_id at creation time
        # so the spawn is immediately associated with the correct run.
        # This eliminates the race window where collect_round might miss
        # a late-created spawn whose parent's run already advanced.
        spawned_asset = Asset(
            value=spawn_value,
            asset_type=spec.spawn_asset_type,
            discovery_run_id=asset.discovery_run_id,
        )
        db.add(spawned_asset)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            spawned_asset = (
                db.query(Asset)
                .filter(Asset.value == spawn_value, Asset.asset_type == spec.spawn_asset_type)
                .first()
            )
            if spawned_asset is None:
                raise  # should never happen — constraint guarantees existence
        else:
            db.refresh(spawned_asset)

    # Check for existing spawn job — any status (PENDING, RUNNING,
    # COMPLETED, FAILED) means this asset+tool pair has already been
    # handled or is currently being handled.  FAILED jobs from earlier
    # rounds are still skipped; the wave orchestrator never re-spawns
    # the same pair.
    existing_job = (
        db.query(ScanJob)
        .filter(
            ScanJob.asset_id == spawned_asset.id,
            ScanJob.tool == spec.spawns,
        )
        .first()
    )
    if existing_job is not None:
        # Link the existing job to this parent for traceability, but
        # don't queue a duplicate.
        job.spawned_asset_id = spawned_asset.id
        job.spawned_job_id = existing_job.id
        db.commit()
        return

    # No existing job — create one and link it
    spawned_job = ScanJob(asset_id=spawned_asset.id, tool=spec.spawns, status=ScanStatus.PENDING)
    db.add(spawned_job)
    try:
        db.flush()
    except IntegrityError:
        # Another worker raced us to create this job (unique constraint on
        # asset_id+tool). Re-query and link to the winner.
        db.rollback()
        spawned_job = (
            db.query(ScanJob)
            .filter(
                ScanJob.asset_id == spawned_asset.id,
                ScanJob.tool == spec.spawns,
            )
            .first()
        )
        if spawned_job is None:
            raise  # should never happen

    job.spawned_asset_id = spawned_asset.id
    job.spawned_job_id = spawned_job.id
    db.commit()

    run_tool_scan.delay(spawned_job.id)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def run_tool_scan(self, job_id: int):
    """Run whichever tool a ScanJob was queued for.

    Generic over tools: the job carries a `ToolName`, the registry maps
    that to the tool's `run`/`parse` functions, and everything else
    (status transitions, retry-on-rate-limit, versioning, Finding
    persistence, and now tool-chaining) is identical no matter which
    tool ran. A new tool never needs a new Celery task -- only a new
    TOOL_REGISTRY entry.
    """
    db = SessionLocal()
    job = asset = spec = None
    should_chain = True  # reset on Retry; all other outcomes chain
    try:
        job = db.get(ScanJob, job_id)
        if job is None:
            raise ValueError(f"ScanJob {job_id} not found")

        # Skip jobs cancelled by the user while still queued
        if job.status == ScanStatus.FAILED and job.error_message == "Cancelled by user":
            _logger.info("Job %d was cancelled — skipping", job_id)
            should_chain = False  # cancelled jobs must not spawn downstream
            return {"job_id": job_id, "status": "cancelled"}

        asset = db.get(Asset, job.asset_id)
        if asset is None:
            raise ValueError(f"Asset {job.asset_id} not found")

        spec = get_tool_spec(job.tool)

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now(UTC)
        db.commit()

        last_result = (
            db.query(ScanResult)
            .join(ScanJob)
            .filter(ScanJob.asset_id == asset.id, ScanJob.tool == job.tool)
            .order_by(ScanResult.version.desc())
            .first()
        )
        next_version = (last_result.version + 1) if last_result else 1

        try:
            raw_data = spec.run(asset.value)
        except ToolRateLimitError as e:
            should_chain = False  # will retry — chain on the final outcome instead
            raise self.retry(exc=e) from e
        except ToolNoDataError as e:
            job.status = ScanStatus.COMPLETED
            job.error_message = str(e)[:1000]
            job.completed_at = datetime.now(UTC)
            db.add(ScanResult(scan_job_id=job.id, version=next_version, raw_data={}))
            db.commit()
            return {"job_id": job.id, "status": "completed_no_data"}
        except ToolScanError as e:
            # Legitimate tool failure (e.g. WHOIS server returned no data,
            # DNS lookup failed).  Mark the job FAILED and return normally
            # so Celery doesn't log "raised unexpected" at ERROR level —
            # this is an expected outcome, not a bug.
            job.status = ScanStatus.FAILED
            job.error_message = str(e)[:1000]
            job.completed_at = datetime.now(UTC)
            db.commit()
            return {"job_id": job.id, "status": "failed", "error": str(e)}

        result = ScanResult(scan_job_id=job.id, version=next_version, raw_data=raw_data)
        db.add(result)
        db.commit()
        db.refresh(result)

        # Re-check whether the job was cancelled while the tool was running
        # (the cancel endpoint flips the DB row while the worker is busy).
        db.refresh(job)
        if job.status == ScanStatus.FAILED and job.error_message == "Cancelled by user":
            _logger.info("Job %d was cancelled during scan — discarding result", job_id)
            should_chain = False  # cancelled jobs must not spawn downstream
            # Clean up the orphaned ScanResult we just persisted
            db.delete(result)
            db.commit()
            return {"job_id": job_id, "status": "cancelled"}

        for finding_data in spec.parse(raw_data):
            db.add(Finding(scan_result_id=result.id, **finding_data))

        job.status = ScanStatus.COMPLETED
        job.completed_at = datetime.now(UTC)
        db.commit()

        return {"job_id": job.id, "status": "completed", "version": next_version}

    except MaxRetriesExceededError:
        # Celery exhausted retries — mark the job FAILED so the wave
        # orchestrator doesn't wait forever.  Must be caught BEFORE the
        # generic `except Retry` below.
        should_chain = False
        _logger.warning("Job %d exceeded max retries — marking FAILED", job_id)
        try:
            job = db.get(ScanJob, job_id)
            if job is not None:
                job.status = ScanStatus.FAILED
                job.error_message = "Max retries exceeded"
                job.completed_at = datetime.now(UTC)
                db.commit()
        except Exception:
            _logger.exception("Failed to mark job %d as FAILED after retry exhaustion", job_id)
        raise  # let Celery handle the task failure

    except Retry:
        should_chain = False
        raise

    except Exception as e:
        job = db.get(ScanJob, job_id)
        if job is not None:
            job.status = ScanStatus.FAILED
            job.error_message = str(e)[:1000]
            job.completed_at = datetime.now(UTC)
            db.commit()
        raise

    finally:
        if should_chain and job is not None and asset is not None and spec is not None:
            try:
                _spawn_chained_scan(db, job, asset, spec)
            except Exception:
                _logger.warning(
                    "Chained scan dispatch failed for job %d (tool=%s → %s)",
                    job.id,
                    spec.tool,
                    spec.spawns,
                    exc_info=True,
                )

        # If this asset belongs to a DiscoveryRun, poke collect_round so the
        # wave orchestrator can check whether the round is complete.
        # Pokes are debounced to prevent N-job completion storms (audit N13).
        if asset is not None and asset.discovery_run_id is not None:
            try:
                _maybe_poke_collect_round(asset.discovery_run_id)
            except Exception:
                _logger.debug(
                    "Failed to enqueue collect_round for run %d",
                    asset.discovery_run_id,
                    exc_info=True,
                )

        db.close()


# ── periodic maintenance ────────────────────────────────────────────

# Jobs stuck RUNNING longer than this are considered lost (worker crash,
# network partition, etc.) and will be reaped.  5 min is generous — no
# legitimate tool takes > 2 min (theHarvester with CRT.sh timeout + retry
# is ~60 s; Nmap/HTTPX are similar).
_STUCK_JOB_TIMEOUT_SECONDS = 60 * 5  # 5 minutes


@celery_app.task
def reap_stuck_jobs() -> dict:
    """Periodic task: mark RUNNING jobs as FAILED if their ``started_at``
    timestamp is older than ``_STUCK_JOB_TIMEOUT_SECONDS``.

    This is the recovery path for worker crashes — without ``acks_late``,
    a dead worker's task is never redelivered, so the database row stays
    RUNNING forever and the wave orchestrator hangs.  The reaper closes
    that loop.
    """
    from datetime import timedelta

    db = SessionLocal()
    try:
        cutoff = datetime.now(UTC) - timedelta(seconds=_STUCK_JOB_TIMEOUT_SECONDS)
        stuck = (
            db.query(ScanJob)
            .filter(
                ScanJob.status == ScanStatus.RUNNING,
                ScanJob.started_at.isnot(None),
                ScanJob.started_at < cutoff,
            )
            .all()
        )

        reaped = 0
        runs_to_poke: set[int] = set()
        for job in stuck:
            job.status = ScanStatus.FAILED
            job.error_message = "Worker lost — timed out after 30 min"
            job.completed_at = datetime.now(UTC)
            reaped += 1
            _logger.warning(
                "Reaping stuck job %d (asset=%d, tool=%s, started=%s)",
                job.id,
                job.asset_id,
                job.tool,
                job.started_at,
            )
            # Collect affected run IDs so we can poke collect_round
            asset = db.get(Asset, job.asset_id)
            if asset is not None and asset.discovery_run_id is not None:
                runs_to_poke.add(asset.discovery_run_id)

        if reaped > 0:
            db.commit()
            _logger.info("Reaped %d stuck job(s) across %d run(s)", reaped, len(runs_to_poke))

            # Poke collect_round for each affected run so the wave can
            # continue after stuck jobs are cleared.
            from app.orchestrator import collect_round

            for run_id in runs_to_poke:
                try:
                    collect_round.apply_async((run_id,), countdown=3)
                except Exception:
                    _logger.warning(
                        "reap_stuck_jobs — failed to poke collect_round for run %d", run_id
                    )

        return {"reaped": reaped, "cutoff": cutoff.isoformat()}
    except Exception:
        _logger.exception("reap_stuck_jobs failed")
        raise
    finally:
        db.close()
