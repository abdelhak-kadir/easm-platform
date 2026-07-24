from datetime import UTC, datetime

from celery.exceptions import Retry

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, Finding, ScanJob, ScanResult, ScanStatus
from app.tools.base import ToolNoDataError, ToolRateLimitError
from app.tools.registry import ToolSpec, get_tool_spec


def _spawn_chained_scan(db, job: ScanJob, asset: Asset, spec: ToolSpec) -> None:
    """If `spec` declares a chained tool, resolve the spawn value from
    this asset, find-or-create the spawned asset, and queue a job for
    it. No-op if the spec doesn't chain or resolution fails/returns
    nothing (e.g. domain has no A record).

    Called for BOTH the "completed" and "completed_no_data" outcomes --
    DNS resolution doesn't depend on WHOIS actually having a record for
    the domain, so a chain-eligible tool should still try even when its
    own lookup came back empty.
    """
    if not spec.spawns or not spec.resolve_spawn_value:
        return

    spawn_value = spec.resolve_spawn_value(asset.value)
    if not spawn_value:
        return

    spawned_asset = (
        db.query(Asset)
        .filter(Asset.value == spawn_value, Asset.asset_type == spec.spawn_asset_type)
        .first()
    )
    if spawned_asset is None:
        spawned_asset = Asset(value=spawn_value, asset_type=spec.spawn_asset_type)
        db.add(spawned_asset)
        db.commit()
        db.refresh(spawned_asset)

    spawned_job = ScanJob(asset_id=spawned_asset.id, tool=spec.spawns, status=ScanStatus.PENDING)
    db.add(spawned_job)
    db.commit()
    db.refresh(spawned_job)

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
    try:
        job = db.get(ScanJob, job_id)
        if job is None:
            raise ValueError(f"ScanJob {job_id} not found")

        asset = db.get(Asset, job.asset_id)
        if asset is None:
            raise ValueError(f"Asset {job.asset_id} not found")

        spec = get_tool_spec(job.tool)

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now(UTC)
        db.commit()

        try:
            raw_data = spec.run(asset.value)
        except ToolRateLimitError as e:
            # Transient — let Celery retry with backoff instead of failing the job.
            raise self.retry(exc=e) from e
        except ToolNoDataError as e:
            job.status = ScanStatus.COMPLETED
            job.error_message = str(e)[:1000]
            job.completed_at = datetime.now(UTC)
            db.commit()
            _spawn_chained_scan(db, job, asset, spec)
            return {"job_id": job.id, "status": "completed_no_data"}

        last_result = (
            db.query(ScanResult)
            .join(ScanJob)
            .filter(ScanJob.asset_id == asset.id, ScanJob.tool == job.tool)
            .order_by(ScanResult.version.desc())
            .first()
        )
        next_version = (last_result.version + 1) if last_result else 1

        result = ScanResult(scan_job_id=job.id, version=next_version, raw_data=raw_data)
        db.add(result)
        db.commit()
        db.refresh(result)

        for finding_data in spec.parse(raw_data):
            db.add(Finding(scan_result_id=result.id, **finding_data))

        job.status = ScanStatus.COMPLETED
        job.completed_at = datetime.now(UTC)
        db.commit()

        _spawn_chained_scan(db, job, asset, spec)

        return {"job_id": job.id, "status": "completed", "version": next_version}

    except Retry:
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
        db.close()
