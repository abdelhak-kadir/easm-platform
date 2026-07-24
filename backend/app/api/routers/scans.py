from fastapi import APIRouter, HTTPException

from app.api.deps import DBSession
from app.models import Asset, ScanJob, ScanResult, ScanStatus, ToolName
from app.tools.registry import get_tool_spec, tools_for_asset_type

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/discover/{asset_id}")
def trigger_discovery(asset_id: int, db: DBSession):
    """Queue every tool registered for this asset's type.

    This is the "Ordonnanceur dynamique" / "Sélection des outils selon
    le type d'actif" entry point from the discovery flow -- the caller
    doesn't pick a tool, the registry does, based on asset.asset_type.

    NOTE: must stay registered before `/{tool}/{asset_id}` below. Both
    are POST routes with a literal-or-variable first segment plus
    `asset_id`, so route registration order decides whether "discover"
    resolves here or gets validated (and rejected) as a ToolName.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    specs = tools_for_asset_type(asset.asset_type)
    if not specs:
        raise HTTPException(
            status_code=400,
            detail=f"No tools registered for asset type '{asset.asset_type}'",
        )

    from app.tasks import run_tool_scan

    queued = []
    for spec in specs:
        job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
        db.add(job)
        db.commit()
        db.refresh(job)
        task = run_tool_scan.delay(job.id)
        queued.append({"task_id": task.id, "job_id": job.id, "tool": spec.tool})

    return {"asset_id": asset.id, "queued": queued}


@router.post("/{tool}/{asset_id}")
def trigger_tool_scan(tool: ToolName, asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        get_tool_spec(tool)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    job = ScanJob(asset_id=asset.id, tool=tool, status=ScanStatus.PENDING)
    db.add(job)
    db.commit()
    db.refresh(job)

    from app.tasks import run_tool_scan

    task = run_tool_scan.delay(job.id)
    return {"task_id": task.id, "job_id": job.id, "status": "queued", "tool": tool}


def _serialize_job(db: DBSession, job: ScanJob) -> dict:
    """Shared shape for a job, including its chained-scan info if any
    (see ToolSpec.spawns / app.tasks._spawn_chained_scan)."""
    spawned_job = db.get(ScanJob, job.spawned_job_id) if job.spawned_job_id else None
    spawned_asset = db.get(Asset, job.spawned_asset_id) if job.spawned_asset_id else None
    return {
        "id": job.id,
        "tool": job.tool,
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
        "spawned_asset_id": job.spawned_asset_id,
        "spawned_asset_value": spawned_asset.value if spawned_asset else None,
        "spawned_job_id": job.spawned_job_id,
        "spawned_job_tool": spawned_job.tool if spawned_job else None,
        "spawned_job_status": spawned_job.status if spawned_job else None,
    }


@router.get("/{job_id}")
def get_scan_job(job_id: int, db: DBSession):
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return _serialize_job(db, job)


@router.get("/{job_id}/results")
def get_scan_results(job_id: int, db: DBSession):
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")

    result = (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .order_by(ScanResult.version.desc())
        .first()
    )
    if result is None:
        return {"job_id": job_id, "status": job.status, "version": None, "findings": []}

    return {
        "job_id": job_id,
        "status": job.status,
        "version": result.version,
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "title": f.title,
                "severity": f.severity,
                "data": f.data,
            }
            for f in result.findings
        ],
    }


@router.get("/asset/{asset_id}")
def list_scans_for_asset(asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.asset_id == asset_id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )
    return [_serialize_job(db, j) for j in jobs]
