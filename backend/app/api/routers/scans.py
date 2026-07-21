from fastapi import APIRouter, HTTPException

from app.api.deps import DBSession
from app.models import Asset, ScanJob, ScanStatus, ToolName

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/shodan/{asset_id}")
def trigger_shodan_scan(asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    job = ScanJob(asset_id=asset.id, tool=ToolName.SHODAN, status=ScanStatus.PENDING)
    db.add(job)
    db.commit()
    db.refresh(job)

    from app.tasks import run_shodan_scan

    task = run_shodan_scan.delay(job.id)
    return {"task_id": task.id, "job_id": job.id, "status": "queued"}


@router.get("/{job_id}")
def get_scan_job(job_id: int, db: DBSession):
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {
        "id": job.id,
        "status": job.status,
        "tool": job.tool,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
    }
