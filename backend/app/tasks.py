from datetime import UTC, datetime

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, Finding, ScanJob, ScanResult, ScanStatus, ToolName
from app.tools.shodan import parse as shodan_parse
from app.tools.shodan import scan as shodan_scan


@celery_app.task(bind=True)
def run_shodan_scan(self, asset_id: int):
    db = SessionLocal()
    try:
        asset = db.get(Asset, asset_id)
        if asset is None:
            raise ValueError(f"Asset {asset_id} not found")

        job = ScanJob(
            asset_id=asset.id,
            tool=ToolName.SHODAN,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        try:
            raw_data = shodan_scan.run(asset.value)

            last_result = (
                db.query(ScanResult)
                .join(ScanJob)
                .filter(ScanJob.asset_id == asset.id, ScanJob.tool == ToolName.SHODAN)
                .order_by(ScanResult.version.desc())
                .first()
            )
            next_version = (last_result.version + 1) if last_result else 1

            result = ScanResult(scan_job_id=job.id, version=next_version, raw_data=raw_data)
            db.add(result)
            db.commit()
            db.refresh(result)

            for finding_data in shodan_parse.parse(raw_data):
                db.add(Finding(scan_result_id=result.id, **finding_data))

            job.status = ScanStatus.COMPLETED
            job.completed_at = datetime.now(UTC)
            db.commit()

            return {"job_id": job.id, "status": "completed", "version": next_version}

        except Exception as e:
            job.status = ScanStatus.FAILED
            job.error_message = str(e)[:1000]
            job.completed_at = datetime.now(UTC)
            db.commit()
            raise
    finally:
        db.close()
