from fastapi import APIRouter, HTTPException
from sqlalchemy import func

from app.api.deps import DBSession
from app.api.schemas import AcceptSuggestedAssets
from app.models import Asset, AssetType, ScanJob, ScanResult, ScanStatus, ToolName
from app.tools.registry import get_tool_spec, tools_for_asset_type
from app.tools.shodan.org_search import (
    ShodanSearchError,
    is_likely_shared_hosting,
    search_by_net,
    search_by_org,
)

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


@router.post("/suggest-assets/accept")
def accept_suggested_assets(payload: AcceptSuggestedAssets, db: DBSession):
    """Turn a chosen subset of suggested IPs into real Assets and queue
    discovery for each -- same tools-for-asset-type flow as
    /scans/discover/{asset_id}, just for several assets at once."""
    from app.tasks import run_tool_scan
    from app.tools.registry import tools_for_asset_type

    created = []
    for value in payload.ips:
        asset = (
            db.query(Asset).filter(Asset.value == value, Asset.asset_type == AssetType.IP).first()
        )
        is_new = asset is None
        if is_new:
            asset = Asset(value=value, asset_type=AssetType.IP)
            db.add(asset)
            db.commit()
            db.refresh(asset)

        queued = []
        if is_new:
            for spec in tools_for_asset_type(AssetType.IP):
                job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
                db.add(job)
                db.commit()
                db.refresh(job)
                task = run_tool_scan.delay(job.id)
                queued.append({"task_id": task.id, "job_id": job.id, "tool": spec.tool})

        created.append(
            {"asset_id": asset.id, "value": asset.value, "created": is_new, "queued": queued}
        )

    return {"created": created}


@router.post("/{tool}/{asset_id}")
def trigger_tool_scan(tool: ToolName, asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        spec = get_tool_spec(tool)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # trigger_discovery (above) only ever queues tools that
    # tools_for_asset_type() says apply to the asset -- this endpoint
    # bypasses that selection (the caller names the tool directly), so
    # it needs its own check or a mismatched pairing like
    # (shodan, a domain asset) can be queued and silently "work"
    # (Shodan resolves hostnames fine) even though it's not a valid
    # combination per the registry.
    if asset.asset_type not in spec.asset_types:
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{tool}' does not apply to asset type '{asset.asset_type}'",
        )

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


def _serialize_job_with_asset(db: DBSession, job: ScanJob) -> dict:
    """Same as `_serialize_job`, plus the *owning* asset's identity.

    Used by the dashboard feed (`GET /scans`), which spans every asset
    at once, so each row needs to say which target it belongs to --
    unlike `_serialize_job`, which is used from an asset-scoped context
    where the caller already knows that.
    """
    asset = db.get(Asset, job.asset_id)
    return {
        **_serialize_job(db, job),
        "asset_id": job.asset_id,
        "asset_value": asset.value if asset else None,
        "asset_type": asset.asset_type if asset else None,
    }


@router.get("")
def list_scans(db: DBSession, limit: int = 50, status: ScanStatus | None = None):
    """Recent scan jobs across ALL assets, newest first -- the feed the
    dashboard uses to show "what's running / what just happened"
    without requiring a target to be selected first.

    NOTE: registered before `/{job_id}` below (same reasoning as
    `trigger_discovery` above) -- otherwise `/scans/stats` would be
    swallowed by `/{job_id}` and 422 trying to parse "stats" as an int.
    """
    query = db.query(ScanJob).order_by(ScanJob.created_at.desc())
    if status is not None:
        query = query.filter(ScanJob.status == status)
    jobs = query.limit(limit).all()
    return [_serialize_job_with_asset(db, j) for j in jobs]


@router.get("/stats")
def scan_stats(db: DBSession):
    """Counts for the dashboard's summary strip: targets tracked, and
    scan jobs grouped by status (pending/running/completed/failed).
    """
    rows = db.query(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status).all()
    by_status = {s.value: 0 for s in ScanStatus}
    for status, count in rows:
        by_status[status] = count

    return {
        "by_status": by_status,
        "total_assets": db.query(Asset).count(),
        "total_scans": sum(by_status.values()),
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


@router.get("/{job_id}/suggest-assets")
def suggest_related_assets(job_id: int, db: DBSession, by: str = "org"):
    """Suggest other IPs sharing this job's org or netblock, based on a
    completed Shodan scan's host_info. Returns candidates for review --
    does NOT create assets (org/net matches are too noisy to auto-chain
    like WHOIS<->Shodan)."""
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.tool != ToolName.SHODAN:
        raise HTTPException(status_code=400, detail="Job must be a Shodan scan")
    if job.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job has not completed yet")

    if by not in ("org", "net"):
        raise HTTPException(status_code=400, detail="'by' must be 'org' or 'net'")

    result = (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .order_by(ScanResult.version.desc())
        .first()
    )
    if result is None:
        raise HTTPException(status_code=404, detail="No scan result for this job")

    raw = result.raw_data
    org = raw.get("org")
    ip = raw.get("ip_str")

    try:
        if by == "org":
            if not org:
                raise HTTPException(status_code=400, detail="This scan has no org to search by")
            candidates = search_by_org(org)
        else:
            if not ip:
                raise HTTPException(
                    status_code=400, detail="This scan has no IP to derive a netblock from"
                )
            cidr = f"{ip}/24"
            candidates = search_by_net(cidr)
    except ShodanSearchError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    tracked_ips = {a.value for a in db.query(Asset).filter(Asset.asset_type == AssetType.IP).all()}
    for c in candidates:
        c["already_tracked"] = c["ip"] in tracked_ips
        c["is_source"] = c["ip"] == ip

    return {
        "job_id": job_id,
        "by": by,
        "query_value": org if by == "org" else f"{ip}/24",
        "is_shared_hosting_warning": by == "org" and is_likely_shared_hosting(org),
        "candidates": candidates,
    }
