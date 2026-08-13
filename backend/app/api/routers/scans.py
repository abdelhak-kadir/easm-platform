from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from app.api.deps import DBSession
from app.api.schemas import AcceptDiscoveredAssets, AcceptSuggestedAssets
from app.models import (
    Asset,
    AssetStatus,
    AssetType,
    DiscoveryRun,
    RunStatus,
    ScanJob,
    ScanResult,
    ScanStatus,
    ToolName,
)
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

    asset.status = AssetStatus.RUNNING
    db.commit()

    queued = []
    for spec in specs:
        # Skip if there's already an active (PENDING/RUNNING) job for this
        # asset+tool pair — the partial unique index enforces this at the DB
        # level, but the pre-check avoids a noisy IntegrityError.
        existing = (
            db.query(ScanJob)
            .filter(
                ScanJob.asset_id == asset.id,
                ScanJob.tool == spec.tool,
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
            .first()
        )
        if existing is not None:
            continue

        job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
        db.add(job)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            continue
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
            asset.status = AssetStatus.RUNNING
            db.commit()
            for spec in tools_for_asset_type(AssetType.IP):
                existing = (
                    db.query(ScanJob)
                    .filter(
                        ScanJob.asset_id == asset.id,
                        ScanJob.tool == spec.tool,
                        ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                    )
                    .first()
                )
                if existing is not None:
                    continue

                job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
                db.add(job)
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    continue
                db.refresh(job)
                task = run_tool_scan.delay(job.id)
                queued.append({"task_id": task.id, "job_id": job.id, "tool": spec.tool})

        created.append(
            {"asset_id": asset.id, "value": asset.value, "created": is_new, "queued": queued}
        )

    return {"created": created}


@router.post("/suggest-discovered/accept")
def accept_discovered_assets(payload: AcceptDiscoveredAssets, db: DBSession):
    """Turn a chosen subset of theHarvester-discovered hosts into real
    Assets and queue discovery for each -- same tools-for-asset-type
    flow as /scans/discover/{asset_id} and /scans/suggest-assets/accept,
    just sourced from crt.sh-derived hostnames instead of Shodan
    org/net matches.
    """
    if payload.asset_type != AssetType.SUBDOMAIN:
        raise HTTPException(
            status_code=400,
            detail=f"asset_type '{payload.asset_type}' is not yet supported "
            "for discovered-asset acceptance",
        )

    from app.tasks import run_tool_scan
    from app.tools.registry import tools_for_asset_type

    created = []
    for value in payload.values:
        asset = (
            db.query(Asset)
            .filter(Asset.value == value, Asset.asset_type == payload.asset_type)
            .first()
        )
        is_new = asset is None
        if is_new:
            asset = Asset(value=value, asset_type=payload.asset_type)
            db.add(asset)
            db.commit()
            db.refresh(asset)

        queued = []
        if is_new:
            asset.status = AssetStatus.RUNNING
            db.commit()
            for spec in tools_for_asset_type(payload.asset_type):
                existing = (
                    db.query(ScanJob)
                    .filter(
                        ScanJob.asset_id == asset.id,
                        ScanJob.tool == spec.tool,
                        ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                    )
                    .first()
                )
                if existing is not None:
                    continue

                job = ScanJob(asset_id=asset.id, tool=spec.tool, status=ScanStatus.PENDING)
                db.add(job)
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    continue
                db.refresh(job)
                task = run_tool_scan.delay(job.id)
                queued.append({"task_id": task.id, "job_id": job.id, "tool": spec.tool})

        created.append(
            {"asset_id": asset.id, "value": asset.value, "created": is_new, "queued": queued}
        )

    return {"created": created}


# ── Wave-based discovery (orchestrator endpoints) ─────────────────


@router.post("/discovery/start/{asset_id}")
def start_discovery(asset_id: int, db: DBSession, max_rounds: int = 5):
    """Create a DiscoveryRun and kick off the first wave of scans against
    *asset_id*. Every applicable tool is queued; spawned assets feed the
    next round until no new assets are found or *max_rounds* is reached."""
    if max_rounds < 1 or max_rounds > 20:
        raise HTTPException(
            status_code=400,
            detail="max_rounds must be between 1 and 20",
        )

    from app.orchestrator import create_discovery_run, schedule_round

    try:
        run = create_discovery_run(db, asset_id, max_rounds)
    except ValueError as e:
        # Distinguish "asset not found" (404) from "duplicate active run" (409)
        status_code = 409 if "already has an active" in str(e) else 404
        raise HTTPException(status_code=status_code, detail=str(e)) from e

    schedule_round.delay(run.id)
    return {
        "run_id": run.id,
        "root_asset_id": asset_id,
        "max_rounds": max_rounds,
        "status": "started",
    }


@router.get("/discovery/{run_id}")
def get_discovery(run_id: int, db: DBSession):
    """Return the current state of a discovery run (round, asset counts,
    active jobs). The frontend polls this to show progress."""
    from app.orchestrator import get_run_status

    status = get_run_status(db, run_id)
    if status is None:
        raise HTTPException(status_code=404, detail="DiscoveryRun not found")
    return status


@router.post("/discovery/{run_id}/continue")
def continue_discovery(run_id: int, db: DBSession):
    """Advance a discovery run to the next round after the user has
    reviewed and accepted human-gated discovered assets.

    Integrates orphan assets — those created by human-gated acceptance
    flows (suggest-discovered, suggest-assets) that are not yet tagged
    with any ``discovery_run_id`` — into this run.  Only assets created
    after the run started are considered (temporal scoping prevents
    accidental cross-run contamination)."""
    from app.orchestrator import schedule_round

    run = db.get(DiscoveryRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="DiscoveryRun not found")
    if run.status != RunStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot continue a run with status '{run.status}'",
        )

    # Integrate orphan assets created by human-gated acceptance flows since
    # this run started.  Temporal scoping prevents stealing orphans from
    # other runs (though concurrent runs on the same root are now blocked
    # by create_discovery_run).
    orphans = (
        db.query(Asset)
        .filter(
            Asset.discovery_run_id.is_(None),
            Asset.status.in_([AssetStatus.PENDING, AssetStatus.RUNNING]),
            Asset.created_at >= run.created_at,
        )
        .all()
    )
    integrated = 0
    for a in orphans:
        a.discovery_run_id = run.id
        # Fix status: assets accepted outside the wave are set to RUNNING
        # by the accept endpoints, but the wave needs them in a terminal
        # state (PENDING for schedule_round, or DONE if already scanned).
        # Check whether this asset already has completed jobs — if all its
        # jobs are done, mark it DONE; if some are active, leave RUNNING;
        # otherwise set PENDING so schedule_round picks it up.
        active_jobs = (
            db.query(ScanJob)
            .filter(
                ScanJob.asset_id == a.id,
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
            .count()
        )
        total_jobs = db.query(ScanJob).filter(ScanJob.asset_id == a.id).count()
        if total_jobs > 0 and active_jobs == 0:
            a.status = AssetStatus.DONE
        elif active_jobs == 0:
            a.status = AssetStatus.PENDING
        # else: active_jobs > 0 → leave as RUNNING, completion pokes will advance
        integrated += 1
    if integrated:
        db.commit()

    # Delegate to schedule_round — it will either queue tools for PENDING
    # assets, return "waiting" if RUNNING assets are still in flight
    # (their job-completion pokes will advance the round), or complete the
    # run if no work remains.  We do NOT poke collect_round directly
    # because a concurrent collector for the previous round might race
    # with the integrated assets' in-flight jobs and prematurely terminate
    # the run.
    schedule_round.delay(run_id)

    return {
        "run_id": run_id,
        "status": "continued",
        "round": run.round_number + 1,
        "integrated_assets": integrated,
    }


@router.post("/discovery/{run_id}/cancel")
def cancel_discovery_run(run_id: int, db: DBSession):
    """Cancel an active discovery run and all its in-flight scan jobs.

    Sets the run status to CANCELLED and marks every PENDING/RUNNING job
    belonging to the run's assets as FAILED (``error_message = "Cancelled
    by user"``), matching the per-job cancel contract so the Celery worker
    skips or discards them cooperatively.
    """
    run = db.get(DiscoveryRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="DiscoveryRun not found")
    if run.status != RunStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a run with status '{run.status}'",
        )

    # Cancel every in-flight job tied to assets in this run
    cancelled_jobs = 0
    asset_ids = [
        row[0] for row in db.query(Asset.id).filter(Asset.discovery_run_id == run_id).all()
    ]
    if asset_ids:
        jobs = (
            db.query(ScanJob)
            .filter(
                ScanJob.asset_id.in_(asset_ids),
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
            .all()
        )
        for job in jobs:
            job.status = ScanStatus.FAILED
            job.error_message = "Cancelled by user"
            job.completed_at = datetime.now(UTC)
            cancelled_jobs += 1

    run.status = RunStatus.CANCELLED
    run.completed_at = datetime.now(UTC)
    db.commit()

    return {
        "run_id": run_id,
        "cancelled_jobs": cancelled_jobs,
        "status": "cancelled",
    }


@router.post("/{job_id}/cancel")
def cancel_scan_job(job_id: int, db: DBSession):
    """Cancel a PENDING or RUNNING scan job. Sets it to FAILED with a
    user-friendly message; the Celery worker skips cancelled jobs."""
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a job with status '{job.status}'",
        )
    job.status = ScanStatus.FAILED
    job.error_message = "Cancelled by user"
    job.completed_at = datetime.now(UTC)
    db.commit()
    return _serialize_job(db, job)


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

    # Check for existing active scan — at most one PENDING/RUNNING per asset+tool
    existing_active = (
        db.query(ScanJob)
        .filter(
            ScanJob.asset_id == asset.id,
            ScanJob.tool == tool,
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
        .first()
    )
    if existing_active is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Tool '{tool}' is already scanning asset {asset_id} "
            f"(job_id={existing_active.id}, status={existing_active.status})",
        )

    job = ScanJob(asset_id=asset.id, tool=tool, status=ScanStatus.PENDING)
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Tool '{tool}' is already scanning asset {asset_id}",
        ) from None
    db.refresh(job)

    asset.status = AssetStatus.RUNNING
    db.commit()

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


@router.get("/asset/{asset_id}/diff")
def diff_scan_results(asset_id: int, db: DBSession, tool: ToolName | None = None):
    """Compare the latest two ScanResult versions per tool for *asset_id*.

    Returns a list of diffs, one per tool that has ≥2 completed scans
    with recorded results.  Each diff entry tells you which top-level
    keys were added, removed, or changed between the previous and latest
    version.

    Optional *tool* query param limits the diff to a single tool.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Gather completed jobs for this asset, grouped by tool
    tool_names = [tool] if tool else None
    jobs_query = db.query(ScanJob).filter(
        ScanJob.asset_id == asset_id,
        ScanJob.status == ScanStatus.COMPLETED,
    )
    if tool_names:
        jobs_query = jobs_query.filter(ScanJob.tool.in_(tool_names))

    jobs = jobs_query.order_by(ScanJob.created_at.asc()).all()

    # Group results by tool
    tool_results: dict[ToolName, list[ScanResult]] = {}
    for job in jobs:
        for result in job.results:
            if result.raw_data:  # skip empty results (no-data outcomes)
                tool_results.setdefault(job.tool, []).append(result)

    diffs: list[dict] = []
    for tool_name, results in tool_results.items():
        if len(results) < 2:
            continue
        # results are already in chronological order (jobs ordered asc)
        prev = results[-2]
        latest = results[-1]
        entry = _diff_dicts(prev.raw_data, latest.raw_data)
        entry["tool"] = tool_name
        entry["latest_version"] = latest.version
        entry["previous_version"] = prev.version
        diffs.append(entry)

    return {"asset_id": asset_id, "diffs": diffs}


def _diff_dicts(prev: dict, latest: dict) -> dict:
    """Shallow key comparison of two dicts, with list-aware value handling.

    For list values the diff reports added / removed items; for scalar
    values it reports old → new.  Keys present in only one dict are
    reported as added or removed.
    """
    all_keys = set(prev) | set(latest)
    added: list[str] = []
    removed: list[str] = []
    changed: list[dict] = []

    for key in sorted(all_keys):
        old = prev.get(key)
        new = latest.get(key)

        if key not in prev:
            added.append(key)
        elif key not in latest:
            removed.append(key)
        elif isinstance(old, list) and isinstance(new, list):
            old_set = set(old)
            new_set = set(new)
            if old_set != new_set:
                changed.append(
                    {
                        "key": key,
                        "added_items": sorted(new_set - old_set),
                        "removed_items": sorted(old_set - new_set),
                    }
                )
        elif old != new:
            changed.append({"key": key, "old": old, "new": new})

    return {"added_keys": added, "removed_keys": removed, "changed_keys": changed}


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


# Tools whose raw_data["hosts"] feeds the suggest-discovered acceptance flow.
_DISCOVERY_TOOLS: frozenset[ToolName] = frozenset(
    {
        ToolName.THEHARVESTER,
        ToolName.SUBFINDER,
        ToolName.AMASS,
        ToolName.MERKLEMAP,
        ToolName.CERTSPOTTER,
        ToolName.SUBLIST3R,
        ToolName.DNSDUMPSTER,
        ToolName.PUBLICWWW,
        ToolName.CLOUDSCRAPER,
        ToolName.CSPRECON,
        ToolName.WAYMORE,
        ToolName.PASSIVEDNS,
        ToolName.SHODAN,
    }
)


@router.get("/{job_id}/suggest-discovered")
def suggest_discovered_assets(job_id: int, db: DBSession, category: str = "hosts"):
    """Surface passive-enumeration-discovered hostnames as candidates for
    promotion to real, trackable SUBDOMAIN Assets. Works with any tool
    in ``_DISCOVERY_TOOLS`` (theHarvester, Subfinder, Amass) that produces
    ``raw_data["hosts"]``.

    Returns candidates for review — does NOT create assets (wildcard certs,
    search-engine noise, and stale DNS entries can pollute results, so this
    stays human-gated like the Shodan org/net suggestions)."""
    if category != "hosts":
        raise HTTPException(
            status_code=400,
            detail="Only category='hosts' is currently supported "
            "(email-derived assets need AssetType.EMAIL, not yet implemented)",
        )

    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.tool not in _DISCOVERY_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Job tool '{job.tool}' does not produce discovered hosts. "
            f"Expected one of: {sorted(t.value for t in _DISCOVERY_TOOLS)}",
        )
    if job.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job has not completed yet")

    result = (
        db.query(ScanResult)
        .filter(ScanResult.scan_job_id == job_id)
        .order_by(ScanResult.version.desc())
        .first()
    )
    if result is None:
        raise HTTPException(status_code=404, detail="No scan result for this job")

    hosts = result.raw_data.get("hosts", [])
    tracked = {
        a.value for a in db.query(Asset).filter(Asset.asset_type == AssetType.SUBDOMAIN).all()
    }

    return {
        "job_id": job_id,
        "category": category,
        "candidates": [{"value": h, "already_tracked": h in tracked} for h in hosts],
    }


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
