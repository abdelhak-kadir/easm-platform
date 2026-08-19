import ipaddress
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import DBSession
from app.api.schemas import AssetCreate
from app.models import (
    Asset,
    AssetType,
    Finding,
    ScanJob,
    ScanResult,
    ScanStatus,
    Severity,
    ToolName,
)

router = APIRouter(prefix="/assets", tags=["assets"])


def _infer_asset_type(value: str) -> AssetType:
    """Authoritative asset-type classification.

    This is deliberately done server-side, ignoring whatever
    `asset_type` the client sent: a client-side heuristic (see
    AssetSearch.tsx) is fine as a UX nicety, but if it's ever wrong --
    or a caller hits the API directly -- a mistyped asset silently
    only matches the wrong subset of tools in
    `tools_for_asset_type()` (e.g. a domain stored as `ip` only ever
    matches Shodan, never WHOIS). Deriving the type here instead means
    that class of bug can't happen again, no matter what the request
    payload claims.
    """
    try:
        ipaddress.ip_address(value.strip())
        return AssetType.IP
    except ValueError:
        return AssetType.DOMAIN


@router.post("")
def create_asset(payload: AssetCreate, db: DBSession):
    asset_type = _infer_asset_type(payload.value)

    existing = (
        db.query(Asset).filter(Asset.value == payload.value, Asset.asset_type == asset_type).first()
    )
    if existing:
        return {
            "id": existing.id,
            "value": existing.value,
            "asset_type": existing.asset_type,
            "status": existing.status,
            "discovery_run_id": existing.discovery_run_id,
            "root_asset_id": existing.root_asset_id,
        }

    asset = Asset(value=payload.value, asset_type=asset_type)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    if asset_type == AssetType.DOMAIN:
        asset.root_asset_id = asset.id  # a domain is its own root domain
        db.commit()
        db.refresh(asset)
    return {
        "id": asset.id,
        "value": asset.value,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "discovery_run_id": asset.discovery_run_id,
        "root_asset_id": asset.root_asset_id,
    }


@router.get("")
def list_assets(db: DBSession):
    return db.query(Asset).all()


# ── risk score ────────────────────────────────────────────────────────

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Maximum possible score per finding — if every finding were CRITICAL.
# Used to normalise the raw sum into a 0-100 range.
_MAX_WEIGHT = _SEVERITY_WEIGHT[Severity.CRITICAL]  # 10


def _compute_asset_risk(db: Session, asset_id: int) -> dict:
    """Aggregate risk score for *asset_id* across all completed tool scans.

    Returns a 0-100 score, severity breakdown, CVE count, exposed port
    count, and the timestamp of the most recent scan so the frontend can
    show a trend indicator.

    Extracted as a helper so the dashboard endpoint can inline risk
    without duplicating the logic.
    """
    # Gather all findings from the latest version of each completed tool scan
    latest_results = (
        db.query(ScanResult)
        .join(ScanJob)
        .filter(
            ScanJob.asset_id == asset_id,
            ScanJob.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanResult.version.desc())
        .all()
    )

    # Keep only the latest version per tool
    seen_tools: set[str] = set()
    findings: list[Finding] = []
    last_scan: str | None = None
    for result in latest_results:
        tool = result.scan_job.tool
        if tool in seen_tools:
            continue
        seen_tools.add(tool)
        findings.extend(result.findings)
        ts = result.created_at
        if ts is not None:
            ts_str = ts.isoformat()
            if last_scan is None or ts_str > last_scan:
                last_scan = ts_str

    if not findings:
        return {
            "asset_id": asset_id,
            "score": 0,
            "max_score": 100,
            "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "finding_count": 0,
            "cve_count": 0,
            "exposed_ports": 0,
            "last_scan": last_scan,
        }

    breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cve_count = 0
    exposed_ports = 0

    for f in findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        breakdown[sev.value] = breakdown.get(sev.value, 0) + 1
        if f.finding_type == "vulnerability":
            cve_count += 1
        if f.finding_type == "open_port":
            exposed_ports += 1

    # Weighted sum normalised to 0-100
    raw = sum(_SEVERITY_WEIGHT.get(Severity(s), 0) * count for s, count in breakdown.items())
    max_possible = len(findings) * _MAX_WEIGHT
    score = round((raw / max_possible) * 100) if max_possible > 0 else 0

    return {
        "asset_id": asset_id,
        "score": score,
        "max_score": 100,
        "breakdown": breakdown,
        "finding_count": len(findings),
        "cve_count": cve_count,
        "exposed_ports": exposed_ports,
        "last_scan": last_scan,
    }


@router.get("/{asset_id}/risk")
def get_asset_risk(asset_id: int, db: DBSession):
    """Aggregate risk score for *asset_id* across all completed tool scans."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _compute_asset_risk(db, asset_id)


# ── dashboard ─────────────────────────────────────────────────────────


def _severity_counts_for_results(db: Session, result_ids: list[int]) -> dict[str, int]:
    """Return ``{critical, high, medium, low, info}`` counts for a batch of ScanResult ids."""
    if not result_ids:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = db.query(Finding).filter(Finding.scan_result_id.in_(result_ids)).all()
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        counts[sev.value] = counts.get(sev.value, 0) + 1
    return counts


def _latest_result_ids(db: Session, asset_ids: list[int]) -> dict[int, list[int]]:
    """Return ``{asset_id: [result_id, ...]}`` for the latest completed
    ScanResult version per (asset, tool)."""
    if not asset_ids:
        return {}
    rows = (
        db.query(ScanResult)
        .join(ScanJob)
        .filter(
            ScanJob.asset_id.in_(asset_ids),
            ScanJob.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanResult.version.desc())
        .all()
    )
    seen: dict[tuple[int, str], int] = {}  # (asset_id, tool) -> result_id
    for r in rows:
        key = (r.scan_job.asset_id, r.scan_job.tool)
        if key not in seen:
            seen[key] = r.id
    by_asset: dict[int, list[int]] = {aid: [] for aid in asset_ids}
    for (asset_id, _tool), result_id in seen.items():
        by_asset.setdefault(asset_id, []).append(result_id)
    return by_asset


@router.get("/{asset_id}/dashboard")
def get_asset_dashboard(asset_id: int, db: DBSession):
    """Centralized view of an asset, its scans, related assets, and risk.

    Returns everything needed to render the asset-detail dashboard in
    a single request: tool summary cards, related assets (via spawn
    chains), findings summaries, and the aggregated risk score.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    # ── own scans ────────────────────────────────────────────────────
    own_jobs = (
        db.query(ScanJob)
        .filter(ScanJob.asset_id == asset_id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )

    # ── related assets (one hop via spawn chain) ──────────────────────
    related_ids: set[int] = set()

    # Downstream (children): this asset's scans spawned these assets
    for j in own_jobs:
        if j.spawned_asset_id and j.spawned_asset_id != asset_id:
            related_ids.add(j.spawned_asset_id)

    # Upstream (parents): scans whose spawned_asset_id == this asset
    parent_jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.spawned_asset_id == asset_id,
            ScanJob.asset_id != asset_id,
        )
        .all()
    )
    parent_asset_ids = {j.asset_id for j in parent_jobs}
    related_ids |= parent_asset_ids

    # Root-domain linkage: every asset sharing this asset's root domain
    # (subdomains, spawned IPs) is related too — groups the whole attack
    # surface under the domain even when no spawn chain connects them.
    root_id = asset.root_asset_id or (asset.id if asset.asset_type == AssetType.DOMAIN else None)
    root_linked_ids: set[int] = set()
    if root_id is not None:
        root_linked = (
            db.query(Asset).filter(Asset.root_asset_id == root_id, Asset.id != asset_id).all()
        )
        root_linked_ids = {a.id for a in root_linked}
        related_ids |= root_linked_ids

    # Deduplicate and exclude self
    related_ids.discard(asset_id)

    # Batch-load related assets + their jobs
    related_assets_rows: list[Asset] = (
        db.query(Asset).filter(Asset.id.in_(list(related_ids))).all() if related_ids else []
    )
    related_assets_map = {a.id: a for a in related_assets_rows}

    related_jobs_map: dict[int, list[ScanJob]] = {aid: [] for aid in related_ids}
    if related_ids:
        related_jobs_rows = (
            db.query(ScanJob)
            .filter(ScanJob.asset_id.in_(list(related_ids)))
            .order_by(ScanJob.created_at.desc())
            .all()
        )
        for j in related_jobs_rows:
            related_jobs_map.setdefault(j.asset_id, []).append(j)

    # Links: the scan jobs that connect this asset to each related asset
    child_links = {j.spawned_asset_id: j for j in own_jobs if j.spawned_asset_id in related_ids}
    parent_links = {j.asset_id: j for j in parent_jobs if j.asset_id in related_ids}

    # ── findings summaries ───────────────────────────────────────────
    all_asset_ids = [asset_id] + list(related_ids)
    result_ids_map = _latest_result_ids(db, all_asset_ids)

    def _make_summary(aid: int, jobs: list[ScanJob]) -> dict:
        rids = result_ids_map.get(aid, [])
        sevs = _severity_counts_for_results(db, rids)
        finding_count = sum(sevs.values())
        latest_status = jobs[0].status if jobs else None
        return {
            "latest_status": latest_status,
            "finding_count": finding_count,
            "severities": sevs,
        }

    # ── build related_assets payload ──────────────────────────────────
    from app.tools.registry import tools_for_asset_type

    related_payload: list[dict] = []
    for rel_id in sorted(related_ids):
        rel_asset = related_assets_map.get(rel_id)
        if rel_asset is None:
            continue
        # Determine relation direction
        is_child = rel_id in child_links or rel_id in root_linked_ids
        is_parent = rel_id in parent_links
        if is_child and is_parent:
            relation = "both"
        elif is_child:
            relation = "child"
        else:
            relation = "parent"

        links: list[dict] = []
        if is_child and child_links.get(rel_id):
            links.append(_serialize_job(db, child_links[rel_id]))
        if is_parent and parent_links.get(rel_id):
            links.append(_serialize_job(db, parent_links[rel_id]))

        rel_scans = related_jobs_map.get(rel_id, [])
        related_payload.append(
            {
                "asset": {
                    "id": rel_asset.id,
                    "value": rel_asset.value,
                    "asset_type": rel_asset.asset_type,
                    "status": rel_asset.status,
                    "discovery_run_id": rel_asset.discovery_run_id,
                    "root_asset_id": rel_asset.root_asset_id,
                },
                "relation": relation,
                "links": links,
                "scans": [_serialize_job(db, j) for j in rel_scans],
                "summary": _make_summary(rel_id, rel_scans),
            }
        )

    # ── tool summary ──────────────────────────────────────────────────
    applicable = tools_for_asset_type(asset.asset_type)
    tool_names = list({spec.tool for spec in applicable})
    # Also include any tools that were ever run on this asset but aren't
    # in the registry (e.g. manually triggered, or experimental)
    run_tools = {j.tool for j in own_jobs}
    all_tool_names = sorted(set(tool_names) | run_tools, key=lambda t: t.value)

    tool_summary: list[dict] = []
    for tool in all_tool_names:
        tool_jobs = sorted(
            [j for j in own_jobs if j.tool == tool],
            key=lambda j: j.created_at or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )
        latest = tool_jobs[0] if tool_jobs else None
        applicable_flag = tool in {spec.tool for spec in applicable}
        tool_category = ""
        try:
            from app.tools.registry import get_tool_spec

            tool_category = get_tool_spec(tool).category
        except (ValueError, ImportError):
            pass

        if latest:
            # Only count findings from this tool's latest result
            completed_jobs = [j for j in tool_jobs if j.status == ScanStatus.COMPLETED]
            tool_result_ids: list[int] = []
            if completed_jobs:
                for j in completed_jobs:
                    for r in j.results:
                        tool_result_ids.append(r.id)
                # Keep latest version only
                tool_result_ids = sorted(set(tool_result_ids), reverse=True)
            sevs = _severity_counts_for_results(db, tool_result_ids[:1])  # latest only

            tool_summary.append(
                {
                    "tool": tool,
                    "category": tool_category,
                    "applicable": applicable_flag,
                    "latest_job": _serialize_job(db, latest),
                    "latest_status": latest.status,
                    "job_count": len(tool_jobs),
                    "finding_count": sum(sevs.values()),
                    "severities": sevs,
                    "last_completed_at": (
                        max(j.completed_at.isoformat() for j in tool_jobs if j.completed_at)
                        if any(j.completed_at for j in tool_jobs)
                        else None
                    ),
                }
            )
        else:
            tool_summary.append(
                {
                    "tool": tool,
                    "category": tool_category,
                    "applicable": applicable_flag,
                    "latest_job": None,
                    "latest_status": None,
                    "job_count": 0,
                    "finding_count": 0,
                    "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "last_completed_at": None,
                }
            )

    # ── assemble ──────────────────────────────────────────────────────
    return {
        "asset": {
            "id": asset.id,
            "value": asset.value,
            "asset_type": asset.asset_type,
            "status": asset.status,
            "discovery_run_id": asset.discovery_run_id,
            "root_asset_id": asset.root_asset_id,
        },
        "scans": [_serialize_job(db, j) for j in own_jobs],
        "related_assets": related_payload,
        "tool_summary": tool_summary,
        "risk": _compute_asset_risk(db, asset_id),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {
        "id": asset.id,
        "value": asset.value,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "discovery_run_id": asset.discovery_run_id,
        "root_asset_id": asset.root_asset_id,
    }


# ── reputation (grouped IP blacklist view for a root domain) ───────────


def _aggregate_reputation(db: Session, root_id: int) -> dict:
    """Aggregate IP-blacklist findings across every asset belonging to
    *root_id* (the root itself + all assets whose ``root_asset_id`` points
    at it).  Latest completed ip_blacklist result per member only —
    same latest-version-per-tool pattern as ``_compute_asset_risk``.

    Returns the payload for ``GET /assets/{id}/reputation``: per-IP
    summaries, listings grouped by RBL zone, and unchecked IPs.
    """
    member_ids = [
        row[0]
        for row in db.query(Asset.id)
        .filter(or_(Asset.id == root_id, Asset.root_asset_id == root_id))
        .all()
    ]
    members = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(member_ids)).all()}

    rows = (
        db.query(ScanResult)
        .join(ScanJob)
        .filter(
            ScanJob.asset_id.in_(member_ids),
            ScanJob.tool == ToolName.IP_BLACKLIST,
            ScanJob.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanResult.version.desc())
        .all()
    )
    latest_by_asset: dict[int, ScanResult] = {}
    for r in rows:
        latest_by_asset.setdefault(r.scan_job.asset_id, r)

    ips: list[dict] = []
    zone_agg: dict[str, list[str]] = {}
    listed_ips = 0
    total_zone_listings = 0
    unchecked_ips: list[str] = []

    for aid in sorted(member_ids):
        member = members[aid]
        result = latest_by_asset.get(aid)
        if result is None:
            if member.asset_type == AssetType.IP:
                unchecked_ips.append(member.value)
            continue

        summary: dict = {}
        listings: list[dict] = []
        abuseipdb: dict | None = None
        for f in result.findings:
            if f.finding_type == "ip_reputation":
                summary = f.data
            elif f.finding_type == "rbl_listing":
                listings.append(f.data)
                zone = f.data.get("zone", "?")
                zone_agg.setdefault(zone, []).append(member.value)
            elif f.finding_type == "abuseipdb_report":
                abuseipdb = f.data

        entry: dict = {
            "ip": member.value,
            "asset_id": aid,
            "listed_count": summary.get("rbl_listed_count", len(listings)),
            "tor_exit": bool(summary.get("tor_exit")),
            "abuseipdb_score": summary.get("abuseipdb_score"),
            "zones_checked": summary.get("zones_checked"),
            "zones_with_errors": summary.get("zones_with_errors"),
            "last_checked": result.created_at.isoformat() if result.created_at else None,
            "zones": listings,
        }
        if abuseipdb is not None:
            entry["abuseipdb"] = abuseipdb
        if entry["listed_count"] > 0:
            listed_ips += 1
        total_zone_listings += len(listings)
        ips.append(entry)

    by_zone = [
        {"zone": zone, "count": len(ips_list), "listed_ips": sorted(set(ips_list))}
        for zone, ips_list in sorted(zone_agg.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    return {
        "total_ips": len(member_ids),
        "listed_ips": listed_ips,
        "total_zone_listings": total_zone_listings,
        "ips": ips,
        "by_zone": by_zone,
        "unchecked_ips": sorted(set(unchecked_ips)),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/{asset_id}/reputation")
def get_asset_reputation(asset_id: int, db: DBSession):
    """Grouped IP-blacklist reputation view for an asset's root domain:
    every member IP's listings, aggregated by RBL zone.  A domain views
    itself; a subdomain/IP views its root domain."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    root_id = asset.root_asset_id if asset.root_asset_id is not None else asset.id
    root = db.get(Asset, root_id)
    return {
        "root_asset": {
            "id": root.id if root else root_id,
            "value": root.value if root else None,
            "asset_type": root.asset_type if root else None,
        },
        **_aggregate_reputation(db, root_id),
    }


# ── shared serialization (imported from scans.py at the bottom to
#    avoid a circular import) ──────────────────────────────────────────


def _serialize_job(db: Session, job: ScanJob) -> dict:
    """Shared shape for a job, including its chained-scan info.

    Copied here rather than importing from scans.py to keep the
    routers independent — the function is small and stable.
    """
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
