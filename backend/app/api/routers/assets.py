import ipaddress

from fastapi import APIRouter, HTTPException

from app.api.deps import DBSession
from app.api.schemas import AssetCreate
from app.models import Asset, AssetType, Finding, ScanJob, ScanResult, ScanStatus, Severity

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
        }

    asset = Asset(value=payload.value, asset_type=asset_type)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {
        "id": asset.id,
        "value": asset.value,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "discovery_run_id": asset.discovery_run_id,
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


@router.get("/{asset_id}/risk")
def get_asset_risk(asset_id: int, db: DBSession):
    """Aggregate risk score for *asset_id* across all completed tool scans.

    Returns a 0-100 score, severity breakdown, CVE count, exposed port
    count, and the timestamp of the most recent scan so the frontend can
    show a trend indicator.
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

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
    }
