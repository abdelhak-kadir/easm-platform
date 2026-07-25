import ipaddress

from fastapi import APIRouter, HTTPException

from app.api.deps import DBSession
from app.api.schemas import AssetCreate
from app.models import Asset, AssetType

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
        return {"id": existing.id, "value": existing.value, "asset_type": existing.asset_type}

    asset = Asset(value=payload.value, asset_type=asset_type)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": asset.id, "value": asset.value, "asset_type": asset.asset_type}


@router.get("")
def list_assets(db: DBSession):
    return db.query(Asset).all()


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: DBSession):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"id": asset.id, "value": asset.value, "asset_type": asset.asset_type}
