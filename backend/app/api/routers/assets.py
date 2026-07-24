from fastapi import APIRouter, HTTPException

from app.api.deps import DBSession
from app.api.schemas import AssetCreate
from app.models import Asset

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("")
def create_asset(payload: AssetCreate, db: DBSession):
    existing = (
        db.query(Asset)
        .filter(Asset.value == payload.value, Asset.asset_type == payload.asset_type)
        .first()
    )
    if existing:
        return {"id": existing.id, "value": existing.value, "asset_type": existing.asset_type}

    asset = Asset(value=payload.value, asset_type=payload.asset_type)
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
