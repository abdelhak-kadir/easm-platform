from pydantic import BaseModel

from app.models import AssetType


class AssetCreate(BaseModel):
    value: str
    asset_type: AssetType
