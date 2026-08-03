from pydantic import BaseModel

from app.models import AssetType


class AssetCreate(BaseModel):
    value: str
    asset_type: AssetType


class AcceptSuggestedAssets(BaseModel):
    ips: list[str]


class AcceptDiscoveredAssets(BaseModel):
    values: list[str]
    asset_type: AssetType = AssetType.SUBDOMAIN
