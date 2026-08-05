from pydantic import BaseModel, field_validator

from app.models import AssetType


class AssetCreate(BaseModel):
    value: str
    asset_type: AssetType | None = None  # optional — server infers the real type

    @field_validator("asset_type", mode="before")
    @classmethod
    def coerce_empty_to_none(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v


class AcceptSuggestedAssets(BaseModel):
    ips: list[str]


class AcceptDiscoveredAssets(BaseModel):
    values: list[str]
    asset_type: AssetType = AssetType.SUBDOMAIN
