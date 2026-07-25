"""One-off data repair for assets whose stored `asset_type` doesn't
match their value -- fallout from a frontend bug where every new
target was created with `asset_type: "ip"` regardless of what was
typed. That left domains like "sanpc.ma" stored as `ip` rows, which
`tools_for_asset_type()` only ever matches against Shodan, never
WHOIS. The API-level fix (assets.py now infers asset_type
server-side) stops new bad rows from being created; this script
cleans up ones that already exist.

For each asset whose stored type doesn't match `ipaddress.ip_address`
reality:
  - If a *correctly*-typed duplicate already exists for the same
    value (e.g. the frontend fix created a second, correct row after
    the bad one), every ScanJob pointing at the bad row -- as its own
    asset, or as something WHOIS's chaining spawned into -- is
    repointed at the correct row, and the bad row is deleted.
  - Otherwise the bad row is simply corrected in place.

Idempotent: running it again after everything's already correct is a
no-op.

Usage (inside the backend container, so DATABASE_URL is set):
    docker compose exec backend python scripts/fix_asset_types.py
"""

import ipaddress

from app.database import SessionLocal
from app.models import Asset, AssetType, ScanJob


def infer_asset_type(value: str) -> AssetType:
    try:
        ipaddress.ip_address(value.strip())
        return AssetType.IP
    except ValueError:
        return AssetType.DOMAIN


def main() -> None:
    db = SessionLocal()
    try:
        assets = db.query(Asset).all()
        retyped = 0
        merged = 0

        for asset in assets:
            correct_type = infer_asset_type(asset.value)
            if asset.asset_type == correct_type:
                continue

            duplicate = (
                db.query(Asset)
                .filter(Asset.value == asset.value, Asset.asset_type == correct_type)
                .first()
            )

            if duplicate:
                db.query(ScanJob).filter(ScanJob.asset_id == asset.id).update(
                    {"asset_id": duplicate.id}, synchronize_session=False
                )
                db.query(ScanJob).filter(ScanJob.spawned_asset_id == asset.id).update(
                    {"spawned_asset_id": duplicate.id}, synchronize_session=False
                )
                db.delete(asset)
                merged += 1
                print(
                    f"merged '{asset.value}' "
                    f"({asset.asset_type}#{asset.id} -> {duplicate.asset_type}#{duplicate.id})"
                )
            else:
                print(f"retyped '{asset.value}' ({asset.asset_type} -> {correct_type})")
                asset.asset_type = correct_type
                retyped += 1

        db.commit()
        print(f"\ndone -- {retyped} retyped in place, {merged} merged into existing duplicates")
    finally:
        db.close()


if __name__ == "__main__":
    main()
