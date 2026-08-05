"""Tests for the §1 schema additions: AssetStatus, extended AssetType,
Asset.status column, Asset.discovery_run_id, and DiscoveryRun table.

Run with:
  cd backend && source ../.venv/bin/activate && pytest tests/test_models_schema.py -q
"""

from app.models import Asset, AssetStatus, AssetType, DiscoveryRun


class TestAssetStatus:
    def test_asset_status_values(self):
        assert AssetStatus.PENDING == "pending"
        assert AssetStatus.RUNNING == "running"
        assert AssetStatus.DONE == "done"

    def test_asset_status_column_is_configured(self):
        """status defaults are applied by SQLAlchemy at INSERT time;
        verify the column is declared with the right default."""
        from sqlalchemy import inspect as sa_inspect

        col = sa_inspect(Asset).columns["status"]
        assert col.default is not None
        # The default should produce AssetStatus.PENDING
        assert col.default.arg == "pending"

    def test_asset_explicit_status(self):
        asset = Asset(
            value="example.com",
            asset_type=AssetType.DOMAIN,
            status=AssetStatus.RUNNING,
        )
        assert asset.status == AssetStatus.RUNNING


class TestAssetTypeExtended:
    def test_new_asset_types_exist(self):
        assert AssetType.EMAIL == "email"
        assert AssetType.SERVICE == "service"
        assert AssetType.TECHNOLOGY == "technology"

    def test_all_asset_types(self):
        all_types = set(AssetType)
        assert AssetType.DOMAIN in all_types
        assert AssetType.SUBDOMAIN in all_types
        assert AssetType.IP in all_types
        assert AssetType.EMAIL in all_types
        assert AssetType.SERVICE in all_types
        assert AssetType.TECHNOLOGY in all_types


class TestDiscoveryRun:
    def test_discovery_run_column_defaults(self):
        """SQLAlchemy applies defaults at INSERT time, not construction.
        Verify the columns are configured with the correct defaults."""
        from sqlalchemy import inspect as sa_inspect

        insp = sa_inspect(DiscoveryRun)
        assert insp.columns["round_number"].default.arg == 0
        assert insp.columns["max_rounds"].default.arg == 5
        assert insp.columns["status"].default.arg == "running"

    def test_discovery_run_created_at_is_callable_default(self):
        """created_at uses utcnow as default — applied at INSERT time."""
        from sqlalchemy import inspect as sa_inspect

        col = sa_inspect(DiscoveryRun).columns["created_at"]
        # callable defaults are stored in .default (ColumnDefault)
        assert col.default is not None

    def test_discovery_run_custom_max_rounds(self):
        run = DiscoveryRun(root_asset_id=1, max_rounds=3)
        assert run.max_rounds == 3

    def test_discovery_run_asset_ids_storage(self):
        run = DiscoveryRun(
            root_asset_id=1,
            current_round_asset_ids=[10, 20, 30],
        )
        assert run.current_round_asset_ids == [10, 20, 30]

    def test_discovery_run_minimal_construction(self):
        """DiscoveryRun(root_asset_id=1) accepts just the required FK.
        Column defaults (round_number, max_rounds, status, created_at)
        are INSERT-level — they're None on the Python object until flush."""
        run = DiscoveryRun(root_asset_id=1)
        assert run.root_asset_id == 1
        assert run.current_round_asset_ids is None
        assert run.completed_at is None
        # INSERT-level defaults — verify via column introspection, not instance
        from sqlalchemy import inspect as sa_inspect

        insp = sa_inspect(DiscoveryRun)
        assert insp.columns["round_number"].default.arg == 0
        assert insp.columns["max_rounds"].default.arg == 5
        assert insp.columns["status"].default.arg == "running"

    def test_discovery_run_fields_are_writable(self):
        """All fields on DiscoveryRun accept explicit values at construction."""
        run = DiscoveryRun(
            root_asset_id=42,
            round_number=2,
            max_rounds=10,
            status="completed",
            current_round_asset_ids=[1, 2, 3],
        )
        assert run.root_asset_id == 42
        assert run.round_number == 2
        assert run.max_rounds == 10
        assert run.status == "completed"
        assert run.current_round_asset_ids == [1, 2, 3]
