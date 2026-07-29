"""Tests that app.tasks._spawn_chained_scan calls
`spec.resolve_spawn_value(db, asset.value)` -- i.e. the db session is
threaded through to the resolver, which is what lets
`_resolve_ip_to_domain` (registry.py) check for a cached scan before
hitting the network.

This intentionally stubs `spec` and returns None from
`resolve_spawn_value`, so the test stays isolated from the rest of
`_spawn_chained_scan`'s DB/Celery side effects and only asserts the
call contract that the fix depends on.
"""

from unittest.mock import MagicMock

from app.models import ToolName
from app.tasks import _spawn_chained_scan


def test_spawn_chained_scan_passes_db_session_to_resolver():
    db = MagicMock()
    job = MagicMock()
    asset = MagicMock(value="93.184.216.34")

    spec = MagicMock()
    spec.spawns = ToolName.WHOIS
    spec.resolve_spawn_value = MagicMock(return_value=None)

    _spawn_chained_scan(db, job, asset, spec)

    spec.resolve_spawn_value.assert_called_once_with(db, "93.184.216.34")


def test_spawn_chained_scan_noop_when_spec_does_not_chain():
    db = MagicMock()
    job = MagicMock()
    asset = MagicMock(value="93.184.216.34")

    spec = MagicMock()
    spec.spawns = None
    spec.resolve_spawn_value = MagicMock()

    _spawn_chained_scan(db, job, asset, spec)

    spec.resolve_spawn_value.assert_not_called()
    db.query.assert_not_called()


def test_spawn_chained_scan_noop_when_resolver_returns_none():
    """resolve_spawn_value returning None (e.g. no PTR record, no A
    record) must stop the chain cleanly -- no spawned Asset/ScanJob
    should be created."""
    db = MagicMock()
    job = MagicMock()
    asset = MagicMock(value="93.184.216.34")

    spec = MagicMock()
    spec.spawns = ToolName.WHOIS
    spec.resolve_spawn_value = MagicMock(return_value=None)

    _spawn_chained_scan(db, job, asset, spec)

    # Only the resolver should have been consulted -- nothing else
    # (find-or-create Asset, ScanJob creation, delay()) should run.
    db.add.assert_not_called()
