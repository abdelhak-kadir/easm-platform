"""Declarative tool registry.

Maps each `ToolName` to the `run`/`parse` functions that implement it,
plus which `AssetType`s it applies to. `tools_for_asset_type()` is the
"Sélection des outils selon le type d'actif" step from the discovery
diagram, in code -- it's what the orchestrator calls to decide what to
queue next.

Adding a new tool means adding one entry here (plus its own
scan.py/parse.py) -- app/tasks.py and the routers never change.
"""

from collections.abc import Callable
from dataclasses import dataclass

from app.models import AssetType, ToolName
from app.tools.shodan import parse as shodan_parse
from app.tools.shodan import scan as shodan_scan
from app.tools.whois import parse as whois_parse
from app.tools.whois import scan as whois_scan


@dataclass(frozen=True)
class ToolSpec:
    tool: ToolName
    run: Callable[[str], dict]
    parse: Callable[[dict], list[dict]]
    asset_types: frozenset[AssetType]


TOOL_REGISTRY: dict[ToolName, ToolSpec] = {
    ToolName.SHODAN: ToolSpec(
        tool=ToolName.SHODAN,
        run=shodan_scan.run,
        parse=shodan_parse.parse,
        asset_types=frozenset({AssetType.IP}),
    ),
    ToolName.WHOIS: ToolSpec(
        tool=ToolName.WHOIS,
        run=whois_scan.run,
        parse=whois_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
    ),
}


def get_tool_spec(tool: ToolName) -> ToolSpec:
    try:
        return TOOL_REGISTRY[tool]
    except KeyError:
        raise ValueError(f"No registry entry for tool {tool!r}") from None


def tools_for_asset_type(asset_type: AssetType) -> list[ToolSpec]:
    """Every registered tool applicable to this asset type, in registry order."""
    return [spec for spec in TOOL_REGISTRY.values() if asset_type in spec.asset_types]
