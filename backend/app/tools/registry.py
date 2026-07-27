"""Declarative tool registry.

Maps each `ToolName` to the `run`/`parse` functions that implement it,
plus which `AssetType`s it applies to. `tools_for_asset_type()` is the
"Sélection des outils selon le type d'actif" step from the discovery
diagram, in code -- it's what the orchestrator calls to decide what to
queue next.

Adding a new tool means adding one entry here (plus its own
scan.py/parse.py) -- app/tasks.py and the routers never change.

A ToolSpec can also declare that it *spawns* another tool once it
completes -- e.g. WHOIS resolves the domain to an IP and spawns a
Shodan scan on that IP. This is opt-in per tool (`spawns` is None by
default) and handled generically in app/tasks.py, so most tools never
need to think about it.
"""

import socket
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

    # Chaining (all optional -- a tool that doesn't chain leaves these None):
    spawns: ToolName | None = None
    spawn_asset_type: AssetType | None = None
    resolve_spawn_value: Callable[[str], str | None] | None = None


def _resolve_domain_to_ip(domain: str) -> str | None:
    """Best-effort DNS A-record lookup used to chain WHOIS -> Shodan.

    Returns None (rather than raising) on failure -- a domain with no
    A record, or a transient DNS error, just means nothing gets
    spawned. It must never fail the WHOIS job that already completed.
    """
    try:
        return socket.gethostbyname(domain.strip())
    except OSError:
        return None


def _resolve_ip_to_domain(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return None


TOOL_REGISTRY: dict[ToolName, ToolSpec] = {
    ToolName.SHODAN: ToolSpec(
        tool=ToolName.SHODAN,
        run=shodan_scan.run,
        parse=shodan_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        spawns=ToolName.WHOIS,
        spawn_asset_type=AssetType.DOMAIN,
        resolve_spawn_value=_resolve_ip_to_domain,
    ),
    ToolName.WHOIS: ToolSpec(
        tool=ToolName.WHOIS,
        run=whois_scan.run,
        parse=whois_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        spawns=ToolName.SHODAN,
        spawn_asset_type=AssetType.IP,
        resolve_spawn_value=_resolve_domain_to_ip,
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
