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

from sqlalchemy.orm import Session

from app.models import Asset, AssetType, ScanJob, ScanResult, ScanStatus, ToolName
from app.tools.email_security import parse as email_security_parse
from app.tools.email_security import scan as email_security_scan
from app.tools.reverse_dns import parse as reverse_dns_parse
from app.tools.reverse_dns import scan as reverse_dns_scan
from app.tools.shodan import parse as shodan_parse
from app.tools.shodan import scan as shodan_scan
from app.tools.theharvester import parse as theharvester_parse
from app.tools.theharvester import scan as theharvester_scan
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
    resolve_spawn_value: Callable[["Session", str], str | None] | None = None


def _resolve_domain_to_ip(db: Session, domain: str) -> str | None:
    """Best-effort DNS A-record lookup used to chain WHOIS -> Shodan.

    Returns None (rather than raising) on failure -- a domain with no
    A record, or a transient DNS error, just means nothing gets
    spawned. It must never fail the WHOIS job that already completed.
    """
    try:
        return socket.gethostbyname(domain.strip())
    except OSError:
        return None


def _resolve_ip_to_domain(db: Session, ip: str) -> str | None:
    asset = db.query(Asset).filter(Asset.value == ip, Asset.asset_type == AssetType.IP).first()
    if asset:
        cached = (
            db.query(ScanResult)
            .join(ScanJob)
            .filter(
                ScanJob.asset_id == asset.id,
                ScanJob.tool == ToolName.REVERSE_DNS,
                ScanJob.status == ScanStatus.COMPLETED,
            )
            .order_by(ScanResult.version.desc())
            .first()
        )
        if cached:
            hostnames = cached.raw_data.get("hostnames") or []
            if hostnames:
                return _extract_registrable_domain_from_hostname(hostnames[0])
            return None  # completed but no PTR data -- don't retry over network

    try:
        raw = reverse_dns_scan.run(ip)
    except Exception:
        return None
    hostnames = raw.get("hostnames") or []
    if not hostnames:
        return None
    return _extract_registrable_domain_from_hostname(hostnames[0])


def _extract_registrable_domain_from_hostname(hostname: str) -> str | None:
    """Best-effort: turn 'mail.example.com' into 'example.com' so the
    spawned WHOIS scan targets a real, registered domain rather than
    a subdomain/hostname WHOIS has no record for."""
    from app.tools.whois.scan import _to_registrable_domain

    return _to_registrable_domain(hostname)


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
    ToolName.REVERSE_DNS: ToolSpec(
        tool=ToolName.REVERSE_DNS,
        run=reverse_dns_scan.run,
        parse=reverse_dns_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        spawns=ToolName.WHOIS,
        spawn_asset_type=AssetType.DOMAIN,
        resolve_spawn_value=_resolve_ip_to_domain,
    ),
    ToolName.THEHARVESTER: ToolSpec(
        tool=ToolName.THEHARVESTER,
        run=theharvester_scan.run,
        parse=theharvester_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
    ),
    ToolName.EMAIL_SECURITY: ToolSpec(
        tool=ToolName.EMAIL_SECURITY,
        run=email_security_scan.run,
        parse=email_security_parse.parse,
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
