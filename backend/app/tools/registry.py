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
from app.tools.amass import parse as amass_parse
from app.tools.amass import scan as amass_scan
from app.tools.censys import parse as censys_parse
from app.tools.censys import scan as censys_scan
from app.tools.certspotter import parse as certspotter_parse
from app.tools.certspotter import scan as certspotter_scan
from app.tools.cloudscraper import parse as cloudscraper_parse
from app.tools.cloudscraper import scan as cloudscraper_scan
from app.tools.csprecon import parse as csprecon_parse
from app.tools.csprecon import scan as csprecon_scan
from app.tools.dnsdumpster import parse as dnsdumpster_parse
from app.tools.dnsdumpster import scan as dnsdumpster_scan
from app.tools.email_security import parse as email_security_parse
from app.tools.email_security import scan as email_security_scan
from app.tools.holehe import parse as holehe_parse
from app.tools.holehe import scan as holehe_scan
from app.tools.httpx import parse as httpx_parse
from app.tools.httpx import scan as httpx_scan
from app.tools.ip_blacklist import parse as ip_blacklist_parse
from app.tools.ip_blacklist import scan as ip_blacklist_scan
from app.tools.merklemap import parse as merklemap_parse
from app.tools.merklemap import scan as merklemap_scan
from app.tools.nmap import parse as nmap_parse
from app.tools.nmap import scan as nmap_scan
from app.tools.passivedns import parse as passivedns_parse
from app.tools.passivedns import scan as passivedns_scan
from app.tools.publicwww import parse as publicwww_parse
from app.tools.publicwww import scan as publicwww_scan
from app.tools.reverse_dns import parse as reverse_dns_parse
from app.tools.reverse_dns import scan as reverse_dns_scan
from app.tools.shodan import parse as shodan_parse
from app.tools.shodan import scan as shodan_scan
from app.tools.ssl_checker import parse as ssl_checker_parse
from app.tools.ssl_checker import scan as ssl_checker_scan
from app.tools.subfinder import parse as subfinder_parse
from app.tools.subfinder import scan as subfinder_scan
from app.tools.sublist3r import parse as sublist3r_parse
from app.tools.sublist3r import scan as sublist3r_scan
from app.tools.subover import parse as subover_parse
from app.tools.subover import scan as subover_scan
from app.tools.theharvester import parse as theharvester_parse
from app.tools.theharvester import scan as theharvester_scan
from app.tools.waymore import parse as waymore_parse
from app.tools.waymore import scan as waymore_scan
from app.tools.whois import parse as whois_parse
from app.tools.whois import scan as whois_scan


@dataclass(frozen=True)
class ToolSpec:
    tool: ToolName
    run: Callable[[str], dict]
    parse: Callable[[dict], list[dict]]
    asset_types: frozenset[AssetType]
    # categories: dns, domain, certificate, subdomain, web, network,
    #             cloud, smtp, ssl, search, takeover, reputation
    category: str = "other"

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
        category="search",
        spawns=ToolName.WHOIS,
        spawn_asset_type=AssetType.DOMAIN,
        resolve_spawn_value=_resolve_ip_to_domain,
    ),
    ToolName.CENSYS: ToolSpec(
        tool=ToolName.CENSYS,
        run=censys_scan.run,
        parse=censys_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        category="search",
        spawns=ToolName.WHOIS,
        spawn_asset_type=AssetType.DOMAIN,
        resolve_spawn_value=_resolve_ip_to_domain,
    ),
    ToolName.WHOIS: ToolSpec(
        tool=ToolName.WHOIS,
        run=whois_scan.run,
        parse=whois_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="domain",
        spawns=ToolName.SHODAN,
        spawn_asset_type=AssetType.IP,
        resolve_spawn_value=_resolve_domain_to_ip,
    ),
    ToolName.REVERSE_DNS: ToolSpec(
        tool=ToolName.REVERSE_DNS,
        run=reverse_dns_scan.run,
        parse=reverse_dns_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        category="dns",
        spawns=ToolName.WHOIS,
        spawn_asset_type=AssetType.DOMAIN,
        resolve_spawn_value=_resolve_ip_to_domain,
    ),
    ToolName.THEHARVESTER: ToolSpec(
        tool=ToolName.THEHARVESTER,
        run=theharvester_scan.run,
        parse=theharvester_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.EMAIL_SECURITY: ToolSpec(
        tool=ToolName.EMAIL_SECURITY,
        run=email_security_scan.run,
        parse=email_security_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="dns",
    ),
    ToolName.SUBFINDER: ToolSpec(
        tool=ToolName.SUBFINDER,
        run=subfinder_scan.run,
        parse=subfinder_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.AMASS: ToolSpec(
        tool=ToolName.AMASS,
        run=amass_scan.run,
        parse=amass_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.MERKLEMAP: ToolSpec(
        tool=ToolName.MERKLEMAP,
        run=merklemap_scan.run,
        parse=merklemap_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="certificate",
    ),
    ToolName.HTTPX: ToolSpec(
        tool=ToolName.HTTPX,
        run=httpx_scan.run,
        parse=httpx_parse.parse,
        asset_types=frozenset({AssetType.SUBDOMAIN, AssetType.IP}),
        category="web",
    ),
    ToolName.NMAP: ToolSpec(
        tool=ToolName.NMAP,
        run=nmap_scan.run,
        parse=nmap_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        category="network",
    ),
    ToolName.IP_BLACKLIST: ToolSpec(
        tool=ToolName.IP_BLACKLIST,
        run=ip_blacklist_scan.run,
        parse=ip_blacklist_parse.parse,
        asset_types=frozenset({AssetType.IP}),
        category="reputation",
    ),
    ToolName.PASSIVEDNS: ToolSpec(
        tool=ToolName.PASSIVEDNS,
        run=passivedns_scan.run,
        parse=passivedns_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.HOLEHE: ToolSpec(
        tool=ToolName.HOLEHE,
        run=holehe_scan.run,
        parse=holehe_parse.parse,
        asset_types=frozenset({AssetType.EMAIL}),
        category="smtp",
    ),
    ToolName.CERTSPOTTER: ToolSpec(
        tool=ToolName.CERTSPOTTER,
        run=certspotter_scan.run,
        parse=certspotter_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="certificate",
    ),
    ToolName.SSL_CHECKER: ToolSpec(
        tool=ToolName.SSL_CHECKER,
        run=ssl_checker_scan.run,
        parse=ssl_checker_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="ssl",
    ),
    ToolName.SUBLIST3R: ToolSpec(
        tool=ToolName.SUBLIST3R,
        run=sublist3r_scan.run,
        parse=sublist3r_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.DNSDUMPSTER: ToolSpec(
        tool=ToolName.DNSDUMPSTER,
        run=dnsdumpster_scan.run,
        parse=dnsdumpster_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="dns",
    ),
    ToolName.PUBLICWWW: ToolSpec(
        tool=ToolName.PUBLICWWW,
        run=publicwww_scan.run,
        parse=publicwww_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="web",
    ),
    ToolName.CLOUDSCRAPER: ToolSpec(
        tool=ToolName.CLOUDSCRAPER,
        run=cloudscraper_scan.run,
        parse=cloudscraper_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="cloud",
    ),
    ToolName.CSPRECON: ToolSpec(
        tool=ToolName.CSPRECON,
        run=csprecon_scan.run,
        parse=csprecon_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="web",
    ),
    ToolName.WAYMORE: ToolSpec(
        tool=ToolName.WAYMORE,
        run=waymore_scan.run,
        parse=waymore_parse.parse,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        category="subdomain",
    ),
    ToolName.SUBOVER: ToolSpec(
        tool=ToolName.SUBOVER,
        run=subover_scan.run,
        parse=subover_parse.parse,
        asset_types=frozenset({AssetType.SUBDOMAIN}),
        category="takeover",
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
