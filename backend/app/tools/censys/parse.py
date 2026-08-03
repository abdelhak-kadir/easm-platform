from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw Censys host response into a list of Finding-ready dicts.

    Reuses the cross-tool ``host_info`` and ``open_port`` finding types
    so the frontend renders Censys results without any Censys-specific code.
    """
    findings: list[dict] = []

    ip = raw_data.get("ip")
    if ip:
        findings.append(_parse_host_info(raw_data))

    for service in raw_data.get("services") or []:
        findings.append(_parse_service(service))

    return findings


def _parse_host_info(result: dict) -> dict:
    """Everything Censys knows about the host, as a single ``host_info`` finding."""
    ip = result.get("ip")
    location = result.get("location") or {}
    asn_info = result.get("autonomous_system") or {}
    os_info = result.get("operating_system") or {}

    ports: list[int] = []
    for svc in result.get("services") or []:
        if (port := svc.get("port")) is not None:
            ports.append(port)

    return {
        "finding_type": "host_info",
        "title": f"Host information for {ip}",
        "severity": Severity.INFO,
        "data": {
            "ip": ip,
            "org": asn_info.get("organization") or asn_info.get("description"),
            "isp": None,
            "asn": asn_info.get("asn"),
            "hostnames": [],
            "domains": [],
            "country_name": location.get("country"),
            "country_code": location.get("country_code"),
            "city": location.get("city"),
            "region_code": location.get("province"),
            "latitude": (coords := location.get("coordinates")) and coords.get("latitude"),
            "longitude": (coords := location.get("coordinates")) and coords.get("longitude"),
            "os": os_info.get("description") or os_info.get("product"),
            "tags": [],
            "ports": sorted(ports),
            "last_update": result.get("last_updated_at"),
        },
    }


def _parse_service(service: dict) -> dict:
    port = service.get("port")
    transport = (service.get("transport_protocol") or "TCP").lower()
    svc_name = service.get("service_name") or ""
    product = service.get("extended_service_name") or svc_name
    title = f"Open port {port}/{transport}" + (f" ({product})" if product else "")

    software_list = service.get("software") or []
    banner = ""
    sw_products: list[str] = []
    for sw in software_list:
        if sw.get("product"):
            sw_products.append(f"{sw['product']} {sw.get('version', '')}".strip())
    if sw_products:
        banner = "; ".join(sw_products)

    if not banner:
        banner = (service.get("banner") or "")[:500]

    return {
        "finding_type": "open_port",
        "title": title,
        "severity": Severity.INFO,
        "data": {
            "port": port,
            "transport": transport,
            "product": product,
            "version": "",
            "banner": banner,
        },
    }
