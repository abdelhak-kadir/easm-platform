from app.models import Severity

# Shodan doesn't give a severity for open ports directly, so we treat them
# as informational and let vulnerabilities carry the real risk signal.
_CVSS_THRESHOLDS = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw Shodan host response into a list of Finding-ready dicts."""
    findings = []

    if raw_data.get("ip_str"):
        findings.append(_parse_host_info(raw_data))

    findings.extend(_parse_open_port(service) for service in raw_data.get("data", []))

    detected_cpes = _collect_detected_cpes(raw_data)
    for cve_id, vuln_info in _iter_vulns(raw_data.get("vulns")):
        findings.append(_parse_vulnerability(cve_id, vuln_info, detected_cpes))

    return findings


def _iter_vulns(vulns) -> list[tuple[str, dict]]:
    """Shodan's `vulns` field is normally a dict of
    `{cve_id: {cvss, summary}}`, but for some hosts it comes back as a
    bare list of CVE ID strings instead (no CVSS/summary attached).
    Normalize both shapes to (cve_id, info_dict) pairs so downstream
    parsing doesn't care which one Shodan sent.
    """
    if not vulns:
        return []
    if isinstance(vulns, dict):
        return list(vulns.items())
    if isinstance(vulns, list):
        return [(cve_id, {}) for cve_id in vulns]
    return []


def _parse_host_info(raw_data: dict) -> dict:
    """Everything Shodan knows about the host itself, as a single finding.

    Kept under one generic finding_type ("host_info") rather than a
    Shodan-specific shape, so a results viewer can render it without
    knowing which tool produced it -- other tools (whois, censys) can
    emit the same finding_type later with whatever subset of fields
    they have.
    """
    ip = raw_data.get("ip_str")
    return {
        "finding_type": "host_info",
        "title": f"Host information for {ip}",
        "severity": Severity.INFO,
        "data": {
            "ip": ip,
            "org": raw_data.get("org"),
            "isp": raw_data.get("isp"),
            "asn": raw_data.get("asn"),
            "hostnames": raw_data.get("hostnames", []),
            "domains": raw_data.get("domains", []),
            "country_name": raw_data.get("country_name"),
            "country_code": raw_data.get("country_code"),
            "city": raw_data.get("city"),
            "region_code": raw_data.get("region_code"),
            "latitude": raw_data.get("latitude"),
            "longitude": raw_data.get("longitude"),
            "os": raw_data.get("os"),
            "tags": raw_data.get("tags", []),
            "ports": raw_data.get("ports", []),
            "last_update": raw_data.get("last_update"),
        },
    }


def _parse_open_port(service: dict) -> dict:
    port = service.get("port")
    transport = service.get("transport", "tcp")
    product = service.get("product", "")
    title = f"Open port {port}/{transport}" + (f" ({product})" if product else "")

    data: dict = {
        "port": port,
        "transport": transport,
        "product": product,
        "version": service.get("version", ""),
        "banner": (service.get("data") or "")[:500],
    }

    # CPEs — the structured "what exactly is this software" signal,
    # invaluable for risk scoring and CVE correlation downstream.
    cpes = service.get("cpe") or []
    if cpes:
        data["cpe"] = cpes

    # HTTP module details (server header, status, title, host).
    http = service.get("http") or {}
    if http.get("server"):
        data["http_server"] = http["server"]
    if http.get("status"):
        data["http_status"] = http["status"]
    if http.get("title"):
        data["http_title"] = http["title"]
    if http.get("host"):
        data["http_host"] = http["host"]

    return {
        "finding_type": "open_port",
        "title": title,
        "severity": Severity.INFO,
        "data": data,
    }


def _parse_vulnerability(cve_id: str, vuln_info: dict, detected_cpes: list[str]) -> dict:
    cvss = vuln_info.get("cvss") or 0.0
    data: dict = {
        "cvss": cvss,
        "summary": vuln_info.get("summary", ""),
    }

    # Fix verdict: compare the versions Shodan detected on the host against
    # the CVE's affected-version list. Only computable when the CVEDB
    # record (with `cves`) made it into the scan result.
    affected_cpes = vuln_info.get("cves") or []
    if affected_cpes:
        verdict = _compute_verdict(detected_cpes, affected_cpes)
        if verdict:
            data.update(verdict)

    # Exploit-context passthrough (CISA KEV flag, EPSS probability).
    for key in ("kev", "epss", "epss_ranking", "published_time", "references"):
        value = vuln_info.get(key)
        if value:
            data[key] = value

    return {
        "finding_type": "vulnerability",
        "title": cve_id,
        "severity": _severity_from_cvss(cvss),
        "data": data,
    }


def _collect_detected_cpes(raw_data: dict) -> list[str]:
    """All CPE strings Shodan detected on the host: top-level `cpes` when
    present, plus every service's `cpe` field."""
    cpes = list(raw_data.get("cpes") or [])
    for service in raw_data.get("data", []):
        cpes.extend(service.get("cpe") or [])
    return cpes


def _compute_verdict(detected_cpes: list[str], affected_cpes: list[str]) -> dict:
    """Compare detected product versions against the CVE's affected-CPE list.

    cvedb.shodan.io ships `cpes` as an *enumerated* list of affected
    versions (NVD-style), which can contain gaps (e.g. 2.4.3..2.4.9 may be
    absent). So we only claim "fixed" when the detected version is strictly
    newer than every listed affected version, and "unknown" when it falls
    inside the range without being listed.

    Returns {"verdict", "detected_version", "latest_affected"} or {} when no
    detected product matches the CVE's affected products.
    """
    affected_versions: dict[tuple[str, str], list[str]] = {}
    for cpe in affected_cpes:
        parsed = _parse_cpe(cpe)
        if parsed is None:
            continue
        vendor, product, version = parsed
        affected_versions.setdefault((vendor, product), []).append(version)

    for cpe in detected_cpes:
        parsed = _parse_cpe(cpe)
        if parsed is None:
            continue
        vendor, product, version = parsed
        if version == "*":
            continue
        versions = affected_versions.get((vendor, product))
        if versions is None:
            continue
        if "*" in versions:
            # CVE affects every version of the product.
            return {"verdict": "vulnerable", "detected_version": version}
        latest = _max_version(versions)
        if version in versions:
            return {
                "verdict": "vulnerable",
                "detected_version": version,
                "latest_affected": latest,
            }
        if _version_key(version) > _version_key(latest):
            return {
                "verdict": "fixed",
                "detected_version": version,
                "latest_affected": latest,
            }
        return {
            "verdict": "unknown",
            "detected_version": version,
            "latest_affected": latest,
        }
    return {}


def _parse_cpe(cpe: str) -> tuple[str, str, str] | None:
    """Pull (vendor, product, version) out of a CPE string.

    Two formats arrive in practice:
    - CPE 2.3 (CVEDB affected lists): `cpe:2.3:a:apache:http_server:2.4.49:…`
    - CPE 2.2 (Shodan service `cpe` fields): `cpe:/a:apache:http_server:2.4.49`
    Both put vendor/product/version in the same relative slots; everything
    after is ignored.
    """
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>:…
        if len(parts) < 6:
            return None
        vendor, product, version = parts[3], parts[4], parts[5]
    elif cpe.startswith("cpe:/"):
        parts = cpe.split(":")
        # cpe:/<part>:<vendor>:<product>:<version>:…
        if len(parts) < 5:
            return None
        vendor, product, version = parts[2], parts[3], parts[4]
    else:
        return None
    if not vendor or not product or not version:
        return None
    return vendor.lower(), product.lower(), version


def _version_key(version: str) -> tuple:
    """Comparable key for dotted versions like '2.4.49' or '1.1.1k'.

    Numeric segments sort before alphabetic ones (a patch letter is newer
    than a bare release), and equal numeric prefixes with letters compare
    lexically ('1.1.1k' < '1.1.1m'). A verdict heuristic, not a semver
    solver.
    """
    return tuple(
        (0, int(segment)) if segment.isdigit() else (1, segment) for segment in version.split(".")
    )


def _max_version(versions: list[str]) -> str:
    return max(versions, key=_version_key)


def _severity_from_cvss(cvss: float) -> Severity:
    for threshold, severity in _CVSS_THRESHOLDS:
        if cvss >= threshold:
            return severity
    return Severity.INFO
