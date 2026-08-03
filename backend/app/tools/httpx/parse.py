from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn raw httpx output into Finding-ready dicts.

    One ``http_service`` finding per JSON response line. Each finding
    carries the URL, status code, page title, detected technologies,
    webserver, IP, CDN provider, and redirect location when available.

    The frontend renders unknown ``finding_type`` values as raw JSON
    fallback — no frontend changes needed for this type to be visible.
    """
    if not raw_data:
        return []

    target = raw_data.get("target", "")
    responses: list[dict] = raw_data.get("responses") or []
    sources_used: list[str] = raw_data.get("sources_used") or []

    findings: list[dict] = []
    for r in responses:
        url = r.get("url") or r.get("input") or target
        status_code = r.get("status_code")
        title = r.get("title") or ""
        tech_list: list[str] = r.get("tech") or []
        webserver = (
            r.get("webserver") or r.get("server") or (r.get("response_header", {}).get("server"))
        )
        location = r.get("location") or ""

        label = f"HTTP {status_code}" if status_code else "HTTP ?"
        if title:
            label += f" — {title[:80]}"

        findings.append(
            {
                "finding_type": "http_service",
                "title": f"{label} ({url})",
                "severity": Severity.INFO,
                "data": {
                    "target": target,
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "technologies": tech_list,
                    "webserver": webserver,
                    "cdn": r.get("cdn_name") or r.get("cdn") or "",
                    "ip": r.get("ip") or r.get("host") or "",
                    "location": location,
                    "content_type": r.get("content_type") or "",
                    "content_length": r.get("content_length"),
                    "websocket": r.get("websocket", False),
                    "sources_used": sources_used,
                },
            }
        )

    return findings
