from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn CloudScraper output into Finding-ready dicts.

    Produces:

    1. ``vulnerability`` for each PUBLIC bucket (severity HIGH)
    2. ``host_info`` — summary of buckets found
    """
    if not raw_data:
        return []

    domain = raw_data.get("domain", "")
    buckets: list[dict] = raw_data.get("buckets") or []
    findings: list[dict] = []

    public = [b for b in buckets if b.get("public")]
    private = [b for b in buckets if not b.get("public")]

    # ── Public buckets → vulnerability ──────────────────────────────
    for bucket in public:
        findings.append(
            {
                "finding_type": "vulnerability",
                "title": f"Bucket PUBLIC {bucket['provider']}: {bucket['bucket']}",
                "severity": Severity.HIGH,
                "data": {
                    "source": "cloudscraper",
                    "cve": "",
                    "bucket": bucket["bucket"],
                    "provider": bucket["provider"],
                    "url": bucket.get("url", ""),
                    "exposure": "public_read",
                    "description": (
                        f"Cloud storage bucket {bucket['bucket']} ({bucket['provider']}) "
                        f"is publicly accessible at {bucket.get('url', '')}"
                    ),
                },
            }
        )

    # ── Private buckets → host_info ─────────────────────────────────
    bucket_list = [f"{b['bucket']} ({b['provider']})" for b in buckets]

    findings.append(
        {
            "finding_type": "host_info",
            "title": f"Cloud: {len(public)} public, {len(private)} privé pour {domain}",
            "severity": Severity.HIGH if public else Severity.INFO,
            "data": {
                "source": "cloudscraper",
                "buckets_found": bucket_list,
                "public_count": len(public),
                "private_count": len(private),
            },
        }
    )

    return findings
