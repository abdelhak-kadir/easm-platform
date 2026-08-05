from app.models import Severity


def parse(raw_data: dict) -> list[dict]:
    """Turn a raw holehe response into a single Finding-ready dict.

    One finding per scan rather than one per service — with 100+
    services checked, per-service findings would flood the results
    list for little benefit; the service list itself carries the detail.
    """
    if not raw_data:
        return []

    email = raw_data.get("email", "")
    services = sorted(raw_data.get("services") or [], key=lambda s: s.get("name", ""))
    if not services:
        return []

    count = len(services)
    return [
        {
            "finding_type": "email_presence",
            "title": f"Email {email} found on {count} service{'s' if count != 1 else ''}",
            "severity": Severity.INFO,
            "data": {
                "email": email,
                "services": services,
                "total_count": count,
            },
        }
    ]
