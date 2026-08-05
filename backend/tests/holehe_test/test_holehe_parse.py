from app.models import Severity
from app.tools.holehe.parse import parse


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_no_services():
    assert parse({"email": "a@example.com", "services": []}) == []


def test_parse_returns_one_finding():
    raw = {
        "email": "a@example.com",
        "services": [
            {"name": "twitter", "domain": "twitter.com"},
            {"name": "github", "domain": "github.com"},
        ],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "email_presence"
    assert f["severity"] == Severity.INFO
    assert f["data"]["total_count"] == 2
    assert "2 services" in f["title"]


def test_parse_sorts_services_by_name():
    raw = {
        "email": "a@example.com",
        "services": [{"name": "zoom"}, {"name": "amazon"}],
    }
    findings = parse(raw)
    names = [s["name"] for s in findings[0]["data"]["services"]]
    assert names == ["amazon", "zoom"]


def test_parse_singular_service_title():
    raw = {"email": "a@example.com", "services": [{"name": "github"}]}
    assert "1 service " in parse(raw)[0]["title"] or "1 service" in parse(raw)[0]["title"]


def test_parse_includes_email_in_data():
    raw = {"email": "a@example.com", "services": [{"name": "github"}]}
    assert parse(raw)[0]["data"]["email"] == "a@example.com"
