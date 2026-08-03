from app.models import Severity
from app.tools.httpx.parse import parse


def test_parse_handles_empty_dict():
    assert parse({}) == []


def test_parse_handles_none():
    assert parse(None) == []


def test_parse_omits_empty_responses():
    assert parse({"target": "example.com", "responses": []}) == []


def test_parse_single_response():
    raw = {
        "target": "example.com",
        "responses": [
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "Example",
                "tech": ["HSTS", "Nginx"],
                "webserver": "nginx/1.18",
                "ip": "93.184.216.34",
                "cdn_name": "Cloudflare",
                "location": "",
                "content_type": "text/html",
                "content_length": 1256,
            }
        ],
        "sources_used": ["httpx"],
    }
    findings = parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "http_service"
    assert f["severity"] == Severity.INFO
    assert "HTTP 200" in f["title"]
    assert "Example" in f["title"]
    assert f["data"]["status_code"] == 200
    assert f["data"]["technologies"] == ["HSTS", "Nginx"]
    assert f["data"]["webserver"] == "nginx/1.18"
    assert f["data"]["ip"] == "93.184.216.34"
    assert f["data"]["cdn"] == "Cloudflare"
    assert f["data"]["sources_used"] == ["httpx"]


def test_parse_multiple_responses():
    raw = {
        "target": "example.com",
        "responses": [
            {"url": "https://example.com", "status_code": 200},
            {"url": "http://example.com", "status_code": 301},
        ],
    }
    findings = parse(raw)
    assert len(findings) == 2


def test_parse_uses_input_when_url_missing():
    raw = {
        "target": "example.com",
        "responses": [{"input": "example.com", "status_code": 404}],
    }
    findings = parse(raw)
    assert "example.com" in findings[0]["title"]


def test_parse_falls_back_to_target_for_url():
    raw = {
        "target": "example.com",
        "responses": [{"status_code": 503}],
    }
    findings = parse(raw)
    assert "example.com" in findings[0]["title"]


def test_parse_title_truncation():
    """Titles longer than 80 chars are truncated with [:80]."""
    raw = {
        "target": "example.com",
        "responses": [
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "A" * 100,
            }
        ],
    }
    findings = parse(raw)
    title = findings[0]["title"]
    # The title format is "HTTP 200 — <title[:80]> (<url>)"
    assert "A" * 80 in title
    assert "A" * 81 not in title
