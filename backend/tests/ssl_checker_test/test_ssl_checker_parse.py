from app.tools.ssl_checker.parse import parse


def make_raw(**overrides):
    data = {
        "domain": "example.com",
        "cn": "example.com",
        "issuer": "Let's Encrypt",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "days_left": 143,
        "expired": False,
        "serial_hex": "abc123",
        "fingerprint_sha256": "aa" * 32,
        "sans": ["example.com", "www.example.com"],
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
    data.update(overrides)
    return data


def test_parse_valid_cert():
    findings = parse(make_raw())
    assert len(findings) == 1  # no new SANs beyond www
    cert = findings[0]
    assert cert["finding_type"] == "ssl_certificate"
    assert cert["severity"] == "info"
    assert cert["data"]["issuer"] == "Let's Encrypt"
    assert cert["data"]["fingerprint_sha256"] == "aa" * 32


def test_parse_expired_cert():
    findings = parse(make_raw(days_left=0, expired=True))
    cert = findings[0]
    assert cert["finding_type"] == "ssl_certificate"
    assert cert["severity"] == "high"
    assert "expiré" in cert["title"]


def test_parse_expiring_soon():
    findings = parse(make_raw(days_left=7, expired=False))
    cert = findings[0]
    assert cert["finding_type"] == "ssl_certificate"
    assert cert["severity"] == "medium"


def test_parse_expiring_medium():
    findings = parse(make_raw(days_left=20, expired=False))
    cert = findings[0]
    assert cert["finding_type"] == "ssl_certificate"
    assert cert["severity"] == "low"


def test_parse_new_sans_emit_discovered_assets():
    findings = parse(
        make_raw(sans=["example.com", "www.example.com", "api.example.com", "mail.example.com"])
    )
    assert len(findings) == 2
    cert = findings[0]
    assert cert["finding_type"] == "ssl_certificate"
    discovered = findings[1]
    assert discovered["finding_type"] == "discovered_assets"
    assert discovered["data"]["category"] == "hosts"
    assert "api.example.com" in discovered["data"]["items"]
    assert "mail.example.com" in discovered["data"]["items"]
    assert "example.com" not in discovered["data"]["items"]
    assert "www.example.com" not in discovered["data"]["items"]


def test_parse_empty_raw():
    assert parse({}) == []


def test_parse_no_domain():
    findings = parse(make_raw(domain=""))
    cert = findings[0]
    assert cert["data"]["domain"] == ""


def test_severity_edge_cases():
    # days_left is None but not expired — info
    findings = parse(make_raw(days_left=None, expired=False))
    assert findings[0]["severity"] == "info"

    # exactly 0 days but not marked expired — high
    findings = parse(make_raw(days_left=0, expired=False))
    assert findings[0]["severity"] == "high"

    # exactly 14 days — medium
    findings = parse(make_raw(days_left=14, expired=False))
    assert findings[0]["severity"] == "medium"
