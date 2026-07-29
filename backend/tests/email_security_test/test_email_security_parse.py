from app.models import Severity
from app.tools.email_security.parse import parse


def test_parse_handles_empty_response():
    assert parse({}) == []


def test_parse_flags_missing_spf_as_medium():
    raw = {"domain": "example.com", "spf_record": None, "dmarc_record": "v=DMARC1; p=reject"}
    findings = parse(raw)
    spf = next(f for f in findings if f["data"]["check"] == "spf")

    assert spf["severity"] == Severity.MEDIUM
    assert spf["data"]["present"] is False


def test_parse_flags_present_spf_as_info():
    raw = {
        "domain": "example.com",
        "spf_record": "v=spf1 ~all",
        "dmarc_record": ("v=DMARC1; p=reject"),
    }
    findings = parse(raw)
    spf = next(f for f in findings if f["data"]["check"] == "spf")

    assert spf["severity"] == Severity.INFO
    assert spf["data"]["record"] == "v=spf1 ~all"


def test_parse_flags_missing_dmarc_as_high():
    raw = {"domain": "example.com", "spf_record": "v=spf1 ~all", "dmarc_record": None}
    findings = parse(raw)
    dmarc = next(f for f in findings if f["data"]["check"] == "dmarc")

    assert dmarc["severity"] == Severity.HIGH
    assert dmarc["data"]["present"] is False


def test_parse_dmarc_reject_policy_is_info():
    raw = {"domain": "example.com", "dmarc_record": "v=DMARC1; p=reject; rua=mailto:x@example.com"}
    findings = parse(raw)
    dmarc = next(f for f in findings if f["data"]["check"] == "dmarc")

    assert dmarc["data"]["policy"] == "reject"
    assert dmarc["severity"] == Severity.INFO


def test_parse_dmarc_none_policy_is_medium():
    raw = {"domain": "example.com", "dmarc_record": "v=DMARC1; p=none"}
    findings = parse(raw)
    dmarc = next(f for f in findings if f["data"]["check"] == "dmarc")

    assert dmarc["data"]["policy"] == "none"
    assert dmarc["severity"] == Severity.MEDIUM


def test_parse_dmarc_quarantine_policy_is_low():
    raw = {"domain": "example.com", "dmarc_record": "v=DMARC1; p=quarantine"}
    findings = parse(raw)
    dmarc = next(f for f in findings if f["data"]["check"] == "dmarc")

    assert dmarc["severity"] == Severity.LOW


def test_parse_dkim_finding_present_when_selectors_found():
    raw = {"domain": "example.com", "dkim_selectors_found": ["default", "google"]}
    findings = parse(raw)
    dkim = next(f for f in findings if f["data"]["check"] == "dkim")

    assert dkim["severity"] == Severity.INFO
    assert dkim["data"]["selectors"] == ["default", "google"]


def test_parse_omits_dkim_finding_when_no_selectors_found():
    raw = {"domain": "example.com", "dkim_selectors_found": []}
    findings = parse(raw)

    assert all(f["data"]["check"] != "dkim" for f in findings)


def test_parse_always_returns_spf_and_dmarc_findings():
    raw = {"domain": "example.com", "spf_record": None, "dmarc_record": None}
    findings = parse(raw)
    checks = {f["data"]["check"] for f in findings}

    assert checks == {"spf", "dmarc"}
