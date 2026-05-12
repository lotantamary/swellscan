from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.models.evidence import Evidence, Severity, Signal
from backend.models.verdict import Confidence, Verdict, VerdictLabel
from tests.fixtures.emails import make_email


def test_email_parses_valid_payload():
    email = make_email(subject="Test")
    assert email.subject == "Test"
    assert email.from_.address == "alice@example.com"


def test_email_body_size_cap_enforced():
    with pytest.raises(ValidationError):
        make_email(body_text="x" * 100_001)


def test_evidence_construction():
    ev = Evidence(
        signal=Signal.SPF_FAIL,
        severity=Severity.HIGH,
        confidence=0.95,
        explanation="SPF failed for example.com",
        mitre_techniques=["T1566.002"],
        details={"sender_ip": "1.2.3.4"},
        detector="headers",
    )
    assert ev.signal == Signal.SPF_FAIL
    assert ev.confidence == 0.95


def test_verdict_construction():
    verdict = Verdict(
        request_id="abc",
        score=82,
        label=VerdictLabel.MALICIOUS,
        confidence=Confidence.HIGH,
        summary="High-confidence malicious",
        evidence=[],
        computed_at=datetime.now(timezone.utc),
        latency_ms=400,
        detectors_run=["headers", "urls"],
    )
    assert verdict.label == VerdictLabel.MALICIOUS
