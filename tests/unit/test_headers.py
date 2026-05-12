import pytest

from backend.detectors.headers import HeadersDetector
from backend.models.evidence import Severity, Signal
from tests.fixtures.emails import make_email


@pytest.mark.asyncio
async def test_spf_pass_emits_info_evidence():
    email = make_email(auth_results="spf=pass; dkim=pass; dmarc=pass")
    evs = await HeadersDetector().run(email)
    signals = {e.signal for e in evs}
    assert Signal.SPF_PASS in signals
    assert all(e.severity == Severity.INFO for e in evs)


@pytest.mark.asyncio
async def test_spf_fail_emits_high_severity():
    email = make_email(auth_results="spf=fail; dkim=none; dmarc=fail")
    evs = await HeadersDetector().run(email)
    spf_evs = [e for e in evs if e.signal == Signal.SPF_FAIL]
    assert len(spf_evs) == 1
    assert spf_evs[0].severity == Severity.HIGH
    assert "T1566.002" in spf_evs[0].mitre_techniques


@pytest.mark.asyncio
async def test_reply_to_domain_mismatch():
    email = make_email(
        from_address="noreply@bank.com",
        reply_to="attacker@evil.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    assert any(e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH for e in evs)
