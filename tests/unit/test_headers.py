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


# V2.S3a: severity-scaled Reply-To handling (research finding #6 part 1)


@pytest.mark.asyncio
async def test_v2_reply_to_freemail_is_high_severity():
    """From corporate to freemail Reply-To = HIGH severity (strong BEC indicator)."""
    email = make_email(
        from_address="ceo@corporate.com",
        reply_to="ceo.personal@gmail.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 1
    assert rep[0].severity == Severity.HIGH
    assert rep[0].confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_v2_reply_to_different_corporate_is_medium_severity():
    """Different non-freemail Reply-To = MEDIUM severity (V1 behavior)."""
    email = make_email(
        from_address="contact@company.com",
        reply_to="contact@other-company.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 1
    assert rep[0].severity == Severity.MEDIUM
    assert rep[0].confidence == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_v2_reply_to_matches_from_no_signal():
    """Reply-To matches From = no signal."""
    email = make_email(
        from_address="alice@company.com",
        reply_to="alice@company.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 0


@pytest.mark.asyncio
async def test_v2_reply_to_subdomain_of_from_no_signal():
    """Reply-To is a subdomain of From = no signal (legitimate practice; fixes V1 over-fire)."""
    email = make_email(
        from_address="noreply@company.com",
        reply_to="support@mail.company.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 0
