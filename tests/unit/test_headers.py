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


# V2.S3b: Return-Path mismatch (research finding #6 part 2). Field already
# plumbed end-to-end in V1; only the detector logic is new.


@pytest.mark.asyncio
async def test_v2_return_path_freemail_is_high_severity():
    """Corporate From + freemail Return-Path = HIGH severity (rare in legit setups)."""
    email = make_email(
        from_address="ceo@corporate.com",
        return_path="<bounce.handler@gmail.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 1
    assert rp[0].severity == Severity.HIGH
    assert rp[0].confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_v2_return_path_different_corporate_is_medium_severity():
    """Different non-transactional, non-freemail Return-Path = MEDIUM severity."""
    email = make_email(
        from_address="contact@company.com",
        return_path="<bounce@othercorp.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 1
    assert rp[0].severity == Severity.MEDIUM
    assert rp[0].confidence == pytest.approx(0.75)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mailer",
    [
        "<bounces+abc@sendgrid.net>",
        "<bounce@mailgun.org>",
        "<01000001-abc@amazonses.com>",
        "<bounce@mandrillapp.com>",
        "<bounce@sparkpostmail.com>",
    ],
)
async def test_v2_return_path_transactional_mailer_no_signal(mailer):
    """Known transactional-mailer Return-Path = no signal (legitimate)."""
    email = make_email(
        from_address="notifications@company.com",
        return_path=mailer,
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 0, f"Should not fire for transactional mailer {mailer}"


@pytest.mark.asyncio
async def test_v2_return_path_matches_from_no_signal():
    """Return-Path matches From = no signal."""
    email = make_email(
        from_address="alice@company.com",
        return_path="<alice@company.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 0


@pytest.mark.asyncio
async def test_v2_return_path_subdomain_no_signal():
    """Subdomain Return-Path = no signal (legitimate bounce-handling subdomain)."""
    email = make_email(
        from_address="noreply@company.com",
        return_path="<bounces@mail.company.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 0


@pytest.mark.asyncio
async def test_v2_return_path_empty_no_signal():
    """Empty Return-Path = no signal (not all mail servers set it)."""
    email = make_email(
        from_address="alice@company.com",
        return_path="",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 0


# V2.S10 fix B: cousin subdomains under a common registrable parent should
# not fire mismatch signals (e.g. accounts.google.com vs gaia.bounces.google.com).


@pytest.mark.asyncio
async def test_v2_return_path_cousin_subdomain_same_parent_no_signal():
    """V2.S10 fix B: accounts.google.com vs gaia.bounces.google.com = same org, no signal."""
    email = make_email(
        from_address="noreply@accounts.google.com",
        return_path="<bounce@gaia.bounces.google.com>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 0


@pytest.mark.asyncio
async def test_v2_reply_to_cousin_subdomain_same_parent_no_signal():
    """V2.S10 fix B: same logic applied to Reply-To check."""
    email = make_email(
        from_address="noreply@accounts.google.com",
        reply_to="support@feedback.google.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 0


@pytest.mark.asyncio
async def test_v2_return_path_different_parents_still_fires():
    """Regression guard: genuinely different orgs still fire."""
    email = make_email(
        from_address="contact@realcompany.com",
        return_path="<bounce@otherorg.example>",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rp = [e for e in evs if e.signal == Signal.RETURN_PATH_DOMAIN_MISMATCH]
    assert len(rp) == 1


@pytest.mark.asyncio
async def test_v2_reply_to_different_parents_still_fires():
    """Regression guard: Reply-To across different parents still fires."""
    email = make_email(
        from_address="ceo@corporate.com",
        reply_to="ceo.alt@another-org.com",
        auth_results="spf=pass; dkim=pass; dmarc=pass",
    )
    evs = await HeadersDetector().run(email)
    rep = [e for e in evs if e.signal == Signal.REPLY_TO_DOMAIN_MISMATCH]
    assert len(rep) == 1
