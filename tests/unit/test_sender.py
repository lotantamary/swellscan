import pytest

from backend.detectors.sender import SenderDetector
from backend.models.evidence import Signal
from tests.fixtures.emails import make_email


@pytest.mark.asyncio
async def test_lookalike_microsoft_domain_detected():
    email = make_email(
        from_address="support@account-microsoft-secure.com",
        from_name="Microsoft Account Team",
    )
    evs = await SenderDetector().run(email)
    assert any(e.signal == Signal.LOOKALIKE_DOMAIN for e in evs)


@pytest.mark.asyncio
async def test_display_name_domain_mismatch_detected():
    email = make_email(
        from_address="randomuser@gmail.com",
        from_name="PayPal Support",
    )
    evs = await SenderDetector().run(email)
    assert any(e.signal == Signal.DISPLAY_NAME_DOMAIN_MISMATCH for e in evs)


@pytest.mark.asyncio
async def test_legitimate_sender_emits_no_signals():
    email = make_email(from_address="alice@example.com", from_name="Alice")
    evs = await SenderDetector().run(email)
    assert evs == []


# V2.S10 fix A: legitimate subdomains of known brand domains should not fire
# LOOKALIKE_DOMAIN or DISPLAY_NAME_DOMAIN_MISMATCH. V1 over-fired on these
# because `from_domain not in legit_domains` is True for any subdomain.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "from_address",
    [
        "noreply@accounts.google.com",
        "team@docs.google.com",
        "alerts@security.google.com",
        "no-reply@drive.google.com",
        "support@mail.dropbox.com",
        "billing@apple.icloud.com",
    ],
)
async def test_v2_legitimate_brand_subdomain_no_signals(from_address):
    """V2.S10 fix A: legitimate brand subdomains must not fire false-positives."""
    email = make_email(from_address=from_address, from_name="Team")
    evs = await SenderDetector().run(email)
    lookalike = [e for e in evs if e.signal == Signal.LOOKALIKE_DOMAIN]
    display = [e for e in evs if e.signal == Signal.DISPLAY_NAME_DOMAIN_MISMATCH]
    assert lookalike == [], f"false LOOKALIKE_DOMAIN on {from_address}"
    assert display == [], f"false DISPLAY_NAME_DOMAIN_MISMATCH on {from_address}"


@pytest.mark.asyncio
async def test_v2_legitimate_subdomain_with_brand_display_name_no_signals():
    """Subdomain of legit brand + brand-named display = no signals (e.g. Gmail Team from accounts.google.com)."""
    email = make_email(
        from_address="security-alert@accounts.google.com",
        from_name="Google Security",
    )
    evs = await SenderDetector().run(email)
    risky_signals = [
        e.signal
        for e in evs
        if e.signal
        in (Signal.LOOKALIKE_DOMAIN, Signal.DISPLAY_NAME_DOMAIN_MISMATCH, Signal.FREEMAIL_IMPERSONATING_BRAND)
    ]
    assert risky_signals == []


@pytest.mark.asyncio
async def test_v2_genuine_lookalike_still_fires_after_fix():
    """Regression guard: actual lookalike domains MUST still fire."""
    email = make_email(
        from_address="alerts@accountsgoogle.com",
        from_name="Google Security",
    )
    evs = await SenderDetector().run(email)
    assert any(e.signal == Signal.LOOKALIKE_DOMAIN for e in evs)


@pytest.mark.asyncio
async def test_v2_brand_in_unrelated_tld_still_fires():
    """Regression guard: brand keyword in unrelated TLD should still fire."""
    email = make_email(
        from_address="support@google-verify.net",
        from_name="Google Support",
    )
    evs = await SenderDetector().run(email)
    assert any(e.signal == Signal.LOOKALIKE_DOMAIN for e in evs)
