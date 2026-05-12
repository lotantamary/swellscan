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
