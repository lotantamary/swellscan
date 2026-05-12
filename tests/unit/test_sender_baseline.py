from datetime import datetime, timezone

import pytest

from backend.detectors.sender_baseline import SenderBaselineDetector
from backend.models.email import SenderHistory
from backend.models.evidence import Signal
from tests.fixtures.emails import make_email


@pytest.mark.asyncio
async def test_first_seen_when_no_history():
    email = make_email(from_address="new@unknown.com", sender_history=None)
    evs = await SenderBaselineDetector().run(email)
    assert any(e.signal == Signal.FIRST_SEEN_SENDER for e in evs)


@pytest.mark.asyncio
async def test_domain_drift_detected():
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=20,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 10, 11, 14, 15, 16, 17],
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.d=outlook.com",
        sender_history=history,
    )
    evs = await SenderBaselineDetector().run(email)
    assert any(e.signal == Signal.SENDER_DOMAIN_DRIFT for e in evs)
