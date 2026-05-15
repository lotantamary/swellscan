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


@pytest.mark.asyncio
async def test_domain_drift_detected_via_header_i_format():
    """Task 30.5 fix: real Gmail Authentication-Results uses `header.i=@domain`
    more commonly than `header.d=domain`. Both must extract the signing
    domain. Discovered during Task 29 dump - existing baseline entries from
    real Gmail-delivered emails had empty typical_signing_domains because the
    old regex only matched header.d=.
    """
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=20,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 10, 11, 14, 15, 16, 17],
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.i=@outlook.com header.s=selector1",
        sender_history=history,
    )
    evs = await SenderBaselineDetector().run(email)
    assert any(e.signal == Signal.SENDER_DOMAIN_DRIFT for e in evs)


@pytest.mark.asyncio
async def test_no_drift_when_typical_signing_domains_is_empty():
    """Task 31 Phase A catch: drift must not fire when the baseline has no
    recorded typical signing domain. An empty baseline means "no history
    yet" - the current signing-domain is the first we've observed, not a
    drift event. Without this guard, every existing baseline entry whose
    typical_signing_domains was empty (because the pre-30.5 regex never
    extracted anything) fired a false drift on the first scan after the
    regex was fixed. Matches the empty-list guard already in place for
    typical_send_hours and typical_ip_prefixes.

    Discovered when scanning a real Google Cloud welcome email post-30.5
    redeploy returned SUSPICIOUS 27/100 with a "Sender domain drift"
    finding against an empty `typical_signing_domains: []` baseline.
    """
    history = SenderHistory(
        from_address="googlecloud@google.com",
        first_seen=datetime(2026, 5, 12, tzinfo=timezone.utc),
        messages_seen=1,
        typical_signing_domains=[],  # empty - the bug-triggering state
        typical_send_hours=[17],
    )
    email = make_email(
        from_address="googlecloud@google.com",
        auth_results="dkim=pass header.i=@google.com header.s=20230601",
        sender_history=history,
    )
    evs = await SenderBaselineDetector().run(email)
    assert not any(e.signal == Signal.SENDER_DOMAIN_DRIFT for e in evs)


@pytest.mark.asyncio
async def test_domain_match_via_header_i_format_no_drift():
    """Task 30.5 fix: header.i= form must also be recognized as a MATCH
    when the extracted domain is in typical_signing_domains. Otherwise
    legitimate emails from known senders would silently bypass the
    drift check.
    """
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=20,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 10, 11, 14, 15, 16, 17],
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.i=@company.com header.s=selector1",
        sender_history=history,
    )
    evs = await SenderBaselineDetector().run(email)
    assert not any(e.signal == Signal.SENDER_DOMAIN_DRIFT for e in evs)


@pytest.mark.asyncio
async def test_send_time_in_range_does_not_fire():
    """Task 31.5 fix: an hour INSIDE the observed [min, max] window must
    not fire SENDER_SEND_TIME_ANOMALY. The pre-fix set-membership check
    would have fired on hour 10 against observed hours {9, 14, 17} since
    10 isn't literally in the recorded set."""
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=20,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 14, 17],  # range = [9, 17]
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.d=company.com",
        sender_history=history,
        received_at=datetime(2026, 5, 14, 10, 30, tzinfo=timezone.utc),  # 10:30, in range
    )
    evs = await SenderBaselineDetector().run(email)
    assert not any(e.signal == Signal.SENDER_SEND_TIME_ANOMALY for e in evs)


@pytest.mark.asyncio
async def test_send_time_outside_range_fires():
    """An hour OUTSIDE the observed [min, max] window fires the signal."""
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=20,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 10, 11, 14, 15, 16, 17],  # range = [9, 17]
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.d=company.com",
        sender_history=history,
        received_at=datetime(2026, 5, 14, 3, 17, tzinfo=timezone.utc),  # 03:17, outside
    )
    evs = await SenderBaselineDetector().run(email)
    assert any(e.signal == Signal.SENDER_SEND_TIME_ANOMALY for e in evs)


@pytest.mark.asyncio
async def test_send_time_anomaly_requires_min_3_observations():
    """A sender with fewer than 3 recorded hours doesn't have enough
    data to define a meaningful send-time window - signal stays silent
    rather than false-positiving on every fresh sender's first few scans."""
    history = SenderHistory(
        from_address="ceo@company.com",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        messages_seen=2,
        typical_signing_domains=["company.com"],
        typical_send_hours=[9, 17],  # only 2 observations
    )
    email = make_email(
        from_address="ceo@company.com",
        auth_results="dkim=pass header.d=company.com",
        sender_history=history,
        received_at=datetime(2026, 5, 14, 3, 17, tzinfo=timezone.utc),
    )
    evs = await SenderBaselineDetector().run(email)
    assert not any(e.signal == Signal.SENDER_SEND_TIME_ANOMALY for e in evs)
