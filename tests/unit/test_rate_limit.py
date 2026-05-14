"""V2.S14: tests for the per-user rate limiter."""

import pytest

from backend import rate_limit


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Clear the module-level dict between tests; otherwise state leaks."""
    rate_limit.reset_for_tests()
    yield
    rate_limit.reset_for_tests()


def test_v2_under_cap_allowed():
    """First DAILY_LIMIT calls all succeed."""
    for _ in range(rate_limit.DAILY_LIMIT):
        assert rate_limit.check_and_record("alice@example.com", now=1000.0)


def test_v2_over_cap_rejected():
    """The (DAILY_LIMIT + 1)th call is rejected."""
    for _ in range(rate_limit.DAILY_LIMIT):
        rate_limit.check_and_record("alice@example.com", now=1000.0)
    assert not rate_limit.check_and_record("alice@example.com", now=1000.0)


def test_v2_separate_users_have_separate_counters():
    """One user hitting the cap doesn't affect another user."""
    for _ in range(rate_limit.DAILY_LIMIT):
        rate_limit.check_and_record("alice@example.com", now=1000.0)
    # Alice is at cap
    assert not rate_limit.check_and_record("alice@example.com", now=1000.0)
    # Bob is fresh, gets in
    assert rate_limit.check_and_record("bob@example.com", now=1000.0)


def test_v2_window_slides_after_24h():
    """A call made now does not count against a call made 25 hours ago."""
    # 100 calls at t=0
    for _ in range(rate_limit.DAILY_LIMIT):
        rate_limit.check_and_record("alice@example.com", now=0.0)
    # At t = 25 hours later, all prior calls have rotated out
    later = rate_limit.WINDOW_SECONDS + 3600
    assert rate_limit.check_and_record("alice@example.com", now=later)


def test_v2_partial_window_keeps_recent_calls():
    """Calls from 23 hours ago still count against the user."""
    for _ in range(rate_limit.DAILY_LIMIT):
        rate_limit.check_and_record("alice@example.com", now=0.0)
    # 23 hours later - still inside the 24h window
    later = rate_limit.WINDOW_SECONDS - 3600
    assert not rate_limit.check_and_record("alice@example.com", now=later)
