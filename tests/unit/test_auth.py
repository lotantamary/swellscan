from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend import rate_limit
from backend.auth import _parse_audiences, verify_request


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """V2.S14: clear shared rate-limit state so tests don't bleed counters."""
    rate_limit.reset_for_tests()
    yield
    rate_limit.reset_for_tests()


@pytest.mark.asyncio
async def test_missing_bearer_raises_401():
    with pytest.raises(HTTPException) as exc:
        await verify_request(authorization="NotBearer xxx")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_raises_401():
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        side_effect=ValueError("bad"),
    ):
        with pytest.raises(HTTPException) as exc:
            await verify_request(authorization="Bearer abc.def.ghi")
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_disallowed_user_raises_403():
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        return_value={"email": "evil@example.com"},
    ):
        with pytest.raises(HTTPException) as exc:
            await verify_request(authorization="Bearer abc.def.ghi")
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_allowed_user_passes():
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        return_value={"email": "test@example.com"},
    ):
        with patch("backend.auth.config.ALLOWED_USERS", {"test@example.com"}):
            payload = await verify_request(authorization="Bearer abc.def.ghi")
            assert payload["email"] == "test@example.com"


# V2.S14: multi-audience support


def test_v2_parse_audiences_single_value():
    """V1 behavior: a single audience string parses to a single-element list."""
    assert _parse_audiences("aud-one") == ["aud-one"]


def test_v2_parse_audiences_comma_separated():
    """Comma-separated values parse to a list of audiences."""
    assert _parse_audiences("aud-one,aud-two,aud-three") == [
        "aud-one",
        "aud-two",
        "aud-three",
    ]


def test_v2_parse_audiences_tolerates_whitespace_and_empty():
    """Surrounding whitespace and empty entries are filtered out."""
    assert _parse_audiences("aud-one, aud-two ,  ,aud-three,") == [
        "aud-one",
        "aud-two",
        "aud-three",
    ]


# V2.S14: rate-limit integration in auth gate


@pytest.mark.asyncio
async def test_v2_rate_limit_blocks_user_over_cap():
    """The 101st call from the same user returns 429."""
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        return_value={"email": "heavy@example.com"},
    ):
        with patch("backend.auth.config.ALLOWED_USERS", {"heavy@example.com"}):
            for _ in range(rate_limit.DAILY_LIMIT):
                await verify_request(authorization="Bearer abc.def.ghi")
            with pytest.raises(HTTPException) as exc:
                await verify_request(authorization="Bearer abc.def.ghi")
            assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_v2_rate_limit_separate_users_independent():
    """One user hitting the cap does not affect another allowed user."""
    with patch("backend.auth.config.ALLOWED_USERS", {"a@e.com", "b@e.com"}):
        with patch(
            "backend.auth.google_id_token.verify_oauth2_token",
            return_value={"email": "a@e.com"},
        ):
            for _ in range(rate_limit.DAILY_LIMIT):
                await verify_request(authorization="Bearer abc.def.ghi")
        # a@e.com is now at cap
        with patch(
            "backend.auth.google_id_token.verify_oauth2_token",
            return_value={"email": "b@e.com"},
        ):
            payload = await verify_request(authorization="Bearer abc.def.ghi")
            assert payload["email"] == "b@e.com"


@pytest.mark.asyncio
async def test_v2_disallowed_user_does_not_consume_rate_limit_slot():
    """A 403 from allowlist check happens BEFORE the rate-limit counter
    increments, so a disallowed user cannot burn quota."""
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        return_value={"email": "evil@example.com"},
    ):
        with pytest.raises(HTTPException) as exc:
            await verify_request(authorization="Bearer abc.def.ghi")
        assert exc.value.status_code == 403
    # And the bucket for evil@example.com should be empty.
    # We verify by allowing them and confirming they get the full quota.
    with patch(
        "backend.auth.google_id_token.verify_oauth2_token",
        return_value={"email": "evil@example.com"},
    ):
        with patch("backend.auth.config.ALLOWED_USERS", {"evil@example.com"}):
            # All DAILY_LIMIT calls succeed - no prior counter from the 403 above.
            for _ in range(rate_limit.DAILY_LIMIT):
                await verify_request(authorization="Bearer abc.def.ghi")
