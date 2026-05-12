from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend.auth import verify_request


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
