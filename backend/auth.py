from fastapi import Header, HTTPException
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token
import structlog

from backend import rate_limit
from backend.config import config

log = structlog.get_logger()


def _parse_audiences(raw: str) -> list[str]:
    """V2.S14: OIDC_AUDIENCE env var is now comma-separated to support
    multiple Apps Script projects sharing this backend. Empty entries and
    surrounding whitespace are tolerated.
    """
    return [a.strip() for a in raw.split(",") if a.strip()]


async def verify_request(authorization: str = Header(...)) -> dict:
    """FastAPI dependency: verify Google OIDC ID token from Authorization header.

    Raises 401 if token missing/invalid; 403 if user not in ALLOWED_USERS;
    429 if user is over their daily rate limit. Returns the decoded token
    payload.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    audiences = _parse_audiences(config.OIDC_AUDIENCE)
    try:
        payload = google_id_token.verify_oauth2_token(
            token, GoogleRequest(), audience=audiences
        )
    except ValueError as exc:
        log.warning("oidc_verification_failed", error=str(exc))
        raise HTTPException(401, "Invalid token")
    email = payload.get("email", "")
    if email not in config.ALLOWED_USERS:
        log.warning("oidc_user_not_allowed", email=email)
        raise HTTPException(403, "User not authorized")
    if not rate_limit.check_and_record(email):
        log.warning("rate_limit_exceeded", email=email)
        raise HTTPException(
            429,
            "Daily call limit reached for this user. Try again tomorrow.",
        )
    return payload
