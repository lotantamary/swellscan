from fastapi import Header, HTTPException
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token
import structlog

from backend.config import config

log = structlog.get_logger()


async def verify_request(authorization: str = Header(...)) -> dict:
    """FastAPI dependency: verify Google OIDC ID token from Authorization header.

    Raises 401 if token missing/invalid; 403 if user not in ALLOWED_USERS.
    Returns the decoded token payload.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = google_id_token.verify_oauth2_token(
            token, GoogleRequest(), audience=config.OIDC_AUDIENCE
        )
    except ValueError as exc:
        log.warning("oidc_verification_failed", error=str(exc))
        raise HTTPException(401, "Invalid token")
    email = payload.get("email", "")
    if email not in config.ALLOWED_USERS:
        log.warning("oidc_user_not_allowed", email=email)
        raise HTTPException(403, "User not authorized")
    return payload
