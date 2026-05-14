import os

from dotenv import load_dotenv

load_dotenv()


def _strip(value: str) -> str:
    """Strip leading/trailing whitespace from env values.

    Task 31 fix: Secret Manager secrets uploaded via `echo` without `-n`
    carry trailing `\\r\\n` characters which propagate into HTTP headers
    and URL query strings. httpx rejects those at request-construction
    time, so every external API call (Anthropic, VirusTotal, Safe
    Browsing) silently failed since V2.S9 deployed. Diagnosed via Cloud
    Run logs during Task 31 Phase A.
    """
    return value.strip() if value else value


class Config:
    ANTHROPIC_API_KEY: str = _strip(os.environ["ANTHROPIC_API_KEY"])
    VIRUSTOTAL_API_KEY: str = _strip(os.environ["VIRUSTOTAL_API_KEY"])
    SAFEBROWSING_API_KEY: str = _strip(os.environ["SAFEBROWSING_API_KEY"])
    URLSCAN_API_KEY: str = _strip(os.environ.get("URLSCAN_API_KEY", ""))
    ALLOWED_USERS: set[str] = {u.strip() for u in os.environ["ALLOWED_USERS"].split(",") if u.strip()}
    OIDC_AUDIENCE: str = _strip(os.environ["OIDC_AUDIENCE"])
    LOG_LEVEL: str = _strip(os.environ.get("LOG_LEVEL", "INFO"))


config = Config()
