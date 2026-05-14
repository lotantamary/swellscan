import httpx
import structlog

from backend.config import config

log = structlog.get_logger()


class SafeBrowsingClient:
    BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    # Task 31 fix: was 4.0. Safe Browsing API responses can be slow on
    # the free tier; the previous timeout was likely the reason
    # URL_KNOWN_PHISHING never fired on the Safe Browsing test URL we
    # inject in demo 2.
    TIMEOUT = 15.0

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client or httpx.AsyncClient(timeout=self.TIMEOUT)

    async def lookup(self, urls: list[str]) -> set[str]:
        """Return the subset of URLs flagged as threats."""
        body = {
            "client": {"clientId": "swellscan", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        try:
            resp = await self._http.post(
                f"{self.BASE}?key={config.SAFEBROWSING_API_KEY}", json=body
            )
            resp.raise_for_status()
            matches = resp.json().get("matches", [])
            return {m["threat"]["url"] for m in matches}
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            # Task 31 fix: previously swallowed silently. Log the failure
            # mode so we can diagnose if URL signals stop firing.
            log.warning(
                "safebrowsing_lookup_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                url_count=len(urls),
            )
            return set()
