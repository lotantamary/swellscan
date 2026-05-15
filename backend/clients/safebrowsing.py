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
            # Task 31.5 security-review hardening: drop error=str(exc).
            # Safe Browsing's v4 API requires the API key as a URL query
            # parameter (?key=...), and httpx exception __str__ can include
            # the request URL with the key inline. Logging error_type plus
            # the response status code (when available) is sufficient for
            # diagnosis without ever shipping the key into Cloud Logging.
            log.warning(
                "safebrowsing_lookup_failed",
                error_type=type(exc).__name__,
                status=getattr(getattr(exc, "response", None), "status_code", None),
                url_count=len(urls),
            )
            return set()
