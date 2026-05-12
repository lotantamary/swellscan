import httpx

from backend.config import config


class SafeBrowsingClient:
    BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    TIMEOUT = 4.0

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
        except (httpx.HTTPError, httpx.TimeoutException):
            return set()
