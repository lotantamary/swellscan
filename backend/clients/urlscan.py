import httpx

from backend.config import config


class UrlscanClient:
    BASE = "https://urlscan.io/api/v1"
    TIMEOUT = 4.0

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client or httpx.AsyncClient(timeout=self.TIMEOUT)

    async def search_existing(self, url: str) -> dict:
        """Look up existing scan results for a URL (no new scan submitted)."""
        try:
            resp = await self._http.get(
                f"{self.BASE}/search/?q=page.url:{url}",
                headers=(
                    {"API-Key": config.URLSCAN_API_KEY}
                    if config.URLSCAN_API_KEY
                    else {}
                ),
            )
            if resp.status_code != 200:
                return {"found": False}
            results = resp.json().get("results", [])
            if not results:
                return {"found": False}
            top = results[0]
            return {
                "found": True,
                "verdict": top.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "final_url": top.get("page", {}).get("url", url),
            }
        except (httpx.HTTPError, httpx.TimeoutException):
            return {"found": False, "error": "urlscan_request_failed"}
