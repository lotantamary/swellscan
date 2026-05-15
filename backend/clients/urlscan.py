from urllib.parse import quote

import httpx
import structlog

from backend.config import config

log = structlog.get_logger()


class UrlscanClient:
    BASE = "https://urlscan.io/api/v1"
    # Kept tight on purpose: urlscan is the cushion-tier reputation source.
    # If it slows us down it should fail fast and let the verdict ship on
    # VirusTotal + Safe Browsing alone.
    TIMEOUT = 4.0

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client or httpx.AsyncClient(timeout=self.TIMEOUT)

    async def search_existing(self, url: str) -> dict:
        """Look up an existing scan in urlscan.io's public index.

        We never submit a new scan; we only query whether the public archive
        already saw this URL. The query parameter is URL-encoded to prevent
        a hostile URL from injecting extra urlscan-DSL operators into our
        request.
        """
        try:
            q = quote(f"page.url:{url}", safe="")
            resp = await self._http.get(
                f"{self.BASE}/search/?q={q}",
                headers=(
                    {"API-Key": config.URLSCAN_API_KEY}
                    if config.URLSCAN_API_KEY
                    else {}
                ),
            )
            if resp.status_code != 200:
                log.warning(
                    "urlscan_lookup_non_200",
                    status=resp.status_code,
                )
                return {"found": False}
            results = resp.json().get("results", [])
            if not results:
                return {"found": False}
            top = results[0]
            return {
                "found": True,
                "verdict": top.get("verdicts", {}).get("overall", {}).get("malicious", False),
            }
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            log.warning(
                "urlscan_request_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return {"found": False, "error": "urlscan_request_failed"}
