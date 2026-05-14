import base64

import httpx
import structlog

from backend.config import config

log = structlog.get_logger()


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"
    # Task 31 fix: was 4.0 - too aggressive for free-tier VT response
    # latency. Aligned with the other external-API client timeouts.
    TIMEOUT = 15.0

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client or httpx.AsyncClient(timeout=self.TIMEOUT)

    async def url_reputation(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            resp = await self._http.get(
                f"{self.BASE}/urls/{url_id}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                return {"found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()) if stats else 0,
                "categories": list(data.get("categories", {}).values()),
            }
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            log.warning(
                "virustotal_url_lookup_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return {"found": False, "error": "vt_request_failed"}

    async def file_hash_reputation(self, sha256: str) -> dict:
        try:
            resp = await self._http.get(
                f"{self.BASE}/files/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                return {"found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()) if stats else 0,
            }
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            log.warning(
                "virustotal_hash_lookup_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return {"found": False, "error": "vt_request_failed"}
