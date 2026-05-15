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

    # Tag-based phishing/malicious labels urlscan applies to scans.
    # Treated as a positive verdict signal at the wrapper boundary; lets us
    # benefit from urlscan's tagging even when the (paid-tier) strict
    # consensus field `verdicts.overall.malicious` is not reachable.
    _MALICIOUS_TAGS: frozenset[str] = frozenset({"phishing", "malicious"})

    async def search_existing(self, url: str) -> dict:
        """Look up an existing scan in urlscan.io's public index.

        We never submit a new scan; we only query whether the public archive
        already saw this URL. The query parameter is URL-encoded to prevent
        a hostile URL from injecting extra urlscan-DSL operators into our
        request.

        The returned `verdict` boolean is true when urlscan considers this
        URL malicious by ANY of:
          1. Strict multi-source consensus (`verdicts.overall.malicious`)
          2. urlscan's own automated verdict (`verdicts.urlscan.malicious`)
          3. The scan being tagged 'phishing' or 'malicious' by urlscan's
             automated analysis or community contributors
        The single boolean is what UrlsDetector consumes; the gap-only
        emission logic and conservative MEDIUM/0.7 scoring already bound
        the impact of a noisier-than-consensus signal.
        """
        try:
            # urlscan's query parser uses ':' as a field-selector delimiter.
            # A URL like https://x/ would be parsed as `page.url:https` plus
            # the remainder, matching nothing. Wrapping the URL in double
            # quotes makes urlscan treat the colons as part of the value.
            # Defensive: strip any literal double quotes from the URL since
            # they aren't legal in URL syntax and would otherwise terminate
            # the quoted value prematurely.
            quoted_url = f'"{url.replace(chr(34), "")}"'
            q = quote(f"page.url:{quoted_url}", safe="")
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
            verdicts = top.get("verdicts") or {}
            tags = top.get("task", {}).get("tags") or []
            is_malicious = (
                verdicts.get("overall", {}).get("malicious", False)
                or verdicts.get("urlscan", {}).get("malicious", False)
                or any(
                    isinstance(t, str) and t.lower() in self._MALICIOUS_TAGS
                    for t in tags
                )
            )
            return {
                "found": True,
                "verdict": is_malicious,
            }
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            log.warning(
                "urlscan_request_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return {"found": False, "error": "urlscan_request_failed"}
