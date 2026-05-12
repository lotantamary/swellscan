import asyncio
import re
from urllib.parse import urlparse

from backend.clients.safebrowsing import SafeBrowsingClient
from backend.clients.urlscan import UrlscanClient
from backend.clients.virustotal import VirusTotalClient
from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}
IP_HOST_RE = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.I)


class UrlsDetector(Detector):
    name = "urls"

    def __init__(
        self,
        vt: VirusTotalClient | None = None,
        sb: SafeBrowsingClient | None = None,
        us: UrlscanClient | None = None,
    ):
        self._vt = vt or VirusTotalClient()
        self._sb = sb or SafeBrowsingClient()
        # urlscan client is wired but unused in v1 — reserved for the
        # behavioral-evidence stretch in Task 33 (final redirect chain,
        # screenshot reference). Keeping the slot avoids a constructor
        # change later when we plug it in.
        self._us = us or UrlscanClient()

    async def run(self, email: Email) -> list[Evidence]:
        urls = list(dict.fromkeys(email.urls_in_body))  # dedup, preserve order
        if not urls:
            return []
        out: list[Evidence] = []

        # static URL inspection
        for url in urls:
            host = urlparse(url).hostname or ""
            if IP_HOST_RE.match(url):
                out.append(
                    Evidence(
                        signal=Signal.URL_USES_IP_NOT_DOMAIN,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        explanation=f"URL uses raw IP address instead of a domain: {url}",
                        mitre_techniques=["T1566.002"],
                        details={"url": url},
                        detector=self.name,
                    )
                )
            if host in SHORTENERS:
                out.append(
                    Evidence(
                        signal=Signal.URL_SHORTENER,
                        severity=Severity.LOW,
                        confidence=0.7,
                        explanation=f"URL uses a known shortener ({host}) — destination is hidden.",
                        mitre_techniques=["T1566.002"],
                        details={"url": url},
                        detector=self.name,
                    )
                )

        # reputation lookups in parallel
        vt_results, sb_flagged = await asyncio.gather(
            asyncio.gather(*(self._vt.url_reputation(u) for u in urls)),
            self._sb.lookup(urls),
        )

        for url, vt in zip(urls, vt_results):
            if vt.get("found") and vt.get("malicious", 0) >= 1:
                positives, total = vt["malicious"], vt.get("total", 0)
                confidence = min(0.99, 0.5 + positives / max(total, 1))
                out.append(
                    Evidence(
                        signal=Signal.URL_KNOWN_MALICIOUS,
                        severity=Severity.CRITICAL,
                        confidence=confidence,
                        explanation=f"URL flagged as malicious by {positives}/{total} engines on VirusTotal.",
                        mitre_techniques=["T1566.002"],
                        details={
                            "url": url,
                            "vt_positives": positives,
                            "vt_total": total,
                        },
                        detector=self.name,
                    )
                )

        for url in urls:
            if url in sb_flagged:
                out.append(
                    Evidence(
                        signal=Signal.URL_KNOWN_PHISHING,
                        severity=Severity.CRITICAL,
                        confidence=0.99,
                        explanation=f"URL flagged by Google Safe Browsing: {url}",
                        mitre_techniques=["T1566.002"],
                        details={"url": url},
                        detector=self.name,
                    )
                )

        return out
