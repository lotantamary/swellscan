import asyncio
import re
from urllib.parse import urlparse

from backend.clients.safebrowsing import SafeBrowsingClient
from backend.clients.urlscan import UrlscanClient
from backend.clients.virustotal import VirusTotalClient
from backend.config import config
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
        # urlscan = third URL-reputation source, gated by URLSCAN_ENABLED.
        # Fills the gap where VirusTotal and Safe Browsing haven't yet
        # indexed a fresh phishing domain but urlscan's public archive
        # captured the page's actual rendered behavior. Conservative
        # weighting (MEDIUM/0.7) + emission only when neither VT nor SB
        # already flagged the URL prevents double-counting and bounds the
        # impact on borderline SUSPICIOUS verdicts.
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
                        explanation=f"URL uses a known shortener ({host}) - destination is hidden.",
                        mitre_techniques=["T1566.002"],
                        details={"url": url},
                        detector=self.name,
                    )
                )

        # reputation lookups in parallel. urlscan is gated by env-var kill
        # switch; when off, we skip its branch entirely (no allocated work).
        if config.URLSCAN_ENABLED:
            vt_results, sb_flagged, us_results = await asyncio.gather(
                asyncio.gather(*(self._vt.url_reputation(u) for u in urls)),
                self._sb.lookup(urls),
                asyncio.gather(*(self._us.search_existing(u) for u in urls)),
            )
        else:
            vt_results, sb_flagged = await asyncio.gather(
                asyncio.gather(*(self._vt.url_reputation(u) for u in urls)),
                self._sb.lookup(urls),
            )
            us_results = [{"found": False}] * len(urls)

        vt_flagged: set[str] = set()
        for url, vt in zip(urls, vt_results):
            if vt.get("found") and vt.get("malicious", 0) >= 1:
                vt_flagged.add(url)
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

        # urlscan fires ONLY for URLs that VT and Safe Browsing missed - this
        # is the gap-coverage role. Fresh phishing domains live in this gap
        # for 4-24h between registration and blocklist coverage; urlscan's
        # behavioral archive often catches them first.
        for url, us in zip(urls, us_results):
            if (
                us.get("found")
                and us.get("verdict")
                and url not in vt_flagged
                and url not in sb_flagged
            ):
                out.append(
                    Evidence(
                        signal=Signal.URL_BEHAVIORAL_FLAGGED,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        explanation=(
                            f"URL was flagged as malicious by urlscan.io's "
                            f"behavioral analysis (no signature-database hit): {url}"
                        ),
                        mitre_techniques=["T1566.002"],
                        details={"url": url},
                        detector=self.name,
                    )
                )

        return out
