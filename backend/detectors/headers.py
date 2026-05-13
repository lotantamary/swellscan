import re

from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

SPF_PATTERN = re.compile(
    r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", re.I
)
DKIM_PATTERN = re.compile(
    r"dkim=(pass|fail|none|neutral|policy|temperror|permerror)", re.I
)
DMARC_PATTERN = re.compile(r"dmarc=(pass|fail|bestguesspass|none)", re.I)

# V2.S3a: known freemail domains. Corporate-From + freemail-Reply-To = strong
# BEC indicator. TODO (future cleanup): consolidate with FREEMAIL set in
# sender.py into a shared constants module.
FREEMAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "hotmail.com",
    "icloud.com",
    "proton.me",
    "aol.com",
    "live.com",
}


class HeadersDetector(Detector):
    name = "headers"

    async def run(self, email: Email) -> list[Evidence]:
        out: list[Evidence] = []
        auth = email.headers.authentication_results

        spf = self._match(SPF_PATTERN, auth)
        if spf == "pass":
            out.append(
                self._ev(Signal.SPF_PASS, Severity.INFO, 1.0, "SPF passed.")
            )
        elif spf == "fail":
            out.append(
                self._ev(
                    Signal.SPF_FAIL,
                    Severity.HIGH,
                    0.95,
                    "Sender domain did not pass SPF verification.",
                    mitre=["T1566.002"],
                    details={"sender_ip": email.headers.x_originating_ip},
                )
            )
        elif spf == "softfail":
            out.append(
                self._ev(
                    Signal.SPF_SOFTFAIL,
                    Severity.MEDIUM,
                    0.7,
                    "SPF soft-fail (sender authorized status unclear).",
                )
            )

        dkim = self._match(DKIM_PATTERN, auth)
        if dkim == "pass":
            out.append(
                self._ev(
                    Signal.DKIM_VALID, Severity.INFO, 1.0, "DKIM signature valid."
                )
            )
        elif dkim in (None, "none"):
            out.append(
                self._ev(
                    Signal.DKIM_MISSING,
                    Severity.MEDIUM,
                    0.7,
                    "No DKIM signature present.",
                    mitre=["T1566.002"],
                )
            )

        dmarc = self._match(DMARC_PATTERN, auth)
        if dmarc == "fail":
            out.append(
                self._ev(
                    Signal.DMARC_FAIL,
                    Severity.HIGH,
                    0.9,
                    "DMARC alignment failed.",
                    mitre=["T1566"],
                )
            )

        # V2.S3a: severity-scaled Reply-To handling. Freemail Reply-To from a
        # corporate sender is the dominant 2025 BEC pattern (Verizon DBIR,
        # Doppel, Proofpoint). Subdomain Reply-To is legitimate and no longer
        # falsely flagged (fixes a V1 over-fire).
        if email.headers.reply_to:
            from_domain = email.from_.address.split("@", 1)[-1].lower()
            reply_domain = (
                email.headers.reply_to.split("@", 1)[-1]
                .lower()
                .rstrip(">")
                .strip()
            )
            domains_differ = bool(reply_domain) and reply_domain != from_domain
            is_subdomain = bool(reply_domain) and (
                reply_domain.endswith("." + from_domain)
                or from_domain.endswith("." + reply_domain)
            )
            if domains_differ and not is_subdomain:
                if (
                    reply_domain in FREEMAIL_DOMAINS
                    and from_domain not in FREEMAIL_DOMAINS
                ):
                    severity, confidence = Severity.HIGH, 0.9
                    explanation = (
                        f"Reply-To points to a personal email account "
                        f"({reply_domain}) while sender domain is "
                        f"{from_domain} - common BEC pattern."
                    )
                else:
                    severity, confidence = Severity.MEDIUM, 0.8
                    explanation = (
                        f"Reply-To domain ({reply_domain}) does not match "
                        f"From domain ({from_domain})."
                    )
                out.append(
                    self._ev(
                        Signal.REPLY_TO_DOMAIN_MISMATCH,
                        severity,
                        confidence,
                        explanation,
                        mitre=["T1566"],
                        details={
                            "from_domain": from_domain,
                            "reply_domain": reply_domain,
                        },
                    )
                )

        if not email.headers.message_id_header:
            out.append(
                self._ev(
                    Signal.MISSING_MESSAGE_ID,
                    Severity.LOW,
                    0.6,
                    "Email is missing Message-ID header.",
                )
            )

        return out

    @staticmethod
    def _match(pattern: re.Pattern, text: str) -> str | None:
        m = pattern.search(text)
        return m.group(1).lower() if m else None

    def _ev(
        self,
        signal,
        severity,
        confidence,
        explanation,
        *,
        mitre=None,
        details=None,
    ):
        return Evidence(
            signal=signal,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            mitre_techniques=mitre or [],
            details=details or {},
            detector=self.name,
        )
