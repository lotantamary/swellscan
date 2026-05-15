import re

from backend._freemail import FREEMAIL_DOMAINS
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

# V2.S10 fix B: registrable-parent extraction. Cousin subdomains under a
# common parent (e.g. accounts.google.com vs gaia.bounces.google.com) belong
# to the same org and should not trigger Reply-To / Return-Path mismatch
# signals. Simple last-2-labels heuristic; would need the Public Suffix List
# to handle .co.uk-style multi-label TLDs precisely. The PSL gap produces
# false-negatives (missing a real mismatch) rather than false-positives, so
# acceptable for our scope.
def _registrable_parent(domain: str) -> str:
    """Return the last two DNS labels of a domain, joined with a dot."""
    if not domain:
        return ""
    parts = domain.rsplit(".", 2)
    return ".".join(parts[-2:])



# V2.S3b: Return-Path transactional-mailer allowlist. These domains legitimately
# differ from the From: domain because the sender uses a third-party mail
# service to handle bounces. Without this allowlist, the signal would
# false-fire on every Sendgrid/Mailgun/SES-routed email.
TRANSACTIONAL_MAILER_DOMAINS = {
    "sendgrid.net",
    "mailgun.org",
    "amazonses.com",
    "mandrillapp.com",
    "sparkpostmail.com",
    "sparkpostmail1.com",
    "mtasv.net",
    "rsgsv.net",
    "mailchimp.com",
    "constantcontact.com",
    "salesforceiq.com",
    "exacttarget.com",
    "marketo.com",
    "pardot.com",
    "hubspotemail.net",
    "intercom-mail.com",
    "postmarkapp.com",
    "customeriomail.com",
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
                    mitre=["T1566.002"],
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
            # V2.S10 fix B: cousin subdomains under the same registrable
            # parent (e.g. accounts.google.com / feedback.google.com) are
            # same-org and should not fire.
            same_parent = bool(reply_domain) and (
                _registrable_parent(reply_domain)
                == _registrable_parent(from_domain)
            )
            if domains_differ and not same_parent:
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

        # V2.S3b: Return-Path mismatch. Return-Path is set by the sending MTA
        # so it's harder to forge than Reply-To. Mismatch is a stronger
        # forgery signal but transactional setups commonly produce legitimate
        # mismatches - the allowlist filters those out.
        if email.headers.return_path:
            rp_raw = (
                email.headers.return_path.strip().lstrip("<").rstrip(">").strip()
            )
            rp_domain = (
                rp_raw.split("@", 1)[-1].lower() if "@" in rp_raw else ""
            )
            from_domain = email.from_.address.split("@", 1)[-1].lower()
            domains_differ = bool(rp_domain) and rp_domain != from_domain
            # V2.S10 fix B: cousin subdomains under the same registrable
            # parent are same-org (e.g. accounts.google.com / gaia.bounces.google.com).
            same_parent = bool(rp_domain) and (
                _registrable_parent(rp_domain)
                == _registrable_parent(from_domain)
            )
            is_transactional = rp_domain in TRANSACTIONAL_MAILER_DOMAINS
            if domains_differ and not same_parent and not is_transactional:
                if (
                    rp_domain in FREEMAIL_DOMAINS
                    and from_domain not in FREEMAIL_DOMAINS
                ):
                    severity, confidence = Severity.HIGH, 0.9
                    explanation = (
                        f"Return-Path points to a personal email account "
                        f"({rp_domain}) while sender domain is {from_domain} "
                        f"- bounce-routing this way is rare in legitimate "
                        f"corporate email."
                    )
                else:
                    severity, confidence = Severity.MEDIUM, 0.75
                    explanation = (
                        f"Return-Path domain ({rp_domain}) does not match "
                        f"From domain ({from_domain}) and is not a known "
                        f"transactional mailer."
                    )
                out.append(
                    self._ev(
                        Signal.RETURN_PATH_DOMAIN_MISMATCH,
                        severity,
                        confidence,
                        explanation,
                        mitre=["T1566"],
                        details={
                            "from_domain": from_domain,
                            "return_path_domain": rp_domain,
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
                    mitre=["T1566"],
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
