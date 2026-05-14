from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

KNOWN_BRANDS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "dropbox": ["dropbox.com"],
    "bank": [],  # generic
}
FREEMAIL = {
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "hotmail.com",
    "icloud.com",
    "proton.me",
}


def _edit_distance(a: str, b: str) -> int:
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(s: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "5": "s", "$": "s"})
    return s.translate(table)


def _is_subdomain_of_brand(from_domain: str, legit_domains: list[str]) -> bool:
    """V2.S10 fix A: a legitimate brand subdomain (e.g. accounts.google.com,
    mail.dropbox.com) is NOT a lookalike. Match if from_domain equals or is a
    subdomain of any legit_domain."""
    return any(
        from_domain == legit or from_domain.endswith("." + legit)
        for legit in legit_domains
    )


class SenderDetector(Detector):
    name = "sender"

    async def run(self, email: Email) -> list[Evidence]:
        out: list[Evidence] = []
        from_domain = email.from_.address.split("@", 1)[-1].lower()
        normalized_domain = _normalize_homoglyphs(from_domain)
        display = email.from_.display_name.lower()

        for brand, legit_domains in KNOWN_BRANDS.items():
            if (
                brand in normalized_domain
                and from_domain not in legit_domains
                # V2.S10 fix A: legitimate subdomains of brand domains are NOT lookalikes.
                and not _is_subdomain_of_brand(from_domain, legit_domains)
            ):
                for legit in legit_domains:
                    if _edit_distance(from_domain, legit) <= 5:
                        out.append(
                            Evidence(
                                signal=Signal.LOOKALIKE_DOMAIN,
                                severity=Severity.HIGH,
                                confidence=0.9,
                                explanation=f"Sender domain {from_domain} resembles legitimate brand domain {legit}.",
                                mitre_techniques=["T1566"],
                                details={
                                    "claimed_brand": brand,
                                    "compared_against": legit,
                                    "edit_distance": _edit_distance(from_domain, legit),
                                },
                                detector=self.name,
                            )
                        )
                        break
                else:
                    out.append(
                        Evidence(
                            signal=Signal.LOOKALIKE_DOMAIN,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            explanation=f"Sender domain {from_domain} contains brand keyword '{brand}' but isn't an authorized domain.",
                            mitre_techniques=["T1566"],
                            details={"claimed_brand": brand},
                            detector=self.name,
                        )
                    )
                break

        # display name claims a brand but domain is freemail
        if from_domain in FREEMAIL:
            for brand in KNOWN_BRANDS:
                if brand in display and brand not in from_domain:
                    out.append(
                        Evidence(
                            signal=Signal.FREEMAIL_IMPERSONATING_BRAND,
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            explanation=f"Display name claims '{brand}' but sender is a free-email address ({from_domain}).",
                            mitre_techniques=["T1656"],
                            details={
                                "display_name": display,
                                "from_domain": from_domain,
                                "brand": brand,
                            },
                            detector=self.name,
                        )
                    )
                    break

        # display-name domain mismatch (display claims a brand whose legit
        # domain is NOT the sender's domain). Co-occurs with the freemail
        # signal above when applicable; the two are distinct evidence at
        # different specificity levels.
        # V2.S10 fix A: a legitimate subdomain of the claimed brand is NOT
        # a mismatch (e.g. "Google Security" from accounts.google.com).
        for brand, legit_domains in KNOWN_BRANDS.items():
            if (
                brand in display
                and from_domain not in legit_domains
                and not _is_subdomain_of_brand(from_domain, legit_domains)
            ):
                out.append(
                    Evidence(
                        signal=Signal.DISPLAY_NAME_DOMAIN_MISMATCH,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        explanation=f"Display name mentions '{brand}' but sender domain is unrelated ({from_domain}).",
                        mitre_techniques=["T1656"],
                        details={"display_name": display, "from_domain": from_domain},
                        detector=self.name,
                    )
                )
                break

        return out
