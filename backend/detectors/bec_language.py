"""V2.S6: BEC-language detector.

Detects the most common 2025 BEC payload language: urgency words near
payment-instruction language. Cheap version of thread-hijack defense
(research finding #16 cheap version) - catches the language pattern
regardless of whether we have multi-message thread context.
"""
import re

from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

_URGENCY_PATTERNS = [
    r"\burgent(?:ly)?\b",
    r"\bas soon as possible\b",
    r"\basap\b",
    r"\bimmediately\b",
    r"\btoday\b",
    r"\bby end of day\b",
    r"\beod\b",
    r"\bright away\b",
]
_URGENCY_RE = re.compile("|".join(_URGENCY_PATTERNS), flags=re.I)

_PAYMENT_PATTERNS = [
    r"\bwire transfer\b",
    r"\bwire\s+(?:funds|payment|the money)\b",
    r"\biban\b",
    r"\bswift\s+(?:code|number)\b",
    r"\baccount\s+(?:number|details)\b",
    r"\bbanking\s+(?:details|information)\b",
    r"\bnew\s+(?:bank|account|iban|swift)\b",
    r"\bchange\s+of\s+(?:bank|banking|payment|account)\b",
    r"\bupdated?\s+payment\s+instruction",
    r"\bpayment\s+instruction",
]
_PAYMENT_RE = re.compile("|".join(_PAYMENT_PATTERNS), flags=re.I)

# Max char distance between an urgency hit and a payment hit to count as
# correlated. ~100 chars is roughly one sentence.
_PROXIMITY_CHARS = 100

# Standalone phrase that fires on its own (no urgency word needed).
# Matches "change of banking detail(s)", "change of payment detail(s)", etc.
_CHANGE_BANKING_RE = re.compile(
    r"\bchange\s+of\s+(?:bank|banking|payment|account)\s+detail",
    flags=re.I,
)


class BecLanguageDetector(Detector):
    name = "bec_language"

    async def run(self, email: Email) -> list[Evidence]:
        body = (email.body.text or "") + " " + (email.body.html or "")
        if not body.strip():
            return []

        # Path 1: standalone high-signal phrase fires by itself
        if _CHANGE_BANKING_RE.search(body):
            return [self._evidence()]

        # Path 2: urgency + payment-instruction within proximity
        urgency_hits = [m.start() for m in _URGENCY_RE.finditer(body)]
        payment_hits = [m.start() for m in _PAYMENT_RE.finditer(body)]
        if not urgency_hits or not payment_hits:
            return []
        for u in urgency_hits:
            for p in payment_hits:
                if abs(u - p) <= _PROXIMITY_CHARS:
                    return [self._evidence()]
        return []

    def _evidence(self) -> Evidence:
        return Evidence(
            signal=Signal.PAYMENT_INSTRUCTION_URGENCY,
            severity=Severity.HIGH,
            confidence=0.85,
            explanation=(
                "Body combines urgency language with payment or "
                "banking-detail changes - a known BEC pattern, especially "
                "in thread-hijack and vendor-impersonation attacks."
            ),
            mitre_techniques=["T1566", "T1656"],
            details={},
            detector=self.name,
        )
