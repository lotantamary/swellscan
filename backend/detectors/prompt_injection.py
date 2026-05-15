import re

from backend._security_patterns import CLOSING_TAG_MIMIC, ZERO_WIDTH
from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

INJECTION_PATTERNS = [
    # Task 31 Phase A catch: original pattern was
    # `ignore\s+(?:your\s+)?(?:previous|prior|the\s+above|all)\s+instruction`
    # which couldn't match "Ignore all previous instructions" because the
    # qualifier alternation accepted only ONE word. Now `(?:(?:your|all|the)\s+)*`
    # allows zero or more stackable qualifiers before the previous/prior/above/all
    # selector. Backwards compatible with single-qualifier phrasings.
    re.compile(
        r"ignore\s+(?:(?:your|all|the)\s+)*(?:previous|prior|the\s+above|all)\s+instruction",
        re.I,
    ),
    re.compile(r"disregard\s+(?:the\s+)?(?:above|previous)", re.I),
    re.compile(r"forget\s+(?:your|the)\s+(?:role|instructions|system)", re.I),
    re.compile(r"new\s+instructions?:", re.I),
    re.compile(r"system\s+prompt:", re.I),
    # Task 31 Phase A catch: original pattern required "as + safe/benign/0/clean"
    # directly, missing real attack phrasings like "as verdict=benign" or
    # "as verdict: benign". Optional `verdict[=:]` prefix added before the
    # outcome word.
    re.compile(
        r"(?:mark|rate|classify|score)\s+this\s+(?:email\s+)?as\s+(?:verdict\s*[=:]\s*)?(?:safe|benign|0|clean)",
        re.I,
    ),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\b", re.I),
    re.compile(r"\b(?:act|pretend)\s+as\s+(?:a|an)", re.I),
]
BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# Strip http(s):// URLs AND data: URIs from the body before checking for
# base64-like blobs. Marketing tracking URLs and inline base64-encoded
# images legitimately contain long base64-shaped strings; neither is an
# "encoded payload in body text" in the threat-model sense. URLs are the
# URL detector's responsibility; inline images are normal HTML.
# Without this, every marketing email with a tracking pixel or embedded
# logo image fires a false ENCODED_PAYLOAD_IN_BODY finding.
_URLS_AND_DATA_URIS = re.compile(r"(?:https?://|data:)\S+", re.I)

# V2.S5: payload-fragmentation detection. Pattern: 5+ short (1-3 char) quoted
# tokens close together (the splits), AND an assembly verb anywhere in body
# (the reassembly hint). Both required to limit false positives - legitimate
# enumeration like "choose 'a', 'b', or 'c'" has neither 5 tokens NOR an
# assembly verb.
_FRAG_QUOTED_TOKENS = re.compile(r"(?:['\"][\w./:@-]{1,3}['\"][\s,]*){5,}")
_FRAG_ASSEMBLY_VERB = re.compile(
    r"\b(?:joined|combined|concatenated|assemble|reassemble|reconstruct)\b",
    flags=re.I,
)


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    async def run(self, email: Email) -> list[Evidence]:
        out: list[Evidence] = []
        body = email.body.text + "\n" + email.body.html

        matched_patterns: list[str] = []
        matched_excerpts: list[str] = []
        for pat in INJECTION_PATTERNS:
            m = pat.search(body)
            if m:
                matched_patterns.append(pat.pattern)
                matched_excerpts.append(m.group(0)[:120])
        if matched_patterns:
            out.append(
                Evidence(
                    signal=Signal.PROMPT_INJECTION_ATTEMPT,
                    severity=Severity.HIGH,
                    confidence=0.92,
                    explanation="Body contains text attempting to manipulate AI-based scanners.",
                    mitre_techniques=["T1566"],
                    details={
                        "matched_patterns": matched_patterns,
                        "matched_excerpts": matched_excerpts,
                    },
                    detector=self.name,
                )
            )

        tag_match = CLOSING_TAG_MIMIC.search(body)
        if tag_match:
            out.append(
                Evidence(
                    signal=Signal.TAG_ESCAPING_ATTEMPT,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    explanation="Body contains a closing delimiter sequence consistent with a prompt-sandbox escape attempt.",
                    mitre_techniques=["T1566"],
                    details={"matched": tag_match.group(0)},
                    detector=self.name,
                )
            )

        if ZERO_WIDTH.search(body):
            out.append(
                Evidence(
                    signal=Signal.SUSPICIOUS_UNICODE_IN_BODY,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    explanation="Body contains zero-width or invisible Unicode characters - common in evasion attempts.",
                    mitre_techniques=["T1027"],
                    details={},
                    detector=self.name,
                )
            )

        # Scope the base64 check to body text outside URLs and inline
        # data: images. Without this, marketing emails with tracking
        # pixels or embedded logo images fire a false-positive.
        body_for_payload_check = _URLS_AND_DATA_URIS.sub("", body)
        if BASE64_BLOB_PATTERN.search(body_for_payload_check):
            out.append(
                Evidence(
                    signal=Signal.ENCODED_PAYLOAD_IN_BODY,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    explanation="Body contains a long base64-like string - may be an encoded payload.",
                    mitre_techniques=["T1027"],
                    details={},
                    detector=self.name,
                )
            )

        if _FRAG_QUOTED_TOKENS.search(body) and _FRAG_ASSEMBLY_VERB.search(body):
            out.append(
                Evidence(
                    signal=Signal.PAYLOAD_FRAGMENTATION_ATTEMPT,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    explanation=(
                        "Body contains short tokens followed by assembly "
                        "instructions - pattern used to evade LLM safety "
                        "filters by splitting payloads."
                    ),
                    mitre_techniques=["T1027"],
                    details={},
                    detector=self.name,
                )
            )

        return out
