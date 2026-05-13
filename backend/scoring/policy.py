"""Scoring weights, thresholds, and (V2.S7) correlation bonuses.

All scoring policy lives here - tunable in one place.
"""
from backend.models.evidence import Severity, Signal

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 10,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

LLM_INVOCATION_THRESHOLD: int = 25
MALICIOUS_THRESHOLD: int = 60
MAX_SCORE: int = 100

# V2.S7: hand-curated correlation rules. Each rule fires when ALL signals in
# the set are present in the evidence. Bonuses stack across rules.
# apply_correlation_bonuses() caps the total at MAX_SCORE.
CORRELATION_BONUSES: list[dict] = [
    {
        "signals": {
            Signal.LOOKALIKE_DOMAIN,
            Signal.URL_KNOWN_MALICIOUS,
            Signal.SPF_FAIL,
        },
        "bonus": 15,
        "rationale": (
            "Credential-harvesting trio: lookalike-domain + malicious URL + "
            "SPF fail is the textbook fingerprint of a phishing campaign."
        ),
    },
    {
        "signals": {
            Signal.PROMPT_INJECTION_ATTEMPT,
            Signal.URL_KNOWN_MALICIOUS,
        },
        "bonus": 20,
        "rationale": (
            "AI-targeted attack: an attacker sophisticated enough to ship a "
            "payload AND target AI scanners is high-confidence malicious."
        ),
    },
    {
        "signals": {
            Signal.FIRST_SEEN_SENDER,
            Signal.SENDER_DOMAIN_DRIFT,
            Signal.LLM_HIGH_RISK_PATTERN,
        },
        "bonus": 15,
        "rationale": (
            "Impersonation: cold sender + signing-domain change + "
            "LLM-flagged content = high-probability impersonation."
        ),
    },
    {
        "signals": {
            Signal.SENDER_IP_GEOGRAPHY_CHANGE,
            Signal.PAYMENT_INSTRUCTION_URGENCY,
        },
        "bonus": 20,
        "rationale": (
            "Thread-hijack signature: a known sender's infrastructure shifts "
            "AND they suddenly request urgent payment changes - the dominant "
            "2025-2026 BEC variant. Full thread-context detection is Future "
            "Work; this rule catches the cheap-version signature."
        ),
    },
]
