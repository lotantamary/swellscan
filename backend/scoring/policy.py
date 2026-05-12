"""Scoring weights, thresholds, and (stretch) correlation bonuses.

All scoring policy lives here — tunable in one place.
"""
from backend.models.evidence import Severity

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

# Stretch (filled in Task 38 if time permits): correlation bonuses.
# Each rule: a set of signals that must all be present, plus the bonus to add.
CORRELATION_BONUSES: list[dict] = []
