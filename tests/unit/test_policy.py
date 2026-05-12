from backend.models.evidence import Severity
from backend.scoring.policy import (
    LLM_INVOCATION_THRESHOLD,
    MALICIOUS_THRESHOLD,
    SEVERITY_WEIGHTS,
)


def test_severity_weights_monotonic():
    weights = [
        SEVERITY_WEIGHTS[s]
        for s in (
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        )
    ]
    assert weights == sorted(weights)


def test_thresholds():
    assert LLM_INVOCATION_THRESHOLD == 25
    assert MALICIOUS_THRESHOLD == 60
