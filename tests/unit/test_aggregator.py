from backend.models.evidence import Evidence, Severity, Signal
from backend.models.verdict import VerdictLabel
from backend.scoring.aggregator import (
    build_verdict,
    compute_raw_score,
    label_from_score,
)


def make_ev(signal: Signal, severity: Severity, conf: float = 1.0) -> Evidence:
    return Evidence(
        signal=signal,
        severity=severity,
        confidence=conf,
        explanation="test",
        mitre_techniques=[],
        details={},
        detector="test",
    )


def test_score_empty_evidence_is_zero():
    assert compute_raw_score([]) == 0


def test_score_single_critical_at_full_confidence():
    ev = make_ev(Signal.URL_KNOWN_MALICIOUS, Severity.CRITICAL, 1.0)
    assert compute_raw_score([ev]) == 40


def test_score_caps_at_100():
    evs = [make_ev(Signal.URL_KNOWN_MALICIOUS, Severity.CRITICAL, 1.0)] * 5
    assert compute_raw_score(evs) == 100


def test_label_safe_below_25():
    assert label_from_score(20) == VerdictLabel.SAFE


def test_label_suspicious_25_to_59():
    assert label_from_score(40) == VerdictLabel.SUSPICIOUS


def test_label_malicious_above_60():
    assert label_from_score(70) == VerdictLabel.MALICIOUS


def test_build_verdict_includes_detectors_run():
    v = build_verdict(evidence=[], detectors_run=["headers"], latency_ms=100)
    assert v.detectors_run == ["headers"]
    assert v.score == 0
    assert v.label == VerdictLabel.SAFE
