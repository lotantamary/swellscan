"""V2.S7: correlation-engine tests.

Note on test severities: real detectors emit these signals at HIGH or CRITICAL.
We deliberately use lower severities here so raw_score + bonus stays below
MAX_SCORE (100); otherwise the cap would swallow the bonus and obscure
whether the correlation rule actually fired.
"""
import pytest

from backend.models.evidence import Evidence, Severity, Signal
from backend.scoring.aggregator import apply_correlation_bonuses, compute_raw_score


def _ev(signal: Signal, sev: Severity = Severity.HIGH, conf: float = 1.0) -> Evidence:
    return Evidence(
        signal=signal,
        severity=sev,
        confidence=conf,
        explanation="test",
        mitre_techniques=[],
        details={},
        detector="test",
    )


def test_v2_correlation_credential_harvesting_trio():
    """LOOKALIKE + URL_KNOWN_MALICIOUS + SPF_FAIL = credential-harvesting bonus +15."""
    evidence = [
        _ev(Signal.LOOKALIKE_DOMAIN),
        _ev(Signal.URL_KNOWN_MALICIOUS),
        _ev(Signal.SPF_FAIL),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 15


def test_v2_correlation_credential_harvesting_trio_safebrowsing_variant():
    """LOOKALIKE + URL_KNOWN_PHISHING + SPF_FAIL = same credential-harvesting bonus +15.

    Task 30.5 fix: the original rule only matched URL_KNOWN_MALICIOUS (VT).
    Safe Browsing flags fire URL_KNOWN_PHISHING instead. The rule's semantic
    is 'URL flagged by reputation service' which both signals satisfy.
    """
    evidence = [
        _ev(Signal.LOOKALIKE_DOMAIN),
        _ev(Signal.URL_KNOWN_PHISHING),
        _ev(Signal.SPF_FAIL),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 15


def test_v2_correlation_ai_targeted():
    """PROMPT_INJECTION + URL_KNOWN_MALICIOUS = AI-targeted bonus +20."""
    evidence = [
        _ev(Signal.PROMPT_INJECTION_ATTEMPT),
        _ev(Signal.URL_KNOWN_MALICIOUS),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 20


def test_v2_correlation_ai_targeted_safebrowsing_variant():
    """PROMPT_INJECTION + URL_KNOWN_PHISHING = same AI-targeted bonus +20.

    Task 30.5 fix: parallel to the trio variant. Either reputation service's
    hostile-URL signal paired with a prompt-injection attempt fires the rule.
    """
    evidence = [
        _ev(Signal.PROMPT_INJECTION_ATTEMPT),
        _ev(Signal.URL_KNOWN_PHISHING),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 20


def test_v2_correlation_impersonation():
    """FIRST_SEEN + SENDER_DOMAIN_DRIFT + LLM_HIGH_RISK = impersonation bonus +15."""
    evidence = [
        _ev(Signal.FIRST_SEEN_SENDER, Severity.LOW),
        _ev(Signal.SENDER_DOMAIN_DRIFT, Severity.MEDIUM),
        _ev(Signal.LLM_HIGH_RISK_PATTERN, Severity.HIGH),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 15


def test_v2_correlation_thread_hijack():
    """SENDER_IP_GEOGRAPHY_CHANGE + PAYMENT_INSTRUCTION_URGENCY = thread-hijack bonus +20."""
    evidence = [
        _ev(Signal.SENDER_IP_GEOGRAPHY_CHANGE, Severity.MEDIUM),
        _ev(Signal.PAYMENT_INSTRUCTION_URGENCY),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw + 20


def test_v2_correlation_no_match_no_bonus():
    """A single signal from any rule = no bonus (subset rule needs ALL signals)."""
    evidence = [_ev(Signal.LOOKALIKE_DOMAIN)]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted == raw


def test_v2_correlation_multiple_rules_fire_and_stack():
    """Two correlation rules both match -> bonuses stack."""
    # All at LOW severity so raw + 35 bonus stays under MAX_SCORE
    evidence = [
        _ev(Signal.LOOKALIKE_DOMAIN, Severity.LOW),
        _ev(Signal.URL_KNOWN_MALICIOUS, Severity.LOW),
        _ev(Signal.SPF_FAIL, Severity.LOW),
        _ev(Signal.PROMPT_INJECTION_ATTEMPT, Severity.LOW),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    # Rule 1 (credential trio) fires: +15. Rule 2 (AI-targeted) fires: +20.
    assert adjusted == raw + 35


def test_v2_correlation_caps_at_max_score():
    """Bonus does not push score above MAX_SCORE."""
    evidence = [
        _ev(Signal.LOOKALIKE_DOMAIN, Severity.CRITICAL),
        _ev(Signal.URL_KNOWN_MALICIOUS, Severity.CRITICAL),
        _ev(Signal.SPF_FAIL, Severity.CRITICAL),
    ]
    raw = compute_raw_score(evidence)
    adjusted = apply_correlation_bonuses(evidence, raw)
    assert adjusted <= 100
