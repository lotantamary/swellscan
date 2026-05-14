"""V2.S8: unit tests for Pipeline._summarize body-building logic.

Three branches:
  1. LLM-written summary_body present in evidence details
  2. SAFE template when all evidence is INFO/LOW
  3. Fallback to top evidence explanation
"""

from backend.models.evidence import Evidence, Severity, Signal
from backend.pipeline import Pipeline


def _ev(
    signal: Signal,
    severity: Severity,
    explanation: str = "test",
    details: dict | None = None,
) -> Evidence:
    return Evidence(
        signal=signal,
        severity=severity,
        confidence=1.0,
        explanation=explanation,
        mitre_techniques=[],
        details=details or {},
        detector="test",
    )


def test_v2_summarize_safe_uses_template():
    """SAFE case (all INFO/LOW) yields the templated lean sentence."""
    evidence = [
        _ev(Signal.SPF_PASS, Severity.INFO, "SPF passed."),
        _ev(Signal.DKIM_VALID, Severity.INFO, "DKIM signature valid."),
    ]
    summary = Pipeline._summarize(evidence)
    assert summary == "Authentication and sender check out, no suspicious content detected."


def test_v2_safe_template_fires_when_one_medium_signal_keeps_score_below_threshold():
    """V2.S10 fix C: SAFE label + one low-confidence MEDIUM signal still uses
    the SAFE template (not the V1 top-evidence fallback).

    Example from V2.S9 live scan: marketing email with base64-encoded tracking
    pixel fired ENCODED_PAYLOAD_IN_BODY (MEDIUM, conf 0.6 = ~6 raw) but the
    verdict was correctly SAFE.
    """
    evidence = [
        Evidence(
            signal=Signal.ENCODED_PAYLOAD_IN_BODY,
            severity=Severity.MEDIUM,
            confidence=0.6,
            explanation="Body contains a long base64-like string - may be an encoded payload.",
            mitre_techniques=["T1027"],
            details={},
            detector="prompt_injection",
        ),
    ]
    summary = Pipeline._summarize(evidence)
    assert summary == "Authentication and sender check out, no suspicious content detected."


def test_v2_summarize_uses_llm_summary_body_when_present():
    """When any evidence carries llm_summary_body in details, that wins."""
    llm_body = (
        "This email pretends to be from a well-known brand and asks you to "
        "click an unsafe link."
    )
    evidence = [
        _ev(
            Signal.LOOKALIKE_DOMAIN,
            Severity.HIGH,
            "Sender domain resembles brand X.",
        ),
        _ev(
            Signal.LLM_HIGH_RISK_PATTERN,
            Severity.HIGH,
            "LLM flagged high-risk patterns in the body.",
            details={"llm_summary_body": llm_body},
        ),
    ]
    summary = Pipeline._summarize(evidence)
    assert summary == llm_body


def test_v2_summarize_falls_back_to_top_evidence_when_no_llm_body():
    """SUSPICIOUS-class score with no LLM body falls back to top evidence's explanation."""
    evidence = [
        _ev(
            Signal.LOOKALIKE_DOMAIN,
            Severity.HIGH,
            "Sender domain resembles brand X.",
        ),
        _ev(Signal.DKIM_MISSING, Severity.MEDIUM, "No DKIM signature present."),
    ]
    summary = Pipeline._summarize(evidence)
    assert summary == "Sender domain resembles brand X."


def test_v2_summarize_empty_evidence_returns_default():
    """No evidence at all (pre-V1 behavior preserved)."""
    summary = Pipeline._summarize([])
    assert summary == "No suspicious signals detected."


def test_v2_summarize_empty_llm_body_is_ignored():
    """Empty llm_summary_body string falls through to next branch."""
    evidence = [
        _ev(
            Signal.LLM_BENIGN_JUDGMENT,
            Severity.INFO,
            "Benign per LLM.",
            details={"llm_summary_body": ""},
        ),
    ]
    summary = Pipeline._summarize(evidence)
    # INFO-only -> SAFE template applies
    assert summary == "Authentication and sender check out, no suspicious content detected."
