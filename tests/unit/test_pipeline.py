"""V2.S8: unit tests for Pipeline._summarize body-building logic.

Three branches:
  1. LLM-written summary_body present in evidence details
  2. SAFE template when all evidence is INFO/LOW
  3. Fallback to top evidence explanation
"""

from backend.models.evidence import Evidence, Severity, Signal
from backend.models.verdict import VerdictLabel
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


def test_v2_safe_variant_known_sender_with_auth():
    """V2.S12 Variant 1: auth-pass + known sender + no drift = 'matches the pattern'."""
    evidence = [
        _ev(Signal.SPF_PASS, Severity.INFO, "SPF passed."),
        _ev(Signal.DKIM_VALID, Severity.INFO, "DKIM signature valid."),
    ]
    assert (
        Pipeline._summarize(evidence, VerdictLabel.SAFE)
        == "This sender matches the pattern you've seen from them before."
    )


def test_v2_safe_variant_new_sender_with_auth():
    """V2.S12 Variant 2: auth-pass + FIRST_SEEN_SENDER = 'first email...identity checks out'."""
    evidence = [
        _ev(Signal.SPF_PASS, Severity.INFO, "SPF passed."),
        _ev(Signal.DKIM_VALID, Severity.INFO, "DKIM signature valid."),
        _ev(Signal.FIRST_SEEN_SENDER, Severity.LOW, "First time seeing this sender."),
    ]
    assert (
        Pipeline._summarize(evidence, VerdictLabel.SAFE)
        == "This is the first email you've received from this sender, "
        "and their identity checks out."
    )


def test_v2_safe_variant_findings_exist():
    """V2.S12 Variant 3: SAFE label + MEDIUM finding fired + no auth signals = 'minor things turned up'."""
    evidence = [
        Evidence(
            signal=Signal.ENCODED_PAYLOAD_IN_BODY,
            severity=Severity.MEDIUM,
            confidence=0.6,
            explanation="Body contains a long base64-like string.",
            mitre_techniques=["T1027"],
            details={},
            detector="prompt_injection",
        ),
    ]
    assert (
        Pipeline._summarize(evidence, VerdictLabel.SAFE)
        == "Some minor things turned up but nothing concerning."
    )


def test_v2_safe_variant_truly_clean():
    """V2.S12 Variant 4: SAFE label, no MEDIUM+ findings, no auth-pass match = 'nothing stood out'."""
    evidence = [
        _ev(Signal.SPF_PASS, Severity.INFO, "SPF passed."),
        # DKIM_VALID missing -> Variant 1 doesn't apply
    ]
    assert (
        Pipeline._summarize(evidence, VerdictLabel.SAFE)
        == "Nothing in this email stood out as suspicious."
    )


def test_v2_safe_option_b_priority_relationship_wins_over_findings():
    """V2.S12 Option B: when auth+known-sender match AND minor findings exist,
    Variant 1 (relationship) takes priority over Variant 3 (findings)."""
    evidence = [
        _ev(Signal.SPF_PASS, Severity.INFO, "SPF passed."),
        _ev(Signal.DKIM_VALID, Severity.INFO, "DKIM signature valid."),
        Evidence(
            signal=Signal.ENCODED_PAYLOAD_IN_BODY,
            severity=Severity.MEDIUM,
            confidence=0.6,
            explanation="base64-like string.",
            mitre_techniques=["T1027"],
            details={},
            detector="prompt_injection",
        ),
    ]
    assert (
        Pipeline._summarize(evidence, VerdictLabel.SAFE)
        == "This sender matches the pattern you've seen from them before."
    )


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
    summary = Pipeline._summarize(evidence, VerdictLabel.MALICIOUS)
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
    summary = Pipeline._summarize(evidence, VerdictLabel.SUSPICIOUS)
    assert summary == "Sender domain resembles brand X."


def test_v2_summarize_empty_evidence_returns_default():
    """No evidence at all (pre-V1 behavior preserved)."""
    summary = Pipeline._summarize([], VerdictLabel.SAFE)
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
    summary = Pipeline._summarize(evidence, VerdictLabel.SAFE)
    # INFO-only with no SPF/DKIM -> Variant 4 fires
    assert summary == "Nothing in this email stood out as suspicious."
