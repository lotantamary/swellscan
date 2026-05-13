from datetime import datetime, timezone
from uuid import uuid4

from backend.models.evidence import Evidence
from backend.models.verdict import Confidence, Verdict, VerdictLabel
from backend.scoring.policy import (
    CORRELATION_BONUSES,
    LLM_INVOCATION_THRESHOLD,
    MALICIOUS_THRESHOLD,
    MAX_SCORE,
    SEVERITY_WEIGHTS,
)

# Lifeguard-voice openers prepended to the verdict summary per label. The
# Add-on's render.gs splits the summary on the first sentence boundary and
# bolds/colors that opener; the technical body follows in italic.
LIFEGUARD_OPENERS = {
    VerdictLabel.SAFE: "All clear, you can paddle.",
    VerdictLabel.SUSPICIOUS: "Something off about this set.",
    VerdictLabel.MALICIOUS: "Out of the water on this one.",
    VerdictLabel.UNKNOWN: "Status unclear right now.",
}


def compute_raw_score(evidence: list[Evidence]) -> int:
    raw = sum(SEVERITY_WEIGHTS[e.severity] * e.confidence for e in evidence)
    return min(int(round(raw)), MAX_SCORE)


def apply_correlation_bonuses(evidence: list[Evidence], raw_score: int) -> int:
    signals_present = {e.signal for e in evidence}
    bonus = 0
    for rule in CORRELATION_BONUSES:
        if rule["signals"].issubset(signals_present):
            bonus += rule["bonus"]
    return min(raw_score + bonus, MAX_SCORE)


def label_from_score(score: int) -> VerdictLabel:
    if score < LLM_INVOCATION_THRESHOLD:
        return VerdictLabel.SAFE
    if score >= MALICIOUS_THRESHOLD:
        return VerdictLabel.MALICIOUS
    return VerdictLabel.SUSPICIOUS


def confidence_from_evidence(evidence: list[Evidence]) -> Confidence:
    if not evidence:
        return Confidence.LOW
    avg_conf = sum(e.confidence for e in evidence) / len(evidence)
    if avg_conf >= 0.8:
        return Confidence.HIGH
    if avg_conf >= 0.5:
        return Confidence.MEDIUM
    return Confidence.LOW


def build_verdict(
    evidence: list[Evidence],
    detectors_run: list[str],
    latency_ms: int,
    summary: str = "",
) -> Verdict:
    raw = compute_raw_score(evidence)
    final = apply_correlation_bonuses(evidence, raw)
    label = label_from_score(final)
    confidence = confidence_from_evidence(evidence)
    mitre = sorted({m for e in evidence for m in e.mitre_techniques})

    # Prepend the lifeguard-voice opener. render.gs splits the summary on
    # the first sentence boundary so the opener gets bolded + palette-
    # colored and the technical body becomes italic underneath.
    body = summary or "Verdict computed from evidence."
    opener = LIFEGUARD_OPENERS.get(label, "")
    full_summary = f"{opener} {body}" if opener else body

    return Verdict(
        request_id=str(uuid4()),
        score=final,
        label=label,
        confidence=confidence,
        summary=full_summary,
        evidence=evidence,
        mitre_summary=mitre,
        computed_at=datetime.now(timezone.utc),
        latency_ms=latency_ms,
        detectors_run=detectors_run,
    )
