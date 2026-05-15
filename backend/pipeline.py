import asyncio
import time

import structlog

from backend.detectors.attachments import AttachmentsDetector
from backend.detectors.base import Detector
from backend.detectors.bec_language import BecLanguageDetector
from backend.detectors.headers import HeadersDetector
from backend.detectors.llm import LLMDetector
from backend.detectors.prompt_injection import PromptInjectionDetector
from backend.detectors.sender import SenderDetector
from backend.detectors.sender_baseline import SenderBaselineDetector
from backend.detectors.urls import UrlsDetector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal
from backend.models.verdict import Verdict, VerdictLabel
from backend.scoring.aggregator import (
    apply_correlation_bonuses,
    build_verdict,
    compute_raw_score,
    label_from_score,
)
from backend.scoring.policy import LLM_INVOCATION_THRESHOLD

log = structlog.get_logger()

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# V2.S12: SAFE-state body variants. Picked in priority order; first match wins.
# Option B: relationship-and-auth wins over "minor findings" when both match,
# because the body is the headline and the FINDINGS list shows the detail.
_BASELINE_DRIFT_SIGNALS = {
    Signal.SENDER_DOMAIN_DRIFT,
    Signal.SENDER_IP_GEOGRAPHY_CHANGE,
    Signal.SENDER_SEND_TIME_ANOMALY,
}
_RISKY_SEVERITIES = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def _safe_template(evidence: list[Evidence]) -> str:
    signals = {ev.signal for ev in evidence}
    auth_passed = Signal.SPF_PASS in signals and Signal.DKIM_VALID in signals
    new_sender = Signal.FIRST_SEEN_SENDER in signals
    baseline_drift = bool(signals & _BASELINE_DRIFT_SIGNALS)
    has_findings = any(ev.severity in _RISKY_SEVERITIES for ev in evidence)

    if auth_passed and not new_sender and not baseline_drift:
        return "This sender matches the pattern you've seen from them before."
    if auth_passed and new_sender:
        return (
            "This is the first email you've received from this sender, "
            "and their identity checks out."
        )
    if has_findings:
        return "Some minor things turned up but nothing concerning."
    return "Nothing in this email stood out as suspicious."


class Pipeline:
    def __init__(
        self,
        cheap_detectors: list[Detector] | None = None,
        llm_detector: LLMDetector | None = None,
    ):
        self._cheap = cheap_detectors or [
            HeadersDetector(),
            SenderDetector(),
            UrlsDetector(),
            AttachmentsDetector(),
            PromptInjectionDetector(),
            SenderBaselineDetector(),
            BecLanguageDetector(),  # V2.S6
        ]
        self._llm = llm_detector or LLMDetector()

    async def run(self, email: Email) -> Verdict:
        t0 = time.perf_counter()
        # parallel cheap detectors
        results = await asyncio.gather(
            *(d.safe_run(email) for d in self._cheap)
        )
        evidence: list[Evidence] = [e for sub in results for e in sub]
        detectors_run = [d.name for d in self._cheap]

        raw_pre_llm = compute_raw_score(evidence)
        if raw_pre_llm >= LLM_INVOCATION_THRESHOLD:
            try:
                llm_ev = await self._llm.run_with_evidence(email, evidence)
                # Task 31 fix: only count LLM as "consulted" when it
                # actually contributed evidence. The old code appended
                # 'llm' to detectors_run unconditionally on a successful
                # call, including when the call returned None (e.g.
                # timed out) and run_with_evidence returned []. That
                # made the card's "LLM consulted" meta-line lie: it
                # showed True even when the LLM had silently failed.
                # Diagnosed during Task 31 Phase A demo 2 scan when the
                # Anthropic dashboard showed zero balance consumed
                # despite every card claiming "LLM consulted".
                if llm_ev:
                    evidence.extend(llm_ev)
                    detectors_run.append(self._llm.name)
            except Exception as exc:
                log.warning("llm_skipped", error=str(exc))

        # Compute the official score and label ONCE per request. Threaded
        # into both _summarize and build_verdict so the two paths cannot
        # disagree on what the verdict label is.
        final_score = apply_correlation_bonuses(evidence, compute_raw_score(evidence))
        final_label = label_from_score(final_score)

        latency_ms = int((time.perf_counter() - t0) * 1000)
        return build_verdict(
            evidence=evidence,
            detectors_run=detectors_run,
            latency_ms=latency_ms,
            summary=self._summarize(evidence, final_label),
            score=final_score,
            label=final_label,
        )

    @staticmethod
    def _summarize(evidence: list[Evidence], label: VerdictLabel) -> str:
        """V2.S8 body builder, V2.S10-fix-C label check, V2.S12 SAFE variants.

        Preference order:
          1. LLM-written body if any evidence has 'llm_summary_body' in details.
          2. When the final verdict label is SAFE, pick one of four templated
             bodies based on which signals fired (variants 1-4 below).
          3. Fallback to the top evidence's explanation for SUSPICIOUS or
             MALICIOUS verdicts when the LLM didn't fire (V1 behavior).
        """
        if not evidence:
            return "No suspicious signals detected."

        for ev in evidence:
            body = ev.details.get("llm_summary_body")
            if isinstance(body, str) and body.strip():
                return body.strip()

        if label == VerdictLabel.SAFE:
            return _safe_template(evidence)

        top = sorted(
            evidence,
            key=lambda e: (-_SEVERITY_RANK[e.severity], -e.confidence),
        )[0]
        return top.explanation
