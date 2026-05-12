import asyncio
import time

import structlog

from backend.detectors.attachments import AttachmentsDetector
from backend.detectors.base import Detector
from backend.detectors.headers import HeadersDetector
from backend.detectors.llm import LLMDetector
from backend.detectors.prompt_injection import PromptInjectionDetector
from backend.detectors.sender import SenderDetector
from backend.detectors.sender_baseline import SenderBaselineDetector
from backend.detectors.urls import UrlsDetector
from backend.models.email import Email
from backend.models.evidence import Evidence
from backend.models.verdict import Verdict
from backend.scoring.aggregator import build_verdict, compute_raw_score
from backend.scoring.policy import LLM_INVOCATION_THRESHOLD

log = structlog.get_logger()

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


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

        raw = compute_raw_score(evidence)
        if raw >= LLM_INVOCATION_THRESHOLD:
            try:
                llm_ev = await self._llm.run_with_evidence(email, evidence)
                evidence.extend(llm_ev)
                detectors_run.append(self._llm.name)
            except Exception as exc:
                log.warning("llm_skipped", error=str(exc))

        latency_ms = int((time.perf_counter() - t0) * 1000)
        return build_verdict(
            evidence=evidence,
            detectors_run=detectors_run,
            latency_ms=latency_ms,
            summary=self._summarize(evidence),
        )

    @staticmethod
    def _summarize(evidence: list[Evidence]) -> str:
        if not evidence:
            return "No suspicious signals detected."
        top = sorted(
            evidence,
            key=lambda e: (-_SEVERITY_RANK[e.severity], -e.confidence),
        )[:3]
        return " ".join(e.explanation for e in top)
