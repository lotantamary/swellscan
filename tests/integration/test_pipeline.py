from unittest.mock import AsyncMock

import pytest

from backend.clients.safebrowsing import SafeBrowsingClient
from backend.clients.urlscan import UrlscanClient
from backend.clients.virustotal import VirusTotalClient
from backend.detectors.attachments import AttachmentsDetector
from backend.detectors.headers import HeadersDetector
from backend.detectors.llm import LLMDetector
from backend.detectors.prompt_injection import PromptInjectionDetector
from backend.detectors.sender import SenderDetector
from backend.detectors.sender_baseline import SenderBaselineDetector
from backend.detectors.urls import UrlsDetector
from backend.models.evidence import Evidence, Severity, Signal
from backend.pipeline import Pipeline
from tests.fixtures.emails import make_email


def _mocked_pipeline(*, llm_mock=None):
    vt = AsyncMock(spec=VirusTotalClient)
    vt.url_reputation.return_value = {"found": False}
    vt.file_hash_reputation.return_value = {"found": False}
    sb = AsyncMock(spec=SafeBrowsingClient)
    sb.lookup.return_value = set()
    us = AsyncMock(spec=UrlscanClient)
    us.search_existing.return_value = {"found": False}
    llm = AsyncMock(spec=LLMDetector)
    llm.name = "llm"
    llm.run_with_evidence.return_value = llm_mock if llm_mock is not None else []
    return Pipeline(
        cheap_detectors=[
            HeadersDetector(),
            SenderDetector(),
            UrlsDetector(vt=vt, sb=sb, us=us),
            AttachmentsDetector(vt=vt),
            PromptInjectionDetector(),
            SenderBaselineDetector(),
        ],
        llm_detector=llm,
    )


@pytest.mark.asyncio
async def test_clean_email_returns_safe():
    p = _mocked_pipeline()
    verdict = await p.run(
        make_email(auth_results="spf=pass; dkim=pass; dmarc=pass")
    )
    assert verdict.label == "SAFE"
    assert "llm" not in verdict.detectors_run


@pytest.mark.asyncio
async def test_phishy_email_triggers_llm():
    """Task 31 fix: detectors_run reflects detectors that CONTRIBUTED
    evidence, not just those that were called. This test feeds the mock
    LLM a non-empty result to verify the contribution path.
    """
    llm_contribution = [
        Evidence(
            signal=Signal.LLM_HIGH_RISK_PATTERN,
            severity=Severity.HIGH,
            confidence=0.85,
            explanation="LLM judged this malicious.",
            mitre_techniques=["T1566", "T1656"],
            details={"matched_patterns": ["lookalike microsoft"]},
            detector="llm",
        )
    ]
    p = _mocked_pipeline(llm_mock=llm_contribution)
    verdict = await p.run(
        make_email(
            from_address="security@microsoft-secure-login.com",
            auth_results="spf=fail; dkim=none; dmarc=fail",
        )
    )
    assert verdict.label in ("SUSPICIOUS", "MALICIOUS")
    assert "llm" in verdict.detectors_run


@pytest.mark.asyncio
async def test_llm_invoked_but_silent_failure_not_marked_consulted():
    """Task 31 fix: when LLM is invoked (raw score >= threshold) but the
    call returns no evidence (e.g. Anthropic API timed out and the client
    returned None), `detectors_run` MUST NOT include 'llm'. The card's
    'LLM consulted' meta-line is derived from detectors_run; showing it
    when the LLM silently failed misleads the user about whether the
    LLM contributed to the verdict.

    Caught when scanning demo 2 in Task 31 Phase A - card showed
    'LLM consulted' but Anthropic dashboard showed zero balance
    consumed because every call was timing out at the old 5-second limit.
    """
    p = _mocked_pipeline()  # llm_mock defaults to [] in helper
    verdict = await p.run(
        make_email(
            from_address="security@microsoft-secure-login.com",
            auth_results="spf=fail; dkim=none; dmarc=fail",
        )
    )
    assert verdict.label in ("SUSPICIOUS", "MALICIOUS")
    # LLM was invoked (raw score crossed the threshold) but contributed
    # no evidence, so it must not appear in detectors_run.
    assert "llm" not in verdict.detectors_run
