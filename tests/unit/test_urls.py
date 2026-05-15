from unittest.mock import AsyncMock, patch

import pytest

from backend.detectors.urls import UrlsDetector
from backend.models.evidence import Signal
from tests.fixtures.emails import make_email


@pytest.mark.asyncio
async def test_known_malicious_url_emits_critical_evidence():
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": True, "malicious": 23, "total": 76}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {"found": False}
    email = make_email(urls=["https://bad.example.com/login"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert any(e.signal == Signal.URL_KNOWN_MALICIOUS for e in evs)


@pytest.mark.asyncio
async def test_safebrowsing_flagged_url_emits_phishing_evidence():
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = {"https://phish.example.com"}
    us = AsyncMock()
    us.search_existing.return_value = {"found": False}
    email = make_email(urls=["https://phish.example.com"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert any(e.signal == Signal.URL_KNOWN_PHISHING for e in evs)


@pytest.mark.asyncio
async def test_clean_url_emits_nothing():
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {"found": False}
    email = make_email(urls=["https://example.com"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert evs == []


@pytest.mark.asyncio
async def test_urlscan_flagged_url_emits_behavioral_evidence_when_vt_sb_silent():
    """urlscan.io fills the gap when VT and SB haven't yet indexed a fresh
    phishing domain but urlscan's public archive captured its behavior."""
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {"found": True, "verdict": True}
    email = make_email(urls=["https://fresh-phish.example.com/login"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    behavioral = [e for e in evs if e.signal == Signal.URL_BEHAVIORAL_FLAGGED]
    assert len(behavioral) == 1
    assert behavioral[0].severity == "medium"
    assert behavioral[0].confidence == 0.7


@pytest.mark.asyncio
async def test_urlscan_not_emitted_when_vt_already_flagged_url():
    """No double-counting: if VirusTotal already flagged the URL, the urlscan
    confirmation should not pile on a second evidence row for the same URL."""
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": True, "malicious": 5, "total": 76}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {"found": True, "verdict": True}
    email = make_email(urls=["https://double-flagged.example.com"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert not any(e.signal == Signal.URL_BEHAVIORAL_FLAGGED for e in evs)
    assert any(e.signal == Signal.URL_KNOWN_MALICIOUS for e in evs)


@pytest.mark.asyncio
async def test_urlscan_not_emitted_when_safe_browsing_already_flagged_url():
    """Same gap-only rule applies to Safe Browsing overlap."""
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = {"https://sb-flagged.example.com"}
    us = AsyncMock()
    us.search_existing.return_value = {"found": True, "verdict": True}
    email = make_email(urls=["https://sb-flagged.example.com"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert not any(e.signal == Signal.URL_BEHAVIORAL_FLAGGED for e in evs)


@pytest.mark.asyncio
async def test_urlscan_failure_does_not_break_pipeline():
    """If urlscan returns an error envelope (timeout, non-200), no evidence
    is emitted and the pipeline keeps producing a verdict from VT + SB."""
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {
        "found": False,
        "error": "urlscan_request_failed",
    }
    email = make_email(urls=["https://example.com"])
    evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert evs == []


@pytest.mark.asyncio
async def test_urlscan_kill_switch_skips_lookups_entirely():
    """When URLSCAN_ENABLED=false, urlscan is not even called - kill switch
    for live demos in case it misbehaves."""
    vt = AsyncMock()
    vt.url_reputation.return_value = {"found": False}
    sb = AsyncMock()
    sb.lookup.return_value = set()
    us = AsyncMock()
    us.search_existing.return_value = {"found": True, "verdict": True}
    email = make_email(urls=["https://would-be-flagged.example.com"])
    with patch("backend.detectors.urls.config.URLSCAN_ENABLED", False):
        evs = await UrlsDetector(vt=vt, sb=sb, us=us).run(email)
    assert not any(e.signal == Signal.URL_BEHAVIORAL_FLAGGED for e in evs)
    us.search_existing.assert_not_called()
