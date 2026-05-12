from unittest.mock import AsyncMock

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
