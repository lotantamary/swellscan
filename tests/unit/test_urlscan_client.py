"""Unit tests for the UrlscanClient verdict-detection logic.

The wrapper turns urlscan.io's search response into a single boolean
verdict for UrlsDetector to consume. The verdict is intentionally
permissive (any of: strict consensus, urlscan's own automated verdict,
or a phishing/malicious task tag) because the strictest field is
paid-tier and rarely set; the conservative MEDIUM/0.7 weighting + the
gap-only emission rule in UrlsDetector bound the downstream impact.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.clients.urlscan import UrlscanClient


def _mock_http(json_payload: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_payload
    http = AsyncMock()
    http.get.return_value = resp
    return http


@pytest.mark.asyncio
async def test_strict_consensus_verdict_fires():
    """The original strict path - urlscan's multi-source overall verdict."""
    http = _mock_http(
        {"results": [{"verdicts": {"overall": {"malicious": True}}, "task": {"tags": []}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/bad")
    assert result == {"found": True, "verdict": True}


@pytest.mark.asyncio
async def test_urlscan_own_verdict_fires():
    """urlscan's own automated ML verdict, even without overall consensus."""
    http = _mock_http(
        {"results": [{"verdicts": {"urlscan": {"malicious": True}}, "task": {"tags": []}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/bad")
    assert result["verdict"] is True


@pytest.mark.asyncio
async def test_phishing_tag_fires():
    """A 'phishing' tag is treated as a positive verdict signal."""
    http = _mock_http(
        {"results": [{"verdicts": {}, "task": {"tags": ["phishing", "credphish"]}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/bad")
    assert result["verdict"] is True


@pytest.mark.asyncio
async def test_malicious_tag_fires():
    """A 'malicious' tag is treated as a positive verdict signal."""
    http = _mock_http(
        {"results": [{"verdicts": {}, "task": {"tags": ["malicious"]}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/bad")
    assert result["verdict"] is True


@pytest.mark.asyncio
async def test_tag_match_is_case_insensitive():
    """Tags can come capitalized; the match should be lowercase-insensitive."""
    http = _mock_http(
        {"results": [{"verdicts": {}, "task": {"tags": ["Phishing"]}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/bad")
    assert result["verdict"] is True


@pytest.mark.asyncio
async def test_clean_scan_does_not_fire():
    """A scan with no malicious signals returns verdict=False."""
    http = _mock_http(
        {"results": [{"verdicts": {}, "task": {"tags": ["@somecontributor"]}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/clean")
    assert result == {"found": True, "verdict": False}


@pytest.mark.asyncio
async def test_no_results_returns_not_found():
    """An empty urlscan archive means we have no opinion to contribute."""
    http = _mock_http({"results": []})
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://never-scanned.example/")
    assert result == {"found": False}


@pytest.mark.asyncio
async def test_non_200_status_returns_not_found():
    """Server-side error degrades silently to 'no opinion'."""
    http = _mock_http({}, status_code=429)
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/")
    assert result == {"found": False}


@pytest.mark.asyncio
async def test_unrelated_tag_does_not_fire():
    """Tags that aren't in the malicious set should not flip the verdict."""
    http = _mock_http(
        {"results": [{"verdicts": {}, "task": {"tags": ["ad-tracking", "cdn"]}}]}
    )
    client = UrlscanClient(http_client=http)
    result = await client.search_existing("https://example.test/")
    assert result["verdict"] is False
