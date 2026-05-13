"""Tests for the /illustration and /dot static-asset endpoints.

The previous implementation generated SVGs in Python; the Task 25 design
pass replaced it with static PNG serving. These tests confirm the new
behavior: file present + correct media type + 1-hour cache header + 404
for unknown labels/severities.
"""
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


# /illustration/{label} ---------------------------------------------------

def test_illustration_safe_returns_png():
    response = client.get("/illustration/SAFE")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "public, max-age=3600"
    assert len(response.content) > 0


def test_illustration_suspicious_returns_png():
    response = client.get("/illustration/SUSPICIOUS")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_illustration_malicious_returns_png():
    response = client.get("/illustration/MALICIOUS")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_illustration_score_query_param_accepted_but_ignored():
    """The ?score=N param is kept for URL compatibility with the prior
    SVG-generator implementation; it must not break serving."""
    a = client.get("/illustration/SAFE?score=0")
    b = client.get("/illustration/SAFE?score=99")
    assert a.status_code == 200
    assert b.status_code == 200
    # Same file => identical bytes regardless of score
    assert a.content == b.content


def test_illustration_unknown_label_returns_404():
    """UNKNOWN is a valid VerdictLabel enum value but has no illustration
    asset - we return 404 rather than inventing a placeholder."""
    response = client.get("/illustration/UNKNOWN")
    assert response.status_code == 404


def test_illustration_invalid_label_returns_422():
    """A label not in the VerdictLabel enum should fail Pydantic validation."""
    response = client.get("/illustration/GARBAGE")
    assert response.status_code == 422


# /dot/{severity} ---------------------------------------------------------

def test_dot_high_returns_png():
    response = client.get("/dot/high")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "public, max-age=3600"
    assert len(response.content) > 0


def test_dot_medium_returns_png():
    response = client.get("/dot/medium")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_dot_low_returns_png():
    response = client.get("/dot/low")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_dot_critical_aliases_to_high():
    """`critical` and `high` share the coral dot - the card UI does not
    visually distinguish the two severity tiers."""
    high = client.get("/dot/high")
    critical = client.get("/dot/critical")
    assert high.status_code == 200
    assert critical.status_code == 200
    assert high.content == critical.content


def test_dot_unknown_severity_returns_404():
    response = client.get("/dot/garbage")
    assert response.status_code == 404


def test_dot_severity_case_insensitive():
    """Severity names from Evidence.severity may arrive uppercase or mixed
    case; the endpoint should accept any casing."""
    response = client.get("/dot/HIGH")
    assert response.status_code == 200
