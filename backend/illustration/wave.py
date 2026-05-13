"""Static illustration + severity-dot asset paths.

Previously this module generated the verdict illustration as an SVG on the
fly. The Task 25 design pass (2026-05-13) replaced that approach with three
approved PNGs the product owner provided directly. This module now just
maps a verdict label or severity name to its on-disk asset path; the
FastAPI routes in `backend.main` do the actual file serving.
"""
from pathlib import Path

from backend.models.verdict import VerdictLabel

ASSETS_DIR = Path(__file__).parent / "assets"
DOTS_DIR = ASSETS_DIR / "dots"

# Only the three real verdict states have illustrations. UNKNOWN would be
# a backend bug rather than a normal verdict; we let it 404 rather than
# inventing a placeholder.
ILLUSTRATION_FILES = {
    VerdictLabel.SAFE: ASSETS_DIR / "safe.png",
    VerdictLabel.SUSPICIOUS: ASSETS_DIR / "suspicious.png",
    VerdictLabel.MALICIOUS: ASSETS_DIR / "malicious.png",
}

# severity name -> dot PNG. `critical` aliases to `high` to share a single
# coral dot; the card UI does not visually distinguish the two.
DOT_FILES = {
    "high": DOTS_DIR / "high.png",
    "critical": DOTS_DIR / "high.png",
    "medium": DOTS_DIR / "medium.png",
    "low": DOTS_DIR / "low.png",
}


def illustration_path(label: VerdictLabel) -> Path | None:
    """Return the on-disk PNG path for the given verdict label, or None if
    no illustration is available for that label."""
    return ILLUSTRATION_FILES.get(label)


def dot_path(severity: str) -> Path | None:
    """Return the on-disk PNG path for the given severity name, or None if
    the severity is unrecognised."""
    return DOT_FILES.get(severity.lower())
