from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import structlog

from backend.api.score import router as score_router
from backend.illustration.wave import dot_path, illustration_path
from backend.models.verdict import VerdictLabel

structlog.configure(processors=[structlog.processors.JSONRenderer()])
log = structlog.get_logger()

app = FastAPI(title="Swellscan", version="0.1.0")
app.include_router(score_router)

_CACHE_HEADERS = {"Cache-Control": "public, max-age=3600"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/illustration/{label}", response_class=FileResponse)
def illustration(label: VerdictLabel, score: int = 0):
    """Serve the static hero PNG for a given verdict label.

    The `score` query parameter is accepted for backwards URL compatibility
    with the prior SVG-generator implementation but is now unused - the score
    is shown in the card body rather than baked into the illustration.
    """
    path = illustration_path(label)
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="Illustration not found")
    return FileResponse(path, media_type="image/png", headers=_CACHE_HEADERS)


@app.get("/dot/{severity}", response_class=FileResponse)
def dot(severity: str):
    """Serve the small severity-dot PNG used as a DecoratedText icon in the
    findings rows of the Add-on card."""
    path = dot_path(severity)
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="Unknown severity")
    return FileResponse(path, media_type="image/png", headers=_CACHE_HEADERS)
