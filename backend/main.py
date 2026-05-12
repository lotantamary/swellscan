from fastapi import FastAPI, Response
import structlog

from backend.api.score import router as score_router
from backend.illustration.wave import render_wave_svg
from backend.models.verdict import VerdictLabel

structlog.configure(processors=[structlog.processors.JSONRenderer()])
log = structlog.get_logger()

app = FastAPI(title="Swellscan", version="0.1.0")
app.include_router(score_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/illustration/{label}", response_class=Response)
def illustration(label: VerdictLabel, score: int = 0):
    svg = render_wave_svg(label, score)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=3600"},
    )
