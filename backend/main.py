from fastapi import FastAPI
import structlog

from backend.api.score import router as score_router

structlog.configure(processors=[structlog.processors.JSONRenderer()])
log = structlog.get_logger()

app = FastAPI(title="Swellscan", version="0.1.0")
app.include_router(score_router)


@app.get("/health")
def health():
    return {"status": "ok"}
