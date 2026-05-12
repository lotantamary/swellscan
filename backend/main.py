from fastapi import FastAPI
import structlog

structlog.configure(processors=[structlog.processors.JSONRenderer()])
log = structlog.get_logger()

app = FastAPI(title="Swellscan", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok"}
