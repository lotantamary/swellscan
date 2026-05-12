import structlog
from fastapi import APIRouter, Depends

from backend.auth import verify_request
from backend.models.email import Email
from backend.models.verdict import Verdict
from backend.pipeline import Pipeline

router = APIRouter()
log = structlog.get_logger()
_pipeline = Pipeline()


@router.post("/score", response_model=Verdict)
async def score(email: Email, user=Depends(verify_request)) -> Verdict:
    verdict = await _pipeline.run(email)
    log.info(
        "score_request_completed",
        request_id=verdict.request_id,
        sender_domain=email.from_.address.split("@", 1)[-1],
        score=verdict.score,
        verdict=verdict.label,
        detectors_run=verdict.detectors_run,
        latency_ms=verdict.latency_ms,
        llm_invoked="llm" in verdict.detectors_run,
        user=user.get("email"),
    )
    return verdict
