from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from backend.models.evidence import Evidence


class VerdictLabel(StrEnum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(BaseModel):
    request_id: str
    score: int = Field(ge=0, le=100)
    label: VerdictLabel
    confidence: Confidence
    summary: str = Field(max_length=600)
    evidence: list[Evidence]
    mitre_summary: list[str] = Field(default_factory=list)
    computed_at: datetime
    latency_ms: int = Field(ge=0)
    detectors_run: list[str]
    illustration_url: str = Field(default="")
