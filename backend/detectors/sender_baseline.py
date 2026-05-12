from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence


class SenderBaselineDetector(Detector):
    """Stub — filled in in Task 17."""

    name = "sender_baseline"

    async def run(self, email: Email) -> list[Evidence]:
        return []
