from abc import ABC, abstractmethod

import structlog

from backend.models.email import Email
from backend.models.evidence import Evidence

log = structlog.get_logger()


class Detector(ABC):
    name: str

    @abstractmethod
    async def run(self, email: Email) -> list[Evidence]: ...

    async def safe_run(self, email: Email) -> list[Evidence]:
        """Wraps run() with exception isolation - never raises."""
        try:
            return await self.run(email)
        except Exception as exc:
            log.warning("detector_failed", detector=self.name, error=str(exc))
            return []
