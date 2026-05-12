import asyncio

from backend.clients.virustotal import VirusTotalClient
from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".com",
    ".ps1",
    ".docm",
    ".xlsm",
    ".pptm",
    ".jar",
    ".msi",
    ".hta",
    ".lnk",
}
# Inner extensions that legitimately appear in compound names (".pdf.exe" etc.)
# — used as the "first half" trigger for the double-extension check.
COMMON_DECOY_EXTENSIONS = {".pdf", ".doc", ".xls", ".jpg", ".png"}


class AttachmentsDetector(Detector):
    name = "attachments"

    def __init__(self, vt: VirusTotalClient | None = None):
        self._vt = vt or VirusTotalClient()

    async def run(self, email: Email) -> list[Evidence]:
        if not email.attachments:
            return []
        out: list[Evidence] = []

        for att in email.attachments:
            name = att.filename.lower()
            parts = name.split(".")
            ext = "." + parts[-1] if len(parts) > 1 else ""

            if ext in RISKY_EXTENSIONS:
                out.append(
                    Evidence(
                        signal=Signal.ATTACHMENT_RISKY_EXTENSION,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        explanation=f"Attachment {att.filename} has risky extension {ext}.",
                        mitre_techniques=["T1566.001"],
                        details={"filename": att.filename, "extension": ext},
                        detector=self.name,
                    )
                )
            if (
                len(parts) >= 3
                and "." + parts[-2] in COMMON_DECOY_EXTENSIONS
                and ext in RISKY_EXTENSIONS
            ):
                out.append(
                    Evidence(
                        signal=Signal.ATTACHMENT_DOUBLE_EXTENSION,
                        severity=Severity.HIGH,
                        confidence=1.0,
                        explanation=f"Attachment {att.filename} uses a double extension — common disguise technique.",
                        mitre_techniques=["T1566.001"],
                        details={"filename": att.filename},
                        detector=self.name,
                    )
                )

        # hash lookups in parallel
        hash_results = await asyncio.gather(
            *(self._vt.file_hash_reputation(a.sha256) for a in email.attachments)
        )
        for att, hr in zip(email.attachments, hash_results):
            if hr.get("found") and hr.get("malicious", 0) >= 1:
                out.append(
                    Evidence(
                        signal=Signal.ATTACHMENT_KNOWN_MALICIOUS_HASH,
                        severity=Severity.CRITICAL,
                        confidence=0.99,
                        explanation=f"Attachment {att.filename} matches a known-malicious file hash ({hr['malicious']}/{hr.get('total', 0)} engines).",
                        mitre_techniques=["T1566.001"],
                        details={
                            "filename": att.filename,
                            "sha256": att.sha256,
                            **hr,
                        },
                        detector=self.name,
                    )
                )

        return out
