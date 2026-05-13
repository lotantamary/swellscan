import asyncio
import re

from backend.clients.virustotal import VirusTotalClient
from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

RISKY_EXTENSIONS = {
    # Executables and scripts (V1)
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
    # V2 additions (2026-05-13, research-driven):
    # SVG with embedded JS - up from 0.1% to 4.9% of phishing attachments in 2025 (KnowBe4, IBM X-Force)
    ".svg",
    # HTML smuggling - JS builds payload client-side via blob URLs, bypasses gateways
    ".html",
    ".htm",
    # Container files that bypass Mark-of-the-Web (auto-mount; MotW does not propagate to inner files)
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
}
# Inner extensions that legitimately appear in compound names (".pdf.exe" etc.)
# - used as the "first half" trigger for the double-extension check.
COMMON_DECOY_EXTENSIONS = {".pdf", ".doc", ".xls", ".jpg", ".png"}

# V2.S4: archive extensions whose contents can't be hashed in the clear when
# password-protected. Correlation with a body password-token is the signal.
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}

# Body-language pattern for password sharing. The `[:=]?` is optional so we
# also catch "Password is xyz" and "Pwd 1234"; accepted false-positive risk
# is bounded by the requirement that an archive attachment ALSO be present.
_BODY_PASSWORD_RE = re.compile(
    r"\b(?:password|passcode|pwd)\s*[:=]?\s*\S{4,40}",
    flags=re.I,
)


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
                        explanation=f"Attachment {att.filename} uses a double extension - common disguise technique.",
                        mitre_techniques=["T1566.001"],
                        details={"filename": att.filename},
                        detector=self.name,
                    )
                )

        # V2.S4: password-archive correlation. Either signal alone is benign;
        # together they're a known evasion pattern for hash-based scanning -
        # the body password is unknown to the scanner so it cannot decrypt
        # and hash the archive contents.
        body_concat = (email.body.text or "") + " " + (email.body.html or "")
        if _BODY_PASSWORD_RE.search(body_concat):
            for att in email.attachments:
                att_name = att.filename.lower()
                att_ext = (
                    "." + att_name.rsplit(".", 1)[-1] if "." in att_name else ""
                )
                if att_ext in ARCHIVE_EXTENSIONS:
                    out.append(
                        Evidence(
                            signal=Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            explanation=(
                                f"Attachment {att.filename} is an archive and "
                                f"the body contains a password-style token. "
                                f"This pattern is commonly used to evade "
                                f"hash-based attachment scanners."
                            ),
                            mitre_techniques=["T1566.001", "T1027.013"],
                            details={
                                "filename": att.filename,
                                "extension": att_ext,
                            },
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
