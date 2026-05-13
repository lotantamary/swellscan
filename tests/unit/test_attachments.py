from unittest.mock import AsyncMock

import pytest

from backend.detectors.attachments import AttachmentsDetector
from backend.models.email import AttachmentMeta
from backend.models.evidence import Severity, Signal
from tests.fixtures.emails import make_email


def make_att(filename="x.pdf", mime="application/pdf", size=1000, sha="a" * 64):
    return AttachmentMeta(
        filename=filename, mime_type=mime, size_bytes=size, sha256=sha
    )


@pytest.mark.asyncio
async def test_double_extension_flagged():
    email = make_email(
        attachments=[
            make_att(filename="invoice.pdf.exe", mime="application/x-msdownload")
        ]
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    assert any(e.signal == Signal.ATTACHMENT_DOUBLE_EXTENSION for e in evs)


@pytest.mark.asyncio
async def test_known_malicious_hash_flagged():
    email = make_email(
        attachments=[make_att(filename="report.pdf", mime="application/pdf")]
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {
        "found": True,
        "malicious": 5,
        "total": 70,
    }
    evs = await AttachmentsDetector(vt=vt).run(email)
    assert any(e.signal == Signal.ATTACHMENT_KNOWN_MALICIOUS_HASH for e in evs)


@pytest.mark.asyncio
async def test_risky_extension_flagged():
    email = make_email(
        attachments=[
            make_att(filename="setup.scr", mime="application/octet-stream")
        ]
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    assert any(e.signal == Signal.ATTACHMENT_RISKY_EXTENSION for e in evs)


# V2.S1: 2025-trending malicious-attachment extensions (research finding #4)
@pytest.mark.parametrize(
    "ext,filename",
    [
        (".svg", "invoice.svg"),
        (".html", "verification.html"),
        (".htm", "doc.htm"),
        (".hta", "installer.hta"),
        (".iso", "delivery.iso"),
        (".img", "image.img"),
        (".vhd", "backup.vhd"),
        (".vhdx", "snapshot.vhdx"),
    ],
)
@pytest.mark.asyncio
async def test_v2_risky_extension_added(ext, filename):
    """V2.S1: each newly-added extension fires ATTACHMENT_RISKY_EXTENSION at HIGH."""
    email = make_email(attachments=[make_att(filename=filename)])
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    risky = [e for e in evs if e.signal == Signal.ATTACHMENT_RISKY_EXTENSION]
    assert len(risky) == 1, f"{ext} should fire ATTACHMENT_RISKY_EXTENSION"
    assert risky[0].severity == Severity.HIGH
