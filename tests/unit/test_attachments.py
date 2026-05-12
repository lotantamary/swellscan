from unittest.mock import AsyncMock

import pytest

from backend.detectors.attachments import AttachmentsDetector
from backend.models.email import AttachmentMeta
from backend.models.evidence import Signal
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
