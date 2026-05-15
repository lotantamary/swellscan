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


# V2.S4: password-protected-archive + body-password-token correlation
# (research finding #7). Wires up the existing ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
# enum stub that was unused in V1.


@pytest.mark.asyncio
async def test_v2_password_archive_fires_when_body_has_password_token():
    """Body 'Password:' token + .zip attachment = HIGH severity signal."""
    email = make_email(
        body_text="Please find attached the documents. Password: SwellScan2026",
        attachments=[make_att(filename="documents.zip")],
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    pw = [
        e for e in evs if e.signal == Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
    ]
    assert len(pw) == 1
    assert pw[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_v2_password_archive_does_not_fire_without_body_password_token():
    """Archive attachment + plain body (no password token) = no signal."""
    email = make_email(
        body_text="Please find attached the project files.",
        attachments=[make_att(filename="project.zip")],
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    pw = [
        e for e in evs if e.signal == Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
    ]
    assert len(pw) == 0


@pytest.mark.asyncio
async def test_v2_password_archive_does_not_fire_without_archive():
    """Body password token + non-archive attachment = no signal (the correlation requires both)."""
    email = make_email(
        body_text="Your password reset link is below.",
        attachments=[make_att(filename="receipt.pdf")],
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    pw = [
        e for e in evs if e.signal == Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
    ]
    assert len(pw) == 0


@pytest.mark.parametrize("ext", [".rar", ".7z"])
@pytest.mark.asyncio
async def test_v2_password_archive_fires_for_rar_and_7z(ext):
    """Detection covers .rar and .7z, not just .zip."""
    email = make_email(
        body_text="Password: x9j2",
        attachments=[make_att(filename=f"archive{ext}")],
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    pw = [
        e for e in evs if e.signal == Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
    ]
    assert len(pw) == 1, f"expected fire for {ext}"


@pytest.mark.parametrize("body", [
    "Please find attached. The archive is encrypted - password to open is: invoice2025",
    "The password is: secret123",
    "Use the attached password to unlock the archive.",
    "Please find your password in this archive: SwellScan2026",
    "Hi, your passcode for the attached zip is hunter22.",
    "PWD = abcdef",
])
@pytest.mark.asyncio
async def test_v2_password_archive_fires_on_natural_language_phrasings(body):
    """Task 31 Phase A catch: the old regex required `password` to be
    IMMEDIATELY followed by a 4-40 char token, which failed on natural
    phrasings like 'password to open is: invoice2025'. The detector now
    fires whenever any password word co-occurs with an archive attachment;
    the inline comment already accepted that false-positive trade-off, but
    the implementation was stricter than the comment described."""
    email = make_email(
        body_text=body,
        attachments=[make_att(filename="invoice.zip")],
    )
    vt = AsyncMock()
    vt.file_hash_reputation.return_value = {"found": False}
    evs = await AttachmentsDetector(vt=vt).run(email)
    pw = [
        e for e in evs if e.signal == Signal.ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE
    ]
    assert len(pw) == 1, f"expected fire on body phrasing: {body!r}"
