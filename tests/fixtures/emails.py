from datetime import datetime, timezone

from backend.models.email import (
    AttachmentMeta,
    Email,
    EmailBody,
    EmailHeaders,
    Sender,
    SenderHistory,
)


def make_email(
    *,
    from_address: str = "alice@example.com",
    from_name: str = "Alice",
    subject: str = "Hello",
    body_text: str = "Hi.",
    body_html: str = "<p>Hi.</p>",
    auth_results: str = "spf=pass; dkim=pass; dmarc=pass",
    return_path: str = "",
    reply_to: str = "",
    urls: list[str] | None = None,
    attachments: list[AttachmentMeta] | None = None,
    sender_history: SenderHistory | None = None,
    sender_ip: str = "209.85.220.42",
    message_id: str = "msg-001",
) -> Email:
    return Email(
        message_id=message_id,
        **{"from": Sender(display_name=from_name, address=from_address)},
        to=["lotan@example.com"],
        subject=subject,
        received_at=datetime(2026, 5, 12, 14, 0, 0, tzinfo=timezone.utc),
        headers=EmailHeaders(
            authentication_results=auth_results,
            return_path=return_path,
            reply_to=reply_to,
            x_originating_ip=sender_ip,
        ),
        body=EmailBody(text=body_text, html=body_html),
        urls_in_body=urls or [],
        attachments=attachments or [],
        sender_history=sender_history,
    )
