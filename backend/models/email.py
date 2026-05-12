from datetime import datetime

from pydantic import BaseModel, Field


class Sender(BaseModel):
    display_name: str = Field(max_length=200)
    address: str = Field(max_length=320)


class EmailHeaders(BaseModel):
    authentication_results: str = Field(default="", max_length=4000)
    received_spf: str = Field(default="", max_length=1000)
    return_path: str = Field(default="", max_length=400)
    reply_to: str = Field(default="", max_length=400)
    message_id_header: str = Field(default="", max_length=400)
    x_originating_ip: str = Field(default="", max_length=100)


class EmailBody(BaseModel):
    text: str = Field(default="", max_length=100_000)
    html: str = Field(default="", max_length=100_000)


class AttachmentMeta(BaseModel):
    filename: str = Field(max_length=400)
    mime_type: str = Field(max_length=200)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)


class SenderHistory(BaseModel):
    from_address: str
    first_seen: datetime | None = None
    messages_seen: int = 0
    typical_signing_domains: list[str] = Field(default_factory=list)
    typical_ip_prefixes: list[str] = Field(default_factory=list)
    typical_send_hours: list[int] = Field(default_factory=list)
    last_messages: list[str] = Field(default_factory=list, max_length=20)


class Email(BaseModel):
    message_id: str = Field(max_length=400)
    from_: Sender = Field(alias="from")
    to: list[str] = Field(max_length=100)
    subject: str = Field(max_length=1000)
    received_at: datetime
    headers: EmailHeaders
    body: EmailBody
    urls_in_body: list[str] = Field(default_factory=list, max_length=200)
    attachments: list[AttachmentMeta] = Field(default_factory=list, max_length=20)
    sender_history: SenderHistory | None = None

    model_config = {"populate_by_name": True}
