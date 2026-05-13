from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Signal(StrEnum):
    # headers
    SPF_PASS = "spf_pass"
    SPF_FAIL = "spf_fail"
    SPF_SOFTFAIL = "spf_softfail"
    DKIM_VALID = "dkim_valid"
    DKIM_MISSING = "dkim_missing"
    DMARC_FAIL = "dmarc_fail"
    REPLY_TO_DOMAIN_MISMATCH = "reply_to_domain_mismatch"
    RETURN_PATH_DOMAIN_MISMATCH = "return_path_domain_mismatch"
    MISSING_MESSAGE_ID = "missing_message_id"
    # sender
    DISPLAY_NAME_DOMAIN_MISMATCH = "display_name_domain_mismatch"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    HOMOGLYPH_IN_DOMAIN = "homoglyph_in_domain"
    FREEMAIL_IMPERSONATING_BRAND = "freemail_impersonating_brand"
    # urls
    URL_KNOWN_MALICIOUS = "url_known_malicious"
    URL_KNOWN_PHISHING = "url_known_phishing"
    URL_TEXT_HREF_MISMATCH = "url_text_href_mismatch"
    URL_USES_IP_NOT_DOMAIN = "url_uses_ip_not_domain"
    URL_SHORTENER = "url_shortener"
    # attachments
    ATTACHMENT_KNOWN_MALICIOUS_HASH = "attachment_known_malicious_hash"
    ATTACHMENT_RISKY_EXTENSION = "attachment_risky_extension"
    ATTACHMENT_DOUBLE_EXTENSION = "attachment_double_extension"
    ATTACHMENT_MIME_EXTENSION_MISMATCH = "attachment_mime_extension_mismatch"
    ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE = "attachment_password_protected_archive"
    # prompt injection
    PROMPT_INJECTION_ATTEMPT = "prompt_injection_attempt"
    TAG_ESCAPING_ATTEMPT = "tag_escaping_attempt"
    SUSPICIOUS_UNICODE_IN_BODY = "suspicious_unicode_in_body"
    ENCODED_PAYLOAD_IN_BODY = "encoded_payload_in_body"
    PAYLOAD_FRAGMENTATION_ATTEMPT = "payload_fragmentation_attempt"
    # sender baseline
    FIRST_SEEN_SENDER = "first_seen_sender"
    SENDER_DOMAIN_DRIFT = "sender_domain_drift"
    SENDER_SEND_TIME_ANOMALY = "sender_send_time_anomaly"
    SENDER_IP_GEOGRAPHY_CHANGE = "sender_ip_geography_change"
    # bec language
    PAYMENT_INSTRUCTION_URGENCY = "payment_instruction_urgency"
    # llm
    LLM_HIGH_RISK_PATTERN = "llm_high_risk_pattern"
    LLM_SUSPICIOUS_PATTERN = "llm_suspicious_pattern"
    LLM_BENIGN_JUDGMENT = "llm_benign_judgment"


class Evidence(BaseModel):
    signal: Signal
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(max_length=400)
    mitre_techniques: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    detector: str = Field(max_length=50)
