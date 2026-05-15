import json

from backend.clients.anthropic import AnthropicClient, _sanitize_body
from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal


class LLMDetector(Detector):
    name = "llm"

    def __init__(self, client: AnthropicClient | None = None):
        self._client = client or AnthropicClient()

    async def run_with_evidence(
        self, email: Email, prior_evidence: list[Evidence]
    ) -> list[Evidence]:
        evidence_json = json.dumps(
            [e.model_dump(mode="json") for e in prior_evidence]
        )
        # Apply the V2 sanitization stack to the string fields the LLM will
        # see in <email_metadata>. Without this, hidden-HTML / Unicode-Tags /
        # closing-tag-mimic / zero-width / EchoLeak-markdown payloads embedded
        # in subject or display_name would reach Claude un-sanitized while the
        # body is sanitized - the V2 defense stack would be silently absent
        # on the metadata path. Caught during Task 31.5 security review.
        metadata = json.dumps(
            {
                "from_address": email.from_.address,
                "display_name": _sanitize_body(email.from_.display_name or ""),
                "subject": _sanitize_body(email.subject or ""),
                "urls_in_body": email.urls_in_body[:20],
                "has_attachments": bool(email.attachments),
            }
        )
        verdict = await self._client.analyze(
            evidence_json=evidence_json,
            email_metadata=metadata,
            body=email.body.text,
        )
        if not verdict:
            return []
        if verdict.verdict == "malicious":
            sig, sev = Signal.LLM_HIGH_RISK_PATTERN, Severity.HIGH
        elif verdict.verdict == "suspicious":
            sig, sev = Signal.LLM_SUSPICIOUS_PATTERN, Severity.MEDIUM
        else:
            sig, sev = Signal.LLM_BENIGN_JUDGMENT, Severity.INFO
        details = {
            "matched_patterns": verdict.matched_patterns,
            "should_warn_user": verdict.should_warn_user,
        }
        # V2.S8: pipeline._summarize reads llm_summary_body from evidence
        # details to build the user-facing one-sentence verdict body.
        if verdict.summary_body and verdict.summary_body.strip():
            details["llm_summary_body"] = verdict.summary_body.strip()
        return [
            Evidence(
                signal=sig,
                severity=sev,
                confidence=verdict.confidence,
                explanation=verdict.reasoning,
                mitre_techniques=(
                    ["T1566", "T1656"]
                    if sig != Signal.LLM_BENIGN_JUDGMENT
                    else []
                ),
                details=details,
                detector=self.name,
            )
        ]

    async def run(self, email: Email) -> list[Evidence]:
        return await self.run_with_evidence(email, [])
