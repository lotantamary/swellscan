import re

from backend.detectors.base import Detector
from backend.models.email import Email
from backend.models.evidence import Evidence, Severity, Signal

# Match both `header.d=domain.com` (older RFC 6376 style; the d= signing
# domain) AND `header.i=@domain.com` (Gmail's more common Authentication-
# Results format; the i= identity, which carries the signing domain after
# an optional leading @). Either capture is the DKIM-signing domain.
DKIM_DOMAIN_RE = re.compile(r"header\.[di]=@?([\w\.\-]+)", re.I)


class SenderBaselineDetector(Detector):
    name = "sender_baseline"

    async def run(self, email: Email) -> list[Evidence]:
        if not email.sender_history or email.sender_history.messages_seen == 0:
            return [
                Evidence(
                    signal=Signal.FIRST_SEEN_SENDER,
                    severity=Severity.LOW,
                    confidence=0.95,
                    explanation=f"First email observed from {email.from_.address}.",
                    mitre_techniques=[],
                    details={"from_address": email.from_.address},
                    detector=self.name,
                )
            ]
        out: list[Evidence] = []
        history = email.sender_history

        # signing domain drift
        m = DKIM_DOMAIN_RE.search(email.headers.authentication_results)
        current_signing = m.group(1).lower() if m else ""
        if current_signing and current_signing not in (
            d.lower() for d in history.typical_signing_domains
        ):
            out.append(
                Evidence(
                    signal=Signal.SENDER_DOMAIN_DRIFT,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    explanation=(
                        f"Known sender {email.from_.address} usually signs from "
                        f"{history.typical_signing_domains}, but this email is signed from {current_signing}."
                    ),
                    mitre_techniques=["T1656"],
                    details={
                        "current": current_signing,
                        "typical": history.typical_signing_domains,
                    },
                    detector=self.name,
                )
            )

        # send-time anomaly
        if history.typical_send_hours:
            current_hour = email.received_at.hour
            if current_hour not in history.typical_send_hours:
                out.append(
                    Evidence(
                        signal=Signal.SENDER_SEND_TIME_ANOMALY,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        explanation=(
                            f"Email arrived at {current_hour:02d}:00 - outside this sender's typical "
                            f"send hours ({sorted(history.typical_send_hours)})."
                        ),
                        mitre_techniques=["T1656"],
                        details={
                            "hour": current_hour,
                            "typical": history.typical_send_hours,
                        },
                        detector=self.name,
                    )
                )

        # IP geography drift (prefix match)
        if history.typical_ip_prefixes and email.headers.x_originating_ip:
            ip_prefix = ".".join(email.headers.x_originating_ip.split(".")[:2])
            if not any(
                p.startswith(ip_prefix) or ip_prefix.startswith(p)
                for p in history.typical_ip_prefixes
            ):
                out.append(
                    Evidence(
                        signal=Signal.SENDER_IP_GEOGRAPHY_CHANGE,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        explanation=f"Email from {email.from_.address} originated from unusual IP range.",
                        mitre_techniques=["T1656"],
                        details={
                            "current_ip": email.headers.x_originating_ip,
                            "typical_prefixes": history.typical_ip_prefixes,
                        },
                        detector=self.name,
                    )
                )
        return out
