import pytest

from backend.detectors.bec_language import BecLanguageDetector
from backend.models.evidence import Severity, Signal
from tests.fixtures.emails import make_email


@pytest.mark.asyncio
async def test_v2_bec_urgency_payment_within_proximity_fires():
    """Urgency word + payment-instruction word within 100 chars = fire."""
    body = (
        "Hi - we need to urgently change the wire transfer instructions "
        "for invoice 42. New IBAN below."
    )
    email = make_email(body_text=body)
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 1
    assert pmt[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_v2_bec_urgency_only_no_fire():
    """Urgency without payment-instruction language = no fire."""
    body = "Please reply ASAP - we have an urgent question."
    email = make_email(body_text=body)
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 0


@pytest.mark.asyncio
async def test_v2_bec_payment_only_no_fire():
    """Payment-instruction language without urgency = no fire (legitimate invoicing)."""
    body = "Attached is the invoice with our standard wire transfer details. Net 30."
    email = make_email(body_text=body)
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 0


@pytest.mark.asyncio
async def test_v2_bec_distant_no_fire():
    """Urgency and payment words too far apart = no fire."""
    body = (
        "URGENT please reply by end of day. "
        + "x" * 300
        + " Also, attached is the standard wire transfer detail sheet."
    )
    email = make_email(body_text=body)
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 0


@pytest.mark.asyncio
async def test_v2_bec_change_banking_keyword():
    """Standalone 'change of banking details' phrase fires by itself."""
    body = (
        "Quick note: there is a change of banking details, please use "
        "the new account."
    )
    email = make_email(body_text=body)
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 1


@pytest.mark.asyncio
async def test_v2_bec_empty_body_no_fire():
    """Empty body = no signal, no crash."""
    email = make_email(body_text="", body_html="")
    evs = await BecLanguageDetector().run(email)
    pmt = [e for e in evs if e.signal == Signal.PAYMENT_INSTRUCTION_URGENCY]
    assert len(pmt) == 0
