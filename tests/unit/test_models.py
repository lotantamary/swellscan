import pytest
from pydantic import ValidationError

from tests.fixtures.emails import make_email


def test_email_parses_valid_payload():
    email = make_email(subject="Test")
    assert email.subject == "Test"
    assert email.from_.address == "alice@example.com"


def test_email_body_size_cap_enforced():
    with pytest.raises(ValidationError):
        make_email(body_text="x" * 100_001)
