from redaction import redact


def test_redacts_email():
    out = redact("contact alice@example.com please")
    assert "alice@example.com" not in out
    assert "[REDACTED_EMAIL]" in out


def test_redacts_api_key():
    out = redact("key = sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234")
    assert "sk-proj-" not in out
    assert "[REDACTED_API_KEY]" in out


def test_redacts_ssn_and_phone():
    out = redact("SSN 123-45-6789 phone +1 555-867-5309")
    assert "123-45-6789" not in out
    assert "555-867-5309" not in out


def test_clean_text_unchanged():
    text = "This text has nothing sensitive in it."
    assert redact(text) == text
