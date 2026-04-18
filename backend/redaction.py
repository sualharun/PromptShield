import re

# Patterns are intentionally conservative — we'd rather under-redact than corrupt the
# stored prompt, since users will want to read it back from history.
PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (
        re.compile(r"\b\+?\d{1,2}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b"),
        "[REDACTED_PHONE]",
    ),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pattern, placeholder in PATTERNS:
        out = pattern.sub(placeholder, out)
    return out
