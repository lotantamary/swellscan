"""Known free/consumer email providers. Detection-data shared across
detectors that need to distinguish corporate addresses from consumer
ones (the headers detector scales Reply-To / Return-Path mismatch
severity by it; the sender detector uses it to flag freemail
accounts using a corporate brand in the display name).

This is intentionally a small hand-curated list, not exhaustive. Adding a
domain here strengthens the BEC signal; missing one weakens it but doesn't
break it.
"""

FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "hotmail.com",
        "icloud.com",
        "proton.me",
        "aol.com",
        "live.com",
    }
)
