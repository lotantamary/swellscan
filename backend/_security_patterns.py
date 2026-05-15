"""Byte patterns shared by the prompt-injection DETECTOR and the LLM-input
SANITIZER. Owning them in one place enforces the contract by construction:
the sanitizer cannot strip less than what the detector flags.

If you add a new evasion pattern, add it here and reference it from BOTH:
  - backend/detectors/prompt_injection.py (raises an Evidence signal)
  - backend/clients/anthropic.py::_sanitize_body (neutralizes for the LLM)
"""
import re

# Closing-tag mimics. Attackers can try to escape the
# `<untrusted_content_xxx>` sandbox tag the system prompt wraps the body in
# by emitting a fake closing tag. Detector raises TAG_ESCAPING_ATTEMPT;
# sanitizer substitutes the match with "[removed]" before the body reaches
# Claude (V2 strategy; V1 used a zero-width-char insertion that the V2
# global zero-width strip would have undone).
CLOSING_TAG_MIMIC = re.compile(
    r"</(?:untrusted|system|instruction|prompt|evidence|email)[a-z_0-9]*>",
    re.I,
)

# Zero-width / invisible Unicode points commonly abused for evasion.
# Codepoints in the class below, in order:
#   U+200B zero-width space, U+200C zero-width non-joiner,
#   U+200D zero-width joiner, U+2060 word joiner, U+FEFF byte-order mark.
# Each character is intentionally invisible in editors - the comment is the
# only readable record of what is here.
ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
