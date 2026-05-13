# Swellscan language bank

Phrases for the README, the 60-second pitch, and the interview narrative. Mirrors Upwind's RSAC 2026 published vocabulary for the layered AI-prompt detection paper.

## Core architecture phrases

- "Layered detection."
- "Cheap deterministic detectors gate the expensive LLM call."
- "Selective LLM validation on the high-risk subset."
- "Sub-millisecond pre-filter before heavyweight reasoning."
- "Evidence-based scoring; the LLM contributes evidence, the aggregator decides the verdict."
- "Self-defending LLM" (the differentiator, not "prompt-injection-aware LLM").

## Trust-boundary phrases

- "Random per-request wrapper tag" (not "dynamic delimiter").
- "Untrusted content is data, not instructions."
- "Defense in depth: detect AND sanitize."

## Cost / latency framing (Upwind-aligned)

- "Score-gated LLM invocation - we don't pay for an LLM call we don't need."
- "The expensive analysis applies only to the subset of emails that warrant it."
- "Per-message scoring; per-sender baseline; both client-side stored, server-side stateless."

## What we do NOT say

- "Powered by AI" (vague). Say "Claude Sonnet 4.6 second-opinion on high-risk emails."
- "Cutting-edge" / "next-generation" / any marketing filler.
- Em-dashes in any user-facing copy.

## Three-feature narrative beats

1. **Self-defending LLM** - we wrap untrusted email content in randomly-suffixed delimiter tags, sanitize closing-tag mimics, strip hidden HTML and Unicode Tags before the LLM sees the body, and validate output with a Pydantic schema. The LLM is hardened against the input we feed it.
2. **Layered detection with selective LLM validation** - the cheap detectors emit evidence with weights; the score gates the LLM call; the aggregator is a pure function with correlation bonuses for known attacker playbooks.
3. **Per-sender baseline** - the Add-on tracks each sender's typical signing-domain, IP prefixes, and send-hour pattern in the user's UserProperties. First-seen senders and drift events become signals fed back into the score.

Use these phrases verbatim where they fit. They mirror Upwind's published voice word-for-word.
