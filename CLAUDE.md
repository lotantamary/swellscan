# Project Overview

Swellscan is a Gmail Add-on that analyzes the currently-open email and produces an explainable maliciousness verdict using **layered detection** — cheap deterministic checks first, an LLM only on emails that aren't clearly safe. Built for the Upwind Security Bootcamp home assignment as a portfolio piece demonstrating product-thinking, evidence-based detection, and security-engineering judgment within a 4-day timebox.

The design deliberately mirrors Upwind's own published architecture (RSAC 2026 malicious-prompt detector): three threat-class coverage areas (phishing-links, BEC, attachments) plus three deliberate stand-out moments — self-defending LLM, wave-themed verdict card with a character arc, and per-sender baselining. Submission deadline: **Fri 2026-05-15 EOD**.

## Tech Stack & Environment

**Backend (`backend/`)** — Python 3.12, FastAPI, async I/O via `httpx`. Pydantic 2 for all request/response models and LLM output validation. `structlog` for structured JSON logging. `google-auth` for OIDC token verification. Anthropic SDK for Claude Sonnet 4.6.

**Gmail Add-on (`addon/`)** — Apps Script (V8 JavaScript), CardService for UI, UrlFetchApp for HTTPS to backend, PropertiesService for per-user storage of sender history + setup state.

**Deployment** — Google Cloud Run (auto-managed TLS, scale-to-zero), Google Secret Manager (3 secrets), Cloud Logging (built-in, free tier).

**External services** — Anthropic API, VirusTotal API v3, Google Safe Browsing, urlscan.io.

**Required environment variables (backend container):**
- `ANTHROPIC_API_KEY` · `VIRUSTOTAL_API_KEY` · `SAFEBROWSING_API_KEY` (Secret Manager refs)
- `ALLOWED_USERS` (comma-separated allowlist of Gmail addresses)
- `OIDC_AUDIENCE` (the Cloud Run service URL — used for ID token verification)

**Local development:** copy `.env.example` to `.env` (gitignored) and fill in the same variables.

## Key Directories & Architecture

| Path | Role |
|---|---|
| `backend/api/` | FastAPI routes — currently only `POST /score`. Thin adapter layer; no business logic |
| `backend/models/` | Pydantic schemas — `Email`, `Evidence`, `Verdict`. The system speaks three nouns; these are them |
| `backend/detectors/` | One file per detector, each implementing the `Detector` ABC in `base.py`. Detectors don't know about each other |
| `backend/scoring/` | `policy.py` holds weights, thresholds, and correlation bonuses; `aggregator.py` is a pure `list[Evidence] → Verdict` |
| `backend/clients/` | Thin wrappers around external APIs — `anthropic.py`, `virustotal.py`, `safebrowsing.py`, `urlscan.py` |
| `backend/illustration/` | `wave.py` generates the per-verdict SVG hero image served to the Add-on |
| `backend/auth.py` | OIDC ID-token verification via Google JWKs + email allowlist check |
| `backend/pipeline.py` | Orchestrator: parallel detector dispatch → aggregator → conditional LLM → final verdict |
| `addon/Code.gs` | `onGmailMessageOpen` trigger; card-state routing |
| `addon/baseline.gs` | Sender-history read/update with `LockService` + `message_id` idempotency |
| `addon/render.gs` | `Verdict` JSON → CardService card builder |
| `tests/unit/` | One file per detector, plus scoring policy tests. ~40 tests target |
| `tests/integration/` | Full pipeline with mocked external APIs via `pytest-httpx` |
| `docs/superpowers/specs/2026-05-12-swellscan-design.md` | The single authoritative design doc — every decision lives here |

**Architectural invariants** (see [design doc lines 168–177](docs/superpowers/specs/2026-05-12-swellscan-design.md#L168) for the full table):
- Detectors are independent — adding one is a single new file
- Scoring is a pure function — tuning lives in `scoring/policy.py:1`
- Backend is stateless — no DB, no session, no race conditions
- Email body is never persisted — read, scored, discarded

## Build & Test Commands

```bash
# Backend — local dev
cd backend
pip install -r requirements.txt
cp .env.example .env  # then fill in real values
uvicorn backend.main:app --reload --port 8080

# Run tests
pytest                          # all tests
pytest --cov=backend            # with coverage (~80% target on detectors + scoring)
pytest tests/unit/test_headers_detector.py  # one file
pip-audit                       # known-CVE check before submission

# Deploy backend to Cloud Run (one command, builds from source)
gcloud run deploy swellscan-backend \
  --source . --region us-central1 \
  --set-secrets="ANTHROPIC_API_KEY=anthropic-api-key:latest,VIRUSTOTAL_API_KEY=virustotal-api-key:latest,SAFEBROWSING_API_KEY=safebrowsing-api-key:latest" \
  --set-env-vars="ALLOWED_USERS=swellscan.demo.lotan@gmail.com,OIDC_AUDIENCE=<cloud-run-url>" \
  --allow-unauthenticated  # app-layer OIDC enforcement, not IAM

# Add-on — deploy via Apps Script editor
# 1. Open script.new, paste contents of addon/*.gs
# 2. Deploy → Test deployments → Install
```

## Conventions & Anti-patterns

**Naming:** Python uses `snake_case` (PEP 8); Apps Script files use `camelCase` functions + `Code.gs`-style filenames. Signal names are `snake_case` enums (`spf_fail`, `prompt_injection_attempt`). Spirit: descriptive over terse — `lookalike_domain` not `lkdmn`.

**Patterns used:**
- **Evidence-based design** — every detector emits `Evidence` objects; the aggregator is a pure function. See [design doc §4 (line 168)](docs/superpowers/specs/2026-05-12-swellscan-design.md#L168).
- **Layered detection** — short-circuit on clearly-safe (score < 25); LLM invoked as second opinion otherwise.
- **Graceful degradation** — one detector failing returns `[]` from that detector; pipeline continues. Story: a DoS against one external API cannot deny users a verdict.
- **OIDC token auth** — no long-lived shared secrets. See `backend/auth.py:1` (planned).

**Avoid (anti-patterns specific to this project):**
- **Never log email body, subject, recipient, attachment names, URLs, or hashes.** Only metadata + sender domain. See [§10.4 of the design doc](docs/superpowers/specs/2026-05-12-swellscan-design.md).
- **Never fetch URLs directly from our backend.** We query reputation services (VT, Safe Browsing, urlscan); they follow redirects in their sandbox infrastructure.
- **Never open attachments.** We use SHA-256 hash lookups only.
- **Never persist email content beyond a single request.** Read, score, discard.
- **Never use shared secrets for Add-on ↔ Backend auth.** OIDC ID tokens only.
- **Never mock individual detectors in integration tests.** Mock at the `clients/` boundary via `pytest-httpx`.
- **Never write Co-Authored-By trailers on commits** unless the user explicitly opts in (user preference).

## Maintenance

This file is a living document. Claude must update it automatically — without being asked — whenever any of the following occur:
- A new file or directory is added that changes the project structure
- A new dependency, library, or tool is introduced
- A build, test, or run command is established or changes
- An architectural pattern or convention is established or changed

Update only the affected section(s). Do not rewrite the whole file. Apply the same updates to `.claude/docs/architectural_patterns.md` when relevant.

## Additional Documentation

- `.claude/docs/architectural_patterns.md` — Deep dives on the evidence-based pattern, OIDC auth flow, prompt-injection defense layers, scoring policy
- `docs/superpowers/specs/2026-05-12-swellscan-design.md` — The full design document. Single source of truth for every architectural and product decision. Read this first.
