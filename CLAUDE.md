# Project Overview

Swellscan is a Gmail Add-on that analyzes the currently-open email and produces an explainable maliciousness verdict using **layered detection** — cheap deterministic checks first, an LLM only on emails that aren't clearly safe. Built for the Upwind Security Bootcamp home assignment as a portfolio piece demonstrating product-thinking, evidence-based detection, and security-engineering judgment within a 4-day timebox.

The design deliberately mirrors Upwind's own published architecture (RSAC 2026 malicious-prompt detector): three threat-class coverage areas (phishing-links, BEC, attachments) plus three deliberate stand-out moments — self-defending LLM, wave-themed verdict card with a character arc, and per-sender baselining. Submission deadline: **Fri 2026-05-15 EOD**.

## Current State (updated 2026-05-13)

**Phases 0-5 complete (Tasks 1-28 of 39).** Backend AND the Gmail Add-on are built, deployed, and **installed live on the demo Gmail account**. The verdict card renders correctly in Gmail's right sidebar end-to-end.

- **Live URL:** [`https://swellscan-backend-102679409749.us-central1.run.app`](https://swellscan-backend-102679409749.us-central1.run.app/health) - `/health` returns `{"status":"ok"}`, `/score` is OIDC-protected (401 without a valid Google ID token), `/illustration/{label}` serves the static hero PNG (SAFE/SUSPICIOUS/MALICIOUS), `/dot/{severity}` serves the severity-dot icon, `/logo.png` serves the Swellscan brand logo. All static endpoints carry a 1-hour cache.
- **Live revision:** `swellscan-backend-00008-gpx`.
- **Tests:** **53 passing** (40 prior + 13 illustration/logo endpoint tests). `pytest` from repo root runs all.
- **Three signature features built and verified end-to-end:**
  1. **Self-defending LLM** - Task 10 prompt-injection detector + Task 14 hardened Anthropic client (random per-request wrapper tag, zero-width sanitization of closing-tag patterns, system-prompt trust-boundary instructions)
  2. **Layered detection** - Task 15 pipeline + Task 4 thresholds (cheap deterministic detectors run in parallel; LLM invoked only when raw score >= 25)
  3. **Per-sender baseline** - Task 17 backend detector + Task 27 Add-on `UserProperties` writer with `LockService` + `message_id` ring-buffer idempotency
- **GCP project:** `swellscan-prod` (project number `102679409749`), owned by `swellscan.demo@gmail.com`, billing on free trial. Three secrets in Secret Manager.
- **OIDC_AUDIENCE** (updated 2026-05-13 during Task 28 Step 4.5): `812475821064-s838lvgcgmc1nj4lbjqivpa48usi4t8v.apps.googleusercontent.com` - the Apps Script project's OAuth client ID, NOT the Cloud Run URL. `ScriptApp.getIdentityToken()` returns a token with `aud` set to the script's OAuth client; the original Cloud Run URL value would 401 on every request.
- **Card visual is LOCKED:** canonical mockup at `addon/design-refs/preview-final-v2.png`. Live card in Gmail matches.
- **What's next:** **Phase 6 - Polish + Submission** (Tasks 29-39 plus inline stretches 31.5, 36.5, 36.6). Demo data → cleanup + security → docs → submission. Submission deadline Fri 2026-05-15 EOD.

For the full deployment-state reference (URLs, IAM, env vars, the bugs we found at deploy time, cleanup commands at end-of-project), see the `project_deploy_state.md` memory file.

**Tasks completed with commit SHAs:**

| Task | Commit | What |
|---|---|---|
| 1 | `fec9e6c` | FastAPI skeleton + `/health` |
| 2 | `84bd9ab` | `Email` Pydantic model + fixtures |
| 3 | `64d6d88` | `Evidence` + `Verdict` models |
| 4 | `6a0e00d` | Scoring policy (weights, thresholds) |
| 5 | `0f37c9c` | Aggregator (pure function) |
| 6 | `dbf3151` | OIDC token verification |
| 7 | `99adbec` | `Detector` ABC with `safe_run` |
| 8 | `f33a867` | Headers detector (SPF/DKIM/DMARC) |
| 9 | `973f657` | Sender detector (lookalike + impersonation) |
| 10 | `a798bbc` | Prompt-injection detector |
| 11 | `6911f42` | External clients (VT, SB, urlscan) |
| 12 | `8f464fc` | URLs detector |
| 13 | `e0c69cd` | Attachments detector |
| 14 | `88439b3` | Anthropic client + LLM detector |
| 15 | `3a2c78b` | Pipeline orchestrator |
| 16 | `137921c` | `POST /score` endpoint |
| 17 | `9b3354c` | Sender-baseline detector |
| 18 | `5f50dcc` | SVG wave illustration generator (later retired during Task 25) |
| 19 | `28e35a0` | Dockerfile (caught missing `requests` dep) |
| 20-21 | (runtime ops) | Cloud Run deployment + demo Gmail account |
| 22 | `c71f2a4` | `appsscript.json` manifest with minimum-needed Gmail scopes |
| 23 | `df44c67` | `setup.gs` one-time config (BACKEND_URL + OIDC_AUDIENCE → ScriptProperties) |
| 24 | `9654029` | `client.gs` HTTP wrapper + RFC 5322 header unfold + Gmail payload builder |
| 25 | `001e2b6`, `a8eb82c` | `render.gs` verdict card builder + backend SVG-to-PNG swap on `/illustration` + new `/dot/{severity}` endpoint |
| 26 | `59c6a10` | `Code.gs` auto-scan trigger + lifeguard-voice stub button handlers |
| 27 | `9b93314` | `baseline.gs` UserProperties with LockService + ring-buffer idempotency + bounded growth on typical_* arrays |
| 28 | (live install + iterations) | Apps Script project created on demo Gmail, OIDC audience captured + backend redeployed (Step 4.5), 8+ post-install design polish commits (`136c05b` script.locale scope, `2e1eee1` lifeguard prefix + dot regen, `c6de9e6` IconImage/CIRCLE + prettySignal, `2793119` button fallback, `abe8ea2` enum fix, `bc39d90` MITRE inline, `02e764b` inline bullet, `c58908c` drop subject/sender, `395bcf2` body indent, `7bccdba` full-title color, `e371659` logo endpoint, `5ed07c8` logo background removal) |

**Plan-vs-implementation drift caught (interview material):**

- **Task 8** headers - planned test assumed `make_email` had a non-empty default Message-ID; fixed by adding `message_id_header` default to the fixture.
- **Task 9** sender - planned `DISPLAY_NAME_DOMAIN_MISMATCH` check used `not any(brand in d for legit_domains + [from_domain])`, always false because the brand is always a substring of its own legit domain. Fixed to `from_domain not in legit_domains`.
- **Task 19** Docker - production container's missing `requests` dep (locally hidden by `pip-audit` dev dep pulling it in transitively). Added explicit `requests==2.34.0` to `requirements.txt`.
- **Task 24** client.gs - planned `parseHeaders` regex captured only the first physical line; RFC 5322 allows long headers to be folded across continuation lines. Without the fix, the backend would emit empty SPF/DKIM/DMARC evidence on most real Gmail messages.
- **Task 24** OIDC audience - planned auth assumed `OIDC_AUDIENCE = Cloud Run URL`; `ScriptApp.getIdentityToken()` actually returns a JWT whose `aud` is the script's OAuth client ID. Caught at trace time, fixed during Task 28 Step 4.5 by capturing the actual `aud` from a one-time helper and redeploying the backend with the matching env var.
- **Task 25** card design - the planned `render.gs` code block was a small-text verdict line with no severity sorting and a generic "Re-scan" button. Replaced wholesale via a full design pass (six mockup iterations + Lotan approval at each); canonical visual locked at `addon/design-refs/preview-final-v2.png`.
- **Task 25** SVG generator retired - Task 18's `wave.py` SVG generator was replaced with static PNG file serving for the three hero illustrations Lotan provided. Public URL contract preserved.
- **Task 22** scopes - the `script.locale` OAuth scope was dropped on a "minimum permissions" principle. Task 28 live install proved the Gmail Add-on framework requires it at runtime even when we never call `Session.getActiveUserLocale()` directly. Scope added back.
- **Task 28** card iterations - first install surfaced a chain of visual fixes that converged via iterative real-Gmail testing: severity dot rendering (IconImage circle-crop unreliable across runtimes; switched to coloring the title text), signal name pretty-printing, button alignment fallback (centered with FixedFooter fallback), summary opener readability, subject+sender row removal as redundant, body text alignment under the title.

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

# Deploy backend to Cloud Run (one command, builds from source).
# The secrets and env vars from the last revision persist, so a code-only
# redeploy can omit --set-secrets and --set-env-vars.
gcloud run deploy swellscan-backend \
  --source . --region us-central1 \
  --set-secrets="ANTHROPIC_API_KEY=anthropic-api-key:latest,VIRUSTOTAL_API_KEY=virustotal-api-key:latest,SAFEBROWSING_API_KEY=safebrowsing-api-key:latest" \
  --set-env-vars="ALLOWED_USERS=swellscan.demo@gmail.com,OIDC_AUDIENCE=https://swellscan-backend-102679409749.us-central1.run.app" \
  --allow-unauthenticated  # app-layer OIDC enforcement, not IAM

# One-time IAM grant needed before the first deploy (so Cloud Run's default
# compute SA can read Secret Manager). Already applied to swellscan-prod.
gcloud projects add-iam-policy-binding swellscan-prod \
  --member="serviceAccount:102679409749-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

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
- `docs/superpowers/plans/2026-05-12-swellscan-implementation.md` — The numbered implementation plan. **Treat code blocks inside it as logic-spec / pseudo-code, not source-of-truth** — see the `feedback_plan_code_is_spec_not_source.md` memory for why. The plan was written speculatively in one pass; it has at least three known bugs that surfaced during implementation (see "Plan-vs-implementation drift caught" table above).
- Memory files at `C:\Users\lotan\.claude\projects\c--Users-lotan-Projects-Upwind\memory\` — 13 files capturing user preferences, project plan, demo strategy, **live deploy state** (`project_deploy_state.md` — URLs, GCP IDs, IAM, env vars), and Upwind research. The `MEMORY.md` index lists all of them.
