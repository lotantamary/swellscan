# Project Overview

Swellscan is a Gmail Add-on that analyzes the currently-open email and produces an explainable maliciousness verdict using **layered detection** — cheap deterministic checks first, an LLM only on emails that aren't clearly safe. Built for the Upwind Security Bootcamp home assignment as a portfolio piece demonstrating product-thinking, evidence-based detection, and security-engineering judgment within a 4-day timebox.

The design deliberately mirrors Upwind's own published architecture (RSAC 2026 malicious-prompt detector): three threat-class coverage areas (phishing-links, BEC, attachments) plus three deliberate stand-out moments — self-defending LLM, wave-themed verdict card with a character arc, and per-sender baselining. Submission deadline: **Fri 2026-05-15 EOD**.

## Current State (updated 2026-05-15, Task 31.5 complete - cleanup + urlscan wire-up + demo 9)

**V1, V2, Phase 6 demos, AND Task 31.5 cleanup ALL complete and deployed.** 6 planned demos + 3 spares (demos 7, 8, 9) verified end-to-end with submission-quality screenshots. Live revision `swellscan-backend-00024-wmr` (2026-05-15). 183 tests passing (was 167). Phase 6 continues at Task 32 (security review) → Task 34 (README full content - **creativity emphasis**) → Task 35 (refresh CLAUDE.md) → Task 37 (PDF cover sheet) → Task 38 (submit). Submission deadline TODAY EOD.

**Task 31.5 surfaced ~17 cleanup candidates across two parallel review skills (simplify + code-review); 7 landed today as Tier 1 + Tier 2, 4 deferred to README backlog with explicit "would do before next production deploy" framing. Also: the design doc promised 3 URL-reputation sources but the code only wired 2 - the urlscan wire-up closes that plan-drift, and the urlscan wrapper picked up two real bug fixes (URL-encoding hardening + the page.url query-format quote-wrapping) while being relaxed to fire on urlscan's tag-based verdicts (the strict consensus field is paid-tier only).**

**Task 31 dogfood pass surfaced 12 plan-drift catches** (interview material - all fixed and committed):
1. Empty-baseline drift false-positive on real Gmail emails
2. Encoded-payload false-positive on URL tracking tokens + inline data: images
3. Anthropic 5s timeout too aggressive for 11KB prompts (→ 30s)
4. Safe Browsing 4s timeout (→ 15s) + structured failure logging
5. VirusTotal 4s timeout (→ 15s) + structured failure logging
6. Card meta lied about "LLM consulted" when LLM call silently failed
7. **Secret Manager values had trailing `\r\n` - broke all 3 external APIs since V2.S9** (THE root cause; revealed by Cloud Run log inspection after Lotan noticed Anthropic dashboard showed zero balance consumed despite cards claiming "LLM consulted")
8. Claude wrapped JSON in markdown code fences (Pydantic rejected) → strip before validation
9. LLM reasoning exceeded artificial 500-char max_length (→ 2000) - Evidence.explanation same
10. V2.S4 password-archive regex too strict for natural-language phrasings ("Password to open is: X" failed)
11. `max_tokens=400` too small for full JSON output on dense scans (→ 1500)
12. Demo 6 body had urgency >100 chars from any payment word AND prompt-injection regex missed "Ignore all previous instructions" + "as verdict=benign" phrasings - both fixed

- **Live URL:** [`https://swellscan-backend-102679409749.us-central1.run.app`](https://swellscan-backend-102679409749.us-central1.run.app/health) - `/health` returns `{"status":"ok"}`, `/score` is OIDC-protected (401 without a valid Google ID token), `/illustration/{label}` serves the static hero PNG (SAFE/SUSPICIOUS/MALICIOUS), `/dot/{severity}` serves the severity-dot icon, `/logo.png` serves the Swellscan brand logo. All static endpoints carry a 1-hour cache.
- **Live revision:** `swellscan-backend-00024-wmr` (Task 31.5 final - urlscan wire-up + relaxation + query-format fix + demo 9 builder; Tier 1 + Tier 2 cleanup landed first).
- **Tests:** **183 passing** (53 V1 + 83 V2 + 31 Task 31 regressions + 5 Task 31.5 urlscan-detector tests + 11 urlscan client tests). `pytest` from repo root runs all.
- **Detectors (8 total, was 7 in V1):** headers, sender, urls, attachments, prompt-injection, sender-baseline, llm, **plus V2 detector `bec_language`** (payment-instruction-urgency BEC defense).
- **New signals in V2 + Task 31.5 (4):** `PAYLOAD_FRAGMENTATION_ATTEMPT` (prompt-injection, V2.S5), `PAYMENT_INSTRUCTION_URGENCY` (bec_language, V2.S6), `RETURN_PATH_DOMAIN_MISMATCH` (headers, V2.S3b), `URL_BEHAVIORAL_FLAGGED` (urls, Task 31.5). Also wired up the previously-dormant `ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE` enum to a real detection rule.
- **Three signature features built and verified end-to-end:**
  1. **Self-defending LLM** - Task 10 prompt-injection detector + Task 14 hardened Anthropic client + V2.S2 defense-in-depth sanitization layer (hidden HTML strip, Unicode Tags block U+E0000-U+E007F strip, markdown image / reference-link strip, global zero-width strip, closing-tag-mimic neutralization)
  2. **Layered detection with correlation engine** - Task 15 pipeline + Task 4 thresholds + V2.S7 correlation rules (4 attacker-playbook bonuses: credential-harvesting trio, AI-targeted, impersonation, thread-hijack signature)
  3. **Per-sender baseline** - Task 17 backend detector + Task 27 Add-on `UserProperties` writer with `LockService` + `message_id` ring-buffer idempotency
- **GCP project:** `swellscan-prod` (project number `102679409749`), owned by `swellscan.demo@gmail.com`, billing on free trial. Three secrets in Secret Manager.
- **OIDC_AUDIENCE** (updated 2026-05-13 during Task 28 Step 4.5): `812475821064-s838lvgcgmc1nj4lbjqivpa48usi4t8v.apps.googleusercontent.com` - the Apps Script project's OAuth client ID, NOT the Cloud Run URL.
- **Card visual is LOCKED:** canonical mockup at `addon/design-refs/preview-final-v2.png`. Live card in Gmail matches. The verdict-card BODY is now LLM-generated for SUSPICIOUS/MALICIOUS (V2.S8 prompt synthesizes multiple signals into one flowing sentence) and 4-variant templated for SAFE (V2.S12: relationship + auth, new-sender + auth, minor-findings-present, truly-clean).
- **What's next:** **Phase 6 Task 32** (pip-audit + security-review skill pass, both fronts of security posture). Then Task 34 (README) → Task 35 (CLAUDE.md final refresh) → Task 37 (PDF cover) → Task 38 (submit email) → Task 39 (handoff). Submission deadline Fri 2026-05-15 EOD.

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

**V2 tasks (Task 33 → 11 accepted research findings + post-deploy fixes):**

| V2 task | Commit | What |
|---|---|---|
| V2 plan + lang bank | `a42084a` | V2 implementation plan at `docs/superpowers/plans/2026-05-13-swellscan-v2.md` + Upwind RSAC language bank at `docs/superpowers/specs/language-bank.md` |
| V2.S1 | `ed5c3a7` | 7 new risky extensions (SVG, HTML, HTM, ISO, IMG, VHD, VHDX) - `.hta` was already in V1 |
| V2.S2 | `eca1cc7` | LLM client defense-in-depth: hidden HTML strip, Unicode Tags strip, markdown image/ref strip, global zero-width strip; closing-tag strategy changed from zero-width-insert to `[removed]` |
| V2.S3a | `9c0a96c` | Reply-To severity scaling (freemail=HIGH, different-corporate=MEDIUM, subdomain=no signal) - also fixes V1 over-fire on subdomain Reply-To |
| V2.S3b | `798d8bc` | Return-Path mismatch detection wired (field was already plumbed end-to-end in V1) + 18-domain transactional-mailer allowlist |
| V2.S4 | `80fa60a` | Password-archive correlation: encrypted archive + body password-token co-occurrence wires up dormant `ATTACHMENT_PASSWORD_PROTECTED_ARCHIVE` enum |
| V2.S5 | `772a234` | `PAYLOAD_FRAGMENTATION_ATTEMPT` signal: 5+ short quoted tokens + assembly verb |
| V2.S6 | `7974e37` | New detector `bec_language.py` - `PAYMENT_INSTRUCTION_URGENCY` signal: urgency word within 100 chars of payment-instruction word, OR standalone "change of banking details" phrase |
| V2.S7 | `52585db`, `151489b` | Correlation engine: 4 attacker-playbook rules in `CORRELATION_BONUSES` (credential-harvesting trio, AI-targeted, impersonation, thread-hijack signature) |
| V2.S8 | `40205a7`, `912f0c7`, `8422cf6` | Readable verdict summary body: LLM-generated for SUSPICIOUS/MALICIOUS (with multi-signal synthesis prompt), template for SAFE. `summary_body` field added to `LLMVerdict` Pydantic schema |
| V2.S9 deploy | (revision `00009-v4n`) | Single deploy covering V2.S1-S8; live scan caught 3 false-positive bugs that V1 had but never surfaced |
| V2.S10 | `2e2ca2d`, `1e630e7`, `89e06db` | Fix A: sender legitimate-subdomain handling (`accounts.google.com` was false-flagging as Google lookalike). Fix B: cousin subdomains under same registrable parent (last-2-DNS-labels heuristic; `accounts.google.com` ↔ `gaia.bounces.google.com` now same-org). Fix C: SAFE template based on verdict label, not evidence severity (SAFE-by-score with one MEDIUM-low-conf signal now correctly uses template, not V1 fallback) |
| V2.S11 deploy | (revision `00010-nm6`) | Single deploy covering V2.S10 fixes |
| V2.S12 | `e602dc6` | Four-variant SAFE body templates (relationship+auth-pass, new-sender+auth-pass, minor-findings, truly-clean) - replaces single static SAFE template; Option B priority (relationship wins over minor-findings when both match) |
| V2.S13 deploy | (revision `00011-bpj`) | Single deploy covering V2.S12 |
| V2.S14 | `cd8a79a` | Multi-audience OIDC support (`OIDC_AUDIENCE` env var now comma-separated) + per-user rate limiter (100 calls / 24h sliding window via `backend/rate_limit.py`, in-memory approximate, wired into `verify_request` after the allowlist check) + Cloud Run `--max-instances=10` flag. Unblocks Path A install in README (other Apps Script projects can share this backend). Defense-in-depth combo: Anthropic prepaid $5 balance (hard cap) + monthly limit $20 + per-user rate limit + max-instances. Live revision `00012-nhf`. |

**Task 31.5 commits (Tier 1 + Tier 2 cleanup, urlscan wire-up, demo 9):**

| Task 31.5 step | Commit | What |
|---|---|---|
| Tier 1 #1 | `c8f6e74` | Shared security-pattern module - `backend/_security_patterns.py` becomes the single source of truth for the closing-tag-mimic regex and the zero-width-character regex. Both prompt_injection detector and the LLM client sanitizer import from there, enforcing the "sanitizer strips what detector flags" contract by construction. |
| Tier 1 #2 | `07680b8` | Unified FREEMAIL set - the headers detector and the sender detector held two divergent freemail-domain sets (one had 8 entries, one had 6) with an explicit TODO to consolidate. Moved canonical superset to `backend/_freemail.py` as a frozenset; both detectors import from there. |
| Tier 1 #3 | `3731178` | OIDC audience cache + empty-list refusal at import - the audience env var is parsed once at module load instead of every request, AND the container now refuses to start if `OIDC_AUDIENCE` parses to an empty list (google-auth's `verify_oauth2_token(audience=[])` silently skips the audience check - so a misconfigured/blank env var would have turned the backend into an open relay). |
| Tier 1 #4a | `44bcad4` | urlscan wired up as the third URL-reputation source (closes a four-document plan-drift: design doc / V1 plan prose / V2 plan limitations all claimed 3 sources, V1 plan code block reserved the client slot but never called `search_existing()` in run()). Conservative MEDIUM/0.7 weighting, gap-only emission (suppressed when VT or SB already flagged the URL), `URLSCAN_ENABLED` env-var kill switch, URL-encoding hardening, structured failure logging. |
| Tier 1 #4b | `c383a4c` | urlscan wrapper relaxed - anonymous urlscan API returns empty `verdicts` blob (strict consensus field is paid-tier); wrapper now also fires on urlscan's automated verdict OR `phishing`/`malicious` task tags. Downstream noise bounded by the conservative scoring + gap-only emission. |
| Tier 1 #4c | `86bbf2a` | urlscan query-format bug fix - the wrapper queried `page.url:https://...` which urlscan's parser interpreted as `page.url:https` plus junk, matching no scans even when the URL was indexed. Wrap URL in double quotes inside the query so colons in `https://` stay part of the value. Real production bug, only surfaced because we tried to verify a known-indexed URL by hand. |
| Tier 2 #5 | `be7bedb` | Score + label computed once per request - was computed three times (LLM-gate, body-builder branch, build_verdict). Pipeline.run now passes precomputed `score` and `label` into both `_summarize` and `build_verdict`. Closes a drift surface for future scoring-policy tweaks. |
| Tier 2 #6 | `5d41526` | `LLMDetector.name` constant replaces `"llm"` string literal in api/score.py log line. The `pipeline.py` `== "SAFE"` was already replaced with `VerdictLabel.SAFE` during the score-once refactor. |
| Tier 2 #7 | `cd3f0d4` | `max()` replaces `sorted()[0]` for top-evidence selection - one-pass instead of full sort. |
| Demo 9 | `61c0ff5` | Demo 9 (blocklist-bypass / fresh-domain phishing URL). Clean vendor-quote email; only signal is URL_BEHAVIORAL_FLAGGED. SAFE label with a single MEDIUM finding - demonstrates the nuanced "signal-over-noise" verdict layer rather than binary classification. |
| Cleanup backlog | `d8e749a` | V2 plan now contains the explicit "Cleanup deferred from Task 31.5 (before next production deploy)" subsection with the 4 items the README's Future Work section surfaces under that heading (header detector consolidation, shared VirusTotalClient, domain_of helper, Add-on detectors-fired count duplication). |

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

**V2 plan-drift catches (interview material):**

- **V2.S1** risky-extension list - plan claimed 8 new extensions; `.hta` was already in V1's RISKY_EXTENSIONS, so 7 net new. Caught by reading V1 attachments.py before writing.
- **V2.S3a/b** test fixture kwarg - plan tests used `authentication_results=` but `make_email` actually takes `auth_results=`. Renamed in tests.
- **V2.S3b** end-to-end plumbing - plan estimated 30-60 min cross-stack work; reading V1 code revealed `EmailHeaders.return_path` field and `client.gs::parseHeaders` Return-Path extraction were already there. Backend-only ~25 min instead.
- **V2.S4** MITRE technique - plan suggested T1027.002 (Software Packing) for password-archive correlation; correct technique is T1027.013 (Encrypted/Encoded File). Switched.
- **V2.S7** correlation test math - plan tests used `Severity.CRITICAL` on URL_KNOWN_MALICIOUS in the credential-harvesting trio test (40 raw); plus two other HIGH signals = ~90 raw, capped at MAX_SCORE=100, swallowed the +15 bonus, made `adjusted >= raw + 15` fail. Lowered test severities, tightened assertion to `==`, added explicit cap-behavior test.
- **V2.S8** SAFE branch trigger - originally used `all evidence INFO/LOW` to fire SAFE template. Live scan (V2.S9) caught that a SAFE-by-score email with ONE MEDIUM-low-confidence signal fell through to V1 top-evidence fallback (showed "Body contains a long base64-like string" on a SAFE card). V2.S10 fix C changed the check to compute final score + use `label_from_score()` directly.
- **V2.S10** sender false-positive - V1 lookalike detector flagged legitimate `accounts.google.com` because `from_domain not in legit_domains` was True for ANY subdomain. V1 had this bug; never caught because V1 tests only covered typo-squat variants. Surfaced only by V2.S9 dogfooding on a real Gmail inbox.
- **V2.S10** cousin-subdomain false-positive - V2.S3b subdomain check (`endswith("." + other)`) only caught direct subdomain relationships, not cousin subdomains under a common parent. `accounts.google.com` ↔ `gaia.bounces.google.com` were treated as cross-org mismatch. Fix: compare last-2-DNS-labels (registrable parent).

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
| `backend/auth.py` | OIDC ID-token verification via Google JWKs + email allowlist check + V2.S14 per-user rate-limit gate |
| `backend/rate_limit.py` | V2.S14 in-memory sliding-window per-user rate limiter (100 calls / 24h). Called from `verify_request`. |
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
  --set-env-vars="ALLOWED_USERS=swellscan.demo@gmail.com,OIDC_AUDIENCE=812475821064-s838lvgcgmc1nj4lbjqivpa48usi4t8v.apps.googleusercontent.com,URLSCAN_ENABLED=true" \
  --max-instances=10 \
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
- `docs/superpowers/specs/language-bank.md` — Upwind-RSAC-aligned phrasing for README + 60-sec pitch + interview narrative. Use phrases here verbatim where they fit.
- `docs/superpowers/plans/2026-05-12-swellscan-implementation.md` — The V1 implementation plan (Tasks 1-39). **Treat code blocks inside it as logic-spec / pseudo-code, not source-of-truth** — see the `feedback_plan_code_is_spec_not_source.md` memory for why. The plan was written speculatively in one pass; multiple bugs surfaced during execution (see "Plan-vs-implementation drift caught" table above). Tasks 36 and 36.6 in this file are superseded by V2.S7 and V2.S8.
- `docs/superpowers/plans/2026-05-13-swellscan-v2.md` — The V2 implementation plan (research-driven enhancements V2.S1-V2.S9). **Same skepticism rule applies.** Completed and shipped via revisions `00009-v4n`, `00010-nm6`, `00011-bpj`, `00012-nhf`. V2.S10-S14 are post-V2.S9 additions documented in commits + memory.
- `.claude/HANDOVER.md` — Canonical session brief for fresh AI sessions. Updated 2026-05-14 with V2 completion state.
- Memory files at `C:\Users\lotan\.claude\projects\c--Users-lotan-Projects-Upwind\memory\` — captures user preferences, project plan, demo strategy, **live deploy state** (`project_deploy_state.md` — URLs, GCP IDs, IAM, env vars), Upwind research, and V2 narrative beats. The `MEMORY.md` index lists all of them.
