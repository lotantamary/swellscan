# Swellscan - Session Handover

This file is the briefing for any AI session picking up Swellscan mid-implementation. The same text gets pasted into the chat when starting a fresh session for maximum first-turn compliance. The on-disk copy exists as (1) a mid-session memory refresh, (2) a starting point for short future-session prompts, and (3) project documentation.

**THE WOW MOMENTS MUST LAND ON BOTH CHANNELS - STAY FOCUSED** (added 2026-05-15). Swellscan goes through two grading lenses: (1) the README that Bar Naor reads BEFORE the interview - graded artifact, first impression; (2) the 45-minute live presentation where Lotan walks through architecture, demos against real Gmail, fields probing questions.

**The wow moments are ALREADY LOCKED.** The full list lives in memory file `project_demo_backbone.md` - 13 moments + 8 demo emails, established earlier this project. **DO NOT INVENT NEW MOMENTS** for the README or live demo. The next session amplifies what's locked, it does not scatter into new ideas. Focused beats comprehensive: Lotan needs to walk into the interview knowing 13 specific things he can defend, not 30 vague claims.

**The README does NOT show everything about the product.** It shows the BACKBONE - the structure that Bar Naor reads to understand the project at a glance. The README structure is ALREADY LOCKED in the parent implementation plan at **Task 34 Step 1** (markdown outline with sections: The problem / What Swellscan does / Three deliberate design choices / Architecture / Setup & deployment / Trade-offs and limitations / What I'd build next / Scalability note / Tech stack / Tests / Security posture / Acknowledgements). Use this structure. Do not add new top-level sections. Each section foregrounds the relevant locked moments from `project_demo_backbone.md`.

**Live-demo prep, also focused.** Every demo screenshot has a corresponding narrative beat ("when this happens, here's what you say"). The 12 dogfood plan-drift catches collapse into 3-4 rehearsed stories (not 12 individual ones). The security-first-on-both-fronts gets a 60-second whiteboard pitch. The "Upwind philosophy applied to a new domain" framing is the 30-second demo opener. Lotan rehearses these specific beats - he does not improvise.

A clean README the recruiter remembers + a live demo where she walks out citing specific signature moments = the goal. Focused. Not scattered.

**SECURITY-FIRST: THE PRODUCT MUST DEFEND ITSELF ON EVERY FRONT** (added 2026-05-15). The product's job is to score malicious email, but its OWN security posture is equally critical and graded under the assignment's "security awareness" rubric. The Task 31.5 cleanup and Task 32 security review must verify that the product is hardened against TWO threat vectors:

1. **Email-borne attackers** (the obvious one): self-defending LLM, body sanitization, untrusted-content wrapping with random-nonce tags, output validation, Pydantic-enforced schema, no tool use / no outbound calls from the LLM, hash-only attachment handling, reputation-API delegation for URLs (no direct fetching).

2. **Attackers targeting the product itself** (the often-missed one): OIDC token authentication with no long-lived shared secrets, asymmetric crypto via Google JWKs, ~1-hour token validity, per-user rate-limiter at the auth boundary (V2.S14), Cloud Run `--max-instances=10` for parallelism cap, Anthropic prepaid $5 hard cap + monthly $20 spend limit (cost-exhaustion attack defense), Secret Manager (not env vars in code), stateless backend (no PII repository to leak), email body never persisted, structured-logging field allowlist (DO log: request_id, sender DOMAIN only, score, verdict, latency; NEVER log: body, subject, recipient, attachment filenames, URLs, hashes), non-root container user, app-layer OIDC enforcement (not IAM), ALLOWED_USERS allowlist + OIDC_AUDIENCE allowlist.

Both fronts must be verified - end to end - during the cleanup + security review. The product is a security product; its own security IS the product's character witness.

**Last updated: 2026-05-15 (submission day), end of "Phase 6 cleanup + security" session. Tasks 29-32 ALL COMPLETE. Live revision `swellscan-backend-00027-4s8`. 186 tests passing. 6 planned demos + 3 spares (demos 7, 8, 9 - demo 9 NEW this session: urlscan blocklist-bypass) all verified end-to-end. Task 31.5 surfaced 17+ cleanup candidates across simplify + code-review skills; 7 landed as Tier 1/2, 4 deferred to README backlog, urlscan wire-up + cache fix landed as bonus work. Task 32 cleared 3 pip-audit CVEs (fastapi/starlette/python-dotenv bumped) and security-review skill found no high-confidence findings. Next session opens at Task 34 (README full content - creativity emphasis), then Task 35 (CLAUDE.md final refresh), Task 37 (PDF), Task 38 (SUBMIT).**

---

I'm continuing work on Swellscan - my home assignment for Upwind Security (a cybersecurity company I'm interviewing with). After I submit it, I will present the project live to their recruiting team in a 45-minute interview, where every architectural and product decision will be questioned. I need to be able to defend each choice myself, in my own words.

═══════════════════════════════════════════════════════════════════════
## GOALS - what we're walking toward
═══════════════════════════════════════════════════════════════════════

Submission deadline: Fri 2026-05-15 EOD.
Demo interview: ~Mon 2026-05-18, 45 minutes, live with Bar Naor and the Upwind hiring team.

Evaluation rubric we're optimizing for (in priority order):
  - Product thinking (which capabilities chosen and why)
  - Creativity (going beyond the obvious - Swellscan's three signature moments)
  - Architecture & design (how components fit, reasoning)
  - Code quality (readability, structure, hygiene)
  - Security awareness (untrusted input, secrets, sensitive data)
  - Communication (README + verbal narrative are first-class deliverables)

These criteria live verbatim in the memory file `project_upwind_assignment.md` along with the hard constraints (Apps Script, real Gmail deployable, public git repo, live demo).

═══════════════════════════════════════════════════════════════════════
## WORKING STYLE I NEED FROM YOU
═══════════════════════════════════════════════════════════════════════

- HARD STOP after every numbered task in the plan. Don't read the next task until I say "go" / "continue" / "next". Between tasks, write a short plain-words recap I could re-read as interview rehearsal material.
- Keep recaps SHORT. Lead with substance. Cut routine decisions. Only surface choices an interviewer would actually probe.
- For every meaningful decision, surface: what we chose, what we rejected, and why. NEVER lead with "simpler" or "for a 4-day demo" as the justification. If a real trade-off exists, present both options honestly with their real strengths and weaknesses.
- Explain non-trivial moves as you make them. I'm a student new to cybersecurity - define every cyber term the first time it appears and tie it back to why our architecture needs it.
- Announce phase transitions before starting the first task in a new phase. We've just finished Phase 5 (Add-on live and working in real Gmail). The next session opens Phase 6 - polish + submission, the last phase before the home assignment is shipped.
- **No em-dashes in any user-facing copy.** Only plain ASCII hyphens (`-`). Em-dash (`—`) is an AI tell; we keep the writing readable as human-authored. Applies to card copy, README, button labels, evidence explanations, any string the user could read. Internal docs (this file, CLAUDE.md, design doc, plan) are exempt. See `feedback_no_em_dashes.md`.
- **Cloud Run deploys always use the full-source rebuild command** (`gcloud run deploy swellscan-backend --source . --region us-central1`), never `services update` even for env-var-only changes. One uniform deploy pattern; time and cost are not constraints. See `feedback_always_full_source_deploy.md`.

═══════════════════════════════════════════════════════════════════════
## CRITICAL - THE PLAN IS A LOGIC SPEC, NOT SOURCE-OF-TRUTH
═══════════════════════════════════════════════════════════════════════

The implementation plan at `docs/superpowers/plans/2026-05-12-swellscan-implementation.md` contains code blocks inside every numbered task. Those code blocks were written by a planner agent in one pass with no execution, no compiler, no tests run. **TREAT THE PLANNED CODE AS PSEUDO-CODE / REFERENCE LOGIC.**

How to actually work with it:

1. Read the planned code as a description of intent. Understand what it's trying to do.
2. BEFORE writing anything, mentally trace the planned code against the planned test. If the trace doesn't work, the plan has a bug - surface it to me, propose a fix, then proceed.
3. Scan the task for references to artifacts changed in earlier tasks (renamed fields, fixture defaults, function signatures). The plan can't update itself; cross-task drift is real.
4. Use the plan's structure and tests as the contract; reconstruct the body deliberately. Identical results are fine for trivial data (Pydantic models, regex constants, palette dicts). Logic code should pass through your own brain.
5. When you DO find a bug in the planned code, surface it explicitly in the recap - those moments are gold for interview ("I followed the plan but the test caught a logic error in step X; I traced it, fixed it, here's why my fix is right"). I want a couple of these.

Several plan bugs have already surfaced and been documented in the plan's "Known plan-vs-implementation drift" table (Tasks 8, 9, 19, 24, 25, 28). Look there for the running pattern.

═══════════════════════════════════════════════════════════════════════
## READ THESE FILES IN ORDER to orient
═══════════════════════════════════════════════════════════════════════

  1. `swellscan/CLAUDE.md` (project map at repo root)
       → Read first. Updated 2026-05-14 with V2 completion state. Has the live Cloud Run revision, V1 + V2 task tables with commit SHAs, V1 + V2 plan-drift catches, the "what's next" pointer. Single best snapshot of where we are.

  2. `swellscan/docs/superpowers/specs/2026-05-12-swellscan-design.md`
       → The authoritative design document. Every architectural and product decision lives here. Card visual decisions are locked - the canonical visual reference is `addon/design-refs/preview-final-v2.png` and the live card now matches it.

  3. `swellscan/docs/superpowers/plans/2026-05-12-swellscan-implementation.md`
       → The V1 implementation plan (Tasks 1-39). Read the "Progress" section at the top + the V2-decision-point note on Task 30. Apply the skepticism rule (code blocks are logic-spec, not source).

  4. `swellscan/docs/superpowers/plans/2026-05-13-swellscan-v2.md`
       → The V2 implementation plan (research-driven enhancements V2.S1-V2.S9). Completed and shipped. V2.S10-V2.S13 are post-deploy fixes documented in commits + CLAUDE.md, not in this plan file. Read the "Code-state findings" section at the top to see what V1 code state V2 was built against.

  5. `swellscan/docs/superpowers/specs/language-bank.md`
       → Upwind-RSAC-aligned phrasing for the README and the 60-second pitch. Use these phrases verbatim where they fit. Created 2026-05-13 in V2.S1.

═══════════════════════════════════════════════════════════════════════
## WHERE TO LOOK FOR SPECIFIC THINGS
═══════════════════════════════════════════════════════════════════════

  - Live backend URL, GCP project ID, allowlisted user, OIDC audience, secret names, IAM grants, cleanup-at-end commands
      → memory file `project_deploy_state.md`
      → Also restated in `CLAUDE.md` "Current State"

  - The three stand-out moments (self-defending LLM, wave verdict card with character arc, per-sender baseline)
      → design doc §3.1-3.3

  - The rubric items and how each decision maps to them
      → memory file `feedback_deliberate_creative_edge.md`
      → design doc has rubric-mapping baked into many sections

  - Upwind's voice + published patterns we're deliberately mirroring (especially the RSAC 2026 layered AI-prompt-detection paper)
      → memory file `reference_upwind_research.md`

  - The actual home-assignment text from the recruiter
      → `C:\Users\lotan\Projects\Upwind\task-instructions\` - sits OUTSIDE the swellscan repo on purpose, never committed, but available locally when you need to re-check what the assignment asks for

  - The canonical card visual (locked 2026-05-13)
      → `swellscan/addon/design-refs/preview-final-v2.png` - all six states (3 verdicts × 2 widths). The live card in Gmail matches this.

═══════════════════════════════════════════════════════════════════════
## MEMORY FILES (particularly load-bearing right now)
═══════════════════════════════════════════════════════════════════════

Memory directory: at `C:\Users\lotan\.claude\projects\c--Users-lotan-Projects-Upwind\memory\`. The `MEMORY.md` index lists all of them. ALL inform how you work.

The ones most important to read FIRST for the upcoming work:

  - `feedback_stop_after_every_task.md` - the hard-stop + recap cadence
  - `feedback_plan_code_is_spec_not_source.md` - THE rule about the plan; I asked specifically that this be the prompt's headline
  - `feedback_explain_as_we_go.md` - running tutor mode for me
  - `feedback_dont_frame_choices_as_convenience.md` - never lead with "simpler" - show both sides honestly
  - `feedback_announce_phase_transitions.md` - phase boundaries get explicit call-outs
  - `feedback_deliberate_creative_edge.md` - every decision needs a story that ties to a rubric item or Upwind value
  - `feedback_mobile_aware_design.md` - UI must work on desktop AND iOS/Android Gmail apps
  - `feedback_no_em_dashes.md` - plain ASCII hyphens only in user-facing copy
  - `feedback_always_full_source_deploy.md` - `gcloud run deploy --source .` for every Cloud Run change
  - `project_deploy_state.md` - live URL + GCP IDs + env vars; updated 2026-05-14 with current revision `00012-nhf` + V2.S14 (multi-audience OIDC + per-user rate limiter + max-instances=10 + Anthropic cost-protection prerequisites)
  - `project_v2_complete.md` (NEW 2026-05-14) - V2 narrative summary: what shipped, key interview beats, the "live-scan caught V1 bug" story
  - `reference_v2_plan_drift_catches.md` (NEW 2026-05-14) - the catches in V2 that became interview material

═══════════════════════════════════════════════════════════════════════
## CURRENT STATE OF THE CODE
═══════════════════════════════════════════════════════════════════════

  **V1 + V2 + Phase 6 (Tasks 29-32) ALL complete.** Next: Task 34 (README full content - **creativity emphasis**) → Task 35 (final CLAUDE.md refresh) → Task 37 (PDF cover sheet) → Task 38 (submit). Submission deadline TODAY 2026-05-15 EOD.

  Backend status: BUILT, TESTED, DEPLOYED post-Task-32. **186 tests passing** (167 from Task 31 + 14 new urlscan client tests + 3 send-time-anomaly range tests + 2 query-format tests).

    Live URL: https://swellscan-backend-102679409749.us-central1.run.app
    Live revision: swellscan-backend-00027-4s8  (Task 32 final - pip-audit deps bump: fastapi 0.136.1 + starlette 1.0.0 + python-dotenv 1.2.2, all 3 CVEs cleared)
    /health                  → {"status":"ok"}
    POST /score              → OIDC-protected (401 on bad tokens)
    /illustration/{label}    → static PNG, 1-hour cache
    /dot/{severity}          → static colored-dot PNG, 1-hour cache
    /logo.png                → Swellscan brand logo, 1-hour cache

  Add-on status: INSTALLED, WORKING. Six files in `addon/`:
    - `appsscript.json` - manifest (Gmail scopes, logoUrl pointing at /logo.png)
    - `setup.gs` - one-time config (writes BACKEND_URL + OIDC_AUDIENCE to ScriptProperties)
    - `client.gs` - HTTP wrapper with OIDC bearer + Gmail payload builder
    - `render.gs` - verdict card builder (palette-driven, severity-colored title, no bullet)
    - `Code.gs` - onGmailMessageOpen auto-scan trigger + 3 lifeguard-voice stub button handlers
    - `baseline.gs` - per-sender history in UserProperties with LockService + message_id idempotency

  **Detectors: 8 total** (V1 had 7). New in V2: `bec_language.py` for BEC payment-instruction urgency.

  **V2 additions live in production:**
    - V2.S2 defense-in-depth LLM sanitization: hidden HTML strip, Unicode Tags block (U+E0000-U+E007F) strip, markdown image / reference-link strip, global zero-width strip, closing-tag-mimic neutralization (strategy change from V1's zero-width-insert to "[removed]" substitution)
    - V2.S3a Reply-To severity scaling (freemail Reply-To from corporate = HIGH; different corporate = MEDIUM; subdomain = no signal - fixes V1 over-fire)
    - V2.S3b Return-Path mismatch detection + 18-domain transactional-mailer allowlist
    - V2.S4 Password-protected-archive correlation (wired up dormant V1 enum)
    - V2.S5 Payload-fragmentation prompt-injection signal
    - V2.S6 `bec_language` detector with PAYMENT_INSTRUCTION_URGENCY signal
    - V2.S7 correlation engine: 4 attacker-playbook bonuses
    - V2.S8 readable verdict-body: LLM-synthesized for risky verdicts (with multi-signal weave directive), templated for SAFE
    - V2.S10 Fix A: sender legitimate-subdomain handling (V1 lookalike bug that flagged `accounts.google.com` as Google lookalike)
    - V2.S10 Fix B: cousin-subdomain handling for Reply-To / Return-Path (last-2-DNS-labels heuristic for registrable parent)
    - V2.S10 Fix C: SAFE body uses verdict label, not evidence severity
    - V2.S12 four-variant SAFE body templates (relationship+auth, new-sender+auth, minor-findings, truly-clean)
    - V2.S14 multi-audience OIDC support (`OIDC_AUDIENCE` env var is now comma-separated; unblocks "Path A" install for other Apps Script projects sharing this backend) + per-user rate limiter (`backend/rate_limit.py`, 100 calls / 24h sliding window, in-memory approximate, wired into `verify_request`) + Cloud Run `--max-instances=10` flag

  **Task 31.5 (cleanup) + Task 32 (security) additions this session:**
    - Tier 1 cleanup: shared security-patterns module (sanitizer/detector regex parity), unified FREEMAIL set, OIDC audience cache + empty-list refusal at import (the latter is a real auth-hardening fix - google-auth's verify_oauth2_token silently skips audience verification when given an empty audience list)
    - Tier 1 #4: urlscan wired up as the third URL-reputation source. The design doc + V1/V2 plans all promised three reputation sources; code only wired two until this session. Wrapper relaxed to fire on urlscan's phishing/malicious tags (anonymous API doesn't expose the strict consensus field); query-format bug fix (URL must be wrapped in quotes inside page.url:...); timeout bumped 4s -> 15s; gap-only emission so urlscan only fires when VT and SB are both silent.
    - Demo 9 (spare): blocklist-bypass / urlscan moment. Atlas Logistics quote email with a real urlscan-flagged URL on Tencent EdgeOne CDN that VT and Safe Browsing have not yet indexed. SAFE/7/100 with one finding: `Url behavioral flagged`. Demonstrates the nuanced "signal over noise" verdict layer rather than binary classification.
    - Tier 2 cleanup: score computed once per request (instead of three times), stringly-typed comparisons replaced with VerdictLabel.SAFE and LLMDetector.name, max() instead of sorted()[0] for top-evidence selection.
    - Tier 1+2 of code-review skill: LLM trust boundary expanded to cover all three prompt tags (evidence_json, email_metadata, untrusted_content) - not just the wrapped body - so a hostile subject or display_name can't smuggle directives past the LLM. _sanitize_body now also applied to subject and display_name (the same V2 sanitization stack the body got). Send-time anomaly fix: was set-membership against observed hours (false-positive engine), now range check with min-3-observations gate. SAFE Variant 1/2 bodies excluded when DMARC_FAIL is in evidence (was a card-displayed-lie - "identity checks out" with DMARC_FAIL in findings). MITRE tags added to SPF_SOFTFAIL + MISSING_MESSAGE_ID. Exception logging redacted on safebrowsing + virustotal clients (Safe Browsing puts API key in URL; httpx exception __str__ rendered the key into logs). CLAUDE.md deploy snippet brought back in sync with prod (had stale OIDC_AUDIENCE URL form + missing max-instances + missing URLSCAN_ENABLED).
    - Add-on cache fix (Code.gs): the Gmail Add-on framework re-invokes onGmailMessageOpen twice per open. The first scan trains the baseline on the just-observed signals; the second scan reads the now-polluted baseline and returns a degraded verdict. Cache the first verdict per message_id (5-min TTL) so phantom re-invocation returns the cached card. Only demo 6 (BEC thread-hijack) showed the bug visibly - it leans entirely on baseline drift signals - but the fix is global.
    - Task 32 (pip-audit): 3 CVEs cleared by bumping fastapi 0.115.6 -> 0.136.1, starlette 0.41.3 -> 1.0.0, python-dotenv 1.0.1 -> 1.2.2. starlette upgrade was a major-version jump; live-tested all 9 demos on the bumped revision, all verdict labels preserved.
    - Task 32 (security-review skill): final defensive sweep. Result verbatim: "No high-confidence findings beyond what is already addressed." Auth + path-serving + external clients + LLM defense + Add-on rendering + baseline storage + container hygiene + Pydantic boundaries + rate-limit keyspace + secret handling all verified clean.

  **Documentation refresh this session:**
    - design.md §3.1 (untrusted-content tag name), §3.2 (PNG vs SVG), §5.2 (Evidence.explanation max 2000), §6 ("eight detectors" + new §6.8 bec_language), §6.3 (URL_BEHAVIORAL_FLAGGED + urlscan rationale + gap-only emission + kill switch), §6.5 (PAYLOAD_FRAGMENTATION_ATTEMPT), §6.7 (LLM threshold corrected from "25-75 band" to ">= 25"), §7.5 (timeout 30s), §9.2 (multi-audience OIDC + empty-list refusal + per-user rate limiter), §9.4 (deploy command with OAuth client ID + URLSCAN_ENABLED + max-instances), §6.2 + §6.3 (homoglyph + URL_TEXT_HREF_MISMATCH softened to honest "leetspeak only, Unicode confusables in Future Work").
    - V2 plan got a new "Cleanup deferred from Task 31.5 (for README 'before next production deploy' section)" subsection with 4 items: Reply-To/Return-Path block consolidation, shared VirusTotalClient, domain_of() helper, Add-on detectors-fired count duplication. These go into the README's Future Work area under a "Cleanup before next deploy" subheading.

  **Demo set: 9 demos total** (6 planned 1-6, 3 spares 7-9):
    1. Google Cloud welcome (SAFE/0/100) - baseline-known SAFE reference
    2. Microsoft credential trio (MALICIOUS/100/100) - phishing playbook + correlation
    3. Dropbox lookalike (SUSPICIOUS/52/100) - brand impersonation, three-tier spectrum
    4. Prompt injection + tag-escape (MALICIOUS) - self-defending LLM headline
    5. invoice.zip + body password (SUSPICIOUS) - V2.S4 password-archive correlation
    6. BEC thread-hijack (MALICIOUS/100/100) - marquee BEC demo + thread-hijack correlation. Needs `resetDemoSeeds()` before the live show.
    7 (spare). Sanitization defeat (SUSPICIOUS/53/100) - V2.S2 layered sanitization visible
    8 (spare). invoice.pdf.exe (MALICIOUS/75/100) - classic double-extension
    9 (spare, NEW). Atlas Logistics blocklist-bypass (SAFE/7/100) - urlscan gap coverage

  All three signature features live and verified at V2 state:
    1. Self-defending LLM (V1 + V2.S2 defense-in-depth additions)
    2. Layered detection with correlation engine (V1 + V2.S7 bonuses)
    3. Per-sender baseline (V1 + V2.S6 thread-hijack cheap-version signal)

  GCP project: swellscan-prod (102679409749)
  Owner: swellscan.demo@gmail.com (also the demo Gmail account)
  Three secrets in Secret Manager.
  IAM: service-account-secretAccessor granted.
  OIDC_AUDIENCE = `812475821064-s838lvgcgmc1nj4lbjqivpa48usi4t8v.apps.googleusercontent.com` (the Apps Script project's OAuth client ID; captured during Task 28 Step 4.5)

═══════════════════════════════════════════════════════════════════════
## DESIGN IS LOCKED
═══════════════════════════════════════════════════════════════════════

The card design was iterated through six mockup versions during Phase 5 (2026-05-13) with full Lotan approval at each step. **The live card in Gmail now matches the canonical mockup at `addon/design-refs/preview-final-v2.png`.** Do not re-open the visual loop without explicit instruction.

Key locked decisions:
- Hero PNG (2:1 cropped illustrations Lotan provided): safe / suspicious / malicious served from `backend/illustration/assets/`
- White card body (CardService default; not customizable)
- Verdict line in palette color + bold, score 0-100 right-aligned next to label
- Meta line: `XXX conf · N detectors · LLM consulted/not needed`
- NO subject + sender row (removed 2026-05-13; the email is already visible in Gmail behind the sidebar, and any sender problem already shows up in the findings)
- Lifeguard-voice summary opener (palette-colored), short line break, italic body
  - SAFE: "All clear, you can paddle"
  - SUSPICIOUS: "Something off about this set"
  - MALICIOUS: "Out of the water on this one"
- Findings: `FINDINGS: N signals detected` header (count in palette color), each row palette-colored title + MITRE id inline + plain body, top 5 sorted by severity then confidence
- Action button: right-aligned anchored FixedFooter (CardService default; Material Design "primary action at trailing edge"). Try/catch fallback path attempts centered ButtonSet but fails silently to right-aligned on this Apps Script runtime.
- Per-state button text wired to lifeguard-voice notification stub handlers (real action wiring is Task 36.5 stretch).

═══════════════════════════════════════════════════════════════════════
## WHAT'S NEXT - PHASE 6 (POLISH + SUBMISSION)
═══════════════════════════════════════════════════════════════════════

This is the FINAL phase before the home assignment ships. Submission is Fri 2026-05-15 EOD.

Phase 6 has 10 active items now (Tasks 29-39 minus the original stretches, since V2 already absorbed Task 33 + Task 36 + Task 36.6). They group into four chunks:

| Chunk | Tasks | Why |
|---|---|---|
| **Demo data** | 29 (pre-seed UserProperties) → 30 (craft 5 demo emails) → 31 (manual end-to-end test against all 5) | The interview demo itself. Five emails the recruiter will watch you scan live. Must be flawless. |
| **Cleanup + security** | 31.5 (simplify + code-review) → 32 (pip-audit + security-review) | Last passes over the code before submission. |
| **Documentation** | 34 (README) → 35 (CLAUDE.md refresh) → 37 (PDF cover sheet) | README is graded. PDF is what reaches the recruiter. |
| **Submission** | 38 (email + repo + PDF) → 39 (handoff) | The button-press moment. |

Recommended sequence: 29 → 30 → 31 first (real testing while bugs are still fixable). Then 31.5 + 32. Then 34 + 35 (docs). 37 + 38 last.

**Tasks already absorbed by V2 (do NOT redo):**
- Task 33 (threat-research scan) - V2 executed this; output is the 11 accepted findings shipped V2.S1-V2.S8
- Task 36 (correlation engine) - V2.S7 supersedes
- Task 36.6 (verdict summary body) - V2.S8 supersedes

**Active stretch (only if time, post-submission):**
- Task 40 (NEW, was Task 36.5): Gandalf-style adversarial playground - public endpoint where the interviewer can try to jailbreak the LLM live in the demo call. Skip unless margin remains after Task 38 submission.

═══════════════════════════════════════════════════════════════════════
## COST PROTECTION (manual prerequisites SET 2026-05-14)
═══════════════════════════════════════════════════════════════════════

Three layers of defense-in-depth for backend costs:

1. **Anthropic prepaid balance: $5** - the actual hard cap. API stops accepting calls when balance hits zero. Cannot be charged more than what's prepaid.
2. **Anthropic monthly spend limit: $20** - safety net for IF a payment method is ever added later.
3. **Per-user rate limit: 100 calls / 24h** (V2.S14) + **max-instances=10** + **ALLOWED_USERS allowlist**.

Estimated per-scan cost: ~$0.01 when LLM fires. The $5 balance covers ~500 LLM-firing scans. Plenty for the demo + a few authorized testers.

═══════════════════════════════════════════════════════════════════════
## DECISION POINT BAKED INTO TASK 30
═══════════════════════════════════════════════════════════════════════

The V2.S6 BEC-language detector emits `PAYMENT_INSTRUCTION_URGENCY` but none of the 5 planned demo emails currently trigger it. Decide at Task 30 execution time:
- **Option A (recommended):** rework demo #2 (Microsoft phishing) to include payment-urgency language so V2.S6 fires on a demo card
- **Option B:** add a 6th BEC demo email
- **Option C:** keep planned 5; V2.S6 stays an architecture talking point without live-demo example

Note added to parent plan's Task 30 spec on 2026-05-13.

═══════════════════════════════════════════════════════════════════════
## REMEMBER FOR TASK 34 (README) - things discovered this session
═══════════════════════════════════════════════════════════════════════

These came up during V2.S10-V2.S14 and need to land in the README. They are NOT yet in the parent plan's Task 34 spec; the new session must remember them when writing the README:

**Install section: document both paths.**
- **Path A: Use shared backend (V2.S14 enables this).** Authorized user emails Lotan with their Gmail address + their Apps Script project's OAuth client ID. Lotan adds them to `ALLOWED_USERS` + `OIDC_AUDIENCE` env vars and re-deploys. ~15 min total including email round-trip.
- **Path B: Self-host backend.** Clone repo, set up own GCP project + billing + 3 API keys in Secret Manager + deploy Cloud Run. 1-2h depending on GCP familiarity.
- **Path C: Marketplace publication** (Future Work) - production-grade install via Google Workspace Marketplace after CASA security assessment.

**Future Work additions (beyond the 13 from the original research scan):**
- **Button-wired feedback loop + sender reputation memory** (combines deferred Task 36.5 button wiring with the prior-verdict-storage idea). User clicks a card button; sender reputation updates; future scans use the user-confirmed reputation as info-only signal. Avoids false-positive amplification by being user-driven.
- **Google Workspace Marketplace publication** as production-grade Path C.
- **Memorystore/Redis-backed exact rate limiting** - current V2.S14 limiter is in-memory approximate.

**Limitations additions:**
- Sender baseline tracks behavior (signing domains, IP prefixes, send hours), NOT reputation memory. A sender flagged MALICIOUS once will not be auto-distrusted on a later clean email. The button-feedback-loop Future Work item is the named upgrade path.
- Add-on requires test-deployment install (Apps Script copy-paste) until Marketplace publication.
- PSL gap on registrable-parent extraction: `.co.uk`-style cousin subdomains are treated as same-org. False-negative direction (missing a real mismatch), not false-positive. Acceptable trade-off vs adding the Public Suffix List as a dependency.

═══════════════════════════════════════════════════════════════════════
## IMMEDIATE NEXT ACTION
═══════════════════════════════════════════════════════════════════════

Start at **Task 34 (README full content)**. This is the GRADED artifact Bar Naor reads BEFORE the live interview. The structure is LOCKED in the parent implementation plan at Task 34 Step 1: The problem / What Swellscan does / Three deliberate design choices / Architecture / Setup & deployment / Trade-offs and limitations / What I'd build next / Scalability note / Tech stack / Tests / Security posture / Acknowledgements. Do not add new top-level sections. Each section foregrounds locked moments from `project_demo_backbone.md` (13 moments + 9 demos).

Sourcing for the README:
  - Three deliberate design choices: design doc §3.1 (self-defending LLM), §3.2 (wave + character arc), §3.3 (per-sender baseline). Plus the urlscan gap-coverage story from this session as a fourth design choice if the section can hold it, or fold into Architecture.
  - Architecture: design doc §4 invariants + §5 data model + §6 detectors (eight). Cross-check the eight detector names + signals against the actual `backend/detectors/` directory and `backend/models/evidence.py` Signal enum.
  - Setup & deployment: three install paths (A = use shared backend, B = self-host, C = Marketplace publication as Future Work). See HANDOVER.md "REMEMBER FOR TASK 34" section below for the canonical path A/B/C copy.
  - Trade-offs and limitations: V2 plan ## Limitations section (multi-modal, per-message, no URL fetching / no body persistence). Plus this-session additions: HIGH conf wording cosmetic, [198.51 IP-prefix cosmetic, automatic baseline learning (Future Work item), urlscan signal scoped to anonymous-API tag verdicts.
  - What I'd build next: V2 plan ## Future Work entries (the 13 from threat-research scan + this-session additions: full Unicode-homoglyph normalization, HTML link-text-href mismatch detection). PLUS a "Cleanup before next deploy" subheading with the 4 items from the V2 plan's Cleanup-Deferred subsection: Reply-To/Return-Path consolidation, shared VirusTotalClient, domain_of() helper, Add-on detectors-fired count duplication. Frame as "spotted and consciously deferred, not missed."
  - Security posture: BOTH FRONTS framing (email-borne attackers + attackers targeting the product itself). Pull the bullet list from this HANDOVER.md's SECURITY-FIRST block (lines 17-21). Mention pip-audit run + clean security-review skill pass on this session.
  - Tests: 186/186 passing. `pytest` from repo root.
  - Tech stack: see CLAUDE.md "Tech Stack & Environment" - mostly current, double-check fastapi 0.136.1 / starlette 1.0.0 / python-dotenv 1.2.2 after the pip-audit bump.
  - Acknowledgements: brief, deliberately Upwind-aligned ("applying Upwind's runtime-first / layered-detection philosophy to a new attack surface").

Locked copy + voice rules for the README (non-negotiable):
  - NO em-dashes. Plain ASCII hyphens only. Applies to every line of user-facing copy in the README.
  - Use phrases from `docs/superpowers/specs/language-bank.md` verbatim where they fit.
  - Frame Swellscan as *"applying Upwind's runtime-first / layered-detection philosophy to a new attack surface (email)"*. NEVER claim email is Upwind's domain; it isn't.
  - Three deliberate stand-out moments are LOCKED at memory `project_demo_backbone.md`. DO NOT INVENT new moments.
  - Scalability note required as the dedicated section per outline.
  - Screenshots already uploaded to `docs/screenshots/`. 12 files total: 9 demo cards (`demo-1-google-cloud-safe.png` through `demo-9-blocklist-bypass-safe.png`) plus 3 generic card-type images (`SAFE-CARD.png`, `suspicious-card.png`, `malicious-card.png`) for the "three deliberate design choices" section's character-arc illustration. Reference them inline in the README markdown: `![demo 1 - SAFE](docs/screenshots/demo-1-google-cloud-safe.png)`. They render automatically on GitHub when Bar Naor views the repo.

After Task 34 lands: Task 35 (final CLAUDE.md refresh - small, mostly already done this session), Task 37 (PDF cover sheet - assignment requires PDF as the email attachment), Task 38 (submit to ou-bootcamp-interviewers@upwind.io with the repo URL + PDF + brief email body).

Default skill: `superpowers:executing-plans`. Commit + push after every task. Hard-stop discipline after every task.

Pre-rehearsal / pre-live-show function order (lives in `_demo_seed.gs` inside the Swellscan Apps Script project):
  1. `clearSenderHistory()` - wipes any baseline state accumulated during testing. Does NOT delete emails.
  2. `seedDemoHistory()` - restores Anthropic + orbitalvendor canonical seeds. Demo 1's swapped Google Cloud sender will show Variant 2 ("first email...identity checks out") on a fresh run, not Variant 1 - both are valid SAFE bodies.
  3. Open demos 1 through 9 in order, each ONCE. Don't re-open within 5 min (cache TTL).

Git authorship is already configured correctly. Commits should be authored as my personal identity WITHOUT a Co-Authored-By trailer (commits should look like my own work on GitHub).

---

**About this file:** This same prompt is pasted inline into each fresh session for maximum first-turn rule binding. The on-disk copy at `swellscan/.claude/HANDOVER.md` exists so the agent can re-read it mid-session if rules drift, and so future sessions can use a short "read `.claude/HANDOVER.md`" prompt instead of re-pasting the whole thing.
