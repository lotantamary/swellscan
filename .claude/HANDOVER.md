# Swellscan - Session Handover

This file is the briefing for any AI session picking up Swellscan mid-implementation. The same text gets pasted into the chat when starting a fresh session for maximum first-turn compliance. The on-disk copy exists as (1) a mid-session memory refresh, (2) a starting point for short future-session prompts, and (3) project documentation.

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
       → Read first. Has a "Current State" section at the top with the live Cloud Run URL, completed-task table with commit SHAs, and the "what's next" pointer. This is the single best snapshot of where we are.

  2. `swellscan/docs/superpowers/specs/2026-05-12-swellscan-design.md`
       → The authoritative design document. Every architectural and product decision lives here. Card visual decisions are locked - the canonical visual reference is `addon/design-refs/preview-final-v2.png` and the live card now matches it.

  3. `swellscan/docs/superpowers/plans/2026-05-12-swellscan-implementation.md`
       → The numbered per-task plan. Read the "Progress" section at the top to see which tasks are done (with commit SHAs) and which are next. Then READ EACH TASK YOU WORK ON WITH THE SKEPTICISM RULE ABOVE - don't paste-and-pray.

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

Memory directory: 15 files at `C:\Users\lotan\.claude\projects\c--Users-lotan-Projects-Upwind\memory\`. The `MEMORY.md` index lists all of them. ALL inform how you work.

The ones most important to read FIRST for the upcoming work:

  - `feedback_stop_after_every_task.md` - the hard-stop + recap cadence
  - `feedback_plan_code_is_spec_not_source.md` - THE rule about the plan; I asked specifically that this be the prompt's headline
  - `feedback_explain_as_we_go.md` - running tutor mode for me
  - `feedback_dont_frame_choices_as_convenience.md` - never lead with "simpler" - show both sides honestly
  - `feedback_announce_phase_transitions.md` - phase boundaries get explicit call-outs
  - `feedback_deliberate_creative_edge.md` - every decision needs a story that ties to a rubric item or Upwind value
  - `feedback_mobile_aware_design.md` - UI must work on desktop AND iOS/Android Gmail apps
  - `feedback_no_em_dashes.md` - plain ASCII hyphens only in user-facing copy (added 2026-05-13)
  - `feedback_always_full_source_deploy.md` - `gcloud run deploy --source .` for every Cloud Run change (added 2026-05-13)
  - `project_deploy_state.md` - live URL + GCP IDs + env vars; updated 2026-05-13 with new `OIDC_AUDIENCE`

═══════════════════════════════════════════════════════════════════════
## CURRENT STATE OF THE CODE
═══════════════════════════════════════════════════════════════════════

  **Phases 0-5 complete. Tasks 1-28 of 39 done.** The Add-on is built, deployed, installed on the demo Gmail account, and verified end-to-end against a real email. The verdict card renders correctly in Gmail's right sidebar exactly as designed.

  Backend status: BUILT, TESTED, DEPLOYED. **53 tests passing** (40 prior + 12 illustration + 1 logo).

    Live URL: https://swellscan-backend-102679409749.us-central1.run.app
    Live revision: swellscan-backend-00008-gpx
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

  All three signature features live and tested end-to-end:
    1. Self-defending LLM (Tasks 10 + 14): prompt-injection detector + hardened Anthropic client
    2. Layered detection (Tasks 4 + 15): cheap detectors first, LLM only when score ≥ 25
    3. Per-sender baseline (Tasks 17 + 27): backend detector + Add-on UserProperties writer

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

Phase 6 has 11 numbered items (Tasks 29-39 plus inline stretches 31.5, 36.5, 36.6). They group into four chunks:

| Chunk | Tasks | Why |
|---|---|---|
| **Demo data** | 29 (pre-seed UserProperties) → 30 (craft 5 demo emails) → 31 (manual end-to-end test against all 5) | The interview demo itself. Five emails the recruiter will watch you scan live. Must be flawless. |
| **Cleanup + security** | 31.5 (simplify + code-review) → 32 (pip-audit + security-review) | Last passes over the code before submission. |
| **Documentation** | 34 (README) → 35 (CLAUDE.md refresh) → 37 (PDF cover sheet) | README is graded. PDF is what reaches the recruiter. |
| **Submission** | 38 (email + repo + PDF) → 39 (handoff) | The button-press moment. |

Recommended sequence: 29 → 30 → 31 first (real testing while bugs are still fixable). Then 31.5 + 32. Then 34 + 35 (docs). Stretches in any gaps. 37 + 38 last.

**Active stretches (only if time, never block submission):**
- Task 33: threat-research scan (90-min internet sweep for missed attack vectors)
- Task 36: correlation engine (signal-set bonuses in scoring policy)
- Task 36.5: wire the three action-button handlers from stubs to real actions
- Task 36.6: rewrite the verdict summary body for better readability

═══════════════════════════════════════════════════════════════════════
## IMMEDIATE NEXT ACTION
═══════════════════════════════════════════════════════════════════════

Start at Task 29 (pre-seed demo Gmail's UserProperties for the per-sender-baseline detector demo). Default skill: `superpowers:executing-plans`. Commit + push after every task.

Git authorship is already configured correctly. Commits should be authored as my personal identity WITHOUT a Co-Authored-By trailer (commits should look like my own work on GitHub).

---

**About this file:** This same prompt is pasted inline into each fresh session for maximum first-turn rule binding. The on-disk copy at `swellscan/.claude/HANDOVER.md` exists so the agent can re-read it mid-session if rules drift, and so future sessions can use a short "read `.claude/HANDOVER.md`" prompt instead of re-pasting the whole thing.
