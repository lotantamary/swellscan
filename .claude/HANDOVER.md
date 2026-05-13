# Swellscan — Session Handover

This file is the briefing for any AI session picking up Swellscan mid-implementation. The same text gets pasted into the chat when starting a fresh session for maximum first-turn compliance. The on-disk copy exists as (1) a mid-session memory refresh, (2) a starting point for short future-session prompts, and (3) project documentation.

---

I'm continuing work on Swellscan — my home assignment for Upwind Security (a cybersecurity company I'm interviewing with). After I submit it, I will present the project live to their recruiting team in a 45-minute interview, where every architectural and product decision will be questioned. I need to be able to defend each choice myself, in my own words.

═══════════════════════════════════════════════════════════════════════
## GOALS — what we're walking toward
═══════════════════════════════════════════════════════════════════════

Submission deadline: Fri 2026-05-15 EOD.
Demo interview: ~Mon 2026-05-18, 45 minutes, live with Bar Naor and the Upwind hiring team.

Evaluation rubric we're optimizing for (in priority order):
  - Product thinking (which capabilities chosen and why)
  - Creativity (going beyond the obvious — Swellscan's three signature moments)
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
- Explain non-trivial moves as you make them. I'm a student new to cybersecurity — define every cyber term the first time it appears and tie it back to why our architecture needs it.
- Announce phase transitions before starting the first task in a new phase. We've just finished Phase 4 (backend live) and the next session opens Phase 5 (Apps Script Add-on). After that there's only Phase 6 (polish + submit).

═══════════════════════════════════════════════════════════════════════
## CRITICAL — THE PLAN IS A LOGIC SPEC, NOT SOURCE-OF-TRUTH
═══════════════════════════════════════════════════════════════════════

The implementation plan at `docs/superpowers/plans/2026-05-12-swellscan-implementation.md` contains code blocks inside every numbered task. Those code blocks were written by a planner agent in one pass with no execution, no compiler, no tests run. **TREAT THE PLANNED CODE AS PSEUDO-CODE / REFERENCE LOGIC.**

How to actually work with it:

1. Read the planned code as a description of intent. Understand what it's trying to do.
2. BEFORE writing anything, mentally trace the planned code against the planned test. If the trace doesn't work, the plan has a bug — surface it to me, propose a fix, then proceed.
3. Scan the task for references to artifacts changed in earlier tasks (renamed fields, fixture defaults, function signatures). The plan can't update itself; cross-task drift is real.
4. Use the plan's structure and tests as the contract; reconstruct the body deliberately. Identical results are fine for trivial data (Pydantic models, regex constants, palette dicts). Logic code should pass through your own brain.
5. When you DO find a bug in the planned code, surface it explicitly in the recap — those moments are gold for interview ("I followed the plan but the test caught a logic error in step X; I traced it, fixed it, here's why my fix is right"). I want a couple of these.

Three plan bugs have already surfaced and been documented in the plan's "Known plan-vs-implementation drift" section (Task 8 fixture mismatch, Task 9 broken substring check, Task 19 missing `requests` dep). Look there for the pattern.

═══════════════════════════════════════════════════════════════════════
## READ THESE FILES IN ORDER to orient
═══════════════════════════════════════════════════════════════════════

  1. `swellscan/CLAUDE.md` (project map at repo root)
       → Read first. Has a "Current State" section at the top with the live Cloud Run URL, completed-task table with commit SHAs, and the "what's next" pointer. This is the single best snapshot of where we are.

  2. `swellscan/docs/superpowers/specs/2026-05-12-swellscan-design.md`
       → The authoritative design document. Every architectural and product decision lives here. Status line at the top confirms backend is deployed; design itself hasn't changed.

  3. `swellscan/docs/superpowers/plans/2026-05-12-swellscan-implementation.md`
       → The numbered per-task plan. Read the new "Progress" section at the top to see which tasks are done (with commit SHAs) and which are next. Then READ EACH TASK YOU WORK ON WITH THE SKEPTICISM RULE ABOVE — don't paste-and-pray.

═══════════════════════════════════════════════════════════════════════
## WHERE TO LOOK FOR SPECIFIC THINGS
═══════════════════════════════════════════════════════════════════════

  - Live backend URL, GCP project ID, allowlisted user, OIDC audience, secret names, IAM grants, cleanup-at-end commands
      → memory file `project_deploy_state.md`
      → Also restated in `CLAUDE.md` "Current State"

  - The three stand-out moments (self-defending LLM, wave verdict card with character arc, per-sender baseline)
      → design doc §3.1–3.3

  - The rubric items and how each decision maps to them
      → memory file `feedback_deliberate_creative_edge.md`
      → design doc has rubric-mapping baked into many sections

  - Upwind's voice + published patterns we're deliberately mirroring (especially the RSAC 2026 layered AI-prompt-detection paper)
      → memory file `reference_upwind_research.md`

  - The actual home-assignment text from the recruiter
      → `C:\Users\lotan\Projects\Upwind\task-instructions\` — sits OUTSIDE the swellscan repo on purpose, never committed, but available locally when you need to re-check what the assignment asks for

═══════════════════════════════════════════════════════════════════════
## MEMORY FILES (particularly load-bearing right now)
═══════════════════════════════════════════════════════════════════════

Memory directory: 13 files at `C:\Users\lotan\.claude\projects\c--Users-lotan-Projects-Upwind\memory\`. The `MEMORY.md` index lists all of them. ALL inform how you work.

The ones most important to read FIRST for the upcoming work:

  - `feedback_stop_after_every_task.md` — the hard-stop + recap cadence
  - `feedback_plan_code_is_spec_not_source.md` — THE rule about the plan; I asked specifically that this be the prompt's headline
  - `feedback_explain_as_we_go.md` — running tutor mode for me
  - `feedback_dont_frame_choices_as_convenience.md` — never lead with "simpler" — show both sides honestly
  - `feedback_announce_phase_transitions.md` — phase boundaries get explicit call-outs
  - `feedback_deliberate_creative_edge.md` — every decision needs a story that ties to a rubric item or Upwind value
  - `feedback_mobile_aware_design.md` — especially relevant NOW: the Add-on must work on desktop Gmail AND iOS/Android Gmail apps
  - `project_deploy_state.md` — live URL + GCP IDs + env vars; the Add-on `client.gs` will hardcode the URL from here

═══════════════════════════════════════════════════════════════════════
## CURRENT STATE OF THE CODE
═══════════════════════════════════════════════════════════════════════

  Phases 0–4 complete. Tasks 1–21 of 39 done.
  Latest commit on `main`: `f7bb34a docs: refresh CLAUDE.md, design status, and plan with Phase 4 state + commits`.

  Backend status: BUILT, TESTED, DEPLOYED. 40 tests passing.

    Live URL: https://swellscan-backend-102679409749.us-central1.run.app
    /health         → {"status":"ok"}
    POST /score     → OIDC-protected (401 on bad tokens)
    /illustration/{label}?score=N → public SVG, 1-hour cache

  All three signature features coded:

    1. Self-defending LLM (Task 10 + Task 14)
    2. Layered detection (Task 15 + Task 4 thresholds)
    3. Per-sender baseline (Task 17)

  GCP project: swellscan-prod (102679409749)
  Owner: swellscan.demo@gmail.com (also the demo Gmail account)
  Three secrets in Secret Manager.
  IAM: service-account-secretAccessor granted.

═══════════════════════════════════════════════════════════════════════
## WHAT'S NEXT
═══════════════════════════════════════════════════════════════════════

▶ Phase 5 — Apps Script Add-on. Tasks 22–28. ~3h.

   ⚠️ This is the FIRST NON-BACKEND PHASE. Everything from here is Google Apps Script (V8 JavaScript) running in Google Workspace. No more Python until Phase 6's polish work.

  - Task 22 — `appsscript.json` manifest (the Apps Script project config)
  - Task 23 — `setup.gs` (one-time config function)
  - Task 24 — `client.gs` (HTTP wrapper with OIDC token — needs the live backend URL from `project_deploy_state.md`)
  - Task 25 — `render.gs` (verdict card builder; PLAN SAYS to invoke `frontend-design:frontend-design` skill BEFORE writing)
  - Task 26 — `Code.gs` (`onGmailMessageOpen` trigger + card-state routing)
  - Task 27 — `baseline.gs` (sender-history in `UserProperties` with `LockService` + `message_id` idempotency)
  - Task 28 — Install Add-on on demo Gmail + end-to-end smoke test

Then Phase 6 covers polish, security review, threat-research stretch, README, submission.

═══════════════════════════════════════════════════════════════════════
## IMMEDIATE NEXT ACTION
═══════════════════════════════════════════════════════════════════════

Start at Task 22 (Apps Script manifest — `appsscript.json`). Default skill: `superpowers:executing-plans`. At Task 25, additionally invoke `frontend-design:frontend-design` before writing the card builder. Commit + push after every task.

Git authorship is already configured correctly. Commits should be authored as my personal identity WITHOUT a Co-Authored-By trailer (commits should look like my own work on GitHub).

---

**About this file:** This same prompt is pasted inline into each fresh session for maximum first-turn rule binding. The on-disk copy at `swellscan/.claude/HANDOVER.md` exists so the agent can re-read it mid-session if rules drift, and so future sessions can use a short "read `.claude/HANDOVER.md`" prompt instead of re-pasting the whole thing.
