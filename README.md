# Swellscan

> Every inbox is a shore. We scan every swell that hits it.

A Gmail Add-on that scores inbound email for maliciousness and surfaces an explainable verdict in the Gmail sidebar. Built for the Upwind Security Bootcamp home assignment.

Swellscan applies Upwind's published runtime-first / layered-detection philosophy to a new attack surface: email. Cheap deterministic detectors gate the expensive LLM call. Every finding carries a MITRE ATT&CK technique ID. Every verdict reads in five seconds.

| | |
|---|---|
| **Live backend** | https://swellscan-backend-102679409749.us-central1.run.app |
| **Live revision** | `swellscan-backend-00027-4s8` |
| **Submitted** | 2026-05-15 |
| **Author** | Lotan |

| SAFE | SUSPICIOUS | MALICIOUS |
|:---:|:---:|:---:|
| ![SAFE](docs/screenshots/SAFE-CARD.png) | ![SUSPICIOUS](docs/screenshots/suspicious-card.png) | ![MALICIOUS](docs/screenshots/malicious-card.png) |
| All clear, you can paddle | Something off about this set | Out of the water on this one |

The card carries a three-state lifeguard character arc: the same scene, the same lifeguard, three different postures. The character is the verdict; the findings list is the evidence.

---

## The problem

Email is still the dominant entry point for attackers to reach humans: phishing, business-email-compromise, credential harvesting, malicious attachments. Modern attacks increasingly target the AI defenders too, smuggling instructions into the email body to manipulate any LLM that reads it.

Gmail's built-in filtering catches the obvious cases. It does not walk the user through *why* a specific message is suspicious. It does not map findings to industry-standard taxonomies. It does not learn what is normal for a specific user's senders. It does not defend itself against adversarial inputs aimed at AI scanners.

Swellscan addresses these gaps.

---

## The solution

On every email the user opens, Swellscan returns a verdict card with a score (0-100), a verdict label (SAFE / SUSPICIOUS / MALICIOUS), a one-sentence summary of why, an explicit confidence band, and a findings list ranked by severity. Each finding carries its MITRE ATT&CK technique IDs. The cheap detectors run first; the LLM is invoked only when the cheap-detector score is at least 25, so roughly 60% of scans short-circuit before any LLM cost is paid.

---

## What's special about Swellscan

Malicious-email scoring is a crowded space, and the basics are table-stakes: auth-header checks, URL reputation, attachment hashing, an LLM as second opinion. Swellscan covers all of those. The list below is the set of positions Swellscan takes that are *not* the obvious option.

1. **The LLM is untrusted by construction, and the attack itself becomes evidence.** Six independent layers of defense around the model (random per-request wrapper tag, body sanitization stack, Pydantic-enforced JSON output, no tool use, dedicated prompt-injection detector). When the email tries to manipulate the model, the manipulation text is used as evidence that raises the maliciousness score, not silently filtered.

2. **Score-gated LLM, mirroring Upwind's RSAC 2026 architecture.** Cheap deterministic detectors run first. The expensive LLM call is invoked only when the cheap-detector score crosses 25, so roughly 60% of scans never pay LLM cost. The four concerns this addresses are Upwind's own published ones: latency, cost, false-positive tolerance, explainability.

3. **A correlation engine with named attacker playbooks.** Four hand-curated bonuses tied to actual attacker behavior (credential-harvesting trio, AI-targeted phishing, brand impersonation, thread-hijack signature). The card shows the user which playbook fired, not just the final score.

4. **Per-sender baseline lives on Google's user infrastructure, never on our backend.** The backend is fully stateless. No PII repository to leak. We could not read user data even as the script's owner.

5. **A one-sentence verdict summary in plain, approachable language.** For risky verdicts, Claude weaves the multiple findings into one natural observation. For SAFE verdicts, one of four templates fires based on which positive signals are present. The user gets the picture in five seconds, not by reading a wall of technical bullet points.

6. **Two-front security posture.** Swellscan detects email-borne attacks AND defends itself as a product: OIDC tokens with no long-lived shared secrets, four cost-exhaustion defense layers, structured-log allowlist, body never persisted. The submission is graded on security awareness, and both fronts are addressed.

---

## The architecture

Three components, one direction of trust, stateless backend.

```
+---------------------------------+        +--------------------------------+
|  Gmail Add-on                   |        |  Google Cloud Run              |
|  Apps Script V8 + CardService   |  HTTPS |  Python 3.12 FastAPI in Docker |
|                                 |  POST  |                                |
|  - Reads email via GmailApp     | -----> |  - 8-detector pipeline         |
|  - Loads sender history from    | /score |  - Pure aggregator function    |
|    UserProperties               |        |  - Score-gated LLM             |
|  - Posts payload + OIDC bearer  |        |  - Stateless, body discarded   |
|  - Renders Verdict as card      |        |  - Auto-scales 0..10           |
+---------------------------------+        +-------------+------------------+
                                                         |
                                                env vars | (read at boot)
                                                         v
                                              +-----------------------------+
                                              |  Google Secret Manager      |
                                              |  - 3 external API keys      |
                                              +-----------------------------+
```

### Request lifecycle

1. User clicks the Swellscan icon in Gmail. `onGmailMessageOpen` fires in [`addon/Code.gs`](addon/Code.gs); the Add-on reads the message, loads the sender's history from `UserProperties`, mints a Google-signed OIDC token, and POSTs the payload to `/score`.
2. The backend ([`backend/auth.py`](backend/auth.py)) verifies the JWT against Google's public keys, checks the email against an allowlist, and enforces a per-user 100-call sliding-window rate limit.
3. The pipeline ([`backend/pipeline.py`](backend/pipeline.py)) dispatches the seven cheap detectors in parallel via `asyncio.gather`. Each emits `Evidence` objects. The aggregator computes the score and applies correlation bonuses. If the score is at least 25, the LLM detector runs as a second opinion.
4. The aggregator runs once more with the LLM's evidence included, builds the verdict + summary body, and returns. The Add-on renders the card and writes the updated sender record back to `UserProperties` under a `LockService` block.

### Invariants

| Property | Guarantee |
|---|---|
| Detectors don't know about each other | Adding one is a single new file. |
| Scoring is a pure function | `list[Evidence] -> Verdict`. Tuning lives in one file. |
| Backend is stateless | Every request self-contained. No DB, no session. |
| Per-user state lives in Google's UserProperties | The user owns their history. |
| Body is never persisted | Read once, scored, discarded. |
| LLM output validated at the boundary | Pydantic schema enforced. |

### The eight detectors

| Detector | What it flags | Cost |
|---|---|---|
| [`headers.py`](backend/detectors/headers.py) | SPF / DKIM / DMARC fails, Reply-To mismatch with severity scaling, Return-Path mismatch with transactional-mailer allowlist | $0 |
| [`sender.py`](backend/detectors/sender.py) | Display-name vs domain mismatch, leetspeak lookalike domains, freemail impersonating brand | $0 |
| [`urls.py`](backend/detectors/urls.py) | VirusTotal + Safe Browsing + urlscan (gap-only) in parallel, IP-as-host, known shorteners | free tier |
| [`attachments.py`](backend/detectors/attachments.py) | Risky extensions (SVG, HTML, ISO, VHD, double-extensions), SHA-256 reputation, password-protected-archive correlation | free tier |
| [`prompt_injection.py`](backend/detectors/prompt_injection.py) | "Ignore previous instructions" patterns, verdict injection, tag-escape, payload fragmentation | $0 |
| [`sender_baseline.py`](backend/detectors/sender_baseline.py) | First-seen sender, signing-domain drift, send-time anomaly, IP-geography change | $0 |
| [`bec_language.py`](backend/detectors/bec_language.py) | Payment-instruction urgency + "change of banking details" - the 2025-2026 BEC signature per Verizon DBIR | $0 |
| [`llm.py`](backend/detectors/llm.py) | Claude Sonnet 4.6 second-opinion on emails with score >= 25. Hardened against prompt injection. | ~$0.005 |

---

## Security posture

Two fronts: attackers operating *through* email content, and attackers operating *against the product itself.*

### Front A: attackers operating through email content

| Defense | Where it lives |
|---|---|
| Random per-request wrapper-tag suffix on untrusted content | [`backend/clients/anthropic.py`](backend/clients/anthropic.py) |
| Body sanitization stack (hidden HTML, Unicode Tags, markdown, zero-width, closing-tag mimics), applied to body + subject + display-name | [`backend/_security_patterns.py`](backend/_security_patterns.py) |
| Pydantic validation of LLM output, no tool use, no function calling | [`backend/clients/anthropic.py`](backend/clients/anthropic.py) |
| URL reputation delegated to specialized sandboxes; backend never visits URLs | [`backend/detectors/urls.py`](backend/detectors/urls.py) |
| Attachments handled by SHA-256 hash only; backend never opens files | [`backend/detectors/attachments.py`](backend/detectors/attachments.py) |
| Body, subject, URLs, hashes, attachment names never logged | structured-logging policy |

### Front B: attackers operating against the product itself

| Defense | Where it lives |
|---|---|
| OIDC ID-token auth, asymmetric crypto via Google JWKs, ~1h token validity | [`backend/auth.py`](backend/auth.py) |
| Multi-audience allowlist with empty-list refusal at import (refuses to start rather than running open) | [`backend/auth.py`](backend/auth.py) |
| Per-user sliding-window rate limiter (100 / 24h) + Cloud Run `--max-instances=10` + Anthropic prepaid $5 hard cap | [`backend/rate_limit.py`](backend/rate_limit.py) + deploy flags |
| Stateless backend + body never persisted; no PII repository to leak | by construction |
| Non-root container (uid 1001), `python:3.12-slim`, pinned dependencies | [`Dockerfile`](Dockerfile) |
| Exception logging redacts request URLs (Safe Browsing puts the API key in the query string) | [`backend/clients/safebrowsing.py`](backend/clients/safebrowsing.py) |

`pip-audit` cleared three CVEs on submission day (fastapi, starlette, python-dotenv bumped). An end-to-end security review of the deployed revision returned, verbatim: *"No high-confidence findings beyond what is already addressed."*

---

## Decisions worth defending

Five places where the obvious option was rejected after weighing the trade-off honestly. These are the calls I would walk into the interview ready to defend.

### 1. Self-defending LLM, not a trusted one

I picked **six independent layers of defense around the LLM** over the alternative of trusting the model. No language-model policy is durable across jailbreaks; relying on the model to refuse prompt injection puts the security posture at the model's mercy. The defense is constructive: when the email's attack text reaches the prompt-injection detector, it becomes HIGH-severity evidence that raises the score. The attack itself becomes the signal.

![demo-4 prompt injection MALICIOUS](docs/screenshots/demo-4-prompt-injection-malicious.png)

### 2. Score-gated LLM, not LLM-on-every-email

I picked **layered detection where the LLM is gated on a cheap-detector score >= 25** over the simpler "always call Claude" approach. The economics are roughly 2.5x cheaper because 60% of scans short-circuit before the LLM is invoked, and the system stays explainable when Claude is unavailable: every cheap-detector signal is independently reproducible.

![demo-2 credential trio MALICIOUS with correlation bonus](docs/screenshots/demo-2-microsoft-credential-trio-malicious.png)

### 3. Named-playbook correlation, not linear scoring alone

I picked **four hand-curated correlation bonuses tied to attacker playbooks** over a purely linear sum (and over the opposite extreme: an opaque ML scoring model). Four named playbooks: credential-harvesting trio, AI-targeted phishing, brand impersonation, thread-hijack signature. The card shows the user which playbook matched, not just the final number. Transparency over black-box.

### 4. Client-side baseline, not a server-side history database

I picked **per-sender history stored on Google's UserProperties infrastructure (scoped to the script and user)** over the conventional approach of keeping per-user history on our own backend. The backend is fully stateless. No PII repository to leak. We could not read user data even as the script's owner.

![demo-6 BEC thread-hijack with baseline drift MALICIOUS](docs/screenshots/demo-6-bec-thread-hijack-malicious.png)

### 5. LLM-synthesized verdict summary, not a templated one

I picked **a Claude-generated one-sentence summary that weaves multiple findings into one natural observation** for risky verdicts, with a four-variant template for SAFE based on which positive signals are present. The alternative was a single static "Authentication checks out" template for every clean email: useful but wallpaper. The summary is the part of the card the user actually reads in the first second; making it speak in plain language about *this specific email* is the user-experience choice.

---

## The honest backlog

What Swellscan does not do yet, what it would cost to run at scale, and what I would build with more time.

### Limitations

- **Multi-modal attacks are out of scope.** Email-only. Deepfake voice + email correlation (the 2024 Arup $25M incident) needs cross-product integration.
- **Per-message scoring, not per-thread.** Subtle banking-detail changes inside an existing trusted thread are only detected if the visible per-message signals fire. Full thread-context BEC is named Future Work.
- **No attachment opening, no URL fetching.** Reputation APIs only. Trade-off: zero-day payloads not yet observed by any reputation service are not detected.
- **Baseline tracks behavior, not reputation memory.** A sender flagged MALICIOUS once is not auto-distrusted later. The button-feedback-loop entry below is the named upgrade path.
- **Install via Apps Script copy-paste** until Marketplace publication.
- **PSL gap.** `.co.uk`-style cousin subdomains under a shared parent are treated as same-org. Direction: false-negative, not false-positive.
- **urlscan signal scoped to the anonymous-tier verdict mechanism** (the paid-tier strict consensus field is not used). The signal is intentionally conservative.
- **Single-region deployment** (us-central1). Multi-region would be table-stakes for production.
- **In-memory rate limiter is approximate at scale.** Each Cloud Run instance has its own counter. Memorystore/Redis exact limiter is Future Work.

### Scalability

Per-user cost model: ~$0 on the 60% of scans that short-circuit, ~$0.005 when the LLM fires. A typical knowledge worker opens ~80 emails per day, so **~$0.16 per user per day** on LLM cost. Free tiers absorb the reputation-API calls.

| Tier | LLM-driven cost | What changes at this scale |
|---|---|---|
| 1 user | ~$5 / month | Current deployment. Free tiers cover everything else. |
| 1,000 users | ~$5,000 / month | Need per-URL reputation cache, Memorystore-backed exact rate limiting, Anthropic prompt caching enabled. |
| 100,000 users | ~$500,000 / month | Need batch-API LLM dispatch, regional Cloud Run, paid VirusTotal tier, managed shared reputation cache. The cost is real; the architecture handles it because the scaling levers (caching, batching, regional, scale-to-zero) are already standard. |

### What I would build next

**Research-driven future work** (twelve entries from the threat-research scan that did not make V2 scope):

- **QR-code decoding (quishing).** 12% of 2025 phishing uses QR codes; deferred for native-library build risk.
- **Confidence-honesty bar on the card.** Surface model uncertainty visibly; deferred because the card visual is locked.
- **Detections-as-code (YAML rule pack).** Lift detector heuristics into `rules/*.yaml`; deferred as zero-new-capability refactor.
- **Punycode / IDN homograph normalization.** V1 covers leetspeak; full Unicode confusables needs `idna` + a confusables library.
- **Redirect unwrapping for link-wrapper URLs.** Needs an SSRF-hardened HTTP client.
- **Full thread-hijack detection (multi-message context).** Cheap version (payment-urgency signal) is in V2; full version expands to per-thread data model.
- **True VEC (per-sender banking-details memory).** Expands privacy posture significantly.
- **BitB / AiTM-specific signals.** Needs WHOIS / RDAP integration for domain-age scoring.
- **Verdict permalink / signed evidence card.** Persistence is a one-way architectural shift.
- **Embedding-similarity layer (Upwind's Stage 2 equivalent).** Production engineering beyond MVP scope.
- **Button-wired feedback loop + sender reputation memory.** The named upgrade path for the baseline-tracks-behavior limitation above.
- **Google Workspace Marketplace publication**, Memorystore-backed exact rate limiting, multi-region Cloud Run.

**Cleanup before next production deploy** (four items spotted in code review, deliberately deferred from submission day so the reviewer can see they were not missed):

- Consolidate the Reply-To and Return-Path branches in [`headers.py`](backend/detectors/headers.py) (~95 lines each, near-duplicates that should share a parameterized helper).
- Share a single `VirusTotalClient` between the URL and attachment detectors (currently two `httpx` connection pools to the same host).
- Centralize email-domain extraction in a `domain_of()` helper (five files with slightly different bracket-handling).
- Deduplicate the "detectors-fired" count between [`addon/Code.gs`](addon/Code.gs) and [`addon/render.gs`](addon/render.gs).

---

## Setup and run

Two install paths. Both are usable today. A third (Google Workspace Marketplace publication) is named in the Future Work above.

### Path A: use the live shared backend (recommended for review)

Run Swellscan against your own Gmail without standing up infrastructure. ~15 minutes including the email round-trip.

1. **Email me** (`lotantamary@gmail.com`) with your Gmail address and your Apps Script project's OAuth client ID (you will produce this in step 4).
2. **Wait for confirmation.** I will add you to the `ALLOWED_USERS` allowlist and add your OAuth client ID to the `OIDC_AUDIENCE` audience list, then redeploy. ~10 minutes.
3. **Create a new Apps Script project** at https://script.new. Name it "Swellscan".
4. **Paste the six files** from this repo's [`addon/`](addon/) folder into the editor (`appsscript.json`, `setup.gs`, `client.gs`, `render.gs`, `Code.gs`, `baseline.gs`). The OAuth client ID is auto-generated; copy it from **Project Settings -> IDs -> OAuth client ID**.
5. **Run `setup()` once** from the editor. It writes `BACKEND_URL` and `OIDC_AUDIENCE` to `ScriptProperties`.
6. **Install the test deployment:** click **Deploy -> Test deployments -> Install**. Open Gmail, click the Swellscan icon in the right sidebar on any email, and watch the verdict card render.

### Path B: self-host the backend

Full reproducibility on a fresh GCP project. 1-2 hours depending on GCP familiarity.

1. **Clone and install dependencies:**
   ```bash
   git clone https://github.com/<your-user>/swellscan.git
   cd swellscan
   pip install -r backend/requirements.txt
   ```
2. **Create a fresh GCP project**, enable billing (free trial works), and enable the Cloud Run, Cloud Build, and Secret Manager APIs.
3. **Provision three secrets** in Secret Manager (your own keys from Anthropic, VirusTotal, Safe Browsing):
   ```bash
   echo -n "sk-ant-..." | gcloud secrets create anthropic-api-key --data-file=-
   echo -n "vt-..."     | gcloud secrets create virustotal-api-key --data-file=-
   echo -n "sb-..."     | gcloud secrets create safebrowsing-api-key --data-file=-
   ```
4. **Grant the default Cloud Run compute service account access to the secrets:**
   ```bash
   gcloud projects add-iam-policy-binding <YOUR_PROJECT> \
     --member="serviceAccount:<PROJECT_NUMBER>-compute@developer.gserviceaccount.com" \
     --role="roles/secretmanager.secretAccessor"
   ```
5. **Deploy.** The same flag set the live revision uses:
   ```bash
   gcloud run deploy swellscan-backend \
     --source . --region us-central1 \
     --set-secrets="ANTHROPIC_API_KEY=anthropic-api-key:latest,VIRUSTOTAL_API_KEY=virustotal-api-key:latest,SAFEBROWSING_API_KEY=safebrowsing-api-key:latest" \
     --set-env-vars="ALLOWED_USERS=your-gmail@gmail.com,OIDC_AUDIENCE=<your-apps-script-oauth-client-id>,URLSCAN_ENABLED=true" \
     --max-instances=10 \
     --allow-unauthenticated
   ```
   `--allow-unauthenticated` means Cloud Run does not enforce IAM; the application enforces auth via the OIDC token verification in [`backend/auth.py`](backend/auth.py).
6. **Install the Add-on** as in Path A steps 3-6, but during `setup()` set `BACKEND_URL` to your own Cloud Run URL.

**If the Add-on returns 401** when you click the icon, the `OIDC_AUDIENCE` env var on the backend probably does not include your Apps Script project's OAuth client ID. `ScriptApp.getIdentityToken()` mints JWTs whose `aud` claim is the OAuth client ID, *not* the Cloud Run URL. Update the env var and redeploy.

### Tests

```bash
pytest                          # 186 tests, ~15s
pytest --cov=backend            # with coverage
pip-audit                       # known-CVE check
```

Unit tests live at [`tests/unit/`](tests/unit/) (one file per detector, plus scoring, models, aggregator, auth, rate-limiter, each external-API client). The integration suite at [`tests/integration/test_pipeline.py`](tests/integration/test_pipeline.py) exercises the full pipeline with mocked external APIs via `pytest-httpx`. As of submission: **186 / 186 passing**, `pip-audit` clean.

---

## Tech stack

**Backend:** Python 3.12, FastAPI 0.136.1, Pydantic 2, `httpx` for async clients, `structlog` for structured JSON logging, `google-auth` for OIDC verification, `anthropic` SDK for Claude Sonnet 4.6. Starlette 1.0.0 and python-dotenv 1.2.2 (bumped on submission day to clear `pip-audit` CVEs).

**Gmail Add-on:** Apps Script V8, `CardService` for UI, `UrlFetchApp` for HTTPS, `PropertiesService` for per-user storage, `LockService` for write serialization, `CacheService` for verdict caching against framework re-invocations.

**Deployment:** Google Cloud Run (auto-managed TLS, scale-to-zero, `python:3.12-slim` non-root container), Google Secret Manager (3 secrets), Cloud Logging.

**External services:** Anthropic API (Claude Sonnet 4.6), VirusTotal API v3, Google Safe Browsing v4, urlscan.io (anonymous tier).

---

## Acknowledgements

The assignment was intentionally open-ended; this submission's framing is to apply Upwind's published runtime-first / layered-detection philosophy to a new attack surface that Upwind itself does not address (email). Vocabulary and patterns are deliberately mirrored: layered detection, signal over noise, evidence-based scoring, prioritized response based on real attacker behavior, MITRE ATT&CK technique mapping on every finding.

The full design lives in [`docs/superpowers/specs/2026-05-12-swellscan-design.md`](docs/superpowers/specs/2026-05-12-swellscan-design.md). The locked Upwind-aligned vocabulary is at [`docs/superpowers/specs/language-bank.md`](docs/superpowers/specs/language-bank.md). References that shaped the architecture: the [Upwind RSAC 2026 announcement on layered malicious-AI-prompt detection](https://www.businesswire.com/news/home/20260323142408/), the [MITRE ATT&CK Phishing technique tree](https://attack.mitre.org/techniques/T1566/), the Verizon 2025 DBIR on BEC payment-instruction trends, and KnowBe4's 2025 risky-attachment data.

Thank you for the room to build something opinionated.
