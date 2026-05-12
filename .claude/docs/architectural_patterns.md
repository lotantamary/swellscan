# Architectural Patterns — Swellscan

Deep documentation of the patterns and decisions behind Swellscan. CLAUDE.md is the map; this file is the legend.

## Architectural Patterns

**Three-tier topology with strict isolation:**
1. Gmail Add-on (Apps Script V8 runtime, runs in Google's infrastructure)
2. Backend service (Python FastAPI on Cloud Run, runs in our GCP project)
3. External reputation services (Anthropic, VirusTotal, Safe Browsing, urlscan.io)

The Add-on holds no detection logic — it reads the email, posts to the backend, renders the response. The backend holds no UI logic — it consumes a typed payload, returns a typed verdict. Each tier can be replaced or tested in isolation.

**Evidence-based detection.** Detectors emit *evidence*, not scores. The aggregator turns evidence into a verdict via one pure function. This separation lets us add new detectors without touching the scorer, and lets us tune the scorer without touching detectors. See [design doc §3.2 line 81](../../docs/superpowers/specs/2026-05-12-swellscan-design.md) and §5.2 for the Evidence schema.

**Layered detection (cost/latency optimization).** Cheap deterministic detectors run in parallel on every request. The LLM detector — the only expensive one — is invoked only when the raw score is ≥25 (anything not clearly SAFE). This mirrors Upwind's RSAC 2026 published pattern. See design doc §5.4.

## Design Decisions

**Why Python for the backend, not Node.js or Go:** the workload is parse-strings + call-HTTP-APIs + call-LLM + return-JSON, where Python is fastest to develop and the Anthropic SDK is most mature. Performance isn't the bottleneck — external API latency is.

**Why Google Cloud Run, not AWS Lambda or self-hosted:** Apps Script already runs in Google's project structure; staying single-cloud means one identity boundary, one console, one OIDC story. Cloud Run's source-based deploy (`gcloud run deploy --source .`) is one-command. Cold-start (~200–400ms) is faster than Lambda Python (~500–800ms) for this workload.

**Why Google OIDC ID tokens, not shared secrets:** asymmetric crypto, automatic hourly rotation, audit trail by user. No long-lived secret to rotate or leak. See design doc §9.2.

**Why LLM threshold is `score ≥ 25` (not `25–75`):** in a security tool, false positives are more costly than false negatives (over-warned users stop trusting it). Paying ~$0.005 per LLM call as a second opinion is the right trade-off against letting a single cheap-signal failure produce a confident MALICIOUS verdict. See design doc §5.4.

**Why per-sender baseline lives in Apps Script UserProperties:** Google-managed encrypted storage, scoped per-user-per-script. The backend remains stateless — it never persists baseline data. Stronger privacy story than any database we could build. See design doc §3.3.

**Why the wave illustration is generated server-side as SVG:** CardService doesn't allow custom CSS or fonts. The hero image is the *only* place we have full pixel control. We concentrate brand identity there and accept Google's defaults elsewhere. See design doc §8.1.

## State Management

**Backend is stateless.** Every request is self-contained. No database, no session, no caching across requests (per-request memoization for URL dedup is fine). Same input → same output. Trivial to scale, easy to reason about, no race conditions.

**Per-user state lives in Apps Script `UserProperties`.** Specifically the per-sender baseline fingerprint. Read on every scan, sent in the request payload, updated by the Add-on after the verdict is rendered.

**Concurrency safety on the Add-on side:** `LockService.getUserLock()` wraps the read-modify-write block of sender history; `message_id`-based ring buffer makes double-clicks idempotent. See design doc §3.3 ("Concurrency safety" paragraph).

**Secrets are runtime-only.** Loaded from Google Secret Manager into the Cloud Run container at boot. Never written to logs, never persisted in code, never in git.

## Recurring Logic Patterns

**Graceful degradation around every detector:**
```python
class HeadersDetector(Detector):
    name = "headers"
    async def run(self, email: Email) -> list[Evidence]:
        try:
            return await self._run_internal(email)
        except Exception as e:
            log.warning("detector_failed", detector=self.name, error=str(e))
            return []
```
One detector failing returns an empty evidence list; the pipeline continues. A DoS against one external API cannot deny users a verdict.

**Three-layer prompt-injection defense (LLM detector):**
1. Random per-request delimiter suffix (`untrusted_content_<random>`) — attacker cannot predict the closing tag
2. Pre-sanitize body to escape any `</tag_keyword` sequences before insertion into the prompt
3. `prompt_injection.py` detector flags tag-escape attempts at HIGH severity — *attempting* the attack becomes a malicious signal
See design doc §7.4 for all 8 defense layers.

**Parallel detector dispatch:**
```python
# pipeline.py — conceptual shape
evidence_lists = await asyncio.gather(*(d.run(email) for d in cheap_detectors))
all_evidence = list(chain.from_iterable(evidence_lists))
raw_score = aggregator.compute(all_evidence)
if raw_score >= 25:
    llm_evidence = await llm_detector.run(email, prior_evidence=all_evidence)
    all_evidence.extend(llm_evidence)
verdict = aggregator.finalize(all_evidence)
```

**Privacy-conscious structured logging:** every log line goes through `structlog` with an explicit allowlist of fields. Email body, subject, recipient, attachment filenames, URLs, hashes are NEVER logged. See design doc §10.4 for the full allowlist.

## API / Interface Design Patterns

**One public endpoint: `POST /score`.** Request body is a Pydantic `Email`; response is a Pydantic `Verdict`. JSON over HTTPS. Authentication via `Authorization: Bearer <google-id-token>` header.

**One health endpoint: `GET /health`.** Returns `{"status": "ok"}`. Cloud Run uses it for liveness.

**Strict request validation at the boundary.** Pydantic enforces types, max lengths (body ≤ 100KB, URL list ≤ 200 entries), and required fields. Malformed requests return `400` before any detection logic runs. Mirrors the security principle: validate untrusted input at the boundary, trust the data structure after.

**OIDC verification middleware:** FastAPI dependency at `backend/auth.py` — every request to `/score` passes through `verify_request(authorization: str = Header(...))` which validates the Google JWT and checks the `email` claim against the in-code allowlist.

**LLM contract enforced at three layers:** Anthropic structured-output mode forces JSON-schema match; Pydantic re-validates on our side; invalid output emits no evidence (graceful degradation rather than hallucination).

## Dependency Injection / Inversion of Control

**Detector pattern.** All detectors implement an abstract base class:
```python
class Detector(ABC):
    name: str
    @abstractmethod
    async def run(self, email: Email) -> list[Evidence]: ...
```
The pipeline holds a list of detector instances and iterates them — no detector knows about any other. New detectors plug in by being added to the list in `pipeline.py`.

**External clients are injected, not imported.** `backend/clients/anthropic.py`, `clients/virustotal.py`, `clients/safebrowsing.py`, `clients/urlscan.py` are constructed at app boot (`main.py`) and passed into detectors via constructor injection. This makes detectors testable with mocked clients.

**FastAPI dependency injection** handles auth verification — the `verify_request` function in `auth.py` is a FastAPI `Depends()` on every protected route. Routes get a verified user identity as a parameter; they don't have to think about token validation.

**Configuration via `config.py`.** Single module loads env vars at import, exposes typed config object. Detectors and clients read from this config; nothing reads `os.environ` directly. Makes testing trivial (override config in fixtures).
