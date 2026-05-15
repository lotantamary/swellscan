/**
 * Swellscan Add-on entry point + per-state action button handlers.
 *
 * Trigger flow (Option A, locked 2026-05-13): when the user clicks the
 * Swellscan icon in Gmail's sidebar, onGmailMessageOpen runs the scan
 * inline (1-3 seconds) and returns the verdict card. There is no
 * intermediate "Ready to scan" card; the user already opted in by
 * installing the Add-on and clicking the icon. CardService cannot
 * auto-update a card after display, so the silent 1-3 second wait is
 * covered by Gmail's default sidebar loading indicator.
 *
 * The three per-state action buttons are wired with stub handlers below
 * that return lifeguard-voice notification toasts. Real action wiring
 * (Mark as expected -> update baseline; See all evidence -> push second
 * card; Report & delete -> GmailApp.moveToTrash) is plan Task 36.5
 * stretch - intentionally not in v1 scope.
 */

function onGmailMessageOpen(e) {
  const messageId = e.gmail.messageId;
  const accessToken = e.gmail.accessToken;
  try {
    // Phantom-trigger guard. Gmail's Add-on framework occasionally invokes
    // onGmailMessageOpen twice for a single user open. The first scan trains
    // the per-sender baseline on the observed signals (the architecture's
    // intentional learning step - documented as Future Work to move under
    // user control). The second scan, 1-3 seconds later, then reads the
    // now-polluted baseline and returns a degraded verdict. The framework
    // renders the second response, overwriting the correct first card.
    //
    // Cache the first verdict per message_id. A phantom re-invocation
    // within 5 minutes returns the cached card directly and skips both the
    // backend call AND the baseline update (already done by the first
    // call - baseline.gs's message_id ring-buffer would no-op anyway).
    // 5-minute TTL covers a live demo session and expires naturally.
    const cache = CacheService.getUserCache();
    const cacheKey = 'verdict:' + messageId;
    const cachedVerdictJson = cache.get(cacheKey);
    if (cachedVerdictJson) {
      try {
        const cachedVerdict = JSON.parse(cachedVerdictJson);
        return [buildVerdictCard(cachedVerdict)];
      } catch (parseErr) {
        // Cache entry corrupt - fall through to a fresh scan.
      }
    }

    const payload = buildEmailPayload(messageId, accessToken);
    const verdict = callBackend(payload);

    // Attach presentation-only fields the card builder expects. We do NOT
    // attach verdict.subject / verdict.sender any more - the card no
    // longer has a subject+sender section because the email is already
    // visible behind/above the Add-on sidebar, and if the sender is the
    // problem the detectors call it out in a specific finding row.
    verdict.detectors_fired = countDetectorsFired(verdict.evidence);
    verdict.llm_invoked = (verdict.detectors_run || []).indexOf('llm') !== -1;

    // Cache the verdict (including the presentation fields above) so a
    // phantom re-invocation rendering from cache produces the identical
    // card. CacheService.put with TTL in seconds; 300 = 5 minutes.
    try {
      cache.put(cacheKey, JSON.stringify(verdict), 300);
    } catch (cacheErr) {
      // CacheService can throw if value is over the per-key size limit
      // (~100KB). Verdicts are typically a few KB; if a future LLM
      // response inflates one beyond the cap, fail silently so the user
      // still sees a card. The phantom-overwrite bug returns, but
      // worst-case the user sees a slightly-wrong second scan rather
      // than a hard error.
    }

    // Sender baseline update. baseline.gs (Task 27) handles message_id
    // idempotency. typeof-guarded so Code.gs ships cleanly even if
    // baseline.gs hasn't been pasted into the Apps Script project yet.
    if (typeof updateSenderHistoryAfterScan === 'function') {
      updateSenderHistoryAfterScan(payload, verdict);
    }

    return [buildVerdictCard(verdict)];
  } catch (err) {
    return [buildErrorCard(err)];
  }
}

/**
 * Count of unique detectors that emitted at least one non-info Evidence
 * item. This is the "N detectors" number shown in the card meta line - a
 * trust signal ("4 independent systems agreed something was off") rather
 * than a count of detectors that ran (which is always close to 7).
 */
function countDetectorsFired(evidence) {
  const seen = {};
  (evidence || []).forEach(function (e) {
    if (e.severity !== 'info' && e.detector) {
      seen[e.detector] = true;
    }
  });
  return Object.keys(seen).length;
}

/**
 * Error card rendered when the scan fails (backend down, network error,
 * 401 from auth). Shown in place of the verdict card so the user can see
 * what went wrong - a notification toast would be too easy to miss when
 * no verdict comes back at all.
 */
function buildErrorCard(err) {
  const msg = (err && err.message) ? String(err.message).substring(0, 240) : 'Unknown error';
  const card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle('Scan failed')
      .setSubtitle('Swellscan')
  );
  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        '<b><font color="#b8442b">Swellscan could not scan this message.</font></b>' +
        '<br>' + escapeHtml(msg)
      )
    )
  );
  return card.build();
}

// --- Stub handlers for the three per-state action buttons ----------------
//
// Each handler returns a notification toast in the lifeguard + surfer voice
// that signals "wired, not yet implemented." Real action bodies are filled
// in during plan Task 36.5 stretch; the function signatures and onClickAction
// wiring in render.gs do not change when that work is done.

function onMarkAsExpectedClicked(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        "The lifeguard's logbook isn't open yet. Coming in a future swell."
      )
    )
    .build();
}

function onSeeAllEvidenceClicked(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        "The full report's still drying on the clipboard. Coming in a future swell."
      )
    )
    .build();
}

function onReportAndDeleteClicked(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        "Cleanup crew's off-shift. We'll haul this one out in a future swell."
      )
    )
    .build();
}

/**
 * Fallback handler for the UNKNOWN-state button defined in render.gs's
 * PALETTE table. Not currently exercised on any happy path (the backend's
 * scoring policy always returns SAFE / SUSPICIOUS / MALICIOUS for a valid
 * scan) but kept for parity so render.gs never references an undefined
 * function name.
 */
function onRescanClicked(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText(
        'Re-open the email to re-scan.'
      )
    )
    .build();
}
