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
    const payload = buildEmailPayload(messageId, accessToken);
    const verdict = callBackend(payload);

    // Attach presentation-only fields the card builder expects. We do NOT
    // attach verdict.subject / verdict.sender any more - the card no
    // longer has a subject+sender section because the email is already
    // visible behind/above the Add-on sidebar, and if the sender is the
    // problem the detectors call it out in a specific finding row.
    verdict.detectors_fired = countDetectorsFired(verdict.evidence);
    verdict.llm_invoked = (verdict.detectors_run || []).indexOf('llm') !== -1;

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
