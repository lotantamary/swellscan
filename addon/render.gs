/**
 * Verdict card builder for Swellscan.
 *
 * Consumes the Verdict payload returned by the backend (`POST /score`) plus
 * a few presentation-only fields the trigger function attaches (subject,
 * sender, detectors_fired, llm_invoked) and renders the card the user sees
 * in the Gmail sidebar.
 *
 * Visual decisions in this file are locked - see plan Task 25 and the
 * canonical mockup at addon/design-refs/preview-final-v2.png. Anything
 * surfaced to the user uses plain ASCII hyphens only; no em-dashes.
 */

const PALETTE = {
  'SAFE':       { color: '#6e9c87', btnText: 'Mark as expected', btnHandler: 'onMarkAsExpectedClicked' },
  'SUSPICIOUS': { color: '#d49a3f', btnText: 'See all evidence', btnHandler: 'onSeeAllEvidenceClicked' },
  'MALICIOUS':  { color: '#b8442b', btnText: 'Report & delete',  btnHandler: 'onReportAndDeleteClicked' },
  'UNKNOWN':    { color: '#808080', btnText: 'Re-scan',           btnHandler: 'onRescanClicked' },
};

const SEVERITY_RANK = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0 };

/**
 * Build the verdict card from an enriched Verdict object. The card is the
 * single source of truth for what the user reads about this scan.
 */
function buildVerdictCard(verdict) {
  const p = PALETTE[verdict.label] || PALETTE.UNKNOWN;
  const meta = computeMetaCounts(verdict);
  const findings = sortAndTrimFindings(verdict.evidence || []);
  const card = CardService.newCardBuilder();

  // 1. Hero illustration (2:1 PNG served by the backend).
  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newImage()
        .setImageUrl(getBackendUrl() + '/illustration/' + verdict.label)
        .setAltText('Swellscan: ' + verdict.label)
    )
  );

  // 2. Verdict line + meta line.
  const detectorWord = meta.detectorsFired === 1 ? 'detector' : 'detectors';
  const llmText = meta.llmInvoked ? 'LLM consulted' : 'LLM not needed';
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph().setText(
          '<b><font color="' + p.color + '">' + escapeHtml(String(verdict.label)) +
          '</font></b>  -  <b>' + Number(verdict.score) + ' / 100</b>'
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          '<font color="#5f6368">' + String(verdict.confidence || 'UNKNOWN').toUpperCase() +
          ' conf &middot; ' + meta.detectorsFired + ' ' + detectorWord +
          ' &middot; ' + llmText + '</font>'
        )
      )
  );

  // 3. Subject + sender (the user verifies the lookalike domain with their own eyes).
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph().setText(
          '<b>' + escapeHtml(truncate(verdict.subject || '', 80)) + '</b>'
        )
      )
      .addWidget(
        CardService.newTextParagraph().setText(
          '<font color="#5f6368">' + escapeHtml(verdict.sender || '') + '</font>'
        )
      )
  );

  // 4. Summary: bold + palette-colored opener, line break, italic body.
  if (verdict.summary) {
    const parts = splitOpener(verdict.summary);
    const summaryHtml =
      '<b><font color="' + p.color + '">' + escapeHtml(parts.opener) + '</font></b>' +
      (parts.body ? '<br><i>' + escapeHtml(parts.body) + '</i>' : '');
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(summaryHtml)
      )
    );
  }

  // 5. Findings: top 5 sorted by severity then confidence.
  if (findings.length > 0) {
    const section = CardService.newCardSection();
    const signalWord = findings.length === 1 ? 'signal' : 'signals';
    section.addWidget(
      CardService.newTextParagraph().setText(
        '<b>FINDINGS: <font color="' + p.color + '">' +
        findings.length + ' ' + signalWord + ' detected</font></b>'
      )
    );
    findings.forEach(function (e) {
      const mitre = (e.mitre_techniques || []).join(', ');
      const top = String(e.severity || 'unknown').toUpperCase() + (mitre ? ' · ' + mitre : '');
      section.addWidget(
        CardService.newDecoratedText()
          .setText(String(e.signal || 'unknown_signal'))
          .setTopLabel(top)
          .setBottomLabel(truncate(e.explanation || '', 200))
          .setWrapText(true)
          .setIconUrl(getBackendUrl() + '/dot/' + (e.severity || 'low'))
      );
    });
    card.addSection(section);
  }

  // 6. Fixed footer button (stub-wired - real action lives in Task 36.5 stretch).
  card.setFixedFooter(
    CardService.newFixedFooter().setPrimaryButton(
      CardService.newTextButton()
        .setText(p.btnText)
        .setBackgroundColor(p.color)
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName(p.btnHandler))
    )
  );

  return card.build();
}

/**
 * Filter info-severity evidence, sort descending by severity then confidence,
 * keep the top 5. Anything beyond 5 is intentionally hidden to keep the card
 * focused; the (stretch) "See all evidence" button would show the full list.
 */
function sortAndTrimFindings(evidence) {
  return evidence
    .filter(function (e) { return e.severity !== 'info'; })
    .sort(function (a, b) {
      const sevDiff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;
      return (b.confidence || 0) - (a.confidence || 0);
    })
    .slice(0, 5);
}

/**
 * Compute the two meta-line counts. If the trigger has already attached
 * detectors_fired / llm_invoked we use those; otherwise we derive them so
 * this function is safe to call against a raw backend verdict too.
 *
 * detectors_fired = unique detectors that emitted at least one non-info
 * evidence item (i.e. how many independent systems flagged something).
 */
function computeMetaCounts(verdict) {
  let detectorsFired = verdict.detectors_fired;
  if (detectorsFired == null) {
    const seen = {};
    (verdict.evidence || []).forEach(function (e) {
      if (e.severity !== 'info' && e.detector) seen[e.detector] = true;
    });
    detectorsFired = Object.keys(seen).length;
  }
  let llmInvoked = verdict.llm_invoked;
  if (llmInvoked == null) {
    llmInvoked = (verdict.detectors_run || []).indexOf('llm') !== -1;
  }
  return { detectorsFired: detectorsFired, llmInvoked: llmInvoked };
}

/**
 * Split the summary on the first sentence boundary. Trailing punctuation
 * is stripped from the opener so it reads as a clean lifeguard directive
 * rather than a fragment ending in a period.
 *
 * Returns { opener, body }. If there is no sentence boundary, body is "".
 */
function splitOpener(text) {
  const s = String(text || '');
  const m = s.match(/^([^.!?]+)[.!?]\s*([\s\S]*)$/);
  if (!m) return { opener: s.trim(), body: '' };
  return { opener: m[1].trim(), body: m[2].trim() };
}

/**
 * Minimal HTML escaping for the inline subset CardService TextParagraph
 * supports (it parses <b>, <i>, <u>, <s>, <a>, <br>, <font>; everything
 * else risks rendering as text or stripping). We only have to escape user
 * data we splice into our own markup, not anything we hard-coded.
 */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncate(s, n) {
  s = String(s);
  return s.length > n ? s.substring(0, n - 1) + '...' : s;
}
