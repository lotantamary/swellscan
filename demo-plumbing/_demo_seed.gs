/**
 * Demo-only sender-history seeding.
 *
 * NOT PART OF THE SWELLSCAN ADD-ON. The Path A install (which copies the
 * five files in addon/) never includes this script. It exists only to
 * pre-populate UserProperties on the demo Gmail account so the per-sender
 * baseline detector demonstrates meaningfully during the live interview.
 *
 * Why it has to live inside the Swellscan Apps Script project (and not a
 * sibling): PropertiesService.getUserProperties() is scoped to (script,
 * user). A sibling project would write to a different bucket than the one
 * Swellscan reads from at scan time. The function is therefore pasted into
 * the Swellscan Apps Script editor as a separate script file with a leading
 * underscore in the name (_demo_seed) so it is visually marked as plumbing.
 *
 * The committed source in this repository (demo-plumbing/_demo_seed.gs) is
 * the source of truth - Apps Script editor copy is downstream of it.
 *
 * Two senders are seeded:
 *
 *   1. invoice+statements@mail.anthropic.com - the actual sender of the
 *      Anthropic billing receipt already sitting in the demo inbox. Real
 *      header values were inspected first (DKIM header.d=mail.anthropic.com,
 *      sending IP prefix 54.240 via Amazon SES) so the baseline matches
 *      exactly what Swellscan will observe when scanning that email. Used
 *      by demo #1 of the live presentation (real-email SAFE scan,
 *      demonstrates baseline-known case of the per-sender-baseline moment).
 *
 *   2. accounts@orbitalvendor.com - a fictional vendor. Seeded with a
 *      "well-known relationship" fingerprint (30 prior messages, single
 *      signing domain, single IP prefix, business-hours range). Demo #6
 *      injects an email FROM this address but signed from gmail.com, from
 *      a different IP prefix, at an off-hour - mismatching all three
 *      baseline axes. That demo card surfaces BEC payment-urgency +
 *      three-axis baseline drift + the thread-hijack correlation rule
 *      (+20) on a single screen.
 *
 * Merge semantics (CRITICAL, plan-drift fix vs original Task 29 plan-code):
 * the function reads existing UserProperties first and MERGES seeded data
 * into it, never blindly overwrites. If the user has already scanned the
 * Anthropic email through Swellscan once, that real entry's last_messages
 * ring buffer is preserved; the seed only enriches messages_seen and the
 * typical-* fingerprint arrays. Safe to re-run.
 *
 * HISTORY_KEY is declared in addon/baseline.gs. Apps Script V8 concatenates
 * all script files into one global scope so the constant is visible here.
 */

function seedDemoHistory() {
  const props = PropertiesService.getUserProperties();
  const existingBlob = props.getProperty(HISTORY_KEY);

  let all = {};
  if (existingBlob) {
    try {
      all = JSON.parse(existingBlob);
    } catch (e) {
      Logger.log('Existing history blob unparseable, starting fresh: ' + e.message);
      all = {};
    }
  }

  const seeds = {
    'invoice+statements@mail.anthropic.com': {
      from_address: 'invoice+statements@mail.anthropic.com',
      first_seen: '2025-12-01T09:00:00Z',
      messages_seen: 30,
      typical_signing_domains: ['mail.anthropic.com'],
      typical_ip_prefixes: ['54.240'],
      // Broad UTC business-hours band so the real arrival hour falls inside
      // regardless of Anthropic's actual billing-job schedule. Anthropic
      // runs from US-Pacific; 13-21 UTC covers 6am-2pm PT.
      typical_send_hours: [13, 14, 15, 16, 17, 18, 19, 20, 21],
      last_messages: [],
    },
    'accounts@orbitalvendor.com': {
      from_address: 'accounts@orbitalvendor.com',
      first_seen: '2025-09-01T09:00:00Z',
      messages_seen: 30,
      typical_signing_domains: ['orbitalvendor.com'],
      typical_ip_prefixes: ['54.240'],
      typical_send_hours: [13, 14, 15, 16, 17, 18, 19, 20, 21],
      last_messages: [],
    },
  };

  let createdCount = 0;
  let mergedCount = 0;
  Object.keys(seeds).forEach(function (addr) {
    const seed = seeds[addr];
    const existing = all[addr];
    if (existing) {
      all[addr] = {
        from_address: seed.from_address,
        first_seen: seed.first_seen,
        messages_seen: Math.max(seed.messages_seen, existing.messages_seen || 0),
        typical_signing_domains: _seedMergeUnique(
          seed.typical_signing_domains,
          existing.typical_signing_domains || []
        ),
        typical_ip_prefixes: _seedMergeUnique(
          seed.typical_ip_prefixes,
          existing.typical_ip_prefixes || []
        ),
        typical_send_hours: _seedMergeUnique(
          seed.typical_send_hours,
          existing.typical_send_hours || []
        ),
        // Preserve real message_id idempotency history so re-scanning an
        // already-scanned message stays a no-op even after re-seeding.
        last_messages: existing.last_messages || [],
      };
      mergedCount += 1;
      Logger.log('MERGED existing entry for ' + addr);
    } else {
      all[addr] = seed;
      createdCount += 1;
      Logger.log('CREATED new entry for ' + addr);
    }
  });

  props.setProperty(HISTORY_KEY, JSON.stringify(all));
  Logger.log('--');
  Logger.log('Seed summary: ' + createdCount + ' created, ' + mergedCount + ' merged.');
  Logger.log('Total senders now in UserProperties: ' + Object.keys(all).length);
  Logger.log('Address list: ' + Object.keys(all).sort().join(', '));
}

/**
 * Read-only helper to print the current UserProperties sender-history blob.
 * Useful before/after seeding to verify state. Reads, never writes.
 */
function dumpSenderHistory() {
  const blob = PropertiesService.getUserProperties().getProperty(HISTORY_KEY);
  if (!blob) {
    Logger.log('UserProperties has no sender_history_v1 entry yet.');
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(blob);
  } catch (e) {
    Logger.log('Existing blob unparseable: ' + e.message);
    Logger.log('Raw blob (first 1000 chars): ' + blob.substring(0, 1000));
    return;
  }
  Logger.log('Senders in history: ' + Object.keys(parsed).length);
  Object.keys(parsed).forEach(function (addr) {
    Logger.log('--');
    Logger.log(addr + ':');
    Logger.log(JSON.stringify(parsed[addr], null, 2));
  });
}

/**
 * Reset helper: clear UserProperties entirely. Use only for re-rehearsing
 * from a clean baseline. Destructive - leaves no recovery path beyond
 * re-seeding.
 */
function clearSenderHistory() {
  PropertiesService.getUserProperties().deleteProperty(HISTORY_KEY);
  Logger.log('UserProperties sender_history_v1 entry deleted.');
}

/**
 * Targeted reset for the two demo seed entries only. Restores Anthropic
 * and orbitalvendor.com baselines to their canonical pre-scan state
 * without touching the rest of UserProperties.
 *
 * Use case: after the first scan of demo 6, the baseline updater wrote
 * `gmail.com` (the BEC injected DKIM domain) into orbitalvendor's
 * typical_signing_domains. On a second scan that pollution means
 * SENDER_DOMAIN_DRIFT no longer fires - we'd lose the demo moment. Run
 * this before re-rehearsing demo 6 to restore the clean baseline.
 *
 * Idempotent: re-running is safe. Other real-sender entries are
 * preserved.
 */
function resetDemoSeeds() {
  const props = PropertiesService.getUserProperties();
  const existingBlob = props.getProperty(HISTORY_KEY);
  let all = {};
  if (existingBlob) {
    try {
      all = JSON.parse(existingBlob);
    } catch (e) {
      Logger.log('Existing blob unparseable, starting fresh: ' + e.message);
      all = {};
    }
  }

  // Canonical seed values (same as seedDemoHistory, kept in sync).
  all['invoice+statements@mail.anthropic.com'] = {
    from_address: 'invoice+statements@mail.anthropic.com',
    first_seen: '2025-12-01T09:00:00Z',
    messages_seen: 30,
    typical_signing_domains: ['mail.anthropic.com'],
    typical_ip_prefixes: ['54.240'],
    typical_send_hours: [13, 14, 15, 16, 17, 18, 19, 20, 21],
    last_messages: [],
  };
  all['accounts@orbitalvendor.com'] = {
    from_address: 'accounts@orbitalvendor.com',
    first_seen: '2025-09-01T09:00:00Z',
    messages_seen: 30,
    typical_signing_domains: ['orbitalvendor.com'],
    typical_ip_prefixes: ['54.240'],
    typical_send_hours: [13, 14, 15, 16, 17, 18, 19, 20, 21],
    last_messages: [],
  };

  props.setProperty(HISTORY_KEY, JSON.stringify(all));
  Logger.log('RESET canonical state for Anthropic + orbitalvendor seed entries.');
  Logger.log('Total senders in history: ' + Object.keys(all).length);
}

function _seedMergeUnique(a, b) {
  const set = {};
  a.forEach(function (x) { set[String(x)] = x; });
  b.forEach(function (x) { set[String(x)] = x; });
  return Object.keys(set).map(function (k) { return set[k]; });
}
