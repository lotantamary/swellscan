/**
 * Per-sender history stored in Google's per-user UserProperties.
 *
 * This is the user-owned half of the per-sender baselining feature - the
 * backend never persists baseline data. On every scan the Add-on reads the
 * sender's existing entry, bundles it into the request payload, and after
 * the verdict is returned writes back an updated entry with the new
 * signing domain, IP prefix, and send hour rolled into the fingerprint.
 *
 * Concurrency safety: read-modify-write is wrapped in a per-user lock
 * (LockService.getUserLock) with a 5-second timeout. A `last_messages`
 * ring buffer makes the update idempotent for the same message_id, so
 * double-clicks or repeat scans never double-count.
 *
 * Storage shape (matches the backend SenderHistory Pydantic model):
 * {
 *   "<address-lowercase>": {
 *     from_address, first_seen, messages_seen,
 *     typical_signing_domains, typical_ip_prefixes,
 *     typical_send_hours, last_messages
 *   },
 *   ...
 * }
 */

const HISTORY_KEY = 'sender_history_v1';
const RING_BUFFER_SIZE = 20;          // recent message_ids per sender
const MAX_SIGNING_DOMAINS = 10;       // bounded growth - older entries drop off
const MAX_IP_PREFIXES = 10;           // bounded growth
const MAX_SEND_HOURS = 24;            // can never exceed 24 anyway, explicit cap
const LOCK_TIMEOUT_MS = 5000;

/**
 * Return the history entry for the given address, or null if there is no
 * history yet for that sender. Called by client.gs while building the
 * request payload.
 */
function readSenderHistoryEntry(fromAddress) {
  if (!fromAddress) return null;
  const props = PropertiesService.getUserProperties();
  const blob = props.getProperty(HISTORY_KEY);
  if (!blob) return null;
  let all;
  try {
    all = JSON.parse(blob);
  } catch (err) {
    Logger.log('sender_history blob unparseable: ' + err.message);
    return null;
  }
  return all[fromAddress.toLowerCase()] || null;
}

/**
 * Fold the just-scanned message into the sender's history. No-op if the
 * sender has no address, the lock can't be acquired in 5 seconds, or the
 * message_id has already been folded in.
 */
function updateSenderHistoryAfterScan(payload, verdict) {
  if (!payload || !payload.from || !payload.from.address) return;
  const addr = payload.from.address.toLowerCase();
  if (!addr) return;

  const lock = LockService.getUserLock();
  if (!lock.tryLock(LOCK_TIMEOUT_MS)) {
    Logger.log('sender_history: skipping update - lock timeout for ' + addr);
    return;
  }
  try {
    const props = PropertiesService.getUserProperties();
    const blob = props.getProperty(HISTORY_KEY);
    let all = {};
    if (blob) {
      try { all = JSON.parse(blob); } catch (err) { all = {}; }
    }

    const entry = all[addr] || {
      from_address: addr,
      first_seen: payload.received_at,
      messages_seen: 0,
      typical_signing_domains: [],
      typical_ip_prefixes: [],
      typical_send_hours: [],
      last_messages: [],
    };

    // Idempotency: double-click or re-scan of the same message is a no-op.
    if (entry.last_messages.indexOf(payload.message_id) !== -1) {
      return;
    }

    entry.messages_seen += 1;
    entry.last_messages = [payload.message_id].concat(entry.last_messages).slice(0, RING_BUFFER_SIZE);

    // Signing domain from Authentication-Results header. Match both
    // `header.d=domain.com` (the d= signing domain) AND
    // `header.i=@domain.com` (Gmail's more common format; the i= identity
    // with optional leading @). Either is the DKIM signing domain.
    const authRes = (payload.headers && payload.headers.authentication_results) || '';
    const dkimMatch = authRes.match(/header\.[di]=@?([\w.\-]+)/i);
    if (dkimMatch) {
      const dom = dkimMatch[1].toLowerCase();
      if (entry.typical_signing_domains.indexOf(dom) === -1) {
        entry.typical_signing_domains.push(dom);
        if (entry.typical_signing_domains.length > MAX_SIGNING_DOMAINS) {
          entry.typical_signing_domains.shift();
        }
      }
    }

    // IP prefix - first two octets of X-Originating-IP.
    const ip = (payload.headers && payload.headers.x_originating_ip) || '';
    if (ip) {
      const prefix = ip.split('.').slice(0, 2).join('.');
      if (prefix && entry.typical_ip_prefixes.indexOf(prefix) === -1) {
        entry.typical_ip_prefixes.push(prefix);
        if (entry.typical_ip_prefixes.length > MAX_IP_PREFIXES) {
          entry.typical_ip_prefixes.shift();
        }
      }
    }

    // Send hour (UTC).
    try {
      const hour = new Date(payload.received_at).getUTCHours();
      if (!isNaN(hour) && entry.typical_send_hours.indexOf(hour) === -1) {
        entry.typical_send_hours.push(hour);
        if (entry.typical_send_hours.length > MAX_SEND_HOURS) {
          entry.typical_send_hours.shift();
        }
      }
    } catch (err) {
      // received_at unparseable; skip the hour fingerprint for this scan.
    }

    all[addr] = entry;
    props.setProperty(HISTORY_KEY, JSON.stringify(all));
  } finally {
    lock.releaseLock();
  }
}
