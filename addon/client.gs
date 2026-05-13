/**
 * HTTP client + Gmail-to-payload builder for Swellscan.
 *
 * The Add-on's only outbound network call: POST /score on the backend,
 * authenticated with the current user's Google OIDC ID token (no shared
 * secret). The backend cryptographically verifies the token against
 * Google's public JWKs and checks the user's email against ALLOWED_USERS.
 */

/**
 * POST the email payload to the backend and return the parsed Verdict JSON.
 * Throws on any non-2xx response so the caller can render an error state.
 */
function callBackend(emailPayload) {
  const token = ScriptApp.getIdentityToken();
  const response = UrlFetchApp.fetch(getBackendUrl() + '/score', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'Authorization': 'Bearer ' + token },
    payload: JSON.stringify(emailPayload),
    muteHttpExceptions: true,        // we handle status codes ourselves
    validateHttpsCertificates: true, // explicit; default is true
    deadline: 25,                    // seconds; well under UrlFetchApp's 60s cap
  });
  const code = response.getResponseCode();
  if (code >= 400) {
    throw new Error('Backend returned ' + code + ': ' + response.getContentText().substring(0, 200));
  }
  return JSON.parse(response.getContentText());
}

/**
 * Build the backend's expected Email payload from the currently-open Gmail
 * message. Everything that reaches the backend is shaped by this function -
 * it is the trust boundary between Gmail's data model and ours.
 */
function buildEmailPayload(messageId, accessToken) {
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const msg = GmailApp.getMessageById(messageId);

  const from_ = parseFromHeader(msg.getFrom());
  const text = msg.getPlainBody().substring(0, 100000);
  const html = msg.getBody().substring(0, 100000);
  const urls = extractUrlsFromHtml(html);

  const attachments = msg.getAttachments({ includeAttachments: true, includeInlineImages: false })
    .slice(0, 20)
    .map(function (a) {
      return {
        filename: a.getName(),
        mime_type: a.getContentType(),
        size_bytes: a.getSize(),
        sha256: computeSha256(a.getBytes()),
      };
    });

  return {
    message_id: msg.getId(),
    from: from_,
    to: msg.getTo().split(',').map(function (s) { return s.trim(); }).slice(0, 100),
    subject: msg.getSubject(),
    received_at: msg.getDate().toISOString(),
    headers: parseHeaders(msg.getRawContent()),
    body: { text: text, html: html },
    urls_in_body: urls,
    attachments: attachments,
    sender_history: readSenderHistoryEntry(from_.address) || null,
  };
}

/**
 * Split a From: header into display name and address.
 * Examples handled:  Alice <a@b.com>   "Alice Q" <a@b.com>   a@b.com
 */
function parseFromHeader(from) {
  const m = from.match(/^(.*?)<(.+)>$/) || [null, from, from];
  const display = (m[1] || '').trim().replace(/^"|"$/g, '');
  const address = (m[2] || from).trim();
  return { display_name: display, address: address };
}

/**
 * Pull the specific headers the backend's detectors care about out of the
 * raw RFC 5322 source.
 *
 * RFC 5322 allows long headers to be *folded* across multiple physical lines,
 * where each continuation line starts with whitespace. A naive ^Name:(.+)$
 * regex would capture only the first line and silently drop the rest -
 * dangerous for Authentication-Results, which carries SPF/DKIM/DMARC verdicts
 * and is one of the most likely headers to be folded. So we unfold first
 * (continuation runs collapse to a single space) and then apply the regex.
 */
function parseHeaders(raw) {
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  const get = function (name) {
    const re = new RegExp('^' + name + ':\\s*(.+)$', 'mi');
    const match = unfolded.match(re);
    return match ? match[1].trim().substring(0, 4000) : '';
  };
  return {
    authentication_results: get('Authentication-Results'),
    received_spf: get('Received-SPF'),
    return_path: get('Return-Path'),
    reply_to: get('Reply-To'),
    message_id_header: get('Message-ID'),
    x_originating_ip: get('X-Originating-IP'),
  };
}

/**
 * Extract http(s) URLs from the HTML body. Used by the backend's URL
 * reputation detector. Captures both href targets and plain-text URLs;
 * the backend de-dupes and queries reputation services in parallel.
 */
function extractUrlsFromHtml(html) {
  const urls = new Set();
  const re = /https?:\/\/[^\s"'<>)]+/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    urls.add(m[0]);
  }
  return Array.from(urls).slice(0, 200);
}

/**
 * SHA-256 hex digest of attachment bytes. Apps Script's computeDigest returns
 * signed bytes (-128..127); we convert to unsigned and hex-encode each.
 * Result is exactly 64 hex chars - matches the backend Pydantic constraint.
 */
function computeSha256(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map(function (b) {
    return ((b < 0 ? b + 256 : b)).toString(16).padStart(2, '0');
  }).join('');
}
