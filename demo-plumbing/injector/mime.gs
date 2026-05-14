/**
 * RFC 5322 / MIME construction helpers for the demo email injector.
 *
 * Used by Code.gs to build raw message strings for Gmail.Users.Messages.insert.
 * Three message shapes covered:
 *   - Simple text/plain (no attachments) - most demos
 *   - text/html (rich HTML body) - sanitization-defeat demo
 *   - multipart/mixed with one attachment - .zip / .pdf.exe demos
 *
 * The whole RFC 5322 string is later base64url-encoded for the Gmail API's
 * 'raw' field. Helpers below produce the pre-encoded string only.
 */

/**
 * Convert a Date to RFC 5322 / RFC 2822 format with UTC offset notation.
 * Example output: "Sun, 10 May 2026 15:23:00 +0000"
 *
 * Apps Script's Utilities.formatDate supports a format string but the
 * ICU-style pattern is verbose. Manual construction is cleaner here.
 */
function rfc5322Date(date) {
  var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function pad(n) { return n < 10 ? '0' + n : String(n); }
  return days[date.getUTCDay()] + ', ' +
    pad(date.getUTCDate()) + ' ' +
    months[date.getUTCMonth()] + ' ' +
    date.getUTCFullYear() + ' ' +
    pad(date.getUTCHours()) + ':' +
    pad(date.getUTCMinutes()) + ':' +
    pad(date.getUTCSeconds()) + ' +0000';
}

/**
 * Encode the full raw RFC 5322 string as base64url (URL-safe base64) per
 * the Gmail API 'raw' field requirement. Apps Script's base64EncodeWebSafe
 * already produces URL-safe encoding.
 */
function base64UrlEncode(rfc5322String) {
  // Apps Script Utilities.base64EncodeWebSafe accepts a string and uses
  // UTF-8 by default. Result has '-' and '_' instead of '+' and '/'.
  return Utilities.base64EncodeWebSafe(rfc5322String, Utilities.Charset.UTF_8);
}

/**
 * Build a complete RFC 5322 message string with the headers Swellscan's
 * detectors care about. Caller supplies values; nothing inferred.
 *
 * opts = {
 *   from: '"Display Name" <addr@example.com>',
 *   to: 'addr@example.com',
 *   subject: 'Subject text',
 *   date: Date object,
 *   messageId: '<unique@host>',     // wrapped in <...>
 *   authResults: 'mx.google.com; spf=pass; dkim=pass; dmarc=pass',
 *   returnPath: '<addr@example.com>',     // optional
 *   replyTo: 'addr@example.com',          // optional
 *   originatingIp: '203.0.113.42',         // optional
 *   bodyText: 'plain text body',          // for text/plain or multipart text part
 *   bodyHtml: '<p>html body</p>',         // optional, makes message multipart/alternative
 *   attachments: [{filename, mimeType, base64Content}]  // optional
 * }
 */
function buildRfc5322Message(opts) {
  var headers = [];
  headers.push('From: ' + opts.from);
  headers.push('To: ' + opts.to);
  headers.push('Subject: ' + opts.subject);
  headers.push('Date: ' + rfc5322Date(opts.date));
  headers.push('Message-ID: ' + opts.messageId);
  headers.push('Authentication-Results: ' + opts.authResults);
  if (opts.returnPath) headers.push('Return-Path: ' + opts.returnPath);
  if (opts.replyTo) headers.push('Reply-To: ' + opts.replyTo);
  if (opts.originatingIp) headers.push('X-Originating-IP: [' + opts.originatingIp + ']');
  headers.push('MIME-Version: 1.0');

  var hasAttachments = opts.attachments && opts.attachments.length > 0;
  var hasHtml = !!opts.bodyHtml;

  if (hasAttachments) {
    var outerBoundary = '----=_swellscan_outer_' + randomHex(12);
    headers.push('Content-Type: multipart/mixed; boundary="' + outerBoundary + '"');
    var parts = [headers.join('\r\n'), '', ''];

    // First mixed part - body (may itself be multipart/alternative if HTML)
    parts.push('--' + outerBoundary);
    if (hasHtml) {
      var altBoundary = '----=_swellscan_alt_' + randomHex(12);
      parts.push('Content-Type: multipart/alternative; boundary="' + altBoundary + '"');
      parts.push('');
      parts.push('--' + altBoundary);
      parts.push('Content-Type: text/plain; charset=UTF-8');
      parts.push('Content-Transfer-Encoding: 7bit');
      parts.push('');
      parts.push(opts.bodyText || '');
      parts.push('--' + altBoundary);
      parts.push('Content-Type: text/html; charset=UTF-8');
      parts.push('Content-Transfer-Encoding: 7bit');
      parts.push('');
      parts.push(opts.bodyHtml);
      parts.push('--' + altBoundary + '--');
    } else {
      parts.push('Content-Type: text/plain; charset=UTF-8');
      parts.push('Content-Transfer-Encoding: 7bit');
      parts.push('');
      parts.push(opts.bodyText || '');
    }

    // One mixed part per attachment
    opts.attachments.forEach(function (att) {
      parts.push('--' + outerBoundary);
      parts.push('Content-Type: ' + att.mimeType + '; name="' + att.filename + '"');
      parts.push('Content-Transfer-Encoding: base64');
      parts.push('Content-Disposition: attachment; filename="' + att.filename + '"');
      parts.push('');
      // Wrap base64 at 76 chars per RFC 2045 - good MUA citizenship.
      parts.push(wrapBase64(att.base64Content, 76));
    });

    parts.push('--' + outerBoundary + '--');
    return parts.join('\r\n');
  }

  if (hasHtml) {
    var altBoundary2 = '----=_swellscan_alt_' + randomHex(12);
    headers.push('Content-Type: multipart/alternative; boundary="' + altBoundary2 + '"');
    var altParts = [headers.join('\r\n'), '', ''];
    altParts.push('--' + altBoundary2);
    altParts.push('Content-Type: text/plain; charset=UTF-8');
    altParts.push('Content-Transfer-Encoding: 7bit');
    altParts.push('');
    altParts.push(opts.bodyText || '');
    altParts.push('--' + altBoundary2);
    altParts.push('Content-Type: text/html; charset=UTF-8');
    altParts.push('Content-Transfer-Encoding: 7bit');
    altParts.push('');
    altParts.push(opts.bodyHtml);
    altParts.push('--' + altBoundary2 + '--');
    return altParts.join('\r\n');
  }

  headers.push('Content-Type: text/plain; charset=UTF-8');
  headers.push('Content-Transfer-Encoding: 7bit');
  return headers.join('\r\n') + '\r\n\r\n' + (opts.bodyText || '');
}

function wrapBase64(s, lineLen) {
  var out = [];
  for (var i = 0; i < s.length; i += lineLen) {
    out.push(s.substring(i, i + lineLen));
  }
  return out.join('\r\n');
}

function randomHex(n) {
  var s = '';
  while (s.length < n) s += Math.random().toString(16).substring(2);
  return s.substring(0, n);
}
