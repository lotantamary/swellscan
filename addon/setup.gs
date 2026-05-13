/**
 * One-time configuration for the Swellscan Add-on.
 *
 * After pasting the addon/ files into a new Apps Script project, open the
 * Apps Script editor, select the `setup` function in the toolbar dropdown,
 * and click Run. Approve OAuth scopes when prompted. The backend URL and
 * OIDC audience are written to ScriptProperties (project-level, shared
 * across all users of this Add-on) — every later call reads them from
 * there instead of hardcoding values into source.
 */
function setup() {
  const BACKEND_URL = 'https://swellscan-backend-102679409749.us-central1.run.app';
  const OIDC_AUDIENCE = 'https://swellscan-backend-102679409749.us-central1.run.app';

  PropertiesService.getScriptProperties().setProperties({
    'BACKEND_URL': BACKEND_URL,
    'OIDC_AUDIENCE': OIDC_AUDIENCE,
  });

  Logger.log('Swellscan setup complete. BACKEND_URL=' + BACKEND_URL);
}

/**
 * Returns the configured backend URL. Throws if setup has not been run yet —
 * a loud failure here is better than silently posting to "undefined/score".
 */
function getBackendUrl() {
  const url = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  if (!url) {
    throw new Error('BACKEND_URL not configured. Run setup() in the Apps Script editor.');
  }
  return url;
}

/**
 * Returns the OIDC audience claim that the backend expects in incoming ID
 * tokens. Falls back to BACKEND_URL when unset (current state — the two are
 * identical for direct Cloud Run access). Kept as a separate property so a
 * future custom-domain deployment can change BACKEND_URL without breaking
 * token verification.
 */
function getOidcAudience() {
  return PropertiesService.getScriptProperties().getProperty('OIDC_AUDIENCE') || getBackendUrl();
}
