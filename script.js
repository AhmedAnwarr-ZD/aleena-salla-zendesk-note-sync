/***** ===== Salla (OAuth) ↔ Zendesk: Private Note → Salla Order History =====
Required Script Properties (File → Project properties → Script properties)
-----------------------------------------------------------------------
SALLA_CLIENT_ID       : <Salla OAuth client_id>
SALLA_CLIENT_SECRET   : <Salla OAuth client_secret>
SALLA_REFRESH_TOKEN   : <Salla OAuth refresh_token>   // from app.store.authorize

ZD_SUBDOMAIN          : shopaleena
ZD_EMAIL              : aanwar@tgc-ksa.com
ZD_API_TOKEN          : <Zendesk API token>
SHARED_KEY            : <shared secret you append as ?key=... on webhook>

Optional:
TZ                    : Asia/Riyadh
ORDER_REGEX           : (21\\d{6,})     // Salla order numbers shown to customers start with 21

OAuth Endpoints:
- Salla token (refresh): POST https://accounts.salla.sa/oauth2/token

Salla Merchant API:
- Base URL            : https://api.salla.dev/admin/v2
- List orders         : GET  /orders?reference_id=<num>
- Order details       : GET  /orders/{order_id}
- Add history         : POST /orders/{order_id}/histories  { "note": "..." }

Zendesk:
- Audits              : GET  https://<subdomain>.zendesk.com/api/v2/tickets/{ticket_id}/audits.json
- User                : GET  https://<subdomain>.zendesk.com/api/v2/users/{user_id}.json
***********************************************************************/

const SP = PropertiesService.getScriptProperties();

const SALLA_BASE      = 'https://api.salla.dev/admin/v2';
const SALLA_TOKEN_URL = 'https://accounts.salla.sa/oauth2/token';

const ZD_SUBDOMAIN  = SP.getProperty('ZD_SUBDOMAIN');
const ZD_EMAIL      = SP.getProperty('ZD_EMAIL');
const ZD_TOKEN      = SP.getProperty('ZD_API_TOKEN');
const SHARED_KEY    = SP.getProperty('SHARED_KEY');
const TZ            = SP.getProperty('TZ') || 'Asia/Riyadh';
const ORDER_REGEX   = new RegExp(SP.getProperty('ORDER_REGEX') || '(21\\d{6,})');

/* ===================== Web App Entrypoints ===================== */

function doPost(e) {
  try {
    Logger.log('=== doPost START ===');
    Logger.log('Raw event: ' + JSON.stringify(e, null, 2));

    const p = normalizeParams_(e);
    Logger.log('Normalized params: ' + JSON.stringify(p, null, 2));

    guardKey_(p.key);
    Logger.log('Key OK');

    const out = syncNoteToSalla_(Number(p.ticket_id), {
      internal_note: p.internal_note,
      author: p.author ? { name: p.author.name } : null
      // salla_store_id removed – we use OAuth for single store
    });

    Logger.log('Sync result: ' + JSON.stringify(out, null, 2));
    Logger.log('=== doPost END (success) ===');

    return ContentService
      .createTextOutput(JSON.stringify({ ok: true, ...out }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    Logger.log('=== doPost ERROR === ' + err);
    return ContentService
      .createTextOutput(JSON.stringify({ ok: false, error: String(err) }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  // For quick manual tests in a browser
  return doPost(e);
}

/* ===================== Core Flow ===================== */
/**
 * 1) Use webhook overrides (internal_note, author.name) when provided.
 * 2) Otherwise fetch latest private note + agent from Zendesk audits.
 * 3) Extract Salla order number (21xxxxxx) from note text.
 * 4) Resolve order by reference/id and append note to Order History via OAuth.
 */
function syncNoteToSalla_(ticketId, overrides) {
  Logger.log('syncNoteToSalla_ called with ticketId=' + ticketId + ', overrides=' + JSON.stringify(overrides));
  overrides = overrides || {};
  if (!ticketId) throw new Error('Missing ticket_id');

  // We now require OAuth props + Zendesk props
  assertProps_([
    'ZD_SUBDOMAIN',
    'ZD_EMAIL',
    'ZD_API_TOKEN',
    'SHARED_KEY',
    'SALLA_CLIENT_ID',
    'SALLA_CLIENT_SECRET',
    'SALLA_REFRESH_TOKEN'
  ]);

  // 1) Note + Agent name (prefer webhook payload)
  let noteText = (overrides.internal_note || '').trim();
  let agentName = (overrides.author && overrides.author.name)
    ? String(overrides.author.name).trim()
    : '';

  Logger.log('Initial noteText="' + noteText + '", agentName="' + agentName + '"');

  if (!noteText || !agentName) {
    const latest = getLatestPrivateNote_(ticketId);
    Logger.log('Fetched from audits: ' + JSON.stringify(latest));
    const zNote = latest.noteText;
    const authorId = latest.authorId;
    if (!zNote) throw new Error('No private note found (and none provided).');
    if (!noteText) noteText = zNote;
    if (!agentName) {
      const zName = getZendeskUserName_(authorId);
      agentName = zName || ('Agent ' + authorId);
    }
  }

  Logger.log('Final noteText="' + noteText + '", agentName="' + agentName + '"');

  // 2) Extract Salla order number (21xxxxxx only)
  const orderRef = extractSallaOrderRef_(noteText);
  Logger.log('Extracted orderRef=' + orderRef);
  if (!orderRef) {
    throw new Error('Could not detect Salla order number (21xxxxxx) in note text.');
  }

  // 3) Resolve order ID via OAuth-protected API
  const orderId = sallaResolveOrderIdByReference_(orderRef);
  Logger.log('Resolved orderId=' + orderId);
  if (!orderId) throw new Error('Salla order not found for reference/id=' + orderRef);

  // 4) Build message + append to history
  const ts = Utilities.formatDate(new Date(), TZ, 'yyyy-MM-dd');
  const messageBlock = '#' + ticketId + ' | ' + agentName + ' | ' + ts + '\n\n' + noteText;
  Logger.log('messageBlock:\n' + messageBlock);

  sallaAppendHistory_(orderId, messageBlock);
  Logger.log('History appended successfully');

  return { ticketId, orderRef, orderId, agentName, ts };
}

/* ===================== Zendesk Helpers ===================== */

function getLatestPrivateNote_(ticketId) {
  const url = 'https://' + ZD_SUBDOMAIN + '.zendesk.com/api/v2/tickets/' + ticketId + '/audits.json';
  const resp = UrlFetchApp.fetch(url, {
    method: 'get',
    muteHttpExceptions: true,
    headers: {
      'Authorization': 'Basic ' + Utilities.base64Encode(ZD_EMAIL + '/token:' + ZD_TOKEN)
    }
  });
  if (resp.getResponseCode() >= 400) {
    throw new Error('Zendesk audits failed: ' + resp.getResponseCode() + ' ' + resp.getContentText());
  }
  const audits = (JSON.parse(resp.getContentText()) || {}).audits || [];

  for (let i = audits.length - 1; i >= 0; i--) {
    const audit = audits[i];
    const evs = audit.events || [];
    for (const ev of evs) {
      if (ev.type === 'Comment' && ev.public === false) {
        const body = (ev.body || '').trim();
        return { noteText: body, authorId: audit.author_id };
      }
    }
  }
  return { noteText: null, authorId: null };
}

function getZendeskUserName_(userId) {
  if (!userId) return null;
  const url = 'https://' + ZD_SUBDOMAIN + '.zendesk.com/api/v2/users/' + userId + '.json';
  const resp = UrlFetchApp.fetch(url, {
    method: 'get',
    muteHttpExceptions: true,
    headers: {
      'Authorization': 'Basic ' + Utilities.base64Encode(ZD_EMAIL + '/token:' + ZD_TOKEN)
    }
  });
  if (resp.getResponseCode() >= 400) return null;
  const user = (JSON.parse(resp.getContentText()) || {}).user || {};
  return user.name || null;
}

/* ===================== Salla OAuth Helpers ===================== */

function getSallaAccessToken_() {
  const existing = SP.getProperty('SALLA_ACCESS_TOKEN');
  const expStr   = SP.getProperty('SALLA_ACCESS_TOKEN_EXP');
  const now = Date.now();

  if (existing && expStr) {
    const exp = Number(expStr);
    if (!isNaN(exp) && now < exp - 60 * 1000) { // 60 sec safety margin
      Logger.log('Using cached Salla access token (expires at ' + exp + ')');
      return existing;
    }
  }

  Logger.log('Refreshing Salla access token via refresh_token');
  return refreshSallaAccessToken_();
}

function refreshSallaAccessToken_() {
  const clientId     = SP.getProperty('SALLA_CLIENT_ID');
  const clientSecret = SP.getProperty('SALLA_CLIENT_SECRET');
  const refreshToken = SP.getProperty('SALLA_REFRESH_TOKEN');

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Missing Salla OAuth properties: SALLA_CLIENT_ID / SALLA_CLIENT_SECRET / SALLA_REFRESH_TOKEN');
  }

  const payload = {
    grant_type: 'refresh_token',
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken
  };

  const resp = UrlFetchApp.fetch(SALLA_TOKEN_URL, {
    method: 'post',
    contentType: 'application/x-www-form-urlencoded',
    payload: payload,
    muteHttpExceptions: true
  });

  const code = resp.getResponseCode();
  const body = resp.getContentText() || '';
  Logger.log('Salla OAuth refresh code=' + code + ', body=' + body.substring(0, 300));

  if (code >= 400) {
    throw new Error('Salla OAuth refresh failed: ' + code + ' ' + body.substring(0,300));
  }

  const data = JSON.parse(body);
  const accessToken = data.access_token;
  if (!accessToken) {
    throw new Error('Salla OAuth refresh: no access_token in response');
  }

  const expiresIn = data.expires_in || 3600; // seconds
  const newRefresh = data.refresh_token || refreshToken;

  SP.setProperty('SALLA_ACCESS_TOKEN', accessToken);
  SP.setProperty('SALLA_ACCESS_TOKEN_EXP', String(Date.now() + expiresIn * 1000));
  SP.setProperty('SALLA_REFRESH_TOKEN', newRefresh);

  return accessToken;
}

/**
 * Generic Salla fetch with OAuth and optional 401 retry.
 */
function sallaAuthorizedFetch_(url, options, allowRetry) {
  allowRetry = (allowRetry === undefined) ? true : allowRetry;
  const token = getSallaAccessToken_();

  options = options || {};
  const headers = options.headers || {};
  headers['Authorization'] = 'Bearer ' + token;
  options.headers = headers;
  options.muteHttpExceptions = true;

  let resp = UrlFetchApp.fetch(url, options);
  let code = resp.getResponseCode();
  let body = resp.getContentText() || '';

  if (code === 401 && allowRetry) {
    Logger.log('Salla call got 401, trying forced token refresh...');
    const fresh = refreshSallaAccessToken_();
    headers['Authorization'] = 'Bearer ' + fresh;
    options.headers = headers;
    resp = UrlFetchApp.fetch(url, options);
    code = resp.getResponseCode();
    body = resp.getContentText() || '';
  }

  return { response: resp, code: code, body: body };
}

/**
 * 1) Try /orders?reference_id=<ref> (list)
 * 2) If nothing found and ref is numeric, try /orders/<ref> (details)
 * Returns numeric order_id or null.
 */
function sallaResolveOrderIdByReference_(referenceId) {
  const listUrl = SALLA_BASE + '/orders?reference_id=' + encodeURIComponent(referenceId);
  Logger.log('Calling Salla list orders: ' + listUrl);

  let { response, code, body } = sallaAuthorizedFetch_(listUrl, { method: 'get' }, true);
  Logger.log('Salla list orders code=' + code + ', body=' + body.substring(0, 300));

  if (code === 200) {
    try {
      const parsed = JSON.parse(body) || {};
      const data = parsed.data;
      if (Array.isArray(data) && data.length > 0) {
        return data[0].id || null;
      }
      if (!Array.isArray(data) && data && data.id) {
        return data.id;
      }
    } catch (e) {
      throw new Error('Salla list orders JSON parse error: ' + e + ' | body=' + body.substring(0,300));
    }
  } else if (code >= 400 && code !== 404) {
    throw new Error('Salla list orders failed: ' + code + ' ' + body.substring(0,300));
  }

  // --- Fallback: try as order_id path param if it's numeric ---
  if (!/^\d+$/.test(String(referenceId))) {
    return null;
  }

  const detailsUrl = SALLA_BASE + '/orders/' + encodeURIComponent(referenceId);
  Logger.log('Calling Salla order details: ' + detailsUrl);

  ({ response, code, body } = sallaAuthorizedFetch_(detailsUrl, { method: 'get' }, true));
  Logger.log('Salla order details code=' + code + ', body=' + body.substring(0,300));

  if (code === 200) {
    try {
      const parsed = JSON.parse(body) || {};
      const data = parsed.data || {};
      if (data.id) return data.id;
      return null;
    } catch (e) {
      throw new Error('Salla order details JSON parse error: ' + e + ' | body=' + body.substring(0,300));
    }
  }

  if (code >= 400 && code !== 404) {
    throw new Error('Salla order details failed: ' + code + ' ' + body.substring(0,300));
  }

  return null;
}

function sallaAppendHistory_(orderId, note) {
  const url = SALLA_BASE + '/orders/' + orderId + '/histories';
  Logger.log('Posting history to Salla url=' + url + ', orderId=' + orderId);

  const { code, body } = sallaAuthorizedFetch_(url, {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify({ note: String(note) })
  }, true);

  Logger.log('Salla history response code=' + code + ', body=' + body.substring(0, 300));

  if (code >= 300) {
    throw new Error('Salla add history failed: ' + code + ' ' + body.substring(0,300));
  }
}

/* ===================== Extraction & Utils ===================== */

function extractSallaOrderRef_(text) {
  if (!text) return null;

  // Strict regex (defaults to 21xxxxxx, 8+ digits)
  const m = text.match(ORDER_REGEX);
  if (m) return m[1] || m[0];

  // Fallback: any long digit run that starts with 21
  const candidates = text.match(/\d{8,}/g) || [];
  const pick = candidates ? candidates.find(function(d){ return d.indexOf('21') === 0; }) : null;
  return pick || null;
}

function normalizeParams_(e) {
  const params = {};
  if (e && e.parameter) Object.keys(e.parameter).forEach(function(k){ params[k] = e.parameter[k]; });
  if (e && e.postData) {
    const ct = (e.postData.type || '').toLowerCase();
    if (ct.indexOf('application/json') >= 0) {
      try { Object.assign(params, JSON.parse(e.postData.contents || '{}')); } catch (_) {}
    }
  }
  return params;
}

function guardKey_(incoming) {
  if (!SHARED_KEY) throw new Error('SHARED_KEY not configured.');
  if (!incoming || incoming !== SHARED_KEY) throw new Error('Unauthorized: bad key.');
}

function assertProps_(keys) {
  const missing = keys.filter(function(k){ return !SP.getProperty(k); });
  if (missing.length) throw new Error('Missing Script Properties: ' + missing.join(', '));
}

/* ===================== Manual Tester & Scheduled Refresh ===================== */

function syncNoteTester() {
  const ticketId = Number(Browser.inputBox('Zendesk Ticket ID?'));
  const res = syncNoteToSalla_(ticketId, null);
  Logger.log(res);
}

function testSallaToken() {
  const token = getSallaAccessToken_();
  Logger.log('Access token (truncated)=' + (token ? token.substring(0, 20) + '...' : 'null'));

  const url = SALLA_BASE + '/orders?per_page=1';
  const { code, body } = sallaAuthorizedFetch_(url, { method: 'get' }, false);
  Logger.log('testSallaToken code=' + code + ', body=' + body.substring(0,300));
}

/**
 * For Salla recommendation: schedule this every ~10 days via Apps Script Triggers.
 */
function scheduledSallaTokenRefresh() {
  Logger.log('Running scheduled Salla token refresh...');
  const token = refreshSallaAccessToken_();
  Logger.log('New access token (truncated)=' + token.substring(0, 20) + '...');
}
