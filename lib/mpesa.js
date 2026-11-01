// The Daraja calls this tester makes. Port of mpesa.php.
// Nothing here decides whether a payout should happen: it sends what it is given and
// reports what came back, including failures, without interpreting them into success.
//
// State (log, token cache, lockout counter) lives in Upstash Redis, because a Vercel
// function has no disk that outlives the request.
const crypto = require('crypto');

class InputError extends Error {}

const env = process.env;
const isLive = () => (env.MPESA_ENV || '').trim().toLowerCase() === 'live';  // ponytail: unset means sandbox, so a missing var never moves real money
const baseUrl = () => (isLive() ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke');
const maxAmount = () => Number(env.MAX_AMOUNT || 100);
const allowedPhones = () => (env.ALLOWED_PHONES || '').split(',').map((s) => s.trim()).filter(Boolean);

/** A missing credential is a loud failure naming what is missing, never a silent empty string. */
function required(key) {
  const v = (env[key] || '').trim();
  if (!v || v.includes('PASTE')) throw new Error(`Missing required env var: ${key}`);
  // A 2048-bit RSA block is 256 bytes = 344 base64 chars. Anything else is the plain password.
  if (key === 'SECURITY_CREDENTIAL' && !credentialLooksEncrypted(v)) {
    throw new Error(`SECURITY_CREDENTIAL looks wrong: ${v.length} characters, expected 344. `
      + 'Paste the ENCRYPTED value, not the initiator password. See credential.js.');
  }
  return v;
}

function credentialLooksEncrypted(v) {
  return v.length === 344 && /^[A-Za-z0-9+/]+={0,2}$/.test(v);
}

function configured() {
  return ['CONSUMER_KEY', 'CONSUMER_SECRET', 'SHORTCODE', 'INITIATOR_NAME', 'SECURITY_CREDENTIAL']
    .every((k) => { try { required(k); return true; } catch { return false; } });
}

// ------------------------------------------------------------------ redis

async function redis(...cmd) {
  const url = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('Redis not configured: add Upstash Redis in the Vercel Marketplace.');
  const res = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify(cmd) });
  const j = await res.json();
  if (j.error) throw new Error(`Redis: ${j.error}`);
  return j.result;
}

const LOG_KEY = 'mpesa:log';
const mlog = async (type, data) => {
  await redis('LPUSH', LOG_KEY, JSON.stringify({ ts: new Date().toISOString(), type, ...data }));
  await redis('LTRIM', LOG_KEY, 0, 199);
};
const readLog = async () => (await redis('LRANGE', LOG_KEY, 0, 199)).map((l) => {
  try { return JSON.parse(l); } catch { return { ts: '?', type: 'unparsed', body: l }; }
});
const clearLog = () => redis('DEL', LOG_KEY);

// ------------------------------------------------------------------ phone

/** Refuse rather than guess. A best-effort conversion pays a stranger, and M-Pesa has no recall. */
function toMsisdn(raw) {
  const input = String(raw ?? '').trim();
  if (!input) throw new InputError('Phone number is empty');
  let d = input.replace(/[\s\-().]/g, '');
  if (d.startsWith('+')) d = d.slice(1);
  if (!/^\d+$/.test(d)) throw new InputError(`Phone number has non-digits: ${input}`);

  let m;
  if (d.length === 10 && d[0] === '0') m = '254' + d.slice(1);
  else if (d.length === 9 && '71'.includes(d[0])) m = '254' + d;
  else if (d.length === 12 && d.startsWith('254')) m = d;
  else throw new InputError(`Not a recognisable Kenyan mobile: ${input}`);

  if (!/^254[71]\d{8}$/.test(m)) throw new InputError(`Not a Kenyan mobile number: ${input} (resolved to ${m})`);
  return m;
}

// ------------------------------------------------------------------ daraja

async function request(method, url, body, headers) {
  let res;
  try {
    // Long enough that a slow answer is not mistaken for a failure: an aborted request
    // whose payment went through is exactly the `unknown` state we never guess about.
    res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(55000) });
  } catch (e) {
    throw new Error(`Daraja request failed: ${e.message}`);
  }
  const raw = await res.text();
  let d;
  try { d = JSON.parse(raw); } catch { /* handled below */ }
  if (!d || typeof d !== 'object' || Array.isArray(d)) {
    throw new Error(`Daraja returned non-JSON (HTTP ${res.status}): ${raw.slice(0, 300)}`);
  }
  // On the response itself so "are we still pointed at sandbox?" is answerable from the error.
  return { ...d, _http_status: res.status, _url: url };
}

/** Daraja tokens last an hour; cache until a minute before expiry. */
async function accessToken() {
  const key = `mpesa:token:${isLive() ? 'live' : 'sandbox'}`;
  const cached = await redis('GET', key);
  if (cached) return cached;

  const basic = Buffer.from(`${required('CONSUMER_KEY')}:${required('CONSUMER_SECRET')}`).toString('base64');
  const r = await request('GET', `${baseUrl()}/oauth/v1/generate?grant_type=client_credentials`, null, { Authorization: `Basic ${basic}` });
  if (typeof r.access_token !== 'string' || !r.access_token) {
    throw new Error('Daraja returned no access token: ' + JSON.stringify(r));
  }
  await redis('SET', key, r.access_token, 'EX', Math.max(60, Number(r.expires_in || 3600) - 60));
  return r.access_token;
}

async function postJson(path, payload) {
  return request('POST', baseUrl() + path, payload, {
    Authorization: `Bearer ${await accessToken()}`,
    'Content-Type': 'application/json',
  });
}

// Where Safaricom calls back. The secret is derived from ADMIN_PASSWORD so the callback
// URLs are not open to anyone who guesses /callback.
const callbackBase = () => {
  const b = (env.CALLBACK_BASE || (env.VERCEL_PROJECT_PRODUCTION_URL && `https://${env.VERCEL_PROJECT_PRODUCTION_URL}`) || '').replace(/\/+$/, '');
  return /^https:\/\//i.test(b) ? b : '';
};
const callbackSecret = () => crypto.createHash('sha256').update('cb:' + (env.ADMIN_PASSWORD || '')).digest('hex').slice(0, 16);
const resultUrl = () => `${callbackBase()}/callback?kind=result&s=${callbackSecret()}`;
const timeoutUrl = () => `${callbackBase()}/callback?kind=timeout&s=${callbackSecret()}`;

function payout(key, msisdn, shillings, commandId, remarks) {
  return postJson('/mpesa/b2c/v3/paymentrequest', {
    OriginatorConversationID: key,
    InitiatorName: required('INITIATOR_NAME'),
    SecurityCredential: required('SECURITY_CREDENTIAL'),
    CommandID: commandId,
    Amount: shillings,
    PartyA: required('SHORTCODE'),
    PartyB: msisdn,
    Remarks: remarks,
    QueueTimeOutURL: timeoutUrl(),
    ResultURL: resultUrl(),
    // "Occassion" (two s's) is Safaricom's own v3 spelling; the correct one is silently ignored.
    Occassion: key,
  });
}

/** Asynchronous: returns their acknowledgement; the answer lands on ResultURL. */
function transactionStatus(transactionId, originatorId) {
  const payload = {
    Initiator: required('INITIATOR_NAME'),
    SecurityCredential: required('SECURITY_CREDENTIAL'),
    CommandID: 'TransactionStatusQuery',
    PartyA: required('SHORTCODE'),
    IdentifierType: '4',
    ResultURL: resultUrl(),
    QueueTimeOutURL: timeoutUrl(),
    Remarks: 'status check',
    Occassion: 'status',
  };
  // TransactionID wins: it identifies one payment exactly, an originator id is only unique to us.
  if ((transactionId || '').trim()) payload.TransactionID = transactionId.trim();
  else if ((originatorId || '').trim()) payload.OriginatorConversationID = originatorId.trim();
  else throw new InputError('A status query needs a receipt or an originator id.');
  return postJson('/mpesa/transactionstatus/v1/query', payload);
}

/** B2C debits the Utility account, not Working. The figure arrives on ResultURL. */
function accountBalance() {
  return postJson('/mpesa/accountbalance/v1/query', {
    Initiator: required('INITIATOR_NAME'),
    SecurityCredential: required('SECURITY_CREDENTIAL'),
    CommandID: 'AccountBalance',
    PartyA: required('SHORTCODE'),
    IdentifierType: '4',
    Remarks: 'balance check',
    QueueTimeOutURL: timeoutUrl(),
    ResultURL: resultUrl(),
  });
}

// ------------------------------------------------------------------ callbacks

/** ResultParameters arrive as a list of {Key, Value}; a lone one may arrive as a bare object. */
function resultParameters(result) {
  let raw = result?.ResultParameters?.ResultParameter ?? [];
  if (raw && raw.Key !== undefined && !Array.isArray(raw)) raw = [raw];
  const out = {};
  for (const p of raw) if (p && p.Key !== undefined) out[String(p.Key)] = p.Value ?? null;
  return out;
}

/** `Name|Currency|Current|Available|Reserved|Uncleared`, accounts joined by `&`. Take Available. */
function balancesFrom(params) {
  const packed = String(params.AccountBalance ?? '');
  if (!packed) return null;
  const out = {};
  for (const account of packed.split('&')) {
    const f = account.split('|');
    if (f.length >= 4) out[f[0].trim()] = parseFloat(f[3]) || 0;
  }
  return Object.keys(out).length ? out : null;
}

/** A queue timeout is NOT a failure: whether it was processed is unknown. */
function summariseCallback(body, kind) {
  const result = body.Result ?? body;
  const params = resultParameters(result);
  const code = result.ResultCode ?? null;
  const paid = String(code) === '0';
  return {
    kind,
    state: kind === 'timeout' ? 'UNKNOWN' : paid ? 'COMPLETED' : 'FAILED',
    code,
    desc: result.ResultDesc ?? null,
    receipt: params.TransactionReceipt ?? result.TransactionID ?? null,
    amount: params.TransactionAmount ?? params.Amount ?? null,
    paid_to: params.ReceiverPartyPublicName ?? null,
    originator: result.OriginatorConversationID ?? null,
    conversation: result.ConversationID ?? null,
    balances: balancesFrom(params),
  };
}

// ------------------------------------------------------------------ lockout guard
// 2001 = invalid initiator, 8006 = credential LOCKED (only the Business Administrator can undo).
// Count consecutive initiator rejections and stop before Safaricom does.

const STRIKES_KEY = 'mpesa:strikes';
const INITIATOR_CODES = ['2001', '8006'];

async function noteInitiatorResult(code) {
  if (code != null && INITIATOR_CODES.includes(String(code))) await redis('INCR', STRIKES_KEY);
  else if (String(code) === '0') await redis('DEL', STRIKES_KEY);   // a clean answer clears it
  // an ordinary payment failure says nothing about the initiator
}
const initiatorStrikes = async () => Number((await redis('GET', STRIKES_KEY)) || 0);
const clearInitiatorStrikes = () => redis('DEL', STRIKES_KEY);

/** Pull an error code out of either shape: a sync rejection or a callback Result. */
function initiatorCodeFrom(response) {
  for (const k of ['errorCode', 'ResponseCode', 'ResultCode']) if (response[k] != null) return String(response[k]);
  return null;
}

// ------------------------------------------------------------------ http helpers

const h = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

module.exports = {
  InputError, isLive, maxAmount, allowedPhones, required, configured, credentialLooksEncrypted,
  redis, mlog, readLog, clearLog, toMsisdn, payout, transactionStatus, accountBalance,
  callbackBase, callbackSecret, resultParameters, balancesFrom, summariseCallback,
  noteInitiatorResult, initiatorStrikes, clearInitiatorStrikes, initiatorCodeFrom, h,
};
