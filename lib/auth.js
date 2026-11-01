// Login for the page that can move money. Signed HttpOnly session cookie, brute-force lockout,
// optional TOTP second factor. The callback endpoint is exempt (Safaricom cannot log in).
const crypto = require('crypto');
const { redis } = require('./mpesa');

const env = process.env;
const SESSION_SECONDS = 3600;   // short on purpose: this page sends real money
const MAX_FAILS = 5;            // per IP, per 15 minutes
const MAX_FAILS_ALL = 30;       // across all IPs, so rotating addresses does not buy unlimited guesses

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(String(a)), sha(String(b)));
// Rotating ADMIN_PASSWORD (or the Daraja secret) invalidates every existing session.
const key = () => sha('sess:' + env.ADMIN_PASSWORD + ':' + env.CONSUMER_SECRET);
const sign = (exp) => crypto.createHmac('sha256', key()).update(String(exp)).digest('base64url');

// --- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ---
function totp(secretB32, t = Date.now()) {
  let bits = '';
  for (const c of secretB32.replace(/[\s=]/g, '').toUpperCase()) {
    const v = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    if (v < 0) throw new Error('ADMIN_TOTP_SECRET is not valid base32');
    bits += v.toString(2).padStart(5, '0');
  }
  const k = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const mac = crypto.createHmac('sha1', k).update(ctr).digest();
  const o = mac[19] & 15;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}
const totpOk = (secret, code) => [-1, 0, 1].some((d) => same(totp(secret, Date.now() + d * 30000), code));

// --- sessions ---
const issue = () => {
  const exp = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  return `${exp}.${sign(exp)}`;
};
function validSession(cookieHeader) {
  const raw = /(?:^|;\s*)sid=([^;]+)/.exec(cookieHeader || '')?.[1];
  const [exp, sig] = (raw || '').split('.');
  return !!(exp && sig && Number(exp) > Date.now() / 1000 && same(sig, sign(exp)));
}
const cookie = (v, age) => `sid=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;

/** Guard for pages. Unauthenticated → login page. Cross-site POSTs refused (SameSite=Strict is the first wall, this the second). */
function authed(req, res) {
  if (!env.ADMIN_PASSWORD) { res.status(503).send('Set ADMIN_PASSWORD in Vercel env vars.'); return false; }
  if (!validSession(req.headers.cookie)) { res.redirect(303, '/login'); return false; }
  if (req.method === 'POST' && (req.headers['sec-fetch-site'] || 'same-origin') !== 'same-origin') {
    res.status(403).send('Cross-site POST refused');
    return false;
  }
  return true;
}

/** Returns a Set-Cookie value on success, or an error string. */
async function login(req) {
  const ip = String(req.headers['x-forwarded-for'] || '?').split(',')[0].trim();
  const kIp = `mpesa:fail:${ip}`, kAll = 'mpesa:fail:all';
  const [nIp, nAll] = [Number(await redis('GET', kIp)) || 0, Number(await redis('GET', kAll)) || 0];
  if (nIp >= MAX_FAILS || nAll >= MAX_FAILS_ALL) return { error: 'Too many attempts. Try again in 15 minutes.' };

  const b = req.body || {};
  // Evaluate both so a wrong password and a wrong code take the same time.
  const pwOk = same(b.password ?? '', env.ADMIN_PASSWORD);
  const codeOk = !env.ADMIN_TOTP_SECRET || totpOk(env.ADMIN_TOTP_SECRET, String(b.code ?? '').trim());
  if (pwOk && codeOk) { await redis('DEL', kIp); return { cookie: cookie(issue(), SESSION_SECONDS) }; }

  for (const k of [kIp, kAll]) { if ((await redis('INCR', k)) === 1) await redis('EXPIRE', k, 900); }
  await new Promise((r) => setTimeout(r, 800));
  return { error: 'Invalid credentials.' };
}

module.exports = { authed, login, totp, issue, validSession, cookie, sign };
