const { h } = require('../lib/mpesa');
const a = require('../lib/auth');

module.exports = async (req, res) => {
  if (!process.env.ADMIN_PASSWORD) return res.status(503).send('Set ADMIN_PASSWORD in Vercel env vars.');

  if (req.query.out !== undefined) {   // /logout
    res.setHeader('Set-Cookie', a.cookie('', 0));
    return res.redirect(303, '/login');
  }

  let error = '';
  if (req.method === 'POST') {
    if ((req.headers['sec-fetch-site'] || 'same-origin') !== 'same-origin') return res.status(403).send('Cross-site POST refused');
    const r = await a.login(req);
    if (r.cookie) { res.setHeader('Set-Cookie', r.cookie); return res.redirect(303, '/'); }
    error = r.error;
  } else if (a.validSession(req.headers.cookie)) {
    return res.redirect(303, '/');
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(error ? 401 : 200).send(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<link rel="stylesheet" href="/style.css">
<main>
  <header><h1>Sign in</h1></header>
  <form method="post" autocomplete="off">
    ${error ? `<p class="err">${h(error)}</p>` : ''}
    <label>Password <input name="password" type="password" autocomplete="current-password" required autofocus></label>
    ${process.env.ADMIN_TOTP_SECRET ? '<label>Authenticator code <input name="code" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code" required></label>' : ''}
    <button>Sign in</button>
  </form>
</main>`);
};
