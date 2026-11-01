const crypto = require('crypto');
const m = require('../lib/mpesa');
const { h } = m;

async function doSend(b) {
  if (m.isLive() && b.confirm !== 'yes') throw new Error('Tick the confirmation box — this sends real money.');

  const msisdn = m.toMsisdn(b.phone);   // throws, does not guess
  const allowed = m.allowedPhones();
  if (allowed.length && !allowed.includes(msisdn)) throw new Error(`${msisdn} is not in ALLOWED_PHONES.`);

  const amountRaw = String(b.amount ?? '').trim();
  if (!/^\d+$/.test(amountRaw) || Number(amountRaw) < 1) throw new Error('Amount must be a whole number of shillings, 1 or more.');
  const amount = Number(amountRaw);
  if (amount > m.maxAmount()) throw new Error(`Amount exceeds MAX_AMOUNT (${m.maxAmount()}).`);

  const command = b.command || 'BusinessPayment';
  if (!['BusinessPayment', 'SalaryPayment', 'PromotionPayment'].includes(command)) throw new Error('Unknown CommandID.');

  // Stop before Safaricom does: repeated initiator rejections end in 8006, a phone-call lockout.
  const strikes = await m.initiatorStrikes();
  if (strikes >= 3) {
    throw new Error(`${strikes} consecutive initiator rejections. Sending again risks 8006 — the credential locked, `
      + 'unlockable only by your Business Administrator. Check the roles and password on that API operator in the '
      + 'Org Portal, then clear the count below.');
  }
  if (!m.callbackBase()) throw new Error('No public callback URL. Set CALLBACK_BASE, or deploy to production so Vercel provides one.');

  // Ours, and recorded before the send: if this request dies mid-flight, this is what a status query needs.
  const key = 'test-' + new Date().toISOString().replace(/\D/g, '').slice(0, 14) + '-' + crypto.randomBytes(4).toString('hex');
  await m.mlog('sending', { key, msisdn, amount, command });

  const response = await m.payout(key, msisdn, amount, command, (String(b.remarks ?? '').trim() || 'B2C test').slice(0, 100));
  const queued = String(response.ResponseCode ?? '') === '0';
  await m.noteInitiatorResult(m.initiatorCodeFrom(response));

  return {
    title: queued ? 'Queued by Safaricom' : 'Rejected',
    note: queued ? 'Queued is not paid. Only the callback says whether money moved — watch the log.'
      : (response.errorMessage ?? 'See the response below.'),
    error: queued ? null : (response.errorMessage ?? `HTTP ${response._http_status ?? '?'}`),
    key, response,
  };
}

const actions = {
  send: doSend,
  unlock: async () => {
    await m.clearInitiatorStrikes();
    return { title: 'Strike count cleared', note: 'This only resets our own counter. If Safaricom already returned 8006 the credential is locked on their side, and only your Business Administrator can undo that.' };
  },
  status: async (b) => ({
    title: 'Status query queued', note: 'The answer arrives on the ResultURL, not here. Watch the log.',
    response: await m.transactionStatus((b.receipt || '').trim() || null, (b.originator || '').trim() || null),
  }),
  balance: async () => ({
    title: 'Balance query queued', note: 'The figures arrive on the ResultURL, not here. Watch the log.',
    response: await m.accountBalance(),
  }),
};

module.exports = async (req, res) => {
  if (!m.authed(req, res)) return;

  const b = (req.method === 'POST' && req.body) || {};
  let result = null;
  if (b.action) {
    try {
      if (!actions[b.action]) throw new Error('Unknown action');
      result = await actions[b.action](b);
    } catch (e) {
      result = { error: e.message };
    }
    await m.mlog(b.action, { result });
  }

  const live = m.isLive();
  const cb = m.callbackBase();
  const ok = m.configured();
  const strikes = await m.initiatorStrikes();
  const dis = (cond) => (cond ? '' : 'disabled');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M-Pesa B2C Tester</title>
<link rel="stylesheet" href="/style.css">
<main>
  <header><h1>M-Pesa B2C Tester</h1>
    <span class="env ${live ? 'live' : 'sandbox'}">${live ? 'LIVE' : 'SANDBOX'}</span>
    <a href="/logs" class="right">Callback log →</a></header>

  ${ok ? '' : '<p class="warn">Set CONSUMER_KEY, CONSUMER_SECRET, SHORTCODE, INITIATOR_NAME and SECURITY_CREDENTIAL in Vercel env vars, then redeploy.</p>'}
  ${cb ? '' : '<p class="warn">No public callback URL (set CALLBACK_BASE) — sending would move money you could never confirm.</p>'}
  ${strikes > 0 ? `<form method="post" class="warn strikes"><span><strong>${strikes}</strong> consecutive initiator rejection${strikes === 1 ? '' : 's'}.
      ${strikes >= 3 ? 'Sending is blocked — the next attempts risk 8006, a lockout only your Business Administrator can undo.' : 'Three in a row blocks sending, because Safaricom locks the credential.'}</span>
      <button name="action" value="unlock" class="ghost">Clear count</button></form>` : ''}

  <form method="post" autocomplete="off">
    <h2>Send a payment</h2>
    <div class="grid">
      <label>Phone number <input name="phone" value="${h(b.phone ?? '')}" placeholder="0712345678" required></label>
      <label>Amount (KES) <input name="amount" type="number" min="1" max="${m.maxAmount()}" value="${h(b.amount ?? '10')}" required></label>
    </div>
    <label>Command
      <select name="command">${['BusinessPayment', 'SalaryPayment', 'PromotionPayment'].map((c) => `<option ${b.command === c ? 'selected' : ''}>${c}</option>`).join('')}</select>
      <span class="hint">BusinessPayment for earnings owed. The others carry different charges and show differently on the recipient's statement.</span>
    </label>
    <label>Remarks <input name="remarks" value="${h(b.remarks ?? 'B2C test')}"></label>
    ${live ? `<label class="check"><input type="checkbox" name="confirm" value="yes" required>
      This moves <strong>real money</strong> out of shortcode ${h(process.env.SHORTCODE)}. B2C cannot be reversed through the API.</label>` : ''}
    <button name="action" value="send" ${dis(ok && cb)}>Send payment</button>
  </form>

  <form method="post" autocomplete="off">
    <h2>Ask what happened</h2>
    <p class="hint">For when a send was queued and no callback ever arrived. Never assume — a retry that turns out to be a duplicate is money gone.</p>
    <div class="grid">
      <label>M-Pesa receipt <span class="hint">e.g. SG632NMUAB</span> <input name="receipt" value="${h(b.receipt ?? '')}"></label>
      <label>or our originator id <span class="hint">the <code>test-…</code> key</span> <input name="originator" value="${h(b.originator ?? '')}"></label>
    </div>
    <div class="row">
      <button name="action" value="status" class="ghost" ${dis(ok)}>Query status</button>
      <button name="action" value="balance" class="ghost" ${dis(ok)}>Check float</button>
    </div>
    <p class="hint"><strong>Start here.</strong> Check float moves no money and proves the loop: the keys authenticate, the initiator holds its roles, Vercel's IP is accepted, and Safaricom can reach the callback.</p>
    <p class="hint">B2C debits the <strong>Utility</strong> account, not Working.</p>
  </form>

  ${result ? `<section class="${result.error ? 'bad' : 'ok'}">
    <h2>${h(result.title ?? 'Failed')}</h2>
    ${result.error ? `<p class="err">${h(result.error)}</p>` : ''}
    ${result.note ? `<p>${h(result.note)}</p>` : ''}
    ${result.key ? `<p class="hint">Originator id <code>${h(result.key)}</code> — keep it, it is how you ask about this payment later.</p>` : ''}
    ${result.response ? `<pre>${h(JSON.stringify(result.response, null, 2))}</pre>` : ''}
  </section>` : ''}

  <footer>${cb ? `<span class="hint">Callbacks → <code>${h(cb)}/callback</code></span>` : '<span class="hint">No callback URL.</span>'}</footer>
</main>`);
};
