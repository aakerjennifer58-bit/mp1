const m = require('../lib/mpesa');
const { h } = m;

module.exports = async (req, res) => {
  if (!m.authed(req, res)) return;
  if (req.method === 'POST' && req.body?.clear) {
    await m.clearLog();
    return res.redirect(303, '/logs');
  }

  const lines = await m.readLog();   // newest first

  const entries = lines.map((e) => {
    const s = e.summary;
    const tone = { COMPLETED: 'ok', FAILED: 'bad', UNKNOWN: 'warn-tone' }[s?.state] || '';
    const rows = s ? [
      ['code', 'ResultCode'], ['desc', 'Description'], ['receipt', 'Receipt'],
      ['amount', 'Amount'], ['paid_to', 'Paid to'], ['originator', 'Originator id'],
    ].filter(([k]) => s[k] != null && s[k] !== '').map(([k, l]) => `<dt>${l}</dt><dd>${h(s[k])}</dd>`).join('') : '';
    const balances = s?.balances ? `<dl class="balances">${Object.entries(s.balances).map(([n, a]) =>
      `<dt>${h(n)}</dt><dd${n.includes('Utility') ? ' class="strong"' : ''}>KSh ${a.toFixed(2)}</dd>`).join('')}</dl>
      <p class="hint">Available, not current — the difference is reserved and cannot be spent. B2C spends Utility.</p>` : '';
    return `<section class="entry ${tone}">
      <h3>${s ? `<span class="state">${h(s.state)}</span>` : ''} ${h(e.type)}${e.kind ? ' · ' + h(e.kind) : ''}
        <span class="hint">${h(e.ts)}</span></h3>
      ${s?.state === 'UNKNOWN' ? `<p class="err">Queue timeout. Safaricom is saying the request waited too long —
        whether it was processed is unknown. Query the status before doing anything; guessing risks a double payment or an unpaid recipient.</p>` : ''}
      ${rows ? `<dl>${rows}</dl>` : ''}${balances}
      <details><summary class="hint">raw</summary><pre>${h(JSON.stringify(e, null, 2))}</pre></details>
    </section>`;
  }).join('');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>B2C log</title>
<link rel="stylesheet" href="/style.css">
<main>
  <header><h1>Callback log</h1><span class="hint">newest first · refreshes every 5s</span>
    <a href="/" class="right">← Send</a></header>
  <form method="post" class="row end"><button name="clear" value="1" class="ghost">Clear log</button></form>
  ${lines.length ? '' : '<p class="hint">Nothing yet. Send a payment, then wait for Safaricom to reach <code>/callback</code>. It is not instant.</p>'}
  ${entries}
</main>`);
};
