// Safaricom posts outcomes here. Record everything, always acknowledge.
// Unauthenticated by design, so it only records and displays; it never acts on a callback.
// The `s` secret keeps strangers from filling the log.
const m = require('../lib/mpesa');

module.exports = async (req, res) => {
  if (req.query.s !== m.callbackSecret()) return res.status(403).end();

  const kind = req.query.kind === 'timeout' ? 'timeout' : 'result';
  const raw = req.body;
  const body = raw && typeof raw === 'object' ? raw : null;

  await m.mlog('callback', {
    kind,
    ip: (req.headers['x-forwarded-for'] || '?').split(',')[0],
    summary: body ? m.summariseCallback(body, kind) : null,
    body: body ?? String(raw ?? ''),
  });

  // Latest balance, so the main page can show it without digging through the log.
  const bal = body && m.summariseCallback(body, kind).balances;
  if (bal) await m.redis('SET', 'mpesa:balance', JSON.stringify({ ts: new Date().toISOString(), balances: bal }));

  // An initiator rejection usually arrives here, not in the send's reply.
  if (body) {
    const code = body.Result?.ResultCode;
    await m.noteInitiatorResult(code == null ? null : String(code));
  }

  // Safaricom retries unless it gets this exact shape.
  res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
};
