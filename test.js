// Self-check: node test.js   (no credentials, no network)
const assert = require('assert');
const m = require('./lib/mpesa');

const refuses = (f, why) => assert.throws(f, m.InputError, `should have refused: ${why}`);

assert.strictEqual(m.toMsisdn('0712345678'), '254712345678');
assert.strictEqual(m.toMsisdn('+254 712 345 678'), '254712345678');
assert.strictEqual(m.toMsisdn('0712-345-678'), '254712345678');
assert.strictEqual(m.toMsisdn('712345678'), '254712345678');
assert.strictEqual(m.toMsisdn('254112345678'), '254112345678');
refuses(() => m.toMsisdn(''), 'empty');
refuses(() => m.toMsisdn('25471234567'), 'too short');
refuses(() => m.toMsisdn('254812345678'), 'not a mobile range');
refuses(() => m.toMsisdn('0712345678abc'), 'trailing junk must not be stripped');
refuses(() => m.toMsisdn('0800123456'), 'landline/shortcode');

// a lone ResultParameter arrives as an object, not a list
const lone = { ResultParameters: { ResultParameter: { Key: 'TransactionReceipt', Value: 'SG632NMUAB' } } };
assert.strictEqual(m.resultParameters(lone).TransactionReceipt, 'SG632NMUAB');
assert.deepStrictEqual(m.resultParameters({}), {});

const paid = m.summariseCallback({ Result: {
  ResultCode: 0, TransactionID: 'SG632NMUAB', OriginatorConversationID: 'test-1',
  ResultParameters: { ResultParameter: [
    { Key: 'TransactionAmount', Value: 10 },
    { Key: 'ReceiverPartyPublicName', Value: '254705912645 - NICHOLAS JOHN SONGOK' },
  ] },
} }, 'result');
assert.strictEqual(paid.state, 'COMPLETED');
assert.strictEqual(paid.receipt, 'SG632NMUAB');
assert.strictEqual(paid.amount, 10);

assert.strictEqual(m.summariseCallback({ Result: { ResultCode: 2001 } }, 'result').state, 'FAILED');
assert.strictEqual(m.summariseCallback({ Result: { ResultCode: 0 } }, 'timeout').state, 'UNKNOWN', 'a timeout must never read as paid');

const b = m.balancesFrom({ AccountBalance: 'Working Account|KES|0.00|0.00|0.00|0.00&Utility Account|KES|245.00|235.00|10.00|0.00' });
assert.strictEqual(b['Utility Account'], 235, 'Available, not Current');
assert.strictEqual(m.balancesFrom({}), null);

assert.throws(() => m.required('SECURITY_CREDENTIAL'), /SECURITY_CREDENTIAL/);
assert.ok(m.credentialLooksEncrypted(require('crypto').randomBytes(256).toString('base64')));
assert.ok(!m.credentialLooksEncrypted('my-initiator-password'));
assert.ok(!m.credentialLooksEncrypted('!'.repeat(344)));

assert.strictEqual(m.initiatorCodeFrom({ errorCode: '2001' }), '2001');
assert.strictEqual(m.initiatorCodeFrom({ ResultCode: 0 }), '0');
assert.strictEqual(m.initiatorCodeFrom({ _http_status: 500 }), null);

console.log('OK — all checks passed');

// --- auth: RFC 6238 vector (secret "12345678901234567890", t=59s -> ...287082) and session signing
process.env.ADMIN_PASSWORD = 'pw'; process.env.CONSUMER_SECRET = 'cs';
const a = require('./lib/auth');
assert.strictEqual(a.totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000), '287082');
const sid = a.issue();
assert.ok(a.validSession(`x=1; sid=${sid}`));
assert.ok(!a.validSession(`sid=${sid}x`), 'tampered signature');
assert.ok(!a.validSession(`sid=${Math.floor(Date.now() / 1000) - 5}.${a.sign(Math.floor(Date.now() / 1000) - 5)}`), 'expired');
assert.ok(!a.validSession(''));
console.log('OK — auth checks passed');
