// Produce SECURITY_CREDENTIAL:  node credential.js <certificate.cer> "<initiator password>"
// Use the certificate for the SAME environment (sandbox and production differ); the wrong one
// fails as `2001 Initiator information is invalid`, which reads like a wrong password.
const fs = require('fs');
const { X509Certificate, publicEncrypt, constants } = require('crypto');

const [cert, password] = process.argv.slice(2);
if (!cert || !password) { console.error('usage: node credential.js <certificate.cer> "<initiator password>"'); process.exit(1); }

const x = new X509Certificate(fs.readFileSync(cert));   // PEM or DER
const out = publicEncrypt({ key: x.publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(password));
console.log('certificate :', x.subject.split('\n').find((l) => l.startsWith('CN=')) || '?');
console.log('credential  :', out.toString('base64'));
