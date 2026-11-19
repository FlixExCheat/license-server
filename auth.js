'use strict';

// Password hashing, opaque session/material tokens and the RSA-signed licence
// ticket the client verifies with an embedded public key.

const crypto = require('crypto');

const SCRYPT_N = 16384;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, { N: SCRYPT_N, r: 8, p: 1 });
  return `s2$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [tag, saltHex, hashHex] = String(stored).split('$');
    if (tag !== 's2' || !saltHex || !hashHex) return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, salt, expected.length,
                                     { N: SCRYPT_N, r: 8, p: 1 });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function token(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function newKey(days) {
  // 4 groups of 5, unambiguous alphabet: no O/0, I/1
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = () => Array.from({ length: 5 }, () =>
    alphabet[crypto.randomInt(0, alphabet.length)]).join('');
  return { code: `${part()}-${part()}-${part()}-${part()}`, days };
}

// ── signing ───────────────────────────────────────────────────────────────

let privateKey = null;
let publicJwk = null;

function initSigning() {
  const pem = process.env.LICENSE_PRIVATE_KEY;
  if (pem && pem.includes('BEGIN')) {
    privateKey = crypto.createPrivateKey(pem.replace(/\\n/g, '\n'));
  } else {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    privateKey = pair.privateKey;
    console.warn('[auth] LICENSE_PRIVATE_KEY not set - generated a throwaway key.');
    console.warn('[auth] the client will reject tickets signed with it.');
  }
  const pub = crypto.createPublicKey(privateKey);
  const jwk = pub.export({ format: 'jwk' });
  publicJwk = { n: jwk.n, e: jwk.e };
}

function publicKey() {
  return publicJwk;
}

// payload is a compact string "u=<id>;k=<key>;h=<hwid>;e=<epoch seconds>"
function signTicket(payload) {
  const signature = crypto.sign('sha256', Buffer.from(payload), privateKey);
  return { payload, sig: signature.toString('base64url') };
}

module.exports = {
  hashPassword, verifyPassword, token, newKey,
  initSigning, publicKey, signTicket,
};
