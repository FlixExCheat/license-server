'use strict';

// Generates the licence signing key pair.
//
//   node scripts/genkey.js
//
// Copy the PEM into the Render env var LICENSE_PRIVATE_KEY (as one line with
// literal \n, Render accepts both), then paste the two numbers printed for the
// client into auth/auth.hpp.

const crypto = require('crypto');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const jwk = publicKey.export({ format: 'jwk' });

console.log('─────────────────────────────────────────────────────────────');
console.log('LICENSE_PRIVATE_KEY  (Render env var, single line form below)');
console.log('─────────────────────────────────────────────────────────────');
console.log(privateKey);
console.log('single line:');
console.log(privateKey.replace(/\n/g, '\\n'));
console.log('');
console.log('─────────────────────────────────────────────────────────────');
console.log('client public key (paste into auth/auth.hpp)');
console.log('─────────────────────────────────────────────────────────────');
console.log(`MODULUS_HEX  = "${jwk.n}"`);
console.log(`EXPONENT_HEX = "${jwk.e}"`);
console.log('');
