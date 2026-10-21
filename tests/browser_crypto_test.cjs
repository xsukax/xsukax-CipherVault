// Exercises the actual production app.js WebCrypto AES/PBKDF2 helpers in Node 22+.
const fs = require('node:fs');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const path = require('node:path');
const assert = require('node:assert/strict');
const src = fs.readFileSync(path.join(__dirname,'../app/static/app.js'),'utf8');
const functions = src.slice(src.indexOf('function nonce('), src.indexOf('async function api('));
const context = {crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,DataView,BigInt,Buffer,
                 PBKDF2_ITERATIONS:600000, encoder:new TextEncoder(), assert, console};
vm.runInNewContext(functions + `
(async()=>{
  const pass = 'long-random-unique-password-used-only-locally';
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prefix = crypto.getRandomValues(new Uint8Array(4));
  const key = await browserKey(pass, salt);
  const data = new TextEncoder().encode('actual-production-browser-encryption');
  const ciphertext0 = await aesEncrypt(key,nonce(prefix,0),data);
  const ciphertext1 = await aesEncrypt(key,nonce(prefix,1),data);
  assert.notDeepEqual(Buffer.from(ciphertext0),Buffer.from(ciphertext1));
  const original = await aesDecrypt(key,nonce(prefix,0),ciphertext0);
  assert.deepEqual(Buffer.from(original),Buffer.from(data));
  const wrongKey = await browserKey('wrong-password',salt);
  await assert.rejects(async()=>aesDecrypt(wrongKey,nonce(prefix,0),ciphertext0));
  await assert.rejects(async()=>aesDecrypt(key,nonce(prefix,1),ciphertext0));
  console.log('Production browser WebCrypto: encryption, decryption, bad-password rejection PASS');
})().catch(e => {console.error(e);process.exitCode=1});`, {...context,process});
