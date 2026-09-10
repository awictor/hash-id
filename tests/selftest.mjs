// Headless regression tests for HashID — hash-type identification by format.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(__dirname, '..', 'index.html'), 'utf8');

const js = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  .map(m => m[1]).sort((a, b) => b.length - a.length)[0];

function el(){ return {value:'',textContent:'',innerHTML:'',style:{},className:'',
  appendChild(){},getAttribute(){return null;},setAttribute(){},removeAttribute(){},
  classList:{add(){},remove(){}},
  addEventListener(){},querySelectorAll(){return[];},querySelector(){return null;},closest(){return null;}}; }
globalThis.document = {
  getElementById: () => el(), createElement: () => el(), querySelector: () => el(),
  querySelectorAll: () => [], documentElement: el()
};
globalThis.localStorage = { getItem:()=>null, setItem(){}, removeItem(){} };
globalThis.matchMedia = () => ({ matches:false });
globalThis.window = { matchMedia: globalThis.matchMedia };

eval(js.replace('if(typeof module !== \'undefined\') module.exports =',
  'globalThis.__t =') );
const { identify, charInfo, RULES } = globalThis.__t;

let n = 0;
const check = (name, fn) => { fn(); n++; console.log('  ok -', name); };

check('empty / whitespace -> no candidates', () => {
  assert.deepEqual(identify(''), []);
  assert.deepEqual(identify('   '), []);
});

check('32-char hex -> MD5 family', () => {
  const c = identify('5f4dcc3b5aa765d61d8327deb882cf99'); // md5("password")
  assert.equal(c[0], 'MD5');
  assert.ok(c.includes('NTLM'));
  assert.ok(c.includes('MD4'));
});

check('40-char hex -> SHA-1 family', () => {
  const c = identify('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'); // sha1("password")
  assert.equal(c[0], 'SHA-1');
  assert.ok(c.includes('RIPEMD-160'));
});

check('64 / 96 / 128 hex -> SHA-256 / 384 / 512', () => {
  assert.equal(identify('a'.repeat(64))[0], 'SHA-256');
  assert.equal(identify('a'.repeat(96))[0], 'SHA-384');
  assert.equal(identify('a'.repeat(128))[0], 'SHA-512');
  assert.equal(identify('a'.repeat(56))[0], 'SHA-224');
});

check('8 / 16 hex -> CRC-32 / MySQL-old', () => {
  assert.equal(identify('cbf43926')[0], 'CRC-32');
  assert.equal(identify('a'.repeat(16))[0], 'MySQL 3.x (pre-4.1)');
});

check('leading/trailing whitespace is trimmed', () => {
  assert.equal(identify('  5f4dcc3b5aa765d61d8327deb882cf99  ')[0], 'MD5');
});

check('bcrypt is detected exactly', () => {
  const c = identify('$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy');
  assert.deepEqual(c, ['bcrypt']);
  assert.deepEqual(identify('$2a$12$' + 'a'.repeat(53)), ['bcrypt']);
});

check('unix crypt families by $ prefix', () => {
  assert.equal(identify('$6$rounds=5000$abc$def')[0], 'sha512crypt ($6$, Unix)');
  assert.equal(identify('$5$abc$def')[0], 'sha256crypt ($5$, Unix)');
  assert.equal(identify('$1$abc$def')[0], 'md5crypt ($1$, Unix / Cisco-IOS)');
  assert.equal(identify('$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')[0], 'Argon2');
});

check('LDAP and Django prefixes', () => {
  assert.equal(identify('{SSHA}abcdef')[0], 'LDAP {SSHA} (salted SHA-1)');
  assert.equal(identify('{SHA}abcdef')[0], 'LDAP {SHA}');
  assert.equal(identify('pbkdf2_sha256$260000$salt$hash')[0], 'Django PBKDF2-SHA256');
});

check('MySQL 4.1+ star form', () => {
  assert.equal(identify('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19')[0], 'MySQL 4.1+ (SHA1(SHA1))');
});

check('JWT three-segment token', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r';
  assert.ok(identify(jwt).includes('JWT (JSON Web Token)'));
});

check('salted hash:salt is flagged', () => {
  const c = identify('5f4dcc3b5aa765d61d8327deb882cf99:abc123');
  assert.equal(c[0], 'MD5 (salted, hash:salt)');
  assert.ok(c.every(x => /salted, hash:salt/.test(x)));
});

check('garbage yields no match', () => {
  assert.deepEqual(identify('hello world this is not a hash!'), []);
  assert.deepEqual(identify('xyz'), []);
});

check('charInfo reports length + charset', () => {
  assert.deepEqual(charInfo('5f4dcc3b5aa765d61d8327deb882cf99'), { length: 32, charset: 'hexadecimal' });
  assert.equal(charInfo('Zm9vYmFy').charset, 'base64');
  assert.equal(charInfo('ab_cd-ef').charset, 'base64url');
  assert.equal(charInfo('héllo!').charset, 'mixed');
  assert.equal(charInfo('').charset, 'empty');
});

check('RULES table is a non-empty array of {test, names}', () => {
  assert.ok(Array.isArray(RULES) && RULES.length >= 15);
  assert.ok(RULES.every(r => r.test instanceof RegExp && Array.isArray(r.names)));
});

console.log(`\n${n} checks passed.`);
