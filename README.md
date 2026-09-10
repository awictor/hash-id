# HashID

**Hash type identifier** — paste a hash and find out what algorithm likely produced it. Recognizes MD5, SHA-1/224/256/384/512, SHA-3/Keccak, bcrypt, Argon2, NTLM, sha512crypt/`$6$`, MySQL, LDAP `{SSHA}`, Django, JWT, and more — and flags salted `hash:salt` forms. One offline HTML file, no signup, no tracking.

👉 **[Open HashID](https://awictor.github.io/hash-id/)**

## Features
- Ranked candidate list (most likely first) with length + character-set info
- Format-based detection: length, charset, and structured prefixes (`$2y$`, `$argon2id$`, `{SSHA}`, `pbkdf2_sha256$`, …)
- Detects salted `hash:salt` combinations
- Dark mode; remembers your input; **100% client-side — nothing is ever sent anywhere**

## Why
When you find a hash in a database dump, a config file, or a CTF, the first question is always "what is this?" HashID answers instantly, offline, without pasting a credential into some random website. Part of the [Toolkit](https://awictor.github.io/toolkit/).

## Note
Many algorithms share a fingerprint (a 32-char hex string could be MD5, NTLM, MD4…), so results are *candidates*, not proof. Identification is by format only — HashID never cracks or looks up hashes.

## Tests
```
node tests/selftest.mjs
```
Pure functions (`identify`, `charInfo`, `RULES`) are covered by headless tests with real hash vectors (MD5/SHA-1 of "password", a canonical bcrypt hash, JWT, salted forms); CI runs them on every push.

## License
MIT © Alex Wictor
