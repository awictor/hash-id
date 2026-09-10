# Changelog

## 0.1.0
- First release. Hash type identifier.
- Format-based detection of 40+ algorithms: MD5/SHA family, bcrypt, Argon2, NTLM, sha512crypt, MySQL, LDAP, Django, JWT, CRC.
- Ranked candidate list + length/charset info; salted hash:salt detection.
- 100% client-side — nothing is transmitted. Dark mode, localStorage memory.
- Headless test suite (15 checks, real hash vectors) + CI.
