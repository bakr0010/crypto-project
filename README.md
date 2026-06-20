# SecureChannel

ENCS4320 Applied Cryptography final project. A secure communication app
built from scratch in Python, implementing the underlying primitives
directly from their RFC/FIPS specifications, then composing them into
an authenticated key-exchange handshake and an AEAD messaging channel.

## Team

- Bakr [last name] - [ID]
- [Teammate name] - [ID]

## Status

In progress. Implemented so far:

- SHA-256 (FIPS 180-4)
- HMAC-SHA-256 (RFC 2104)
- HKDF extract/expand (RFC 5869)

Not yet implemented: ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD (RFC 8439),
X25519 (RFC 7748), the handshake protocol, and the CLI chat application.

## Running the tests

From the repository root:

```
python3 tests/test_sha256.py
python3 tests/test_hmac.py
python3 tests/test_hkdf.py
```

Each test file validates the corresponding primitive against official
test vectors published in its RFC/FIPS document (FIPS 180-4 Appendix B
for SHA-256, RFC 4231 for HMAC-SHA-256, RFC 5869 Appendix A for HKDF).

## No external crypto libraries

None of the files under `src/` import any cryptographic library. They
are implemented from the specification using only Python's standard
library for basic operations (integer arithmetic, byte manipulation).
