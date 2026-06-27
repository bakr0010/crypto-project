# SecureChannel

ENCS4320 Applied Cryptography final project — Birzeit University.

A complete secure communication system built from scratch in Python, implementing all cryptographic primitives directly from their RFC/FIPS specifications.

## Team

- Bakr Adnan
- Jalila Rasmi

## Primitives Implemented

| Component | Specification |
|---|---|
| SHA-256 | FIPS 180-4 |
| HMAC-SHA-256 | RFC 2104 |
| HKDF extract + expand | RFC 5869 |
| ChaCha20 stream cipher | RFC 8439 |
| Poly1305 MAC | RFC 8439 |
| ChaCha20-Poly1305 AEAD | RFC 8439 §2.8 |
| X25519 key exchange | RFC 7748 |

No cryptographic libraries are used inside `src/`. All primitives are implemented in pure Python from their specifications.

## Running the Application

**Step 1 — Generate a pre-shared key (do this once, copy psk.bin to both machines):**
```
python generate_psk.py
```

**Step 2 — Start the server:**
```
python server.py
```

**Step 3 — Start the client (in another terminal):**
```
python client.py
```

Type messages and press Enter to send. Type `/quit` to close the connection.

## Running the Tests

```
python tests/test_sha256.py
python tests/test_hmac.py
python tests/test_hkdf.py
python tests/test_chacha20.py
python tests/test_poly1305.py
python tests/test_aead.py
python tests/test_x25519.py
```

Each test file validates against the official test vectors from its RFC/FIPS document.

## Protocol Design

See `REPORT.md` for full details on the handshake, key schedule, nonce construction, and replay protection.
