# SecureChannel — Protocol Design Report

## Team
- Bakr Adnan — Requirement Engineer
- Jalila Rasmi — Technical Architect

## Overview

SecureChannel is a secure two-party communication system built from scratch in Python. It implements ephemeral key exchange, mutual PSK-based authentication, HKDF key derivation, and ChaCha20-Poly1305 authenticated encryption over TCP.

---

## Message Format

All messages are framed as:

```
[ type: 1 byte ][ length: 2 bytes big-endian ][ payload: length bytes ]
```

Message types:
- `0x01` — handshake (public key or HMAC tag)
- `0x02` — data (sequence number + AEAD ciphertext + tag)
- `0x03` — close

Data message payload layout:
```
[ seq: 8 bytes big-endian ][ ciphertext ][ poly1305 tag: 16 bytes ]
```

---

## Handshake Protocol

```
Client                              Server
  |                                   |
  |--- MSG_HANDSHAKE: client_pub ---->|
  |                                   |  (generates ephemeral keypair)
  |<-- MSG_HANDSHAKE: server_pub -----|
  |                                   |
  |  both compute: shared = X25519(priv, peer_pub)
  |                                   |
  |--- MSG_HANDSHAKE: HMAC_client --->|  (client authenticates)
  |<-- MSG_HANDSHAKE: HMAC_server ----|  (server authenticates)
  |                                   |
  |  both derive session keys via HKDF
```

### Authentication

Each side computes:

```
HMAC-SHA-256(PSK, PROTOCOL_VERSION || our_pub || their_pub || our_id || their_id)
```

The transcript covers both ephemeral public keys and both identities. This binds the session keys to both parties and defeats man-in-the-middle attacks: an attacker cannot forge the HMAC without the PSK, and substituting their own public key changes the transcript, so the HMAC tag won't match.

Tags are compared using `hmac.compare_digest` (constant-time) to prevent timing attacks.

---

## Key Schedule

```
shared_secret = X25519(our_ephemeral_priv, their_ephemeral_pub)

PRK = HKDF-Extract(salt=PSK, IKM=shared_secret)

key_material = HKDF-Expand(PRK, info="SecureChannel session keys", L=88)

client_key  = key_material[0:32]   # used by client to encrypt
server_key  = key_material[32:64]  # used by server to encrypt
nonce_base  = key_material[64:88]  # 24 bytes, truncated to 12 for nonces
```

Mixing the PSK as the HKDF salt ensures that even if the X25519 shared secret were weak, the PSK contributes real entropy to the derived keys.

---

## Nonce Construction

Each directional key has its own sequence counter starting at 0. The nonce for sequence number `seq` is:

```
nonce = nonce_base[0:12] XOR (seq encoded as 8 bytes big-endian, right-aligned)
```

This gives unique nonces per message per direction, as long as sequence numbers don't wrap (capped at 2^64).

---

## Replay Protection

The sequence number is included in the AEAD associated data:

```
AAD = [ MSG_DATA: 1 byte ][ seq: 8 bytes big-endian ]
```

The receiver checks `seq == expected_recv_seq` before decryption. Any out-of-order or replayed message has a mismatched sequence number and is rejected before the AEAD tag is even checked. A replayed ciphertext with the correct sequence number would also fail because the nonce (derived from seq) was already used and the tag would not verify with the current key.

---

## Tamper Detection

The Poly1305 tag covers both the ciphertext and the AAD (which includes the message type and sequence number). Any modification to the header, ciphertext, or tag causes `aead_decrypt` to raise `ValueError("authentication failed")` before any plaintext is returned.

---

## Individual Contributions

**Bakr Adnan:** SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 2104), HKDF (RFC 5869), all corresponding test vectors.

**Jalila Rasmi:** ChaCha20 (RFC 8439), Poly1305 (RFC 8439), ChaCha20-Poly1305 AEAD (RFC 8439), X25519 (RFC 7748), protocol design (handshake, session, replay protection), CLI application, all corresponding test vectors.
