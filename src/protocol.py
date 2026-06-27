import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))

from x25519 import x25519, generate_public_key
from hkdf import hkdf_extract, hkdf_expand
from hmac_sha256 import hmac_sha256
from chacha20_poly1305 import aead_encrypt, aead_decrypt

PROTOCOL_VERSION = b"SecureChannel-1.0"
MSG_HANDSHAKE    = 0x01
MSG_DATA         = 0x02
MSG_CLOSE        = 0x03


def _send_frame(sock, msg_type, payload):
    header = struct.pack(">BH", msg_type, len(payload))
    sock.sendall(header + payload)


def _recv_frame(sock):
    raw = _recv_exact(sock, 3)
    msg_type, length = struct.unpack(">BH", raw)
    payload = _recv_exact(sock, length)
    return msg_type, payload


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _build_transcript(our_pub, their_pub, our_id, their_id):
    return (
        PROTOCOL_VERSION +
        our_pub + their_pub +
        our_id.encode() + their_id.encode()
    )


def _derive_session_keys(shared_secret, psk, client_pub, server_pub):
    salt = psk
    ikm  = shared_secret
    prk  = hkdf_extract(salt, ikm)
    key_material = hkdf_expand(prk, b"SecureChannel session keys", 64 + 24)
    client_key  = key_material[0:32]
    server_key  = key_material[32:64]
    nonce_base  = key_material[64:88]
    return client_key, server_key, nonce_base


def _make_nonce(base, seq):
    n = bytearray(base[:12])
    seq_bytes = struct.pack(">Q", seq)
    for i in range(8):
        n[4 + i] ^= seq_bytes[i]
    return bytes(n)


def _check_all_zero(b):
    return not any(b)


def handshake_client(sock, psk, client_id="client", server_id="server"):
    priv = os.urandom(32)
    pub  = generate_public_key(priv)

    _send_frame(sock, MSG_HANDSHAKE, pub)

    msg_type, server_pub = _recv_frame(sock)
    if msg_type != MSG_HANDSHAKE or len(server_pub) != 32:
        raise ValueError("bad server handshake")

    shared = x25519(priv, server_pub)
    if _check_all_zero(shared):
        raise ValueError("x25519 produced all-zero shared secret")

    transcript = _build_transcript(pub, server_pub, client_id, server_id)
    our_mac    = hmac_sha256(psk, transcript)
    _send_frame(sock, MSG_HANDSHAKE, our_mac)

    msg_type, their_mac = _recv_frame(sock)
    if msg_type != MSG_HANDSHAKE:
        raise ValueError("expected handshake mac from server")

    server_transcript = _build_transcript(server_pub, pub, server_id, client_id)
    expected_mac      = hmac_sha256(psk, server_transcript)
    if not hmac_sha256.__module__ and their_mac != expected_mac:
        raise ValueError("server authentication failed")

    import hmac as _hmac
    if not _hmac.compare_digest(their_mac, expected_mac):
        raise ValueError("server authentication failed")

    client_key, server_key, nonce_base = _derive_session_keys(
        shared, psk, pub, server_pub
    )
    return client_key, server_key, nonce_base


def handshake_server(sock, psk, client_id="client", server_id="server"):
    msg_type, client_pub = _recv_frame(sock)
    if msg_type != MSG_HANDSHAKE or len(client_pub) != 32:
        raise ValueError("bad client handshake")

    priv = os.urandom(32)
    pub  = generate_public_key(priv)

    _send_frame(sock, MSG_HANDSHAKE, pub)

    shared = x25519(priv, client_pub)
    if _check_all_zero(shared):
        raise ValueError("x25519 produced all-zero shared secret")

    msg_type, their_mac = _recv_frame(sock)
    if msg_type != MSG_HANDSHAKE:
        raise ValueError("expected handshake mac from client")

    client_transcript = _build_transcript(client_pub, pub, client_id, server_id)
    expected_mac      = hmac_sha256(psk, client_transcript)

    import hmac as _hmac
    if not _hmac.compare_digest(their_mac, expected_mac):
        raise ValueError("client authentication failed")

    server_transcript = _build_transcript(pub, client_pub, server_id, client_id)
    our_mac           = hmac_sha256(psk, server_transcript)
    _send_frame(sock, MSG_HANDSHAKE, our_mac)

    client_key, server_key, nonce_base = _derive_session_keys(
        shared, psk, client_pub, pub
    )
    return client_key, server_key, nonce_base


class SecureSession:
    def __init__(self, send_key, recv_key, nonce_base, send_seq=0, recv_seq=0):
        self._send_key   = send_key
        self._recv_key   = recv_key
        self._nonce_base = nonce_base
        self._send_seq   = send_seq
        self._recv_seq   = recv_seq

    def send(self, sock, plaintext):
        seq   = self._send_seq
        nonce = _make_nonce(self._nonce_base, seq)
        aad   = struct.pack(">BQ", MSG_DATA, seq)
        ct    = aead_encrypt(self._send_key, nonce, plaintext, aad)
        _send_frame(sock, MSG_DATA, aad[1:] + ct)
        self._send_seq += 1

    def recv(self, sock):
        msg_type, payload = _recv_frame(sock)
        if msg_type == MSG_CLOSE:
            return None
        if msg_type != MSG_DATA:
            raise ValueError(f"unexpected message type {msg_type}")

        seq_bytes = payload[:8]
        ct_and_tag = payload[8:]
        seq = struct.unpack(">Q", seq_bytes)[0]

        if seq != self._recv_seq:
            raise ValueError(f"replay/reorder: expected seq {self._recv_seq} got {seq}")

        nonce = _make_nonce(self._nonce_base, seq)
        aad   = struct.pack(">BQ", MSG_DATA, seq)
        plaintext = aead_decrypt(self._recv_key, nonce, ct_and_tag, aad)
        self._recv_seq += 1
        return plaintext

    def close(self, sock):
        _send_frame(sock, MSG_CLOSE, b"")
