import hmac as _hmac
from chacha20 import _chacha20_block, chacha20_encrypt
from poly1305 import poly1305_mac


def _pad16(data):
    remainder = len(data) % 16
    if remainder:
        return data + b"\x00" * (16 - remainder)
    return data


def _poly1305_key_gen(key, nonce):
    block = _chacha20_block(key, 0, nonce)
    return block[:32]


def _build_mac_data(aad, ciphertext):
    return (
        _pad16(aad) +
        _pad16(ciphertext) +
        len(aad).to_bytes(8, "little") +
        len(ciphertext).to_bytes(8, "little")
    )


def aead_encrypt(key, nonce, plaintext, aad):
    otk = _poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data = _build_mac_data(aad, ciphertext)
    tag = poly1305_mac(mac_data, otk)
    return ciphertext + tag


def aead_decrypt(key, nonce, ciphertext_and_tag, aad):
    if len(ciphertext_and_tag) < 16:
        raise ValueError("input too short")
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]

    otk = _poly1305_key_gen(key, nonce)
    mac_data = _build_mac_data(aad, ciphertext)
    expected_tag = poly1305_mac(mac_data, otk)

    if not _hmac.compare_digest(tag, expected_tag):
        raise ValueError("authentication failed")

    return chacha20_encrypt(key, 1, nonce, ciphertext)
