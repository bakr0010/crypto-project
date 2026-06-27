import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from chacha20_poly1305 import aead_encrypt, aead_decrypt


def test_rfc8439_aead_vector():
    key   = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad   = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    expected_ct  = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    result = aead_encrypt(key, nonce, plaintext, aad)
    ct  = result[:-16]
    tag = result[-16:]

    assert ct  == expected_ct,  f"ct mismatch:\n  got {ct.hex()}\n  exp {expected_ct.hex()}"
    assert tag == expected_tag, f"tag mismatch:\n  got {tag.hex()}\n  exp {expected_tag.hex()}"
    return True


def test_decrypt_roundtrip():
    key   = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad   = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = b"test message for roundtrip"

    ct_and_tag = aead_encrypt(key, nonce, plaintext, aad)
    recovered  = aead_decrypt(key, nonce, ct_and_tag, aad)
    assert recovered == plaintext, f"roundtrip failed: {recovered}"
    return True


def test_tamper_detection():
    key   = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad   = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = b"this message must not be tampered with"

    def should_fail(buf, bad_aad=None):
        try:
            aead_decrypt(key, nonce, bytes(buf), bad_aad if bad_aad else aad)
            return False
        except ValueError:
            return True

    ct = bytearray(aead_encrypt(key, nonce, plaintext, aad))

    flip_ct  = bytearray(ct); flip_ct[0]  ^= 0x01
    flip_tag = bytearray(ct); flip_tag[-1] ^= 0x01

    assert should_fail(flip_ct),               "flipped ciphertext byte should fail"
    assert should_fail(flip_tag),              "flipped tag byte should fail"
    assert should_fail(ct, b"wrong aad"),      "wrong AAD should fail"
    return True


def run():
    tests = [
        ("RFC 8439 §2.8.2 AEAD vector",    test_rfc8439_aead_vector),
        ("decrypt roundtrip",               test_decrypt_roundtrip),
        ("tamper detection (ct, tag, aad)", test_tamper_detection),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {name}\n  {e}")

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
