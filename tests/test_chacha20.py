import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from chacha20 import _quarter_round, _chacha20_block, chacha20_encrypt

def test_quarter_round():
    state = [0] * 16
    state[0] = 0x11111111
    state[1] = 0x01020304
    state[2] = 0x9b8d6f43
    state[3] = 0x01234567
    _quarter_round(state, 0, 1, 2, 3)
    assert state[0] == 0xea2a92f4, f"a: {state[0]:#010x}"
    assert state[1] == 0xcb1cf8ce, f"b: {state[1]:#010x}"
    assert state[2] == 0x4581472e, f"c: {state[2]:#010x}"
    assert state[3] == 0x5881c4bb, f"d: {state[3]:#010x}"
    return True


def test_block():
    key = bytes([
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    ])
    nonce = bytes([
        0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00,
    ])
    counter = 1

    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    block = _chacha20_block(key, counter, nonce)
    assert block == expected, f"block mismatch:\n  got {block.hex()}\n  exp {expected.hex()}"
    return True


def test_encrypt():
    key = bytes([
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    ])
    nonce = bytes([
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00,
    ])
    counter = 1
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    ct = chacha20_encrypt(key, counter, nonce, plaintext)
    assert ct == expected, f"encrypt mismatch:\n  got {ct.hex()}\n  exp {expected.hex()}"
    return True


def run():
    tests = [
        ("RFC 8439 §2.1.1 quarter round", test_quarter_round),
        ("RFC 8439 §2.3.2 block function", test_block),
        ("RFC 8439 §2.4.2 encryption",    test_encrypt),
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
