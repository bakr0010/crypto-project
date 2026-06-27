import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from poly1305 import poly1305_mac

def test_rfc8439_vector():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    msg = b"Cryptographic Forum Research Group"
    expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    tag = poly1305_mac(msg, key)
    assert tag == expected, f"tag mismatch:\n  got {tag.hex()}\n  exp {expected.hex()}"
    return True


def test_rfc8439_section_26():
    key = bytes.fromhex(
        "1c9240a5eb55d38af333888604f6b5f0"
        "473917c1402b80099dca5cbc207075c0"
    )
    msg = bytes.fromhex(
        "2754776173206272696c6c69672c2061"
        "6e642074686520736c6974687920746f"
        "7665730a446964206779726520616e64"
        "2067696d626c6520696e207468652077"
        "6162653a0a416c6c206d696d73792077"
        "6572652074686520626f726f676f7665"
        "732c0a416e6420746865206d6f6d6520"
        "7261746873206f757467726162652e"
    )
    expected = bytes.fromhex("4541669a7eaaee61e708dc7cbcc5eb62")
    tag = poly1305_mac(msg, key)
    assert tag == expected, f"tag mismatch:\n  got {tag.hex()}\n  exp {expected.hex()}"
    return True


def run():
    tests = [
        ("RFC 8439 §2.5.2 Poly1305 MAC", test_rfc8439_vector),
        ("RFC 8439 §2.6   Poly1305 key gen + MAC", test_rfc8439_section_26),
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
