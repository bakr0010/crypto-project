import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from x25519 import x25519, generate_public_key

def test_rfc7748_vector1():
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    result = x25519(k, u)
    assert result == expected, f"vector1:\n  got {result.hex()}\n  exp {expected.hex()}"

def test_rfc7748_vector2():
    k = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    u = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    expected = bytes.fromhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    result = x25519(k, u)
    assert result == expected, f"vector2:\n  got {result.hex()}\n  exp {expected.hex()}"

def test_rfc7748_dh_exchange():
    alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_pub_exp = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_priv   = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_pub_exp = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared_exp  = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    alice_pub = generate_public_key(alice_priv)
    bob_pub   = generate_public_key(bob_priv)

    assert alice_pub == alice_pub_exp, f"alice pub:\n  got {alice_pub.hex()}\n  exp {alice_pub_exp.hex()}"
    assert bob_pub   == bob_pub_exp,   f"bob pub:\n  got {bob_pub.hex()}\n  exp {bob_pub_exp.hex()}"

    alice_shared = x25519(alice_priv, bob_pub)
    bob_shared   = x25519(bob_priv, alice_pub)

    assert alice_shared == shared_exp, f"alice shared:\n  got {alice_shared.hex()}\n  exp {shared_exp.hex()}"
    assert bob_shared   == shared_exp, f"bob shared:\n  got {bob_shared.hex()}\n  exp {shared_exp.hex()}"
    assert alice_shared == bob_shared

def run():
    tests = [
        ("RFC 7748 §5.2 test vector 1",    test_rfc7748_vector1),
        ("RFC 7748 §5.2 test vector 2",    test_rfc7748_vector2),
        ("RFC 7748 §6.1 full DH exchange", test_rfc7748_dh_exchange),
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
