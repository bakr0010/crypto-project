import sys
import os
import hashlib
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sha256 import sha256

VECTORS = [
    (b"abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c"),
]


def fips_vectors_self_check():
    for msg, _ in VECTORS:
        ref = hashlib.sha256(msg).hexdigest()
        print(f"reference for {msg!r}: {ref}")


def run():
    passed = 0
    failed = 0

    for msg, _ in VECTORS:
        expected = hashlib.sha256(msg).hexdigest()
        got = sha256(msg).hex()
        if expected == got:
            passed += 1
        else:
            failed += 1
            print(f"FAIL: input={msg!r}")
            print(f"  expected: {expected}")
            print(f"  got:      {got}")

    for _ in range(50):
        length = random.randint(0, 300)
        data = bytes(random.randint(0, 255) for _ in range(length))
        expected = hashlib.sha256(data).hexdigest()
        got = sha256(data).hex()
        if expected == got:
            passed += 1
        else:
            failed += 1
            print(f"FAIL random: length={length}, data={data.hex()}")

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
