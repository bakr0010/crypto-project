import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hmac_sha256 import hmac_sha256

TC1_KEY = "0b" * 20
TC1_DATA = "4869205468657265"
TC1_HMAC = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

TC2_KEY = "4a656665"
TC2_DATA = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"
TC2_HMAC = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

TC3_KEY = "aa" * 20
TC3_DATA = "dd" * 50
TC3_HMAC = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

TC4_KEY = "0102030405060708090a0b0c0d0e0f10111213141516171819"
TC4_DATA = "cd" * 50
TC4_HMAC = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"

TC6_KEY = "aa" * 131
TC6_DATA = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"
TC6_HMAC = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"

TC7_KEY = "aa" * 131
TC7_DATA = bytes(
    b"This is a test using a larger than block-size key and a larger "
    b"than block-size data. The key needs to be hashed before being "
    b"used by the HMAC algorithm."
).hex()

TC7_HMAC = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"

VECTORS = [
    (TC1_KEY, TC1_DATA, TC1_HMAC),
    (TC2_KEY, TC2_DATA, TC2_HMAC),
    (TC3_KEY, TC3_DATA, TC3_HMAC),
    (TC4_KEY, TC4_DATA, TC4_HMAC),
    (TC6_KEY, TC6_DATA, TC6_HMAC),
    (TC7_KEY, TC7_DATA, TC7_HMAC),
]


def run():
    passed = 0
    failed = 0
    for key_hex, data_hex, expected in VECTORS:
        key = bytes.fromhex(key_hex)
        data = bytes.fromhex(data_hex)
        got = hmac_sha256(key, data).hex()
        if got == expected:
            passed += 1
        else:
            failed += 1
            print("FAIL")
            print("  key:     ", key_hex)
            print("  data:    ", data_hex)
            print("  expected:", expected)
            print("  got:     ", got)

    print()
    print(passed, "passed,", failed, "failed")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
