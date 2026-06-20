import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hkdf import hkdf_extract, hkdf_expand, hkdf

TC1_IKM = "0b" * 22
TC1_SALT = "000102030405060708090a0b0c"
TC1_INFO = "f0f1f2f3f4f5f6f7f8f9"
TC1_L = 42
TC1_PRK = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
TC1_OKM = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

TC3_IKM = "0b" * 22
TC3_SALT = ""
TC3_INFO = ""
TC3_L = 42
TC3_PRK = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
TC3_OKM = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

TC2_IKM = "".join("%02x" % (b & 0xff) for b in range(0x00, 0x50))
TC2_SALT = "".join("%02x" % (b & 0xff) for b in range(0x60, 0xb0))
TC2_INFO = "".join("%02x" % (b & 0xff) for b in range(0xb0, 0x100))
TC2_L = 82
TC2_PRK = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
TC2_OKM = (
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f1d87"
)

VECTORS = [
    (TC1_IKM, TC1_SALT, TC1_INFO, TC1_L, TC1_PRK, TC1_OKM),
    (TC2_IKM, TC2_SALT, TC2_INFO, TC2_L, TC2_PRK, TC2_OKM),
    (TC3_IKM, TC3_SALT, TC3_INFO, TC3_L, TC3_PRK, TC3_OKM),
]


def run():
    passed = 0
    failed = 0
    for ikm_hex, salt_hex, info_hex, length, prk_hex, okm_hex in VECTORS:
        ikm = bytes.fromhex(ikm_hex)
        salt = bytes.fromhex(salt_hex)
        info = bytes.fromhex(info_hex)

        prk = hkdf_extract(salt, ikm)
        if prk.hex() == prk_hex:
            passed += 1
        else:
            failed += 1
            print("FAIL extract")
            print("  expected:", prk_hex)
            print("  got:     ", prk.hex())

        okm = hkdf_expand(prk, info, length)
        if okm.hex() == okm_hex:
            passed += 1
        else:
            failed += 1
            print("FAIL expand")
            print("  expected:", okm_hex)
            print("  got:     ", okm.hex())

        okm_combined = hkdf(salt, ikm, info, length)
        if okm_combined.hex() == okm_hex:
            passed += 1
        else:
            failed += 1
            print("FAIL combined hkdf()")

    print()
    print(passed, "passed,", failed, "failed")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
