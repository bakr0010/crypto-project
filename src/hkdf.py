from hmac_sha256 import hmac_sha256, DIGEST_SIZE


def hkdf_extract(salt, ikm):
    if len(salt) == 0:
        salt = bytes(DIGEST_SIZE)
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    n = (length + DIGEST_SIZE - 1) // DIGEST_SIZE
    if n > 255:
        raise ValueError("requested length too large for HKDF-SHA256")

    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf(salt, ikm, info, length):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)
