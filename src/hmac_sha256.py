from sha256 import sha256

BLOCK_SIZE = 64
DIGEST_SIZE = 32

IPAD = 0x36
OPAD = 0x5c


def _prepare_key(key):
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    return key + b"\x00" * (BLOCK_SIZE - len(key))


def hmac_sha256(key, message):
    k = _prepare_key(key)
    k_ipad = bytes(b ^ IPAD for b in k)
    k_opad = bytes(b ^ OPAD for b in k)
    inner = sha256(k_ipad + message)
    return sha256(k_opad + inner)
