P = (1 << 130) - 5
MASK128 = (1 << 128) - 1


def _clamp(r):
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    return r


def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], "little")
    s = int.from_bytes(key[16:], "little")
    r = _clamp(r)

    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
        acc = (r * (acc + n)) % P

    acc = (acc + s) & MASK128
    return acc.to_bytes(16, "little")
