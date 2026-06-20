H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK32 = 0xffffffff


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK32


def _pad(message):
    ml = len(message) * 8
    message += b"\x80"
    while (len(message) * 8) % 512 != 448:
        message += b"\x00"
    message += ml.to_bytes(8, "big")
    return message


def _blocks(padded):
    return [padded[i:i + 64] for i in range(0, len(padded), 64)]


def _compress(block, h):
    w = [0] * 64
    for t in range(16):
        w[t] = int.from_bytes(block[t * 4:t * 4 + 4], "big")
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK32

    a, b, c, d, e, f, g, hh = h

    for t in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (hh + s1 + ch + K[t] + w[t]) & MASK32
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & MASK32

        hh = g
        g = f
        f = e
        e = (d + temp1) & MASK32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK32

    return [
        (h[0] + a) & MASK32, (h[1] + b) & MASK32,
        (h[2] + c) & MASK32, (h[3] + d) & MASK32,
        (h[4] + e) & MASK32, (h[5] + f) & MASK32,
        (h[6] + g) & MASK32, (h[7] + hh) & MASK32,
    ]


def sha256(message):
    h = list(H_INIT)
    padded = _pad(message)
    for block in _blocks(padded):
        h = _compress(block, h)
    return b"".join(x.to_bytes(4, "big") for x in h)
