MASK32 = 0xffffffff

CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & MASK32


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & MASK32; state[d] ^= state[a]; state[d] = _rotl(state[d], 16)
    state[c] = (state[c] + state[d]) & MASK32; state[b] ^= state[c]; state[b] = _rotl(state[b], 12)
    state[a] = (state[a] + state[b]) & MASK32; state[d] ^= state[a]; state[d] = _rotl(state[d],  8)
    state[c] = (state[c] + state[d]) & MASK32; state[b] ^= state[c]; state[b] = _rotl(state[b],  7)


def _chacha20_block(key, counter, nonce):
    state = (
        CONSTANTS +
        [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)] +
        [counter & MASK32] +
        [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4)]
    )
    working = list(state)

    for _ in range(10):
        _quarter_round(working, 0, 4,  8, 12)
        _quarter_round(working, 1, 5,  9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7,  8, 13)
        _quarter_round(working, 3, 4,  9, 14)

    output = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return b"".join(x.to_bytes(4, "little") for x in output)


def chacha20_encrypt(key, counter, nonce, plaintext):
    out = []
    for i, offset in enumerate(range(0, len(plaintext), 64)):
        block = _chacha20_block(key, counter + i, nonce)
        chunk = plaintext[offset:offset + 64]
        out.append(bytes(a ^ b for a, b in zip(chunk, block)))
    return b"".join(out)
