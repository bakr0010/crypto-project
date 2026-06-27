P = 2**255 - 19
A24 = 121665

def _clamp_scalar(k):
    k = bytearray(k)
    k[0]  &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)

def _decode_u_coord(u):
    u = bytearray(u)
    u[31] &= 127
    return int.from_bytes(u, "little") % P

def _encode_u_coord(u):
    return (u % P).to_bytes(32, "little")

def _inv(x):
    return pow(x, P - 2, P)

def _montgomery_ladder(k_scalar, u):
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k_scalar >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A  = (x_2 + z_2) % P
        AA = (A * A) % P
        B  = (x_2 - z_2) % P
        BB = (B * B) % P
        E  = (AA - BB) % P
        C  = (x_3 + z_3) % P
        D  = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = (x_1 * pow(DA - CB, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    return (x_2 * _inv(z_2)) % P

def x25519(k_bytes, u_bytes):
    k = int.from_bytes(_clamp_scalar(k_bytes), "little")
    u = _decode_u_coord(u_bytes)
    result = _montgomery_ladder(k, u)
    return _encode_u_coord(result)

BASE_POINT = (9).to_bytes(32, "little")

def generate_public_key(private_key):
    return x25519(private_key, BASE_POINT)

def generate_keypair(private_key):
    return private_key, generate_public_key(private_key)
