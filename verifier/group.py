"""Group parameters, SPEC section 2.

p is hard-coded as a literal (RFC 3526 group 15, 3072-bit MODP) and never
recomputed at runtime. The cheap load-time assertions run on import; the
Miller-Rabin primality checks are in verify_group_parameters(), which the
verifier calls once before checking a board.
"""

import hashlib
import random

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 2

WIDTH = 384  # bytes, SPEC 3.1

PINNED = {
    "bit_length_p": 3072,
    "bit_length_q": 3071,
    "first_64_hex_digits_of_p": "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "last_32_hex_digits_of_p": "4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    "sha256_I2B_p": "48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c",
    "sha256_I2B_q": "018089836b3704979e9c4ed47a717e61440ff98b4deba0e7e95e56514442e52c",
    "sha256_I2B_g": "0c29b032a70f848d7ce809f1c926afaea4bce7b3a037ad74b39861c19eb0161c",
}


class GroupParameterError(Exception):
    pass


def _sha256_i2b(x):
    # Local fixed-width encoding so this module has no import cycle with encoding.py.
    return hashlib.sha256(x.to_bytes(WIDTH, "big")).hexdigest()


def is_probable_prime(n, rounds=32, seed=0):
    """Miller-Rabin with `rounds` random bases drawn from a seeded RNG."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(seed)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _check_cheap():
    hex_p = format(P, "X")
    checks = [
        (P.bit_length() == PINNED["bit_length_p"], "bit length of p"),
        (Q.bit_length() == PINNED["bit_length_q"], "bit length of q"),
        (hex_p[:64] == PINNED["first_64_hex_digits_of_p"], "first 64 hex digits of p"),
        (hex_p[-32:] == PINNED["last_32_hex_digits_of_p"], "last 32 hex digits of p"),
        (P == 2 * Q + 1, "p == 2q + 1"),
        (P % 8 == 7, "p % 8 == 7"),
        (pow(G, Q, P) == 1, "g^q == 1 mod p"),
        (_sha256_i2b(P) == PINNED["sha256_I2B_p"], "SHA-256 of I2B(p)"),
        (_sha256_i2b(Q) == PINNED["sha256_I2B_q"], "SHA-256 of I2B(q)"),
        (_sha256_i2b(G) == PINNED["sha256_I2B_g"], "SHA-256 of I2B(g)"),
    ]
    for ok, name in checks:
        if not ok:
            raise GroupParameterError(f"group parameter check failed: {name}")


def verify_group_parameters(rounds=32, seed=0):
    """All five load-time assertions of SPEC section 2, including primality."""
    _check_cheap()
    if not is_probable_prime(P, rounds, seed):
        raise GroupParameterError("p is not prime")
    if not is_probable_prime(Q, rounds, seed + 1):
        raise GroupParameterError("q is not prime")


_check_cheap()
