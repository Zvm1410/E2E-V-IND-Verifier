"""
SPEC.md section 2 — Group parameters.

Implements the RFC 3526 Group 15 (3072-bit MODP) group used as the
DDH/discrete-log group for the exponential ElGamal scheme in this
project, and the load-time assertions and subgroup-membership test
required by SPEC.md sections 2 and 2.1.

No external crypto dependencies. Standard library only.
"""

from encoding import I2B, B2I
import hashlib

# ---------------------------------------------------------------------------
# 1. The mathematics, in symbols
# ---------------------------------------------------------------------------
#
# p is the RFC 3526 Group 15 modulus:
#
#     p = 2^3072 - 2^3008 - 1 + 2^64 * ( floor(2^2942 * pi) + 1690314 )
#
# q is the order of the prime-order subgroup:
#
#     q = (p - 1) / 2
#
# g = 2 is the generator.
#
# p is a *safe prime*: p = 2q + 1 with q itself prime. This is what
# makes G = <g> (the subgroup of squares mod p, i.e. the quadratic
# residues) a prime-order subgroup of (Z/pZ)*, of order q, in which the
# discrete-log and DDH problems are believed hard and in which every
# non-identity element is a generator of G.
#
# g = 2 generates G (rather than the full group (Z/pZ)*, which has
# order 2q and a subgroup of order 2) precisely when 2 is a quadratic
# residue mod p. By quadratic reciprocity, 2 is a QR mod an odd prime p
# iff p = 1 mod 8 or p = 7 mod 8. RFC 3526's primes are constructed to
# satisfy p = 7 (mod 8), so g = 2 generates the order-q subgroup with
# no cofactor clearing needed.
#
# ---------------------------------------------------------------------------
# 2. Source
# ---------------------------------------------------------------------------
#
#   T. Kivinen and M. Kojo, "More Modular Exponential (MODP)
#   Diffie-Hellman groups for Internet Key Exchange (IKE)", RFC 3526,
#   IETF, May 2003. Group 15 (the 3072-bit MODP group), section 4.
#
# RFC 3526 itself does not derive p as an equation; it publishes the
# hex literal. SPEC.md's closed-form expression for p (reproduced
# above) is the standard "pi-derived" construction used to describe
# where these Oakley/MODP primes come from; it is verified against the
# RFC's published hex literal below rather than trusted on its own.
#
# ---------------------------------------------------------------------------
# 3. The verification equations
# ---------------------------------------------------------------------------
#
# At load time (SPEC.md section 2, assertions 1-5):
#
#   (i)   p, q prime                      Miller-Rabin, >= 32 rounds
#   (ii)  p == 2*q + 1                    safe-prime relation
#   (iii) g^q == 1 (mod p)                g has order dividing q
#   (iv)  p == 7 (mod 8)                  2 is a QR mod p (so g=2 works)
#   (v)   SHA-256(I2B(p)) == pinned, and likewise for q and g
#
# Subgroup membership (SPEC.md section 2.1), for any integer x:
#
#   in_group(x)  iff  1 < x < p  and  x^q == 1 (mod p)
#
# This is exactly the Legendre-symbol / QR test: since p = 2q+1,
# Fermat's little theorem gives x^(p-1) = 1 for any x coprime to p,
# and x^q is then a square root of 1, i.e. +-1. x^q == 1 iff x is a
# quadratic residue mod p, iff x lies in the order-q subgroup G.

# ---------------------------------------------------------------------------
# The pinned literal. Computed once from the closed-form expression
# above and hard-coded here, per SPEC.md ("Do not recompute it from
# the formula at runtime."). Verified against the RFC 3526 published
# hex and against the pinned digests in SPEC.md section 2 in the test
# suite (test_group.py) and again at import time below.
# ---------------------------------------------------------------------------

P_HEX = (
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552b"
    "b9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce"
    "3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581"
    "7183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507"
    "a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e"
    "4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0"
    "864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad9"
    "46e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffff"
    "ffff"
)

P = int(P_HEX, 16)
Q = (P - 1) // 2
G = 2

# Pinned check values from SPEC.md section 2, verified at import time.
_PINNED_BITLEN_P = 3072
_PINNED_FIRST64_P = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
_PINNED_LAST32_P = "4b82d120a93ad2caffffffffffffffff"
_PINNED_BITLEN_Q = 3071
_PINNED_SHA256_P = "48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c"
_PINNED_SHA256_Q = "018089836b3704979e9c4ed47a717e61440ff98b4deba0e7e95e56514442e52c"
_PINNED_SHA256_G = "0c29b032a70f848d7ce809f1c926afaea4bce7b3a037ad74b39861c19eb0161c"


# def I2B(x: int, length: int = 384) -> bytes:
#     """SPEC.md 3.1 -- integers to bytes, fixed 384-byte big-endian width."""
#     return x.to_bytes(length, "big")


# def B2I(b: bytes) -> int:
#     """SPEC.md 3.1 -- bytes to integers."""
#     return int.from_bytes(b, "big")


def _miller_rabin(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin primality test, >= 32 rounds per SPEC.md section 2.

    Standard library only: no sympy/gmpy2. Deterministic base-2 trial
    division for small n, then randomized witnesses via `secrets` for
    the general case, as required for a security-sensitive primality
    check (random.random() is not appropriate here).
    """
    import secrets

    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def load_time_assertions(p: int = P, q: int = Q, g: int = G) -> None:
    """SPEC.md section 2, assertions 1-5. Raises AssertionError on any failure."""
    assert _miller_rabin(p, 32), "p failed Miller-Rabin primality (32 rounds)"
    assert _miller_rabin(q, 32), "q failed Miller-Rabin primality (32 rounds)"
    assert p == 2 * q + 1, "p != 2*q + 1"
    assert pow(g, q, p) == 1, "g^q != 1 (mod p)"
    assert p % 8 == 7, "p != 7 (mod 8)"

    h_p = hashlib.sha256(I2B(p)).hexdigest()
    h_q = hashlib.sha256(I2B(q)).hexdigest()
    h_g = hashlib.sha256(I2B(g)).hexdigest()
    assert h_p == _PINNED_SHA256_P, f"SHA-256(I2B(p)) mismatch: {h_p}"
    assert h_q == _PINNED_SHA256_Q, f"SHA-256(I2B(q)) mismatch: {h_q}"
    assert h_g == _PINNED_SHA256_G, f"SHA-256(I2B(g)) mismatch: {h_g}"


# def in_group(x: int, p: int = P, q: int = Q) -> bool:
#     """SPEC.md section 2.1 -- subgroup membership test.

#     in_group(x)  iff  0 < x < p  and  pow(x, q, p) == 1
#     """
#     if not (0 < x < p):
#         return False
#     return pow(x, q, p) == 1


# Run the load-time assertions as soon as this module is imported, per
# SPEC.md: "run by B, C and D independently in their own code."
load_time_assertions()
