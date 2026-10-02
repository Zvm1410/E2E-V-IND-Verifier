"""Exponential ElGamal over RFC 3526 group 15.

Normative source: SPEC.md v1 revision 2, sections 2, 2.1, 3.1, 7, 8.3, 13.1, 13.3.
Cryptographic source: ElGamal (IEEE TIT 1985); exponential / additively
homomorphic variant for elections from Cramer, Gennaro and Schoenmakers,
"A Secure and Optimally Efficient Multi-Authority Election Scheme",
EUROCRYPT 1997. This module implements no new construction.

Scheme, per SPEC section 7:

    sk  <- [1, q)                       (section 6; dealer only, never on device)
    pk  =  g^sk mod p
    r   <- [1, q)                       (r = 0 excluded, see below)
    Enc_pk(v; r) = (alpha, beta) = (g^r mod p,  pk^r * g^v mod p)

The plaintext lives in the exponent, which is what makes the scheme additively
homomorphic and therefore what makes the section 13.1 tally possible.
Decryption yields g^T, not T; T is recovered by search over [0, N], which is
cheap because T is bounded by the ballot count (SPEC section 7).

Two spec rules that are easy to lose and are enforced here rather than assumed:

  * r is drawn from [1, q), not [0, q) (SPEC section 7, change log item 4).
    At r = 0 the ciphertext is (1, g^v) and the vote is readable off the board
    by anyone with no key at all.
  * in_group uses the lower bound 0 < x, not 1 < x (SPEC section 2.1, change
    log item 3). The identity is a legitimate group element. Rejection of
    alpha = 1 is a separate, explicitly named check, not folded into in_group.

INTERFACE CONTRACT with the rest of crypto/. This module imports exactly
four names and nothing else:

    from .group import p, q, g, in_group

If in your tree in_group lives in membership.py rather than group.py, change
that one import line. Importing it from both is how the two copies drift.

SECURITY NOTE, to be stated in the paper alongside SPEC section 18. Python's
built-in pow() is not constant time and CPython's big-int arithmetic is not
side-channel hardened. On the Raspberry Pi 5 hardware track, r and sk are
secret exponents. This is acceptable for a booth-based air-gapped simulation
with no adversary-observable timing channel at cast time, and it is a stated
simplification, not an oversight.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable, Sequence

from group import P as p, Q as q, G as g
from membership import in_group
from encoding import I2B

__all__ = [
    "Ciphertext",
    "ElGamalError",
    "keypair_from_secret",
    "generate_keypair",
    "random_exponent",
    "encrypt",
    "encrypt_random",
    "encrypt_selection",
    "homomorphic_sum",
    "decrypt_to_group_element",
    "recover_exponent",
    "decrypt",
    "check_ciphertext",
]

HEX384_CHARS = 768  # SPEC section 3.5


class ElGamalError(ValueError):
    """Raised when a spec-mandated precondition or check fails."""


# ---------------------------------------------------------------------------
# Ciphertext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Ciphertext:
    """An exponential ElGamal ciphertext (alpha, beta), SPEC section 7.

    Immutable on purpose. A ciphertext that can be mutated after the validity
    proof is built against it is a way to desynchronise proof and statement.
    """

    alpha: int
    beta: int

    def __mul__(self, other: "Ciphertext") -> "Ciphertext":
        """Componentwise product: the section 13.1 aggregation step."""
        if not isinstance(other, Ciphertext):
            return NotImplemented
        return Ciphertext(
            (self.alpha * other.alpha) % p,
            (self.beta * other.beta) % p,
        )

    def to_json(self) -> dict[str, str]:
        """HEX384 form, SPEC section 3.5: 768 lowercase hex chars, never a number."""
        return {
            "alpha": I2B(self.alpha).hex(),
            "beta": I2B(self.beta).hex(),
        }
        

    @classmethod
    def from_json(cls, obj: dict[str, str]) -> "Ciphertext":
        """Parse HEX384. Any length other than 768 is a rejection (section 3.5)."""
        for field in ("alpha", "beta"):
            if field not in obj:
                raise ElGamalError(f"ciphertext missing field {field!r}")
            value = obj[field]
            if not isinstance(value, str):
                raise ElGamalError(f"{field} must be a HEX384 string, not a JSON number")
            if len(value) != HEX384_CHARS:
                raise ElGamalError(
                    f"{field} has {len(value)} hex chars, HEX384 requires {HEX384_CHARS}"
                )
            if value != value.lower():
                raise ElGamalError(f"{field} must be lowercase hex")
        return cls(int(obj["alpha"], 16), int(obj["beta"], 16))


# ---------------------------------------------------------------------------
# Keys (SPEC section 6). Dealer side only; sk never reaches the voter terminal.
# ---------------------------------------------------------------------------


def keypair_from_secret(sk: int) -> tuple[int, int]:
    """Return (sk, pk) for a caller-supplied sk. Used by the dealer and by tests."""
    if not 1 <= sk < q:
        raise ElGamalError("sk must lie in [1, q) per SPEC section 6")
    return sk, pow(g, sk, p)


def generate_keypair() -> tuple[int, int]:
    """Fresh (sk, pk) with sk uniform in [1, q)."""
    return keypair_from_secret(random_exponent())


def random_exponent() -> int:
    """Uniform in [1, q). Zero excluded per SPEC section 7 / change log item 4.

    secrets.randbelow is a CSPRNG. random.randrange is not and must not appear
    anywhere in this package.
    """
    return 1 + secrets.randbelow(q - 1)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def encrypt(pk: int, v: int, r: int) -> Ciphertext:
    """Enc_pk(v; r) = (g^r mod p, pk^r * g^v mod p). SPEC section 7.

    r is an explicit argument with no default. In this system r is not a local
    implementation detail: it is committed pre-poll (section 10) and revealed
    on challenge (section 11). Code that cannot name the r it used cannot
    produce a spoil record.
    """
    if not in_group(pk):
        raise ElGamalError("pk is not in G (SPEC section 2.1)")
    if v not in (0, 1):
        raise ElGamalError("v must be 0 or 1; SPEC section 7 uses indicator encoding")
    if not 1 <= r < q:
        raise ElGamalError("r must lie in [1, q); r = 0 publishes the vote in clear")

    alpha = pow(g, r, p)
    beta = (pow(pk, r, p) * pow(g, v, p)) % p
    return Ciphertext(alpha, beta)


def encrypt_random(pk: int, v: int) -> tuple[Ciphertext, int]:
    """Encrypt with fresh randomness. Returns (ciphertext, r).

    r is returned, never discarded, because the caller owes it to the
    section 10 commitment and to any subsequent challenge.
    """
    r = random_exponent()
    return encrypt(pk, v, r), r


def encrypt_selection(
    pk: int, m: int, j: int, randomness: Sequence[int] | None = None
) -> tuple[list[Ciphertext], list[int]]:
    """The section 7 ballot: m ciphertexts, encrypting 1 at index j, 0 elsewhere.

    Returns (ciphertexts, randomness) with both lists of length m and index
    aligned to candidate index. If randomness is supplied it must already be
    the m values drawn against the pre-poll commitment.
    """
    if m < 2:
        raise ElGamalError("m must be at least 2 (candidate list includes NOTA)")
    if not 0 <= j < m:
        raise ElGamalError(f"candidate index {j} outside [0, {m})")

    if randomness is None:
        rs = [random_exponent() for _ in range(m)]
    else:
        rs = list(randomness)
        if len(rs) != m:
            raise ElGamalError(f"expected {m} randomness values, got {len(rs)}")

    cts = [encrypt(pk, 1 if i == j else 0, rs[i]) for i in range(m)]
    return cts, rs


# ---------------------------------------------------------------------------
# Aggregation (SPEC section 13.1)
# ---------------------------------------------------------------------------


def homomorphic_sum(ciphertexts: Iterable[Ciphertext]) -> Ciphertext:
    """A_i = prod alpha, B_i = prod beta, both mod p.

    Over an empty set this returns (1, 1), the encryption of 0 under r = 0,
    which is the correct identity for the product. A booth with zero counted
    ballots is a section 16 concern, not an arithmetic one.
    """
    a, b = 1, 1
    for ct in ciphertexts:
        a = (a * ct.alpha) % p
        b = (b * ct.beta) % p
    return Ciphertext(a, b)


# ---------------------------------------------------------------------------
# Decryption and tally recovery (SPEC section 13.3)
# ---------------------------------------------------------------------------


def decrypt_to_group_element(ct: Ciphertext, sk: int) -> int:
    """Return g^T = beta * alpha^{-sk} mod p.

    Single-key form. Production uses the threshold path of section 13.3, where
    alpha^sk is replaced by prod_j M_{j,i}^{lambda_j(S)}. This function is for
    the dealer, the harness and the tests. It is never called on the terminal
    and no code path should give it an sk that came off a device.
    """
    if not 1 <= sk < q:
        raise ElGamalError("sk must lie in [1, q)")
    shared = pow(ct.alpha, sk, p)
    return (ct.beta * pow(shared, -1, p)) % p


def recover_exponent(g_to_t: int, bound: int) -> int:
    """Baby-step giant-step for T in [0, bound] with g^T = g_to_t. SPEC section 13.3.

    Raises rather than returning a sentinel: no value of T in range means the
    transcript is inconsistent, which is a rejection, not a zero.
    """
    if bound < 0:
        raise ElGamalError("bound must be non-negative")

    step = 1
    while step * step <= bound:
        step += 1

    table: dict[int, int] = {}
    baby = 1
    for i in range(step):
        table.setdefault(baby, i)
        baby = (baby * g) % p

    factor = pow(pow(g, step, p), -1, p)
    current = g_to_t
    for i in range(step + 1):
        hit = table.get(current)
        if hit is not None:
            t = i * step + hit
            if t <= bound:
                return t
        current = (current * factor) % p

    raise ElGamalError(f"no exponent in [0, {bound}] matches the given group element")


def decrypt(ct: Ciphertext, sk: int, bound: int) -> int:
    """Full single-key decryption to a small integer plaintext."""
    return recover_exponent(decrypt_to_group_element(ct, sk), bound)


# ---------------------------------------------------------------------------
# Verifier-side structural checks (SPEC section 8.3, checks 1 and 2)
# ---------------------------------------------------------------------------


def check_ciphertext(ct: Ciphertext) -> None:
    """Section 8.3 checks 1 and 2, restricted to the parts this module owns.

    Check 1: in_group on both components.
    Check 2: alpha != 1. Applies to ciphertext components only and never to
    proof commitments a_0, b_0, a_1, b_1, where the identity is legitimate and
    rejecting it would create nonzero clean-mode false rejection, which
    section 16 forbids.

    Raises ElGamalError naming the failed check. The verifier owns the
    full ordered check list; this exists so that the prover never publishes a
    ciphertext that its own verifier would refuse.
    """
    if not in_group(ct.alpha):
        raise ElGamalError("check 1: alpha not in G")
    if not in_group(ct.beta):
        raise ElGamalError("check 1: beta not in G")
    if ct.alpha == 1:
        raise ElGamalError("check 2: alpha == 1, encryption randomness was zero")
