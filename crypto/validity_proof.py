"""
Two-branch OR-proof (per-candidate ballot validity proof).

Proves that an exponential-ElGamal ciphertext (alpha, beta) encrypts 0 or 1,
without revealing which. A ballot needs m of these, one per candidate position.

Construction
------------
Disjunctive (OR) composition, Cramer / Damgard / Schoenmakers, "Proofs of Partial
Knowledge and Simplified Design of Witness Hiding Protocols", CRYPTO 1994,
Section 3 (the (1,2)-threshold sharing of the verifier's challenge), applied over
two Chaum-Pedersen equality-of-discrete-log sigma protocols (Chaum and Pedersen,
"Wallet Databases with Observers", CRYPTO 1992). Made non-interactive by
Fiat-Shamir with the strong-binding preimage of SPEC section 8.2.

    Branch 0:  log_g(alpha) == log_pk(beta)          i.e. the plaintext is 0
    Branch 1:  log_g(alpha) == log_pk(beta * g^-1)   i.e. the plaintext is 1

Soundness lives entirely in  c_0 + c_1 == c (mod q).  The four exponentiation
equations below all pass for a proof forged by choosing BOTH sub-challenges
freely; only the sum equation stops it.

What this closes: a compromised booth publishing a ciphertext that encrypts
anything other than 0 or 1 (e.g. 7, or -1) and thereby adding or removing votes
inside a single encrypted position. Without it, nothing constrains the plaintext
and every downstream tally check still passes.

Spec references: SPEC.md sections 7, 8.1, 8.2, 8.3, plus the SPEC revision 2
amendments recorded in SPEC revision 3 (in_group lower bound
0 < x < p, and the alpha != 1 check as check 2 of section 8.3).

This file writes to nothing and reads no board state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

# --------------------------------------------------------------------------
# Shared primitives.
# --------------------------------------------------------------------------
try:  # package-relative first
    from .group import P as p, Q as q, G as g          # group
    from .encoding import I2B, B2I, U64, S32, L  # encoding
    from .membership import in_group           # subgroup membership
except ImportError:  # flat-directory / test fallback
    from group import P as p, Q as q, G as g           # type: ignore
    from encoding import I2B, B2I, U64, S32, L  # type: ignore
    from membership import in_group            # type: ignore


DOMAIN_VALIDITY = "EVOTE-VALIDITY-v1"

#: SPEC 8.2: 32 + 32 + 32 + 8 + 8 + 7 * 384
VALIDITY_PREIMAGE_LEN = 2800


# --------------------------------------------------------------------------
# Record shape (SPEC section 14)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidityProof:
    """The eight published proof values, plus the position they were built for.

    Field order here is the JSON field order of SPEC section 14. It is NOT the
    preimage order; see validity_preimage for that.
    """

    candidate_index: int
    c0: int
    c1: int
    f0: int
    f1: int
    a0: int
    b0: int
    a1: int
    b1: int

    def to_json(self) -> dict:
        """HEX384 for every group element and exponent, per SPEC section 3.5."""
        return {
            "candidate_index": int(self.candidate_index),
            "c0": I2B(self.c0).hex(),
            "c1": I2B(self.c1).hex(),
            "f0": I2B(self.f0).hex(),
            "f1": I2B(self.f1).hex(),
            "a0": I2B(self.a0).hex(),
            "b0": I2B(self.b0).hex(),
            "a1": I2B(self.a1).hex(),
            "b1": I2B(self.b1).hex(),
        }

    @classmethod
    def from_json(cls, obj: dict) -> "ValidityProof":
        def hx(name: str) -> int:
            s = obj[name]
            if not isinstance(s, str) or len(s) != 768:
                raise ValueError(f"{name} is not a 768-character HEX384 field")
            return B2I(bytes.fromhex(s))

        return cls(
            candidate_index=int(obj["candidate_index"]),
            c0=hx("c0"), c1=hx("c1"), f0=hx("f0"), f1=hx("f1"),
            a0=hx("a0"), b0=hx("b0"), a1=hx("a1"), b1=hx("b1"),
        )


# --------------------------------------------------------------------------
# Challenge (SPEC section 8.2)
# --------------------------------------------------------------------------

def validity_preimage(Q: bytes, booth_id: str, ballot_serial: int,
                      candidate_index: int, pk: int, alpha: int, beta: int,
                      a0: int, b0: int, a1: int, b1: int) -> bytes:
    """Exactly the 2800 bytes of SPEC section 8.2, in order.

    Returned rather than hashed in place because the test vectors must carry the
    raw preimage in hex: almost every failure in this project is one wrong byte
    in one preimage, and without the preimage there is no way to find which.

    Note the commitments enter in index order a0, b0, a1, b1 regardless of
    which branch was simulated. The verifier does not know which was.
    """
    if not isinstance(Q, (bytes, bytearray)) or len(Q) != 32:
        raise ValueError("Q must be the 32 raw bytes of SPEC section 5.2")

    pre = b"".join([
        L(DOMAIN_VALIDITY),      # 32
        bytes(Q),                # 32
        S32(booth_id),           # 32
        U64(ballot_serial),      # 8
        U64(candidate_index),    # 8
        I2B(pk),                 # 384
        I2B(alpha),              # 384
        I2B(beta),               # 384
        I2B(a0),                 # 384
        I2B(b0),                 # 384
        I2B(a1),                 # 384
        I2B(b1),                 # 384
    ])
    if len(pre) != VALIDITY_PREIMAGE_LEN:
        raise AssertionError(
            f"validity preimage is {len(pre)} bytes, spec says "
            f"{VALIDITY_PREIMAGE_LEN}; a field is missing or mis-encoded"
        )
    return pre


def validity_challenge(Q: bytes, booth_id: str, ballot_serial: int,
                       candidate_index: int, pk: int, alpha: int, beta: int,
                       a0: int, b0: int, a1: int, b1: int) -> int:
    """c = B2I(SHA-256(preimage)) mod q  (SPEC section 4)."""
    pre = validity_preimage(Q, booth_id, ballot_serial, candidate_index,
                            pk, alpha, beta, a0, b0, a1, b1)
    return B2I(hashlib.sha256(pre).digest()) % q


# --------------------------------------------------------------------------
# Prover (SPEC section 8.1)
# --------------------------------------------------------------------------

def prove_validity(v: int, r: int, alpha: int, beta: int, pk: int,
                   Q: bytes, booth_id: str, ballot_serial: int,
                   candidate_index: int, rng) -> ValidityProof:
    """Build the OR-proof for one ciphertext position.

    v is the true plaintext, 0 or 1. r is the encryption randomness that
    produced (alpha, beta); it is supplied by the caller (the pre-poll commitment of SPEC 10.1 fixes it before
    the poll opens) and is never drawn here.

    rng is a seeded random.Random. Draw order is fixed and load-bearing for the
    test vectors: c_d, then f_d, then w. Do not reorder.
    """
    if v not in (0, 1):
        raise ValueError("validity proof is only defined for v in {0, 1}")
    if not (0 <= r < q):
        raise ValueError("encryption randomness must lie in [0, q)")

    d = 1 - v  # the branch we cannot prove, and therefore simulate

    # --- simulated branch d -------------------------------------------------
    c_d = rng.randrange(q)
    f_d = rng.randrange(q)
    target_d = (beta * pow(g, -d, p)) % p          # beta * g^-d
    a_d = (pow(g, f_d, p) * pow(alpha, -c_d, p)) % p
    b_d = (pow(pk, f_d, p) * pow(target_d, -c_d, p)) % p

    # --- real branch v ------------------------------------------------------
    w = rng.randrange(q)
    a_v = pow(g, w, p)
    b_v = pow(pk, w, p)

    a0, b0 = (a_v, b_v) if v == 0 else (a_d, b_d)
    a1, b1 = (a_v, b_v) if v == 1 else (a_d, b_d)

    # --- challenge, split, response ----------------------------------------
    c = validity_challenge(Q, booth_id, ballot_serial, candidate_index,
                           pk, alpha, beta, a0, b0, a1, b1)
    c_v = (c - c_d) % q          # forced; this is the whole of soundness
    f_v = (w + c_v * r) % q

    c0, f0 = (c_v, f_v) if v == 0 else (c_d, f_d)
    c1, f1 = (c_v, f_v) if v == 1 else (c_d, f_d)

    return ValidityProof(candidate_index=candidate_index,
                         c0=c0, c1=c1, f0=f0, f1=f1,
                         a0=a0, b0=b0, a1=a1, b1=b1)


# --------------------------------------------------------------------------
# Verifier (SPEC section 8.3, as amended by SPEC revision 2)
# --------------------------------------------------------------------------

def check_validity(proof: ValidityProof, alpha: int, beta: int, pk: int,
                   Q: bytes, booth_id: str, ballot_serial: int,
                   candidate_index: int) -> Optional[str]:
    """Return None if the proof passes, else a short reason string.

    candidate_index is passed explicitly and is the position the proof occupies
    in the ballot record, not proof.candidate_index. A record whose stored index
    disagrees with its position is a SPEC 14 parse-level rejection, not this
    function's business; binding to the position is what step 4 below enforces.

    Checks run in the order of SPEC section 8.3, rejecting on first failure.
    The reason strings are what the verifier's property attribution reports under P2.
    """
    # 1. subgroup membership, on every parsed group element
    for name, x in (("alpha", alpha), ("beta", beta), ("a0", proof.a0),
                    ("b0", proof.b0), ("a1", proof.a1), ("b1", proof.b1)):
        if not in_group(x):
            return f"subgroup:{name}"

    # 2. alpha != 1. Ciphertext components only. The identity is legitimate for
    #    a0/b0/a1/b1 -- a simulated commitment equals 1 whenever f_d == r*c_d
    #    (mod q) -- and rejecting it there would make clean-mode false rejection
    #    nonzero, which the zero false-rejection requirement forbids. alpha == 1 means r == 0, at which point
    #    beta == g^v and the vote is readable off the board with no key.
    if alpha == 1:
        return "alpha_is_identity"

    # 3. range checks on challenges and responses
    for name, x in (("c0", proof.c0), ("c1", proof.c1),
                    ("f0", proof.f0), ("f1", proof.f1)):
        if not (0 <= x < q):
            return f"range:{name}"

    # 4. recompute the challenge from the statement we are actually verifying
    c = validity_challenge(Q, booth_id, ballot_serial, candidate_index,
                           pk, alpha, beta, proof.a0, proof.b0,
                           proof.a1, proof.b1)

    # 5. the sub-challenge sum. This is the check carrying soundness. The four
    #    equations below all pass for a proof with both sub-challenges free.
    if (proof.c0 + proof.c1) % q != c:
        return "subchallenge_sum"

    # 6-9. the two Chaum-Pedersen equation pairs
    if pow(g, proof.f0, p) != (proof.a0 * pow(alpha, proof.c0, p)) % p:
        return "eq:g^f0"
    if pow(pk, proof.f0, p) != (proof.b0 * pow(beta, proof.c0, p)) % p:
        return "eq:pk^f0"
    if pow(g, proof.f1, p) != (proof.a1 * pow(alpha, proof.c1, p)) % p:
        return "eq:g^f1"
    beta_over_g = (beta * pow(g, -1, p)) % p
    if pow(pk, proof.f1, p) != (proof.b1 * pow(beta_over_g, proof.c1, p)) % p:
        return "eq:pk^f1"

    return None


def verify_validity(proof: ValidityProof, alpha: int, beta: int, pk: int,
                    Q: bytes, booth_id: str, ballot_serial: int,
                    candidate_index: int) -> bool:
    """Boolean wrapper over check_validity."""
    return check_validity(proof, alpha, beta, pk, Q, booth_id,
                          ballot_serial, candidate_index) is None
