"""
Chaum-Pedersen equality-of-discrete-logarithms proof (DLEQ).

Protocol
--------
Chaum & Pedersen, "Wallet Databases with Observers", CRYPTO '92, LNCS 740,
pp. 89-105. Made non-interactive by Fiat-Shamir (CRYPTO '86) in the strong form
of Bernhard, Pereira & Warinschi (ASIACRYPT 2012).

Relation
--------
    R = { ((g1, h1, u, v), x) : u = g1^x mod p  AND  v = h1^x mod p }

Prover (witness x in Z_q), SPEC section 13.2:
    w  <- uniform in [0, q)
    a  = g1^w mod p
    b  = h1^w mod p
    c  = B2I(SHA-256(preimage)) mod q
    f  = (w + c*x) mod q

Verifier accepts iff
    g1, h1, u, v, a, b in the order-q subgroup   [subgroup membership]
    0 <= c, f < q
    c recomputes from the preimage
    g1^f == a * u^c mod p
    h1^f == b * v^c mod p

WHERE THE PREIMAGE COMES FROM
-----------------------------
SPEC.md does not define a generic Chaum-Pedersen challenge. It defines two
specific ones, with different labels and different field lists:

    section 9.2   sum-to-one proof        EVOTE-SUMONE-v1    2408 bytes
    section 13.2  partial decryption      EVOTE-PARTIAL-v1   2384 bytes

So this module does not own a domain tag and cannot invent one. The core
`prove` / `verify` pair takes the preimage from the caller; the section 13.2
instance is built here because the decryption proofs are its consumer and the layout is
normative.

Section 9.2's instance lives in `sumone.py`, which already builds it correctly.
It is deliberately not rewired through this module: changing working code to
satisfy tidiness risks breaking it for no verifiable gain.

Revision note. An earlier version of this module derived its challenge through
`challenge.py`, which used a one-byte domain tag and keyed SHA-256 with Q
instead of placing Q inside the preimage. That is not the construction in
SPEC.md and no proof produced under it verifies against a spec-conformant
verifier. The verifier is implemented from the document, so the document wins.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Optional

from group import P as p, Q as q, G as g
from encoding import I2B, B2I, U64, L
from membership import in_group

__all__ = [
    "CPProof",
    "CPVerification",
    "PARTIAL_LABEL",
    "PARTIAL_PREIMAGE_LEN",
    "PARTIAL_PREIMAGE_LAYOUT",
    "partial_preimage",
    "partial_challenge",
    "prove_partial_decryption",
    "verify_partial_decryption",
    "prove",
    "verify",
    "simulate",
]

PARTIAL_LABEL: Final[str] = "EVOTE-PARTIAL-v1"

# SPEC section 13.2, field by field, in order. The layout is asserted on every
# build, so a missing or mis-sized field is caught here rather than surfacing as
# an unverifiable transcript three modules away.
PARTIAL_PREIMAGE_LAYOUT: Final[tuple] = (
    ("label", 32),
    ("Q", 32),
    ("trustee_index", 8),
    ("candidate_index", 8),
    ("g", 384),
    ("A_i", 384),
    ("h_j", 384),
    ("M_ji", 384),
    ("a", 384),
    ("b", 384),
)
PARTIAL_PREIMAGE_LEN: Final[int] = 2384


@dataclass(frozen=True)
class CPProof:
    """Public transcript of a Chaum-Pedersen equality proof.

    Field names are SPEC section 13.4's: c, f, a, b. The response is `f`, not
    `s`, because that is what the decryption transcript publishes and what
    the verifier's parser is built against.
    """

    c: int
    f: int
    a: int
    b: int

    def to_dict(self) -> dict:
        """SPEC section 13.4 proof object: four HEX384 fields."""
        return {
            "c": I2B(self.c).hex(),
            "f": I2B(self.f).hex(),
            "a": I2B(self.a).hex(),
            "b": I2B(self.b).hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CPProof":
        missing = {"c", "f", "a", "b"} - d.keys()
        if missing:
            raise ValueError(f"missing proof fields: {sorted(missing)}")
        out = {}
        for k in ("c", "f", "a", "b"):
            if len(d[k]) != 768:
                raise ValueError(
                    f"field {k!r}: expected 768 hex characters, got {len(d[k])}"
                )
            out[k] = B2I(bytes.fromhex(d[k]))
        return cls(**out)


@dataclass(frozen=True)
class CPVerification:
    """Verification outcome. `reason` names the failed check so the verifier can
    attribute a property rather than report a bare Reject."""

    ok: bool
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.ok


# ---------------------------------------------------------------------------
# SPEC section 13.2 -- partial decryption proof
# ---------------------------------------------------------------------------

def partial_preimage(*, Q: bytes, trustee_index: int, candidate_index: int,
                     A_i: int, h_j: int, M_ji: int, a: int, b: int) -> bytes:
    """The exact 2384 bytes of SPEC section 13.2, in order.

    Q is the 32 raw bytes of the base hash, not the group order q.
    They are one letter apart and the type check below is deliberate.
    """
    if not isinstance(Q, (bytes, bytearray)) or len(Q) != 32:
        raise TypeError("Q must be the 32 raw bytes of the base hash, not an int")
    fields = (
        ("label", L(PARTIAL_LABEL)),
        ("Q", bytes(Q)),
        ("trustee_index", U64(trustee_index)),
        ("candidate_index", U64(candidate_index)),
        ("g", I2B(g)),
        ("A_i", I2B(A_i)),
        ("h_j", I2B(h_j)),
        ("M_ji", I2B(M_ji)),
        ("a", I2B(a)),
        ("b", I2B(b)),
    )
    for (want_name, want_len), (got_name, got) in zip(PARTIAL_PREIMAGE_LAYOUT, fields):
        assert want_name == got_name and len(got) == want_len, (
            f"field {got_name} is {len(got)} bytes, SPEC 13.2 says {want_len}"
        )
    preimage = b"".join(value for _, value in fields)
    assert len(preimage) == PARTIAL_PREIMAGE_LEN, (
        f"preimage is {len(preimage)} bytes, SPEC 13.2 says {PARTIAL_PREIMAGE_LEN}. "
        "Find the missing field before doing anything else."
    )
    return preimage


def partial_challenge(**kwargs) -> int:
    """c = B2I(SHA-256(preimage)) mod q, SPEC section 4.

    The reduction is the identity map here, since SHA-256 gives 256 bits and q
    is 3071. It is performed anyway so both implementations do the same thing.
    """
    return B2I(hashlib.sha256(partial_preimage(**kwargs)).digest()) % q


def prove_partial_decryption(*, Q: bytes, trustee_index: int, candidate_index: int,
                             A_i: int, h_j: int, s_j: int, rng):
    """Trustee j proves M_ji = A_i^{s_j} used the share committed in h_j.

    Bases (g, A_i), targets (h_j, M_ji), witness s_j. Returns (M_ji, proof).

    rng is a seeded random.Random (reproducibility). In a real
    deployment w comes from `secrets`; the seeded path exists so that run 4,417
    of 10,000 can be reproduced exactly.
    """
    if not in_group(A_i):
        raise ValueError("A_i is not in the prime-order subgroup")
    if not in_group(h_j):
        raise ValueError("h_j is not in the prime-order subgroup")

    s_j %= q
    if pow(g, s_j, p) != h_j:
        raise ValueError(
            "h_j != g^{s_j}: this share does not match the published commitment"
        )

    M_ji = pow(A_i, s_j, p)
    w = rng.randrange(q)                      # uniform in [0, q), SPEC 13.2
    a = pow(g, w, p)
    b = pow(A_i, w, p)
    c = partial_challenge(Q=Q, trustee_index=trustee_index,
                          candidate_index=candidate_index,
                          A_i=A_i, h_j=h_j, M_ji=M_ji, a=a, b=b)
    f = (w + c * s_j) % q
    return M_ji, CPProof(c=c, f=f, a=a, b=b)


def verify_partial_decryption(*, Q: bytes, trustee_index: int, candidate_index: int,
                              A_i: int, h_j: int, M_ji: int,
                              proof: CPProof) -> CPVerification:
    """SPEC section 13.2 verifier, in order, rejecting on the first failure."""
    for name, val in (("A_i", A_i), ("h_j", h_j), ("M_ji", M_ji),
                      ("a", proof.a), ("b", proof.b)):
        if not in_group(val):
            return CPVerification(False, f"element {name} not in subgroup")
    for name, val in (("c", proof.c), ("f", proof.f)):
        if not 0 <= val < q:
            return CPVerification(False, f"scalar {name} out of range [0, q)")

    expected = partial_challenge(Q=Q, trustee_index=trustee_index,
                                 candidate_index=candidate_index,
                                 A_i=A_i, h_j=h_j, M_ji=M_ji,
                                 a=proof.a, b=proof.b)
    if proof.c != expected:
        return CPVerification(False, "challenge does not match the section 13.2 preimage")

    if pow(g, proof.f, p) != (proof.a * pow(h_j, proof.c, p)) % p:
        return CPVerification(False, "first equation failed: g^f != a * h_j^c")
    if pow(A_i, proof.f, p) != (proof.b * pow(M_ji, proof.c, p)) % p:
        return CPVerification(False, "second equation failed: A_i^f != b * M_ji^c")

    return CPVerification(True, None)


# ---------------------------------------------------------------------------
# Generic core. The caller supplies the preimage, so this module makes no
# hashing decisions of its own.
# ---------------------------------------------------------------------------

def prove(*, preimage_fn, g1: int, h1: int, u: int, v: int, x: int, rng) -> CPProof:
    """Prove log_{g1} u == log_{h1} v == x.

    `preimage_fn(a, b) -> bytes` is supplied by the caller and owns the label
    and the field layout. This module never invents a domain tag: SPEC.md
    defines the preimage per proof instance, not per protocol.
    """
    for name, val in (("g1", g1), ("h1", h1), ("u", u), ("v", v)):
        if not in_group(val):
            raise ValueError(f"element {name} is not in the prime-order subgroup")

    x %= q
    if pow(g1, x, p) != u or pow(h1, x, p) != v:
        raise ValueError("witness does not satisfy the relation")

    w = rng.randrange(q)
    a = pow(g1, w, p)
    b = pow(h1, w, p)
    c = B2I(hashlib.sha256(preimage_fn(a, b)).digest()) % q
    f = (w + c * x) % q
    return CPProof(c=c, f=f, a=a, b=b)


def verify(*, preimage_fn, g1: int, h1: int, u: int, v: int,
           proof: CPProof) -> CPVerification:
    """Check a Chaum-Pedersen equality proof against its statement."""
    for name, val in (("g1", g1), ("h1", h1), ("u", u), ("v", v),
                      ("a", proof.a), ("b", proof.b)):
        if not in_group(val):
            return CPVerification(False, f"element {name} not in subgroup")
    for name, val in (("c", proof.c), ("f", proof.f)):
        if not 0 <= val < q:
            return CPVerification(False, f"scalar {name} out of range [0, q)")

    expected = B2I(hashlib.sha256(preimage_fn(proof.a, proof.b)).digest()) % q
    if proof.c != expected:
        return CPVerification(False, "challenge does not match Fiat-Shamir transcript")

    if pow(g1, proof.f, p) != (proof.a * pow(u, proof.c, p)) % p:
        return CPVerification(False, "first equation failed: g1^f != a * u^c")
    if pow(h1, proof.f, p) != (proof.b * pow(v, proof.c, p)) % p:
        return CPVerification(False, "second equation failed: h1^f != b * v^c")

    return CPVerification(True, None)


def simulate(g1: int, h1: int, u: int, v: int, c: int, f: int) -> CPProof:
    """Special-HVZK simulator: a = g1^f * u^-c, b = h1^f * v^-c.

    Produces a transcript satisfying both verification equations for any (c, f)
    without knowing x. Required for the simulated branches of a disjunctive
    proof. On its own such a transcript does NOT satisfy the Fiat-Shamir check
    and `verify` rejects it -- that is precisely why a standalone CP proof is
    sound.
    """
    c %= q
    f %= q
    a = (pow(g1, f, p) * pow(u, -c, p)) % p
    b = (pow(h1, f, p) * pow(v, -c, p)) % p
    return CPProof(c=c, f=f, a=a, b=b)