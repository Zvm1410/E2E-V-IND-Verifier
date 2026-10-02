"""B7b. Sum-to-one proof.

SPEC.md v1 revision 2, section 9. Basket B.

WHAT THIS CLOSES (the one sentence for the viva):
    The m per-candidate validity proofs of B7 establish that every entry of
    the ballot vector is 0 or 1. They say nothing about how many entries are
    1, so a ballot of all ones passes all m of them and casts m votes. This
    proof binds the componentwise product of the ballot's own ciphertexts to
    an encryption of exactly 1. Without it the ballot is unconstrained in
    weight and the tally is meaningless.

    B7b alone proves sum == 1 (mod q). The range 0 <= sum <= m comes from
    B7. Neither is sufficient without the other; that is why both exist.

SCOPE. This is ONE proof per ballot, not one per candidate. "Applied per
candidate" belongs to B7. There is exactly one sum_proof object in the B3c
ballot record shape.

DEPENDENCIES. B2 (group), B3 (encoding), B3b (membership). Not B7.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# ADAPT THIS BLOCK to the module names in your BasketB folder.
# Do not re-implement these here. Two encoders in one project is the exact
# failure mode SPEC section 3 and handbook section 2.3 exist to prevent.
# --------------------------------------------------------------------------
from group import P as p, Q as q, G as g        # B2, SPEC section 2
from encoding import I2B, B2I, U64, S32, L      # B3, SPEC section 3
from membership import in_group                 # B3b, SPEC section 2.1


SUMONE_LABEL = "EVOTE-SUMONE-v1"

#: SPEC section 9.2. 32 + 32 + 32 + 8 + 6 * 384.
SUMONE_PREIMAGE_LEN = 2408

#: SPEC section 3.5. Hex width of a HEX384 JSON field.
HEX384_CHARS = 768

#: Field layout of the section 9.2 preimage, in order, as (name, length).
#: Exposed so that a failing test can name the offset of the first wrong byte
#: rather than printing 2408 bytes of hex and hoping.
SUMONE_PREIMAGE_LAYOUT: Tuple[Tuple[str, int], ...] = (
    ("label", 32),
    ("Q", 32),
    ("booth_id", 32),
    ("ballot_serial", 8),
    ("g", 384),
    ("pk", 384),
    ("A", 384),
    ("B_over_g", 384),
    ("a", 384),
    ("b", 384),
)


class SumToOneError(ValueError):
    """The prover was handed inputs it cannot honestly prove."""


@dataclass(frozen=True)
class SumProof:
    """The published sum-to-one proof: (c, f, a, b), SPEC section 9.1.

    c is redundant given the preimage and is published anyway, for the same
    reason c_1 is published in section 8: the verifier recomputes it and
    compares, so a mismatch surfaces as a named failure instead of being
    silently absorbed.
    """

    c: int
    f: int
    a: int
    b: int

    def to_json(self) -> dict:
        """The sum_proof object of the B3c ballot record shape."""
        return {
            "c": I2B(self.c).hex(),
            "f": I2B(self.f).hex(),
            "a": I2B(self.a).hex(),
            "b": I2B(self.b).hex(),
        }

    @classmethod
    def from_json(cls, obj: dict) -> "SumProof":
        """Parse with the strictness SPEC section 3.5 requires.

        A parser that is lenient about hex width is a verifier that can be
        walked past, so B is strict about its own output too: this is what
        makes the serialise/parse/serialise round trip a real test.
        """
        missing = {"c", "f", "a", "b"} - set(obj)
        if missing:
            raise ValueError(f"sum_proof missing field(s): {sorted(missing)}")
        extra = set(obj) - {"c", "f", "a", "b"}
        if extra:
            raise ValueError(f"sum_proof has unexpected field(s): {sorted(extra)}")
        values = {}
        for name in ("c", "f", "a", "b"):
            raw = obj[name]
            if not isinstance(raw, str):
                raise ValueError(f"sum_proof.{name} must be a HEX384 string, not a JSON number")
            if len(raw) != HEX384_CHARS:
                raise ValueError(
                    f"sum_proof.{name} is {len(raw)} hex chars, must be exactly {HEX384_CHARS}"
                )
            if raw != raw.lower():
                raise ValueError(f"sum_proof.{name} must be lowercase hex")
            values[name] = B2I(bytes.fromhex(raw))
        return cls(**values)


@dataclass(frozen=True)
class VerifyResult:
    """Verification outcome plus the reason, for D7 property attribution.

    A sum-to-one failure attributes to P2, ballot well-formedness.
    """

    ok: bool
    reason: Optional[str] = None
    check: Optional[int] = None  # which numbered check of SPEC 9.3 failed

    def __bool__(self) -> bool:
        return self.ok


def _as_pairs(ciphertexts: Iterable) -> Sequence[Tuple[int, int]]:
    """Accept either B3c record dicts or plain (alpha, beta) tuples.

    Order is the caller's responsibility: it is the configuration order and
    B3c requires candidate_index ascending with no gaps. Where dicts carry
    candidate_index, the order is asserted here rather than trusted, because
    A and C both build this list independently.
    """
    pairs, seen = [], []
    for i, ct in enumerate(ciphertexts):
        if isinstance(ct, dict):
            alpha, beta = ct["alpha"], ct["beta"]
            if isinstance(alpha, str):
                alpha, beta = B2I(bytes.fromhex(alpha)), B2I(bytes.fromhex(beta))
            idx = ct.get("candidate_index", i)
            seen.append(idx)
        else:
            alpha, beta = ct
            seen.append(i)
        pairs.append((int(alpha), int(beta)))
    if seen != list(range(len(pairs))):
        raise ValueError(
            f"ciphertexts must be candidate_index 0..m-1 ascending with no gaps, got {seen}"
        )
    if not pairs:
        raise ValueError("ballot has no ciphertexts")
    return pairs


def ballot_targets(ciphertexts: Iterable) -> Tuple[int, int]:
    """Return (A, B_over_g), SPEC section 9.

    A = prod(alpha_i) mod p, B = prod(beta_i) mod p, B_over_g = B * g^-1 mod p.

    The verifier calls this on the ballot's OWN ciphertexts and never reads a
    published aggregate. Reading one would let a machine publish a truthful
    looking aggregate next to a ballot that does not produce it.
    """
    pairs = _as_pairs(ciphertexts)
    A, B = 1, 1
    for alpha, beta in pairs:
        A = A * alpha % p
        B = B * beta % p
    return A, B * pow(g, -1, p) % p


def sumone_preimage(*, Q: bytes, booth_id: str, ballot_serial: int, pk: int,
                    A: int, B_over_g: int, a: int, b: int) -> bytes:
    """The exact 2408 bytes of SPEC section 9.2, in order.

    Q is the 32 raw bytes of the base hash from B4b, not the group order q.
    They are one letter apart and the type check below is deliberate.
    """
    if not isinstance(Q, (bytes, bytearray)) or len(Q) != 32:
        raise TypeError("Q must be the 32 raw bytes of the base hash (B4b), not an int")
    fields = (
        ("label", L(SUMONE_LABEL)),
        ("Q", bytes(Q)),
        ("booth_id", S32(booth_id)),
        ("ballot_serial", U64(ballot_serial)),
        ("g", I2B(g)),
        ("pk", I2B(pk)),
        ("A", I2B(A)),
        ("B_over_g", I2B(B_over_g)),
        ("a", I2B(a)),
        ("b", I2B(b)),
    )
    for (want_name, want_len), (got_name, got) in zip(SUMONE_PREIMAGE_LAYOUT, fields):
        assert want_name == got_name and len(got) == want_len, (
            f"field {got_name} is {len(got)} bytes, SPEC 9.2 says {want_len}"
        )
    preimage = b"".join(value for _, value in fields)
    assert len(preimage) == SUMONE_PREIMAGE_LEN, (
        f"preimage is {len(preimage)} bytes, SPEC 9.2 says {SUMONE_PREIMAGE_LEN}. "
        "Find the missing field before doing anything else."
    )
    return preimage


def sumone_challenge(**kwargs) -> int:
    """c = B2I(SHA-256(preimage)) mod q, SPEC section 4.

    The reduction is the identity map here, since SHA-256 gives 256 bits and
    q is 3071. It is performed anyway so both implementations do the same
    thing, per section 4.
    """
    return B2I(hashlib.sha256(sumone_preimage(**kwargs)).digest()) % q


def prove_sum_to_one(*, Q: bytes, booth_id: str, ballot_serial: int, pk: int,
                     ciphertexts: Iterable, r_vector: Sequence[int], rng,
                     check_consistency: bool = True) -> SumProof:
    """Chaum-Pedersen proof that the ballot's ciphertext product encrypts 1.

    rng is a seeded random.Random, per handbook section 1.5. In a real
    deployment w comes from `secrets`; the seeded path exists so that run
    4,417 of 10,000 can be reproduced exactly.

    check_consistency=True catches the caller bug where r_vector does not
    match the ciphertexts it was supposedly used to build, which otherwise
    surfaces three layers away as an unverifiable board. B12's malformed
    ballot injection passes False on purpose.
    """
    pairs = _as_pairs(ciphertexts)
    if len(r_vector) != len(pairs):
        raise ValueError(
            f"r_vector has {len(r_vector)} entries, ballot has {len(pairs)} ciphertexts"
        )
    R = sum(r_vector) % q
    A, B_over_g = ballot_targets(pairs)

    if check_consistency:
        if pow(g, R, p) != A:
            raise SumToOneError(
                "A != g^R: r_vector does not match these ciphertexts"
            )
        if pow(pk, R, p) != B_over_g:
            raise SumToOneError(
                "B*g^-1 != pk^R: this ballot does not encrypt exactly one 1. "
                "Pass check_consistency=False if you are deliberately building "
                "a malformed ballot for B12."
            )

    w = rng.randrange(q)                      # uniform in [0, q), SPEC 9.1
    a = pow(g, w, p)
    b = pow(pk, w, p)
    c = sumone_challenge(Q=Q, booth_id=booth_id, ballot_serial=ballot_serial,
                         pk=pk, A=A, B_over_g=B_over_g, a=a, b=b)
    f = (w + c * R) % q
    return SumProof(c=c, f=f, a=a, b=b)


def verify_sum_to_one(*, Q: bytes, booth_id: str, ballot_serial: int, pk: int,
                      ciphertexts: Iterable, proof: SumProof) -> VerifyResult:
    """SPEC section 9.3, in order, rejecting on the first failure.

    The order is load bearing. Membership before arithmetic, because an
    element outside G breaks the soundness argument rather than merely
    failing an equation.
    """
    A, B_over_g = ballot_targets(ciphertexts)

    # 1. in_group on A, B_over_g, a, b.
    for name, value in (("A", A), ("B_over_g", B_over_g),
                        ("a", proof.a), ("b", proof.b)):
        if not in_group(value):
            return VerifyResult(False, f"{name} is not in G (SPEC 2.1)", 1)

    # 2. Range check on the exponents.
    for name, value in (("c", proof.c), ("f", proof.f)):
        if not 0 <= value < q:
            return VerifyResult(False, f"{name} outside [0, q) (SPEC 2.1)", 2)

    # 3. Recompute the challenge.
    c = sumone_challenge(Q=Q, booth_id=booth_id, ballot_serial=ballot_serial,
                         pk=pk, A=A, B_over_g=B_over_g, a=proof.a, b=proof.b)
    if c != proof.c:
        return VerifyResult(False, "recomputed challenge does not match published c", 3)

    # 4. g^f == a * A^c mod p
    if pow(g, proof.f, p) != proof.a * pow(A, c, p) % p:
        return VerifyResult(False, "g^f != a * A^c", 4)

    # 5. pk^f == b * B_over_g^c mod p
    if pow(pk, proof.f, p) != proof.b * pow(B_over_g, c, p) % p:
        return VerifyResult(False, "pk^f != b * (B*g^-1)^c", 5)

    return VerifyResult(True)
