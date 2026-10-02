"""
B8b. encrypt_and_prove -- the assembly.

Basket B. This file owns no mathematics. It wires B4 (elgamal), B7
(validity_proof), B7b (sumone) and B8's binding into the single function basket
A calls, and returns the three structures record.build_ballot_record consumes.

It does not draw encryption randomness. The vector is drawn and committed before
the poll opens (A7b, SPEC section 10.1) and passed in. If this function ever
draws r itself the pre-poll commitment is decorative and the attack it exists to
catch walks straight through, so there is an explicit assertion below that
elgamal.encrypt_selection used the vector it was handed.

It does not write to the board and it does not build the record. A calls
record.build_ballot_record on the returned triple, or C does.

NAMING WARNING
    group.py exports the subgroup order as `Q`. The base hash of SPEC section
    5.2 is also called `Q`. They are different objects and Python will not warn
    you. This module imports the group order as lowercase `q` so that the
    parameter `Q` can only ever mean the base hash.

DETERMINISM
    The order of draws from `rng` is part of the interface because the test
    vectors depend on it: prove_validity m times in ascending candidate index,
    then prove_sum_to_one once. encrypt_selection draws nothing when randomness
    is supplied. Do not reorder.
"""

from __future__ import annotations

from typing import Any, List, Sequence, Tuple

from group import P as p, Q as q, G as g
from membership import in_group
from elgamal import encrypt_selection
from validity_proof import ValidityProof, prove_validity
from sumone import SumProof, prove_sum_to_one
from record import Ciphertext

__all__ = ["encrypt_and_prove"]

_MAX_U64 = 1 << 64


def _validate_inputs(candidate_index, r_vector, Q, booth_id, ballot_serial, pk, m) -> None:
    if not isinstance(m, int) or m < 2:
        raise ValueError(f"m must be an integer >= 2, got {m!r}")

    if not isinstance(candidate_index, int) or isinstance(candidate_index, bool):
        raise TypeError(f"candidate_index must be an int, got {type(candidate_index).__name__}")
    if not 0 <= candidate_index < m:
        raise ValueError(f"candidate_index {candidate_index} outside [0, {m})")

    if len(r_vector) != m:
        raise ValueError(f"r_vector has length {len(r_vector)}, expected exactly m = {m}")

    # SPEC section 7 and change log item 4. r_i is drawn from [1, q), never
    # [0, q). At r_i = 0 the ciphertext is (1, g^{v_i}) and the vote is readable
    # off the board by anyone with no key. A7b draws it; this is the second gate.
    for i, r in enumerate(r_vector):
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError(f"r_vector[{i}] must be an int, got {type(r).__name__}")
        if not 1 <= r < q:
            raise ValueError(
                f"r_vector[{i}] outside [1, q). Zero randomness publishes the vote "
                f"in clear; see SPEC section 7."
            )

    if not isinstance(Q, (bytes, bytearray)) or len(Q) != 32:
        raise ValueError("Q must be the 32 raw bytes of the base hash (SPEC section 5.2)")

    if not booth_id.isascii():
        raise ValueError("booth_id must be ASCII (SPEC section 3.3)")
    if len(booth_id.encode("utf-8")) > 32:
        raise ValueError("booth_id encodes to more than 32 bytes")

    if not isinstance(ballot_serial, int) or isinstance(ballot_serial, bool):
        raise TypeError("ballot_serial must be an int")
    if not 1 <= ballot_serial < _MAX_U64:
        raise ValueError(f"ballot_serial {ballot_serial} outside [1, 2^64); serials start at 1")

    if not in_group(pk):
        raise ValueError("pk is not a member of G")
    if pk == 1:
        raise ValueError("pk is the identity; sk = 0 and every ciphertext is public")


def encrypt_and_prove(
    candidate_index: int,
    r_vector: Sequence[int],
    Q: bytes,
    booth_id: str,
    ballot_serial: int,
    pk: int,
    m: int,
    rng: Any,
    *,
    self_check: bool = False,
) -> Tuple[List[Ciphertext], List[ValidityProof], SumProof]:
    """Encrypt a vote for `candidate_index` and prove it well formed.

    The positional signature is the one agreed with basket A in A5 and fixed in
    handbook revision 3. `self_check` is keyword-only and defaults off, so A's
    call site is unaffected by its existence.

    Returns (ciphertexts, validity_proofs, sum_proof). The first two have length
    exactly m, ordered by candidate_index ascending with no gaps. Hand the triple
    to record.build_ballot_record for the SPEC section 14 board record.

    `self_check` re-verifies everything before returning, at roughly another 52
    exponentiations. It is a post-condition, not a test: a prover and a verifier
    wrong in the same way both pass it. See handbook section 2.5.
    """
    _validate_inputs(candidate_index, r_vector, Q, booth_id, ballot_serial, pk, m)
    r_list = list(r_vector)

    # --- B4. Encryption. Draws nothing; randomness is supplied. -----------
    raw_cts, used_r = encrypt_selection(pk, m, candidate_index, randomness=r_list)

    # A7b is the reason this assertion exists. If encrypt_selection ever
    # substitutes its own randomness, the pre-poll commitment stops opening
    # against the cast ballot and D6 fails at every challenged ballot for a
    # reason nobody will be able to find from the verifier's output.
    if list(used_r) != r_list:
        raise AssertionError(
            "encrypt_selection did not use the supplied randomness vector; the "
            "pre-poll commitment of A7b would not open against this ballot"
        )
    if len(raw_cts) != m:
        raise AssertionError(f"encrypt_selection returned {len(raw_cts)} ciphertexts, expected {m}")

    ciphertexts: List[Ciphertext] = []
    for i, ct in enumerate(raw_cts):
        # Follows from r_i >= 1, but SPEC 8.3 check 2 rejects alpha = 1 at the
        # verifier and failing here beats publishing it.
        if ct.alpha == 1:
            raise AssertionError(f"alpha is the identity at candidate index {i}")
        ciphertexts.append(Ciphertext(candidate_index=i, alpha=ct.alpha, beta=ct.beta))

    # --- B7 + B8. One two-branch OR-proof per position. -------------------
    # Ascending candidate index. The index is bound into each challenge
    # (SPEC 8.2), so this ordering is load-bearing, not cosmetic.
    validity_proofs: List[ValidityProof] = []
    for i in range(m):
        validity_proofs.append(
            prove_validity(
                v=1 if i == candidate_index else 0,
                r=r_list[i],
                alpha=ciphertexts[i].alpha,
                beta=ciphertexts[i].beta,
                pk=pk,
                Q=Q,
                booth_id=booth_id,
                ballot_serial=ballot_serial,
                candidate_index=i,
                rng=rng,
            )
        )

    # --- B7b. One sum-to-one proof over the whole vector. -----------------
    # sumone._as_pairs accepts B3c record dicts or plain (alpha, beta) tuples,
    # not record.Ciphertext instances. The dict form is used rather than tuples
    # because it carries candidate_index, so _as_pairs asserts the ordering
    # instead of trusting it.
    sum_proof = prove_sum_to_one(
        Q=Q,
        booth_id=booth_id,
        ballot_serial=ballot_serial,
        pk=pk,
        ciphertexts=[
            {"candidate_index": ct.candidate_index, "alpha": ct.alpha, "beta": ct.beta}
            for ct in ciphertexts
        ],
        r_vector=r_list,
        rng=rng,
    )

    if self_check:
        _post_conditions(ciphertexts, validity_proofs, sum_proof, pk, m)

    return ciphertexts, validity_proofs, sum_proof


def _post_conditions(ciphertexts, validity_proofs, sum_proof, pk, m) -> None:
    """Structural post-conditions plus the equations of SPEC 8.3 and 9.3.

    Deliberately does not call validity_proof.verify_validity or
    sumone.verify_sum_to_one: re-stating the equations here means a bug shared
    between a prover and its own verifier does not pass silently. Still weaker
    than a vector check.
    """
    assert len(ciphertexts) == m, f"expected {m} ciphertexts, got {len(ciphertexts)}"
    assert len(validity_proofs) == m, f"expected {m} validity proofs, got {len(validity_proofs)}"
    assert [c.candidate_index for c in ciphertexts] == list(range(m))
    assert [v.candidate_index for v in validity_proofs] == list(range(m))

    g_inv = pow(g, -1, p)
    A, B = 1, 1
    for ct, pr in zip(ciphertexts, validity_proofs):
        A = (A * ct.alpha) % p
        B = (B * ct.beta) % p
        for x in (ct.alpha, ct.beta, pr.a0, pr.b0, pr.a1, pr.b1):
            assert in_group(x), f"element outside G at candidate index {ct.candidate_index}"
        assert ct.alpha != 1
        for e in (pr.c0, pr.c1, pr.f0, pr.f1):
            assert 0 <= e < q
        assert pow(g, pr.f0, p) == (pr.a0 * pow(ct.alpha, pr.c0, p)) % p
        assert pow(pk, pr.f0, p) == (pr.b0 * pow(ct.beta, pr.c0, p)) % p
        assert pow(g, pr.f1, p) == (pr.a1 * pow(ct.alpha, pr.c1, p)) % p
        assert pow(pk, pr.f1, p) == (pr.b1 * pow((ct.beta * g_inv) % p, pr.c1, p)) % p

    B_over_g = (B * g_inv) % p
    for x in (sum_proof.a, sum_proof.b):
        assert in_group(x)
    for e in (sum_proof.c, sum_proof.f):
        assert 0 <= e < q
    assert pow(g, sum_proof.f, p) == (sum_proof.a * pow(A, sum_proof.c, p)) % p
    assert pow(pk, sum_proof.f, p) == (sum_proof.b * pow(B_over_g, sum_proof.c, p)) % p
