"""Ballot proof verification: validity proofs (SPEC 8.3) and the sum-to-one proof (SPEC 9.3).

Each function raises ProofFailure naming the first check that failed, in
the order SPEC fixes. All values arrive already parsed, so subgroup
membership and the [0, q) range have been enforced once by verifier.parse;
they are re-checked here anyway so these functions are safe on their own.
"""

from verifier.encoding import in_exponent_range, in_group, inv
from verifier.group import G, P, Q
from verifier.hashes import challenge, sumone_preimage, validity_preimage

G_INV = inv(G)


class ProofFailure(Exception):
    def __init__(self, check, reason):
        super().__init__(f"check {check}: {reason}")
        self.check = check
        self.reason = reason


def verify_validity_proof(q_hash, booth_id, serial, candidate_index, pk, alpha, beta, proof):
    """SPEC 8.3, checks 1 to 9 in order, for one candidate position."""
    pr = proof
    for name, x in (("alpha", alpha), ("beta", beta), ("a0", pr.a0), ("b0", pr.b0),
                    ("a1", pr.a1), ("b1", pr.b1)):
        if not in_group(x):
            raise ProofFailure(1, f"{name} not in the subgroup")
    # Ciphertext components only; the identity is legitimate for a0..b1.
    if alpha == 1:
        raise ProofFailure(2, "alpha is 1: encryption randomness was zero, vote is public")
    for name, x in (("c0", pr.c0), ("c1", pr.c1), ("f0", pr.f0), ("f1", pr.f1)):
        if not in_exponent_range(x):
            raise ProofFailure(3, f"{name} outside [0, q)")
    c = challenge(validity_preimage(q_hash, booth_id, serial, candidate_index, pk,
                                    alpha, beta, pr.a0, pr.b0, pr.a1, pr.b1))
    # Check 5 carries soundness: 6-9 all pass for a proof whose two
    # sub-challenges were both chosen freely.
    if (pr.c0 + pr.c1) % Q != c:
        raise ProofFailure(5, "c0 + c1 != c mod q")
    if pow(G, pr.f0, P) != pr.a0 * pow(alpha, pr.c0, P) % P:
        raise ProofFailure(6, "g^f0 != a0 * alpha^c0")
    if pow(pk, pr.f0, P) != pr.b0 * pow(beta, pr.c0, P) % P:
        raise ProofFailure(7, "pk^f0 != b0 * beta^c0")
    if pow(G, pr.f1, P) != pr.a1 * pow(alpha, pr.c1, P) % P:
        raise ProofFailure(8, "g^f1 != a1 * alpha^c1")
    if pow(pk, pr.f1, P) != pr.b1 * pow(beta * G_INV % P, pr.c1, P) % P:
        raise ProofFailure(9, "pk^f1 != b1 * (beta/g)^c1")


def ballot_product(ciphertexts):
    """(A, B/g) recomputed from the ballot's own ciphertexts, never read (SPEC 9.3)."""
    big_a = big_b = 1
    for alpha, beta in ciphertexts:
        big_a = big_a * alpha % P
        big_b = big_b * beta % P
    return big_a, big_b * G_INV % P


def verify_sum_proof(q_hash, booth_id, serial, pk, ciphertexts, proof):
    """SPEC 9.3, checks 1 to 5 in order."""
    big_a, b_over_g = ballot_product(ciphertexts)
    for name, x in (("A", big_a), ("B/g", b_over_g), ("a", proof.a), ("b", proof.b)):
        if not in_group(x):
            raise ProofFailure(1, f"{name} not in the subgroup")
    if not (in_exponent_range(proof.c) and in_exponent_range(proof.f)):
        raise ProofFailure(2, "c or f outside [0, q)")
    c = challenge(sumone_preimage(q_hash, booth_id, serial, pk, big_a, b_over_g,
                                  proof.a, proof.b))
    if proof.c != c:
        raise ProofFailure(3, "recomputed challenge differs")
    if pow(G, proof.f, P) != proof.a * pow(big_a, proof.c, P) % P:
        raise ProofFailure(4, "g^f != a * A^c")
    if pow(pk, proof.f, P) != proof.b * pow(b_over_g, proof.c, P) % P:
        raise ProofFailure(5, "pk^f != b * (B/g)^c")


def verify_ballot(q_hash, pk, ballot):
    """Validity proofs, then the sum proof, for one parsed ballot. Raises ProofFailure with the position."""
    for i, ((alpha, beta), proof) in enumerate(zip(ballot.ciphertexts, ballot.validity_proofs)):
        try:
            verify_validity_proof(q_hash, ballot.booth_id, ballot.ballot_serial, i, pk,
                                  alpha, beta, proof)
        except ProofFailure as exc:
            exc.candidate_index = i
            raise
    verify_sum_proof(q_hash, ballot.booth_id, ballot.ballot_serial, pk,
                     ballot.ciphertexts, ballot.sum_proof)
