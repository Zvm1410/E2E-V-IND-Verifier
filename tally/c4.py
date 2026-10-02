"""
c4.py

Decryption Correctness Proofs
SPEC Section 13.2

Uses the Chaum-Pedersen implementation in crypto/cp_proof.py.
"""

from crypto.cp_proof import (
    CPProof,
    prove_partial_decryption,
    verify_partial_decryption,
)

def create_partial_decryption_proof(
    Q,
    trustee_index,
    candidate_index,
    A_i,
    h_j,
    share,
    rng,
):
    """
    Create a Chaum-Pedersen proof that the
    partial decryption was computed using the
    trustee's committed share.

    Returns:
        M_ji, proof
    """

    M_ji, proof = prove_partial_decryption(
        Q=Q,
        trustee_index=trustee_index,
        candidate_index=candidate_index,
        A_i=A_i,
        h_j=h_j,
        s_j=share,
        rng=rng,
    )

    return M_ji, proof


def verify_partial_decryption_proof(
    Q,
    trustee_index,
    candidate_index,
    A_i,
    h_j,
    M_ji,
    proof,
):
    """
    Verify a trustee's partial decryption proof.
    """

    return verify_partial_decryption(
        Q=Q,
        trustee_index=trustee_index,
        candidate_index=candidate_index,
        A_i=A_i,
        h_j=h_j,
        M_ji=M_ji,
        proof=proof,
    )

'''if __name__ == "__main__":

    import random
    from group import P as p, Q as q, G as g

    # -------------------------------------------------
    # Test values
    # -------------------------------------------------

    Q = bytes(32)

    trustee_index = 1
    candidate_index = 0

    share = 12345

    # Published trustee commitment
    h_j = pow(g, share, p)

    # Test A_i
    A_i = pow(g, 67890, p)

    # Deterministic RNG
    rng = random.Random(42)

    # -------------------------------------------------
    # 1. Honest proof
    # -------------------------------------------------

    M_ji, proof = create_partial_decryption_proof(
        Q=Q,
        trustee_index=trustee_index,
        candidate_index=candidate_index,
        A_i=A_i,
        h_j=h_j,
        share=share,
        rng=rng,
    )

    result = verify_partial_decryption_proof(
        Q=Q,
        trustee_index=trustee_index,
        candidate_index=candidate_index,
        A_i=A_i,
        h_j=h_j,
        M_ji=M_ji,
        proof=proof,
    )

    print("Honest proof:", bool(result))

    assert bool(result) is True

    # -------------------------------------------------
    # 2. Wrong share
    # -------------------------------------------------

    try:

        create_partial_decryption_proof(
            Q=Q,
            trustee_index=trustee_index,
            candidate_index=candidate_index,
            A_i=A_i,
            h_j=h_j,
            share=share + 1,
            rng=random.Random(42),
        )

        print("Wrong share: FAILED")

    except ValueError:

        print("Wrong share: PASSED")

    # -------------------------------------------------
    # 3. Wrong trustee index
    # -------------------------------------------------

    result = verify_partial_decryption_proof(
        Q=Q,
        trustee_index=trustee_index + 1,
        candidate_index=candidate_index,
        A_i=A_i,
        h_j=h_j,
        M_ji=M_ji,
        proof=proof,
    )

    print("Wrong trustee index:", bool(result))

    assert bool(result) is False

    print("\nAll decryption-proof sanity checks passed.")'''