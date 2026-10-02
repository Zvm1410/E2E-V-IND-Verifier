"""
threshold.py

Threshold Decryption
SPEC.md Section 13.2 and 13.3
"""

from crypto.group import P as p, Q as q
from crypto.elgamal import homomorphic_sum
from tally.c4 import create_partial_decryption_proof
from crypto.encoding import I2B



def partial_decrypt(A_i: int, share: int) -> int:
    """
    Compute one trustee's partial decryption.

    SPEC 13.2

        M_j,i = A_i ^ s_j mod p
    """

    return pow(A_i, share, p)


def lagrange_coefficient(index, subset):
    """
    Compute the Lagrange coefficient λ_j(S) modulo q.
    """

    numerator = 1
    denominator = 1

    for other in subset:

        if other == index:
            continue

        numerator = (numerator * (-other)) % q
        denominator = (denominator * (index - other)) % q

    denominator_inverse = pow(denominator, -1, q)

    return (numerator * denominator_inverse) % q


def combine_partial_decryptions(partials, subset):
    """
    SPEC 13.3

    combined_i =
        Π M_j,i ^ λ_j(S)

    Parameters
    ----------
    partials : dict[int,int]

        trustee_index -> partial decryption

    subset : list[int]

        trustees participating

    Returns
    -------
    int

        Combined partial decryption.
    """

    combined = 1

    for trustee in subset:

        lam = lagrange_coefficient(
            trustee,
            subset
        )

        combined *= pow(
            partials[trustee],
            lam,
            p
        )

        combined %= p

    return combined


def recover_group_element(
    B_i,
    combined
):
    """
    SPEC 13.3

    g_to_T =
        B_i *
        combined^{-1}

    Returns

        g^T
    """

    inverse = pow(
        combined,
        p - 2,
        p
    )

    return (
        B_i * inverse
    ) % p


def threshold_decrypt(
    aggregate_ciphertext,
    trustee_shares,
    subset
):
    """
    Threshold decryption.

    Parameters
    ----------

    aggregate_ciphertext

        (A_i,B_i)

    trustee_shares

        Dict:
            trustee_index -> share

    subset

        Participating trustees.

    Returns

        g^T
    """

    A_i, B_i = aggregate_ciphertext

    partials = {}
    for trustee in sorted(subset):

        partials[trustee] = partial_decrypt(
            A_i,
            trustee_shares[trustee]
        )

    combined = combine_partial_decryptions(
        partials,
        subset
    )

    g_to_T = recover_group_element(
        B_i,
        combined
    )

    return g_to_T


def aggregate_ciphertexts(ciphertexts):
    """
    Aggregate a list of ciphertexts.

    SPEC 13.1

        A_i = product(alpha)
        B_i = product(beta)

    Returns:
        (A_i, B_i)
    """

    if len(ciphertexts) == 0:
        raise ValueError(
            "No ciphertexts supplied."
        )

    aggregate = homomorphic_sum(ciphertexts)

    return aggregate.alpha, aggregate.beta

def build_decryption_transcript(
    trustee_shares,
    trustee_commitments,
    subset,
    candidate_index,
    aggregate_ciphertext,
    Q,
    rng,
):
    """
    Build the data required for the
    decryption transcript (SPEC 13.4).

    This function does NOT perform the
    final threshold decryption.

    It only prepares the transcript data.
    """

    A_i, _ = aggregate_ciphertext

    lagrange_coefficients = {}

    partials = []

    for trustee in sorted(subset):

        share = trustee_shares[trustee]

        h_j = trustee_commitments[trustee]

        partial, proof = create_partial_decryption_proof(
            Q=Q,
            trustee_index=trustee,
            candidate_index=candidate_index,
            A_i=A_i,
            h_j=h_j,
            share=share,
            rng=rng,
        )

        lagrange_coefficients[
            str(trustee)
        ] = I2B(
            lagrange_coefficient(
             trustee,
             subset,
            )
        ).hex()

        partials.append(
        {
                "trustee_index":
                    trustee,

                "candidate_index":
                    candidate_index,

                "partial":
                    I2B(partial).hex(),

                "proof":
                    proof.to_dict(),
        }
    )

    return {

        "subset":
            sorted(subset),

        "lagrange_coefficients":
            lagrange_coefficients,

        "partials":
            partials,
    }

'''if __name__ == "__main__":

    import random

    from crypto.group import G as g
    from crypto.elgamal import Ciphertext

    # ================================================
    # Test setup
    # ================================================

    Q = bytes(32)

    subset = [1, 2]

    share_1 = 12345
    share_2 = 67890

    trustee_shares = {
        1: share_1,
        2: share_2,
    }

    trustee_commitments = {
        1: pow(g, share_1, p),
        2: pow(g, share_2, p),
    }

    candidate_index = 0

    # ================================================
    # 1. Aggregation
    # ================================================

    ct1 = Ciphertext(
        alpha=pow(g, 111, p),
        beta=pow(g, 222, p),
    )

    ct2 = Ciphertext(
        alpha=pow(g, 333, p),
        beta=pow(g, 444, p),
    )

    aggregate = aggregate_ciphertexts(
        [ct1, ct2]
    )

    print("Aggregation:", aggregate)
    print("Aggregation: PASSED")

    # ================================================
    # 2. Partial decryption
    # ================================================

    A_i, B_i = aggregate

    M1 = partial_decrypt(
        A_i,
        share_1,
    )

    M2 = partial_decrypt(
        A_i,
        share_2,
    )

    assert M1 == pow(A_i, share_1, p)
    assert M2 == pow(A_i, share_2, p)

    print("Partial decryption: PASSED")

    # ================================================
    # 3. Lagrange coefficients
    # ================================================

    lambda_1 = lagrange_coefficient(
        1,
        subset,
    )

    lambda_2 = lagrange_coefficient(
        2,
        subset,
    )

    assert 0 <= lambda_1 < q
    assert 0 <= lambda_2 < q

    print("Lagrange coefficients: PASSED")

    # ================================================
    # 4. Combine partial decryptions
    # ================================================

    partials = {
        1: M1,
        2: M2,
    }

    combined = combine_partial_decryptions(
        partials,
        subset,
    )

    expected = (
        pow(M1, lambda_1, p)
        * pow(M2, lambda_2, p)
    ) % p

    assert combined == expected

    print("Partial combination: PASSED")

    # ================================================
    # 5. Recover g^T
    # ================================================

    g_to_T = recover_group_element(
        B_i,
        combined,
    )

    assert isinstance(g_to_T, int)
    assert 0 <= g_to_T < p

    print("Group element recovery: PASSED")

    # ================================================
    # 6. Complete threshold decryption
    # ================================================

    recovered = threshold_decrypt(
        aggregate,
        trustee_shares,
        subset,
    )

    assert recovered == g_to_T

    print("Threshold decryption: PASSED")

    # ================================================
    # 7. Decryption transcript + Chaum-Pedersen proof
    # ================================================

    rng = random.Random(42)

    transcript = build_decryption_transcript(
        trustee_shares=trustee_shares,
        trustee_commitments=trustee_commitments,
        subset=subset,
        candidate_index=candidate_index,
        aggregate_ciphertext=aggregate,
        Q=Q,
        rng=rng,
    )

    assert transcript["subset"] == [1, 2]

    print("Transcript partials:")
    print(transcript["partials"])
    print("Number of partials:", len(transcript["partials"]))

    assert len(
        transcript["partials"]
    ) == 2

    print("Decryption transcript: PASSED")

    # ================================================
    # 8. Check transcript proof format
    # ================================================

    for entry in transcript["partials"]:

        assert entry["candidate_index"] == 0

        assert len(
            entry["partial"]
        ) == 768

        proof = entry["proof"]

        assert set(proof.keys()) == {
            "c",
            "f",
            "a",
            "b",
        }

        for field in ["c", "f", "a", "b"]:

            assert len(
                proof[field]
            ) == 768

    print("Transcript proof format: PASSED")

    print()
    print("===================================")
    print("ALL THRESHOLD SANITY CHECKS PASSED")
    print("===================================")'''