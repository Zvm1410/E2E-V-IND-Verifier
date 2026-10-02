"""Aggregation and decryption transcript verification (SPEC 13, P5)."""

from math import isqrt

from verifier.encoding import in_exponent_range, in_group, inv
from verifier.group import G, P, Q
from verifier.hashes import challenge, partial_preimage
from verifier.result import CheckFailure


def aggregate(ballots, spoiled_serials, m):
    """SPEC 13.1: per-candidate componentwise product over unspoiled ballots."""
    agg = [[1, 1] for _ in range(m)]
    for ballot in ballots:
        if ballot.ballot_serial in spoiled_serials:
            continue
        for i, (alpha, beta) in enumerate(ballot.ciphertexts):
            agg[i][0] = agg[i][0] * alpha % P
            agg[i][1] = agg[i][1] * beta % P
    return [tuple(x) for x in agg]


def lagrange_coefficient(j, subset):
    """SPEC 6: lambda_j(S) = prod_{i in S, i != j} i / (i - j) mod q."""
    num = den = 1
    for i in subset:
        if i != j:
            num = num * i % Q
            den = den * (i - j) % Q
    return num * pow(den, -1, Q) % Q


def verify_partial(q_hash, trustee_index, candidate_index, big_a, h_j, partial, proof):
    """SPEC 13.2 Chaum-Pedersen check. Returns a reason string, or None if valid."""
    for x in (big_a, h_j, partial, proof.a, proof.b):
        if not in_group(x):
            return "element not in the subgroup"
    if not (in_exponent_range(proof.c) and in_exponent_range(proof.f)):
        return "c or f outside [0, q)"
    c = challenge(partial_preimage(q_hash, trustee_index, candidate_index, big_a, h_j,
                                   partial, proof.a, proof.b))
    if proof.c != c:
        return "recomputed challenge differs"
    if pow(G, proof.f, P) != proof.a * pow(h_j, proof.c, P) % P:
        return "g^f != a * h_j^c"
    if pow(big_a, proof.f, P) != proof.b * pow(partial, proof.c, P) % P:
        return "A^f != b * M^c"
    return None


def discrete_log_bounded(target, bound):
    """Baby-step giant-step for T in [0, bound] with g^T = target. None if absent."""
    step = isqrt(bound) + 1
    baby = {}
    x = 1
    for j in range(step):
        baby.setdefault(x, j)
        x = x * G % P
    giant = pow(inv(G), step, P)
    y = target
    for i in range(step + 1):
        if y in baby:
            t = i * step + baby[y]
            return t if t <= bound else None
        y = y * giant % P
    return None


def check_tally(board):
    """P5: aggregates, partial proofs, Lagrange coefficients, combination,
    declared tally, and the tally summing to ballots_counted."""
    m = board.config.m
    spoiled = {s.ballot_serial for s in board.spoils}
    agg = aggregate(board.ballots, spoiled, m)
    for i, (mine, published) in enumerate(zip(agg, board.tally_aggregate)):
        if mine != published:
            raise CheckFailure("P5", f"tally_aggregate.columns[{i}]",
                               "published aggregate does not recompute from the ciphertexts")

    expected_ids = tuple(c.candidate_id for c in board.config.candidates)
    if board.tally_candidate_ids != expected_ids:
        raise CheckFailure("P5", "tally_declaration.totals",
                           "candidate_id does not match the configuration at that index")

    tr = board.decryption_transcript
    for j in tr.subset:
        if tr.lagrange_coefficients[j] != lagrange_coefficient(j, tr.subset):
            raise CheckFailure("P5", f"decryption_transcript.lagrange_coefficients.{j}",
                               "published coefficient does not recompute")

    commitments = board.trustee_setup.commitments
    combined = [1] * m
    for p in tr.partials:
        big_a = agg[p.candidate_index][0]
        reason = verify_partial(board.base_hash, p.trustee_index, p.candidate_index, big_a,
                                commitments[p.trustee_index - 1], p.partial, p.proof)
        if reason:
            raise CheckFailure("P5", f"decryption_transcript.partials[trustee {p.trustee_index}, "
                                     f"candidate {p.candidate_index}]", reason)
        lam = lagrange_coefficient(p.trustee_index, tr.subset)
        combined[p.candidate_index] = combined[p.candidate_index] * pow(p.partial, lam, P) % P

    counted = board.poll_register.ballots_counted
    for i in range(m):
        g_to_t = agg[i][1] * inv(combined[i]) % P
        t = discrete_log_bounded(g_to_t, counted)
        if t is None:
            raise CheckFailure("P5", f"tally candidate {i}",
                               f"decrypted value is not g^T for any T in [0, {counted}]")
        if t != board.tally_declaration[i]:
            raise CheckFailure("P5", f"tally_declaration.counts[{i}]",
                               f"declared {board.tally_declaration[i]}, ciphertexts give {t}")
    if sum(board.tally_declaration) != counted:
        raise CheckFailure("P5", "tally_declaration",
                           f"counts sum to {sum(board.tally_declaration)}, not ballots_counted {counted}")
