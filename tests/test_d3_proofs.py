"""D3 and D3b: validity and sum-to-one proofs (SPEC 8.3, 9.3).

Run against the real ballots on C's clean board, which carry B's proofs.
Kept to ballot 1 for the mutation tests; each check costs a few 3072-bit
exponentiations.
"""

import dataclasses
import pathlib
import random

import pytest

from verifier.encoding import inv
from verifier.group import G, P, Q
from tests.legacy import parse_legacy
from verifier.parse import load_json, parse_board
from verifier.proofs import (
    ProofFailure,
    verify_ballot,
    verify_sum_proof,
    verify_validity_proof,
)

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"


@pytest.fixture(scope="module")
def board():
    raw = load_json((BOARDS / "clean" / "board.json").read_bytes())
    return parse_legacy(raw)


def _check(board, ballot, i, proof=None, serial=None, booth=None, index=None, ct=None):
    alpha, beta = ct or ballot.ciphertexts[i]
    verify_validity_proof(board.base_hash, booth or ballot.booth_id,
                          serial or ballot.ballot_serial, i if index is None else index,
                          board.trustee_setup.public_key, alpha, beta,
                          proof or ballot.validity_proofs[i])


def test_every_ballot_on_clean_board_verifies(board):
    for ballot in board.ballots:
        verify_ballot(board.base_hash, board.trustee_setup.public_key, ballot)


@pytest.mark.parametrize("field", ["c0", "c1", "f0", "f1", "a0", "b0", "a1", "b1"])
def test_mutating_any_proof_value_is_rejected(board, field):
    ballot = board.ballots[0]
    proof = ballot.validity_proofs[0]
    value = getattr(proof, field)
    # Exponents: flip the low bit. Elements: multiply by g, staying in G.
    mutated = value ^ 1 if field[0] in "cf" else value * G % P
    with pytest.raises(ProofFailure):
        _check(board, ballot, 0, proof=dataclasses.replace(proof, **{field: mutated}))


def test_proof_moved_to_another_candidate_index_fails(board):
    with pytest.raises(ProofFailure, match="check 5"):
        _check(board, board.ballots[0], 0, index=1)


def test_proof_moved_to_another_serial_fails(board):
    with pytest.raises(ProofFailure, match="check 5"):
        _check(board, board.ballots[0], 0, serial=99)


def test_proof_moved_to_another_booth_fails(board):
    with pytest.raises(ProofFailure, match="check 5"):
        _check(board, board.ballots[0], 0, booth="BOOTH-002")


def test_alpha_one_rejected_at_check_2(board):
    ballot = board.ballots[0]
    with pytest.raises(ProofFailure, match="check 2"):
        _check(board, ballot, 0, ct=(1, ballot.ciphertexts[0][1]))


def test_forgery_with_both_subchallenges_free_is_caught_only_by_check_5(board):
    """Choose c0, c1, f0, f1 freely and solve for the commitments. Equations
    6 to 9 then hold by construction, for a ciphertext of any value; only
    the sub-challenge sum stops it."""
    ballot = board.ballots[0]
    pk = board.trustee_setup.public_key
    alpha, beta = ballot.ciphertexts[0]
    beta = beta * G % P  # now encrypts v + 1, i.e. 1 or 2
    rng = random.Random(7)
    c0, c1, f0, f1 = (rng.randrange(Q) for _ in range(4))
    a0 = pow(G, f0, P) * pow(alpha, -c0, P) % P
    b0 = pow(pk, f0, P) * pow(beta, -c0, P) % P
    a1 = pow(G, f1, P) * pow(alpha, -c1, P) % P
    b1 = pow(pk, f1, P) * pow(beta * inv(G) % P, -c1, P) % P
    forged = dataclasses.replace(ballot.validity_proofs[0], c0=c0, c1=c1, f0=f0, f1=f1,
                                 a0=a0, b0=b0, a1=a1, b1=b1)
    assert pow(G, f0, P) == a0 * pow(alpha, c0, P) % P  # check 6 would pass
    assert pow(pk, f1, P) == b1 * pow(beta * inv(G) % P, c1, P) % P  # check 9 would pass
    with pytest.raises(ProofFailure, match="check 5"):
        _check(board, ballot, 0, proof=forged, ct=(alpha, beta))


def test_sum_proof_bound_to_ballot_product(board):
    """A ballot whose product encrypts 2 (an extra factor g in one beta)
    must fail the sum proof, since A and B/g are recomputed, never read."""
    ballot = board.ballots[0]
    cts = list(ballot.ciphertexts)
    cts[3] = (cts[3][0], cts[3][1] * G % P)
    with pytest.raises(ProofFailure):
        verify_sum_proof(board.base_hash, ballot.booth_id, ballot.ballot_serial,
                         board.trustee_setup.public_key, cts, ballot.sum_proof)


def test_sum_proof_mutation_rejected(board):
    ballot = board.ballots[0]
    bad = dataclasses.replace(ballot.sum_proof, f=ballot.sum_proof.f ^ 1)
    with pytest.raises(ProofFailure):
        verify_sum_proof(board.base_hash, ballot.booth_id, ballot.ballot_serial,
                         board.trustee_setup.public_key, ballot.ciphertexts, bad)
