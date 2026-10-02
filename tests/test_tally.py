"""Aggregation, partial decryption proofs, Lagrange coefficients, tally recovery.

Byte-exact against spec/vectors/decryption.json (including every partial
proof preimage), then on the revision 2 clean and tally-manipulation boards.
"""

import dataclasses
import pathlib
from types import SimpleNamespace

import pytest

from tests.vectors import load
from verifier.group import G, P
from verifier.hashes import partial_preimage
from tests.boards_v2 import parse_v2
from verifier.parse import SumProof, load_json, parse_board
from verifier.result import CheckFailure
from verifier.tally import (
    aggregate,
    check_tally,
    discrete_log_bounded,
    lagrange_coefficient,
    verify_partial,
)

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards-v2"
V = load("decryption.json")
Q_HASH = bytes.fromhex(V["base_hash"])
COMMIT = {c["trustee_index"]: int(c["commitment"], 16) for c in V["trustee_commitments"]}


def _vector_aggregate():
    ballots = [SimpleNamespace(ballot_serial=b["ballot_serial"],
                               ciphertexts=[(int(c["alpha"], 16), int(c["beta"], 16))
                                            for c in b["ciphertexts"]])
               for b in V["ballots"]]
    return aggregate(ballots, set(), 6)


def test_aggregate_matches_vector():
    agg = _vector_aggregate()
    for i, col in enumerate(V["aggregate"]):
        assert agg[i] == (int(col["A"], 16), int(col["B"], 16))


def test_lagrange_coefficients_match_vector():
    for j, value in V["lagrange_coefficients"].items():
        assert lagrange_coefficient(int(j), V["subset"]) == int(value, 16)


def test_partial_proof_preimages_byte_exact_and_valid():
    agg = _vector_aggregate()
    for p in V["partials"]:
        j, i = p["trustee_index"], p["candidate_index"]
        pr = SumProof(*(int(p["proof"][k], 16) for k in ("c", "f", "a", "b")))
        mine = partial_preimage(Q_HASH, j, i, agg[i][0], COMMIT[j], int(p["partial"], 16),
                                pr.a, pr.b)
        assert mine.hex() == p["preimage"], (j, i)
        assert verify_partial(Q_HASH, j, i, agg[i][0], COMMIT[j], int(p["partial"], 16), pr) is None


def test_partial_under_wrong_trustee_index_fails():
    agg = _vector_aggregate()
    p = V["partials"][0]
    pr = SumProof(*(int(p["proof"][k], 16) for k in ("c", "f", "a", "b")))
    assert verify_partial(Q_HASH, 2, 0, agg[0][0], COMMIT[2], int(p["partial"], 16), pr)


def test_tally_recovered_from_vector():
    agg = _vector_aggregate()
    lam = {j: lagrange_coefficient(j, V["subset"]) for j in V["subset"]}
    for decl in V["tally_declaration"]:
        i = decl["candidate_index"]
        combined = 1
        for p in V["partials"]:
            if p["candidate_index"] == i:
                combined = combined * pow(int(p["partial"], 16), lam[p["trustee_index"]], P) % P
        g_to_t = agg[i][1] * pow(combined, -1, P) % P
        assert g_to_t == int(decl["g_to_T"], 16)
        assert discrete_log_bounded(g_to_t, V["ballots_counted"]) == decl["count"]


def test_bsgs_agrees_with_brute_force():
    x = 1
    for t in range(0, 1201):
        assert discrete_log_bounded(x, 1200) == t
        x = x * G % P
    assert discrete_log_bounded(pow(G, 1201, P), 1200) is None


def _board(name):
    return parse_v2(load_json((BOARDS / name / "board.json").read_bytes()))


@pytest.fixture(scope="module")
def clean():
    return _board("clean")


def test_clean_board_tally_verifies(clean):
    check_tally(clean)


def test_tally_manipulation_rejected_as_p5():
    with pytest.raises(CheckFailure) as exc:
        check_tally(_board("tally-manipulation"))
    assert exc.value.prop == "P5"


def test_altered_ciphertext_fails_at_aggregate(clean):
    b = clean.ballots[0]
    cts = list(b.ciphertexts)
    cts[0] = (cts[0][0] * G % P, cts[0][1])
    bad = dataclasses.replace(clean, ballots=(dataclasses.replace(b, ciphertexts=tuple(cts)),
                                             *clean.ballots[1:]))
    with pytest.raises(CheckFailure, match="aggregate"):
        check_tally(bad)


def test_counts_individually_plausible_but_wrong_sum_rejected(clean):
    """Shift one vote between candidates: each count is in range, the sum
    is unchanged, so the per-candidate comparison is what catches it."""
    counts = list(clean.tally_declaration)
    i = counts.index(max(counts))
    counts[i] -= 1
    counts[(i + 2) % len(counts)] += 1
    with pytest.raises(CheckFailure, match="declared"):
        check_tally(dataclasses.replace(clean, tally_declaration=tuple(counts)))


def test_published_lagrange_mismatch_rejected(clean):
    tr = clean.decryption_transcript
    j = tr.subset[0]
    coeffs = {**tr.lagrange_coefficients, j: tr.lagrange_coefficients[j] + 1}
    bad = dataclasses.replace(clean, decryption_transcript=dataclasses.replace(
        tr, lagrange_coefficients=coeffs))
    with pytest.raises(CheckFailure, match="coefficient"):
        check_tally(bad)


def test_partial_from_wrong_share_rejected(clean):
    tr = clean.decryption_transcript
    p0 = tr.partials[0]
    forged = dataclasses.replace(p0, partial=p0.partial * G % P)
    bad = dataclasses.replace(clean, decryption_transcript=dataclasses.replace(
        tr, partials=(forged, *tr.partials[1:])))
    with pytest.raises(CheckFailure, match="partials"):
        check_tally(bad)


def test_declared_candidate_id_must_match_config(clean):
    ids = list(clean.tally_candidate_ids)
    ids[0], ids[1] = ids[1], ids[0]
    with pytest.raises(CheckFailure, match="candidate_id") as exc:
        check_tally(dataclasses.replace(clean, tally_candidate_ids=tuple(ids)))
    assert exc.value.prop == "P5"
