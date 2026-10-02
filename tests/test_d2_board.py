"""D2: the whole-board parser against C's exported clean board.

C's board differs from SPEC section 14 in four places (listed in
KNOWN_DEVIATIONS). The verifier follows SPEC.md, so the raw board is
rejected until either C's export or SPEC.md changes. The second test
applies exactly those four changes and confirms nothing else differs.
"""

import copy
import pathlib

import pytest

from verifier.hashes import base_hash
from verifier.parse import ParseError, load_json, parse_board

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"

KNOWN_DEVIATIONS = """
election_config has no "seed" (SPEC 14 says the 5.1 config verbatim);
trustee_setup uses "pk" not "public_key" and has no "record_type";
prepoll randomness_commitments carry an extra "nonce_commitment";
tally_declaration uses "totals"/"votes"/"candidate_id" not "counts"/"count".
"""


def _clean():
    return load_json((BOARDS / "clean" / "board.json").read_bytes())


def _apply_known_deviations(board):
    b = copy.deepcopy(board)
    b["election_config"]["seed"] = 0
    ts = b["trustee_setup"]
    ts["public_key"] = ts.pop("pk")
    ts["record_type"] = "trustee_setup"
    for r in b["prepoll"]["randomness_commitments"]:
        r.pop("nonce_commitment")
    totals = b["tally_declaration"].pop("totals")
    b["tally_declaration"]["counts"] = [
        {"candidate_index": t["candidate_index"], "count": t["votes"]} for t in totals]
    return b


@pytest.mark.xfail(strict=True, raises=ParseError, reason=KNOWN_DEVIATIONS)
def test_clean_board_parses_against_spec():
    parse_board(_clean())


def test_clean_board_differs_from_spec_only_in_known_deviations():
    board = parse_board(_apply_known_deviations(_clean()))
    assert board.config.m == 6
    assert len(board.ballots) == board.poll_register.ballots_issued


def test_base_hash_recomputed_independently_matches_c():
    board = parse_board(_apply_known_deviations(_clean()))
    c, ts, ak = board.config, board.trustee_setup, board.authority_keys
    q = base_hash(c.election_id, [x.candidate_id for x in c.candidates], c.n, c.t,
                  ts.public_key, ts.commitments, ak.k, ak.officer, ak.agents)
    assert q == board.base_hash


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("spoils"),
    lambda b: b.update(extra={}),
    lambda b: b["ballots"][0]["ciphertexts"][0].update(alpha=format(0, "0768x")),
])
def test_board_rejections(mutate):
    b = _apply_known_deviations(_clean())
    mutate(b)
    with pytest.raises(ParseError):
        parse_board(b)
