"""D2: the whole-board parser against C's exported boards (SPEC 14, rev 3).

The fixtures predate the removal of `nonce_commitment`; see tests/legacy.py."""

import pathlib

import pytest

from verifier.hashes import base_hash
from tests.legacy import strip_nonces
from verifier.parse import ParseError, load_json, parse_board

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"
NAMES = ["clean", "A8-redirection", "A9-stuffing", "C10-tally-tamper", "C11-retroactive-edit"]


def _load(name):
    return load_json((BOARDS / name / "board.json").read_bytes())


@pytest.mark.parametrize("name", NAMES)
def test_exported_boards_parse_strictly_apart_from_the_nonce(name):
    board = parse_board(strip_nonces(_load(name)))
    assert board.config.m == 6
    assert board.config.seed is None


@pytest.mark.parametrize("name", NAMES)
def test_exported_boards_rejected_for_publishing_nonces(name):
    with pytest.raises(ParseError, match="publishes a nonce"):
        parse_board(_load(name))


def test_b12_board_rejected_at_the_malformed_ballot():
    with pytest.raises(ParseError) as exc:
        parse_board(strip_nonces(_load("B12-malformed")))
    assert exc.value.path.startswith("ballots[10]")


def test_base_hash_recomputed_independently_matches_c():
    board = parse_board(strip_nonces(_load("clean")))
    c, ts, ak = board.config, board.trustee_setup, board.authority_keys
    q = base_hash(c.election_id, [x.candidate_id for x in c.candidates], c.n, c.t,
                  ts.public_key, ts.commitments, ak.k, ak.officer, ak.agents)
    assert q == board.base_hash


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("spoils"),
    lambda b: b.update(extra={}),
    lambda b: b["election_config"].update(seed=1),
    lambda b: b["trustee_setup"].update(record_type="trustee_setup"),
    lambda b: b["prepoll"]["randomness_commitments"][0].update(nonce_commitment="00" * 32),
    lambda b: b["tally_declaration"]["totals"][0].pop("candidate_id"),
    lambda b: b["tally_declaration"]["totals"].pop(),
    lambda b: b["tally_aggregate"]["columns"].reverse(),
    lambda b: b["schedule_opening"].update(schedule_seed="00"),
    lambda b: b["ballots"][0]["ciphertexts"][0].update(alpha=format(0, "0768x")),
])
def test_board_rejections(mutate):
    b = strip_nonces(_load("clean"))
    mutate(b)
    with pytest.raises(ParseError):
        parse_board(b)
