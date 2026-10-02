"""Property attribution on the revision 2 boards, with only their pre-poll
commitments rebuilt to SPEC 10 (tests/spec10.py). P1's digest and
signatures are checked on the files as they are, and every ballot proof,
spoil opening and decryption proof is the original.

Tester selections for the redirection board: it and the tally-manipulation
board come from the same election (same key, same pre-poll commitments,
same spoil randomness). The latter's spoils at serials 6 and 7 open to
candidates 4 and 1, which is what the tester pressed; the redirecting
machine opened 5 and 5.
"""

import pathlib

import pytest

import verifier.verify as v
from tests.boards_v2 import strip_nonces
from tests.spec10 import rebuild

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards-v2"
TESTER_SELECTIONS = {6: 4, 7: 1}

_real_parse_board = v.parse_board


def _parse_and_rebuild(obj):
    board = _real_parse_board(strip_nonces(obj))
    return rebuild(board) if board.ballots else board  # P1's ballot-free pre-parse untouched


_cache = {}


def _verify(name, tester=None):
    key = (name, tuple(sorted((tester or {}).items())))
    if key not in _cache:
        d = BOARDS / name
        mp = pytest.MonkeyPatch()
        mp.setattr(v, "parse_board", _parse_and_rebuild)
        try:
            _cache[key] = v.verify((d / "board.json").read_bytes(),
                                   (d / "signatures.json").read_bytes(),
                                   tester_selections=tester)
        finally:
            mp.undo()
    return _cache[key]


def test_clean_accepted_with_p3_passed():
    r = _verify("clean")
    assert r.accepted, r.summary()
    assert r.properties == {p: "passed" for p in ("P1", "P2", "P3", "P4", "P5")}


def test_redirection_named_p3_by_tester_comparison():
    r = _verify("redirection", tester=TESTER_SELECTIONS)
    assert r.failed_property == "P3", r.summary()
    assert "opened candidate 5, tester selected 4" in r.failure.reason


def test_redirection_without_tester_record_is_not_detected():
    """SPEC 11.1: a truthful opening is consistent on the board. Without
    the tester's comparison the board verifies; this is the stated limit."""
    assert _verify("redirection").accepted


def test_stuffing_named_p4():
    r = _verify("stuffing")
    assert r.failed_property == "P4", r.summary()
    assert r.properties["P3"] == "passed"


def test_tally_manipulation_named_p5():
    r = _verify("tally-manipulation", tester={6: 4, 7: 1})
    assert r.failed_property == "P5", r.summary()
    assert all(r.properties[p] == "passed" for p in ("P1", "P2", "P3", "P4"))


def test_retroactive_edit_named_p1():
    assert _verify("board-edit").failed_property == "P1"


def test_malformed_named_p2():
    assert _verify("malformed").failed_property == "P2"
