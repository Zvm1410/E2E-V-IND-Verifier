"""D7 attribution on C's six boards with the pre-poll commitments rebuilt
to SPEC 10 (tests/spec10.py). Everything else is the real board: P1's
digest and signatures are checked on the file exactly as exported, and
every ballot proof, spoil opening and decryption proof is C's.

This is what the attribution table will show once A's commitments follow
SPEC 10. It is not a substitute for regenerated boards.

A8's tester selections: A8 and C10 are the same election (same key, same
pre-poll commitments, same spoil randomness); C10's spoils at serials 6
and 7 open to candidates 4 and 1. A8's machine opened 5 and 5. Confirm
against A's private log when it is available.
"""

import pathlib

import pytest

import verifier.verify as v
from tests.spec10 import rebuild

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"
A8_TESTER = {6: 4, 7: 1}

_real_parse_board = v.parse_board


def _parse_and_rebuild(obj):
    board = _real_parse_board(obj)
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
                                   compat=True, tester_selections=tester)
        finally:
            mp.undo()
    return _cache[key]


def test_clean_accepted_with_p3_passed():
    r = _verify("clean")
    assert r.accepted, r.summary()
    assert r.properties == {p: "passed" for p in ("P1", "P2", "P3", "P4", "P5")}


def test_a8_redirection_named_p3_by_tester_comparison():
    r = _verify("A8-redirection", tester=A8_TESTER)
    assert r.failed_property == "P3", r.summary()
    assert "opened candidate 5, tester selected 4" in r.failure.reason


def test_a8_without_tester_record_is_not_detected():
    """SPEC 11.1: a truthful opening is consistent on the board. Without
    the tester's comparison the board verifies; this is the stated limit."""
    assert _verify("A8-redirection").accepted


def test_a9_stuffing_named_p4():
    r = _verify("A9-stuffing")
    assert r.failed_property == "P4", r.summary()
    assert r.properties["P3"] == "passed"


def test_c10_tally_manipulation_named_p5():
    r = _verify("C10-tally-tamper", tester={6: 4, 7: 1})
    assert r.failed_property == "P5", r.summary()
    assert all(r.properties[p] == "passed" for p in ("P1", "P2", "P3", "P4"))


def test_c11_retroactive_edit_named_p1():
    assert _verify("C11-retroactive-edit").failed_property == "P1"


def test_b12_malformed_named_p2():
    assert _verify("B12-malformed").failed_property == "P2"
