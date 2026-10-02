"""D7: end-to-end verification and property attribution on C's six boards.

Expected attribution is the table in handbook D7 / SPEC 16. Three boards
cannot reach their expected property until the pre-poll commitments follow
SPEC 10 (see tests/test_d6_spoils.py): P3 runs before P4 and P5 and fails
first on every board, including the clean one. Those are strict xfails, so
the day the boards are regenerated correctly this file says so.
"""

import pathlib

import pytest

import verifier.verify as v
from verifier.spoils import NOT_EXERCISED

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"
BLOCKED = "pre-poll commitments do not follow SPEC 10.1/10.2, so P3 fails first"

_cache = {}


def _verify(name, **kw):
    key = (name, tuple(sorted(kw)))
    if key not in _cache:
        d = BOARDS / name
        _cache[key] = v.verify((d / "board.json").read_bytes(),
                               (d / "signatures.json").read_bytes(), compat=True, **kw)
    return _cache[key]


def test_c11_retroactive_edit_named_p1():
    r = _verify("C11-retroactive-edit")
    assert r.failed_property == "P1"
    assert all(r.properties[p] == "not_checked" for p in ("P2", "P3", "P4", "P5"))


def test_b12_malformed_ballot_named_p2():
    r = _verify("B12-malformed")
    assert r.failed_property == "P2"
    assert r.properties["P1"] == "passed"


@pytest.mark.xfail(strict=True, reason=BLOCKED)
def test_clean_board_accepted():
    assert _verify("clean").accepted


@pytest.mark.xfail(strict=True, reason=BLOCKED)
def test_a9_stuffing_named_p4():
    assert _verify("A9-stuffing").failed_property == "P4"


@pytest.mark.xfail(strict=True, reason=BLOCKED)
def test_c10_tally_manipulation_named_p5():
    assert _verify("C10-tally-tamper").failed_property == "P5"


@pytest.mark.xfail(strict=True, reason=BLOCKED + "; A8 fails P3 but for the commitment, "
                                                  "not the redirection")
def test_a8_redirection_named_p3_for_the_redirection():
    r = _verify("A8-redirection", tester_selections={6: 0, 7: 0})
    assert r.failed_property == "P3" and "tester selected" in r.failure.reason


def test_strict_mode_rejects_c_schema_as_p1():
    d = BOARDS / "clean"
    r = v.verify((d / "board.json").read_bytes(), (d / "signatures.json").read_bytes())
    assert r.failed_property == "P1" and "seed" in str(r.failure)


def test_clean_board_passes_p4_and_p5_once_p3_does(monkeypatch):
    """Everything after P3 already passes on the clean board."""
    monkeypatch.setattr(v, "check_cast_as_intended", lambda board, sel: "passed")
    d = BOARDS / "clean"
    r = v.verify((d / "board.json").read_bytes(), (d / "signatures.json").read_bytes(), compat=True)
    assert r.accepted, r.summary()


def test_c1_accepts_with_p3_not_exercised(monkeypatch):
    monkeypatch.setattr(v, "check_cast_as_intended", lambda board, sel: NOT_EXERCISED)
    d = BOARDS / "clean"
    r = v.verify((d / "board.json").read_bytes(), (d / "signatures.json").read_bytes(), compat=True)
    assert r.accepted
    assert r.properties["P3"] == "not_exercised"
    assert "P3: not exercised" in r.summary()


def test_garbage_input_is_a_p1_rejection_not_a_crash():
    r = v.verify(b"{not json", b"{}")
    assert r.failed_property == "P1"
