"""End-to-end property attribution on the boards in tests/fixtures/boards,
produced by make_bundles.sh: a clean run, one run per attack, and
configuration C1. Expected outcomes are SPEC 16; under C1 the election is
accepted with P3 not exercised.
"""

import json
import pathlib

import pytest

import verifier.verify as v

pytestmark = pytest.mark.slow

ROOT = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"

EXPECTED = {
    "clean": None,
    "redirection": "P3",
    "stuffing": "P4",
    "malformed": "P2",
    "tally-manipulation": "P5",
    "board-edit": "P1",
    "c1-no-test-ballots": None,
}


def _verify(tag):
    d = ROOT / tag
    if not (d / "board.json").exists():
        pytest.skip(f"{d} not present; run make_bundles.sh")
    tester_file = d / "tester_selections.json"
    tester = ({int(k): int(x) for k, x in json.loads(tester_file.read_text()).items()}
              if tester_file.exists() else None)
    return v.verify((d / "board.json").read_bytes(), (d / "signatures.json").read_bytes(),
                    tester_selections=tester)


@pytest.mark.parametrize("tag,expected", EXPECTED.items())
def test_attribution(tag, expected):
    r = _verify(tag)
    assert r.failed_property == expected, r.summary()
    if expected:
        earlier = [p for p in ("P1", "P2", "P3", "P4", "P5") if p < expected]
        assert all(r.properties[p] in ("passed", "not_exercised") for p in earlier), r.summary()


def test_c1_reports_p3_not_exercised():
    r = _verify("c1-no-test-ballots")
    assert r.properties["P3"] == "not_exercised", r.summary()


def test_clean_run_exercised_p3():
    """A clean run whose schedule drew nothing would leave P3 vacuous."""
    d = ROOT / "clean"
    if not (d / "board.json").exists():
        pytest.skip("clean board not present")
    assert json.loads((d / "board.json").read_text())["spoils"], "no test ballots drawn"
