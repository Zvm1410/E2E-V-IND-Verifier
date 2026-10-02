"""End-to-end attribution on boards regenerated with pipeline/make_bundles.sh.

Copy the seven bundle-<tag>/ directories into tests/fixtures/boards-r3/<tag>/. Each test is skipped until its board is
there. Expected outcomes are handbook D7 / SPEC 16, plus C1 (handbook C12).
"""

import json
import pathlib

import pytest

import verifier.verify as v

ROOT = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards-r3"

EXPECTED = {
    "clean": None,
    "A8-redirection": "P3",
    "A9-stuffing": "P4",
    "B12-malformed": "P2",
    "C10-tally-tamper": "P5",
    "C11-retroactive-edit": "P1",
    "C1-no-test-ballots": None,
}


def _verify(tag):
    d = ROOT / tag
    if not (d / "board.json").exists():
        pytest.skip(f"{d} not present; run pipeline/make_bundles.sh")
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
    r = _verify("C1-no-test-ballots")
    assert r.properties["P3"] == "not_exercised", r.summary()


def test_clean_run_exercised_p3():
    """A clean run whose schedule drew nothing would leave P3 vacuous."""
    d = ROOT / "clean"
    if not (d / "board.json").exists():
        pytest.skip("clean board not present")
    assert json.loads((d / "board.json").read_text())["spoils"], "no test ballots drawn"
