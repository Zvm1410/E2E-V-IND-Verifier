"""B10's own vector test looks for spec/vectors/ beside its test file, so it
skips from vendor/b10. This runs the same cases from here, against B's
unmodified module."""

import json
from fractions import Fraction

import pytest

from baseline_c0 import bad_booth_count, c0_cluster, c0_srs
from tests.vectors import VECTORS

DATA = json.loads((VECTORS / "baseline_c0.json").read_text())


def _expected(case):
    return Fraction(int(case["expected"]["num"]), int(case["expected"]["den"]))


def _from_rle(rle):
    return [value for value, repeats in rle for _ in range(repeats)]


@pytest.mark.parametrize("case", DATA["srs"], ids=lambda c: c["check"][:40])
def test_srs_cases(case):
    got = c0_srs(case["N"], case["k"], case["s"], d=Fraction(case["d_num"], case["d_den"]))
    assert got == _expected(case)


@pytest.mark.parametrize("case", DATA["cluster"], ids=lambda c: c["check"][:40])
def test_cluster_cases(case):
    counts = _from_rle(case["booth_manipulated_rle"])
    assert len(counts) == case["num_booths"]
    assert sum(counts) == case["manipulated_ballots"]
    assert bad_booth_count(counts, case["threshold"]) == case["bad_booths"]
    got = c0_cluster(counts, case["booths_audited"],
                     d=Fraction(case["d_num"], case["d_den"]), threshold=case["threshold"])
    assert got == _expected(case)


@pytest.mark.parametrize("case", DATA["invalid"], ids=lambda c: c["reason"])
def test_invalid_cases_rejected(case):
    args = case["args"]
    with pytest.raises((ValueError, TypeError)):
        if case["regime"] == "srs":
            c0_srs(args["N"], args["k"], args["s"],
                   d=Fraction(args.get("d_num", 1), args.get("d_den", 1)))
        else:
            c0_cluster([0] * args["num_booths"], args["booths_audited"],
                       threshold=args.get("threshold", 1))
