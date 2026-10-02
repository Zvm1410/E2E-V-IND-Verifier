"""D8 and D9 sanity checks on the fast election model."""

from fractions import Fraction

import pytest

from harness.sim import simulate, run_seed
from harness.stats import wilson

P = Fraction(1, 20)


def _rate(config, adversary, k, p, runs, **kw):
    hits = sum(simulate(config, adversary, k, p, run_seed("t", config, adversary, k, p, kw, i),
                        **kw).detected for i in range(runs))
    return hits, runs


def test_d8_same_seed_same_outcome():
    a = simulate("C2", "A2", 5, P, seed=1234, tester="naive")
    b = simulate("C2", "A2", 5, P, seed=1234, tester="naive")
    assert a == b


@pytest.mark.parametrize("k", [1, 5, 20])
def test_d9_blind_adversary_reproduces_analytic_bound(k):
    """D9 sanity check 1: C2 under A0 must give 1 - (1 - p)^k within the interval."""
    hits, runs = _rate("C2", "A0", k, P, 3000)
    lo, hi = wilson(hits, runs)
    assert lo <= 1 - (1 - float(P)) ** k <= hi


def test_d9_oracle_drives_detection_to_zero():
    """D9 sanity check 2 (handbook A10 calibration): AOracle knows the schedule."""
    hits, runs = _rate("C2", "AOracle", 20, P, 1000)
    assert hits == 0


def test_c1_never_detects_and_reports_not_exercised():
    for i in range(50):
        o = simulate("C1", "A0", 10, P, seed=i)
        assert not o.detected and o.property == "not_exercised" and o.tests == 0


def test_full_leak_is_as_good_as_the_oracle():
    hits, _ = _rate("C2", "A3", 20, P, 500, leak=1.0)
    assert hits == 0


def test_naive_tester_lets_a2_evade():
    """The fingerprinting effect: A2 against a naive tester is caught less
    often than against a disciplined one."""
    naive, n = _rate("C2", "A2", 10, P, 2000, tester="naive")
    disciplined, _ = _rate("C2", "A2", 10, P, 2000, tester="disciplined")
    assert wilson(naive, n)[1] < wilson(disciplined, n)[0]


def test_disciplined_tester_leaves_a2_no_better_than_blind():
    a2, n = _rate("C2", "A2", 10, P, 3000, tester="disciplined")
    a0, _ = _rate("C2", "A0", 10, P, 3000)
    lo2, hi2 = wilson(a2, n)
    lo0, hi0 = wilson(a0, n)
    assert lo2 <= hi0 and lo0 <= hi2  # intervals overlap


def test_c0_matches_b10_srs_closed_form():
    from baseline_c0 import c0_srs
    hits, runs = _rate("C0", "A0", 10, P, 3000)
    exact = float(c0_srs(200, 10, 200 * P.numerator // P.denominator))
    lo, hi = wilson(hits, runs)
    assert lo <= exact <= hi
