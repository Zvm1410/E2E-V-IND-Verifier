"""
Tests for C0, the paper-audit baseline simulator.

The central check is `test_srs_monte_carlo_matches_hypergeometric`: if
the Monte Carlo and the closed form disagree, the simulator is wrong and so
is everything built on it.

Everything else falls into three groups. Closed-form identities that hold
independently of any parameter choice, and would catch a transposed
argument or an off-by-one. Behavioural facts about the difference between
the two regimes, which are the paper's finding and are asserted so a
refactor cannot quietly erase them. Input validation.

`TestSpecVector` reproduces `spec/vectors/baseline_c0.json` exactly.
"""

from __future__ import annotations

import json
from fractions import Fraction
from math import comb
from pathlib import Path

import pytest

from baseline_c0 import (
    allocate_manipulation,
    bad_booth_count,
    c0_cluster,
    c0_srs,
    compromised_booths_for_margin,
    detection_probability,
    e2e_detection_probability,
    evasion_probability,
    hypergeometric_pmf,
    monte_carlo_cluster,
    monte_carlo_srs,
    monte_carlo_standard_error,
    required_sample_size,
    same_rate_sample_size,
)

SEED = 20260826
TRIALS = 40_000
SIGMA = 4  # agreement tolerance, in Monte Carlo standard errors

# (units, bad, sampled) triples spanning small, ECI-scale and degenerate.
UNIT_CASES = [
    (10, 1, 1),
    (10, 3, 4),
    (100, 1, 5),
    (250, 5, 5),
    (250, 25, 5),
    (2000, 100, 40),
    (200_000, 1000, 4000),
    (17, 5, 17),
    (17, 0, 5),
]

# A plausible assembly segment: 250 booths of 800 ballots, five audited.
BOOTHS = 250
BOOTH_SIZE = 800
AUDITED = 5
BALLOTS = BOOTHS * BOOTH_SIZE


# --------------------------------------------------------------------------
# Monte Carlo against the closed form
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "N,k,s",
    [
        (2000, 100, 40),
        (1000, 10, 50),
        (500, 250, 5),
        (1200, 1, 60),
        (800, 799, 3),
    ],
)
def test_srs_monte_carlo_matches_hypergeometric(N, k, s):
    """The central sanity check.

        1 - C(N - k, s) / C(N, s)

    computed exactly, against a direct simulation of the sampling
    procedure. The two share no arithmetic: one is a ratio of binomial
    coefficients, the other draws a sample and looks at it. Tolerance is
    four Monte Carlo standard errors, not a fixed epsilon, so it tracks
    the trial count instead of loosening silently as cases are added.
    """
    exact = c0_srs(N, k, s)
    closed_form = 1 - Fraction(comb(N - k, s), comb(N, s)) if N - k >= s else Fraction(1)
    assert exact == closed_form

    empirical = monte_carlo_srs(N, k, s, trials=TRIALS, seed=SEED)
    tolerance = SIGMA * monte_carlo_standard_error(float(exact), TRIALS)
    assert abs(empirical - float(exact)) <= tolerance, (
        f"N={N} k={k} s={s}: simulation {empirical} vs closed form "
        f"{float(exact)}, tolerance {tolerance}"
    )


@pytest.mark.parametrize("touched", [2, 5, 25, 125, 250])
def test_cluster_monte_carlo_matches_hypergeometric(touched):
    """The same check for the cluster arm, which is the regime actually
    being reported; it carries the headline number, so it gets the same
    treatment."""
    counts = allocate_manipulation(
        1000, BOOTHS, touched, booth_capacity=BOOTH_SIZE
    )
    exact = c0_cluster(counts, AUDITED)
    empirical = monte_carlo_cluster(counts, AUDITED, trials=TRIALS, seed=SEED)
    tolerance = SIGMA * monte_carlo_standard_error(float(exact), TRIALS)
    assert abs(empirical - float(exact)) <= tolerance


def test_monte_carlo_srs_with_imperfect_paper_trail():
    N, k, s, d = 1000, 20, 100, Fraction(1, 2)
    exact = c0_srs(N, k, s, d=d)
    empirical = monte_carlo_srs(N, k, s, trials=TRIALS, seed=SEED, d=d)
    tolerance = SIGMA * monte_carlo_standard_error(float(exact), TRIALS)
    assert abs(empirical - float(exact)) <= tolerance


# --------------------------------------------------------------------------
# The finding: cluster versus SRS depends on concentration
# --------------------------------------------------------------------------

def _spread(k: int, touched: int):
    return allocate_manipulation(k, BOOTHS, touched, booth_capacity=BOOTH_SIZE)


def test_cluster_is_far_weaker_under_concentrated_manipulation():
    """1000 ballots moved inside five booths.

    SRS at the same overall rate is near-certain to catch it. Cluster
    sampling catches it about once in ten. This gap is the argument for
    reporting the cluster arm.
    """
    counts = _spread(1000, 5)
    cluster = c0_cluster(counts, AUDITED)
    srs = c0_srs(BALLOTS, 1000, same_rate_sample_size([BOOTH_SIZE] * BOOTHS, AUDITED))
    assert cluster < Fraction(1, 10)
    assert srs > Fraction(999, 1000)


def test_cluster_is_not_weaker_under_maximally_spread_manipulation():
    """One manipulated ballot in each of `t` booths.

    At this allocation cluster sampling is at least as strong as SRS, and
    strictly stronger once t > 1, because a full hand count of an audited
    booth cannot sample around its single bad slip while an SRS draw can.

    This is asserted because it contradicts the intuition that cluster
    sampling is uniformly weaker. It is not: it is weaker under
    concentration, which is the case that matters, and the claim in the
    paper has to be stated that way to survive review.
    """
    sample_size = same_rate_sample_size([BOOTH_SIZE] * BOOTHS, AUDITED)
    for touched in (1, 2, 5, 50, 125, 250):
        counts = _spread(touched, touched)  # exactly one per touched booth
        cluster = c0_cluster(counts, AUDITED)
        srs = c0_srs(BALLOTS, touched, sample_size)
        assert cluster >= srs, f"touched={touched}"
    assert c0_cluster(_spread(250, 250), AUDITED) == 1


def test_cluster_detection_depends_only_on_booths_touched():
    """Cluster sampling is blind to how much was taken from each booth.

    Five booths hit for 20 votes each and five booths hit for 800 votes
    each are the same number to the cluster audit, and forty times apart
    to SRS. This is exactly the property that makes the cluster arm the
    honest baseline.
    """
    light = c0_cluster(_spread(100, 5), AUDITED)
    heavy = c0_cluster(_spread(4000, 5), AUDITED)
    assert light == heavy


def test_cluster_detection_is_monotone_in_booths_touched():
    values = [
        c0_cluster(_spread(4000, touched), AUDITED)
        for touched in (5, 10, 25, 50, 125, 250)
    ]
    assert all(a <= b for a, b in zip(values, values[1:]))


def test_srs_detection_is_blind_to_allocation():
    """The mirror of the previous two: SRS depends on k alone."""
    sample_size = same_rate_sample_size([BOOTH_SIZE] * BOOTHS, AUDITED)
    baseline = c0_srs(BALLOTS, 1000, sample_size)
    for touched in (2, 5, 250):
        counts = _spread(1000, touched)
        assert sum(counts) == 1000
        assert c0_srs(BALLOTS, sum(counts), sample_size) == baseline


# --------------------------------------------------------------------------
# Closed-form identities
# --------------------------------------------------------------------------

@pytest.mark.parametrize("units,bad,sampled", UNIT_CASES)
def test_hypergeometric_symmetry_identity(units, bad, sampled):
    """C(U-b, a) / C(U, a) == C(U-a, b) / C(U, b).

    Both equal (U-b)!(U-a)! / [(U-b-a)! U!]. Evasion is symmetric under
    swapping the number of bad units with the number audited. A
    transposed argument survives every eyeball check and dies here.
    """
    lhs = evasion_probability(units, bad, sampled, d=1)
    rhs = (
        Fraction(comb(units - sampled, bad), comb(units, bad))
        if units - sampled >= bad
        else Fraction(0)
    )
    assert lhs == rhs
    assert isinstance(lhs, Fraction)


@pytest.mark.parametrize("units,bad,sampled", UNIT_CASES)
def test_product_form_matches_binomial_form(units, bad, sampled):
    """Evasion == prod_{j=0}^{a-1} (U - b - j) / (U - j)."""
    product = Fraction(1)
    for j in range(sampled):
        product *= Fraction(max(units - bad - j, 0), units - j)
    assert evasion_probability(units, bad, sampled, d=1) == product


@pytest.mark.parametrize("units,bad,sampled", UNIT_CASES)
def test_pmf_sums_to_exactly_one(units, bad, sampled):
    total = sum(
        (hypergeometric_pmf(units, bad, sampled, x) for x in range(min(sampled, bad) + 1)),
        Fraction(0),
    )
    assert total == 1


@pytest.mark.parametrize("units,sampled", [(100, 5), (250, 5), (1000, 5), (17, 17)])
def test_single_bad_unit_is_exactly_the_sampling_fraction(units, sampled):
    """One bad unit, d = 1, gives P_det = a / U exactly, with no rounding."""
    assert detection_probability(units, 1, sampled, d=1) == Fraction(sampled, units)


@pytest.mark.parametrize("d_num,d_den", [(1, 2), (9, 10), (1, 4), (99, 100)])
def test_single_bad_unit_scales_linearly_in_d(d_num, d_den):
    d = Fraction(d_num, d_den)
    assert detection_probability(250, 1, 5, d=d) == Fraction(5, 250) * d


def test_boundaries():
    assert detection_probability(250, 0, 5, d=1) == 0      # nothing to find
    assert detection_probability(250, 10, 0, d=1) == 0     # nothing audited
    assert detection_probability(250, 10, 250, d=1) == 1   # full hand count
    assert detection_probability(250, 250, 1, d=1) == 1    # everything bad
    assert detection_probability(250, 10, 5, d=0) == 0     # paper trail lies
    assert detection_probability(250, 246, 5, d=1) == 1    # bad > U - a


def test_full_hand_count_with_imperfect_trail():
    """a = U, d < 1: P_det = 1 - (1 - d)^bad. Auditing everything is not enough."""
    d = Fraction(1, 3)
    assert detection_probability(250, 4, 250, d=d) == 1 - (1 - d) ** 4


@pytest.mark.parametrize("units,bad", [(250, 10), (300, 25), (1000, 50)])
def test_monotone_in_sample_size(units, bad):
    values = [detection_probability(units, bad, a, d=1) for a in range(31)]
    assert all(x <= y for x, y in zip(values, values[1:]))


@pytest.mark.parametrize("units,sampled", [(250, 5), (300, 12)])
def test_monotone_in_bad_count(units, sampled):
    values = [detection_probability(units, bad, sampled, d=1) for bad in range(41)]
    assert all(x <= y for x, y in zip(values, values[1:]))


# --------------------------------------------------------------------------
# The five-booth rule
# --------------------------------------------------------------------------

def test_five_booth_rule_barely_moves_with_population_size():
    """n = 5 regardless of B, so detection is near-invariant in B.

    An adversary holding 5 percent of the booths is caught with about the
    same probability whether the segment has 250 booths or 1000.
    """
    small = c0_cluster(allocate_manipulation(1000, 250, 12, BOOTH_SIZE), AUDITED)
    large = c0_cluster(allocate_manipulation(4000, 1000, 50, BOOTH_SIZE), AUDITED)
    assert abs(small - large) < Fraction(1, 50)


@pytest.mark.parametrize("units", [250, 300, 500, 1000])
def test_required_sample_size_dwarfs_the_five_booth_rule(units):
    n = required_sample_size(units, units // 20, Fraction(1, 100), d=1)
    assert n is not None and n > 5


@pytest.mark.parametrize(
    "units,bad,alpha",
    [(250, 10, Fraction(1, 100)), (300, 3, Fraction(1, 20)), (1000, 50, Fraction(1, 1000))],
)
def test_required_sample_size_is_the_smallest_sufficient(units, bad, alpha):
    n = required_sample_size(units, bad, alpha, d=1)
    assert n is not None
    assert detection_probability(units, bad, n, d=1) >= 1 - alpha
    assert detection_probability(units, bad, n - 1, d=1) < 1 - alpha


def test_required_sample_size_unreachable_with_bad_paper_trail():
    assert required_sample_size(250, 1, Fraction(1, 100), d=Fraction(1, 2)) is None


# --------------------------------------------------------------------------
# Allocation helpers
# --------------------------------------------------------------------------

def test_allocation_conserves_k_and_spreads_evenly():
    counts = allocate_manipulation(1000, 250, 7)
    assert sum(counts) == 1000
    assert len(counts) == 250
    assert max(counts) - min(c for c in counts if c) <= 1
    assert bad_booth_count(counts) == 7


def test_allocation_rejects_impossible_requests():
    with pytest.raises(ValueError, match="without leaving some untouched"):
        allocate_manipulation(3, 250, 5)
    with pytest.raises(ValueError, match="cannot place"):
        allocate_manipulation(10, 250, 0)
    with pytest.raises(ValueError, match="manipulated ballots in a booth"):
        allocate_manipulation(10_000, 250, 5, booth_capacity=BOOTH_SIZE)


def test_threshold_discards_thin_manipulation():
    """A decision rule that ignores small discrepancies erases the
    allocation that cluster sampling is otherwise best at catching."""
    counts = allocate_manipulation(250, 250, 250)  # one ballot each
    assert c0_cluster(counts, AUDITED, threshold=1) == 1
    assert c0_cluster(counts, AUDITED, threshold=2) == 0


def test_same_rate_sample_size_matches_the_cluster_rate():
    sizes = [BOOTH_SIZE] * BOOTHS
    assert same_rate_sample_size(sizes, AUDITED) == BALLOTS * AUDITED // BOOTHS
    assert Fraction(same_rate_sample_size(sizes, AUDITED), BALLOTS) == Fraction(
        AUDITED, BOOTHS
    )


def test_same_rate_sample_size_floors_against_srs():
    sizes = [7] * 3
    assert same_rate_sample_size(sizes, 1) == 7
    assert same_rate_sample_size([5, 6, 7], 1) == 6


# --------------------------------------------------------------------------
# Exactness and validation
# --------------------------------------------------------------------------

def test_returns_fraction_not_float():
    assert isinstance(c0_srs(250, 10, 5), Fraction)
    assert isinstance(c0_cluster(_spread(100, 5), AUDITED), Fraction)


@pytest.mark.parametrize(
    "call",
    [
        lambda: c0_srs(250, 10, 5, d=0.5),
        lambda: required_sample_size(250, 10, alpha=0.01),
        lambda: c0_cluster([1] * 250, 5, d=0.5),
    ],
)
def test_floats_are_rejected(call):
    with pytest.raises(TypeError, match="exact"):
        call()


@pytest.mark.parametrize(
    "units,bad,sampled",
    [(0, 0, 0), (-1, 0, 0), (250, 251, 5), (250, -1, 5), (250, 10, 251), (250, 10, -1)],
)
def test_invalid_population_rejected(units, bad, sampled):
    with pytest.raises(ValueError):
        detection_probability(units, bad, sampled, d=1)


def test_bool_is_not_an_int_here():
    with pytest.raises(TypeError):
        detection_probability(250, True, 5, d=1)


def test_empty_booth_list_rejected():
    with pytest.raises(ValueError, match="non-empty"):
        c0_cluster([], 0)


# --------------------------------------------------------------------------
# Linkage to the E2E arm
# --------------------------------------------------------------------------

def test_booths_needed_is_a_ceiling():
    assert compromised_booths_for_margin(1000, 40) == 25
    assert compromised_booths_for_margin(1001, 40) == 26
    assert compromised_booths_for_margin(0, 40) == 0


def test_e2e_bound_matches_spec_form():
    p = Fraction(1, 50)
    assert e2e_detection_probability(0, p) == 0
    assert e2e_detection_probability(1, p) == p
    assert e2e_detection_probability(10, p) == 1 - (1 - p) ** 10


def test_the_headline_comparison():
    """Same attack, three regimes.

    Move 1000 votes at 40 per booth: 25 of 250 booths. Cluster sampling
    at five booths catches it about two times in five. SRS at the same
    overall rate is near-certain. The E2E arm at a 2 percent test rate is
    above 0.999 and, unlike either paper arm, does not care how the
    manipulation is spread.
    """
    booths_touched = compromised_booths_for_margin(1000, 40)
    counts = allocate_manipulation(1000, BOOTHS, booths_touched, BOOTH_SIZE)
    cluster = c0_cluster(counts, AUDITED)
    srs = c0_srs(BALLOTS, 1000, same_rate_sample_size([BOOTH_SIZE] * BOOTHS, AUDITED))
    e2e = e2e_detection_probability(1000, Fraction(1, 50))
    assert Fraction(35, 100) < cluster < Fraction(45, 100)
    assert srs > Fraction(999, 1000)
    assert e2e > Fraction(999, 1000)
    assert cluster < srs


# --------------------------------------------------------------------------
# The specification vector
# --------------------------------------------------------------------------

def _find_vector():
    here = Path(__file__).resolve().parent
    for base in (here, here.parent):
        for candidate in (base / "vectors" / "baseline_c0.json",
                          base / "spec" / "vectors" / "baseline_c0.json"):
            if candidate.exists():
                return candidate
    return None


VECTOR = _find_vector()


def _expected(case) -> Fraction:
    """Exact rational from decimal strings. `approx` is non-normative."""
    return Fraction(int(case["expected"]["num"]), int(case["expected"]["den"]))


def _from_rle(rle):
    counts = []
    for value, repeats in rle:
        counts.extend([value] * repeats)
    return counts


@pytest.mark.skipif(
    VECTOR is None,
    reason=(
        "baseline_c0.json not found in vectors/ or spec/vectors/."
    ),
)
class TestSpecVector:
    """The vector restates the hypergeometric computation independently of
    the module under test. Disagreement means one of the two is wrong."""

    data = json.loads(VECTOR.read_text()) if VECTOR else {}

    def test_srs_cases(self):
        assert self.data["srs"], "vector has no SRS cases"
        for case in self.data["srs"]:
            got = c0_srs(
                case["N"], case["k"], case["s"],
                d=Fraction(case["d_num"], case["d_den"]),
            )
            assert got == _expected(case), case["check"]

    def test_cluster_cases(self):
        assert self.data["cluster"], "vector has no cluster cases"
        for case in self.data["cluster"]:
            counts = _from_rle(case["booth_manipulated_rle"])
            assert len(counts) == case["num_booths"]
            assert sum(counts) == case["manipulated_ballots"]
            assert bad_booth_count(counts, case["threshold"]) == case["bad_booths"]
            got = c0_cluster(
                counts, case["booths_audited"],
                d=Fraction(case["d_num"], case["d_den"]),
                threshold=case["threshold"],
            )
            assert got == _expected(case), case["check"]

    def test_invalid_cases_are_rejected(self):
        for case in self.data["invalid"]:
            args = case["args"]
            with pytest.raises((ValueError, TypeError)):
                if case["regime"] == "srs":
                    c0_srs(
                        args["N"], args["k"], args["s"],
                        d=Fraction(args.get("d_num", 1), args.get("d_den", 1)),
                    )
                else:
                    c0_cluster(
                        [0] * args["num_booths"], args["booths_audited"],
                        threshold=args.get("threshold", 1),
                    )

    def test_approx_field_is_close_but_not_normative(self):
        for case in self.data["srs"] + self.data["cluster"]:
            assert abs(float(_expected(case)) - case["expected"]["approx"]) < 1e-12
