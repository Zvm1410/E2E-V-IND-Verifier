"""
C0 -- paper-audit baseline simulator.

Two regimes, both reported.

    C0_cluster   Whole booths are the sampling unit. `c` booths out of `B`
                 are chosen at random and their slips are fully hand
                 counted. This is actual ECI practice: five polling
                 stations per assembly segment.

    C0_srs       Individual ballots sampled at random at the same overall
                 rate, s / N == c / B. Not practice -- there is no
                 per-ballot EVM record for a single slip to be checked
                 against -- and it is included as a generous upper bound
                 on the status quo, not as a description of it.

Reporting only C0_srs overstates the detection power of the status quo.
Reporting only C0_cluster invites the objection that the weakest baseline
was chosen. Both go in the paper.

MODEL

    N   ballots in the audit population
    k   manipulated ballots
    B   booths, with sizes summing to N
    c   booths audited (cluster regime)
    s   ballots audited (SRS regime), s = N * c // B for the same rate
    d   probability that auditing a manipulated unit actually surfaces the
        discrepancy. d = 1 is the honest-paper-trail assumption; d < 1
        models firmware that also mis-prints slips (Appel, DeMillo and
        Stark 2020).

Both regimes are the same hypergeometric computation over different units.
Let `U` be the number of units, `bad` the number of units that carry
manipulation, `a` the number of units audited, and X the number of bad
units in the sample:

    X ~ Hypergeometric(U, bad, a)

        Pr[X = x] = C(bad, x) * C(U - bad, a - x) / C(U, a)

    Pr[evade] = E[(1 - d)^X] = sum_x Pr[X = x] * (1 - d)^x

    P_det = 1 - E[(1 - d)^X]

At d = 1 this collapses to the hypergeometric zero-cell:

    P_det = 1 - C(U - bad, a) / C(U, a)

Instantiated:

    C0_srs      U = N, bad = k, a = s
    C0_cluster  U = B, bad = number of booths carrying at least `threshold`
                manipulated ballots, a = c

The whole difference between the two regimes is that a booth carrying 200
manipulated ballots is one bad unit under cluster sampling and 200 bad
units under SRS. Everything else is shared code, deliberately, so that
the mandated C0_srs sanity check exercises the same arithmetic the
cluster arm uses.

SOURCES
    Hypergeometric acceptance sampling applied to vote-tally audits:
        R. G. Saltman, "Effective Use of Computing Technology in
        Vote-Tallying", NBS SP 500-30, 1975.
        P. B. Stark, "Conservative statistical post-election audits",
        Annals of Applied Statistics 2(2), 2008.
        M. Lindeman and P. B. Stark, "A Gentle Introduction to
        Risk-Limiting Audits", IEEE Security & Privacy 10(5), 2012.
    Cluster sampling of whole booths, and the Indian VVPAT regime:
        A. G. Bhatt, R. L. Karandikar and O. P. Ghosh, "Random Sampling
        for Testing of EVMs via VVPAT Slip Verification", ISI report to
        the Election Commission of India, 22 March 2019.
        K. Ashok Vardhan Shetty, "Fixing India's VVPAT-based Audit of
        EVMs", 2018.
        Citizens' Commission on Elections, "Report on EVMs and VVPAT"
        (Lokur et al.), 2021.
    Why d may be less than 1:
        A. W. Appel, R. A. DeMillo and P. B. Stark, "Ballot-Marking
        Devices Cannot Ensure the Will of the Voters", 2020.

NOTE ON POPULATION
    Detection depends entirely on how the audit population is defined,
    and the ECI has never fixed one. Booth sizes are a required argument
    with no default.

ARITHMETIC
    Exact throughout: math.comb over ints, fractions.Fraction for ratios,
    integer powers of (1 - d). Floats are rejected at the boundary --
    pass Fraction(1, 2), not 0.5. Consistent with SPEC.md 10.2, and
    required if these numbers are ever to appear in a test vector.
    Floats appear only in the Monte Carlo simulators, which are estimates
    by construction and are labelled as such.

This module computes no hash, parses no board, and uses no domain
separation label. It touches nothing frozen in SPEC.md.
"""

from __future__ import annotations

import random
from fractions import Fraction
from math import comb
from typing import Optional, Sequence

__all__ = [
    "hypergeometric_pmf",
    "evasion_probability",
    "detection_probability",
    "required_sample_size",
    "c0_srs",
    "c0_cluster",
    "allocate_manipulation",
    "same_rate_sample_size",
    "bad_booth_count",
    "monte_carlo_srs",
    "monte_carlo_cluster",
    "monte_carlo_standard_error",
    "compromised_booths_for_margin",
    "e2e_detection_probability",
]


# --------------------------------------------------------------------------
# Argument checking
# --------------------------------------------------------------------------

def _int(value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _check_units(units: int, bad: int, sampled: int) -> None:
    _int(units, "units")
    _int(bad, "bad")
    _int(sampled, "sampled")
    if units < 1:
        raise ValueError(f"units must be at least 1, got {units}")
    if not 0 <= bad <= units:
        raise ValueError(f"bad must lie in [0, units], got bad={bad}, units={units}")
    if not 0 <= sampled <= units:
        raise ValueError(
            f"sampled must lie in [0, units], got sampled={sampled}, units={units}"
        )


def _as_probability(d, name: str) -> Fraction:
    """Coerce to an exact Fraction in [0, 1]. Floats are rejected."""
    if isinstance(d, float):
        raise TypeError(
            f"{name} must be exact: pass an int or a Fraction, not a float. "
            f"Use Fraction(1, 2), not 0.5."
        )
    value = Fraction(d)
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must lie in [0, 1], got {value}")
    return value


# --------------------------------------------------------------------------
# Unit-agnostic core
# --------------------------------------------------------------------------

def hypergeometric_pmf(units: int, bad: int, sampled: int, x: int) -> Fraction:
    """Pr[X = x] where X is the number of bad units in the sample.

    Returns an exact Fraction; returns 0 outside the support rather than
    raising, so callers can sum over a generous range.
    """
    _check_units(units, bad, sampled)
    _int(x, "x")
    if x < 0 or x > bad or x > sampled or (sampled - x) > (units - bad):
        return Fraction(0)
    return Fraction(comb(bad, x) * comb(units - bad, sampled - x), comb(units, sampled))


def evasion_probability(units: int, bad: int, sampled: int, d=1) -> Fraction:
    """Pr[the audit finds nothing] = E[(1 - d)^X], exact.

    At d = 1 this is C(units - bad, sampled) / C(units, sampled).
    """
    _check_units(units, bad, sampled)
    d = _as_probability(d, "d")
    miss = 1 - d
    total = Fraction(0)
    for x in range(min(sampled, bad) + 1):
        pmf = hypergeometric_pmf(units, bad, sampled, x)
        if pmf:
            total += pmf * (miss ** x)
    return total


def detection_probability(units: int, bad: int, sampled: int, d=1) -> Fraction:
    """P_det = 1 - E[(1 - d)^X], exact.

    Unit-agnostic. Prefer c0_srs or c0_cluster, so that the choice of unit
    is recorded at the call site.
    """
    return 1 - evasion_probability(units, bad, sampled, d)


def required_sample_size(units: int, bad: int, alpha, d=1) -> Optional[int]:
    """Smallest number of units to audit for P_det >= 1 - alpha.

    Returns None if no sample size up to `units` reaches the target, which
    happens whenever d < 1 and (1 - d)^bad stays above alpha even at a
    full hand count. P_det is nondecreasing in the sample size, so binary
    search is sound.
    """
    _check_units(units, bad, 0)
    alpha = _as_probability(alpha, "alpha")
    d = _as_probability(d, "d")
    target = 1 - alpha
    if detection_probability(units, bad, units, d) < target:
        return None
    lo, hi = 0, units
    while lo < hi:
        mid = (lo + hi) // 2
        if detection_probability(units, bad, mid, d) >= target:
            hi = mid
        else:
            lo = mid + 1
    return lo


# --------------------------------------------------------------------------
# C0_srs -- individual ballots as the sampling unit
# --------------------------------------------------------------------------

def c0_srs(N: int, k: int, s: int, d=1) -> Fraction:
    """Detection probability when `s` of `N` individual ballots are sampled.

    At d = 1:

        1 - C(N - k, s) / C(N, s)

    The generous upper bound on the status quo, not a model of it.
    """
    return detection_probability(N, k, s, d)


# --------------------------------------------------------------------------
# C0_cluster -- whole booths as the sampling unit
# --------------------------------------------------------------------------

def bad_booth_count(booth_manipulated: Sequence[int], threshold: int = 1) -> int:
    """Number of booths carrying at least `threshold` manipulated ballots.

    `threshold` exists because a real audit may treat a one- or two-vote
    discrepancy as clerical rather than as evidence. The ECI has published
    no decision rule, so the default is 1 -- any discrepancy counts -- and
    anything else must be chosen explicitly and stated in the paper.
    """
    _int(threshold, "threshold")
    if threshold < 1:
        raise ValueError(f"threshold must be at least 1, got {threshold}")
    counts = list(booth_manipulated)
    for i, value in enumerate(counts):
        _int(value, f"booth_manipulated[{i}]")
        if value < 0:
            raise ValueError(f"booth_manipulated[{i}] must be non-negative, got {value}")
    return sum(1 for value in counts if value >= threshold)


def c0_cluster(
    booth_manipulated: Sequence[int],
    booths_audited: int,
    d=1,
    threshold: int = 1,
) -> Fraction:
    """Detection probability when whole booths are audited.

    `booth_manipulated` is the per-booth count of manipulated ballots, one
    entry per booth, so its length is B. A booth is bad if it carries at
    least `threshold` manipulated ballots; an audited bad booth is caught
    with probability d, because the hand count covers all of its slips.

    The allocation matters more than the total. The same k spread over
    many booths and concentrated in a few give very different answers here
    and identical answers under c0_srs. That difference is the finding, so
    the allocation is an explicit argument rather than something derived
    from k inside this function.
    """
    counts = list(booth_manipulated)
    if not counts:
        raise ValueError("booth_manipulated must be non-empty")
    bad = bad_booth_count(counts, threshold)
    return detection_probability(len(counts), bad, booths_audited, d)


def allocate_manipulation(
    k: int,
    num_booths: int,
    booths_touched: int,
    booth_capacity: Optional[int] = None,
) -> tuple:
    """Spread `k` manipulated ballots over `booths_touched` of `num_booths`.

    Returns a tuple of length `num_booths`. The manipulation is divided as
    evenly as possible over the touched booths, remainder to the lowest
    indices. Booth identity is irrelevant to the hypergeometric, so the
    touched booths are taken to be the first ones.

    `booth_capacity`, if given, is the number of ballots cast at a booth;
    an allocation exceeding it is rejected rather than silently modelling
    an adversary shifting more votes than exist.
    """
    _int(k, "k")
    _int(num_booths, "num_booths")
    _int(booths_touched, "booths_touched")
    if k < 0:
        raise ValueError(f"k must be non-negative, got {k}")
    if num_booths < 1:
        raise ValueError(f"num_booths must be at least 1, got {num_booths}")
    if not 0 <= booths_touched <= num_booths:
        raise ValueError(
            f"booths_touched must lie in [0, num_booths], "
            f"got {booths_touched} of {num_booths}"
        )
    if k > 0 and booths_touched == 0:
        raise ValueError("cannot place manipulated ballots in zero booths")
    if k < booths_touched:
        raise ValueError(
            f"cannot spread {k} manipulated ballots over {booths_touched} booths "
            f"without leaving some untouched; reduce booths_touched"
        )

    counts = [0] * num_booths
    if booths_touched:
        base, extra = divmod(k, booths_touched)
        for i in range(booths_touched):
            counts[i] = base + (1 if i < extra else 0)

    if booth_capacity is not None:
        _int(booth_capacity, "booth_capacity")
        if booth_capacity < 1:
            raise ValueError(f"booth_capacity must be at least 1, got {booth_capacity}")
        if counts and max(counts) > booth_capacity:
            raise ValueError(
                f"allocation puts {max(counts)} manipulated ballots in a booth "
                f"holding {booth_capacity}"
            )
    return tuple(counts)


def same_rate_sample_size(booth_sizes: Sequence[int], booths_audited: int) -> int:
    """Ballots to sample under C0_srs to match the cluster audit rate.

    s = N * c // B, so that s / N equals c / B. Floor division: where the
    division is not exact the SRS arm gets slightly fewer ballots than the
    cluster arm, which biases the comparison against SRS. Since SRS is the
    generous upper bound, biasing against it is the safe direction.
    """
    _int(booths_audited, "booths_audited")
    sizes = list(booth_sizes)
    if not sizes:
        raise ValueError("booth_sizes must be non-empty")
    for i, size in enumerate(sizes):
        _int(size, f"booth_sizes[{i}]")
        if size < 1:
            raise ValueError(f"booth_sizes[{i}] must be at least 1, got {size}")
    num_booths = len(sizes)
    if not 0 <= booths_audited <= num_booths:
        raise ValueError(
            f"booths_audited must lie in [0, {num_booths}], got {booths_audited}"
        )
    return sum(sizes) * booths_audited // num_booths


# --------------------------------------------------------------------------
# Monte Carlo -- the mandated sanity check
# --------------------------------------------------------------------------

def monte_carlo_srs(N: int, k: int, s: int, trials: int, seed: int, d=1) -> float:
    """Simulate the SRS audit directly. Returns an empirical detection rate.

    Shares no arithmetic with c0_srs: this draws a sample and looks at it.
    Agreement between the two is the module's central sanity check.
    """
    _check_units(N, k, s)
    _int(trials, "trials")
    _int(seed, "seed")
    if trials < 1:
        raise ValueError(f"trials must be at least 1, got {trials}")
    d = _as_probability(d, "d")
    perfect = d == 1
    d_float = float(d)
    rng = random.Random(seed)
    ballots = range(N)
    hits = 0
    for _ in range(trials):
        found = sum(1 for ballot in rng.sample(ballots, s) if ballot < k)
        if not found:
            continue
        if perfect or any(rng.random() < d_float for _ in range(found)):
            hits += 1
    return hits / trials


def monte_carlo_cluster(
    booth_manipulated: Sequence[int],
    booths_audited: int,
    trials: int,
    seed: int,
    d=1,
    threshold: int = 1,
) -> float:
    """Simulate the cluster audit directly. Returns an empirical rate."""
    counts = list(booth_manipulated)
    if not counts:
        raise ValueError("booth_manipulated must be non-empty")
    _check_units(len(counts), 0, booths_audited)
    _int(trials, "trials")
    _int(seed, "seed")
    if trials < 1:
        raise ValueError(f"trials must be at least 1, got {trials}")
    d = _as_probability(d, "d")
    _int(threshold, "threshold")
    if threshold < 1:
        raise ValueError(f"threshold must be at least 1, got {threshold}")
    perfect = d == 1
    d_float = float(d)
    rng = random.Random(seed)
    booths = range(len(counts))
    hits = 0
    for _ in range(trials):
        bad_seen = sum(
            1 for booth in rng.sample(booths, booths_audited)
            if counts[booth] >= threshold
        )
        if not bad_seen:
            continue
        if perfect or any(rng.random() < d_float for _ in range(bad_seen)):
            hits += 1
    return hits / trials


def monte_carlo_standard_error(p: float, trials: int) -> float:
    """Standard error of a Monte Carlo detection rate estimate.

    sqrt(p * (1 - p) / trials). Use a multiple of this as the agreement
    tolerance rather than a fixed epsilon, so the tolerance tracks the
    trial count instead of silently loosening as cases are added.
    """
    _int(trials, "trials")
    if trials < 1:
        raise ValueError(f"trials must be at least 1, got {trials}")
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"p must lie in [0, 1], got {p}")
    return (p * (1.0 - p) / trials) ** 0.5


# --------------------------------------------------------------------------
# Linkage to the E2E arm
# --------------------------------------------------------------------------

def compromised_booths_for_margin(margin_votes: int, max_shift_per_booth: int) -> int:
    """Booths an adversary must touch to move `margin_votes` votes.

    `max_shift_per_booth` is the largest per-booth shift the adversary will
    risk before the booth's result is implausible on its face. This is the
    parameter that makes the cluster arm comparable to the E2E bound, which
    is stated per manipulated ballot rather than per booth.
    """
    _int(margin_votes, "margin_votes")
    _int(max_shift_per_booth, "max_shift_per_booth")
    if margin_votes < 0:
        raise ValueError(f"margin_votes must be non-negative, got {margin_votes}")
    if max_shift_per_booth < 1:
        raise ValueError(
            f"max_shift_per_booth must be at least 1, got {max_shift_per_booth}"
        )
    return -(-margin_votes // max_shift_per_booth)


def e2e_detection_probability(k: int, p) -> Fraction:
    """1 - (1 - p)^k, the in-poll test-ballot bound, for the comparison table.

    k manipulated ballots, p the test-ballot rate (SPEC.md 10.2 test_rate,
    num over den). Restated here only so both arms are plotted from one
    code path; the normative mechanism lives in the challenge module.
    """
    _int(k, "k")
    if k < 0:
        raise ValueError(f"k must be non-negative, got {k}")
    p = _as_probability(p, "p")
    return 1 - (1 - p) ** k
