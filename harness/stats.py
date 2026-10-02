"""Confidence intervals for detection rates."""

from math import sqrt

Z95 = 1.959963984540054


def wilson(successes, trials, z=Z95):
    """Wilson score interval for a binomial proportion. Returns (low, high)."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    if not 0 <= successes <= trials:
        raise ValueError("successes must lie in [0, trials]")
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    # Exact at the edges: the closed form gives 0 and 1 there, floats give 1e-17.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == trials else min(1.0, centre + half)
    return low, high
