import pytest

from harness.stats import wilson


def test_worked_example():
    """8 successes in 10 trials gives roughly 0.49 to 0.94."""
    lo, hi = wilson(8, 10)
    assert round(lo, 2) == 0.49 and round(hi, 2) == 0.94


def test_edges_stay_in_unit_interval():
    assert wilson(0, 50)[0] == 0.0 and wilson(0, 50)[1] > 0
    assert wilson(50, 50)[1] == 1.0 and wilson(50, 50)[0] < 1


def test_interval_narrows_with_trials():
    a, b = wilson(50, 100), wilson(500, 1000)
    assert (b[1] - b[0]) < (a[1] - a[0])


@pytest.mark.parametrize("s,n", [(-1, 10), (11, 10), (0, 0)])
def test_invalid(s, n):
    with pytest.raises(ValueError):
        wilson(s, n)
