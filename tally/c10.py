"""
c10.py

Basket C - Tally Manipulation Attack Hook
"""


def manipulate_tally(declared_tally, enabled=False):
    """
    C10 attack hook.

    When enabled, deliberately publish a tally
    that does not match the ciphertexts.

    When disabled, return the original tally.
    """

    if not enabled:
        return declared_tally

    manipulated_tally = declared_tally.copy()

    if not manipulated_tally:
        raise ValueError(
            "Cannot manipulate an empty tally."
        )

    # Deliberately change the first candidate's tally.
    first_candidate = sorted(
        manipulated_tally.keys()
    )[0]

    manipulated_tally[first_candidate] += 1

    return manipulated_tally


'''if __name__ == "__main__":

    # Normal tally
    tally = {
        0: 10,
        1: 7,
        2: 3,
    }

    # Flag OFF
    normal = manipulate_tally(
        tally,
        enabled=False,
    )

    assert normal == tally

    print("Attack disabled: PASSED")

    # Flag ON
    attacked = manipulate_tally(
        tally,
        enabled=True,
    )

    assert attacked[0] == 11
    assert attacked[1] == 7
    assert attacked[2] == 3

    print("Attack enabled: PASSED")

    # Original must remain unchanged
    assert tally[0] == 10

    print("Original tally unchanged: PASSED")

    print()
    print("ALL C10 SANITY CHECKS PASSED")'''