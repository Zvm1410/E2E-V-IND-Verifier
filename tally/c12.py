"""
c12.py

Basket C - Configuration C1
"""

def apply_configuration_c1(config, enabled=False):
    """
    Configuration C1.

    When enabled, disable the in-poll
    test-ballot mechanism by setting
    the test rate to zero.
    """

    if not enabled:
        return config.copy()

    modified = config.copy()

    modified["test_rate"] = 0

    return modified


def generate_test_schedule(config):
    """
    Generate the test schedule.

    With test_rate = 0, there are no
    test ballots and therefore no
    test-ballot spoil records.
    """

    test_rate = config.get(
        "test_rate",
        0,
    )

    if test_rate == 0:
        return []

    return None


'''if __name__ == "__main__":

    config = {
        "test_rate": 10,
    }

    # C1 disabled
    normal = apply_configuration_c1(
        config,
        enabled=False,
    )

    assert normal["test_rate"] == 10

    print("C1 disabled: PASSED")

    # C1 enabled
    c1 = apply_configuration_c1(
        config,
        enabled=True,
    )

    assert c1["test_rate"] == 0

    print("C1 enabled: test rate = 0: PASSED")

    # No test ballots
    schedule = generate_test_schedule(c1)

    assert schedule == []

    print("C1 enabled: empty test schedule: PASSED")

    # Original configuration unchanged
    assert config["test_rate"] == 10

    print("Original configuration unchanged: PASSED")

    print()
    print("ALL C12 SANITY CHECKS PASSED")'''