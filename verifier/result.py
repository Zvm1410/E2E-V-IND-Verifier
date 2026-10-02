"""Verification outcome types shared by every stage (SPEC 16)."""

PROPERTIES = ("P1", "P2", "P3", "P4", "P5")


class CheckFailure(Exception):
    """A property failed. `record` names the board record that caused it."""

    def __init__(self, prop, record, reason):
        assert prop in PROPERTIES, prop
        super().__init__(f"{prop} {record}: {reason}")
        self.prop = prop
        self.record = record
        self.reason = reason
