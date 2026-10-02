"""The testing authority: holder of the test-schedule seed (SPEC 10.2).

The schedule decides which ballots are challenged. If the voting machine
could compute it, compromised firmware would know exactly which ballots are
safe to manipulate, which is the AOracle adversary and defeats the test
ballots entirely. So the seed is generated here, off the machine, by the
authority that runs the in-poll testing. The machine is given only the
commitment T, which it publishes in the pre-poll section; the authority
keeps the seed and the schedule, gives the tester the list of serials to
challenge, and publishes the seed at poll close so anyone can recompute T
and the schedule.

In a deployment this runs on a separate device and only T is entered into
the machine. In this repository run_election.py and the kiosk GUI play the
authority's role in the same process; neither hands the seed or the
schedule to the machine's code before close.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from crypto.encoding import L, S32


def derive_schedule(seed: bytes, ballots_expected: int, num: int, den: int) -> set[int]:
    """SPEC 10.2: serial s is a test ballot iff

        B2I(SHA-256(L("EVOTE-TESTDRAW-v1") || seed || U64(s))[0:8]) * den
            < num * 2^64

    Each serial is drawn independently, so the number of test ballots varies
    around num/den * N. Exact integer arithmetic throughout.
    """
    picks: set[int] = set()
    for s in range(1, ballots_expected + 1):
        digest = hashlib.sha256(L("EVOTE-TESTDRAW-v1") + seed + s.to_bytes(8, "big")).digest()
        if int.from_bytes(digest[:8], "big") * den < num * 2**64:
            picks.add(s)
    return picks


def seed_from_int(value: int) -> bytes:
    """Reproducible seed for simulated runs (handbook 1.5: a seeded override
    of the cryptographic source, for tests only)."""
    return hashlib.sha256(b"EVOTE-AUTHORITY-SEED" + value.to_bytes(16, "big")).digest()


class TestingAuthority:
    def __init__(self, Q: bytes, booth_id: str, num: int, den: int,
                 ballots_expected: int, seed: Optional[bytes] = None):
        # Production: 32 bytes from the OS. Simulated runs pass seed_from_int(...).
        self._seed = seed if seed is not None else secrets.token_bytes(32)
        if len(self._seed) != 32:
            raise ValueError("schedule seed must be 32 bytes")
        self.commitment = hashlib.sha256(
            L("EVOTE-TESTSCHED-v1") + Q + S32(booth_id) + self._seed
            + num.to_bytes(8, "big") + den.to_bytes(8, "big")
        ).hexdigest()
        self.schedule = derive_schedule(self._seed, ballots_expected, num, den)

    def reveal(self) -> str:
        """The seed, published at poll close (SPEC 10.2)."""
        return self._seed.hex()
