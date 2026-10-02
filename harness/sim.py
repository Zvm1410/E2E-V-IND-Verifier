"""D8: one simulated election, fast model.

Given a configuration (C0, C1 or C2), an adversary (A0 to A3, or AOracle),
a manipulation count k, a test rate p and a seed, run one election and
report whether the vote redirection was detected and under which property.

What is modelled, and what is not
---------------------------------
The schedule is SPEC 10.2's per-serial draw, computed by the verifier's own
`is_scheduled` from a seed. The adversaries are basket A's classes, imported
unmodified from vendor/a10. The machine sees, for each ballot, the features
of A's dictionary (elapsed time since poll open, ballot index, time from
selection to confirmation, input device) before it encrypts, decides by its
adversary's rule which ballots are safe to manipulate, and redirects k of
them chosen uniformly among those it judges not to be tests.

Detection under C2 is the event that a redirected serial is a scheduled test
ballot. That is exactly what the verifier's P3 checks on a real board: the
challenged ballot is opened, and the tester's comparison of SPEC 11.1 fails.
harness/full_runs.py confirms, election by election through the real
prover and the real verifier, that the two agree. The cryptography itself
is not simulated here; it is what makes the event observable, and it is
exercised in full by the verifier tests and those full runs.

Behaviour model (voters and testers)
------------------------------------
Voters arrive with exponential gaps (mean VOTER_GAP_S), take a log-normal
time from selection to confirmation (median VOTER_CONFIRM_MS), and use the
touchscreen except for a small fraction on the accessibility keypad.
A *disciplined* tester is drawn from the same distributions as a voter. A
*naive* tester confirms more slowly and mostly uses the keypad, which is
the behaviour A2Interaction looks for. The constants are stated here so the
paper can report them.
"""

from __future__ import annotations

import hashlib
import math
import random
import sys
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT, ROOT / "vendor" / "a10", ROOT / "vendor" / "b10"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from app.services.adversary import (  # noqa: E402  (basket A, unmodified)
    A0Blind, A1Temporal, A2Interaction, A3Leakage, AdversaryFeatures, AOracle,
)
from verifier.hashes import is_scheduled  # noqa: E402

CONFIGS = ("C0", "C1", "C2")
ADVERSARIES = ("A0", "A1", "A2", "A3", "AOracle")
TESTERS = ("disciplined", "naive")

VOTER_GAP_S = 90.0
VOTER_CONFIRM_MS = 1800.0
VOTER_CONFIRM_SIGMA = 0.5
VOTER_KEYPAD = 0.03
NAIVE_CONFIRM_MS = 4500.0
NAIVE_CONFIRM_SIGMA = 0.4
NAIVE_KEYPAD = 0.8

DETECTED_P3 = "P3"
NOT_EXERCISED = "not_exercised"
PAPER_AUDIT = "paper_audit"


@dataclass(frozen=True)
class Outcome:
    detected: bool
    property: str | None  # "P3", "paper_audit", "not_exercised", or None
    manipulated: int      # ballots actually redirected (<= k)
    tests: int            # scheduled test ballots in the election
    caught: int           # redirected ballots that were tests (or audited, under C0)


def _features(serial, elapsed, is_test, tester, rng):
    naive = is_test and tester == "naive"
    median, sigma, keypad = ((NAIVE_CONFIRM_MS, NAIVE_CONFIRM_SIGMA, NAIVE_KEYPAD) if naive
                             else (VOTER_CONFIRM_MS, VOTER_CONFIRM_SIGMA, VOTER_KEYPAD))
    return AdversaryFeatures(
        elapsed_seconds=elapsed,
        ballot_index=serial,
        selection_to_confirm_ms=rng.lognormvariate(math.log(median), sigma),
        input_device="keypad" if rng.random() < keypad else "touchscreen",
    )


def _leaked_schedule(schedule, ballots, leak, rng):
    """A3: a corrupted copy of the schedule, same size, `leak` of it correct."""
    true = sorted(schedule)
    correct = rng.sample(true, round(leak * len(true)))
    decoys = rng.sample([s for s in range(1, ballots + 1) if s not in schedule],
                        len(true) - len(correct))
    return set(correct) | set(decoys)


def _adversary(name, schedule, ballots, leak, rng):
    if name == "A0":
        return A0Blind()
    if name == "A1":
        return A1Temporal()
    if name == "A2":
        return A2Interaction()
    if name == "A3":
        return A3Leakage(_leaked_schedule(schedule, ballots, leak, rng))
    if name == "AOracle":
        return AOracle(set(schedule))
    raise ValueError(f"unknown adversary {name!r}")


def simulate(config, adversary, k, p, seed, ballots=200, tester="disciplined", leak=0.0):
    """One election. `p` is the test rate as a Fraction (also the C0 audit rate)."""
    if config not in CONFIGS:
        raise ValueError(f"unknown configuration {config!r}")
    if tester not in TESTERS:
        raise ValueError(f"unknown tester regime {tester!r}")
    p = Fraction(p)
    rng = random.Random(seed)
    schedule_seed = hashlib.sha256(b"EVOTE-HARNESS-v1" + seed.to_bytes(16, "big")).digest()

    num = p.numerator if config == "C2" else 0
    schedule = {s for s in range(1, ballots + 1)
                if num and is_scheduled(schedule_seed, s, num, p.denominator)}

    adv = _adversary(adversary, schedule, ballots, leak, rng)
    elapsed, safe = 0.0, []
    for s in range(1, ballots + 1):
        elapsed += rng.expovariate(1 / VOTER_GAP_S)
        if not adv.is_probably_test(_features(s, elapsed, s in schedule, tester, rng)):
            safe.append(s)
    targets = set(rng.sample(safe, min(k, len(safe))))

    if config == "C2":
        caught = len(targets & schedule)
        return Outcome(caught > 0, DETECTED_P3 if caught else None, len(targets),
                       len(schedule), caught)
    if config == "C1":
        return Outcome(False, NOT_EXERCISED, len(targets), 0, 0)
    # C0: after the poll, hand-count a simple random sample at the same rate.
    audited = set(rng.sample(range(1, ballots + 1), ballots * p.numerator // p.denominator))
    caught = len(targets & audited)
    return Outcome(caught > 0, PAPER_AUDIT if caught else None, len(targets), 0, caught)


def run_seed(*parts):
    """Deterministic per-run seed from the cell parameters and run index."""
    text = "|".join(str(x) for x in parts).encode()
    return int.from_bytes(hashlib.sha256(text).digest()[:16], "big")
