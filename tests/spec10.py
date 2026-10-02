"""Rebuild a parsed board's pre-poll commitments and schedule seed to SPEC 10.

The revision 2 boards commit with formulas that differ from SPEC 10.1 and
10.2. This keeps every real ballot, spoil, signature and transcript and
replaces only K_s for the spoiled serials, the schedule seed and T, so the
checks can be exercised on a board whose schedule the test chooses. Test
use only; never imported by verifier/.
"""

import dataclasses
import hashlib

from verifier.hashes import is_scheduled, randomness_commitment, schedule_commitment


def seed_for(schedule, issued, num, den):
    """First seed whose SPEC 10.2 draw over serials 1..issued is exactly `schedule`."""
    for i in range(1_000_000):
        seed = hashlib.sha256(b"spec10-rebuild" + i.to_bytes(8, "big")).digest()
        if {s for s in range(1, issued + 1) if is_scheduled(seed, s, num, den)} == set(schedule):
            return seed
    raise AssertionError("no seed found")


def rebuild(board, seed=None, num=None, den=None):
    c = board.config
    if num is not None:
        c = dataclasses.replace(c, test_rate_num=num, test_rate_den=den)
    by_serial = {sp.ballot_serial: sp for sp in board.spoils}
    if seed is None:
        seed = seed_for(by_serial, board.poll_register.ballots_issued,
                        c.test_rate_num, c.test_rate_den)
    commits = tuple(
        (s, randomness_commitment(board.base_hash, c.booth_id, s, by_serial[s].randomness,
                                  by_serial[s].nonce) if s in by_serial else k)
        for s, k in board.prepoll.randomness_commitments)
    t = schedule_commitment(board.base_hash, c.booth_id, seed, c.test_rate_num, c.test_rate_den)
    prepoll = dataclasses.replace(board.prepoll, randomness_commitments=commits,
                                  test_schedule_commitment=t)
    return dataclasses.replace(board, config=c, prepoll=prepoll, schedule_seed=seed)
