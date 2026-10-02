"""D6: spoil records and the test schedule (SPEC 10, 11, 16 P3).

Returns "passed" or "not_exercised"; raises CheckFailure("P3", ...) on
failure. "not_exercised" is configuration C1 (test_rate.num == 0): the
schedule commitment is still opened and must give an empty schedule, and
any spoil record is then itself a failure.
"""

from verifier.group import G, P
from verifier.hashes import is_scheduled, randomness_commitment, schedule_commitment
from verifier.result import CheckFailure
from verifier.tally import aggregate

PASSED = "passed"
NOT_EXERCISED = "not_exercised"


def recompute_schedule(board):
    c = board.config
    return {s for s in range(1, board.poll_register.ballots_issued + 1)
            if is_scheduled(board.schedule_seed, s, c.test_rate_num, c.test_rate_den)}


def check_cast_as_intended(board, tester_selections=None):
    """`tester_selections`, if given, maps serial -> the candidate index the
    tester actually pressed. SPEC 11 has the tester compare the opened index
    with their own selection; the board alone cannot see that comparison,
    so a machine that redirects and then opens truthfully is caught only
    when this record is supplied (by the harness, or a real tester's log)."""
    c = board.config
    pk = board.trustee_setup.public_key
    commitments = dict(board.prepoll.randomness_commitments)

    expected_t = schedule_commitment(board.base_hash, c.booth_id, board.schedule_seed,
                                     c.test_rate_num, c.test_rate_den)
    if expected_t != board.prepoll.test_schedule_commitment:
        raise CheckFailure("P3", "prepoll.test_schedule_commitment",
                           "revealed schedule seed does not open the pre-poll commitment")
    schedule = recompute_schedule(board)

    if c.test_rate_num == 0:
        if board.spoils:
            raise CheckFailure("P3", "spoils[0]", "spoil record present with test ballots disabled")
        return NOT_EXERCISED

    ballots = {b.ballot_serial: b for b in board.ballots}
    for n, sp in enumerate(board.spoils):
        name = f"spoils[{n}] (serial {sp.ballot_serial})"
        ballot = ballots.get(sp.ballot_serial)
        if ballot is None:
            raise CheckFailure("P3", name, "spoil record for a serial with no ballot")
        for i, (r, (alpha, beta)) in enumerate(zip(sp.randomness, ballot.ciphertexts)):
            v = 1 if i == sp.opened_candidate_index else 0
            if pow(G, r, P) != alpha or pow(pk, r, P) * pow(G, v, P) % P != beta:
                raise CheckFailure("P3", name, f"re-encryption differs at candidate {i}")
        k_s = randomness_commitment(board.base_hash, c.booth_id, sp.ballot_serial,
                                    sp.randomness, sp.nonce)
        if commitments.get(sp.ballot_serial) != k_s:
            raise CheckFailure("P3", name, "revealed randomness and nonce do not open K_s")
        if sp.ballot_serial not in schedule:
            raise CheckFailure("P3", name, "spoil record for a serial the schedule did not draw")
        if tester_selections is not None and sp.ballot_serial in tester_selections:
            if tester_selections[sp.ballot_serial] != sp.opened_candidate_index:
                raise CheckFailure("P3", name,
                                   f"opened candidate {sp.opened_candidate_index}, tester "
                                   f"selected {tester_selections[sp.ballot_serial]}")

    skipped = sorted(schedule - {sp.ballot_serial for sp in board.spoils})
    if skipped:
        raise CheckFailure("P3", f"schedule serial {skipped[0]}",
                           "scheduled test ballot has no spoil record (challenge skipped)")

    spoiled = {sp.ballot_serial for sp in board.spoils}
    if spoiled and board.tally_aggregate != tuple(aggregate(board.ballots, spoiled, c.m)):
        if board.tally_aggregate == tuple(aggregate(board.ballots, set(), c.m)):
            raise CheckFailure("P3", "tally_aggregate", "spoiled ballots included in the aggregate")
    return PASSED
