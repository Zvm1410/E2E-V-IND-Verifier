"""D6: spoil records and the test schedule (SPEC 10, 11).

C's boards commit to the schedule and the randomness with formulas that
differ from SPEC 10.1 and 10.2, so they fail here (strict xfail below).
The other tests take the real spoil records from the A8 board (real
randomness, real ciphertexts) and rebuild only the pre-poll commitments
and the schedule seed to SPEC, which isolates the D6 logic.
"""

import dataclasses
import pathlib

import pytest

from verifier.compat import normalise_c_export
from verifier.group import P
from tests.spec10 import rebuild, seed_for
from verifier.hashes import schedule_commitment
from verifier.parse import load_json, parse_board
from verifier.result import CheckFailure
from verifier.spoils import NOT_EXERCISED, PASSED, check_cast_as_intended
from verifier.tally import aggregate

BOARDS = pathlib.Path(__file__).resolve().parent / "fixtures" / "boards"

BOARD_FORMULAS = """
C's boards: test_schedule_commitment = SHA-256(schedule_seed), not SPEC 10.2's T;
K_s = SHA-256(U64(s) || S32(booth_id) || I2B(r_0..r_m-1) || nonce), SPEC 10.1 without
the label and Q; and spoils at serials 6, 7 where SPEC 10.2's schedule is empty.
"""


def _board(name):
    return parse_board(normalise_c_export(load_json((BOARDS / name / "board.json").read_bytes())))


@pytest.fixture(scope="module")
def a8_raw():
    return _board("A8-redirection")


@pytest.fixture(scope="module")
def spec_board(a8_raw):
    return rebuild(a8_raw)


@pytest.mark.xfail(strict=True, raises=CheckFailure, reason=BOARD_FORMULAS)
def test_a8_board_as_exported_meets_spec_10(a8_raw):
    check_cast_as_intended(a8_raw)


def test_spec_conformant_spoils_pass(spec_board):
    assert check_cast_as_intended(spec_board) == PASSED


def _spoil(board, n, **kw):
    spoils = list(board.spoils)
    spoils[n] = dataclasses.replace(spoils[n], **kw)
    return dataclasses.replace(board, spoils=tuple(spoils))


def test_altered_randomness_component_fails(spec_board):
    r = list(spec_board.spoils[0].randomness)
    r[3] = (r[3] + 1) % ((P - 1) // 2)
    with pytest.raises(CheckFailure, match="re-encryption differs at candidate 3"):
        check_cast_as_intended(_spoil(spec_board, 0, randomness=tuple(r)))


def test_lying_about_opened_index_fails(spec_board):
    sp = spec_board.spoils[0]
    with pytest.raises(CheckFailure, match="re-encryption"):
        check_cast_as_intended(_spoil(spec_board, 0,
                                      opened_candidate_index=(sp.opened_candidate_index + 1) % 6))


def test_altered_nonce_fails_commitment(spec_board):
    sp = spec_board.spoils[1]
    with pytest.raises(CheckFailure, match="K_s"):
        check_cast_as_intended(_spoil(spec_board, 1, nonce=bytes(32)))


def test_skipped_scheduled_challenge_caught(spec_board):
    """The machine quietly skipped serial 7's challenge: no spoil record."""
    board = dataclasses.replace(spec_board, spoils=spec_board.spoils[:1])
    with pytest.raises(CheckFailure, match="challenge skipped"):
        check_cast_as_intended(board)


def test_spoil_for_unscheduled_serial_caught(a8_raw):
    seed = seed_for({6}, 20, 1, 20)
    with pytest.raises(CheckFailure, match="did not draw"):
        check_cast_as_intended(rebuild(a8_raw, seed=seed))


def test_spoiled_ballot_counted_in_aggregate_caught(spec_board):
    everything = tuple(aggregate(spec_board.ballots, set(), spec_board.config.m))
    with pytest.raises(CheckFailure, match="included in the aggregate"):
        check_cast_as_intended(dataclasses.replace(spec_board, tally_aggregate=everything))


def test_wrong_schedule_seed_caught(spec_board):
    with pytest.raises(CheckFailure, match="does not open"):
        check_cast_as_intended(dataclasses.replace(spec_board, schedule_seed=bytes(32)))


def test_a8_redirection_caught_against_tester_record(spec_board):
    """A8's machine opened candidate 5 on both challenged ballots. A tester
    who pressed anything else catches it; the board alone cannot."""
    pressed = {sp.ballot_serial: 2 for sp in spec_board.spoils}
    with pytest.raises(CheckFailure, match="tester selected 2"):
        check_cast_as_intended(spec_board, tester_selections=pressed)
    honest = {sp.ballot_serial: sp.opened_candidate_index for sp in spec_board.spoils}
    assert check_cast_as_intended(spec_board, tester_selections=honest) == PASSED


def test_c1_reports_not_exercised(spec_board):
    board = rebuild(dataclasses.replace(spec_board, spoils=()), seed=bytes(range(32)),
                     num=0, den=20)
    assert check_cast_as_intended(board) == NOT_EXERCISED


def test_c1_with_a_spoil_record_fails(spec_board):
    board = rebuild(spec_board, seed=bytes(range(32)), num=0, den=20)
    with pytest.raises(CheckFailure, match="test ballots disabled"):
        check_cast_as_intended(board)


def test_rate_change_changes_schedule_commitment(spec_board):
    c = spec_board.config
    t1 = schedule_commitment(spec_board.base_hash, c.booth_id, spec_board.schedule_seed, 1, 20)
    t2 = schedule_commitment(spec_board.base_hash, c.booth_id, spec_board.schedule_seed, 0, 20)
    assert t1 != t2
