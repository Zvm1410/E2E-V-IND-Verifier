#!/usr/bin/env python3
"""Sanity test for the ballot-stuffing attack hook.

Verifies board ballot count exceeds poll register by exactly the
configured `stuffed_count` when the feature is enabled.
"""
from pathlib import Path
import sys

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.services.ballot_service import BallotService
from app.services.poll_state import PollState
from app.services.election_loader import load_election_config


def main():
    cfg = load_election_config(Path("config/election.json"))
    ps = PollState()
    svc = BallotService(cfg, ps)

    # configure stuffing
    svc.attack_config.ballot_stuffing_enabled = True
    svc.attack_config.stuffed_count = 3

    ballots_to_cast = 10
    for i in range(ballots_to_cast):
        sel = i % cfg.candidate_count
        ps.begin_ballot()
        ps.mark_selection(sel)
        artifacts = svc.encrypt_and_prove(sel)
        svc.append_ballot(artifacts)
        ps.finish_ballot()

    board_ballots = [r for r in svc.board_records if r.get("record_type") == "ballot"]
    board_count = len(board_ballots)
    reg = ps.poll_register()

    expected = reg["ballots_issued"] + svc.attack_config.stuffed_count

    print("ballots_issued:", reg["ballots_issued"], "board_ballots:", board_count, "expected:", expected)

    if board_count == expected:
        print("[PASS] board ballot count exceeds register by stuffed_count")
    else:
        print("[FAIL] unexpected board ballot count")


if __name__ == "__main__":
    main()
