#!/usr/bin/env python3
"""Sanity test for the vote-redirection attack hook.

With the flag off, the `private_log` should be empty and board candidate
indices should equal true selections. With the flag on, `private_log` should
contain entries for redirected ballots and the board should contain the
substituted indices.
"""
from pathlib import Path
import sys

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.services.ballot_service import BallotService
from app.services.poll_state import PollState
from app.services.election_loader import load_election_config


def run_scenario(redirect_enabled: bool, redirect_to: int, ballots: int = 5):
    cfg = load_election_config(Path("config/election.json"))
    ps = PollState()
    svc = BallotService(cfg, ps)

    svc.attack_config.vote_redirection_enabled = redirect_enabled
    svc.attack_config.redirect_to_index = redirect_to

    true_selections = []
    for i in range(ballots):
        sel = (i % cfg.candidate_count)
        true_selections.append(sel)
        ps.begin_ballot()
        ps.mark_selection(sel)
        artifacts = svc.encrypt_and_prove(candidate_index=sel)
        svc.append_ballot(artifacts)
        ps.finish_ballot()

    # Gather board candidate indices
    board_ballots = [r for r in svc.board_records if r.get("record_type") == "ballot"]
    board_indices = [b.get("candidate_index") for b in board_ballots[:ballots]]

    # Private log entries for redirection
    redir_entries = [e for e in svc.private_log.entries if e.get("type") == "vote_redirection"]

    return {
        "true": true_selections,
        "board": board_indices,
        "private_log": redir_entries,
    }


def main():
    cfg = load_election_config(Path("config/election.json"))
    redirect_to = (cfg.candidate_count - 1) if cfg.candidate_count > 1 else 0

    # Scenario 1: flag off
    res_off = run_scenario(False, redirect_to, ballots=6)
    if len(res_off["private_log"]) != 0:
        print("[FAIL] private_log non-empty when redirection disabled")
        return

    if res_off["true"] != res_off["board"]:
        print("[FAIL] board differs from true selections when redirection disabled")
        print("true", res_off["true"])
        print("board", res_off["board"])
        return

    print("[PASS] No redirection with flag off; private log empty and board matches true selections")

    # Scenario 2: flag on
    res_on = run_scenario(True, redirect_to, ballots=6)
    # Expect private_log length == ballots (each selection redirected)
    if len(res_on["private_log"]) != 6:
        print("[FAIL] private_log length unexpected when redirection on", len(res_on["private_log"]))
        print(res_on["private_log"])
        return

    # Board indices should equal redirect_to for each
    if any(idx != redirect_to for idx in res_on["board"]):
        print("[FAIL] board candidate indices not all substituted as expected")
        print("board", res_on["board"])
        return

    print("[PASS] Redirection active: private log recorded and board shows substituted indices")


if __name__ == "__main__":
    main()
