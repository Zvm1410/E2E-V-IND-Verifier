"""End-to-end election runner.

Runs one election through the whole system without the kiosk UI. It does no
cryptography itself: every step calls ``crypto/``, ``tally/``, ``board/`` and
the machine's ``app/services``. It also plays the testing authority
(``testing_authority.py``).

    1. load config                                     (app.services.election_loader)
    2. initialise election  = BallotService(...)
         - trusted dealer for sk/pk + shares           (tally.trustees)
         - Ed25519 officer + agent keys                (board.authority)
         - base hash Q                                  (crypto.base_hash)
         - pre-poll r vectors + commitments K_s        (SPEC 10.1)
       testing authority: schedule seed, commitment T  (SPEC 10.2)
    3. publish pre-poll section                        (board.append_prepoll)
    4. open poll                                       (PollState.open_poll)
    5. cast N ballots; challenge the scheduled serials
    6. reveal schedule seed, write poll register       (board)
    7. aggregate unspoiled ballots per candidate       (tally.threshold)
    8. threshold-decrypt each candidate column         (tally.threshold)
    9. baby-step giant-step recovery of each count     (crypto.elgamal)
   10. append tally aggregate, decryption transcript, tally declaration
   11. compute board digest, multisign, export         (board.digest / signature / export)

``--config`` selects the configuration, ``--ballots`` the number cast,
``--out-dir`` the output directory, ``--authority-seed`` a reproducible
schedule; the remaining flags switch on the attack hooks. With no arguments
it uses ``config/election.json`` and casts 20 ballots.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

# --- Bootstrapping the import graph ------------------------------------
# ``crypto/__init__.py`` puts its own directory on sys.path so the modules
# inside it can keep their absolute imports (``from group import ...``). We
# import ``crypto`` first purely for that side effect.
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import crypto  # noqa: F401  (import for sys.path side effect)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one election end to end.")
    parser.add_argument("--config", default="config/election.json",
                        help="Path to election configuration JSON.")
    parser.add_argument("--ballots", type=int, default=20,
                        help="Number of ballots to cast (test run).")
    parser.add_argument("--out-dir", default="out",
                        help="Directory to write board.json / signatures.json.")
    parser.add_argument("--seed-offset", type=int, default=0,
                        help="Vary ballot selections without changing the "
                             "election setup seed (tests only).")
    parser.add_argument("--stuff", type=int, default=0,
                        help="Ballot stuffing: append N ballots no voter cast.")
    parser.add_argument("--redirect-to", type=int, default=None,
                        help="Vote redirection: encrypt this candidate index instead of the voter's choice.")
    parser.add_argument("--authority-seed", type=int, default=None,
                        help="Reproducible testing-authority seed (simulation only); "
                             "default draws 32 bytes from the OS.")
    parser.add_argument("--redirect-serials", type=str, default=None,
                        help="Comma-separated serials to redirect, each to the next "
                             "candidate after the voter's choice (harness full runs).")
    parser.add_argument("--verify-spoils", action="store_true",
                        help="Assert every spoil record round-trips (SPEC 11).")
    parser.add_argument("--verify-tally", type=str, default=None,
                        help="JSON dict {candidate_index: expected} to assert.")
    parser.add_argument("--force-sign", action="store_true",
                        help="Sign even if the tally does not match the register (stuffing runs).")
    parser.add_argument("--malform", action="store_true",
                        help="Malformed ballot injection: add one ballot with a forged validity proof.")
    parser.add_argument("--tamper-tally", action="store_true",
                        help="Tally manipulation: declare a tally that does not match the aggregate.")
    parser.add_argument("--retroactive-edit", action="store_true",
                        help="Retroactive board edit: change a ballot record after signing.")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    banner("Cryptographic Audit Framework - integrated pipeline")

    # -------- 1. Load configuration ----------------------------------
    from app.services.election_loader import load_election_config
    print(f"[1] Loading configuration: {args.config}")
    cfg = load_election_config(args.config)
    print(f"    election_id     : {cfg.election_id}")
    print(f"    booth_id        : {cfg.booth_id}")
    print(f"    candidates (m)  : {cfg.candidate_count}")
    print(f"    trustees (n, t) : ({cfg.trustees_n}, {cfg.trustees_t})")
    print(f"    authorities k/N : ({cfg.agent_k}, {cfg.agents})")
    print(f"    test rate       : {cfg.test_rate_num}/{cfg.test_rate_den}")
    print(f"    ballots_expected: {cfg.ballots_expected}")
    print(f"    seed            : {cfg.seed}")

    # -------- 2. Initialise election ---------------------------------
    from app.services.poll_state import PollState
    from app.services.ballot_service import BallotService
    print("[2] Initialising election (trusted dealer, authority keys, base hash Q)")
    poll_state = PollState()
    service = BallotService(cfg, poll_state)
    print(f"    pk              : {service.trustee_setup.pk.bit_length()}-bit public key")
    print(f"    base hash Q     : {service.Q.hex()[:32]}...")

    # The testing authority generates the schedule seed off the machine
    # (testing_authority.py) and gives the machine only the commitment T.
    from testing_authority import TestingAuthority, seed_from_int
    authority = TestingAuthority(
        service.Q, cfg.booth_id, cfg.test_rate_num, cfg.test_rate_den,
        cfg.ballots_expected,
        seed=None if args.authority_seed is None else seed_from_int(args.authority_seed),
    )
    service.load_schedule_commitment(authority.commitment)
    print(f"    schedule commit : {authority.commitment[:32]}...  (from the testing authority)")

    # -------- Attack hooks (optional) --------------------------------
    if args.redirect_to is not None:
        service.attack_config.vote_redirection_enabled = True
        service.attack_config.redirect_to_index = int(args.redirect_to)
        print(f"    ATTACK          : vote redirection ON -> index {args.redirect_to}")
    if args.stuff > 0:
        service.attack_config.ballot_stuffing_enabled = True
        service.attack_config.stuffed_count = int(args.stuff)
        print(f"    ATTACK          : ballot stuffing ON  -> {args.stuff} extra")

    # -------- 3. Publish pre-poll section ----------------------------
    print("[3] Publishing pre-poll commitments (K_s per serial, schedule commitment T)")
    service.publish_pre_poll_commitments()

    # -------- 4. Open poll -------------------------------------------
    print("[4] Opening poll")
    poll_state.open_poll()

    # -------- 5. Cast ballots ----------------------------------------
    ballots_to_cast = min(int(args.ballots), cfg.ballots_expected)
    # Deterministic per-ballot voter choices so ``--verify-tally`` can
    # assert an expected result.
    voter_rng = random.Random(cfg.seed ^ 0xDECAFBAD ^ args.seed_offset)
    # The tester challenges exactly the serials the committed schedule
    # drew (SPEC 10.2), no more and no fewer. A spoil on any other serial,
    # or a scheduled serial left unchallenged, is a P3 failure.
    spoil_serials = {s for s in authority.schedule
                     if 1 <= s <= ballots_to_cast}
    print(f"[5] Casting {ballots_to_cast} ballots "
          f"({len(spoil_serials)} scheduled for challenge: {sorted(spoil_serials)})")
    # SPEC 11.1: the tester's own record of what they pressed on each
    # challenged ballot. Never written to the board.
    tester_selections: Dict[int, int] = {}

    intended_tally: Counter[int] = Counter()
        # ---- Malformed ballot injection -----------------------------
    if args.malform:
        print("    ATTACK        : injecting a malformed ballot before the cast loop")
        import random as _random
        from crypto.encrypt_and_prove import encrypt_and_prove as _eap
        from crypto.record import build_ballot_record
        from board import board as _bb
        malformed_serial = 999999
        _r = [1 + (i * 7919) % (10**6) for i in range(cfg.candidate_count)]
        _cts, _vps, _sp = _eap(
            candidate_index=0, r_vector=_r, Q=service.Q,
            booth_id=cfg.booth_id, ballot_serial=malformed_serial,
            pk=service.trustee_setup.pk, m=cfg.candidate_count,
            rng=_random.Random(0xDEADBEEF),
        )
        # Forge: flip one hex nibble in the first proof's c0.
        # ValidityProof is a frozen dataclass, so mutate via dataclass.replace.
        from dataclasses import replace as _replace
        _proof = _vps[0]
        _c0_hex = format(_proof.c0, "x")
        _flipped_hex = ("f" if _c0_hex[0] != "f" else "0") + _c0_hex[1:]
        _flipped_int = int(_flipped_hex, 16)
        _vps[0] = _replace(_proof, c0=_flipped_int)
        mal_record = build_ballot_record(
            booth_id=cfg.booth_id, ballot_serial=malformed_serial,
            m=cfg.candidate_count, ciphertexts=_cts,
            validity_proofs=_vps, sum_proof=_sp,
        )
        _bb.append_ballot(service.board, mal_record)
        args.force_sign = True
 
    redirect_serials = ({int(x) for x in args.redirect_serials.split(",") if x}
                        if args.redirect_serials else set())
    for serial in range(1, ballots_to_cast + 1):
        session = poll_state.begin_ballot()
        assert session.serial == serial, (
            f"serial mismatch: got {session.serial}, expected {serial}"
        )
        chosen = voter_rng.randrange(cfg.candidate_count)
        poll_state.mark_selection(chosen)
        poll_state.confirm_selection()

        if redirect_serials:
            # Targeted redirection: only the listed serials, each to a different candidate.
            service.attack_config.vote_redirection_enabled = serial in redirect_serials
            service.attack_config.redirect_to_index = (chosen + 1) % cfg.candidate_count

        artifacts = service.encrypt_and_prove(chosen)

        if serial in spoil_serials:
            # SPEC section 11: spoil this serial. Do NOT count it.
            tester_selections[serial] = chosen
            service.append_spoil(artifacts, artifacts.candidate_index)
            poll_state.spoil_current_ballot()
        else:
            service.append_ballot(artifacts)
            # ``artifacts.candidate_index`` is what was ACTUALLY encrypted
            # (may differ from ``chosen`` under redirection), which is what the
            # decryption will recover.
            intended_tally[artifacts.candidate_index] += 1
        poll_state.finish_ballot()

        if serial % max(1, ballots_to_cast // 10) == 0:
            print(f"    ... cast {serial}/{ballots_to_cast}")

    # -------- 6. Close poll ------------------------------------------
    print("[6] Closing poll: revealing schedule seed, writing poll register")
    service.reveal_schedule_and_publish_register(authority.reveal())
    reg = poll_state.poll_register()
    print(f"    ballots_issued  : {reg['ballots_issued']}")
    print(f"    ballots_spoiled : {reg['ballots_spoiled']}")
    print(f"    ballots_counted : {reg['ballots_counted']}")

    if args.verify_spoils:
        print("    verifying every spoil record ...")
        bad = []
        for sp in service.board.get("spoils", []):
            if not service.verify_spoil_record(sp):
                bad.append(sp["ballot_serial"])
        if bad:
            print(f"    !! spoil records that did NOT round-trip: {bad}")
            return 2
        print(f"    all {len(service.board.get('spoils', []))} "
              f"spoil records round-tripped (SPEC section 11 sanity check)")

    # -------- 7. Aggregate per-candidate -----------------------------
    from tally.threshold import (
        aggregate_ciphertexts, threshold_decrypt,
        build_decryption_transcript,
    )
    from crypto.elgamal import recover_exponent
    from crypto.record import hex384

    print("[7] Aggregating counted ballots per candidate (SPEC 13.1)")
    columns = service.valid_ballots_ciphertexts()

    # -------- 8+9. Threshold decrypt + recover -----------------------
    from tally.trustees import choose_decryption_subset
    subset = choose_decryption_subset(service.trustee_setup)
    print(f"[8] Threshold decryption with trustee subset {subset} "
          f"(t={service.trustee_setup.t})")

    aggregates: List[Dict[str, str]] = []
    tally: Dict[int, int] = {}
    transcript_partials: List[dict] = []
    lagrange_by_str: Dict[str, str] = {}

    # A deterministic RNG for the decryption proofs so runs are reproducible.
    proof_rng = random.Random(cfg.seed ^ 0xBEEFCAFE)

    for i, column in enumerate(columns):
        if not column:
            # No ballots for candidate i -> aggregate = encryption of 0
            # under r = 0 (SPEC section 13.1). Still needs a transcript.
            A_i, B_i = 1, 1
            aggregates.append({
                "candidate_index": i,
                "alpha": hex384(A_i),
                "beta": hex384(B_i),
            })
            tally[i] = 0
            continue

        A_i, B_i = aggregate_ciphertexts(column)
        aggregates.append({
            "candidate_index": i,
            "alpha": hex384(A_i),
            "beta": hex384(B_i),
        })

        g_to_T = threshold_decrypt(
            (A_i, B_i),
            service.trustee_setup.shares,
            subset,
        )
        # Bound: no candidate can receive more votes than the total counted.
        bound = max(1, reg["ballots_counted"])
        tally[i] = recover_exponent(g_to_T, bound)

        # Build the decryption transcript for this candidate column.
        per_candidate = build_decryption_transcript(
            trustee_shares=service.trustee_setup.shares,
            trustee_commitments=service.trustee_setup.commitments,
            subset=subset,
            candidate_index=i,
            aggregate_ciphertext=(A_i, B_i),
            Q=service.Q,
            rng=proof_rng,
        )
        # The transcript's `lagrange_coefficients` and `subset` are the
        # same for every candidate; capture them once.
        lagrange_by_str.update(per_candidate["lagrange_coefficients"])
        transcript_partials.extend(per_candidate["partials"])

    # -------- 10. Append tally aggregate + transcript + declaration --
    from board import board as bb
    print("[10] Appending tally_aggregate, decryption_transcript, tally_declaration")
    service.board["tally_aggregate"] = {
        "record_type": "tally_aggregate",
        "columns": aggregates,
    }
    bb.append_decryption_transcript(
        service.board,
        subset=sorted(subset),
        lagrange_coefficients=lagrange_by_str,
        partials=transcript_partials,
    )
    tally_by_id: Dict[str, int] = {}
    for c in cfg.candidates:
        tally_by_id[c.candidate_id] = tally.get(c.index, 0)
    service.board["tally_declaration"] = {
        "record_type": "tally_declaration",
        "totals": [
            {"candidate_index": c.index,
             "candidate_id": c.candidate_id,
             "votes": tally.get(c.index, 0)}
            for c in cfg.candidates
        ],
    }

        # ---- Tally manipulation -------------------------------------
    if args.tamper_tally:
        print("    ATTACK        : tally declaration altered (adding 100 to CAND-A)")
        service.board["tally_declaration"]["totals"][0]["votes"] += 100
        args.force_sign = True

    print("    per-candidate tally:")
    for c in cfg.candidates:
        marker = " " if tally.get(c.index, 0) == intended_tally.get(c.index, 0) else "!"
        print(f"      {marker} {c.candidate_id:<10} index={c.index} "
              f"votes={tally.get(c.index, 0)}  "
              f"(intended {intended_tally.get(c.index, 0)})")
    print(f"    sum of votes = {sum(tally.values())}  "
          f"(should equal ballots_counted = {reg['ballots_counted']})")

    if sum(tally.values()) != reg["ballots_counted"]:
        print("    !! tally does not sum to ballots_counted.")
        if not args.force_sign:
            print("       refusing to sign (use --force-sign to override).")
            return 3
        print("       signing anyway because --force-sign was passed.")

    if args.verify_tally:
        expected = json.loads(args.verify_tally)
        # Cast expected keys to int.
        expected = {int(k): int(v) for k, v in expected.items()}
        if expected != {int(k): int(v) for k, v in tally.items()}:
            print(f"    !! expected {expected} but recovered {dict(tally)}")
            return 4
        print("    tally matches --verify-tally payload")

    # -------- 11. Digest, sign, export -------------------------------
    print("[11] Computing board digest, multisignature, exporting")
    board_out = out_dir / "board.json"
    sig_out = out_dir / "signatures.json"

    bb.write_board(service.board, str(board_out))

    from board.digest import compute_board_digest
    from board.signature import (
        create_signature_message, sign_message,
        create_signature_file, write_signature_file,
    )
    digest_hex = compute_board_digest(service.board)
    msg = create_signature_message(digest_hex)
    officer_sig = sign_message(service._authority_privates["officer"], msg)
    agent_sigs = [
        sign_message(priv, msg)
        for priv in service._authority_privates["agents"]
    ]
    sigfile = create_signature_file(digest_hex, officer_sig, agent_sigs)
    write_signature_file(sigfile, str(sig_out))
        # ---- Retroactive board edit ---------------------------------
    if args.retroactive_edit:
        print("    ATTACK        : a ballot record changed after signing")
        if service.board["ballots"]:
            b0 = service.board["ballots"][0]
            a = b0["ciphertexts"][0]["alpha"]
            b0["ciphertexts"][0]["alpha"] = ("f" if a[0] != "f" else "0") + a[1:]
            bb.write_board(service.board, str(board_out))
    # The machine's private attack log: for the evaluation harness only,
    # never bundled or exported.
    (out_dir / "private_attack_log.json").write_text(
        json.dumps(service.private_log.entries, indent=2) + "\n")
    tester_out = out_dir / "tester_selections.json"
    tester_out.write_text(json.dumps(
        {str(k): v for k, v in sorted(tester_selections.items())}, indent=2) + "\n")
    print(f"    digest          : {digest_hex}")
    print(f"    board written   : {board_out}")
    print(f"    sigs written    : {sig_out}")
    print(f"    tester record   : {tester_out} (SPEC 11.1, not part of the board)")

    # Verify the exported files contain no forbidden material.
    print("[12] Verifying export contains no secrets (board.export.scan_for_secrets)")
    from board.export import export_files, scan_for_secret_values
    export_files(str(board_out), str(sig_out))
    spoiled = {sp["ballot_serial"] for sp in service.board.get("spoils", [])}
    shares = service.trustee_setup.shares
    shares = shares.values() if isinstance(shares, dict) else shares
    secret_hex = [
        format(share if isinstance(share, int) else share[-1], "x") for share in shares
    ] + [
        service.pre_poll_nonces[s] for s in service.pre_poll_nonces if s not in spoiled
    ]
    scan_for_secret_values(str(board_out), secret_hex)

    banner("ELECTION COMPLETED SUCCESSFULLY")
    return 0


def banner(text: str) -> None:
    line = "=" * max(50, len(text) + 4)
    print(line)
    print(f"  {text}")
    print(line)


if __name__ == "__main__":
    sys.exit(main())
