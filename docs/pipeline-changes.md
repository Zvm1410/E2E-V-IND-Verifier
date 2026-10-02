# Prover-side fixes (SPEC revision 3)

Fixes to the machine and integration code (baskets A and C) so the boards
it produces satisfy SPEC revision 3. None touches `crypto/` or `tally/`.
These files first entered the repository under `pipeline/` exactly as
received (commit b2feb5e), so `git log -p --follow <file>` shows every change.

## What changed and why

| File | Change | Why |
|---|---|---|
| `app/services/ballot_service.py` | `K_s` now starts with `L("EVOTE-RCOMMIT-v1") \|\| Q` and puts `S32(booth_id)` before `U64(serial)` | SPEC 10.1. Without Q a commitment is not bound to this election. |
| | `T` is SPEC 10.2's 144-byte preimage, not `SHA-256(seed)` | Binds the rate, booth and election to the schedule. |
| | Schedule is SPEC 10.2's independent per-serial draw | The old hash walk picked a fixed count by a different rule, so the verifier could not recompute it. |
| | `nonce_commitment` removed from the pre-poll section | It held the raw secret nonce for every serial, published before the poll. Handbook C9 forbids exporting the nonce of an unspoiled ballot. |
| `testing_authority.py` (new) | Generates the schedule seed off the machine, gives the machine only T, gives the tester the schedule, reveals the seed at close | The machine drew the seed from the same deterministic source as the ballot randomness, so compromised firmware could compute the schedule (SPEC 10.2, revision 3 item 6). |
| `app/services/ballot_service.py` | No longer draws the seed or computes the schedule; `load_schedule_commitment(T)` before the poll, the revealed seed passed in at close | As above. |
| `app/ui/window.py` | Creates the testing authority, loads T, and publishes the pre-poll section at start-up | The GUI published the pre-poll section only at close of poll; SPEC 10 requires it before the first ballot. |
| `run_election.py` | Plays the testing authority (`--authority-seed` for reproducible runs); spoils exactly the scheduled serials; `--spoils` removed | The old code topped the schedule up with random serials, which is a spoil the schedule never drew (P3). |
| | Writes `tester_selections.json` | SPEC 11.1: the tester's record of what they pressed on each challenged ballot. Not part of the board. |
| | Runs a value-based secrets scan on the export | Handbook C9. |
| `board/export.py` | `scan_for_secret_values` | The old scan only checked key names, so a secret under an ordinary key (as the nonce was) passed. |
| `export_bundle.py` (was `bundle_for_basket_d.py`) | Copies the tester record into the bundle; describes the files only | The old README described P3 to P5 differently from SPEC 16. |
| `app/services/benchmark.py` | Real timings and the process's peak RSS | It reported an invented proof time (`cast_ms * 0.7`) and memory from `random.uniform`. |
| `app/ui/screens/admin_screen.py` | Challenge refused on unscheduled serials; the re-encryption check is actually run and its result shown; bundle labels renamed | The panel printed "re-encryption stub matches" without checking, and allowed spoils the schedule never drew. |
| `tally/c10.py`, `tally/c12.py` (removed) | Never imported. `c12.py` set the test rate to a bare 0 rather than the `num`/`den` pair the loader requires, and its `generate_test_schedule` returned `[]` or `None`; `c10.py` duplicated `run_election.py --tamper-tally` | One implementation each: C1 is `config/election_c1.json` with the schedule from `testing_authority.py`; C10 is `--tamper-tally`. |
| `config/election_c1.json` | `test_rate.num = 0` | Configuration C1 (handbook C12). |
| `make_bundles.sh` | Builds all seven bundles | One command for the clean run, five attacks and C1. |

## Regenerating the bundles

From the project root:

```
./make_bundles.sh          # BALLOTS=60 by default
```

This writes `bundle-<tag>/` and `bundle-<tag>.tar.gz` for clean, A8, A9, B12, C10, C11
and C1. At a 1/20 test rate, 60 ballots gives about three scheduled test
ballots per run.
