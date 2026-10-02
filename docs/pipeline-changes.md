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
| `run_election.py` | Spoils exactly the scheduled serials; `--spoils` removed | The old code topped the schedule up with random serials, which is a spoil the schedule never drew (P3). |
| | Writes `tester_selections.json` | SPEC 11.1: the tester's record of what they pressed on each challenged ballot. Not part of the board. |
| | Runs a value-based secrets scan on the export | Handbook C9. |
| `board/export.py` | `scan_for_secret_values` | The old scan only checked key names, so a secret under an ordinary key (as the nonce was) passed. |
| `bundle_for_basket_d.py` | Copies the tester record into the bundle; README text matches SPEC | The old README described P3 to P5 differently from SPEC 16. |
| `config/election_c1.json` | `test_rate.num = 0` | Configuration C1 (handbook C12). |
| `make_bundles.sh` | Builds all seven bundles | One command for the clean run, five attacks and C1. |

## Regenerating the bundles

From the project root:

```
./make_bundles.sh          # BALLOTS=60 by default
```

This writes `for-basket-d-<tag>.tar.gz` for clean, A8, A9, B12, C10, C11
and C1. At a 1/20 test rate, 60 ballots gives about three scheduled test
ballots per run.
