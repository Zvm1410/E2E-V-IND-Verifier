# E2E-V-IND-Verifier

Basket D of the end-to-end verifiable voting audit framework: the independent
verifier (`verifier/`), the evaluation harness (`harness/`) and the result
tables (`results/`).

The verifier is written from `spec/SPEC.md` and `spec/vectors/` only. It never
imports from, and is never written by reading, `crypto/` or `tally/`
(handbook section 1.2, enforced by `tests/test_independence.py`).

## Setup

```
python3 -m venv .venv          # Python 3.11 or later
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Running it

```
python -m verifier board.json signatures.json [--tester tester_selections.json]
```

The full test suite takes about 15 minutes, mostly 3072-bit exponentiations
in the end-to-end board runs (`tests/test_d7_attribution.py`).

## Other directories

- `pipeline/`: fixes to the group repository's machine and integration code
  (not `crypto/` or `tally/`) so its boards meet SPEC revision 3, and
  `make_bundles.sh` to regenerate all seven bundles. See `pipeline/README.md`.
- `harness/`: the evaluation. `sim.py` (D8), `sweep.py` (D9), `full_runs.py`
  (D10, the full-crypto check of the fast model, and attribution on real
  bundles), `tables.py` (D11), `bench.py` (A11 on the Pi), `stats.py` (Wilson).
- `results/`: sweep output and `tables.md`.
- `vendor/b10/`, `vendor/a10/`: B's C0 baseline and A's adversary classes, unmodified.

## Progress

| Task | What | Status |
|---|---|---|
| D2 | Arithmetic, encoding, subgroup and range checks, strict parser | done; every exported board parses strictly under SPEC revision 3 |
| D3 | Validity proof verification (SPEC 8.3) | done; every proof on the clean, A8 and A9 boards verifies |
| D3b | Sum-to-one verification (SPEC 9.3) | done |
| D4 | Aggregate and decryption transcript (SPEC 13) | done; partial-proof preimages byte-exact against decryption.json; C10 rejected as P5 |
| D5 | Digest, signatures, register cross-check (SPEC 12, 15) | done; C11 rejected as P1, A9 as P4 |
| D6 | Spoil records and test schedule (SPEC 10, 11) | done against SPEC; C's boards fail (pre-poll commitments, see below) |
| D7 | Property attribution P1 to P5 (SPEC 16) | done; all six attributions correct with the pre-poll section corrected; awaiting regenerated boards |
| D8 | Harness: one simulated election (`harness/sim.py`) | done; SPEC 10.2 schedule, A's adversaries unmodified (vendor/a10) |
| D9 | Repeated-election sweep with Wilson intervals (`harness/sweep.py`) | done; 234 cells x 2000 runs; both sanity checks pass |
| D10 | Clean-mode false rejection (`harness/full_runs.py --clean`) | script ready; runs on the machine with crypto/ |
| D11 | Result tables (`harness/tables.py` -> `results/tables.md`) | done for simulated results; full-crypto and Pi cells fill in when run |

## Findings, and what was done about them

1. **Board schema.** SPEC 14 revised to the exported field names (SPEC
   revision 3, item 2); the parser is strict against it.
2. **Pre-poll commitments.** The machine computed `K_s` without the label
   and Q, set `T = SHA-256(seed)`, drew the schedule by a different rule,
   and topped spoils up with unscheduled serials, so P3 failed on every
   board. Fixed in `pipeline/`; boards to be regenerated.
3. **Published nonces.** Every exported board carried each serial's secret
   nonce in `prepoll` as `nonce_commitment` (handbook C9). Removed in
   `pipeline/`; the verifier rejects any pre-poll nonce under P1, and the
   exporter now scans values, not just key names.
4. **Tester record.** SPEC 11.1: the tester compares at the booth; the
   harness, or `--tester`, supplies the selections. Without them a
   redirection opened truthfully is not detectable from the board.
5. **Benchmark stub.** The GUI's A11 benchmark timed SHA-256 and invented
   proof times and memory. Replaced for the paper by `harness/bench.py`.

### Attribution on the revision 2 boards with the pre-poll section corrected

`tests/test_d7_spec10_rebuilt.py` keeps every real record on the exported
boards, drops the leaked nonces and rebuilds only K_s, the schedule seed
and T to SPEC 10:

| Board | Expected | Verifier |
|---|---|---|
| clean | Accept | Accept, P1 to P5 passed |
| A8 redirection | P3 | P3, tester selected 4, machine opened 5 |
| A9 stuffing | P4 | P4, with P3 passed |
| B12 malformed | P2 | P2 |
| C10 tally manipulation | P5 | P5, with P1 to P4 passed |
| C11 retroactive edit | P1 | P1 |

`tests/test_e2e_regenerated.py` runs the same table, plus C1, on the
regenerated boards once they are in `tests/fixtures/boards-r3/`.
