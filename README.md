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
python -m verifier board.json signatures.json            # strict SPEC 14
python -m verifier board.json signatures.json --compat   # accept C's current field names
```

The full test suite takes about 15 minutes, mostly 3072-bit exponentiations
in the end-to-end board runs (`tests/test_d7_attribution.py`).

## Progress

| Task | What | Status |
|---|---|---|
| D2 | Arithmetic, encoding, subgroup and range checks, strict parser | done against SPEC; C's clean board differs from SPEC 14 in four fields (see tests/test_d2_board.py); waits on ballot.json and negative.json vectors |
| D3 | Validity proof verification (SPEC 8.3) | done; every proof on the clean, A8 and A9 boards verifies |
| D3b | Sum-to-one verification (SPEC 9.3) | done |
| D4 | Aggregate and decryption transcript (SPEC 13) | done; partial-proof preimages byte-exact against decryption.json; C10 rejected as P5 |
| D5 | Digest, signatures, register cross-check (SPEC 12, 15) | done; C11 rejected as P1, A9 as P4 |
| D6 | Spoil records and test schedule (SPEC 10, 11) | done against SPEC; C's boards fail (pre-poll commitments, see below) |
| D7 | Property attribution P1 to P5 (SPEC 16) | done; C11 named P1, B12 named P2; clean, A8, A9, C10 blocked on SPEC 10 |
| D8 to D11 | Harness, repeated elections, false rejection, tables | B10's C0 baseline vendored in vendor/b10 |

## Open findings against other baskets

1. **Board schema (C).** Four fields differ from SPEC 14: no `seed` in
   `election_config`, `pk` for `public_key` with no `record_type` in
   `trustee_setup`, an undocumented `nonce_commitment` in `prepoll`, and
   `totals`/`votes` for `counts`/`count` in `tally_declaration`.
   `--compat` maps these; the strict run rejects as P1.
2. **Pre-poll commitments (A, ingested by C).** On every board the test
   schedule commitment is `SHA-256(schedule_seed)`, not SPEC 10.2's T, and
   `K_s` is `SHA-256(U64(s) || S32(booth_id) || I2B(r_0..r_m-1) || nonce)`,
   SPEC 10.1 without the label and Q. Spoils sit on serials 6 and 7, where
   the SPEC 10.2 schedule over the issued serials is empty. P3 therefore
   fails on every board, including the clean one, and runs before P4 and
   P5, so A9 and C10 are not attributed correctly until the boards are
   regenerated.
3. **No C1 board.** "P3 not exercised" is tested on modified boards only.
4. **Tester record (spec gap).** A machine that redirects and then opens
   the challenged ballot truthfully is consistent on the board; only the
   tester's own record of what they pressed catches it. SPEC 11 does not
   say where that record lives. `verify(..., tester_selections=...)`
   accepts it.
