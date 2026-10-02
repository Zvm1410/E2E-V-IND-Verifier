# E2E-V-IND-Verifier

Cryptographic audit framework for end-to-end verifiable voting on air-gapped
electronic voting machines, with an independently written verifier and the
evaluation behind the paper.

A vote is a vector of exponential-ElGamal ciphertexts over the 3072-bit RFC
3526 group, one per candidate, each with a Cramer-Damgard-Schoenmakers proof
that it encrypts 0 or 1 and a Chaum-Pedersen proof that the vector sums to one.
The machine commits to every ballot's randomness before the poll opens, and
an off-machine testing authority commits to a test schedule; scheduled ballots are challenged and opened, which is
what catches a machine that redirects votes. Trustees decrypt only the
per-candidate aggregates, with proofs. Everything is published on a signed
bulletin board that a verifier checks property by property.

The normative description is [`spec/SPEC.md`](spec/SPEC.md) (revision 3).

## Layout

| Path | What | Basket |
|---|---|---|
| `spec/` | SPEC.md and test vectors | B and D |
| `app/` | Kiosk GUI, election loader, ballot service, attack hooks A8/A9, fingerprinting adversaries A10 | A |
| `crypto/` | Group, encoding, ElGamal, validity and sum proofs, `encrypt_and_prove`, base hash | B |
| `baseline/` | C0 paper-audit baseline (B10) | B |
| `tally/` | Trusted dealer, Shamir sharing, threshold decryption, decryption proofs | C |
| `board/` | Bulletin board, digest, Ed25519 multisignature, export checks | C |
| `run_election.py` | One election end to end, with the attack flags | C |
| `testing_authority.py` | Off-machine holder of the test-schedule seed (SPEC 10.2) | D |
| `export_bundle.py`, `make_bundles.sh` | Package and regenerate the evaluation boards | C, D |
| `verifier/` | Independent verifier, P1 to P5 with attribution | D |
| `harness/` | Simulated elections (D8), sweep (D9), full-crypto runs (D10), tables (D11), Pi benchmark | D |
| `results/` | Sweep output and `tables.md` | D |
| `tests/` | Verifier and harness tests; real boards in `tests/fixtures/` | D |
| `scripts/` | Basket A's attack-hook sanity scripts | A |
| `docs/pipeline-changes.md` | Fixes made to A's and C's code for SPEC revision 3 | D |

## The independence constraint

`verifier/` never imports from, and was not written from, `crypto/` or
`tally/`. It was built from SPEC.md, the test vectors and exported boards, and
frozen before the prover code entered this repository. See
[`INDEPENDENCE.md`](INDEPENDENCE.md) for the commit and the SHA-256 of every
verifier file at that point; `tests/test_independence.py` enforces the import
rule on every test run.

## Setup

```
python3 -m venv .venv           # Python 3.11 or later
source .venv/bin/activate
pip install -r requirements.txt
```

## Run an election and verify it

```
python run_election.py --ballots 40 --out-dir out
python -m verifier out/board.json out/signatures.json --tester out/tester_selections.json
```

`run_election.py` takes `--redirect-to N` (A8), `--stuff N` (A9), `--malform`
(B12), `--tamper-tally` (C10), `--retroactive-edit` (C11), and
`--config config/election_c1.json` for configuration C1. The verifier prints
`Accept`, or `Reject` with the failing property and record, and the state of
each of P1 to P5 (passed, failed, not exercised, not checked).

`./make_bundles.sh` regenerates all seven evaluation bundles.

## Evaluation

```
python -m harness.sweep                                   # D9: 234 cells x 2000 simulated elections
python -m harness.full_runs --clean 30 --redirect 30      # D10 and the fast-model check, real crypto
python -m harness.full_runs --attribution .               # D7 attribution on the seven bundles
python -m harness.tables                                  # D11: results/tables.md
python -m harness.bench --ballots 500                     # A11 on the Raspberry Pi
```

`harness/sim.py` explains what the fast model simulates and why the full
runs are the check on it.

## Tests

```
pytest                 # about 15 minutes, mostly 3072-bit exponentiations
```

## Status

| Task | State |
|---|---|
| Verifier D2 to D7 | Done. Every proof, decryption proof and signature on the exported boards verifies; attribution correct on all six boards with the pre-poll section corrected. |
| SPEC revision 3 | Board schema, removal of the published nonces, tester's comparison (11.1). |
| Prover fixes | Pre-poll commitments and schedule to SPEC 10, nonce leak, tester record, value-based export scan. See `docs/pipeline-changes.md`. |
| D8, D9, D11 | Done for simulated results; both D9 sanity checks pass. |
| D10, full-crypto check, attribution on regenerated boards | Done. 12 clean elections, 0 false rejections; 12 redirection runs, verifier agrees with the fast model on all 12 (3 detected); all seven bundles attributed correctly. |
| A11 benchmark | `harness/bench.py`; the GUI's admin-panel benchmark (`app/services/benchmark.py`) is a stub and is not used for the paper. |

## Findings recorded during the build

1. The exported board schema differed from SPEC 14; SPEC revised to match.
2. The machine's pre-poll commitments and test schedule did not follow
   SPEC 10, and spoils were topped up with unscheduled serials, so P3 failed
   on every board. Fixed in `app/services/ballot_service.py` and
   `run_election.py`.
3. Every revision 2 board published each serial's secret nonce before the
   poll. Removed; the verifier rejects it under P1, and the exporter now
   scans values as well as key names.
4. A redirecting machine that opens a challenged ballot truthfully is
   consistent on the board; only the tester's own record catches it (SPEC
   11.1). The verifier takes that record with `--tester`.
5. At equal sampling rates, test ballots and random-sample paper audits
   detect blind redirection at the same rate (Table 1). The advantage over
   current practice is against cluster audits of whole booths (Table 4),
   plus attribution and independence from the paper trail.
