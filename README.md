# E2E-V-IND-Verifier

Cryptographic audit framework for end-to-end verifiable voting on air-gapped
electronic voting machines, with an independently written verifier and the
evaluation reported in the paper.

A vote is a vector of exponential-ElGamal ciphertexts over the 3072-bit RFC
3526 group, one per candidate, each with a Cramer-Damgard-Schoenmakers proof
that it encrypts 0 or 1 and a Chaum-Pedersen proof that the vector sums to
one. The machine commits to every ballot's randomness before the poll opens,
and an off-machine testing authority commits to a test schedule; scheduled
ballots are challenged and opened, which is what catches a machine that
redirects votes. Trustees decrypt only the per-candidate aggregates, with
proofs. Everything is published on a signed bulletin board that the verifier
checks property by property.

The normative description is [`spec/SPEC.md`](spec/SPEC.md).

## Layout

| Path | Contents |
|---|---|
| `spec/` | The specification and its test vectors |
| `app/` | Voting machine: kiosk GUI, configuration loader, ballot service, attack hooks, fingerprinting adversaries |
| `crypto/` | Group, encoding, exponential ElGamal, validity and sum-to-one proofs, `encrypt_and_prove`, base hash |
| `tally/` | Trusted dealer, Shamir sharing, threshold decryption, decryption proofs |
| `board/` | Bulletin board, digest, Ed25519 multisignature, export checks |
| `testing_authority.py` | Off-machine holder of the test-schedule seed (SPEC 10.2) |
| `run_election.py` | One election end to end, with the attack hooks as flags |
| `export_bundle.py`, `make_bundles.sh` | Package one election; build every evaluation scenario |
| `verifier/` | Independent verifier: properties P1 to P5, with attribution |
| `baseline/` | C0: detection probability of post-election paper audits |
| `harness/` | Evaluation: simulated elections, sweep, full-crypto runs, tables, hardware benchmark |
| `results/` | Evaluation output and `tables.md` |
| `tests/` | Verifier and harness tests; boards in `tests/fixtures/` |
| `scripts/` | Sanity scripts for the attack hooks; the verifier independence check |
| `docs/pi-benchmark.md` | How to run the hardware benchmark |

## Verifier independence

`verifier/` never imports from, and was not written from, `crypto/` or
`tally/`. It was built from the specification, the test vectors and exported
boards, and completed before the prover's cryptography entered this
repository. [`INDEPENDENCE.md`](INDEPENDENCE.md) gives the commit and file
hashes; `python scripts/check_verifier_unchanged.py` shows the verifier's
logic has not changed since, and `tests/test_independence.py` enforces the
import rule on every test run.

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

`run_election.py` takes `--redirect-to N` (vote redirection), `--stuff N`
(ballot stuffing), `--malform` (malformed ballot), `--tamper-tally` (tally
manipulation), `--retroactive-edit` (board edited after signing), and
`--config config/election_c1.json` for configuration C1 (no test ballots).
The verifier prints `Accept`, or `Reject` with the failing property and
record, and the state of each of P1 to P5: passed, failed, not exercised or
not checked.

`./make_bundles.sh` builds all seven scenarios: a clean election, one per
attack, and C1.

## Evaluation

```
python -m harness.sweep                                   # 234 cells x 2000 simulated elections
python -m harness.full_runs --clean 30 --redirect 30      # false rejection and the fast-model check, real crypto
python -m harness.full_runs --attribution .               # attribution on the seven bundles
python -m harness.tables                                  # results/tables.md
python -m harness.bench --ballots 500                     # hardware benchmark (docs/pi-benchmark.md)
```

`harness/sim.py` describes what the fast election model simulates, and why
the full-crypto runs are the check on it.

| Configuration | Detection mechanism |
|---|---|
| C0 | Post-election paper audit: cluster sampling of polling stations, or simple random sampling at the same rate |
| C1 | Full cryptographic pipeline and verifier, no test ballots |
| C2 | C1 plus scheduled test ballots at rate p |

| Adversary | Decides which ballots to manipulate from |
|---|---|
| A0 | Nothing (blind) |
| A1 | Elapsed time and ballot position |
| A2 | Selection-to-confirmation time and input device |
| A3 | A leaked copy of the schedule, partly correct |
| AOracle | The true schedule (calibration) |

## Tests

```
pytest -n 4            # unit and integration tests, about 9 minutes on 4 cores
pytest -m slow -n 4    # also verify all seven 60-ballot boards end to end
```
