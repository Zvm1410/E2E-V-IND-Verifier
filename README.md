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

## Progress

| Task | What | Status |
|---|---|---|
| D2 | Arithmetic, encoding, subgroup and range checks, strict parser | done against SPEC; C's clean board differs from SPEC 14 in four fields (see tests/test_d2_board.py); waits on ballot.json and negative.json vectors |
| D3 | Validity proof verification (SPEC 8.3) | |
| D3b | Sum-to-one verification (SPEC 9.3) | |
| D4 | Aggregate and decryption transcript (SPEC 13) | |
| D5 | Digest, signatures, register cross-check (SPEC 12, 15) | |
| D6 | Spoil records and test schedule (SPEC 10, 11) | |
| D7 | Property attribution P1 to P5 (SPEC 16) | |
| D8 to D11 | Harness, repeated elections, false rejection, tables | |
