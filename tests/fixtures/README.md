# Test fixtures

`boards/` holds one bundle per scenario, produced by `make_bundles.sh`: a
clean election, one election per attack (vote redirection, ballot stuffing,
malformed ballot, tally manipulation, retroactive board edit) and
configuration C1. Each directory has the board, its signature file, the
configuration and the tester's record. `tests/test_end_to_end.py` verifies
all seven.

`boards-v2/` holds the same scenarios in the earlier SPEC revision 2
format. That format published every serial's secret nonce and committed to
the schedule differently, so these boards are rejected under P1. They are
kept as negative fixtures, and the unit tests use their ballots, proofs,
spoil openings and decryption transcripts as real cryptographic material
(`tests/boards_v2.py`).
