# Test fixtures

`boards/` holds the six boards produced by the integrated pipeline before
SPEC revision 3: a clean run and one run per attack hook (A8, A9, B12, C10,
C11), each with its signature file and configuration. They carry real
ballots, proofs, spoil openings and decryption transcripts, which is why the
verifier tests use them, and they also carry the two defects revision 3
fixed: the pre-poll section publishes every serial's nonce, and the
commitments do not follow SPEC 10. As exported they are rejected under P1;
`tests/legacy.py` explains how the tests reach their cryptographic content.

`boards-r3/` (when present) holds the bundles regenerated with
`make_bundles.sh` after the fixes; `tests/test_e2e_regenerated.py` runs on them.
