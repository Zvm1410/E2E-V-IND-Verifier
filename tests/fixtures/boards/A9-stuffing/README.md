# Bulletin board handover for Basket D

This bundle contains only what the independent verifier (Basket D)
consumes. No prover source code is included; per the project scope,
the verifier must be built without visibility into crypto/, tally/,
board/ or app/.

## Files

- **board.json** - the SPEC section 14 bulletin board. Twelve
  top-level keys, each with the shape agreed on Day 2 (see SPEC).
- **signatures.json** - officer + agent Ed25519 signatures over the
  32-byte-padded label `EVOTE-SIG-v1` concatenated with the SHA-256
  board digest.
- **election.json** - the election configuration. Used by the verifier
  only to recompute the base hash Q from its own implementation of
  the SPEC section 5.2 preimage, and to independently know
  `(n, t, agents, k, candidates)`.

## Verifier properties to check (in order)

Per the handbook (SPEC section 8.3 / verifier properties list):

1. **P1** - group parameters, base hash, encoding round-trips, subgroup
   membership of every element on the board.
2. **P2** - every ballot record is well-formed and every validity proof
   verifies against the base hash Q recomputed from `election.json`
   (not from `board.base_hash`).
3. **P3** - the test schedule opens correctly: `SHA-256(schedule_seed) ==
   test_schedule_commitment`, and every scheduled test serial appears
   as a spoil record.
4. **P4** - the pre-poll section holds one commitment per serial in
   `[1, ballots_expected]` and the schedule commitment; a board
   missing any serial fails here.
5. **P5** - the poll register is consistent with the board:
   `ballots_issued == count(ballots)`,
   `ballots_spoiled == count(spoils)`, and
   `ballots_counted == ballots_issued - ballots_spoiled`.

## Digest & signature check

```
digest = SHA-256( L("EVOTE-BOARD-v1")  ||  canonical_json(board_without_signature_fields) )
```

`canonical_json` = sorted keys, no whitespace, ASCII escaping, group
elements and exponents as 768-character lowercase hex strings.

`signatures.json` must show `k` valid agent signatures plus the officer
signature; `k-1` fails.
