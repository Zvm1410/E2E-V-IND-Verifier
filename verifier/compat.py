"""Opt-in mapping from C's current board export to SPEC 14 field names.

C's exporter differs from SPEC 14 in four places (tests/test_d2_board.py).
Until the group settles each one in SPEC.md, the verifier can be run with
compat=True, which applies exactly these renames and nothing else. A strict
run (the default) rejects C's board.
"""

import copy


def normalise_c_export(board):
    b = copy.deepcopy(board)
    # SPEC 14 wants the 5.1 config verbatim; C omits the simulation seed,
    # which the verifier never uses (it drives the prover's draws).
    b.get("election_config", {}).setdefault("seed", 0)
    ts = b.get("trustee_setup", {})
    if "pk" in ts and "public_key" not in ts:
        ts["public_key"] = ts.pop("pk")
    ts.setdefault("record_type", "trustee_setup")
    for r in b.get("prepoll", {}).get("randomness_commitments", []):
        if isinstance(r, dict):
            r.pop("nonce_commitment", None)
    td = b.get("tally_declaration", {})
    if "totals" in td and "counts" not in td:
        td["counts"] = [{"candidate_index": t.get("candidate_index"), "count": t.get("votes")}
                        for t in td.pop("totals")]
    return b
