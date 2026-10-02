"""D7: the verifier entry point, with property attribution (SPEC 16).

Properties run in the order P1, P2, P3, P4, P5 and the first failure is
reported with the record that caused it. Each property ends in one of:
passed, failed, not_exercised (P3 under configuration C1), or not_checked
(an earlier property failed, so this one was never reached).
"""

from dataclasses import dataclass, field

from verifier.compat import normalise_c_export
from verifier.group import verify_group_parameters
from verifier.integrity import check_ballot_count, check_parameters, check_signed_digest
from verifier.parse import (
    ParseError,
    load_json,
    parse_authority_keys,
    parse_board,
    parse_signatures,
)
from verifier.proofs import ProofFailure, verify_ballot
from verifier.result import PROPERTIES, CheckFailure
from verifier.spoils import check_cast_as_intended
from verifier.tally import check_tally

PASSED, FAILED, NOT_EXERCISED, NOT_CHECKED = "passed", "failed", "not_exercised", "not_checked"


@dataclass
class Result:
    properties: dict = field(default_factory=lambda: {p: NOT_CHECKED for p in PROPERTIES})
    failure: CheckFailure = None

    @property
    def accepted(self):
        return self.failure is None

    @property
    def failed_property(self):
        return self.failure.prop if self.failure else None

    def summary(self):
        lines = ["Accept" if self.accepted else f"Reject: {self.failure}"]
        lines += [f"  {p}: {state.replace('_', ' ')}" for p, state in self.properties.items()]
        return "\n".join(lines)


def _parse_property(path):
    """Which property a malformed record belongs to."""
    if path.startswith("ballots"):
        return "P2"
    if path.startswith("spoils"):
        return "P3"
    return "P1"


def _run(result, board_bytes, signature_bytes, compat, tester_selections):
    try:
        obj = load_json(board_bytes)
        signatures = parse_signatures(load_json(signature_bytes))
        if not isinstance(obj, dict) or "authority_keys" not in obj:
            raise ParseError("authority_keys", "missing")
        keys = parse_authority_keys(obj["authority_keys"])
    except ParseError as exc:
        raise CheckFailure("P1", exc.path, exc.reason) from exc
    check_signed_digest(board_bytes, obj, keys, signatures)

    obj = normalise_c_export(obj) if compat else obj
    try:
        # P1's own records first, with ballots and spoils held back, so a
        # malformed ballot is attributed to P2 only after P1 has passed.
        check_parameters(parse_board(dict(obj, ballots=[], spoils=[])))
    except ParseError as exc:
        raise CheckFailure(_parse_property(exc.path), exc.path, exc.reason) from exc
    result.properties["P1"] = PASSED
    try:
        board = parse_board(obj)
    except ParseError as exc:
        raise CheckFailure(_parse_property(exc.path), exc.path, exc.reason) from exc

    pk = board.trustee_setup.public_key
    for n, ballot in enumerate(board.ballots):
        try:
            verify_ballot(board.base_hash, pk, ballot)
        except ProofFailure as exc:
            where = getattr(exc, "candidate_index", None)
            record = f"ballots[{n}] (serial {ballot.ballot_serial})"
            record += f" validity_proofs[{where}]" if where is not None else " sum_proof"
            raise CheckFailure("P2", record, str(exc)) from exc
    result.properties["P2"] = PASSED

    result.properties["P3"] = check_cast_as_intended(board, tester_selections)
    check_ballot_count(board)
    result.properties["P4"] = PASSED
    check_tally(board)
    result.properties["P5"] = PASSED


def verify(board_bytes, signature_bytes, compat=False, tester_selections=None):
    """Verify one exported board. Never raises on a bad board; the outcome
    is in the returned Result."""
    result = Result()
    try:
        _run(result, board_bytes, signature_bytes, compat, tester_selections)
    except CheckFailure as exc:
        result.failure = exc
        result.properties[exc.prop] = FAILED
    return result


def main(argv=None):
    import argparse
    import pathlib
    import sys

    ap = argparse.ArgumentParser(description="Independent verifier (basket D).")
    ap.add_argument("board", type=pathlib.Path)
    ap.add_argument("signatures", type=pathlib.Path)
    ap.add_argument("--compat", action="store_true",
                    help="accept C's current field names (see verifier/compat.py)")
    args = ap.parse_args(argv)
    verify_group_parameters()
    result = verify(args.board.read_bytes(), args.signatures.read_bytes(), compat=args.compat)
    print(result.summary())
    sys.exit(0 if result.accepted else 1)
