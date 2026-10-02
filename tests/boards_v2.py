"""Access to the boards in tests/fixtures/boards-v2.

Those boards are in the SPEC revision 2 format, which carried every
serial's secret nonce as `nonce_commitment`; the verifier rejects them for
it under P1. Tests that need their cryptographic material (proofs, spoils,
transcripts) parse them with that one field removed. Raw-byte checks
(digest, signatures) use the files as they are."""

import copy

from verifier.parse import parse_board


def strip_nonces(obj):
    b = copy.deepcopy(obj)
    for entry in b.get("prepoll", {}).get("randomness_commitments", []):
        if isinstance(entry, dict):
            entry.pop("nonce_commitment", None)
    return b


def parse_v2(obj):
    return parse_board(strip_nonces(obj))
