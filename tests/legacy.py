"""The board fixtures in tests/fixtures/boards were exported before SPEC
revision 3 removed `nonce_commitment`, which carried every serial's secret
nonce. The verifier rejects them for it under P1. Tests that need their
real cryptographic material (proofs, spoils, transcripts) parse them with
that one field removed. Raw-byte checks (digest, signatures) still use
the files exactly as exported."""

import copy

from verifier.parse import parse_board


def strip_nonces(obj):
    b = copy.deepcopy(obj)
    for entry in b.get("prepoll", {}).get("randomness_commitments", []):
        if isinstance(entry, dict):
            entry.pop("nonce_commitment", None)
    return b


def parse_legacy(obj):
    return parse_board(strip_nonces(obj))
