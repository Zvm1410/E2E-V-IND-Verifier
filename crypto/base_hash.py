"""
base_hash.py — SPEC.md v1 revision 2, section 5.2.

Computes the election base hash Q.

Q is 32 raw bytes: SHA-256 over a 4136-byte preimage (at the default
configuration m=6, n=5, a=4) that binds the group parameters, the election
identifier, the candidate list, the trustee set and the signing authorities.

Q appears as the second field of every challenge preimage in the system
(sections 8.2, 9.2, 10.1, 10.2, 13.2). A single wrong byte here does not fail
loudly: every proof still verifies against itself, and only fails when basket D
recomputes it. That is why the preimage length is asserted rather than trusted,
and why build_base_hash_preimage() is exposed separately from compute_base_hash().

Note on revision 2, change log item 1: the fixed part of the preimage is 1704
bytes, not 1696. The stale summary omitted U64(m). An implementation that
produces 4128 bytes at the default configuration is missing that field.

booth_id is deliberately NOT in Q. One election configuration may run at several
booths; booth_id is carried separately by each preimage that needs it.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence, Tuple

from encoding import I2B, B2I, U64, S32, S64, L

# Field widths from section 3, used by the length arithmetic below.
I2B_WIDTH = 384          # section 3.1: group elements AND exponents
LABEL_WIDTH = 32         # section 3.4
S32_WIDTH = 32           # section 3.3: booth_id
S64_WIDTH = 64           # section 3.3: election_id, candidate_id
U64_WIDTH = 8            # section 3.2
ED25519_PUBKEY_BYTES = 32

# --------------------------------------------------------------------------
# Section 5.2
# --------------------------------------------------------------------------

BASE_LABEL = "EVOTE-BASE-v1"

# 32 + 384 + 384 + 384 + 64 + 8 + 16 + 384 + 16 + 32
FIXED_PART_BYTES = 1704


def expected_preimage_length(m: int, n: int, a: int) -> int:
    """Section 5.2: 1704 + 64m + 384n + 32a."""
    return FIXED_PART_BYTES + S64_WIDTH * m + I2B_WIDTH * n + ED25519_PUBKEY_BYTES * a


def _check_pubkey(key: bytes, what: str) -> bytes:
    """Ed25519 public keys enter the preimage as 32 RAW bytes.

    The board publishes them as 64-character hex (section 6). Hashing the hex
    string would contribute 64 bytes per key and silently change Q, so a str is
    rejected outright rather than helpfully decoded.
    """
    if isinstance(key, str):
        raise TypeError(
            f"{what}: expected 32 raw bytes, got str. The 64-char hex form is the "
            f"board representation only (section 6); decode it before hashing."
        )
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"{what}: expected bytes, got {type(key).__name__}")
    if len(key) != ED25519_PUBKEY_BYTES:
        raise ValueError(
            f"{what}: Ed25519 public key must be {ED25519_PUBKEY_BYTES} bytes, "
            f"got {len(key)}"
        )
    return bytes(key)


def build_base_hash_fields(
    *,
    p: int,
    q: int,
    g: int,
    election_id: str,
    candidate_ids: Sequence[str],
    n: int,
    t: int,
    pk: int,
    trustee_commitments: Sequence[int],
    num_agents: int,
    k: int,
    officer_pubkey: bytes,
    agent_pubkeys: Sequence[bytes],
) -> List[Tuple[str, bytes]]:
    """Return the preimage as an ordered list of (field_name, bytes).

    Exposed separately from the concatenated preimage because section 17
    requires raw preimage bytes in every vector involving a hash: when a digest
    disagrees, the field map is what lets you find which field is wrong instead
    of diffing 4136 bytes by eye.
    """
    m = len(candidate_ids)
    if m == 0:
        raise ValueError("candidate list is empty")
    if len(trustee_commitments) != n:
        raise ValueError(
            f"trustee_commitments has {len(trustee_commitments)} entries, n={n}"
        )
    if len(agent_pubkeys) != num_agents:
        raise ValueError(
            f"agent_pubkeys has {len(agent_pubkeys)} entries, agents={num_agents}"
        )
    if not (1 <= t <= n):
        raise ValueError(f"threshold t={t} out of range for n={n}")
    if not (1 <= k <= num_agents):
        raise ValueError(f"k={k} out of range for agents={num_agents}")

    fields: List[Tuple[str, bytes]] = [
        ("label", L(BASE_LABEL)),
        ("p", I2B(p)),
        ("q", I2B(q)),
        ("g", I2B(g)),
        ("election_id", S64(election_id)),
        ("m", U64(m)),
    ]
    for i, cid in enumerate(candidate_ids):
        fields.append((f"candidate_id[{i}]", S64(cid)))
    fields.append(("n", U64(n)))
    fields.append(("t", U64(t)))
    fields.append(("pk", I2B(pk)))
    for j, h in enumerate(trustee_commitments):
        fields.append((f"h[{j + 1}]", I2B(h)))
    fields.append(("num_agents", U64(num_agents)))
    fields.append(("k", U64(k)))
    fields.append(("officer_pubkey", _check_pubkey(officer_pubkey, "officer_pubkey")))
    for idx, key in enumerate(agent_pubkeys):
        fields.append(
            (f"agent_pubkey[{idx}]", _check_pubkey(key, f"agent_pubkey[{idx}]"))
        )
    return fields


def build_base_hash_preimage(**kwargs) -> bytes:
    """The 4136-byte preimage of section 5.2 at the default configuration.

    The length assertion is not decorative. Revision 2 of the specification
    exists because a summary line disagreed with the field list by one U64.
    """
    fields = build_base_hash_fields(**kwargs)
    preimage = b"".join(payload for _, payload in fields)

    m = len(kwargs["candidate_ids"])
    n = kwargs["n"]
    a = kwargs["num_agents"]
    expected = expected_preimage_length(m, n, a)
    if len(preimage) != expected:
        raise AssertionError(
            f"base hash preimage is {len(preimage)} bytes, expected {expected} "
            f"for m={m}, n={n}, a={a}. Section 5.2: a preimage of "
            f"{expected - U64_WIDTH} is missing a U64 field, not disagreeing "
            f"about a total."
        )
    return preimage


def compute_base_hash(**kwargs) -> bytes:
    """Q, as 32 raw bytes."""
    return hashlib.sha256(build_base_hash_preimage(**kwargs)).digest()


def field_offsets(fields: Sequence[Tuple[str, bytes]]) -> List[Tuple[str, int, int]]:
    """(name, offset, length) for each field. Debugging aid for vector mismatches."""
    out: List[Tuple[str, int, int]] = []
    offset = 0
    for name, payload in fields:
        out.append((name, offset, len(payload)))
        offset += len(payload)
    return out
