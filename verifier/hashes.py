"""Hash preimages, SPEC section 4 onward. Each builder returns the raw preimage
so a mismatch can be located byte by byte against the test vectors."""

import hashlib

from verifier.encoding import b2i, i2b, label, s64, u64
from verifier.group import G, P, Q


def challenge(preimage):
    """SPEC 4: B2I(SHA-256(preimage)) mod q."""
    return b2i(hashlib.sha256(preimage).digest()) % Q


def base_hash_preimage(election_id, candidate_ids, n, t, pk, commitments,
                       k, officer_key, agent_keys):
    """SPEC 5.2. Length 1704 + 64m + 384n + 32a."""
    if len(commitments) != n:
        raise ValueError("need exactly n trustee commitments")
    parts = [
        label("EVOTE-BASE-v1"),
        i2b(P), i2b(Q), i2b(G),
        s64(election_id),
        u64(len(candidate_ids)),
        *(s64(c) for c in candidate_ids),
        u64(n), u64(t),
        i2b(pk),
        *(i2b(h) for h in commitments),
        u64(len(agent_keys)), u64(k),
        officer_key,
        *agent_keys,
    ]
    for key in (officer_key, *agent_keys):
        if len(key) != 32:
            raise ValueError("Ed25519 public keys are 32 raw bytes")
    preimage = b"".join(parts)
    expected = 1704 + 64 * len(candidate_ids) + 384 * n + 32 * len(agent_keys)
    assert len(preimage) == expected, (len(preimage), expected)
    return preimage


def base_hash(*args, **kwargs):
    """Q as 32 raw bytes."""
    return hashlib.sha256(base_hash_preimage(*args, **kwargs)).digest()
