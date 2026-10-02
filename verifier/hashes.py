"""Hash preimages, SPEC section 4 onward. Each builder returns the raw preimage
so a mismatch can be located byte by byte against the test vectors."""

import hashlib

from verifier.encoding import b2i, i2b, label, s32, s64, u64
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


def validity_preimage(q_hash, booth_id, serial, candidate_index, pk, alpha, beta,
                      a0, b0, a1, b1):
    """SPEC 8.2. Exactly 2800 bytes."""
    preimage = b"".join([
        label("EVOTE-VALIDITY-v1"), q_hash, s32(booth_id), u64(serial),
        u64(candidate_index), i2b(pk), i2b(alpha), i2b(beta),
        i2b(a0), i2b(b0), i2b(a1), i2b(b1),
    ])
    assert len(preimage) == 2800, len(preimage)
    return preimage


def sumone_preimage(q_hash, booth_id, serial, pk, big_a, b_over_g, a, b):
    """SPEC 9.2. Exactly 2408 bytes."""
    preimage = b"".join([
        label("EVOTE-SUMONE-v1"), q_hash, s32(booth_id), u64(serial),
        i2b(G), i2b(pk), i2b(big_a), i2b(b_over_g), i2b(a), i2b(b),
    ])
    assert len(preimage) == 2408, len(preimage)
    return preimage


def partial_preimage(q_hash, trustee_index, candidate_index, big_a, h_j, partial, a, b):
    """SPEC 13.2. Exactly 2384 bytes."""
    preimage = b"".join([
        label("EVOTE-PARTIAL-v1"), q_hash, u64(trustee_index), u64(candidate_index),
        i2b(G), i2b(big_a), i2b(h_j), i2b(partial), i2b(a), i2b(b),
    ])
    assert len(preimage) == 2384, len(preimage)
    return preimage


def randomness_commitment(q_hash, booth_id, serial, randomness, nonce):
    """SPEC 10.1: K_s. Length 136 + 384m."""
    if len(nonce) != 32:
        raise ValueError("nonce is 32 bytes")
    preimage = b"".join([label("EVOTE-RCOMMIT-v1"), q_hash, s32(booth_id), u64(serial),
                         *(i2b(r) for r in randomness), nonce])
    assert len(preimage) == 136 + 384 * len(randomness)
    return hashlib.sha256(preimage).digest()


def schedule_commitment(q_hash, booth_id, schedule_seed, num, den):
    """SPEC 10.2: T. Exactly 144 bytes of preimage."""
    preimage = b"".join([label("EVOTE-TESTSCHED-v1"), q_hash, s32(booth_id), schedule_seed,
                         u64(num), u64(den)])
    assert len(preimage) == 144, len(preimage)
    return hashlib.sha256(preimage).digest()


def is_scheduled(schedule_seed, serial, num, den):
    """SPEC 10.2 per-serial draw, exact integer comparison."""
    digest = hashlib.sha256(label("EVOTE-TESTDRAW-v1") + schedule_seed + u64(serial)).digest()
    return b2i(digest[:8]) * den < num * 2**64
