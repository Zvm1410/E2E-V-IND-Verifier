"""Trusted dealer for the election secret key.

A trusted dealer stands in for distributed key generation. This is a
deliberate simplification: it changes nothing the verifier checks, since
the partial decryptions, their proofs and the commitments are the same
either way (SPEC section 18).

    1. draw sk uniformly in [1, q)                    (SPEC section 6)
    2. compute pk = g^sk mod p                        (SPEC section 6)
    3. split sk into n shares with threshold t        (sss.split_secret)
    4. compute per-trustee commitments h_j = g^s_j    (SPEC section 6)

The dealer's copy of sk is discarded after the split. Shares are held by
trustees; only public data (pk, {h_j}) reaches the bulletin board. Every
mathematical operation comes from ``crypto.elgamal``, ``crypto.group`` or
``tally.sss``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from crypto.group import P as p, Q as q, G as g
from crypto.elgamal import keypair_from_secret
from tally.sss import split_secret


@dataclass(frozen=True)
class TrusteeSetup:
    """The output of the dealer ceremony.

    ``sk`` and ``shares`` are secret and must never reach the bulletin
    board. ``pk``, ``commitments`` and ``t``, ``n`` are public.
    """
    n: int
    t: int
    sk: int                             # SECRET - discarded after split
    pk: int                             # public
    shares: Dict[int, int]              # trustee_index -> share (SECRET)
    commitments: Dict[int, int]         # trustee_index -> h_j = g^s_j (public)


def run_dealer(
    n: int,
    t: int,
    seed: int,
) -> TrusteeSetup:
    """Deterministic trusted dealer ceremony.

    Deterministic on ``seed`` so an end-to-end run can be reproduced.
    Determinism is provided by ``random.Random(seed)`` for sk selection
    and by Shamir's own ``seed`` argument for the polynomial. Neither
    is a security claim; production would use ``secrets`` and a real
    DKG. See the note at the top of this module.
    """
    if not (1 <= t <= n):
        raise ValueError(f"threshold t={t} out of range for n={n}")

    rng = random.Random(seed)
    # sk in [1, q). Do NOT use secrets here: we want determinism from
    # the seeded harness so the whole election can be replayed.
    sk = 1 + rng.randrange(q - 1)
    _, pk = keypair_from_secret(sk)

    # Deterministic Shamir split; sss.split_secret takes its own seed.
    raw_shares = split_secret(
        secret=sk,
        threshold=t,
        num_shares=n,
        seed=seed ^ 0xA5A5A5A5,          # keep sss seed distinct from sk seed
    )
    shares: Dict[int, int] = {x: y for x, y in raw_shares}

    # Trustee commitments h_j = g^{s_j} mod p (SPEC section 6).
    commitments: Dict[int, int] = {j: pow(g, s, p) for j, s in shares.items()}

    return TrusteeSetup(
        n=n,
        t=t,
        sk=sk,
        pk=pk,
        shares=shares,
        commitments=commitments,
    )


def choose_decryption_subset(setup: TrusteeSetup) -> List[int]:
    """Pick the first ``t`` trustees, in ascending index order.

    ``threshold.py`` accepts any subset of size >= t. Deterministic
    choice makes the decryption transcript reproducible.
    """
    return sorted(setup.shares.keys())[: setup.t]
